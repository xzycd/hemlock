"""Per-package registry metadata for the --online rules.

Public endpoints only: no credentials, no account, no telemetry. Each package
gets one pass on a thread pool, and that pass also picks up build provenance
so there is never a second wave of requests over the same list.
"""

from __future__ import annotations

import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from .http import ABSENT, Http
from .model import Package
from .provenance import npm_provenance, pypi_provenance, repo_slug
from .pypi import normalize

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week"
PYPI = "https://pypi.org/pypi"


class Registry:
    def __init__(self, http: Http | None = None, workers: int = 12):
        self.http = http or Http()
        self.workers = workers

    @property
    def failures(self) -> list[str]:
        return self.http.failures

    def enrich(self, packages: list[Package], progress=None) -> None:
        by_key: dict[tuple[str, str, str | None], list[Package]] = {}
        for p in packages:
            if p.kind == "package":
                by_key.setdefault((p.ecosystem, p.name, p.version), []).append(p)
        if not by_key:
            return

        keys = list(by_key)
        done = 0
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for key, meta in zip(keys, pool.map(lambda k: self._lookup(*k), keys), strict=True):
                for pkg in by_key[key]:
                    pkg.meta.update(meta)
                done += 1
                if progress:
                    progress(done, len(keys))

    def _lookup(self, ecosystem: str, name: str, version: str | None) -> dict:
        try:
            return self._npm(name, version) if ecosystem == "npm" else self._pypi(name, version)
        except Exception as exc:  # a malformed payload must not kill the scan
            self.http.failures.append(f"{ecosystem}:{name}: {exc}")
            return {}

    # -- npm --------------------------------------------------------------

    def _npm(self, name: str, version: str | None) -> dict:
        quoted = urllib.parse.quote(name, safe="@")
        doc = self.http.get(f"{NPM_REGISTRY}/{quoted}", allow_404=True)
        if not doc:
            # The packument URL carries no version, so a 404 here is the
            # registry saying it has nothing under this name at all. A
            # request that failed says nothing and must not be read as one.
            return {"unpublished": True} if doc is ABSENT else {}

        versions = doc.get("versions") or {}
        times = doc.get("time") or {}
        version = version or (doc.get("dist-tags") or {}).get("latest")
        entry = versions.get(version) or {}
        meta: dict = {}
        if version:
            meta["resolved_version"] = version

        if published := _parse_time(times.get(version)):
            meta["published_at"] = published

        # Only releases that came out *before* this one count as history.
        # Sorting by recency alone gets this backwards for a pinned older
        # version, where the newest releases are the ones it predates.
        stamp = times.get(version)
        earlier = sorted(
            (v for v in versions if v != version and v in times and (not stamp or times[v] < stamp)),
            key=lambda v: times[v], reverse=True,
        )

        if publisher := (entry.get("_npmUser") or {}).get("name"):
            meta["publisher"] = publisher
        # Everyone who ever shipped an earlier release, not just the last few.
        # A co-maintainer who publishes every other version is not news; an
        # account that has never published this package before is.
        meta["prior_publishers"] = sorted({
            name for v in earlier
            if (name := (versions[v].get("_npmUser") or {}).get("name"))
        })

        dist = entry.get("dist") or {}
        if dist.get("unpackedSize"):
            meta["unpacked_size"] = dist["unpackedSize"]
        for prev in earlier:
            if size := ((versions[prev].get("dist") or {}).get("unpackedSize")):
                meta["prior_unpacked_size"] = size
                break

        if entry.get("deprecated"):
            meta["deprecated"] = entry["deprecated"]

        declared = entry.get("repository") or doc.get("repository")
        if not declared:
            meta["repo_missing"] = True
        else:
            meta["declared_repo"] = repo_slug(declared)

        if counts := self.http.get(f"{NPM_DOWNLOADS}/{quoted}", allow_404=True):
            if isinstance(counts.get("downloads"), int):
                meta["downloads"] = counts["downloads"]

        if version:
            meta["provenance"] = npm_provenance(name, version, self.http)
        return meta

    # -- pypi -------------------------------------------------------------

    def _pypi(self, name: str, version: str | None) -> dict:
        slug = urllib.parse.quote(normalize(name), safe="")
        path = f"{slug}/{urllib.parse.quote(version, safe='')}/json" if version else f"{slug}/json"
        doc = self.http.get(f"{PYPI}/{path}", allow_404=True)
        if not doc:
            if doc is not ABSENT:
                return {}
            # Unlike npm's packument, this URL carries the version, so a 404
            # covers two different answers: no such project, or a project
            # with no such release. Only the first is what HEM507 reports, and
            # telling them apart costs one request on a path that is rare by
            # definition.
            if version and self.http.get(f"{PYPI}/{slug}/json", allow_404=True):
                return {}
            return {"unpublished": True}

        info = doc.get("info") or {}
        files = doc.get("urls") or []
        meta: dict = {}

        stamps = [f["upload_time_iso_8601"] for f in files if f.get("upload_time_iso_8601")]
        if stamps and (published := _parse_time(min(stamps))):
            meta["published_at"] = published

        if info.get("yanked"):
            meta["yanked"] = True
            meta["yanked_reason"] = info.get("yanked_reason")

        urls = info.get("project_urls") or {}
        repo = info.get("home_page") or next(
            (v for k, v in urls.items()
             if k.lower() in {"source", "repository", "homepage", "source code", "code", "github"}),
            None,
        )
        if repo:
            meta["declared_repo"] = repo_slug(repo)
        else:
            meta["repo_missing"] = True

        if sizes := [f["size"] for f in files if f.get("size")]:
            meta["unpacked_size"] = max(sizes)

        # A bare name means "whatever PyPI serves today", which the versionless
        # document already answers. Resolving it the way the npm branch does
        # matters for more than tidiness: provenance is looked up per file, so
        # skipping this made `hemlock check <name>` report every signed package
        # as having no attestation, hemlock's own release included.
        version = version or info.get("version")
        if version:
            meta["resolved_version"] = version

        # PEP 740 attestations attach to a file, so prefer the wheel.
        target = next((f for f in files if f.get("packagetype") == "bdist_wheel"), files[0] if files else None)
        if target and version:
            meta["provenance"] = pypi_provenance(normalize(name), version, target["filename"], self.http)
        return meta


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
