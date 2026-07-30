"""Registry lookups for the --online rules.

Public endpoints only, no credentials, no account required. Responses are
cached on disk because a second run five minutes later should not cost the
registry anything, and because a scan you re-run while triaging should be
instant.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from .model import Package
from .pypi import normalize

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week"
PYPI = "https://pypi.org/pypi"

USER_AGENT = "hemlock (+https://github.com/hemlock-scan/hemlock)"
CACHE_TTL = 6 * 3600


class Registry:
    def __init__(self, cache_dir: str | None = None, workers: int = 8, timeout: int = 15):
        self.cache_dir = cache_dir or _default_cache()
        self.workers = workers
        self.timeout = timeout
        self.failures: list[str] = []
        os.makedirs(self.cache_dir, exist_ok=True)

    # -- fetching ---------------------------------------------------------

    def _get(self, url: str) -> dict | None:
        key = hashlib.sha256(url.encode()).hexdigest()[:32]
        path = os.path.join(self.cache_dir, key + ".json")
        try:
            if time.time() - os.path.getmtime(path) < CACHE_TTL:
                with open(path, "rb") as fh:
                    return json.loads(gzip.decompress(fh.read()))
        except (OSError, ValueError):
            pass

        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                doc = json.loads(raw)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            self.failures.append(f"{url}: {exc}")
            return None

        try:
            with open(path, "wb") as fh:
                fh.write(gzip.compress(json.dumps(doc).encode()))
        except OSError:
            pass
        return doc

    # -- enrichment -------------------------------------------------------

    def enrich(self, packages: list[Package], progress=None) -> None:
        """Fill pkg.meta for every distinct package, in parallel."""
        by_key: dict[tuple[str, str, str | None], list[Package]] = {}
        for p in packages:
            by_key.setdefault((p.ecosystem, p.name, p.version), []).append(p)

        done = 0
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            results = pool.map(lambda k: self._lookup(*k), by_key)
            for key, meta in zip(by_key, results, strict=True):
                for pkg in by_key[key]:
                    pkg.meta.update(meta)
                done += 1
                if progress:
                    progress(done, len(by_key))

    def _lookup(self, ecosystem: str, name: str, version: str | None) -> dict:
        try:
            if ecosystem == "npm":
                return self._npm(name, version)
            return self._pypi(name, version)
        except Exception as exc:  # a bad payload should never kill a scan
            self.failures.append(f"{ecosystem}:{name}: {exc}")
            return {}

    def _npm(self, name: str, version: str | None) -> dict:
        doc = self._get(f"{NPM_REGISTRY}/{urllib.parse.quote(name, safe='@')}")
        if not doc:
            return {}
        versions = doc.get("versions") or {}
        times = doc.get("time") or {}
        version = version or (doc.get("dist-tags") or {}).get("latest")
        entry = versions.get(version) or {}
        meta: dict = {}

        if published := _parse_time(times.get(version)):
            meta["published_at"] = published

        # Releases that went out before this one, newest first.
        history = sorted(
            (v for v in versions if v != version and v in times),
            key=lambda v: times[v],
            reverse=True,
        )
        if entry.get("_npmUser", {}).get("name"):
            meta["publisher"] = entry["_npmUser"]["name"]
        priors = [versions[v].get("_npmUser", {}).get("name") for v in history[:10]]
        meta["prior_publishers"] = [p for p in priors if p]

        dist = entry.get("dist") or {}
        meta["signed"] = bool(dist.get("signatures") or dist.get("attestations"))
        if dist.get("unpackedSize"):
            meta["unpacked_size"] = dist["unpackedSize"]
        for prev in history:
            size = (versions[prev].get("dist") or {}).get("unpackedSize")
            if size:
                meta["prior_unpacked_size"] = size
                break

        if entry.get("deprecated"):
            meta["deprecated"] = entry["deprecated"]
        if not (entry.get("repository") or doc.get("repository")):
            meta["repo_missing"] = True

        counts = self._get(f"{NPM_DOWNLOADS}/{urllib.parse.quote(name, safe='@')}")
        if counts and isinstance(counts.get("downloads"), int):
            meta["downloads"] = counts["downloads"]
        return meta

    def _pypi(self, name: str, version: str | None) -> dict:
        slug = urllib.parse.quote(normalize(name), safe="")
        url = f"{PYPI}/{slug}/{urllib.parse.quote(version, safe='')}/json" if version else f"{PYPI}/{slug}/json"
        doc = self._get(url)
        if not doc:
            return {}
        info = doc.get("info") or {}
        meta: dict = {}

        files = doc.get("urls") or []
        stamps = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
        if stamps and (published := _parse_time(min(stamps))):
            meta["published_at"] = published

        if info.get("yanked"):
            meta["yanked"] = True
            meta["yanked_reason"] = info.get("yanked_reason")

        urls = info.get("project_urls") or {}
        has_repo = info.get("home_page") or any(
            k.lower() in {"source", "repository", "homepage", "source code", "code", "github"}
            for k in urls
        )
        if not has_repo:
            meta["repo_missing"] = True

        if vulns := doc.get("vulnerabilities"):
            meta["vulnerabilities"] = vulns

        sizes = [f.get("size") for f in files if f.get("size")]
        if sizes:
            meta["unpacked_size"] = max(sizes)
        return meta


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _default_cache() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "hemlock")
