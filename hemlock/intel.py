"""OSV lookups: known-malicious versions and published advisories.

osv.dev aggregates the OpenSSF malicious-packages feed alongside ordinary
vulnerability data. Records whose id starts with MAL- name a specific version
as malware rather than merely vulnerable, which is a different claim and gets
handled differently everywhere downstream.

One batch request covers a thousand packages across both ecosystems, so this
is the cheapest signal in the tool by a wide margin.
"""

from __future__ import annotations

from .http import Http
from .model import Package
from .pypi import normalize

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
BATCH_SIZE = 500

ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}


class Osv:
    def __init__(self, http: Http | None = None):
        self.http = http or Http()

    def enrich(self, packages: list[Package], progress=None) -> None:
        targets = [p for p in packages if p.kind == "package" and p.version]
        if not targets:
            return

        # One query per distinct coordinate; the same package can appear in
        # several manifests and does not need asking about twice.
        by_coord: dict[tuple[str, str, str], list[Package]] = {}
        for p in targets:
            key = (p.ecosystem, self._name(p), p.version)
            by_coord.setdefault(key, []).append(p)

        coords = list(by_coord)
        done = 0
        for chunk in _chunks(coords, BATCH_SIZE):
            payload = {
                "queries": [
                    {"package": {"ecosystem": ECOSYSTEM[eco], "name": name}, "version": version}
                    for eco, name, version in chunk
                ]
            }
            response = self.http.post(OSV_BATCH, payload)
            results = (response or {}).get("results") or []

            for coord, result in zip(chunk, results, strict=False):
                ids = [v["id"] for v in (result.get("vulns") or [])]
                if not ids:
                    continue
                malware, advisories = self._split(ids)
                for pkg in by_coord[coord]:
                    if malware:
                        pkg.meta["malware"] = malware
                    if advisories:
                        pkg.meta["advisories"] = advisories

            done += len(chunk)
            if progress:
                progress(done, len(coords))

    def _split(self, ids: list[str]) -> tuple[list[dict], list[str]]:
        """Separate malware reports from ordinary advisories, and drop any
        record OSV has withdrawn.

        The withdrawal check is not defensive programming for its own sake.
        In May 2026 OSV pulled 157 malware reports that an automated
        classifier had raised against trusted npm and PyPI packages, and
        every tool that had already ingested them kept failing builds. A
        scanner that calls a package malware owes it to the reader to check
        whether the claim still stands.
        """
        malware, advisories = [], []
        for vuln_id in ids:
            if not vuln_id.startswith("MAL-"):
                advisories.append(vuln_id)
                continue
            detail = self.http.get(OSV_VULN + vuln_id, allow_404=True) or {}
            if detail.get("withdrawn"):
                continue
            malware.append({
                "id": vuln_id,
                "summary": detail.get("summary") or "Reported as malicious",
                "aliases": detail.get("aliases") or [],
            })
        return malware, advisories

    @staticmethod
    def _name(pkg: Package) -> str:
        return normalize(pkg.name) if pkg.ecosystem == "pypi" else pkg.name


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]
