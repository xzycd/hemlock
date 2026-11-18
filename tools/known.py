"""Refresh the lists of established package names the naming rules stand down for.

A name that a million installs a week already resolve to is not somebody's
typo of a neighbour, however close the spelling. The lists are taken whole
from two public datasets rather than curated here, so there is no judgement
in them to argue with:

  npm   npm-high-impact: a million weekly downloads, or heavily depended on
  PyPI  hugovk/top-pypi-packages: the most downloaded projects of the month

    python3 tools/known.py

Writes hemlock/known/npm.txt and hemlock/known/pypi.txt. Run it before a
release; a list that is a few months old only costs a false positive on
whatever became popular since.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from datetime import UTC, datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hemlock.pypi import normalize  # noqa: E402

NPM_LATEST = "https://registry.npmjs.org/npm-high-impact/latest"
NPM_LIST = "https://cdn.jsdelivr.net/npm/npm-high-impact@{version}/lib/top.js"
PYPI_LIST = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
# Past this rank a PyPI project sees fewer downloads in a month than mirrors
# and scanners give any upload, which stops being evidence that people use it.
PYPI_KEEP = 8000

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hemlock", "known")


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed https URLs above
        return resp.read()


def write(name: str, source: str, names: list[str]) -> None:
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"# {source}\n# fetched {datetime.now(UTC):%Y-%m-%d} by tools/known.py\n")
        fh.write("\n".join(sorted(set(names))) + "\n")
    print(f"{path}: {len(set(names)):,} names")


def main() -> None:
    os.makedirs(OUT, exist_ok=True)

    version = json.loads(fetch(NPM_LATEST))["version"]
    listing = fetch(NPM_LIST.format(version=version)).decode()
    npm = re.findall(r"^\s*'([^']+)',?\s*$", listing, re.M)
    if len(npm) < 5000:
        raise SystemExit(f"npm-high-impact@{version} yielded {len(npm)} names; the file format has moved")
    write("npm.txt", f"npm-high-impact@{version}", npm)

    doc = json.loads(fetch(PYPI_LIST))
    rows = doc["rows"][:PYPI_KEEP]
    if len(rows) < PYPI_KEEP:
        raise SystemExit(f"top-pypi-packages yielded {len(rows)} rows, expected {PYPI_KEEP}")
    write("pypi.txt", f"top-pypi-packages, {doc['last_update'][:10]}, first {PYPI_KEEP:,}",
          [normalize(row["project"]) for row in rows])


if __name__ == "__main__":
    main()
