"""Score a change to a dependency list rather than the whole tree.

A full scan tells you about a codebase. When you are reviewing a pull request
you want the other thing: what did this change let in? Everything already in
the lockfile was somebody else's decision, and re-reading it on every PR is
how people learn to skim the output.

So `hemlock diff` resolves both sides, keeps what is new or moved, and scores
only that.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass, field

from . import npm, pypi
from .model import Package
from .policy import Policy
from .scan import Report, _stage, run_rules

PARSERS = {
    "package-lock.json": npm, "npm-shrinkwrap.json": npm, "yarn.lock": npm, "package.json": npm,
    "poetry.lock": pypi, "Pipfile.lock": pypi, "pyproject.toml": pypi, "requirements.txt": pypi,
}


@dataclass
class Change:
    package: Package
    kind: str  # "added" | "updated"
    was: str | None = None


@dataclass
class DiffReport(Report):
    changes: list[Change] = field(default_factory=list)
    removed: list[Package] = field(default_factory=list)
    base_label: str = "base"
    head_label: str = "head"

    @property
    def unchanged(self) -> int:
        return self._unchanged

    _unchanged: int = 0


def parser_for(path: str):
    name = os.path.basename(path)
    if name in PARSERS:
        return PARSERS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return pypi
    return None


def read_manifest(path: str, root: str) -> list[Package]:
    module = parser_for(path)
    return module.parse(path, root) if module else []


def from_git(ref: str, path: str, repo_root: str) -> list[Package]:
    """Resolve a manifest as it existed at a git ref.

    The blob is written to a temporary file with its original name, because
    every parser here dispatches on the filename and `git show` gives you
    bytes with no name attached.
    """
    rel = os.path.relpath(os.path.abspath(path), repo_root)
    try:
        blob = subprocess.run(
            ["git", "-C", repo_root, "show", f"{ref}:{rel}"],
            capture_output=True, check=True, timeout=30,
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return []  # the file did not exist at that ref, so everything is new

    with tempfile.TemporaryDirectory() as tmp:
        staged = os.path.join(tmp, os.path.basename(path))
        with open(staged, "wb") as fh:
            fh.write(blob)
        return read_manifest(staged, tmp)


def git_root(start: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", start, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return out.stdout.strip() or None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None


def compare(base: list[Package], head: list[Package]) -> tuple[list[Change], list[Package], int]:
    before = {(p.ecosystem, p.name): p for p in base if p.kind == "package"}
    changes, unchanged = [], 0

    for pkg in head:
        if pkg.kind != "package":
            continue
        was = before.pop((pkg.ecosystem, pkg.name), None)
        if was is None:
            changes.append(Change(pkg, "added"))
        elif (was.version or was.spec) != (pkg.version or pkg.spec):
            changes.append(Change(pkg, "updated", was.version or was.spec))
        else:
            unchanged += 1

    return changes, list(before.values()), unchanged


def run(base: list[Package], head: list[Package], policy: Policy, root: str,
        online: bool = False, progress=None, labels: tuple[str, str] = ("base", "head")) -> DiffReport:
    changes, removed, unchanged = compare(base, head)
    subjects = [c.package for c in changes]

    report = DiffReport(root=root, packages=subjects, online=online,
                        changes=changes, removed=removed,
                        base_label=labels[0], head_label=labels[1])
    report._unchanged = unchanged

    if online and subjects:
        from .http import Http
        from .intel import Osv
        from .registry import Registry

        http = Http()
        Osv(http).enrich(subjects, progress=_stage(progress, "checking osv.dev"))
        Registry(http).enrich(subjects, progress=_stage(progress, "querying registries"))
        report.http_calls, report.cache_hits = http.calls, http.hits
        if http.failures:
            report.warnings.append(f"{len(http.failures)} lookups failed, so some online rules were skipped")

    run_rules(report, policy, online, subjects)
    return report
