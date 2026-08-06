"""What this project used to have installed.

Every other command here reads the working tree, which answers a question
about now. The question people actually ask on the morning a compromise is
announced is about then: were we ever on that version, for how long, and did
anything run an install while we were.

A conventional scanner cannot answer it. If you have already bumped past the
bad release, `npm audit` says clean, and it is telling the truth about a
question nobody asked. Meanwhile CI installed that version on every push for
as long as it was pinned, and whatever it could reach is gone.

The answer is in git. A lockfile is a list of exact coordinates, so its
history is a time series of exactly what would have been installed, and it
only changes in commits that touch it. That makes sampling at those commits
complete rather than approximate: between two of them the answer cannot have
moved.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import npm, pypi
from .diff import git_root, parser_for, read_manifest
from .model import Package

# How many blobs to ask git for at a time. The batch reader exists to stop
# spawning a process per commit, and a chunk keeps the other end of that from
# holding four hundred lockfiles in memory at once.
CHUNK = 32
DEFAULT_LIMIT = 200


@dataclass(frozen=True)
class Commit:
    sha: str
    when: datetime
    subject: str

    @property
    def short(self) -> str:
        return self.sha[:7]


@dataclass
class Snapshot:
    """What the manifests resolved to at one commit."""

    commit: Commit
    coords: set[tuple[str, str, str]] = field(default_factory=set)


@dataclass
class Window:
    """One version of one package, and the stretch it sat in the lockfile.

    `entered` is the commit that introduced it. `left` is the commit that took
    it back out, or None while it is still there. `bounded` is False when the
    version was already present in the oldest commit read, which means it
    entered at or before that point and we cannot say which.
    """

    ecosystem: str
    name: str
    version: str
    entered: Commit
    left: Commit | None = None
    bounded: bool = True
    commits: int = 0
    malware: list[dict] = field(default_factory=list)
    advisories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @property
    def coord(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def ended(self) -> datetime:
        return self.left.when if self.left else datetime.now(UTC)

    @property
    def days(self) -> float:
        return max(0.0, (self.ended - self.entered.when).total_seconds() / 86400)

    @property
    def open(self) -> bool:
        return self.left is None

    @property
    def severity(self) -> str:
        if self.malware:
            return "critical"
        return "medium" if self.advisories else "clean"


@dataclass
class HistoryReport:
    root: str
    subject: str = ""
    manifests: list[str] = field(default_factory=list)
    commits: list[Commit] = field(default_factory=list)
    windows: list[Window] = field(default_factory=list)
    coords: int = 0
    truncated: bool = False
    package: str = ""
    online: bool = False
    warnings: list[str] = field(default_factory=list)
    http_calls: int = 0
    cache_hits: int = 0
    elapsed: float = 0.0

    @property
    def exposed(self) -> list[Window]:
        return [w for w in self.windows if w.malware]

    @property
    def flagged(self) -> list[Window]:
        return [w for w in self.windows if w.malware or w.advisories]

    @property
    def span(self) -> tuple[datetime, datetime] | None:
        """The commits read, oldest to newest."""
        if not self.commits:
            return None
        return self.commits[0].when, self.commits[-1].when

    @property
    def axis(self) -> tuple[datetime, datetime] | None:
        """The period a timeline is drawn against, which runs to today.

        Whatever HEAD pins is still installed, so its window has not ended. An
        axis that stopped at the last commit would draw a dependency taken two
        years ago as a single cell at the right edge and call it current.
        """
        if not self.commits:
            return None
        return self.commits[0].when, max(self.commits[-1].when, datetime.now(UTC))


# -- git -------------------------------------------------------------------


def _git(repo_root: str, *args: str, timeout: int = 60) -> str:
    out = subprocess.run(["git", "-C", repo_root, *args],
                         capture_output=True, text=True, timeout=timeout)
    return out.stdout if out.returncode == 0 else ""


def commits_touching(repo_root: str, paths: list[str], limit: int = DEFAULT_LIMIT,
                     since: str = "") -> tuple[list[Commit], bool]:
    """Every commit that changed one of these files, oldest first.

    First-parent only. A merge brings a branch's lockfile onto the mainline in
    one commit, and what this command reports on is what the mainline carried,
    because that is what was built, installed and deployed.
    """
    if not paths:
        return [], False

    range_args = [f"{since}..HEAD"] if since else []
    raw = _git(repo_root, "log", "--first-parent", f"--max-count={limit + 1}",
               "--format=%H%x1f%ct%x1f%s", *range_args, "--", *paths)

    found: list[Commit] = []
    for line in raw.splitlines():
        sha, _, rest = line.partition("\x1f")
        stamp, _, subject = rest.partition("\x1f")
        if not sha or not stamp.isdigit():
            continue
        found.append(Commit(sha, datetime.fromtimestamp(int(stamp), UTC), subject.strip()))

    truncated = len(found) > limit
    return list(reversed(found[:limit])), truncated


def blobs(repo_root: str, specs: list[str]) -> dict[str, bytes]:
    """Read many blobs from one git process.

    `git show` per commit is a process per commit, and a lockfile that changed
    four hundred times is four hundred processes. `cat-file --batch` takes the
    whole list on stdin and answers with a header line and the raw bytes, so
    the cost stops scaling with how long the project has existed.
    """
    if not specs:
        return {}
    try:
        proc = subprocess.run(
            ["git", "-C", repo_root, "cat-file", "--batch"],
            input=("\n".join(specs) + "\n").encode(),
            capture_output=True, timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError):
        return {}

    out, at, found = proc.stdout, 0, {}
    for spec in specs:
        end = out.find(b"\n", at)
        if end < 0:
            break
        header = out[at:end].decode("utf-8", "replace").split()
        at = end + 1
        # "<oid> missing" for a path that did not exist at that commit, and no
        # body follows it. That is ordinary: manifests get added and deleted.
        if len(header) < 3 or not header[2].isdigit():
            continue
        size = int(header[2])
        found[spec] = out[at:at + size]
        at += size + 1  # git writes a newline after every object
    return found


# -- history ---------------------------------------------------------------


def tags_in_window(repo_root: str, entered: str, left: str | None) -> list[str]:
    """Tags that were cut while a version was in the tree.

    "You were exposed for six days" is a fact about a lockfile. "You shipped
    v1.4.0 and v1.4.1 during those six days" is the same fact in the form
    somebody has to act on, because those artifacts were built against it and
    may need pulling.

    Ancestry rather than dates: a tag contains the commit that introduced the
    version and does not contain the one that removed it. That is exactly the
    set of releases built with it, and it stays right when tags are cut from
    branches or a release is dated later than the commit it points at.
    """
    during = {t for t in _git(repo_root, "tag", "--contains", entered).split() if t}
    if not during:
        return []
    if left:
        during -= {t for t in _git(repo_root, "tag", "--contains", left).split() if t}
    return sorted(during)


def manifest_paths(root: str, repo_root: str) -> list[str]:
    """The manifests to follow, relative to the repository root.

    Taken from the working tree. A manifest that was deleted before HEAD is
    not followed, which is worth knowing but not worth guessing about: the
    versions it pinned are almost always in a sibling lockfile anyway.
    """
    paths = []
    for module in (npm, pypi):
        for path in module.find_manifests(root):
            paths.append(os.path.relpath(os.path.abspath(path), repo_root))
    return sorted(set(paths))


def _coords_in(rel: str, raw: bytes) -> set[tuple[str, str, str]]:
    """Parse one historical manifest.

    Every parser dispatches on the filename and a blob arrives with no name
    attached, so it gets written back out under its original basename. Only
    pinned versions count: a range says what was allowed, not what was there.
    """
    with tempfile.TemporaryDirectory() as tmp:
        staged = os.path.join(tmp, os.path.basename(rel))
        with open(staged, "wb") as fh:
            fh.write(raw)
        return {(p.ecosystem, p.name, p.version) for p in read_manifest(staged, tmp)
                if p.kind == "package" and p.version}


def snapshots(repo_root: str, commits: list[Commit], paths: list[str],
              progress=None) -> list[Snapshot]:
    """Resolve every commit, batching the reads across commits rather than
    within one. Asking per commit is a git process per commit, which is the
    cost this was written to avoid."""
    readable = [p for p in paths if parser_for(p)]
    specs = [f"{c.sha}:{p}" for c in commits for p in readable]
    found = {c.sha: Snapshot(c) for c in commits}

    done = 0
    for chunk in _chunks(specs, CHUNK):
        for spec, raw in blobs(repo_root, chunk).items():
            sha, _, rel = spec.partition(":")
            found[sha].coords |= _coords_in(rel, raw)
        done += len(chunk)
        if progress:
            progress(min(done, len(specs)), len(specs))
    return [found[c.sha] for c in commits]


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def windows(shots: list[Snapshot]) -> list[Window]:
    """Turn a sequence of snapshots into spans of presence.

    A coordinate that leaves and comes back gets two windows rather than one,
    because two separate exposures are two separate things to answer for.
    """
    if not shots:
        return []

    live: dict[tuple[str, str, str], Window] = {}
    closed: list[Window] = []

    for i, shot in enumerate(shots):
        for coord in shot.coords - set(live):
            eco, name, version = coord
            live[coord] = Window(eco, name, version, entered=shot.commit, bounded=i > 0)
        for coord in list(live):
            if coord in shot.coords:
                live[coord].commits += 1
            else:
                window = live.pop(coord)
                window.left = shot.commit
                closed.append(window)

    closed.extend(live.values())
    closed.sort(key=lambda w: (w.entered.when, w.name, w.version))
    return closed


# -- the command -----------------------------------------------------------


def run(root: str, online: bool = False, package: str = "", limit: int = DEFAULT_LIMIT,
        since: str = "", progress=None) -> HistoryReport:
    import time

    from .scan import _stage

    started = time.perf_counter()
    repo_root = git_root(root) or root
    paths = manifest_paths(root, repo_root)

    report = HistoryReport(root=root, subject=os.path.basename(os.path.abspath(root)) or root,
                           manifests=paths, package=package, online=online)
    if not paths:
        report.elapsed = time.perf_counter() - started
        return report

    # A shallow clone is the default on most CI checkouts, and it looks
    # exactly like a project with a short history. Saying "never exposed"
    # about fifty commits somebody fetched by accident is the one failure
    # this command cannot afford.
    if _git(repo_root, "rev-parse", "--is-shallow-repository").strip() == "true":
        report.warnings.append(
            "this is a shallow clone, so only part of the history is here at all; "
            "fetch it in full (actions/checkout with fetch-depth: 0)"
        )

    found, report.truncated = commits_touching(repo_root, paths, limit=limit, since=since)
    report.commits = found
    shots = snapshots(repo_root, found, paths, progress=_stage(progress, "reading history"))
    every = windows(shots)
    report.coords = len({(w.ecosystem, w.name, w.version) for w in every})

    if package:
        wanted = package.lower()
        every = [w for w in every if wanted in w.name.lower()]

    if online and every:
        _enrich(report, every, progress)

    # Without a name to follow, the interesting windows are the ones something
    # is known about. With one, every window is the answer to the question.
    report.windows = every if package else [w for w in every if w.malware or w.advisories]
    report.windows.sort(key=lambda w: (not w.malware, not w.advisories, w.entered.when))

    # Only where it changes what somebody does. A release built against a
    # malicious version may have to be pulled; a release built against a
    # package that later got an advisory is an upgrade, not a recall.
    for window in report.windows:
        if window.malware:
            window.tags = tags_in_window(repo_root, window.entered.sha,
                                         window.left.sha if window.left else None)
    report.elapsed = time.perf_counter() - started
    return report


def _enrich(report: HistoryReport, every: list[Window], progress=None) -> None:
    """Ask osv.dev about every version this project ever pinned.

    One batched request covers five hundred coordinates, so the whole history
    of a large project costs a handful of requests. The lookup is by exact
    version, which is the only reason this works: a range would tell you
    nothing about what was actually installed.
    """
    from .http import Http
    from .intel import Osv
    from .scan import _stage

    by_coord: dict[tuple[str, str, str], list[Window]] = {}
    for w in every:
        by_coord.setdefault((w.ecosystem, w.name, w.version), []).append(w)

    probes = [Package(eco, name, version=version) for eco, name, version in by_coord]
    http = Http()
    Osv(http).enrich(probes, progress=_stage(progress, "checking osv.dev"))

    for probe in probes:
        for w in by_coord[(probe.ecosystem, probe.name, probe.version)]:
            w.malware = probe.meta.get("malware", [])
            w.advisories = probe.meta.get("advisories", [])

    report.http_calls, report.cache_hits = http.calls, http.hits
    if http.failures:
        report.warnings.append(
            f"{len(http.failures)} lookups failed, so some versions went unchecked "
            f"(first: {http.failures[0]})"
        )
