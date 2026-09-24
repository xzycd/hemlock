"""Find campaigns across npm packages using install code, hosts and publisher history."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import timedelta

from . import fingerprint as fp
from .model import Package

# Ignore hosts and accounts shared by more than this many owners. Payloads
# have no cap because a large copied install script is still relevant.
CROWD = 60

# How alike two files have to be. Containment rather than similarity, because
# a payload appended to a real file is most of the payload and a fraction of
# the file; the absolute floor is what stops "small file inside big file" from
# meaning anything on its own.
SAME_CODE = 0.80
SAME_CODE_FLOOR = 8

# Versions published this close together, across packages that are otherwise
# unrelated, are one push. Evidence only -- never a link.
BURST = timedelta(hours=72)

MAX_FILES_PER_PACKAGE = 8
MAX_FILE_BYTES = 2_000_000

# Hosts that appear in install scripts for ordinary reasons. Sharing one of
# these says two packages both download things, which is not a relationship.
COMMON_HOSTS = frozenset("""
    registry.npmjs.org registry.yarnpkg.com npmjs.com www.npmjs.com
    pypi.org files.pythonhosted.org test.pypi.org
    github.com www.github.com raw.githubusercontent.com objects.githubusercontent.com
    codeload.github.com api.github.com gitlab.com bitbucket.org
    nodejs.org registry.npmmirror.com unpkg.com cdn.jsdelivr.net jsdelivr.net
    npmmirror.com googleapis.com storage.googleapis.com
    localhost 127.0.0.1 example.com
""".split())

_URL = re.compile(r"\bhttps?://([A-Za-z0-9._-]+(?::\d+)?)", re.I)
_SCRIPT_REF = re.compile(r"[\w./@-]+\.(?:js|cjs|mjs|py)\b")


@dataclass(frozen=True)
class Link:
    """One reason to believe two or more packages are the same operation."""

    kind: str  # "payload" | "endpoint" | "publisher"
    key: str  # what matched, canonically
    display: str  # what to print
    members: tuple[str, ...] = ()  # package coordinates
    detail: str = ""  # the measurement behind it, when there is one


@dataclass
class Campaign:
    """A set of packages the evidence says arrived together."""

    label: str
    members: list[Package] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    burst: str = ""
    _keys: frozenset[str] | None = field(default=None, repr=False, compare=False)

    @property
    def kinds(self) -> list[str]:
        return sorted({ln.kind for ln in self.links})

    @property
    def member_keys(self) -> frozenset[str]:
        if self._keys is None:
            self._keys = frozenset(key_of(m) for m in self.members)
        return self._keys

    def links_of(self, kind: str) -> list[Link]:
        return [ln for ln in self.links if ln.kind == kind]

    @property
    def behavioral(self) -> bool:
        """Linked by what the code does, rather than by who uploaded it.

        A shared account is a reason to look. A shared payload is the finding.
        """
        return any(ln.kind in ("payload", "endpoint") for ln in self.links)


def key_of(pkg: Package) -> str:
    return f"{pkg.ecosystem}:{pkg.coord}"


# --------------------------------------------------------------------------
# ownership
# --------------------------------------------------------------------------


def owner_of(pkg: Package) -> str | None:
    """Who publishes this, as far as can be told without asking the registry.

    An npm scope is the strongest offline answer. Failing that, the repository
    the package declares: two packages pointing at the same organization on
    the same host are one project shipping twice, not two projects agreeing.
    Returning None means unknown, and unknown never suppresses a link.
    """
    if pkg.ecosystem == "npm" and pkg.name.startswith("@") and "/" in pkg.name:
        return f"scope:{pkg.name.split('/')[0]}"

    repo = pkg.meta.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    if not isinstance(repo, str) or not repo:
        return None

    cleaned = re.sub(r"^(git\+|git:|ssh://|git@)", "", repo).replace(":", "/", 1)
    parts = [p for p in re.sub(r"^https?//|^https?://", "", cleaned).split("/") if p]
    if len(parts) >= 2:
        return f"repo:{parts[0].lower()}/{parts[1].lower()}"
    return None


def _same_owner(a: Package, b: Package) -> bool:
    oa, ob = owner_of(a), owner_of(b)
    return oa is not None and oa == ob


# --------------------------------------------------------------------------
# indicator extraction
# --------------------------------------------------------------------------


def install_commands(pkg: Package) -> list[str]:
    hooks = ("preinstall", "install", "postinstall", "prepare", "prepublish")
    return [str(v) for k, v in (pkg.scripts or {}).items() if k in hooks and v]


def install_reachable(pkg: Package) -> list[str]:
    """Files named by install hooks, confined to the package directory."""
    root = pkg.source_dir
    if not root or not os.path.isdir(root):
        return []

    names: list[str] = []
    for cmd in install_commands(pkg):
        names += _SCRIPT_REF.findall(cmd)

    real_root = os.path.realpath(root)
    out: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name.startswith(("http:", "https:", "npm", "node_modules")):
            continue
        path = os.path.realpath(os.path.join(root, name))
        for candidate in (path, path + ".js", os.path.join(path, "index.js")):
            if candidate in seen:
                continue
            if not os.path.isfile(candidate) or os.path.islink(candidate):
                continue
            # realpath above resolved any symlink in the way; this is what
            # confirms the destination is still inside the package.
            if os.path.commonpath([real_root, candidate]) != real_root:
                continue
            seen.add(candidate)
            out.append(candidate)
            break
        if len(out) >= MAX_FILES_PER_PACKAGE:
            break
    return out


def _read(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _hosts(text: str, skip: set[str]) -> set[str]:
    found = set()
    for host in _URL.findall(text):
        host = host.split(":")[0].lower().rstrip(".")
        if not host or host in COMMON_HOSTS or host in skip:
            continue
        # A subdomain of somewhere everybody talks to is still somewhere
        # everybody talks to.
        if any(host.endswith("." + common) for common in COMMON_HOSTS):
            continue
        found.add(host)
    return found


def _own_hosts(pkg: Package) -> set[str]:
    """Hosts the package itself declares. Fetching from your own homepage is
    not a relationship with anybody else."""
    out = set()
    for key in ("repository", "homepage"):
        value = pkg.meta.get(key)
        if isinstance(value, dict):
            value = value.get("url")
        if isinstance(value, str):
            out |= {h.split(":")[0].lower() for h in _URL.findall(value)}
    return out


def publisher_changed(pkg: Package) -> str | None:
    """The account behind this version, when it is not the account behind the
    ones before it. Same condition as HEM502, because an established publisher
    releasing normally is not an indicator of anything."""
    current = pkg.meta.get("publisher")
    history = pkg.meta.get("prior_publishers") or []
    if current and history and current not in history:
        return str(current)
    return None


# --------------------------------------------------------------------------
# correlation
# --------------------------------------------------------------------------


class _Union:
    """Disjoint sets, so that A-B and B-C make one campaign rather than two."""

    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def correlate(packages: list[Package]) -> list[Campaign]:
    """Group packages that the evidence says arrived together.

    Returns campaigns of two or more. Everything else in this module exists to
    keep that list short.
    """
    by_key = {key_of(p): p for p in packages}
    if len(by_key) < 2:
        return []

    # Install-time source is read once here and handed to both extractors.
    # Both want the same files, and on a large tree the difference between
    # reading them once and reading them twice is most of the runtime.
    sources = {key: _install_sources(pkg) for key, pkg in by_key.items()}

    links: list[Link] = []
    links += _payload_links(by_key, sources)
    links += _shared_value_links(by_key, "endpoint",
                                 lambda pkg: _endpoint_values(pkg, sources[key_of(pkg)]))
    links += _shared_value_links(by_key, "publisher", _publisher_values)
    if not links:
        return []

    groups = _Union()
    for link in links:
        first = link.members[0]
        for other in link.members[1:]:
            groups.union(first, other)

    campaigns: dict[str, Campaign] = {}
    for link in links:
        root = groups.find(link.members[0])
        campaigns.setdefault(root, Campaign(label="")).links.append(link)

    out: list[Campaign] = []
    for camp in campaigns.values():
        members = sorted({m for ln in camp.links for m in ln.members})
        camp.members = [by_key[m] for m in members if m in by_key]
        if len(camp.members) < 2:
            continue
        camp.links.sort(key=lambda ln: (_KIND_ORDER.index(ln.kind), ln.display))
        camp.burst = _burst(camp.members)
        out.append(camp)

    # Biggest and most behavioural first; the label is assigned after sorting
    # so that C1 is the one a reader should look at.
    out.sort(key=lambda c: (-len(c.links_of("payload")), -len(c.members), c.members[0].name))
    for n, camp in enumerate(out, start=1):
        camp.label = f"C{n}"
    return out


_KIND_ORDER = ["payload", "endpoint", "publisher"]


def _install_sources(pkg: Package) -> list[tuple[str, str]]:
    """Every file an install would run, as (path relative to the package, text)."""
    out = []
    for path in install_reachable(pkg):
        text = _read(path)
        if text:
            out.append((os.path.relpath(path, pkg.source_dir or ""), text))
    return out


def _endpoint_values(pkg: Package, sources: list[tuple[str, str]]) -> set[str]:
    skip = _own_hosts(pkg)
    found: set[str] = set()
    for cmd in install_commands(pkg):
        found |= _hosts(cmd, skip)
    for _rel, text in sources:
        found |= _hosts(text, skip)
    return found


def _publisher_values(pkg: Package) -> set[str]:
    who = publisher_changed(pkg)
    return {who} if who else set()


def _shared_value_links(by_key: dict[str, Package], kind: str, extract) -> list[Link]:
    """Link packages that produced the same value, subject to the guards."""
    holders: dict[str, list[str]] = {}
    for key, pkg in by_key.items():
        for value in extract(pkg):
            holders.setdefault(value, []).append(key)

    links: list[Link] = []
    for value, keys in sorted(holders.items()):
        keys = sorted(set(keys))
        distinct_owners = _drop_same_owner(keys, by_key)
        if len(distinct_owners) < 2 or len(distinct_owners) > CROWD:
            continue
        links.append(Link(kind=kind, key=value, display=value, members=tuple(keys),
                          detail=_VALUE_DETAIL[kind].format(n=len(keys))))
    return links


_VALUE_DETAIL = {
    "endpoint": "reached from the install path of {n} packages",
    "publisher": "new to all {n} packages, and published them",
}


def _drop_same_owner(keys: list[str], by_key: dict[str, Package]) -> list[str]:
    """Count distinct owners when deciding whether a shared value is a link."""
    kept: list[str] = []
    seen_owners: set[str] = set()
    for key in keys:
        owner = owner_of(by_key[key])
        if owner is None:
            kept.append(key)
            continue
        if owner in seen_owners:
            continue
        seen_owners.add(owner)
        kept.append(key)
    return kept


def _payload_links(by_key: dict[str, Package], sources: dict[str, list[tuple[str, str]]]) -> list[Link]:
    """Link packages whose install-time code is the same code.

    Two passes, because the two cases have very different costs. Files that
    normalize to exactly the same fingerprint set -- which is what a payload
    copied into many packages produces, however differently each copy is
    written -- are grouped by that set in one dictionary pass, so a campaign
    across a thousand packages costs a thousand lookups rather than half a
    million comparisons.

    Only what is left over goes through the pairwise path, for the harder case
    of a payload pasted into a file that also contains something else. There
    the inverted index supplies the candidate pairs, which is the whole reason
    for winnowing rather than hashing whole files, and a fingerprint shared by
    a crowd of otherwise dissimilar files is dropped as an idiom.
    """
    sketches: dict[str, fp.Sketch] = {}
    owner: dict[str, str] = {}  # file id -> package key
    where: dict[str, str] = {}  # file id -> path relative to the package

    for key in by_key:
        for rel, text in sources[key]:
            lang = fp.language_of(rel)
            if not lang:
                continue
            sk = fp.sketch(text, lang)
            if not sk:
                continue
            fid = f"{key}::{rel}"
            sketches[fid] = sk
            owner[fid] = key
            where[fid] = rel

    if len(sketches) < 2:
        return []

    # Fingerprint set -> packages carrying it, so one Link describes the payload.
    matched: dict[frozenset[int], set[str]] = {}
    evidence: dict[frozenset[int], float] = {}
    matched_where: dict[frozenset[int], str] = {}

    # Pass one: exact agreement, in linear time.
    # Use the full fingerprint set here. Display labels are only identifiers.
    exact: dict[frozenset[int], list[str]] = {}
    for fid, sk in sketches.items():
        exact.setdefault(sk.prints, []).append(fid)
    for prints, fids in exact.items():
        owners = {owner[fid] for fid in fids}
        if len(owners) < 2:
            continue
        matched[prints] = owners
        evidence[prints] = 1.0
        matched_where[prints] = where[fids[0]]

    # Pass two: partial agreement, over one representative per distinct shape.
    residual = {fids[0]: sketches[fids[0]] for fids in exact.values()}
    for a, b in fp.candidates(residual):
        if owner[a] == owner[b]:
            continue
        if _same_owner(by_key[owner[a]], by_key[owner[b]]):
            continue
        sa, sb = sketches[a], sketches[b]
        if fp.shared_run(sa, sb) < SAME_CODE_FLOOR or fp.containment(sa, sb) < SAME_CODE:
            continue
        shared = sa.prints & sb.prints
        if shared in matched and evidence.get(shared) == 1.0:
            continue  # already reported as an exact group
        # Everything that normalized to either shape carries this payload, not
        # only the two representatives that were compared.
        group = {owner[fid] for fid in exact[sa.prints] + exact[sb.prints]}
        matched.setdefault(shared, set()).update(group)
        evidence[shared] = max(evidence.get(shared, 0.0), fp.similarity(sa, sb))
        matched_where.setdefault(shared, where[a])

    links: list[Link] = []
    for shared, keys in sorted(matched.items(), key=lambda item: fp.label_for(item[0])):
        # Require separate owners to form a link, then retain every affected
        # package. Dropping a scope's other members would hide detections.
        members = sorted(keys)
        if len(_drop_same_owner(members, by_key)) < 2:
            continue
        pct = round(evidence[shared] * 100)
        same = "identical" if pct == 100 else f"{pct}% identical"
        links.append(Link(
            kind="payload",
            key=fp.label_for(shared),
            display=f"payload {fp.label_for(shared)}",
            members=tuple(members),
            detail=f"{same} code in {plural(len(members), 'package')} under "
                   f"{plural(_owners(members, by_key), 'separate owner')}, compared after "
                   f"names and strings are removed (first seen as {matched_where[shared]})",
        ))
    return links


def _owners(keys: list[str], by_key: dict[str, Package]) -> int:
    """Distinct publishers behind a set of packages, counting every unknown
    owner as its own. Unknown is the common case for an unscoped npm package
    with no repository field, and treating them all as one would understate
    exactly the spread this is reporting."""
    known = {owner_of(by_key[k]) for k in keys if owner_of(by_key[k]) is not None}
    unknown = sum(1 for k in keys if owner_of(by_key[k]) is None)
    return len(known) + unknown


def plural(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _burst(members: list[Package]) -> str:
    """One line about publication timing, when the registry supplied it.

    Corroboration only. A tight window across packages already linked by their
    code says one push; the same window across unrelated packages says it was
    a Tuesday.
    """
    stamps = [p.meta.get("published_at") for p in members]
    stamps = [s for s in stamps if s is not None]
    if len(stamps) < 2:
        return ""
    span = max(stamps) - min(stamps)
    if span > BURST:
        return ""
    hours = span.total_seconds() / 3600
    when = "within the same hour" if hours < 1 else f"within {round(hours)} hours"
    return f"all {len(stamps)} versions published {when} of each other"


def for_package(campaigns: list[Campaign], pkg: Package) -> Campaign | None:
    """Which campaign, if any, this package belongs to.

    Called once per campaign rule per package, so the membership test is a set
    lookup rather than a walk: on a tree where one campaign holds hundreds of
    packages the walk is quadratic and shows up in a profile immediately.
    """
    key = key_of(pkg)
    for camp in campaigns:
        if key in camp.member_keys:
            return camp
    return None
