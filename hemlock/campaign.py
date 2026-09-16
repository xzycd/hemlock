"""Correlation: the findings that only exist between packages.

Every other part of this tool judges one package at a time. That is the right
unit for a typosquat, which is a fact about a single name, and it is the wrong
unit for the thing that has actually been happening to npm.

A modern compromise is not one bad package. It is one payload, pushed into
however many packages the stolen token could reach. Shai-Hulud put the same
`bundle.js` behind a `postinstall` in hundreds of them in a weekend, all
reporting to one webhook. Read one of those packages on its own and you get a
package that runs a script at install time and ships a file that is hard to
read: a medium, the kind of finding a busy repository has forty of. Read six
of them together and you get the incident.

The difference between those two readings is not a better rule. It is a
different unit of judgement, and this module is that unit. It looks for
evidence that two packages are the same operation:

- the same code, compared by shape so that renaming and re-minifying do not
  hide it (see `fingerprint.py`);
- the same network endpoint, once the places everybody talks to are removed;
- the same account, but only where that account is new to the packages it has
  just published.

Packages linked by any of those are one campaign, and the campaign is reported
through the ordinary rules HEM801-HEM803, in a category of its own. That is
deliberate: it means a correlated finding is weighted, suppressed, baselined,
serialized and explained by exactly the machinery everything else uses, and it
means the existing "categories that agree count for more" arithmetic does the
escalation without a second scoring system being invented for it.

The hard part is not finding links. It is not finding them everywhere. Five
guards do that work, and each one exists because without it something
enormous and entirely innocent lights up:

1. Only code that an install would actually execute is fingerprinted --
   scripts named by a hook, declared entry points -- rather than every file in
   the tree. A vendored copy of a helper library under `dist/` is shared by
   thousands of packages and means nothing.
2. Any indicator shared by more than `CROWD` packages is dropped as an idiom.
   Real campaigns are large but not universal, and a fingerprint held by four
   hundred packages is a common bundler prelude.
3. Packages that share an owner are never linked to each other. A monorepo
   publishes one helper in thirty packages under one scope, and that is a
   build system, not a campaign.
4. A publish burst is never a link by itself. Half a dependency tree moves in
   the same week for entirely boring reasons; timing corroborates a link that
   already exists, and proves nothing on its own.
5. Code with no structural variety is not compared at all -- see `MIN_PRINTS`
   in `fingerprint.py`. A barrel of re-exports and a generated constants table
   normalize to the same short pattern repeated, and would otherwise match
   each other and everything like them.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import timedelta

from . import fingerprint as fp
from .model import Package

# A value held by more than this many distinct owners is describing the
# ecosystem rather than an incident. It applies to hosts and accounts, where a
# popular endpoint or a busy organization account really can be shared by
# hundreds of unrelated packages for dull reasons.
#
# It deliberately does NOT apply to a shared payload. The first version of
# this capped that too, and the result was that a scan of fifteen hundred
# packages carrying one identical install script reported nothing at all: the
# cap read the largest possible compromise as the most ordinary idiom. Size is
# not evidence of innocence here. Several hundred packages under several
# hundred different owners shipping the same install-time code has one
# explanation, and it is the one this tool exists to print.
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
    """Files an install would run, as absolute paths that exist on disk.

    Three sources, in the order an attacker uses them: a file named directly
    by a hook, a declared binary, and the package's own entry point. Anything
    outside the package directory is refused -- a hook is free to name
    `../../etc/passwd`, and following that would read a file this scan has no
    business opening and attribute it to the package.
    """
    root = pkg.source_dir
    if not root or not os.path.isdir(root):
        return []

    names: list[str] = []
    for cmd in install_commands(pkg):
        names += _SCRIPT_REF.findall(cmd)

    doc = _installed_manifest(pkg)
    binv = doc.get("bin")
    if isinstance(binv, str):
        names.append(binv)
    elif isinstance(binv, dict):
        names += [v for v in binv.values() if isinstance(v, str)]
    if isinstance(doc.get("main"), str):
        names.append(doc["main"])

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


def _installed_manifest(pkg: Package) -> dict:
    """package.json fields the parser kept, without re-reading the file."""
    return {k: pkg.meta[k] for k in ("bin", "main", "repository") if k in pkg.meta}


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
        if len(keys) < 2 or len(keys) > CROWD:
            continue
        kept = _drop_same_owner(keys, by_key)
        if len(kept) < 2:
            continue
        links.append(Link(kind=kind, key=value, display=value, members=tuple(kept),
                          detail=_VALUE_DETAIL[kind].format(n=len(kept))))
    return links


_VALUE_DETAIL = {
    "endpoint": "reached from the install path of {n} packages",
    "publisher": "new to all {n} packages, and published them",
}


def _drop_same_owner(keys: list[str], by_key: dict[str, Package]) -> list[str]:
    """Collapse each owner to one representative.

    A shared value across thirty packages of one scope is one package as far
    as this is concerned. Keeping a single representative rather than
    discarding the whole group is what preserves the case that matters: one
    monorepo and one unrelated package sharing a payload is still a link, and
    it is the interesting one.
    """
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

    # payload label -> the packages carrying it, so that one Link describes one
    # payload rather than one pair.
    matched: dict[str, set[str]] = {}
    evidence: dict[str, float] = {}

    # Pass one: exact agreement, in linear time.
    exact: dict[str, list[str]] = {}
    for fid, sk in sketches.items():
        exact.setdefault(sk.label, []).append(fid)
    for label, fids in exact.items():
        owners = {owner[fid] for fid in fids}
        if len(owners) < 2:
            continue
        matched[label] = owners
        evidence[label] = 1.0
        where[label] = where[fids[0]]

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
        shared = fp.label_for(sa.prints & sb.prints)
        if shared in matched and evidence.get(shared) == 1.0:
            continue  # already reported as an exact group
        # Everything that normalized to either shape carries this payload, not
        # only the two representatives that were compared.
        group = {owner[fid] for fid in exact[sa.label] + exact[sb.label]}
        matched.setdefault(shared, set()).update(group)
        evidence[shared] = max(evidence.get(shared, 0.0), fp.similarity(sa, sb))
        where.setdefault(shared, where[a])

    links: list[Link] = []
    for shared, keys in sorted(matched.items()):
        # The same owner collapse the value links use. Pairwise rejection above
        # stops two packages of one scope linking to each other, but it does
        # not stop thirty of them each linking to the same outsider and
        # arriving here as one thirty-one member campaign. The outsider is the
        # finding; the scope behind it is one entry.
        members = _drop_same_owner(sorted(keys), by_key)
        if len(members) < 2:
            continue
        pct = round(evidence[shared] * 100)
        same = "identical" if pct == 100 else f"{pct}% identical"
        links.append(Link(
            kind="payload",
            key=shared,
            display=f"payload {shared}",
            members=tuple(members),
            detail=f"{same} code in {plural(len(members), 'package')} under "
                   f"{plural(_owners(members, by_key), 'separate owner')}, compared after "
                   f"names and strings are removed (first seen as {where[shared]})",
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
