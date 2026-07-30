"""Core types and the rule registry.

A rule is a function that looks at one package and yields evidence strings.
No evidence, no finding. The registry holds the weights and the prose, so
rules stay small and the scoring stays in one place.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from textwrap import dedent

# Category codes double as the first digit of every rule id.
CATEGORIES = {
    "naming": "Identity and naming",
    "install": "Install-time execution",
    "code": "Code shape",
    "lockfile": "Pinning and integrity",
    "registry": "Registry trust",
    "provenance": "Build provenance",
    "intel": "Public intelligence",
}

SEVERITY_BANDS = [
    (85, "critical"),
    (60, "high"),
    (30, "medium"),
    (1, "low"),
    (0, "clean"),
]


@dataclass
class Package:
    """One dependency, as resolved from a manifest."""

    ecosystem: str  # "npm" | "pypi"
    name: str
    kind: str = "package"  # "manifest" for findings about a file, not a dependency
    version: str | None = None
    spec: str | None = None  # the range as written, e.g. "^4.1.0"
    resolved: str | None = None  # tarball / wheel URL from the lockfile
    integrity: str | None = None
    direct: bool = False
    dev: bool = False
    origin: str = ""  # manifest this came from, relative to scan root
    scripts: dict[str, str] = field(default_factory=dict)
    source_dir: str | None = None  # unpacked on disk (node_modules/…), if present
    meta: dict = field(default_factory=dict)  # registry payload, filled by --online

    @property
    def coord(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name

    def __hash__(self) -> int:
        return hash((self.ecosystem, self.name, self.version, self.origin))


@dataclass
class Rule:
    id: str
    title: str
    category: str
    weight: int
    explain: str
    online: bool
    check: Callable[[Package, Context], Iterable[str]]
    # A certain rule reports a fact somebody else has already established
    # rather than an inference of our own, so it settles the verdict alone
    # and skips the weighting entirely.
    certain: bool = False


@dataclass
class Finding:
    rule: Rule
    package: Package
    evidence: list[str]


@dataclass
class Verdict:
    """A package plus everything we found on it, scored."""

    package: Package
    findings: list[Finding]
    score: int
    base: int
    multiplier: float
    categories: list[str]
    parts: dict[str, int] = field(default_factory=dict)
    certain: bool = False

    @property
    def severity(self) -> str:
        for floor, name in SEVERITY_BANDS:
            if self.score >= floor:
                return name
        return "clean"


@dataclass
class Context:
    """Everything a rule might need beyond the package itself."""

    root: str
    online: bool = False
    packages: list[Package] = field(default_factory=list)
    fresh_days: int = 14
    registry = None  # hemlock.registry.Registry, set when online

    def dependents(self, pkg: Package) -> int:
        return sum(1 for p in self.packages if p.name != pkg.name)


RULES: dict[str, Rule] = {}


def rule(rid: str, *, title: str, category: str, weight: int, explain: str,
         online: bool = False, certain: bool = False):
    """Register a check. Yield one string per piece of evidence."""

    def register(fn):
        if rid in RULES:
            raise ValueError(f"duplicate rule id {rid}")
        if category not in CATEGORIES:
            raise ValueError(f"unknown category {category}")
        RULES[rid] = Rule(rid, title, category, weight, dedent(explain).strip(), online, fn, certain)
        return fn

    return register


def active_rules(online: bool, disabled: set[str]) -> Iterator[Rule]:
    for rid in sorted(RULES):
        r = RULES[rid]
        if r.online and not online:
            continue
        if rid in disabled:
            continue
        yield r
