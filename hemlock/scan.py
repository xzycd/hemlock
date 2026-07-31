"""The engine: find manifests, resolve packages, run rules, score."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from . import npm, pypi, rules  # noqa: F401  (importing rules registers them)
from .graph import Graph
from .graph import build as build_graph
from .model import Context, Finding, Package, Verdict, active_rules
from .policy import Policy
from .score import score_package


@dataclass
class Report:
    root: str
    # What the header calls this run. A scan names the directory; `check` has
    # no directory to name and says what it was handed instead.
    subject: str = ""
    # One line about what could not be looked at. `check` sets it, because a
    # package named on the command line has no source or lockfile to read and
    # a report that does not say so is claiming more than it found.
    scope: str = ""
    manifests: list[str] = field(default_factory=list)
    packages: list[Package] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)
    suppressed: int = 0
    online: bool = False
    warnings: list[str] = field(default_factory=list)
    http_calls: int = 0
    cache_hits: int = 0
    baselined: int = 0
    elapsed: float = 0.0
    graph: Graph | None = None

    @property
    def flagged(self) -> list[Verdict]:
        return [v for v in self.verdicts if v.score > 0]

    @property
    def malware(self) -> list[Verdict]:
        return [v for v in self.verdicts if v.certain]

    def worst(self) -> str:
        order = ["clean", "low", "medium", "high", "critical"]
        return max((v.severity for v in self.verdicts), key=order.index, default="clean")

    def counts(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in self.flagged:
            out[v.severity] += 1
        return out


def _stage(progress, label: str):
    """Give a progress callback a name for the phase it is reporting on."""
    if progress is None:
        return None
    return lambda done, total: progress(label, done, total)


def collect(root: str) -> tuple[list[str], list[Package]]:
    manifests, packages = [], []
    for module in (npm, pypi):
        for path in module.find_manifests(root):
            found = module.parse(path, root)
            if found:
                manifests.append(os.path.relpath(path, root))
                packages.extend(found)
    return manifests, _dedupe(packages)


def _dedupe(packages: list[Package]) -> list[Package]:
    """A lockfile can list the same package at the same version many times."""
    seen: dict[tuple, Package] = {}
    for p in packages:
        key = (p.ecosystem, p.name, p.version, p.origin)
        if key in seen:
            seen[key].direct = seen[key].direct or p.direct
        else:
            seen[key] = p
    return list(seen.values())


def run(root: str, policy: Policy, online: bool = False, progress=None) -> Report:
    started = time.perf_counter()
    manifests, packages = collect(root)
    report = Report(root=root, manifests=manifests, packages=packages, online=online)
    report.graph = build_graph(root, packages)

    ctx = Context(root=root, online=online, packages=packages, fresh_days=policy.fresh_days)

    if online and packages:
        enrich(report, ctx, packages, progress)

    run_rules(report, policy, online, packages, ctx,
              progress=_stage(progress, "applying rules"))
    report.elapsed = time.perf_counter() - started
    return report


def enrich(report: Report, ctx: Context, packages: list[Package], progress=None) -> None:
    """Fill in registry metadata, provenance and OSV records. Shared by
    `scan` and `check`, which differ only in where the package list came
    from."""
    from .http import Http
    from .intel import Osv
    from .registry import Registry

    http = Http()
    ctx.registry = Registry(http)
    # OSV goes first: it is one batched request for the whole list, and a
    # package already reported as malware makes everything else moot.
    Osv(http).enrich(packages, progress=_stage(progress, "checking osv.dev"))
    ctx.registry.enrich(packages, progress=_stage(progress, "querying registries"))
    report.http_calls, report.cache_hits = http.calls, http.hits
    if http.failures:
        report.warnings.append(
            f"{len(http.failures)} lookups failed, so some online rules were skipped "
            f"(first: {http.failures[0]})"
        )


ECOSYSTEMS = ("npm", "pypi")

# Without a project on disk there is no package.json, no source tree and no
# lockfile, so the install-time, code-shape and pinning rules have nothing to
# read. Saying which rules "ran" would be true and useless; this says which
# evidence existed.
CHECK_SCOPE = (
    "A name on the command line has no install scripts, no source and no lockfile "
    "entry behind it, so only the naming checks can speak offline. "
    "Add --online for osv.dev, build provenance and registry history."
)
CHECK_SCOPE_ONLINE = (
    "A name on the command line has no install scripts, no source and no lockfile "
    "entry behind it, so the install-time, code-shape and pinning checks had "
    "nothing to read. Scan the project itself for those."
)


def parse_spec(text: str, default: str = "npm") -> Package:
    """`chalk@5.6.1`, `pypi:requests==2.32.3`, `@types/node@20.1.0`."""
    ecosystem = default
    head, sep, rest = text.partition(":")
    if sep and head in ECOSYSTEMS:
        ecosystem, text = head, rest

    name, version = text, ""
    if ecosystem == "pypi" and "==" in text:
        name, _, version = text.partition("==")
    else:
        # npm scoped names open with @, so only a later one is the version.
        at = text.rfind("@")
        if at > 0:
            name, version = text[:at], text[at + 1:]

    return Package(ecosystem=ecosystem, name=name.strip(), version=version.strip() or None,
                   spec=version.strip() or None, direct=True, origin="(command line)")


def check(specs: list[Package], policy: Policy, online: bool = False, progress=None) -> Report:
    """Judge packages named on the command line, with no project around them.

    The point is the decision you make before `npm install`, not the audit you
    run afterwards.
    """
    started = time.perf_counter()
    subject = specs[0].coord if len(specs) == 1 else f"{len(specs)} packages"
    report = Report(root="", subject=subject, packages=specs, online=online,
                    scope=CHECK_SCOPE_ONLINE if online else CHECK_SCOPE)
    ctx = Context(root="", online=online, packages=specs, fresh_days=policy.fresh_days)

    if online and specs:
        enrich(report, ctx, specs, progress)

    run_rules(report, policy, online, specs, ctx,
              progress=_stage(progress, "applying rules"))
    report.elapsed = time.perf_counter() - started
    return report


def run_rules(report: Report, policy: Policy, online: bool, packages: list[Package],
              ctx: Context | None = None, progress=None) -> None:
    """Apply every active rule to every package and fill in the verdicts.

    Shared with `hemlock diff`, which runs the same rules over a much
    smaller list.
    """
    ctx = ctx or Context(root=report.root, online=online, packages=packages,
                         fresh_days=policy.fresh_days)
    checks = list(active_rules(online, policy.disable))

    for done, pkg in enumerate(packages, start=1):
        if progress:
            progress(done, len(packages))
        findings: list[Finding] = []
        # A manifest entry stands in for a file, so only the configuration
        # rules apply to it. A filename cannot be a typosquat.
        applicable = [c for c in checks if pkg.kind == "package" or c.category == "lockfile"]
        for check in applicable:
            try:
                evidence = [e for e in check.check(pkg, ctx) if e]
            except Exception as exc:
                report.warnings.append(f"{check.id} errored on {pkg.coord}: {exc}")
                continue
            if not evidence:
                continue
            if policy.suppresses(check.id, pkg.name):
                report.suppressed += 1
                continue
            findings.append(Finding(check, pkg, evidence))
        report.verdicts.append(score_package(pkg, findings))

    report.verdicts.sort(key=lambda v: (-v.score, v.package.name))
    for ig in policy.expired:
        report.warnings.append(f"expired suppression: {ig.rule} on {ig.package} (expired {ig.expires})")
