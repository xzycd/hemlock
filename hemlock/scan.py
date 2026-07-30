"""The engine: find manifests, resolve packages, run rules, score."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import npm, pypi, rules  # noqa: F401  (importing rules registers them)
from .model import Context, Finding, Package, Verdict, active_rules
from .policy import Policy
from .score import score_package


@dataclass
class Report:
    root: str
    manifests: list[str] = field(default_factory=list)
    packages: list[Package] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)
    suppressed: int = 0
    online: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> list[Verdict]:
        return [v for v in self.verdicts if v.score > 0]

    def worst(self) -> str:
        order = ["clean", "low", "medium", "high", "critical"]
        return max((v.severity for v in self.verdicts), key=order.index, default="clean")

    def counts(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in self.flagged:
            out[v.severity] += 1
        return out


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
    manifests, packages = collect(root)
    report = Report(root=root, manifests=manifests, packages=packages, online=online)

    ctx = Context(root=root, online=online, packages=packages, fresh_days=policy.fresh_days)

    if online and packages:
        from .registry import Registry

        reg = Registry()
        ctx.registry = reg
        reg.enrich(packages, progress=progress)
        if reg.failures:
            report.warnings.append(f"{len(reg.failures)} registry lookups failed; those rules were skipped")

    checks = list(active_rules(online, policy.disable))
    for pkg in packages:
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
    return report
