"""Scoring.

Three ideas, each deliberately simple enough to argue with.

1. Every rule carries a weight, and the weights are grouped by category.

2. Within one category, extra signals are worth less than the first. Four
   findings about an install script are still one observation about an
   install script, so a category scores its heaviest hit plus 40% of the
   rest. Without this, any package with a busy `postinstall` maxes out.

3. Across categories, agreement counts for more. A near-miss name that also
   runs an install hook that also ships obfuscated code is three independent
   reasons to worry, so the base gets a 25% bump per additional category.

The arithmetic is printed under every result. If you disagree with a number,
you can see which one to change.
"""

from __future__ import annotations

from .model import Finding, Package, Verdict

ECHO = 0.4  # value of each additional finding within a category
CORROBORATION = 0.25  # bump per additional category that agrees


def score_package(pkg: Package, findings: list[Finding]) -> Verdict:
    if not findings:
        return Verdict(pkg, [], 0, 0, 1.0, [], {})

    by_category: dict[str, list[int]] = {}
    for f in findings:
        by_category.setdefault(f.rule.category, []).append(f.rule.weight)

    parts: dict[str, int] = {}
    for category, weights in by_category.items():
        weights.sort(reverse=True)
        parts[category] = round(weights[0] + ECHO * sum(weights[1:]))

    base = sum(parts.values())
    multiplier = 1.0 + CORROBORATION * (len(parts) - 1)
    total = min(100, round(base * multiplier))

    ordered = sorted(findings, key=lambda f: (-f.rule.weight, f.rule.id))
    return Verdict(pkg, ordered, total, base, multiplier, sorted(parts), parts)


def arithmetic(v: Verdict, unicode: bool = True) -> str:
    """The 'show your work' line printed under each result."""
    if not v.findings:
        return "0"
    times, arrow = ("×", "→") if unicode else ("x", "->")
    terms = " + ".join(f"{cat} {score}" for cat, score in sorted(v.parts.items(), key=lambda kv: -kv[1]))
    if v.multiplier == 1.0:
        return f"{terms} {arrow} {v.score}"
    capped = " capped" if round(v.base * v.multiplier) > 100 else ""
    return (
        f"{terms} = {v.base}  {times}{v.multiplier:.2f} "
        f"({len(v.parts)} categories agree)  {arrow}  {v.score}{capped}"
    )
