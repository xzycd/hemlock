"""Output: terminal, JSON, SARIF.

The terminal view does one thing: it makes the reason a package was flagged
readable without opening anything else. So every finding shows its evidence
inline and every result shows the arithmetic behind its score.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import textwrap

from .model import CATEGORIES, RULES, Rule
from .scan import Report
from .score import arithmetic

RESET = "\033[0m"
STYLE = {
    # Purple leads the palette because that is what gives poison hemlock away:
    # the blotches on its stem are the one thing wild parsley does not have.
    "accent": "\033[38;5;141m",
    "critical": "\033[38;5;171m",
    "high": "\033[38;5;209m",
    "medium": "\033[38;5;179m",
    "low": "\033[38;5;109m",
    "clean": "\033[38;5;108m",
    "dim": "\033[38;5;243m",
    "rule": "\033[38;5;146m",
    "bold": "\033[1m",
}

UNICODE = {
    "full": "●", "hollow": "○", "trace": "·",
    "line": "─", "tee": "├", "pipe": "│", "elbow": "└",
    "on": "▇", "off": "░", "sep": "·", "chevron": "›",
}
ASCII = {
    "full": "*", "hollow": "o", "trace": ".",
    "line": "-", "tee": "|", "pipe": "|", "elbow": "`",
    "on": "#", "off": ".", "sep": "-", "chevron": ">",
}

MARK = {"critical": "full", "high": "full", "medium": "hollow", "low": "hollow", "clean": "trace"}

# The single sentence printed above the results, chosen by the worst thing
# found. Ordered most alarming first; the first match wins. Both forms are
# spelled out because the verb changes with the count, not just the noun.
HEADLINES = [
    ("HEM204", "{n} package reads credentials from an install script.",
               "{n} packages read credentials from an install script."),
    ("HEM202", "{n} package fetches and runs code at install time.",
               "{n} packages fetch and run code at install time."),
    ("HEM203", "{n} package decodes a hidden payload at install time.",
               "{n} packages decode a hidden payload at install time."),
    ("HEM502", "{n} package was published by an account that had not published it before.",
               "{n} packages were published by accounts that had not published them before."),
    ("HEM103", "{n} package name carries a look-alike character.",
               "{n} package names carry a look-alike character."),
    ("HEM301", "{n} package ships deliberately unreadable code.",
               "{n} packages ship deliberately unreadable code."),
    ("HEM101", "{n} package is a keystroke or two from one you probably meant.",
               "{n} packages are a keystroke or two from ones you probably meant."),
    ("HEM507", "{n} package has a published advisory against the installed version.",
               "{n} packages have a published advisory against the installed version."),
    ("HEM201", "{n} package runs a script when it is installed.",
               "{n} packages run a script when they are installed."),
]


class Ink:
    def __init__(self, enabled: bool):
        self.on = enabled

    def __call__(self, text: str, *names: str) -> str:
        if not self.on or not names:
            return text
        return "".join(STYLE.get(n, "") for n in names) + text + RESET


def want_color(flag: str) -> bool:
    if flag == "never":
        return False
    if flag == "always":
        return True
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def glyphs() -> dict[str, str]:
    encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    return UNICODE if "utf" in encoding else ASCII


def width() -> int:
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 110))


def _visible(text: str) -> int:
    return len(re.sub(r"\033\[[0-9;]*m", "", text))


# --------------------------------------------------------------------------


def terminal(report: Report, ink: Ink, show_all: bool = False) -> str:
    w, g = width(), glyphs()
    uni = g is UNICODE
    out: list[str] = [""]

    out.append(_header(report, ink, g, w))
    out.append("")

    if line := headline(report):
        out.append("  " + ink(line, "bold"))
        out.append("")

    shown = report.verdicts if show_all else report.flagged
    if not shown:
        out.append(f"  {ink(g['trace'], 'clean')}  nothing flagged")
        out.append("")

    for v in shown:
        out.extend(_verdict_block(v, ink, g, w, uni))

    out.append(_summary(report, ink, g))
    if top := _top_rule(report):
        out.append(
            f"  {ink(g['chevron'], 'accent')} {ink(f'hemlock explain {top}', 'accent')}"
            f"   {ink('to read why any of these rules exist', 'dim')}"
        )
    for warning in report.warnings:
        out.append("  " + ink("! " + warning, "dim"))
    out.append("")
    return "\n".join(out)


def _header(report: Report, ink: Ink, g: dict, w: int) -> str:
    mode = "online" if report.online else "offline"
    sep = f" {g['sep']} "
    meta = sep.join([f"{len(report.packages)} packages", f"{len(report.manifests)} manifests", mode])
    fill = max(2, w - len("hemlock") - len(meta) - 6)
    return (
        f"  {ink('hemlock', 'accent', 'bold')} "
        f"{ink(g['line'] * fill, 'dim')}  {ink(meta, 'dim')}"
    )


def _verdict_block(v, ink: Ink, g: dict, w: int, uni: bool) -> list[str]:
    sev = v.severity
    if v.package.kind == "manifest":
        tag, title = "file", v.package.origin
    else:
        tag = v.package.ecosystem
        title = f"{v.package.name} {v.package.version or v.package.spec or ''}".strip()

    head = (
        f"  {ink(g[MARK[sev]], sev)}  {ink(f'{v.score:>3}', sev, 'bold')}  "
        f"{ink(f'{tag:<4}', 'dim')}  {title}"
    )
    pad = max(1, w - _visible(head) - len(sev))
    lines = [head + " " * pad + ink(sev, sev)]

    for i, f in enumerate(v.findings):
        last = i == len(v.findings) - 1
        branch = g["elbow"] if last else g["tee"]
        gutter = " " if last else ink(g["pipe"], "dim")
        lines.append(f"     {ink(branch, 'dim')} {ink(f.rule.id, 'rule')}  {f.rule.title}")
        for line in f.evidence[:4]:
            for chunk in textwrap.wrap(line, w - 20) or [line]:
                lines.append(f"     {gutter}         {ink(chunk, 'dim')}")

    if v.findings:
        lines.append("       " + ink(arithmetic(v, unicode=uni), "dim"))
    lines.append("")
    return lines


def headline(report: Report) -> str | None:
    """One sentence naming the worst thing in the scan, in plain English."""
    fired: dict[str, set[str]] = {}
    for v in report.flagged:
        for f in v.findings:
            fired.setdefault(f.rule.id, set()).add(v.package.name)

    for rule_id, singular, plural in HEADLINES:
        if names := fired.get(rule_id):
            n = len(names)
            return (singular if n == 1 else plural).format(n=n)

    total = sum(report.counts().values())
    if total == 1:
        return "1 package is worth a look before your next install."
    if total:
        return f"{total} packages are worth a look before your next install."
    return None


def _top_rule(report: Report) -> str | None:
    best = None
    for v in report.flagged:
        for f in v.findings:
            if best is None or f.rule.weight > best.weight:
                best = f.rule
    return best.id if best else None


def _summary(report: Report, ink: Ink, g: dict, span: int = 18) -> str:
    counts = report.counts()
    total = max(len(report.packages), 1)
    flagged = sum(counts.values())

    bar = ""
    used = 0
    for sev in ("critical", "high", "medium", "low"):
        if not counts[sev]:
            continue
        blocks = max(1, round(span * counts[sev] / total))
        blocks = min(blocks, span - used)
        bar += ink(g["on"] * blocks, sev)
        used += blocks
        if used >= span:
            break
    bar += ink(g["off"] * (span - used), "dim")

    bits = [f"{len(report.packages)} scanned"]
    for sev in ("critical", "high", "medium", "low"):
        if counts[sev]:
            bits.append(ink(f"{counts[sev]} {sev}", sev))
    if report.suppressed:
        bits.append(ink(f"{report.suppressed} suppressed", "dim"))
    if not flagged:
        bits.append(ink("all clear", "clean"))

    return f"  {bar}  " + ink(f" {g['sep']} ", "dim").join(bits)


# --------------------------------------------------------------------------


def as_json(report: Report) -> str:
    payload = {
        "tool": "hemlock",
        "version": _version(),
        "root": report.root,
        "online": report.online,
        "manifests": report.manifests,
        "headline": headline(report),
        "summary": {"scanned": len(report.packages), "suppressed": report.suppressed, **report.counts()},
        "warnings": report.warnings,
        "results": [
            {
                "ecosystem": v.package.ecosystem,
                "name": v.package.name,
                "version": v.package.version,
                "origin": v.package.origin,
                "direct": v.package.direct,
                "score": v.score,
                "severity": v.severity,
                "scoring": {
                    "base": v.base,
                    "multiplier": round(v.multiplier, 2),
                    "categories": v.categories,
                    "per_category": v.parts,
                },
                "findings": [
                    {
                        "rule": f.rule.id,
                        "title": f.rule.title,
                        "category": f.rule.category,
                        "weight": f.rule.weight,
                        "evidence": f.evidence,
                    }
                    for f in v.findings
                ],
            }
            for v in report.flagged
        ],
    }
    return json.dumps(payload, indent=2)


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def as_sarif(report: Report) -> str:
    used = {f.rule.id: f.rule for v in report.flagged for f in v.findings}
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hemlock",
                        "version": _version(),
                        "informationUri": "https://github.com/hemlock-scan/hemlock",
                        "rules": [
                            {
                                "id": r.id,
                                "name": r.title,
                                "shortDescription": {"text": r.title},
                                "fullDescription": {"text": r.explain},
                                "properties": {"category": r.category, "weight": r.weight},
                            }
                            for r in sorted(used.values(), key=lambda r: r.id)
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule.id,
                        "level": SARIF_LEVEL[v.severity],
                        "message": {
                            "text": f"{v.package.name}@{v.package.version or v.package.spec}: "
                            f"{f.rule.title} ({'; '.join(f.evidence[:3])})"
                        },
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": v.package.origin or "."}}}
                        ],
                        "properties": {"score": v.score, "severity": v.severity},
                    }
                    for v in report.flagged
                    for f in v.findings
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2)


# --------------------------------------------------------------------------


def explain(rule: Rule, ink: Ink) -> str:
    w, g = min(width(), 84), glyphs()
    tags = [CATEGORIES[rule.category], f"weight {rule.weight}"]
    if rule.online:
        tags.append("needs --online")

    out = [
        "",
        f"  {ink(rule.id, 'accent', 'bold')}  {ink(rule.title, 'bold')}",
        "  " + ink(f" {g['sep']} ".join(tags), "dim"),
        "  " + ink(g["line"] * (w - 4), "dim"),
        "",
    ]
    for para in rule.explain.split("\n\n"):
        out += ["  " + line for line in textwrap.wrap(" ".join(para.split()), w - 4)]
        out.append("")
    return "\n".join(out)


def rule_table(ink: Ink, online_only: bool = False) -> str:
    g = glyphs()
    out = [""]
    for cat, label in CATEGORIES.items():
        group = [r for r in RULES.values() if r.category == cat and (not online_only or r.online)]
        if not group:
            continue
        out.append(f"  {ink(label, 'accent', 'bold')}")
        for r in sorted(group, key=lambda r: r.id):
            flag = ink("  online", "dim") if r.online else ""
            out.append(
                f"    {ink(r.id, 'rule')}  {r.title:<48}{ink(f'{r.weight:>3}', 'dim')}{flag}"
            )
        out.append("")
    out.append(
        f"  {ink(g['chevron'], 'accent')} {ink('hemlock explain <rule>', 'accent')}"
        f"   {ink('for the reasoning behind any of these', 'dim')}"
    )
    out.append("")
    return "\n".join(out)


def spinner_frame(step: int) -> str:
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if glyphs() is UNICODE else "|/-\\"
    return frames[step % len(frames)]


def progress_line(done: int, total: int, ink: Ink, span: int = 14) -> str:
    g = glyphs()
    filled = round(span * done / total) if total else 0
    bar = ink(g["on"] * filled, "accent") + ink(g["off"] * (span - filled), "dim")
    return (
        f"  {ink(spinner_frame(done), 'accent')} {ink('querying registries', 'dim')}  "
        f"{bar}  {ink(f'{done}/{total}', 'dim')}"
    )


def _version() -> str:
    from . import __version__

    return __version__
