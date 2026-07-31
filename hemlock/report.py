"""Output: terminal, Markdown, JSON, SARIF.

The terminal view does one thing: it makes the reason a package was flagged
readable without opening anything else. So every finding shows its evidence
inline and every result shows the arithmetic behind its score.

One exception to that, deliberately. A package on a public malware list is
not a score to be read and weighed, it is an instruction, so it gets a box
and skips the arithmetic entirely.

Drawing primitives live in `ui.py`. What follows is only the layout.
"""

from __future__ import annotations

import json
import os
import textwrap

from . import ui
from .model import CATEGORIES, RULES, Rule
from .scan import Report
from .score import arithmetic
from .ui import (
    ASCII,
    UNICODE,
    Ink,
    badge,
    color_depth,
    duration,
    gauge,
    link,
    linkify,
    panel,
    rail,
    registry_url,
    spinner_frame,
    visible,
    want_color,
    wants_links,
    width,
)

# Re-exported so `report` stays the one import a caller needs for output.
__all__ = [
    "ASCII", "UNICODE", "Ink", "badge", "color_depth", "duration", "gauge",
    "spinner_frame", "want_color", "wants_links", "width",
    "terminal", "terminal_diff", "as_json", "as_json_diff", "as_markdown",
    "as_markdown_diff", "as_sarif", "explain", "rule_table", "why", "headline",
]

MARK = {"critical": "full", "high": "full", "medium": "hollow", "low": "hollow", "clean": "trace"}
CHANGE_MARK = {"added": "+", "updated": "~", "removed": "-"}

# Left margin, coloured rail, space. Everything inside a result block hangs
# off column four.
INDENT = 4


class Removal:
    """Stands in for a Change on rows describing a dependency that left."""

    kind = "removed"
    was = None


# The single sentence printed above the results, chosen by the worst thing
# found. Ordered most alarming first; the first match wins. Both forms are
# spelled out because the verb changes with the count, not just the noun.
HEADLINES = [
    ("HEM701", "{n} package is on a public malware list.",
               "{n} packages are on a public malware list."),
    ("HEM204", "{n} package reads credentials from an install script.",
               "{n} packages read credentials from an install script."),
    ("HEM602", "{n} package was built somewhere other than the repository it points you at.",
               "{n} packages were built somewhere other than the repositories they point you at."),
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
    ("HEM702", "{n} package has a published advisory against the installed version.",
               "{n} packages have a published advisory against the installed version."),
    ("HEM201", "{n} package runs a script when it is installed.",
               "{n} packages run a script when they are installed."),
]


# --------------------------------------------------------------------------
# scan view
# --------------------------------------------------------------------------


def terminal(report: Report, ink: Ink, show_all: bool = False, fail_on: str = "") -> str:
    w, g = width(), ui.glyphs()
    uni = g is UNICODE
    out: list[str] = [""]

    counted = [plural(len(report.packages), "package")]
    # `check` has no manifests, and "0 manifests" in the header of a report
    # about two package names reads as a failure to find them.
    if report.manifests:
        counted.append(plural(len(report.manifests), "manifest"))
    counted += ["online" if report.online else "offline", duration(report.elapsed)]
    meta = f" {g['sep']} ".join(counted)

    subject = report.subject or _subject(report.root)
    out.append(_rule_line("hemlock", subject, meta, ink, g, w))
    out.append("")

    if report.scope:
        out.extend(f"  {ink(line, 'dim')}" for line in textwrap.wrap(report.scope, w - INDENT))
        out.append("")

    out.extend(_alarm(report, ink, w))

    if line := headline(report):
        out.append("  " + ink(line, "bold"))
        out.append("")

    shown = report.verdicts if show_all else report.flagged
    if not shown:
        out.extend(_all_clear(report, ink, w))

    # A rule flagging thirty packages on its own is one observation about a
    # project, not thirty. Printing it thirty times is how the finding that
    # actually failed the build ends up somewhere in the middle of a scroll.
    crowds = _crowds(shown, fail_on)
    penned = {id(v) for group in crowds for v in group}

    for v in shown:
        if id(v) not in penned:
            out.extend(_verdict_block(v, ink, g, w, uni, graph=report.graph))
    for group in crowds:
        out.extend(_crowd_block(group, ink, g, w))

    out.append(_summary(report, ink, g))
    out.extend(_verdict_line(report, ink, g, w, fail_on))
    out.extend(_footer(report, ink, g))
    out.append("")
    return _page(out)


# Below this a group is not worth collapsing; you may as well read them.
CROWD_MIN = 5
# High and critical are never collapsed, whatever the threshold is set to.
CROWD_SEVERITIES = ("low", "medium")
SEVERITY_RANK = ["low", "medium", "high", "critical"]


def _crowds(shown: list, fail_on: str = "") -> list[list]:
    """Packages flagged by exactly one rule, grouped where that rule is
    flagging a crowd of them.

    Nothing at or above the failing threshold is ever folded. Whatever broke
    the build gets its own block, however many of them there are.
    """
    ceiling = len(SEVERITY_RANK)
    if fail_on in SEVERITY_RANK:
        ceiling = SEVERITY_RANK.index(fail_on)

    solo: dict[str, list] = {}
    for v in shown:
        if len(v.findings) != 1 or v.severity not in CROWD_SEVERITIES:
            continue
        if SEVERITY_RANK.index(v.severity) >= ceiling:
            continue
        solo.setdefault(v.findings[0].rule.id, []).append(v)
    groups = [g for g in solo.values() if len(g) >= CROWD_MIN]
    return sorted(groups, key=lambda g: -max(v.score for v in g))


def _crowd_block(group: list, ink: Ink, g: dict, w: int) -> list[str]:
    """One rule, every package it caught. Nothing is hidden: the names are all
    here, they are just not each given five lines of their own."""
    worst = max(group, key=lambda v: v.score)
    sev, rule = worst.severity, group[0].findings[0].rule
    bar = f"  {rail(ink, sev)} "

    left = (f"{bar}{gauge(worst.score, sev, ink)}{ink(f'{worst.score:>5}', sev, 'bold')}"
            f"  {ink(rule.id, 'rule')}  {rule.title}")
    label = ink(plural(len(group), "package"), sev)
    lines = [left + " " * max(1, w - visible(left) - visible(label)) + label]

    names = ", ".join(sorted(v.package.name for v in group))
    for chunk in textwrap.wrap(names, w - INDENT - 4):
        lines.append(f"{bar}  {ink(chunk, 'dim')}")
    if rule.fix:
        for i, chunk in enumerate(textwrap.wrap(rule.fix, w - INDENT - 9)):
            lines.append(f"{bar}  {ink('fix', 'accent') if i == 0 else '   '}  {chunk}")
    lines.append("")
    return lines


def _verdict_line(report, ink: Ink, g: dict, w: int, fail_on: str) -> list[str]:
    """Why the exit code is what it is, naming the packages responsible.

    Without this, a project with forty low findings and one high one gives you
    a wall of output and a `1`, and no way to tell which line caused it.
    """
    if fail_on not in SEVERITY_RANK:
        return []
    blame = [v for v in report.flagged
             if v.severity in SEVERITY_RANK
             and SEVERITY_RANK.index(v.severity) >= SEVERITY_RANK.index(fail_on)]
    if not blame:
        return []
    names = ", ".join(v.package.name for v in blame[:4])
    if len(blame) > 4:
        names += f", and {len(blame) - 4} more"
    return [f"  {ink('exit 1', 'critical', 'bold')}  "
            + ink(f"{plural(len(blame), 'package')} at {fail_on} or above: {names}", "dim")]


def _page(lines: list[str]) -> str:
    """Trailing spaces are invisible on screen and noise in every other place
    the output ends up."""
    return "\n".join(line.rstrip() for line in lines)


def plural(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _subject(root: str) -> str:
    """What was scanned, short enough to sit in a header. The directory name
    identifies a project; the absolute path just pushes the metadata off."""
    return os.path.basename(os.path.abspath(root)) or root


def _rule_line(label: str, subject: str, meta: str, ink: Ink, g: dict, w: int) -> str:
    left = f"{label}  {subject} " if subject else f"{label} "
    fill = max(2, w - len(left) - len(meta) - 6)
    return (f"  {ink(label, 'accent', 'bold')}  {ink(subject, 'dim')} "
            f"{ink(g['line'] * fill, 'dim')}  {ink(meta, 'dim')}")


def _all_clear(report: Report, ink: Ink, w: int) -> list[str]:
    """The reward. It has to say what did not run, or it reads as a promise
    the tool cannot make."""
    offline_rules = sum(1 for r in RULES.values() if not r.online)
    online_rules = len(RULES) - offline_rules
    read = plural(len(report.packages), "package")
    if report.manifests:
        read += f", {plural(len(report.manifests), 'manifest')}"
    scope = (f"{read}, all {len(RULES)} checks ran." if report.online
             else f"{read}, {offline_rules} offline checks.")
    # `check` already carries its own line about what it could not read, and
    # saying it twice on one screen reads as a tool arguing with itself.
    tail = ("Nothing here matched, which is all a clean scan ever means."
            if report.online or report.scope else
            f"The {online_rules} that need the network did not run. "
            f"Add --online for registry, provenance and osv.dev.")

    body = textwrap.wrap(f"{scope} {tail}", w - INDENT)
    lines = [f"  {rail(ink, 'clean')} {ink('nothing flagged', 'clean', 'bold')}"]
    lines += [f"  {rail(ink, 'clean')} {ink(chunk, 'dim')}" for chunk in body]
    lines.append("")
    return lines


def _alarm(report: Report, ink: Ink, w: int) -> list[str]:
    """The one case that gets to interrupt: a version on a public malware
    list. A box, used exactly once. If everything is boxed then nothing is."""
    hits = report.malware
    if not hits:
        return []
    names = ", ".join(v.package.coord for v in hits[:3])
    if len(hits) > 3:
        names += f" and {len(hits) - 3} more"
    body = (
        f"{names} {'is' if len(hits) == 1 else 'are'} on a public malware list. "
        f"Remove {'it' if len(hits) == 1 else 'them'}, then rotate every credential "
        f"the install could reach."
    )
    wrapped = [ink(chunk, "critical") for chunk in textwrap.wrap(body, w - 8)]
    return panel("MALWARE", wrapped, ink, "critical", w) + [""]


def _verdict_block(v, ink: Ink, g: dict, w: int, uni: bool, change=None,
                   graph=None, marks: bool = False) -> list[str]:
    sev = v.severity
    bar = f"  {rail(ink, sev)} "
    lines = [_row(v, sev, change, ink, g, w, marks)]

    for i, f in enumerate(v.findings):
        last = i == len(v.findings) - 1
        branch = g["elbow"] if last else g["tee"]
        gutter = " " if last else ink(g["pipe"], "dim")
        lines.append(f"{bar}{ink(branch, 'dim')} {ink(f.rule.id, 'rule')}  {f.rule.title}")
        for line in f.evidence[:4]:
            for chunk in textwrap.wrap(line, w - INDENT - 12) or [line]:
                lines.append(f"{bar}{gutter}         {ink(linkify(chunk, ink), 'dim')}")

    if v.findings:
        lines.append(f"{bar}  " + ink(arithmetic(v, unicode=uni), "dim"))
        lines.extend(_tail(v, ink, g, w, graph, bar))
    lines.append("")
    return lines


def _tail(v, ink: Ink, g: dict, w: int, graph, bar: str) -> list[str]:
    """The two lines that turn a finding into something you can act on:
    where the package came from, and what to do about it."""
    out = []
    if graph is not None and v.package.kind == "package":
        route = _route(v.package, graph, g)
        if route:
            out.append(f"{bar}  {ink('via', 'dim')}  {ink(route, 'dim')}")

    remedy = next((f.rule.fix for f in v.findings if f.rule.fix), "")
    if remedy:
        for i, chunk in enumerate(textwrap.wrap(remedy, w - INDENT - 9)):
            label = ink("fix", "accent") if i == 0 else "   "
            out.append(f"{bar}  {label}  {chunk}")
    return out


def _route(pkg, graph, g: dict) -> str:
    if graph.is_direct(pkg.ecosystem, pkg.name):
        return ""
    paths = graph.paths_to(pkg.ecosystem, pkg.name, limit=1)
    if not paths:
        return ""
    return f" {g['chevron']} ".join(paths[0])


def _row(v, sev: str, change, ink: Ink, g: dict, w: int, marks: bool) -> str:
    """One result line: rail, gauge, score, change marker, ecosystem, name."""
    if v.package.kind == "manifest":
        tag, title = "file", v.package.origin
    else:
        tag = v.package.ecosystem
        name = f"{v.package.name} {v.package.version or v.package.spec or ''}".strip()
        title = link(name, registry_url(v.package.ecosystem, v.package.name, v.package.version), ink)
    if change is not None and getattr(change, "was", None):
        title += ink(f"  (was {change.was})", "dim")

    score = badge("MAL", ink) if v.certain else ink(f"{v.score:>5}", sev, "bold")
    label = badge("malware", ink) if v.certain else ink(sev, sev)
    marker = ""
    if marks:
        mark = CHANGE_MARK[change.kind] if change is not None else " "
        tone = "added" if change is not None and change.kind == "added" else "accent"
        marker = f"{ink(mark, tone)}  "

    left = (f"  {rail(ink, sev)} {gauge(v.score, sev, ink, full=v.certain)}"
            f"{score}  {marker}{ink(f'{tag:<4}', 'dim')}  {title}")
    pad = max(1, w - visible(left) - visible(label))
    return left + " " * pad + label


def _clean_row(v, change, ink: Ink, g: dict, w: int, marks: bool) -> str:
    """A package that changed and came back clean. 'We looked and it was fine'
    is the answer a reviewer is usually after."""
    return _row(v, "clean", change, ink, g, w, marks)


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

    bar, used = "", 0
    for sev in ("critical", "high", "medium", "low"):
        if not counts[sev]:
            continue
        blocks = min(max(1, round(span * counts[sev] / total)), span - used)
        bar += ink(g["on"] * blocks, sev)
        used += blocks
        if used >= span:
            break
    bar += ink(g["off"] * (span - used), "clean" if not used else "dim")

    bits = [f"{len(report.packages)} scanned"]
    for sev in ("critical", "high", "medium", "low"):
        if counts[sev]:
            bits.append(ink(f"{counts[sev]} {sev}", sev))
    if report.suppressed:
        bits.append(ink(f"{report.suppressed} suppressed", "dim"))
    if getattr(report, "baselined", 0):
        bits.append(ink(f"{report.baselined} known", "dim"))
    if not sum(counts.values()):
        bits.append(ink("all clear", "clean"))

    return f"  {bar}  " + ink(f" {g['sep']} ", "dim").join(bits)


def _footer(report: Report, ink: Ink, g: dict) -> list[str]:
    out = []
    if top := _top_rule(report):
        out.append(
            f"  {ink(g['chevron'], 'accent')} {ink(f'hemlock explain {top}', 'accent')}"
            f"   {ink('to read why any of these rules exist', 'dim')}"
        )
    if report.online and (report.http_calls or report.cache_hits):
        out.append(ink(f"  {report.http_calls} requests, {report.cache_hits} served from cache", "dim"))
    for warning in report.warnings:
        out.append("  " + ink("! " + warning, "dim"))
    return out


# --------------------------------------------------------------------------
# diff view
# --------------------------------------------------------------------------


def terminal_diff(report, ink: Ink) -> str:
    w, g = width(), ui.glyphs()
    uni = g is UNICODE
    by_name = {c.package.name: c for c in report.changes}
    out = [""]

    changed = len(report.changes)
    meta = f" {g['sep']} ".join(
        filter(None, [
            f"{changed} changed",
            f"{len(report.removed)} removed" if report.removed else "",
            f"{report.unchanged} unchanged",
        ])
    )
    scope = f"{report.base_label} {g['arrow']} {report.head_label}"
    out.append(_rule_line("hemlock diff", scope, meta, ink, g, w))
    out.append("")

    out.extend(_alarm(report, ink, w))

    if not changed:
        out.append(f"  {rail(ink, 'clean')} {ink('no dependencies were added or moved', 'clean')}")
        out.append("")
        return _page(out + _footer(report, ink, g) + [""])

    if line := headline(report):
        out.append("  " + ink(line, "bold"))
        out.append("")

    for v in report.flagged:
        out.extend(_verdict_block(v, ink, g, w, uni, change=by_name.get(v.package.name),
                                  graph=report.graph, marks=True))

    clean = [v for v in report.verdicts if v.score == 0]
    for v in clean:
        out.append(_clean_row(v, by_name.get(v.package.name), ink, g, w, marks=True))
    for pkg in report.removed:
        out.append(_removed_row(pkg, ink, g, w))
    if clean or report.removed:
        out.append("")

    out.append(_summary(report, ink, g))
    out.extend(_footer(report, ink, g))
    out.append("")
    return _page(out)


def _removed_row(pkg, ink: Ink, g: dict, w: int) -> str:
    left = (f"  {rail(ink, 'clean')} {gauge(0, 'clean', ink)}     "
            f"  {ink('-', 'removed')}  {ink(f'{pkg.ecosystem:<4}', 'dim')}  "
            f"{ink(pkg.name, 'removed')}")
    label = ink("removed", "dim")
    return left + " " * max(1, w - visible(left) - visible(label)) + label


# --------------------------------------------------------------------------
# markdown, for a pull request comment
# --------------------------------------------------------------------------

DOT = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪", "clean": "🟢"}
# Lets a bot find and replace its own comment instead of adding a new one to
# every push.
MARKER = "<!-- hemlock -->"
# A pull request comment holding two hundred rows is a comment nobody reads.
MD_ROWS = 20


def as_markdown(report: Report) -> str:
    out = [MARKER, "## hemlock", ""]
    out += _md_callout(report)
    if report.flagged:
        out += _md_table(report.flagged)
        out += _md_details(report.flagged)
    out.append(_md_footer(report, f"{len(report.packages)} scanned"))
    return "\n".join(out)


def as_markdown_diff(report) -> str:
    changes = {c.package.name: c for c in report.changes}
    out = [MARKER, "## hemlock", "",
           f"`{report.base_label}` → `{report.head_label}`", ""]
    out += _md_callout(report)
    if report.flagged:
        out += _md_table(report.flagged, changes)
        out += _md_details(report.flagged)
    scope = f"{len(report.changes)} changed, {report.unchanged} unchanged"
    out.append(_md_footer(report, scope))
    return "\n".join(out)


def _md_callout(report) -> list[str]:
    """GitHub renders these as coloured panels, which is the only colour a
    pull request comment gets."""
    line = headline(report)
    if report.malware:
        names = ", ".join(f"`{v.package.coord}`" for v in report.malware)
        return ["> [!CAUTION]",
                f"> {names} {'is' if len(report.malware) == 1 else 'are'} on a public "
                "malware list. Remove and rotate every credential the install could reach.",
                ""]
    if not line:
        return ["> [!NOTE]", "> Nothing flagged. A clean scan means nothing here matched, "
                "which is all it ever means.", ""]
    counts = report.counts()
    level = "WARNING" if counts["critical"] or counts["high"] else "NOTE"
    return [f"> [!{level}]", f"> {line}", ""]


def _md_table(flagged, changes: dict | None = None) -> list[str]:
    head = "| | Package | Score | Why |"
    rule = "|:--:|---|--:|---|"
    if changes is not None:
        head = "| | | Package | Score | Why |"
        rule = "|:--:|:--:|---|--:|---|"
    rows = [head, rule]
    for v in flagged[:MD_ROWS]:
        titles = [f.rule.title for f in v.findings]
        why = titles[0] + (f", and {len(titles) - 1} more" if len(titles) > 1 else "")
        score = "**malware**" if v.certain else str(v.score)
        cells = [DOT[v.severity], _md_name(v), score, why]
        if changes is not None:
            change = changes.get(v.package.name)
            cells.insert(1, f"`{CHANGE_MARK[change.kind]}`" if change else "")
        rows.append("| " + " | ".join(cells) + " |")
    rows.append("")
    if len(flagged) > MD_ROWS:
        # Say so rather than truncating quietly. A silently short list reads
        # as "that was everything".
        rows += [f"{len(flagged) - MD_ROWS} more, worst first. "
                 f"Run `hemlock scan .` locally for the rest.", ""]
    return rows


def _md_name(v) -> str:
    if v.package.kind == "manifest":
        return f"`{v.package.origin}`"
    url = registry_url(v.package.ecosystem, v.package.name, v.package.version)
    label = f"`{v.package.coord}`"
    return f"[{label}]({url})" if url else label


def _md_details(flagged) -> list[str]:
    out = ["<details>", "<summary>Evidence</summary>", ""]
    for v in flagged[:MD_ROWS]:
        out.append(f"**{v.package.coord}** &nbsp; {v.package.ecosystem} &nbsp; `{v.package.origin}`")
        out.append("")
        for f in v.findings:
            out.append(f"- `{f.rule.id}` {f.rule.title}")
            for line in f.evidence[:4]:
                out.append(f"  - `{_md_escape(line)}`")
        remedy = next((f.rule.fix for f in v.findings if f.rule.fix), "")
        if remedy:
            out.append("")
            out.append(f"*fix:* {remedy}")
        out.append("")
    out += ["</details>", ""]
    return out


def _md_escape(text: str) -> str:
    """Evidence is raw registry and lockfile text. Inside a code span the only
    character that can end it early is a backtick."""
    return text.replace("`", "'")


def _md_footer(report, scope: str) -> str:
    counts = report.counts()
    bits = [scope] + [f"{n} {sev}" for sev, n in counts.items() if n]
    if getattr(report, "baselined", 0):
        bits.append(f"{report.baselined} known")
    mode = "online" if report.online else "offline"
    return f"<sub>{' · '.join(bits)} · {mode} · hemlock {_version()}</sub>"


# --------------------------------------------------------------------------
# machine-readable
# --------------------------------------------------------------------------


def as_json(report: Report) -> str:
    payload = {
        "tool": "hemlock",
        "version": _version(),
        "root": report.root,
        "online": report.online,
        "manifests": report.manifests,
        "headline": headline(report),
        "malware": [v.package.coord for v in report.malware],
        "summary": {"scanned": len(report.packages), "suppressed": report.suppressed, **report.counts()},
        "warnings": report.warnings,
        "results": [_result(v) for v in report.flagged],
    }
    return json.dumps(payload, indent=2)


def as_json_diff(report) -> str:
    kinds = {c.package.name: c for c in report.changes}
    payload = {
        "tool": "hemlock",
        "version": _version(),
        "mode": "diff",
        "base": report.base_label,
        "head": report.head_label,
        "online": report.online,
        "headline": headline(report),
        "malware": [v.package.coord for v in report.malware],
        "summary": {
            "changed": len(report.changes),
            "removed": len(report.removed),
            "unchanged": report.unchanged,
            **report.counts(),
        },
        "removed": [{"ecosystem": p.ecosystem, "name": p.name} for p in report.removed],
        "warnings": report.warnings,
        "results": [
            {**_result(v),
             "change": kinds[v.package.name].kind if v.package.name in kinds else None,
             "previous": kinds[v.package.name].was if v.package.name in kinds else None}
            for v in report.flagged
        ],
    }
    return json.dumps(payload, indent=2)


def _result(v) -> dict:
    return {
        "ecosystem": v.package.ecosystem,
        "name": v.package.name,
        "version": v.package.version,
        "origin": v.package.origin,
        "direct": v.package.direct,
        "score": v.score,
        "severity": v.severity,
        "certain": v.certain,
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


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
HOME = "https://github.com/xzycd/hemlock"


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
                        "informationUri": HOME,
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
# explain / rules
# --------------------------------------------------------------------------


def explain(rule: Rule, ink: Ink) -> str:
    w, g = min(width(), 84), ui.glyphs()
    tags = [CATEGORIES[rule.category], f"weight {rule.weight}"]
    if rule.certain:
        tags.append("settles the verdict alone")
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
        out += ["  " + linkify(line, ink) for line in textwrap.wrap(" ".join(para.split()), w - 4)]
        out.append("")
    if rule.fix:
        for i, chunk in enumerate(textwrap.wrap(rule.fix, w - 10)):
            out.append(f"  {ink('fix', 'accent') if i == 0 else '   '}  {chunk}")
        out.append("")
    return _page(out)


def rule_table(ink: Ink, online_only: bool = False) -> str:
    g = ui.glyphs()
    out = [""]
    for cat, label in CATEGORIES.items():
        group = [r for r in RULES.values() if r.category == cat and (not online_only or r.online)]
        if not group:
            continue
        out.append(f"  {ink(label, 'accent', 'bold')}")
        for r in sorted(group, key=lambda r: r.id):
            weight = ink(" MAL", "critical") if r.certain else ink(f"{r.weight:>3}", "dim")
            bar = _weight_bar(r, ink, g)
            flag = ink(" online", "dim") if r.online else "       "
            out.append(f"    {ink(r.id, 'rule')}  {r.title:<52}{weight} {bar}{flag}")
        out.append("")
    out.append(
        f"  {ink(g['chevron'], 'accent')} {ink('hemlock explain <rule>', 'accent')}"
        f"   {ink('for the reasoning behind any of these', 'dim')}"
    )
    out.append("")
    return _page(out)


def _weight_bar(r: Rule, ink: Ink, g: dict, span: int = 6) -> str:
    """Weights are the argument nobody reads. Drawing them makes it obvious
    that HEM201 on its own is not meant to convict anything."""
    if r.certain:
        return ink(g["on"] * span, "critical")
    filled = min(span, max(1, round(span * r.weight / 55)))
    return ink(g["on"] * filled, "accent") + ink(g["off"] * (span - filled), "dim")


# --------------------------------------------------------------------------
# why
# --------------------------------------------------------------------------


def why(report, matches: list, ink: Ink) -> str:
    w, g = width(), ui.glyphs()
    out = [""]

    for verdict, pkg in matches:
        name = f"{pkg.name} {pkg.version or pkg.spec or ''}".strip()
        title = link(name, registry_url(pkg.ecosystem, pkg.name, pkg.version), ink)
        head = f"  {ink(title, 'bold')}  {ink(pkg.ecosystem, 'dim')}"
        if pkg.origin:
            head += ink(f"  {g['sep']}  {pkg.origin}", "dim")
        out.append(head)

        sev = verdict.severity if verdict else "clean"
        if verdict and verdict.findings:
            reading = badge("malware", ink) if verdict.certain else ink(f"{verdict.score}  {sev}", sev)
            out.append(f"  {gauge(verdict.score if verdict else 0, sev, ink, full=bool(verdict and verdict.certain))}"
                       f"  {reading}")
        out.append("")

        out.extend(_why_route(report.graph, pkg, ink, g))
        out.append("")

        if verdict and verdict.findings:
            out.append(f"  {ink('flagged', 'dim')}")
            for f in verdict.findings:
                out.append(f"    {ink(f.rule.id, 'rule')}  {f.rule.title}")
                for line in f.evidence[:3]:
                    for chunk in textwrap.wrap(line, w - 14) or [line]:
                        out.append(f"            {ink(linkify(chunk, ink), 'dim')}")
            remedy = next((f.rule.fix for f in verdict.findings if f.rule.fix), "")
            if remedy:
                out.append("")
                for i, chunk in enumerate(textwrap.wrap(remedy, w - 10)):
                    out.append(f"  {ink('fix', 'accent') if i == 0 else '   '}  {chunk}")
        else:
            out.append(f"  {ink('nothing flagged', 'clean')}")
        out.append("")

    return _page(out)


def _why_route(graph, pkg, ink: Ink, g: dict) -> list[str]:
    """A route drawn as a staircase rather than written on one line. Depth is
    the thing you are looking for, and depth is what indentation shows."""
    if graph and graph.is_direct(pkg.ecosystem, pkg.name):
        return [f"  {ink('asked for directly', 'clean')}"]
    routes = graph.paths_to(pkg.ecosystem, pkg.name, limit=3) if graph else []
    if not routes:
        return [f"  {ink('no path found; the lockfile does not record who asked for it', 'dim')}"]

    out = [f"  {ink('reached through', 'dim')}"]
    for n, route in enumerate(routes):
        if n:
            out.append(f"  {ink('or', 'dim')}")
        out.append(f"    {route[0]}")
        for depth, name in enumerate(route[1:], start=1):
            pad = "  " * (depth - 1)
            last = depth == len(route) - 1
            out.append(f"    {pad}{ink(g['elbow'], 'dim')} "
                       f"{ink(name, 'accent') if last else name}")
    return out


def _version() -> str:
    from . import __version__

    return __version__
