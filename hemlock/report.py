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
    band,
    clip,
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
    "terminal", "terminal_diff", "terminal_history", "as_json", "as_json_diff",
    "as_json_history", "as_markdown", "as_markdown_diff", "as_sarif", "explain",
    "rule_table", "why", "headline",
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
    # Above HEM101 on purpose. When a misspelled name fires both, "it does not
    # exist" is the sentence that answers the question, and "it is a keystroke
    # away from one that does" is the detail underneath it.
    ("HEM507", "{n} package is not on the registry at all.",
               "{n} packages are not on the registry at all."),
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
    crowds = _crowds(shown)
    penned = {id(v) for group in crowds for v in group}

    for v in shown:
        if id(v) not in penned:
            out.extend(_verdict_block(v, ink, g, w, uni, graph=report.graph))
    for group in crowds:
        out.extend(_crowd_block(group, ink, g, w, full_names=_at_or_above(group, fail_on)))

    out.append(_summary(report, ink, g))
    out.extend(_verdict_line(report, ink, g, w, fail_on))
    out.extend(_footer(report, ink, g))
    out.append("")
    return _page(out)


# Below this a group is not worth collapsing; you may as well read them.
CROWD_MIN = 5
# Critical is never collapsed, and neither is anything `certain`, which is the
# malware case. High is collapsed now: sixteen byte-identical high blocks on a
# monorepo scan is not sixteen findings, it is one finding and fifteen
# scrolls. Because a group keys on the whole signature, and a score is
# computed from the rule set, every member of a group carries the same score,
# so folding them loses nothing. What protects the reader is further down:
# a group at or above the failing threshold lists every name it holds.
CROWD_SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = ["low", "medium", "high", "critical"]


def _crowds(shown: list) -> list[list]:
    """Packages carrying the same set of findings, grouped where there is a
    crowd of them.

    Grouping keys on the whole signature rather than on a single rule. A
    fifty thousand package lockfile turned out to hold 4,745 flagged packages
    and nine distinct signatures, which is nine observations repeated, not
    4,745 of them. Keying on one rule left every multi-finding package to
    print on its own, which missed most of the repetition.
    """
    alike: dict[tuple, list] = {}
    for v in shown:
        if v.certain or not v.findings or v.severity not in CROWD_SEVERITIES:
            continue
        alike.setdefault(tuple(f.rule.id for f in v.findings), []).append(v)
    groups = [g for g in alike.values() if len(g) >= CROWD_MIN]
    return sorted(groups, key=lambda g: (-max(v.score for v in g), g[0].package.name))


def _at_or_above(group: list, fail_on: str) -> bool:
    if fail_on not in SEVERITY_RANK:
        return False
    floor = SEVERITY_RANK.index(fail_on)
    return any(SEVERITY_RANK.index(v.severity) >= floor for v in group)


# A group of two thousand packages is one observation and two thousand names.
# Past this many the names stop being a list you read and become a wall you
# scroll, so the rest are counted instead. Never silently: the line says how
# many were held back and where the full set is.
CROWD_NAMES = 24


def _crowd_block(group: list, ink: Ink, g: dict, w: int, full_names: bool = False) -> list[str]:
    """One signature, every package carrying it, on a handful of lines
    instead of a block each."""
    worst = max(group, key=lambda v: v.score)
    sev, rules = worst.severity, [f.rule for f in group[0].findings]
    bar = f"  {rail(ink, sev)} "

    ids = f" {g['sep']} ".join(r.id for r in rules)
    title = rules[0].title if len(rules) == 1 else f"{rules[0].title}, and {len(rules) - 1} more"
    left = (f"{bar}{gauge(worst.score, sev, ink)}{ink(f'{worst.score:>5}', sev, 'bold')}"
            f"  {ink(ids, 'rule')}  {title}")
    label = ink(plural(len(group), "package"), sev)
    lines = [left + " " * max(1, w - visible(left) - visible(label)) + label]

    ordered = sorted(v.package.name for v in group)
    # A group that broke the build is enumerated in full, however long that
    # runs. Anything below the threshold is context, and context gets a cap.
    names = ", ".join(ordered if full_names else ordered[:CROWD_NAMES])
    if not full_names and len(ordered) > CROWD_NAMES:
        names += f", and {len(ordered) - CROWD_NAMES:,} more"
    for chunk in textwrap.wrap(names, w - INDENT - 4):
        lines.append(f"{bar}  {ink(chunk, 'dim')}")

    for rule in rules:
        if rule.fix:
            head = ink("fix", "accent") if rule is rules[0] else ink("and", "dim")
            for i, chunk in enumerate(textwrap.wrap(rule.fix, w - INDENT - 9)):
                lines.append(f"{bar}  {head if i == 0 else '   '}  {chunk}")
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
    # The moment somebody is most likely to believe a clean tree means a clean
    # project is the moment they have just been told everything is fine.
    if report.online and not report.scope and report.manifests:
        lines += [f"  {rail(ink, 'clean')} {ink(chunk, 'dim')}"
                  for chunk in textwrap.wrap(HISTORY_HINT, w - INDENT)]
    lines.append("")
    return lines


HISTORY_HINT = ("This is the tree as it stands. hemlock history --online reads what it used to be, "
                "because a version you have already upgraded past was still installed at the time.")


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
# history view
# --------------------------------------------------------------------------

# The band is drawn against the whole period the report covers, so every row
# is on the same axis and two exposures can be compared by looking at them.
BAND = 28


def terminal_history(report, ink: Ink) -> str:
    w, g = width(), ui.glyphs()
    out: list[str] = [""]

    counted = [plural(len(report.commits), "commit"), plural(len(report.manifests), "manifest")]
    counted += ["online" if report.online else "offline", duration(report.elapsed)]
    subject = report.subject or _subject(report.root)
    out.append(_rule_line("hemlock history", subject, f" {g['sep']} ".join(counted), ink, g, w))
    out.append("")

    # Both of these keep the footer. A shallow clone is the ordinary reason a
    # repository looks like it has no history, and the line explaining that is
    # in there.
    if not report.manifests:
        return _page(out + [f"  {ink('no npm or Python manifests to follow', 'dim')}", ""]
                     + _history_footer(report, ink, g) + [""])
    if not report.commits:
        return _page(out + [f"  {ink('no commits have touched a manifest here', 'dim')}",
                            f"  {ink('history needs a git repository with a committed lockfile', 'dim')}", ""]
                     + _history_footer(report, ink, g) + [""])

    out.extend(_exposure_alarm(report, ink, w))

    if line := _history_headline(report):
        out.append("  " + ink(line, "bold"))
        out.append("")

    if report.package:
        out.extend(_timeline_block(report, ink, g, w))
        # The timeline colours a bad version red and stops there. Anyone who
        # ran this with --online and got a red row is owed the record behind
        # it and the thing to do about it.
        for window in report.windows:
            if window.malware or window.advisories:
                out.extend(_window_block(report, window, ink, g, w))
    elif report.windows:
        for window in report.windows:
            out.extend(_window_block(report, window, ink, g, w))
    else:
        out.extend(_history_all_clear(report, ink, w))

    out.append(_history_summary(report, ink, g))
    out.extend(_history_footer(report, ink, g))
    out.append("")
    return _page(out)


def _fraction(report, when) -> float:
    """Where a moment sits in the period the report covers, 0 to 1."""
    axis = report.axis
    if not axis:
        return 0.0
    first, last = axis
    total = (last - first).total_seconds()
    if total <= 0:
        return 0.0
    return min(1.0, max(0.0, (when - first).total_seconds() / total))


def _window_block(report, window, ink: Ink, g: dict, w: int) -> list[str]:
    sev = window.severity
    bar = f"  {rail(ink, sev)} "

    name = f"{window.name} {window.version}"
    title = link(name, registry_url(window.ecosystem, window.name, window.version), ink)
    mark = badge("MAL", ink) if window.malware else "     "
    left = (f"  {rail(ink, sev)} {gauge(0, sev, ink, full=bool(window.malware))}{mark}  "
            f"{ink(f'{window.ecosystem:<4}', 'dim')}  {title}")
    label = ink(_lasted(window), sev)
    out = [left + " " * max(1, w - visible(left) - visible(label)) + label]

    branches: list[str] = []
    for record in window.malware[:2]:
        aliases = f" ({', '.join(record['aliases'][:1])})" if record.get("aliases") else ""
        branches.append(ink(linkify(f"{record['id']}{aliases}: {clip(record['summary'], 60)}", ink), "dim"))
    if window.advisories:
        shown = ", ".join(window.advisories[:4])
        more = f" and {len(window.advisories) - 4} more" if len(window.advisories) > 4 else ""
        branches.append(ink(linkify(f"{shown}{more}", ink), "dim"))

    branches.append(f"{ink('entered ', 'dim')}{_moment(window.entered, window.bounded, ink)}")
    branches.append(f"{ink('left    ', 'dim')}" + (
        _moment(window.left, True, ink) if window.left
        else ink("still in the lockfile at HEAD", sev)))
    if window.tags:
        shipped = ", ".join(window.tags[:6])
        if len(window.tags) > 6:
            shipped += f" and {len(window.tags) - 6} more"
        branches.append(f"{ink('shipped ', 'dim')}{ink(shipped, sev)}"
                        + ink(f"  {plural(len(window.tags), 'tag')} cut while it was in the tree", "dim"))

    for i, line in enumerate(branches):
        elbow = g["elbow"] if i == len(branches) - 1 else g["tee"]
        out.append(f"{bar}{ink(elbow, 'dim')} {line}")

    drawn = band(_fraction(report, window.entered.when), _fraction(report, window.ended), ink, sev, BAND)
    axis = report.axis
    caption = f"{axis[0]:%Y-%m-%d} to today" if axis else ""
    out.append(f"{bar}  {drawn}  {ink(caption, 'dim')}")

    if remedy := _history_fix(window):
        for i, chunk in enumerate(textwrap.wrap(remedy, w - INDENT - 9)):
            out.append(f"{bar}  {ink('fix', 'accent') if i == 0 else '   '}  {chunk}")
    out.append("")
    return out


# What to do about a window depends on whether it closed. A malicious version
# you dropped last year is still an incident, because the install already
# happened. An advisory you dropped last year is not: it is gone.
ROTATE = ("Rotate every credential an install could reach in that window, then find out whether CI "
          "ran one. A build that installed it is where the tokens went.")
ROTATE_OPEN = ("This is still in the lockfile. Remove it first, then rotate every credential an "
               "install could reach, starting with whatever CI holds.")


def _history_fix(window) -> str:
    if window.malware:
        return ROTATE_OPEN if window.open else ROTATE
    if window.advisories and window.open:
        return RULES["HEM702"].fix
    return ""


def _moment(commit, bounded: bool, ink: Ink) -> str:
    when = f"{commit.when:%Y-%m-%d}" if bounded else f"at or before {commit.when:%Y-%m-%d}"
    return f"{ink(when, 'dim')}  {ink(commit.short, 'rule')}  {ink(clip(commit.subject, 46), 'dim')}"


def _lasted(window) -> str:
    days = window.days
    if days < 1:
        return f"{max(1, round(days * 24))} hours"
    if days < 60:
        return f"{round(days)} days"
    return f"{days / 30.44:.0f} months"


def _timeline_block(report, ink: Ink, g: dict, w: int) -> list[str]:
    """Every version of one package, against one axis.

    This is the offline half of the command, and it answers a question that
    comes up outside an incident: when did we take this, and what did we have
    before it.
    """
    out: list[str] = []
    for window in sorted(report.windows, key=lambda x: x.entered.when):
        sev = window.severity if window.severity != "clean" else "dim"
        drawn = band(_fraction(report, window.entered.when),
                     _fraction(report, window.ended), ink, sev, BAND)
        ended = "now" if window.open else f"{window.left.when:%Y-%m-%d}"
        dates = f"{window.entered.when:%Y-%m-%d} {g['arrow']} {ended}"
        left = (f"  {rail(ink, window.severity)} {ink(f'{window.ecosystem:<4}', 'dim')}  "
                f"{window.version:<14}  {drawn}  {ink(dates, 'dim')}")
        label = ink(_lasted(window), "dim")
        out.append(left + " " * max(1, w - visible(left) - visible(label)) + label)
    return out + [""] if out else out


def _exposure_alarm(report, ink: Ink, w: int) -> list[str]:
    hits = report.exposed
    if not hits:
        return []
    worst = max(hits, key=lambda x: x.days)
    names = ", ".join(sorted({h.coord for h in hits})[:3])
    if len({h.coord for h in hits}) > 3:
        names += f" and {len({h.coord for h in hits}) - 3} more"
    when = "and it is still there" if worst.open else f"until {worst.left.when:%Y-%m-%d}"
    body = (
        f"{names} sat in this lockfile for {_lasted(worst)}, {when}. "
        f"Anything an install could reach in that window should be treated as taken, "
        f"whatever the scan of your working tree says today."
    )
    wrapped = [ink(chunk, "critical") for chunk in textwrap.wrap(body, w - 8)]
    return panel("EXPOSED", wrapped, ink, "critical", w) + [""]


def _history_headline(report) -> str | None:
    if report.package:
        versions = len({(x.name, x.version) for x in report.windows})
        if not versions:
            return f'nothing matching "{report.package}" was ever pinned here.'
        line = (f"{plural(versions, 'version')} of {report.package} "
                f"{'has' if versions == 1 else 'have'} been in this lockfile")
        # A version that was taken, dropped and taken again is two spans and
        # one version, and a row count that disagrees with the sentence above
        # it is the kind of thing that costs a reader ten seconds.
        spans = len(report.windows)
        return f"{line}, across {spans} spans." if spans != versions else f"{line}."
    exposed = len({x.coord for x in report.exposed})
    if exposed:
        return (f"{exposed} version you once pinned is on a public malware list."
                if exposed == 1 else
                f"{exposed} versions you once pinned are on a public malware list.")
    flagged = len({x.coord for x in report.flagged})
    if flagged:
        return (f"{flagged} version you once pinned has a published advisory against it."
                if flagged == 1 else
                f"{flagged} versions you once pinned have published advisories against them.")
    return None


def _history_all_clear(report, ink: Ink, w: int) -> list[str]:
    if not report.online:
        body = (f"{report.coords} distinct versions were pinned here across "
                f"{plural(len(report.commits), 'commit')}. Nothing was checked against anything: "
                f"add --online to put every one of them past osv.dev, or name a package to see "
                f"when it came and went.")
        tone = "dim"
    else:
        # "Every version this project ever pinned" is a claim about the whole
        # project, and a capped log or a shallow clone makes it false.
        scope = ("every version this project ever pinned" if _ever(report) == "ever pinned"
                 else f"every version pinned across the {plural(len(report.commits), 'commit')} read")
        body = (f"{report.coords} versions went past osv.dev, and none is on a malware list or "
                f"carries an advisory. That is {scope}, which is what an install would have "
                f"resolved to at the time.")
        tone = "clean"
    lines = [f"  {rail(ink, 'clean')} {ink('never exposed' if report.online else 'read, not checked', tone, 'bold')}"]
    lines += [f"  {rail(ink, 'clean')} {ink(chunk, 'dim')}" for chunk in textwrap.wrap(body, w - INDENT)]
    lines.append("")
    return lines


def _ever(report) -> str:
    """"Ever" is a claim about the whole project. It stops being true the
    moment the log was capped or the clone was shallow."""
    return "in this window" if report.truncated or report.warnings else "ever pinned"


def _history_summary(report, ink: Ink, g: dict) -> str:
    bits = [plural(len(report.commits), "commit"), f"{report.coords} versions {_ever(report)}"]
    if report.exposed:
        bits.append(ink(f"{len({x.coord for x in report.exposed})} malicious", "critical"))
    advisories = len({x.coord for x in report.flagged}) - len({x.coord for x in report.exposed})
    if advisories > 0:
        bits.append(ink(f"{advisories} with advisories", "medium"))
    if span := report.span:
        bits.append(ink(f"{span[0]:%Y-%m-%d} to {span[1]:%Y-%m-%d}", "dim"))
    return "  " + ink(f" {g['sep']} ", "dim").join(bits)


def _history_footer(report, ink: Ink, g: dict) -> list[str]:
    out = []
    if report.truncated:
        out.append("  " + ink(f"! only the newest {len(report.commits)} manifest commits were read; "
                              f"raise it with --limit", "dim"))
    if report.online and (report.http_calls or report.cache_hits):
        out.append(ink(f"  {report.http_calls} requests, {report.cache_hits} served from cache", "dim"))
    for warning in report.warnings:
        out.append("  " + ink("! " + warning, "dim"))
    return out


def as_json_history(report) -> str:
    payload = {
        "tool": "hemlock",
        "version": _version(),
        "mode": "history",
        "root": report.root,
        "online": report.online,
        "package": report.package or None,
        "manifests": report.manifests,
        "range": {
            "commits": len(report.commits),
            "truncated": report.truncated,
            "from": report.span[0].isoformat() if report.span else None,
            "to": report.span[1].isoformat() if report.span else None,
        },
        "summary": {
            "versions": report.coords,
            "exposed": len({w.coord for w in report.exposed}),
            "with_advisories": len({w.coord for w in report.flagged}) - len({w.coord for w in report.exposed}),
        },
        "warnings": report.warnings,
        "windows": [
            {
                "ecosystem": w.ecosystem,
                "name": w.name,
                "version": w.version,
                "entered": {"sha": w.entered.sha, "date": w.entered.when.isoformat(),
                            "subject": w.entered.subject, "exact": w.bounded},
                "left": ({"sha": w.left.sha, "date": w.left.when.isoformat(), "subject": w.left.subject}
                         if w.left else None),
                "days": round(w.days, 2),
                "commits": w.commits,
                "tags": w.tags,
                "still_present": w.open,
                "malware": [m["id"] for m in w.malware],
                "advisories": w.advisories,
            }
            for w in report.windows
        ],
    }
    return json.dumps(payload, indent=2)


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
