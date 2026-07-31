"""Terminal primitives: colour, glyphs, gauges, rails, panels, links.

Everything here is about how a line looks. `report.py` decides what goes on
it. Keeping the two apart is what stops a change to the palette turning into a
change to the wording.

Three things degrade, in this order. Colour drops from 24-bit to the 256
palette to nothing at all. Box drawing drops to ASCII when the terminal cannot
promise UTF-8. Hyperlinks disappear when nothing is there to click them. Each
of those falls back on its own, so a plain pipe on an old terminal still gets
readable output rather than a worse version of a nicer one.
"""

from __future__ import annotations

import os
import re
import shutil
import sys

RESET = "\033[0m"
BOLD = "\033[1m"

# (24-bit, xterm-256). Two families and nothing else. Severity is one warm
# ramp that heats up: grey, straw, ember, red. Purple is the brand, and it is
# never used to mean a severity, so the eye learns that anything purple is the
# tool talking about itself.
#
# The previous palette put magenta, orange, yellow, teal and green on the same
# screen. Five hues cannot be ranked at a glance, so a reader had to fall back
# on reading the numbers, which is what the colour was there to save them.
# Nothing here is fully saturated; a report is read for minutes at a time.
PALETTE = {
    "accent":   ("#a78bfa", 141),
    "critical": ("#dd5566", 167),
    "high":     ("#d47b45", 173),
    "medium":   ("#b8935a", 137),
    # Low sits close to dim on purpose. A wall of low findings is background,
    # and the one high finding behind it is what somebody opened this for.
    "low":      ("#7a8194", 103),
    "clean":    ("#6fae82", 108),
    "dim":      ("#6b6b78", 242),
    "rule":     ("#9a9ab8", 146),
    "paper":    ("#ffffff", 231),
    "added":    ("#b8935a", 137),
    "removed":  ("#6b6b78", 242),
}

# Deep at the root, pale at the tip, like the stem the tool is named after.
# The wordmark reads down it; the spinner cycles along it.
RAMP = [("#dcc9fb", 189), ("#c6adf3", 183), ("#af8fe8", 141), ("#9673d8", 135), ("#7d59c4", 98)]

UNICODE = {
    "full": "●", "hollow": "○", "trace": "·",
    "line": "─", "tee": "├", "pipe": "│", "elbow": "└",
    "on": "█", "off": "░", "sep": "·", "chevron": "›", "arrow": "→",
    "rail": "▌", "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "edge": "│",
    "ellipsis": "…",
}
ASCII = {
    # The tee is "+" rather than "|" so a finding branch stays distinguishable
    # from the rail running down the left of the block beside it.
    "full": "*", "hollow": "o", "trace": ".",
    "line": "-", "tee": "+", "pipe": "|", "elbow": "`",
    "on": "#", "off": ".", "sep": "-", "chevron": ">", "arrow": "->",
    "rail": "|", "tl": "+", "tr": "+", "bl": "+", "br": "+", "edge": "|",
    "ellipsis": "...",
}

# CSI colour codes and OSC sequences both have to come off before any width
# arithmetic, or every padded column drifts by the length of its escapes.
ESCAPES = re.compile(r"\033\][^\033\a]*(?:\033\\|\a)|\033\[[0-9;]*m")

# Anything osv.dev will resolve. Worth linking because the id on its own is
# the least useful part of an advisory.
ADVISORY = re.compile(r"\b(?:GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}"
                      r"|MAL-\d{4}-\d+|CVE-\d{4}-\d{4,}|PYSEC-\d{4}-\d+|OSV-\d{4}-\d+)\b")


# -- capability detection --------------------------------------------------


def color_depth(flag: str = "auto", stream=None) -> int:
    """0 for no colour, 8 for the 256 palette, 24 for direct colour."""
    stream = stream or sys.stdout
    if flag == "never":
        return 0
    if flag != "always":
        if os.environ.get("NO_COLOR") or not stream.isatty():
            return 0
    if os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit"):
        return 24
    term = os.environ.get("TERM", "")
    if term == "dumb":
        return 0
    # Terminals that only ever ship direct colour do not bother advertising it.
    if any(t in term for t in ("kitty", "alacritty", "ghostty", "wezterm")):
        return 24
    if os.environ.get("TERM_PROGRAM") in ("iTerm.app", "WezTerm", "ghostty", "vscode"):
        return 24
    return 8


def want_color(flag: str = "auto", stream=None) -> bool:
    return color_depth(flag, stream) > 0


def wants_links(stream=None) -> bool:
    """Hyperlinks are ignored by terminals that do not understand them, but
    not by files and pipes, where the escape ends up in the text."""
    stream = stream or sys.stdout
    return bool(stream.isatty() and os.environ.get("TERM") != "dumb"
                and not os.environ.get("HEMLOCK_NO_LINKS"))


def glyphs() -> dict[str, str]:
    encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    return UNICODE if "utf" in encoding else ASCII


def width() -> int:
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 110))


# -- ink -------------------------------------------------------------------


class Ink:
    """Applies colour, or does not. Everything drawn goes through one of these
    so that a plain run is the same code path with the escapes left out."""

    def __init__(self, color: bool | int = 0, links: bool = False):
        self.depth = (8 if color else 0) if isinstance(color, bool) else int(color)
        self.on = self.depth > 0
        self.links = bool(links)

    def __call__(self, text: str, *names: str) -> str:
        if not self.on or not names:
            return text
        codes = "".join(BOLD if n == "bold" else self.fg(n) for n in names)
        return codes + text + RESET

    def fg(self, name: str) -> str:
        return self._code(name, 38)

    def bg(self, name: str) -> str:
        return self._code(name, 48)

    def _code(self, name: str, plane: int) -> str:
        entry = PALETTE.get(name)
        return code(entry, self.depth, plane) if entry else ""


def code(entry: tuple[str, int], depth: int, plane: int = 38) -> str:
    """One palette entry, rendered at whatever the terminal can take."""
    hexcode, x256 = entry
    if depth >= 24:
        r, g, b = (int(hexcode[i:i + 2], 16) for i in (1, 3, 5))
        return f"\033[{plane};2;{r};{g};{b}m"
    return f"\033[{plane};5;{x256}m"


def visible(text: str) -> int:
    return len(ESCAPES.sub("", text))


# -- pieces ----------------------------------------------------------------


def badge(text: str, ink: Ink, tone: str = "critical") -> str:
    """Reverse-video label. The padding gives the background something to sit
    on, and is kept without colour so a badge occupies the same width either
    way. Columns are laid out around it."""
    if not ink.on:
        return f" {text} "
    return f"{ink.bg(tone)}{ink.fg('paper')}{BOLD} {text} {RESET}"


def gauge(score: int, severity: str, ink: Ink, span: int = 10, full: bool = False) -> str:
    """A score is a number people argue about. A bar is one they can read
    across eight packages without doing any arithmetic."""
    g = glyphs()
    if full:
        filled = span
    elif score <= 0:
        filled = 0
    else:
        filled = min(span, max(1, round(span * score / 100)))
    return ink(g["on"] * filled, severity) + ink(g["off"] * (span - filled), "dim") * (filled < span)


def rail(ink: Ink, tone: str) -> str:
    """The coloured edge down the left of a result. It is what makes a block
    of findings read as one package rather than as eight loose lines."""
    return ink(glyphs()["rail"], tone)


def panel(title: str, body: list[str], ink: Ink, tone: str, w: int, indent: str = "  ") -> list[str]:
    """A box. Used exactly once, for the one finding that is not a judgement
    call. If everything is in a box then nothing is."""
    g = glyphs()
    inner = w - len(indent) - 4
    head = f"{g['tl']}{g['line']} {title} "
    head += g["line"] * max(0, w - len(indent) - visible(head) - 1) + g["tr"]
    out = [indent + ink(head, tone)]
    for line in body:
        pad = " " * max(0, inner - visible(line))
        out.append(f"{indent}{ink(g['edge'], tone)}  {line}{pad}{ink(g['edge'], tone)}")
    out.append(indent + ink(g["bl"] + g["line"] * (w - len(indent) - 2) + g["br"], tone))
    return out


# -- links -----------------------------------------------------------------


def link(text: str, url: str, ink: Ink) -> str:
    if not ink.links or not url:
        return text
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


def registry_url(ecosystem: str, name: str, version: str | None = None) -> str:
    if ecosystem == "npm":
        base = f"https://www.npmjs.com/package/{name}"
        return f"{base}/v/{version}" if version else base
    if ecosystem == "pypi":
        base = f"https://pypi.org/project/{name}"
        return f"{base}/{version}/" if version else f"{base}/"
    return ""


def linkify(text: str, ink: Ink) -> str:
    """Turn advisory ids inside evidence into something clickable. Run this
    after wrapping: escape sequences have no width but `textwrap` counts them."""
    if not ink.links:
        return text
    return ADVISORY.sub(
        lambda m: link(m.group(0), f"https://osv.dev/vulnerability/{m.group(0)}", ink), text
    )


# -- misc ------------------------------------------------------------------


def duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    return f"{seconds:.1f}s"


def spinner_frame(step: int) -> str:
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if glyphs() is UNICODE else "|/-\\"
    return frames[step % len(frames)]


def pulse(text: str, step: int, ink: Ink) -> str:
    """Walk the ramp and walk back, so the colour breathes instead of
    restarting with a jolt every time it runs out of stops."""
    if not ink.on:
        return text
    swing = 2 * len(RAMP) - 2
    at = step % swing
    return code(RAMP[at if at < len(RAMP) else swing - at], ink.depth) + text + RESET


