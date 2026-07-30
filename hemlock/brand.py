"""The wordmark.

A five row block alphabet that knows seven letters, which is exactly enough
to spell one word. Carrying a general figlet font to render a fixed string
would be more code and less ours.

The animation is a left to right reveal, about a quarter of a second, and it
only runs where it can do no harm: an interactive terminal, colour enabled,
not under CI, and never in front of machine-readable output. Anything that
delays a pipe or corrupts a redirect has stopped being decoration and started
being a bug.
"""

from __future__ import annotations

import os
import sys
import time

GLYPHS = {
    "h": ["█ █", "█ █", "███", "█ █", "█ █"],
    "e": ["███", "█  ", "██ ", "█  ", "███"],
    "m": ["█   █", "██ ██", "█ █ █", "█   █", "█   █"],
    "l": ["█  ", "█  ", "█  ", "█  ", "███"],
    "o": ["███", "█ █", "█ █", "█ █", "███"],
    "c": ["███", "█  ", "█  ", "█  ", "███"],
    "k": ["█  █", "█ █ ", "██  ", "█ █ ", "█  █"],
}

# Deep at the root, pale at the tip, like the stem the tool is named after.
RAMP = ["\033[38;5;183m", "\033[38;5;177m", "\033[38;5;171m", "\033[38;5;135m", "\033[38;5;99m"]
SWEEP = "\033[38;5;225m"
RESET = "\033[0m"

TAGLINE = "poison hemlock looks like parsley"
# Two columns a frame at 6ms lands the whole reveal near 200ms. Slower than
# that and it stops feeling like the program starting and starts feeling like
# the program hanging.
FRAME_SECONDS = 0.006
COLUMNS_PER_FRAME = 2


def render(word: str = "hemlock", scale: int = 2) -> list[str]:
    """Terminal cells are about twice as tall as they are wide, so a glyph
    drawn one cell per pixel comes out spindly. Doubling horizontally is what
    makes it read as a logo rather than as ASCII art."""
    rows = ["" for _ in range(5)]
    for i, letter in enumerate(word):
        glyph = GLYPHS[letter]
        gap = " " * scale if i else ""
        for r in range(5):
            rows[r] += gap + "".join(ch * scale for ch in glyph[r])
    return rows


def paint(rows: list[str], columns: int | None = None, highlight: int | None = None) -> list[str]:
    """Colour the wordmark, optionally revealed only up to `columns`."""
    out = []
    for r, row in enumerate(rows):
        visible = row if columns is None else row[:columns]
        if highlight is not None and 0 <= highlight < len(visible):
            head, tail = visible[:highlight], visible[highlight + 1:]
            out.append(f"{RAMP[r]}{head}{SWEEP}{visible[highlight]}{RAMP[r]}{tail}{RESET}")
        else:
            out.append(f"{RAMP[r]}{visible}{RESET}")
    return out


def wants_animation(color: bool, stream=None) -> bool:
    stream = stream or sys.stdout
    return bool(
        color
        and stream.isatty()
        and not os.environ.get("CI")
        and not os.environ.get("HEMLOCK_NO_ANIMATION")
    )


def logo(color: bool = True, animate: bool = False, version: str = "", stream=None) -> str:
    """The full mark. Animates in place when asked, then returns the final frame."""
    stream = stream or sys.stdout
    rows = render()
    width = max(len(r) for r in rows)

    if animate:
        stream.write("\n")
        for step in range(0, width + COLUMNS_PER_FRAME, COLUMNS_PER_FRAME):
            if step:
                stream.write(f"\033[{len(rows)}A")
            frame = paint(rows, columns=step, highlight=step - 1)
            stream.write("".join(f"\r\033[K  {line}\n" for line in frame))
            stream.flush()
            time.sleep(FRAME_SECONDS)
        stream.write(f"\033[{len(rows)}A")

    body = paint(rows) if color else rows
    lines = ["", *[f"  {line}" for line in body]]

    tail = TAGLINE if not version else f"{TAGLINE}   v{version}"
    lines.append(f"  \033[38;5;243m{tail}\033[0m" if color else f"  {tail}")
    lines.append("")
    return "\n".join(lines)


def sigil(color: bool = True) -> str:
    """The one-line mark used in headers, where five rows would be rude."""
    return "\033[38;5;141m\033[1mhemlock\033[0m" if color else "hemlock"
