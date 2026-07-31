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

from .ui import RAMP, RESET, code, width

GLYPHS = {
    "h": ["█ █", "█ █", "███", "█ █", "█ █"],
    "e": ["███", "█  ", "██ ", "█  ", "███"],
    "m": ["█   █", "██ ██", "█ █ █", "█   █", "█   █"],
    "l": ["█  ", "█  ", "█  ", "█  ", "███"],
    "o": ["███", "█ █", "█ █", "█ █", "███"],
    "c": ["███", "█  ", "█  ", "█  ", "███"],
    "k": ["█  █", "█ █ ", "██  ", "█ █ ", "█  █"],
}

SWEEP = ("#ffffff", 225)
TAIL = ("#7c7c8a", 243)

# Socrates drank it and the eyes are crossed out, which is the whole joke.
# It arrives after the wordmark has finished drawing rather than with it, so
# there is a beat and then a face.
FACE = [
    "█ █   █ █",
    " █     █ ",
    "█ █   █ █",
    "█       █",
    " ███████ ",
]
FACE_GAP = 4
# Below this the face would wrap and the mark would look broken instead of
# absent, so it does not appear at all.
FACE_MIN_WIDTH = 88

TAGLINE = "poison hemlock looks like parsley"
# Two columns a frame at 6ms lands the whole reveal near 200ms. Slower than
# that and it stops feeling like the program starting and starts feeling like
# the program hanging.
FRAME_SECONDS = 0.006
COLUMNS_PER_FRAME = 2
# Long enough to read as a separate beat, short enough that the whole mark
# still lands inside a third of a second.
FACE_BEAT = 0.07


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


def paint(rows: list[str], depth: int = 8, columns: int | None = None,
          highlight: int | None = None) -> list[str]:
    """Colour the wordmark, optionally revealed only up to `columns`."""
    out = []
    for r, row in enumerate(rows):
        tint, sweep = code(RAMP[r], depth), code(SWEEP, depth)
        visible = row if columns is None else row[:columns]
        if highlight is not None and 0 <= highlight < len(visible):
            head, tail = visible[:highlight], visible[highlight + 1:]
            out.append(f"{tint}{head}{sweep}{visible[highlight]}{tint}{tail}{RESET}")
        else:
            out.append(f"{tint}{visible}{RESET}")
    return out


def wants_animation(color: bool | int, stream=None) -> bool:
    stream = stream or sys.stdout
    return bool(
        color
        and stream.isatty()
        and not os.environ.get("CI")
        and not os.environ.get("HEMLOCK_NO_ANIMATION")
    )


def wants_face(columns: int | None = None) -> bool:
    return (width() if columns is None else columns) >= FACE_MIN_WIDTH


def mark(scale: int = 2, face: bool | None = None) -> list[str]:
    """The wordmark, with the face beside it when there is room for it."""
    rows = render(scale=scale)
    if face is None:
        face = wants_face()
    if not face:
        return rows
    grin = ["".join(ch * scale for ch in row) for row in FACE]
    return [f"{w}{' ' * FACE_GAP}{g}" for w, g in zip(rows, grin, strict=True)]


def _arrival(rows: list[str], depth: int, at: int) -> list[str]:
    """One frame with everything past `at` lit in the sweep colour, so the
    face lands instead of fading in."""
    return [f"{code(RAMP[r], depth)}{row[:at]}{code(SWEEP, depth)}{row[at:]}{RESET}"
            for r, row in enumerate(rows)]


def logo(color: bool | int = True, animate: bool = False, version: str = "", stream=None) -> str:
    """The full mark. Animates in place when asked, then returns the final frame."""
    depth = (8 if color else 0) if isinstance(color, bool) else int(color)
    stream = stream or sys.stdout
    word = render()
    span = max(len(r) for r in word)
    rows = mark()

    if animate:
        stream.write("\n")
        for step in range(0, span + COLUMNS_PER_FRAME, COLUMNS_PER_FRAME):
            if step:
                stream.write(f"\033[{len(word)}A")
            frame = paint(word, depth, columns=step, highlight=step - 1)
            stream.write("".join(f"\r\033[K  {line}\n" for line in frame))
            stream.flush()
            time.sleep(FRAME_SECONDS)
        if rows is not word and len(rows[0]) > span:
            stream.write(f"\033[{len(word)}A")
            stream.write("".join(f"\r\033[K  {line}\n" for line in _arrival(rows, depth, span)))
            stream.flush()
            time.sleep(FACE_BEAT)
        stream.write(f"\033[{len(word)}A")

    body = paint(rows, depth) if depth else rows
    lines = ["", *[f"  {line}" for line in body]]

    tail = TAGLINE if not version else f"{TAGLINE}   v{version}"
    lines.append(f"  {code(TAIL, depth)}{tail}{RESET}" if depth else f"  {tail}")
    lines.append("")
    return "\n".join(lines)
