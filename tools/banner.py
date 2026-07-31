"""Render the wordmark to an SVG for the README.

Generated rather than screenshotted, so the banner cannot drift from the
palette. Change `RAMP` or the glyph table and re-run this; anything else and
the README ends up showing a version of the brand that no longer exists.

    python3 tools/banner.py

Writes docs/banner.svg.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hemlock import __version__, brand  # noqa: E402
from hemlock.ui import RAMP  # noqa: E402

# The terminal doubles the wordmark horizontally because a terminal cell is
# about twice as tall as it is wide, so a glyph drawn one cell per pixel comes
# out spindly. An SVG has square pixels and needs no such correction: scale 1
# art with square cells is the same shape the terminal ends up showing.
CELL = 30
PAD = 44
BACKDROP = "#0b0b10"
TAGLINE_FILL = "#7c7c8a"
VERSION_FILL = "#a78bfa"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"


def rows() -> list[str]:
    return brand.mark(scale=1, face=True)


def svg() -> str:
    art = rows()
    cols = max(len(r) for r in art)
    art_w, art_h = cols * CELL, len(art) * CELL
    text_h = 46
    w, h = art_w + PAD * 2, art_h + PAD * 2 + text_h

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" role="img" aria-label="hemlock">',
        f'<rect width="{w}" height="{h}" rx="14" fill="{BACKDROP}"/>',
    ]

    # One rect per lit cell, coloured by row the way the terminal paints it:
    # deep at the root, pale at the tip, like the stem the tool is named after.
    for r, line in enumerate(art):
        fill = RAMP[r][0]
        y = PAD + r * CELL
        run_start = None
        for c in range(len(line) + 1):
            lit = c < len(line) and line[c] == "█"
            if lit and run_start is None:
                run_start = c
            elif not lit and run_start is not None:
                x = PAD + run_start * CELL
                out.append(f'<rect x="{x}" y="{y}" width="{(c - run_start) * CELL}" '
                           f'height="{CELL}" fill="{fill}"/>')
                run_start = None

    baseline = PAD + art_h + 40
    out.append(
        f'<text x="{PAD}" y="{baseline}" font-family="{MONO}" font-size="26" '
        f'fill="{TAGLINE_FILL}">{brand.TAGLINE}'
        f'<tspan fill="{VERSION_FILL}">   v{__version__}</tspan></text>'
    )
    out.append("</svg>")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = os.path.join(root, "docs", "banner.svg")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(svg())
    print(f"wrote {os.path.relpath(target, root)}")
