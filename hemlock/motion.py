"""The line that moves while a scan is running.

A scan spends its time either walking a package list or waiting on a registry.
Neither of those redraws anything on its own, so the display runs on its own
thread and the work only leaves state behind for it to read. Before this, the
line was redrawn from inside the work loop, which meant a scan blocked for ten
seconds on osv.dev sat with a frozen spinner, looking exactly like a scan that
had died.

What moves stays honest about what it means. The bar is real progress through
a real list, and it never advances on its own. The spinner and the word are
time passing and claim nothing about how far along anything is.
"""

from __future__ import annotations

import random
import sys
import threading
import time

from . import ui

# Mostly things you do to a plant you are suspicious of. The list is long
# enough that a run of any length keeps turning up one you have not seen.
WORDS = [
    "Vibing", "Foraging", "Rummaging", "Sniffing", "Untangling", "Unpacking",
    "Sifting", "Prowling", "Squinting", "Combing", "Weeding", "Digging",
    "Peering", "Rooting", "Grazing", "Skulking", "Pondering", "Brooding",
    "Lurking", "Snooping", "Tasting", "Steeping", "Simmering", "Chewing",
    "Sniffing about", "Turning over", "Poking around", "Getting suspicious",
]

# How long one word stays up. Under about five seconds it reads as a slot
# machine and you end up watching it instead of the bar.
DWELL = (5.0, 10.0)

# Nothing is drawn for the first fraction of a second, so a scan that finishes
# in three milliseconds does not flash a progress bar on its way past.
QUIET_SECONDS = 0.15
# Redraw cadence. Twelve or so frames a second is smooth enough for a spinner
# and gentle enough not to flood a terminal on the far end of an ssh session.
TICK_SECONDS = 0.08

WORD_COLUMN = 20
BAR_SPAN = 14


def frame(word: str, label: str, done: int, total: int, elapsed: float,
          ink: ui.Ink, step: int, span: int = BAR_SPAN) -> str:
    """One rendered line. Pure, so a test can read it without a terminal."""
    g = ui.glyphs()
    filled = round(span * done / total) if total else 0
    bar = (ink(g["on"] * max(0, filled - 1), "accent")
           + (ui.pulse(g["on"], step, ink) if filled else "")
           + ink(g["off"] * (span - filled), "dim"))

    said = word + g["ellipsis"]
    pad = " " * max(1, WORD_COLUMN - len(said))
    counts = f"{done}/{total}" if total else ""
    parts = [p for p in (counts, label, ui.duration(elapsed)) if p]
    trail = "  {}  ".format(g["sep"]).join(parts)
    return (f"  {ui.pulse(ui.spinner_frame(step), step, ink)} "
            f"{ui.pulse(said, step, ink)}{pad}{bar}  {ink(trail, 'dim')}")


class Ticker:
    """Owns the live line: one daemon thread drawing, the work loop reporting.

    `update` is called from the hot loop and does nothing but rebind a tuple,
    which is a single atomic operation. That is the whole reason there is no
    lock here: the drawing thread reads a consistent snapshot either way, and
    the work loop never blocks on the display.
    """

    def __init__(self, ink: ui.Ink, stream=None, words: list[str] | None = None,
                 quiet: float = QUIET_SECONDS, tick: float = TICK_SECONDS,
                 dwell: tuple[float, float] = DWELL):
        self.ink = ink
        self.stream = stream or sys.stderr
        self.words = list(words or WORDS)
        self.quiet = quiet
        self.tick = tick
        self.dwell = dwell
        self.drew = False
        self._state = ("", 0, 0)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._rng = random.Random()

    # -- called from the work loop ----------------------------------------

    def update(self, label: str, done: int, total: int) -> None:
        self._state = (label, done, total)

    def __enter__(self) -> Ticker:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None
        # Only erase a line that was written, or a fast scan leaves a stray
        # escape sequence on stderr for nothing.
        if self.drew:
            self.stream.write("\r\033[K")
            self.stream.flush()
            self.drew = False

    # -- the thread --------------------------------------------------------

    def _loop(self) -> None:
        started = time.monotonic()
        word = self._rng.choice(self.words)
        until = started + self._rng.uniform(*self.dwell)
        step = 0

        while not self._stop.wait(self.tick):
            now = time.monotonic()
            if now - started < self.quiet:
                continue
            if now >= until:
                word = self._next(word)
                until = now + self._rng.uniform(*self.dwell)
            step += 1
            label, done, total = self._state
            try:
                self.stream.write(
                    "\r\033[K" + frame(word, label, done, total, now - started, self.ink, step)
                )
                self.stream.flush()
            except (ValueError, OSError):
                # The stream went away underneath us, which happens when the
                # process is being torn down. Stop drawing rather than raise
                # out of a daemon thread nobody is watching.
                return
            self.drew = True

    def _next(self, current: str) -> str:
        options = [w for w in self.words if w != current] or self.words
        return self._rng.choice(options)
