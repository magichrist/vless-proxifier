"""Small, dependency-free drawing helpers for the Textual front-end.

Why this module exists
----------------------
The TUI used to hand every colour and every glyph straight to Textual. That is
fine on a modern true-colour terminal, but the two terminals this tool is most
often run from -- macOS Terminal.app and a plain 256-colour SSH session -- do
not advertise 24-bit colour at all. Textual then quantises each hex value to the
nearest xterm-256 entry, which is a *different* colour from the one the theme
was measured against. On the cream ``gummy`` palette that is the difference
between "warm candy" and "muddy beige".

Two things fix that, and both live here rather than in ``theme.py`` because the
widgets need them too:

* **Capability detection** so the registry can pick a palette whose values are
  already part of the terminal's 256-colour cube (a lossless snap), instead of
  letting the renderer guess.
* **Small drawing primitives** -- gradients, a spinner, a meter -- that produce
  ``rich.text.Text`` spans. Keeping them pure means they can be unit-tested
  without a terminal, which is the only way the look can be pinned at all.

Nothing in this module imports Textual. That is deliberate: ``theme.py`` imports
it, and a cycle there would make the registry unimportable in the one place that
must never fail (start-up).
"""
from __future__ import annotations

import math
import os
import re
from collections.abc import Sequence
from functools import lru_cache

_HEX_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

#: Spinner frames, in the order they are drawn. Braille is used because it is a
#: single cell wide in every monospaced font shipped with macOS and every Linux
#: terminal font that renders box drawing at all -- the same reason the latency
#: bars use block elements rather than emoji.
SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

#: A slow, two-frame "breath" used by idle indicators. Two frames rather than a
#: gradient sweep keeps the refresh cheap and, more importantly, unobtrusive:
#: something that moves quickly in the corner of a terminal reads as an error.
PULSE_FRAMES = ("●", "◉")

#: Progress meter cells, empty then full. Eight steps per cell are unnecessary
#: here -- this is a coarse progress readout, not a measurement.
METER_EMPTY = "░"
METER_FULL = "█"


def _normalise(colour: str) -> str:
    """Expand ``#RGB`` to ``#RRGGBB``; raise on anything else.

    A malformed colour in a span would be silently ignored by Rich and the
    widget would fall back to the ambient colour, which looks like a theme bug.
    Failing here names the offending value instead.
    """
    value = colour.strip()
    if not _HEX_RE.match(value):
        raise ValueError(f"expected a #RGB or #RRGGBB colour, got {colour!r}")
    if len(value) == 4:
        value = "#" + "".join(channel * 2 for channel in value[1:])
    return value.lower()


def rgb(colour: str) -> tuple[int, int, int]:
    """``#RRGGBB`` -> ``(r, g, b)``."""
    value = _normalise(colour)
    return tuple(int(value[index : index + 2], 16) for index in (1, 3, 5))  # type: ignore[return-value]


def luminance(colour: str) -> float:
    """Relative luminance per WCAG 2.2, in 0..1.

    The same formula the theme tests use. It lives here so a widget can decide
    whether a *rendered* colour is legible on the surface it is about to paint,
    rather than trusting that the palette pair it picked was the pair measured.
    """
    def channel(value: int) -> float:
        scaled = value / 255
        return scaled / 12.92 if scaled <= 0.04045 else ((scaled + 0.055) / 1.055) ** 2.4

    red, green, blue = (channel(value) for value in rgb(colour))
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


@lru_cache(maxsize=512)
def contrast_ratio(first: str, second: str) -> float:
    """WCAG contrast ratio between two colours, 1.0..21.0."""
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


@lru_cache(maxsize=256)
def readable_mix(
    foreground: str,
    ground: str,
    *,
    preferred: float = 0.42,
    minimum: float = 4.5,
) -> str:
    """Blend ``foreground`` toward ``ground`` as far as ``minimum`` contrast allows.

    Widgets want a *muted* tone for secondary text -- a count, a label, a
    separator -- and the naive version of that is a fixed blend. That works on
    the dark palette and fails badly on the light one, where blending ink into
    cream crosses 4.5:1 after about a quarter of the way. So the blend is capped
    by measurement instead of by taste: the requested amount is used when it is
    still legible, and bisected down to the largest legible amount otherwise.

    If even the unblended foreground cannot clear the bar, it is returned as-is;
    at that point the palette is wrong and no amount of blending will save it.
    """
    if contrast_ratio(foreground, ground) < minimum:
        return foreground
    if contrast_ratio(mix(foreground, ground, preferred), ground) >= minimum:
        return mix(foreground, ground, preferred)
    low, high = 0.0, preferred
    for _ in range(12):
        middle = (low + high) / 2
        if contrast_ratio(mix(foreground, ground, middle), ground) >= minimum:
            low = middle
        else:
            high = middle
    return mix(foreground, ground, low)


@lru_cache(maxsize=256)
def legible(colour: str, ground: str, *, minimum: float = 4.5) -> str:
    """Darken or lighten ``colour`` until it clears ``minimum`` on ``ground``.

    The palette's accents are measured against the *screen background*, but a
    widget may paint them on a different surface -- the status strip uses
    ``$panel``, which on the light palette is pink rather than cream. One accent
    pair can clear the bar on one and miss it on the other (the light theme's
    error red is 4.65 on cream and 4.20 on pink). Rather than maintain a second
    matrix of every accent against every surface, the colour is nudged toward
    black on a light ground or white on a dark one, by the smallest amount that
    satisfies the ratio. The hue survives; only its lightness moves.
    """
    if contrast_ratio(colour, ground) >= minimum:
        return colour
    target = "#000000" if luminance(ground) >= 0.5 else "#ffffff"
    low, high = 0.0, 1.0
    for _ in range(14):
        middle = (low + high) / 2
        if contrast_ratio(mix(colour, target, middle), ground) >= minimum:
            high = middle
        else:
            low = middle
    return mix(colour, target, high)


def hex_colour(channels: Sequence[int]) -> str:
    """``(r, g, b)`` -> ``#rrggbb``, clamped to the byte range."""
    red, green, blue = (max(0, min(255, int(round(channel)))) for channel in channels)
    return f"#{red:02x}{green:02x}{blue:02x}"


def mix(first: str, second: str, amount: float) -> str:
    """Linear blend of two colours. ``amount=0`` is ``first``; ``1`` is ``second``.

    Linear in sRGB, not in a perceptual space. That is a real limitation -- a
    blend between complementary hues can pass through a dull midpoint -- but
    every blend this UI performs is between neighbouring hues on the same
    palette, where the difference is not visible and the extra code would be.
    """
    amount = max(0.0, min(1.0, amount))
    left, right = rgb(first), rgb(second)
    return hex_colour(
        [left[index] + (right[index] - left[index]) * amount for index in range(3)]
    )


def gradient(colour: str, stops: Sequence[str], *, phase: float = 0.0) -> list[str]:
    """One colour per character of ``colour``, interpolated across ``stops``.

    ``phase`` shifts the gradient cyclically, which is what turns a static
    wordmark into a shimmer without redrawing it character by character from
    the caller. A phase of 0 is a plain left-to-right gradient.
    """
    if not colour:
        return []
    palette = [_normalise(stop) for stop in stops]
    if not palette:
        # There is no sensible colour to fall back to: the argument is a string
        # of text, not a colour. A silent default would paint the wordmark in
        # whatever the ambient style happens to be, which is the kind of bug
        # that gets reported as "the gradient is broken on my machine".
        raise ValueError("gradient() needs at least one stop")
    if len(palette) == 1:
        return palette * len(colour)

    # Duplicate the first stop at the end so the loop is continuous; without it
    # the last character would jump back to the first colour.
    loop = palette + [palette[0]]
    span = len(loop) - 1
    out: list[str] = []
    for index in range(len(colour)):
        position = (index / max(1, len(colour) - 1) + phase) % 1.0
        scaled = position * span
        left = int(scaled)
        fraction = scaled - left
        out.append(mix(loop[left], loop[left + 1], fraction))
    return out


def shimmer(base: str, highlight: str, *, phase: float) -> str:
    """Brighten ``base`` by an amount that fades away from a moving highlight.

    Used only while the app is busy. The falloff is a cosine window so the
    highlight has no visible edge as it travels across a row of glyphs.
    """
    distance = abs(((phase % 1.0) * 2.0) - 1.0)
    strength = 0.5 * (1.0 + math.cos(min(1.0, distance) * math.pi))
    return mix(base, highlight, 0.55 * strength)


def spinner(tick: int) -> str:
    """The spinner frame for ``tick``; total for every integer."""
    return SPINNER_FRAMES[tick % len(SPINNER_FRAMES)]


def pulse(tick: int) -> str:
    """The idle indicator glyph for ``tick``."""
    return PULSE_FRAMES[tick % len(PULSE_FRAMES)]


def meter(done: int, total: int, *, width: int = 8) -> str:
    """A coarse progress meter: ``████░░░░``.

    ``total <= 0`` renders an empty bar rather than dividing by zero. The result
    always occupies exactly ``width`` cells so the caller can pad around it.
    """
    width = max(1, width)
    if total <= 0:
        return METER_EMPTY * width
    filled = int(round(width * max(0, min(done, total)) / total))
    return METER_FULL * filled + METER_EMPTY * (width - filled)


def supports_truecolor() -> bool:
    """Whether the current terminal advertises 24-bit colour.

    ``COLORTERM`` is the only signal that is actually a *capability* claim;
    ``TERM_PROGRAM`` is a vendor list. Both are checked because Terminal.app
    sets neither ``COLORTERM`` nor a true-colour ``TERM`` and is the exact case
    this function exists to detect, while several GUI terminals set only
    ``TERM_PROGRAM``.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("COLORTERM", "").lower() in {"truecolor", "24bit"}:
        return True
    program = os.environ.get("TERM_PROGRAM", "").lower()
    if program in {
        "iterm.app",
        "wezterm",
        "vscode",
        "ghostty",
        "hyper",
        "tabby",
        "vscodium",
        "rio",
        "warpterminal",
    }:
        return True
    term = os.environ.get("TERM", "").lower()
    return "direct" in term or "truecolor" in term


def palette_mode() -> str:
    """``"truecolor"`` or ``"256"`` -- the palette family the UI should use."""
    return "truecolor" if supports_truecolor() else "256"


__all__ = [
    "METER_EMPTY",
    "METER_FULL",
    "PULSE_FRAMES",
    "SPINNER_FRAMES",
    "contrast_ratio",
    "gradient",
    "hex_colour",
    "legible",
    "luminance",
    "meter",
    "mix",
    "palette_mode",
    "pulse",
    "readable_mix",
    "rgb",
    "shimmer",
    "spinner",
    "supports_truecolor",
]
