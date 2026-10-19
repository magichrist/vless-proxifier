"""Colour themes for the Textual front-end, and the registry to switch between them.

Why the registry lives here and not in the app
---------------------------------------------
The key binding that cycles themes is one line of glue that belongs in
``vlessp.tui.app``. Everything that makes that line *safe* lives here: the
palette definitions, the cycle order, and the defensive wrapper around
Textual's registration API. Keeping it separate means the colour work can be
tested without constructing the app, and means a future theme is a data change
in this file rather than an edit to a class that already has a dozen reasons to
change.

Switching is additive, not a replacement
----------------------------------------
``THEME_ORDER`` starts with the designed ``cyber-female`` palette, which is also
the default, and keeps Textual's built-in ``textual-dark`` in the cycle rather
than deleting it. So the app's first look is something chosen for it, the
built-in remains one or two keypresses away and unmodified, and pressing the
cycling key always moves to a genuinely different look.

Contrast is a hard requirement, not a finishing touch
----------------------------------------------------
Every accent role is used as *text* somewhere in this UI (labels, status
values, the log border), so each is held to the WCAG 2.1 AA text bar of 4.5:1
against the theme background rather than the weaker 3:1 non-text bar. That is a
real constraint on the palettes below and it is enforced by assertion in
``tests/test_theme.py``, which walks the full matrix. The practical consequence
is that a light theme with a near-white ground cannot keep pastel accents:
measured on the cream ground, candy colours land between 1.9:1 and 3.0:1, which
is decorative rather than readable. The accents were therefore deepened along
the lightness axis while hue and saturation were held constant, which keeps
each colour recognisably the same family.

Only the eleven base colours are supplied. Textual derives the rest of its CSS
variables ($text, $text-muted, the foreground/background tint ladders, and so
on) from those, so hand-writing dozens of ``variables`` entries would duplicate
Textual's own derivation and drift from it on the next upgrade.

A note on Textual 8.2.8's actual API
-----------------------------------
Earlier versions of Textual exposed class-level ``App.THEMES`` and
``App.DEFAULT_THEME``. In 8.2.8 neither exists. Registration is per *instance*
(``App.register_theme`` writes to ``App._registered_themes``, seeded with the
21 built-in themes in ``App.__init__``), and lookup goes through the
``App.available_themes`` property or ``App.get_theme``. This module therefore
uses only the instance API, which is the one that actually works.

Assigning ``app.theme`` to a name that is not registered raises
``InvalidThemeError`` from the reactive's validator at the assignment itself,
which is why :func:`apply_theme` registers before it sets. Note also that
``App.get_theme`` reads its argument as a comma-separated *preference list*
and returns the first available match, so it answers "is this theme
available?" incorrectly for anything containing a comma;
``App.available_themes`` is the right membership test.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from textual.theme import Theme

from vlessp.tui.graphics import palette_mode

if TYPE_CHECKING:
    from textual.app import App

# The eleven colour fields Textual accepts on a ``Theme``. ``boost`` is the one
# that is easy to forget, and the one whose behaviour is currently surprising:
# in Textual 8.2.8 ``ColorSystem`` reads it at exactly one place
# (``textual/design.py`` line 302), inside a branch that only runs when the
# theme leaves ``panel`` unset *and* is dark. Both themes below set ``panel``
# explicitly, so their ``boost`` value is stored and then never read. It is set
# anyway because the field is part of a complete theme and because it costs
# nothing — but do not expect it to do anything yet, and do not document it as
# though it does.
BASE_COLOURS: tuple[str, ...] = (
    "primary",
    "secondary",
    "warning",
    "error",
    "success",
    "accent",
    "foreground",
    "background",
    "surface",
    "panel",
    "boost",
)

# The WCAG 2.1 AA threshold for normal-size text. Held deliberately above the
# 3:1 non-text bar: every one of these roles is rendered as text in this UI.
AA_TEXT_CONTRAST = 4.5


def _relative_luminance(hex_colour: str) -> float:
    """WCAG relative luminance of a ``#RRGGBB`` (or ``#RGB``) colour.

    Implements the sRGB transfer function from the WCAG 2.1 definition rather
    than approximating it, because the whole palette decision above depends on
    this number being the real one.
    """
    value = hex_colour.lstrip("#")
    if len(value) == 3:
        value = "".join(channel * 2 for channel in value)
    if len(value) != 6:
        raise ValueError(f"expected a #RGB or #RRGGBB colour, got {hex_colour!r}")
    try:
        channels = [int(value[index : index + 2], 16) for index in (0, 2, 4)]
    except ValueError as exc:
        raise ValueError(f"expected a #RGB or #RRGGBB colour, got {hex_colour!r}") from exc

    def linearise(channel: int) -> float:
        proportion = channel / 255.0
        if proportion <= 0.04045:
            return proportion / 12.92
        return ((proportion + 0.055) / 1.055) ** 2.4

    red, green, blue = (linearise(channel) for channel in channels)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(hex_a: str, hex_b: str) -> float:
    """WCAG 2.1 contrast ratio between two colours, from 1.0 to 21.0.

    Order-independent, as the specification requires. This exists so the
    palette claims in this module's comments are checkable rather than
    assertive: ``tests/test_theme.py`` asserts every pair the design depends on,
    which means a future colour tweak fails a test instead of quietly shipping
    an unreadable theme.
    """
    first = _relative_luminance(hex_a)
    second = _relative_luminance(hex_b)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


# -- palettes ---------------------------------------------------------------
#
# Two variants per theme, chosen once at import time:
#
# ``truecolor``  the palette as designed, with the exact hex values the
#                contrast matrix below was measured against.
# ``256``        the same design snapped to the xterm-256 *cube* (channel
#                values 00/5f/87/af/d7/ff) or grey ramp. Every value here is
#                already a palette entry, so the renderer's downgrade is a
#                no-op instead of a lossy nearest-neighbour guess. That is what
#                makes the theme keep its hue on macOS Terminal.app, which does
#                not advertise 24-bit colour.
#
# The 256 variants are not just quantised versions of the truecolor values.
# Each accent was re-picked from the cube so it still clears 4.5:1 on the same
# ground; a naive snap of, say, the olive accent lands under the bar. The
# contrast matrix in ``tests/test_theme.py`` walks whichever variant is active,
# so both are held to the same standard.
GUMMY_TRUECOLOR: dict[str, str] = {
    "primary": "#D30059",
    "secondary": "#B64800",
    "warning": "#8D6300",
    "error": "#D62839",
    "success": "#2F7939",
    "accent": "#517516",
    "foreground": "#3B2C3A",
    "background": "#FFF6E9",
    "surface": "#FFFDF7",
    "panel": "#FFE9C7",
    "boost": "#140B05",
}

GUMMY_256: dict[str, str] = {
    # Deep raspberry / burnt orange / honey, all cube entries. The state colours
    # are a step darker than their truecolour cousins because they are also
    # painted on the pink panel (the table header and status strip), not only on
    # the cream ground; a green that clears 4.5:1 on cream can still fail on the
    # lighter pink. These clear both.
    "primary": "#D7005F",
    "secondary": "#AF5F00",
    "warning": "#5F5F00",
    "error": "#AF0000",
    "success": "#005F00",
    "accent": "#005F5F",
    # Cool-neutral ink on a cube cream ground, with white cards and a candy
    # pink panel so the surfaces stay distinguishable after quantisation.
    "foreground": "#3A3A3A",
    "background": "#FFFFD7",
    "surface": "#FFFFFF",
    "panel": "#FFD7D7",
    # Inert today, but it still has to be a real 256 entry: the whole point of
    # this variant is that no value relies on the renderer's nearest-neighbour
    # guess, and an off-palette value here would be the one exception.
    "boost": "#080808",
}

CYBER_FEMALE_TRUECOLOR: dict[str, str] = {
    "primary": "#FF2E9A",
    "secondary": "#22E0F0",
    "warning": "#FFC53D",
    "error": "#FF4D6D",
    "success": "#3DFFC0",
    "accent": "#B14BFF",
    "foreground": "#F0E6FF",
    "background": "#0B0A14",
    "surface": "#16122A",
    "panel": "#1E1840",
    "boost": "#2A2158",
}

CYBER_FEMALE_256: dict[str, str] = {
    # Neon magenta, cyan and violet, each an exact cube entry. The grey-ramp
    # ground keeps the neon reading as neon; a cube black would band badly on
    # Terminal.app's default profile.
    "primary": "#FF5FAF",
    "secondary": "#5FD7FF",
    "warning": "#FFD75F",
    "error": "#FF5F5F",
    "success": "#5FFF87",
    "accent": "#AF87FF",
    "foreground": "#EEEEEE",
    "background": "#121212",
    "surface": "#1C1C1C",
    "panel": "#262626",
    "boost": "#303030",
}

#: Which family was selected. Exported so the app can say so in the log pane
#: once, instead of the user wondering why the colours differ between machines.
PALETTE_MODE: str = palette_mode()


def _theme(name: str, palette: dict[str, str], *, dark: bool) -> Theme:
    """Build a Textual ``Theme`` from a palette dict.

    Only the eleven base colours are supplied; Textual derives the rest. See the
    note above ``BASE_COLOURS`` for why ``boost`` is stored but currently inert.
    """
    return Theme(name=name, dark=dark, **palette)


GUMMY = _theme(
    "gummy",
    GUMMY_TRUECOLOR if PALETTE_MODE == "truecolor" else GUMMY_256,
    dark=False,
)

CYBER_FEMALE = _theme(
    "cyber-female",
    CYBER_FEMALE_TRUECOLOR if PALETTE_MODE == "truecolor" else CYBER_FEMALE_256,
    dark=True,
)


#: Every theme this module defines, keyed by the name Textual knows it by.
#:
#: ``textual-dark`` is deliberately *absent*. It ships with Textual, it is
#: already registered on every ``App``, and re-registering a built-in would
#: mean shipping a copy of someone else's palette that silently goes stale when
#: Textual updates it.
THEMES: dict[str, Theme] = {
    "gummy": GUMMY,
    "cyber-female": CYBER_FEMALE,
}

#: Cycle order for the theme key binding.
#:
#: The designed theme first, because that is the one the app starts on -- a
#: cycle whose first entry is not the current theme makes every count of
#: keypresses off by one. The built-in stays in the cycle so a user who wants
#: Textual's neutral look, or who is debugging a palette, can still reach it.
THEME_ORDER: tuple[str, ...] = ("cyber-female", "gummy", "textual-dark")

#: The theme a fresh install starts on, and the fallback whenever a requested
#: name cannot be applied.
#:
#: This used to be Textual's ``textual-dark``, on the principle that a new
#: feature must not silently restyle an existing interface. The built-in is
#: still reachable and unmodified, but it is no longer the first look: it is a
#: neutral utility theme that was never chosen for this app, and on a
#: 256-colour terminal its greys quantise into something flatter still.
DEFAULT_THEME_NAME: str = "cyber-female"


def next_theme(current: str) -> str:
    """Name of the theme after ``current``, wrapping around at the end.

    Total by construction: this is called straight from a key handler, and a
    crash there takes the whole UI with it. An unknown ``current`` — a theme
    Textual knows but this module does not, or a name that has since been
    renamed — has no meaningful position in the cycle, so it resets to
    :data:`DEFAULT_THEME_NAME` rather than guessing an index.

    ``tests/test_theme.py`` pins the unknown-name branch and walks the cycle a
    few hundred times, because "it wraps" and "it is total" are separate claims
    and only the second one is what keeps the keybinding alive.
    """
    try:
        index = THEME_ORDER.index(current)
    except ValueError:
        return DEFAULT_THEME_NAME
    return THEME_ORDER[(index + 1) % len(THEME_ORDER)]


def apply_theme(app: App, name: str) -> str:
    """Apply ``name`` to ``app``, registering it first if it needs it.

    Returns the name actually applied, which is not always the name asked for.
    ``App.theme`` is a reactive whose validator rejects any name that is not in
    ``App.available_themes``, so setting an unregistered theme raises
    ``InvalidThemeError`` at the assignment — a failure that would otherwise
    surface as an unhandled exception inside a keypress. Registration therefore
    happens here, and any name that still cannot be applied falls back to the
    default instead of propagating.

    Membership is tested with ``App.available_themes`` rather than
    ``App.get_theme``: ``get_theme`` treats its argument as a comma-separated
    *preference list* and returns the first available match, so
    ``get_theme("gummy,textual-dark")`` would happily report that a
    two-element string is a registered theme. That is the wrong answer to the
    question being asked here.
    """
    if name in THEMES and name not in app.available_themes:
        app.register_theme(THEMES[name])

    for candidate in (name, DEFAULT_THEME_NAME):
        try:
            app.theme = candidate
        except Exception:
            # Deliberately broad: the point of this function is that the key
            # binding cannot crash the UI, and the exact exception type is
            # Textual's business, not a reason to propagate it.
            continue
        return candidate

    # Both candidates refused. Return what is actually in force rather than
    # claiming a switch that did not happen.
    return app.theme


def register_all(app: App) -> None:
    """Register every theme in :data:`THEMES` on ``app``. Call from ``on_mount``.

    Idempotent by construction — ``register_theme`` overwrites — so this is safe
    on a re-mount. Registering up front rather than lazily inside
    :func:`apply_theme` is what lets Textual validate ``app.theme`` at all, and
    it means the first press of the cycling key is not the one that pays for
    the registration.
    """
    for theme in THEMES.values():
        app.register_theme(theme)


__all__ = [
    "AA_TEXT_CONTRAST",
    "BASE_COLOURS",
    "CYBER_FEMALE",
    "CYBER_FEMALE_256",
    "CYBER_FEMALE_TRUECOLOR",
    "DEFAULT_THEME_NAME",
    "GUMMY",
    "GUMMY_256",
    "GUMMY_TRUECOLOR",
    "PALETTE_MODE",
    "THEMES",
    "THEME_ORDER",
    "apply_theme",
    "next_theme",
    "register_all",
]