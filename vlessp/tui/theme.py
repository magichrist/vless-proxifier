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
``THEME_ORDER`` deliberately starts with Textual's built-in ``textual-dark``,
which is what this app already looked like before themes existed. A user who
never presses the cycling key sees precisely the pre-existing interface. The
alternative — making one of the new themes the default — would silently
restyle an application that was working fine, which is the kind of change that
gets discovered as a bug report rather than as a feature.

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


# -- themes -----------------------------------------------------------------
#
# gummy — "candy-bright on cream".
#
# Five of the six accents were deepened from the original brief. Each was moved
# down its own HSL lightness axis with hue and saturation held constant, to the
# brightest value still clearing 5.0:1 on the cream ground. Hue preservation is
# the point: #517516 is still the same lime as #8AC926, just legible. Measured
# against #FFF6E9, before -> after:
#
#     primary    #FF5FA2 -> #D30059   2.65 -> 5.01   (bubblegum -> deep raspberry)
#     secondary  #FF8A3D -> #B64800   2.19 -> 5.01   (tangerine -> burnt orange)
#     accent     #8AC926 -> #517516   1.87 -> 5.02   (lime -> olive lime)
#     success    #3FA34D -> #2F7939   2.99 -> 5.01   (green -> forest)
#     warning    #E8A200 -> #8D6300   2.04 -> 5.01   (amber -> dark honey)
#
# error was left at #D62839 (4.65) because it was the only accent that already
# cleared the bar, and the ground colours were left alone: foreground #3B2C3A
# sits at 12.20 on the background, so the cream palette is not what is failing.
#
# The unavoidable cost is that "candy-bright" has to live in the borders,
# fills, and Textual's own derived tints rather than in the text colours. A
# pastel accent on a near-white ground cannot be readable at any size; the
# saturated reading of this theme is carried by the palette itself.
GUMMY = Theme(
    name="gummy",
    primary="#D30059",
    secondary="#B64800",
    warning="#8D6300",
    error="#D62839",
    success="#2F7939",
    accent="#517516",
    foreground="#3B2C3A",
    background="#FFF6E9",
    surface="#FFFDF7",
    panel="#FFE9C7",
    # Dark wash, matching what Textual itself would derive for a light theme.
    # Currently inert for the reason given above BASE_COLOURS.
    boost="#140B05",
    dark=False,
)

# cyber-female — "neon magenta + cyan on dark".
#
# Unchanged from the brief: every pair already cleared 4.5:1 on the indigo-black
# ground with room to spare, so the palette that ships here is the palette that
# was designed. Margins are 4.98 (accent) at the tightest, which is above the
# bar but is the value to watch if this palette is ever revisited.
CYBER_FEMALE = Theme(
    name="cyber-female",
    primary="#FF2E9A",
    secondary="#22E0F0",
    warning="#FFC53D",
    error="#FF4D6D",
    success="#3DFFC0",
    accent="#B14BFF",
    foreground="#F0E6FF",
    background="#0B0A14",
    surface="#16122A",
    panel="#1E1840",
    # Light wash, matching Textual's convention for a dark theme. Currently
    # inert for the reason given above BASE_COLOURS.
    boost="#2A2158",
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
#: Built-in first, so the first press moves *away* from the look the user
#: already had and a user who presses it once still knows what they changed.
THEME_ORDER: tuple[str, ...] = ("textual-dark", "gummy", "cyber-female")

#: The theme a fresh install starts on, and the fallback whenever a requested
#: name cannot be applied. A built-in, so it is registered on every ``App``
#: before any of this code runs and therefore always recoverable.
DEFAULT_THEME_NAME: str = "textual-dark"


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
    "DEFAULT_THEME_NAME",
    "GUMMY",
    "THEMES",
    "THEME_ORDER",
    "apply_theme",
    "next_theme",
    "register_all",
]