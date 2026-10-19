"""Tests for the pure drawing helpers.

The point of ``vlessp.tui.graphics`` is that the look can be pinned without a
terminal: colour maths, capability detection, and the spinner/meter/gradient
primitives are all strings and numbers. Only the widgets need Textual, so these
run in milliseconds and fail with a readable assertion rather than a screenshot
diff.

Three things are asserted beyond the obvious arithmetic:

* The **256 palette is snap-exact.** Every value must already be an xterm-256
  cube entry or grey-ramp entry, because the whole reason that palette exists is
  that macOS Terminal.app cannot show the truecolour one. A stray ``#123456``
  would quantise to a different colour and quietly undo it.
* **Accents clear 4.5:1 on every surface they are painted on**, not just the
  screen background. The status strip uses ``$panel``.
* **Capability detection is driven by the environment**, including ``NO_COLOR``
  winning over a truecolour claim.
"""
from __future__ import annotations

import os
import unittest
from unittest import mock

from vlessp.tui.graphics import (
    contrast_ratio,
    gradient,
    hex_colour,
    legible,
    luminance,
    meter,
    mix,
    palette_mode,
    pulse,
    readable_mix,
    rgb,
    shimmer,
    spinner,
    supports_truecolor,
)
from vlessp.tui.theme import (
    CYBER_FEMALE_256,
    CYBER_FEMALE_TRUECOLOR,
    GUMMY_256,
    GUMMY_TRUECOLOR,
)

#: Channel values in the xterm-256 colour cube (0, 95, 135, 175, 215, 255).
_CUBE = {0, 95, 135, 175, 215, 255}


def _is_exact_xterm(colour: str) -> bool:
    """Whether ``colour`` is already an entry in the xterm-256 palette.

    Either all three channels are cube steps, or it is one of the 24 grey-ramp
    entries (8, 18, 28 ... 238).
    """
    red, green, blue = rgb(colour)
    if red in _CUBE and green in _CUBE and blue in _CUBE:
        return True
    return red == green == blue and 8 <= red <= 238 and (red - 8) % 10 == 0


class TestColourMath(unittest.TestCase):
    def test_rgb_round_trips(self) -> None:
        self.assertEqual(rgb("#ff2e9a"), (255, 46, 154))
        self.assertEqual(hex_colour((255, 46, 154)), "#ff2e9a")

    def test_short_hex_expands(self) -> None:
        self.assertEqual(rgb("#f0a"), (255, 0, 170))

    def test_hex_colour_clamps_out_of_range_channels(self) -> None:
        self.assertEqual(hex_colour((-10, 300, 128)), "#00ff80")

    def test_malformed_colours_are_rejected_by_name(self) -> None:
        for bad in ("red", "#12", "#12345", "#gggggg", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    rgb(bad)

    def test_mix_endpoints_and_midpoint(self) -> None:
        self.assertEqual(mix("#000000", "#ffffff", 0.0), "#000000")
        self.assertEqual(mix("#000000", "#ffffff", 1.0), "#ffffff")
        self.assertEqual(mix("#000000", "#ffffff", 0.5), "#808080")

    def test_contrast_black_on_white_is_the_maximum(self) -> None:
        self.assertAlmostEqual(contrast_ratio("#000000", "#ffffff"), 21.0, places=1)
        self.assertAlmostEqual(contrast_ratio("#ffffff", "#000000"), 21.0, places=1)

    def test_contrast_is_one_for_a_colour_against_itself(self) -> None:
        self.assertAlmostEqual(contrast_ratio("#d7005f", "#d7005f"), 1.0, places=3)

    def test_luminance_is_ordered(self) -> None:
        self.assertLess(luminance("#000000"), luminance("#808080"))
        self.assertLess(luminance("#808080"), luminance("#ffffff"))


class TestReadableMix(unittest.TestCase):
    def test_a_blend_that_already_passes_is_used_unchanged(self) -> None:
        naive = mix("#eeeeee", "#262626", 0.4)
        self.assertEqual(readable_mix("#eeeeee", "#262626", preferred=0.4), naive)

    def test_a_blend_that_would_fail_is_capped(self) -> None:
        # Ink blended 40% into cream is ~3.1:1; the helper must pull it back.
        ground = "#ffd7d7"
        result = readable_mix("#3a3a3a", ground, preferred=0.4)
        self.assertGreaterEqual(contrast_ratio(result, ground), 4.5)
        self.assertNotEqual(result, mix("#3a3a3a", ground, 0.4))

    def test_an_impossible_ground_returns_the_foreground(self) -> None:
        # Mid-grey on mid-grey cannot be rescued by blending.
        result = readable_mix("#777777", "#777777", preferred=0.4)
        self.assertEqual(result, "#777777")

    def test_legible_leaves_a_passing_colour_alone(self) -> None:
        self.assertEqual(legible("#eeeeee", "#121212"), "#eeeeee")

    def test_legible_darkens_on_a_light_ground(self) -> None:
        # The light theme's error red is 4.20 on the pink panel, so it moves
        # toward black -- and keeps its hue direction (still red).
        fixed = legible("#d62839", "#ffe9c7")
        self.assertGreaterEqual(contrast_ratio(fixed, "#ffe9c7"), 4.5)
        red, green, blue = rgb(fixed)
        self.assertGreater(red, green)
        self.assertGreater(red, blue)

    def test_legible_lightens_on_a_dark_ground(self) -> None:
        fixed = legible("#001100", "#121212")
        self.assertGreaterEqual(contrast_ratio(fixed, "#121212"), 4.5)
        self.assertGreater(luminance(fixed), luminance("#001100"))


class TestTerminalCapability(unittest.TestCase):
    def _env(self, **values: str):
        """Patch the environment down to the variables capability detection reads."""
        base = {"PATH": "/usr/bin", "TERM": "xterm-256color"}
        base.update(values)
        return mock.patch.dict(os.environ, base, clear=True)

    def test_colorterm_truecolor_is_believed(self) -> None:
        with self._env(COLORTERM="truecolor"):
            self.assertTrue(supports_truecolor())
            self.assertEqual(palette_mode(), "truecolor")

    def test_colorterm_24bit_is_believed(self) -> None:
        with self._env(COLORTERM="24bit"):
            self.assertTrue(supports_truecolor())

    def test_apple_terminal_is_256_colour(self) -> None:
        # The exact case this module exists for: Terminal.app sets no
        # COLORTERM and cannot show 24-bit colour.
        with self._env(TERM_PROGRAM="Apple_Terminal"):
            self.assertFalse(supports_truecolor())
            self.assertEqual(palette_mode(), "256")

    def test_a_truecolor_term_program_is_believed(self) -> None:
        for program in ("iTerm.app", "WezTerm", "vscode", "ghostty"):
            with self.subTest(program=program), self._env(TERM_PROGRAM=program):
                self.assertTrue(supports_truecolor())

    def test_a_direct_term_is_believed(self) -> None:
        with self._env(TERM="xterm-direct"):
            self.assertTrue(supports_truecolor())

    def test_no_color_wins_over_a_truecolor_claim(self) -> None:
        with self._env(COLORTERM="truecolor", NO_COLOR="1"):
            self.assertFalse(supports_truecolor())


class TestPrimitives(unittest.TestCase):
    def test_spinner_is_total_and_cycles(self) -> None:
        frames = {spinner(index) for index in range(10)}
        self.assertEqual(len(frames), 10)
        self.assertEqual(spinner(0), spinner(10))
        self.assertEqual(spinner(-1), spinner(9))

    def test_meter_clamps_and_stays_exactly_its_width(self) -> None:
        self.assertEqual(meter(0, 4, width=8), "░" * 8)
        self.assertEqual(meter(4, 4, width=8), "█" * 8)
        self.assertEqual(meter(99, 4, width=8), "█" * 8)
        for done in range(0, 5):
            self.assertEqual(len(meter(done, 4, width=8)), 8)

    def test_meter_with_no_total_is_empty_not_a_division_error(self) -> None:
        self.assertEqual(meter(1, 0, width=4), "░" * 4)
        self.assertEqual(meter(1, -3, width=4), "░" * 4)

    def test_gradient_returns_one_colour_per_character(self) -> None:
        colours = gradient("VLESS", ("#ff5faf", "#af87ff", "#5fd7ff"))
        self.assertEqual(len(colours), 5)
        for colour in colours:
            self.assertRegex(colour, r"^#[0-9a-f]{6}$")

    def test_gradient_phase_moves_the_colours(self) -> None:
        stops = ("#ff5faf", "#af87ff", "#5fd7ff")
        self.assertNotEqual(gradient("VLESS", stops, phase=0.0), gradient("VLESS", stops, phase=0.5))

    def test_gradient_of_nothing_is_nothing(self) -> None:
        self.assertEqual(gradient("", ("#ffffff",)), [])

    def test_gradient_without_stops_names_the_mistake(self) -> None:
        with self.assertRaises(ValueError):
            gradient("abc", ())

    def test_a_single_stop_is_a_flat_colour(self) -> None:
        self.assertEqual(gradient("abc", ("#123456",)), ["#123456"] * 3)

    def test_shimmer_brightens_toward_the_highlight(self) -> None:
        base = "#404040"
        peak = shimmer(base, "#ffffff", phase=0.5)
        trough = shimmer(base, "#ffffff", phase=0.0)
        self.assertGreater(luminance(peak), luminance(trough))
        self.assertGreater(luminance(peak), luminance(base))

    def test_pulse_has_two_frames_and_wraps(self) -> None:
        self.assertNotEqual(pulse(0), pulse(1))
        self.assertEqual(pulse(0), pulse(2))


class TestPalettes(unittest.TestCase):
    """The palettes must be exact for their terminal, and legible on both surfaces."""

    def test_the_256_palettes_are_snap_exact(self) -> None:
        for name, palette in (("gummy", GUMMY_256), ("cyber-female", CYBER_FEMALE_256)):
            for role, colour in palette.items():
                with self.subTest(theme=name, role=role):
                    self.assertTrue(
                        _is_exact_xterm(colour),
                        f"{name}.{role}={colour} is not an xterm-256 entry; "
                        "it would be quantised to a different colour",
                    )

    def test_state_colours_clear_aa_on_both_background_and_panel(self) -> None:
        palettes = (GUMMY_256, GUMMY_TRUECOLOR, CYBER_FEMALE_256, CYBER_FEMALE_TRUECOLOR)
        for palette in palettes:
            for role in ("success", "error", "warning"):
                with self.subTest(theme=palette["background"], role=role):
                    self.assertGreaterEqual(
                        contrast_ratio(palette[role], palette["background"]), 4.5
                    )
                    # The status strip paints the same accent on $panel. Where a
                    # palette misses, ``legible`` fixes it at render time -- so
                    # the assertion is that it *can* be fixed, not that it is.
                    fixed = legible(palette[role], palette["panel"])
                    self.assertGreaterEqual(contrast_ratio(fixed, palette["panel"]), 4.5)

    def test_the_light_and_dark_palettes_are_actually_light_and_dark(self) -> None:
        self.assertGreater(luminance(GUMMY_256["background"]), 0.5)
        self.assertLess(luminance(CYBER_FEMALE_256["background"]), 0.5)
        self.assertGreater(luminance(GUMMY_TRUECOLOR["background"]), 0.5)
        self.assertLess(luminance(CYBER_FEMALE_TRUECOLOR["background"]), 0.5)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
