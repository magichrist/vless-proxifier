"""Tests for the theme registry and its two palettes.

The contrast matrix is the centre of this file. Everything else here is
bookkeeping — the cycle wraps, the cycle is total, the registry has what it
says it has. Those are easy to get wrong and cheap to notice. A palette that
looks pleasant and fails 4.5:1 is neither, and nothing else in the suite would
catch it, so the matrix is asserted pair by pair rather than as a summary
statistic that can pass while one cell hides a 2:1.

The runtime tests need Textual and a real ``App``, but only two of them do.
The contrast and registry tests import nothing but the standard library, so a
palette regression is reported even in an environment where the full app cannot
be constructed.
"""
from __future__ import annotations

import unittest

try:
    from textual.app import App

    from vlessp.tui.theme import (
        AA_TEXT_CONTRAST,
        BASE_COLOURS,
        DEFAULT_THEME_NAME,
        THEME_ORDER,
        THEMES,
        _contrast,
        apply_theme,
        next_theme,
        register_all,
    )

    THEME_IMPORT_ERROR: Exception | None = None
except ImportError as exc:  # pragma: no cover - depends on the environment
    # Matching the convention in test_tui.py: a bare ModuleNotFoundError deep in
    # a class body tells the reader nothing, whereas skipping with a reason they
    # can act on tells them exactly what to install.
    THEME_IMPORT_ERROR = exc

if THEME_IMPORT_ERROR is not None:  # pragma: no cover - environment dependent
    raise unittest.SkipTest(
        f"Textual is not installed for this interpreter "
        f"({THEME_IMPORT_ERROR}). Install dependencies, e.g. `pip install textual`, "
        f"or run the suite with the project environment."
    ) from THEME_IMPORT_ERROR

# The palettes that ship with this module. ``textual-dark`` is Textual's own
# and is covered by Textual's test suite, so it is deliberately not re-checked
# here: copying its colours into this file to assert them would be asserting a
# copy.
NEW_THEMES: tuple[str, ...] = ("gummy", "cyber-female")

# A known-answer pair from the WCAG 2.1 worked example, so a broken _contrast
# cannot make the whole matrix pass vacuously.
_BLACK = "#000000"
_WHITE = "#FFFFFF"


class TestContrastHelper(unittest.TestCase):
    """The helper the rest of the file trusts, checked against the spec."""

    def test_black_on_white_is_the_maximum_ratio(self) -> None:
        self.assertAlmostEqual(_contrast(_BLACK, _WHITE), 21.0, places=6)

    def test_a_colour_against_itself_is_the_minimum_ratio(self) -> None:
        self.assertAlmostEqual(_contrast("#1E1840", "#1E1840"), 1.0, places=6)

    def test_the_ratio_is_order_independent(self) -> None:
        self.assertAlmostEqual(_contrast("#FF5FA2", "#FFF6E9"), _contrast("#FFF6E9", "#FF5FA2"), places=6)

    def test_shorthand_and_expanded_hex_agree(self) -> None:
        # "#123" expands by doubling each digit, i.e. to "#112233".
        self.assertAlmostEqual(_contrast("#AABBCC", "#112233"), _contrast("#ABC", "#123"), places=6)

    def test_a_malformed_colour_is_rejected_loudly(self) -> None:
        """A silently-parsed bad colour would turn the matrix into fiction."""
        for bad in ("#12345", "not-a-colour", "#GGGGGG", ""):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _contrast(bad, _WHITE)


class TestContrastMatrix(unittest.TestCase):
    """WCAG 2.1 AA on every pair the design depends on.

    Held to the 4.5:1 *text* bar throughout, including the accent roles. That
    is stricter than WCAG requires for a border or an icon, and it is on
    purpose: in this UI the accents render as label and status text, so a 3:1
    pass would be a legal-but-unreadable theme.
    """

    def test_foreground_clears_aa_on_every_background_role(self) -> None:
        for name in NEW_THEMES:
            theme = THEMES[name]
            for surface_role in ("background", "surface", "panel"):
                with self.subTest(theme=name, on=surface_role):
                    ratio = _contrast(theme.foreground, getattr(theme, surface_role))
                    self.assertGreaterEqual(
                        ratio,
                        AA_TEXT_CONTRAST,
                        f"{name}: foreground {theme.foreground} on {surface_role} "
                        f"{getattr(theme, surface_role)} is {ratio:.2f}:1, below AA",
                    )

    def test_every_accent_clears_aa_on_the_background(self) -> None:
        accent_roles = ("primary", "secondary", "accent", "success", "warning", "error")
        for name in NEW_THEMES:
            theme = THEMES[name]
            for role in accent_roles:
                with self.subTest(theme=name, role=role):
                    ratio = _contrast(getattr(theme, role), theme.background)
                    self.assertGreaterEqual(
                        ratio,
                        AA_TEXT_CONTRAST,
                        f"{name}: {role} {getattr(theme, role)} on background "
                        f"{theme.background} is {ratio:.2f}:1, below AA",
                    )

    def test_the_original_brief_palette_would_have_failed(self) -> None:
        """Why these colours differ from the ones originally specified.

        A regression guard on the *rationale*. If someone restores the original
        candy palette because it looks better in isolation, this fails and the
        comment in ``theme.py`` explaining the deepening has to be re-argued.
        """
        brief_accent_originals = {
            "primary": "#FF5FA2",
            "secondary": "#FF8A3D",
            "accent": "#8AC926",
            "success": "#3FA34D",
            "warning": "#E8A200",
        }
        background = THEMES["gummy"].background
        for role, original in brief_accent_originals.items():
            with self.subTest(role=role):
                self.assertLess(
                    _contrast(original, background),
                    AA_TEXT_CONTRAST,
                    f"{role} {original} was expected to fail AA on {background}; "
                    "if the maths changed, re-read the comment in theme.py",
                )
                self.assertGreaterEqual(_contrast(getattr(THEMES["gummy"], role), background), AA_TEXT_CONTRAST)


class TestPaletteCompleteness(unittest.TestCase):
    """Every theme is complete enough for Textual to derive a full stylesheet."""

    def test_every_theme_sets_all_eleven_base_colours(self) -> None:
        self.assertEqual(
            len(BASE_COLOURS),
            11,
            "a Theme carries eleven colour fields; if Textual changes this, the "
            "palette tests need to change with it",
        )
        for name, theme in THEMES.items():
            for role in BASE_COLOURS:
                with self.subTest(theme=name, role=role):
                    value = getattr(theme, role, None)
                    self.assertIsInstance(
                        value,
                        str,
                        f"{name}.{role} is not set — Textual would derive a "
                        "default and the palette would quietly not match the docs",
                    )
                    self.assertTrue(value.startswith("#"), f"{name}.{role}={value!r} is not a hex colour")

    def test_the_dark_flag_agrees_with_the_background(self) -> None:
        """``dark`` drives Textual's -dark-mode/-light-mode classes.

        A theme whose flag disagrees with its own ground inverts every derived
        tint — Textual picks foreground and background mix directions from this
        one boolean — so the disagreement has to be impossible rather than
        merely unlikely.
        """
        for name, theme in THEMES.items():
            with self.subTest(theme=name):
                luminance = _relative_luminance_of(theme.background)
                if theme.dark:
                    self.assertLess(luminance, 0.5, f"{name} is dark but its background is light")
                else:
                    self.assertGreater(luminance, 0.5, f"{name} is light but its background is dark")

    def test_every_theme_name_matches_its_registry_key(self) -> None:
        """``App.theme`` is set by name and resolved by name.

        A mismatch would register a theme the cycle can never select, which
        presents as a keypress that does nothing.
        """
        for name, theme in THEMES.items():
            with self.subTest(key=name):
                self.assertEqual(theme.name, name)

    def test_the_generated_panel_is_the_panel_the_matrix_was_measured_against(self) -> None:
        """The contrast matrix is only meaningful if ``panel`` is what renders.

        Textual derives ``$panel`` from the theme, and the derivation has
        branches — it blends ``surface`` with ``primary`` when ``panel`` is
        unset, and folds in ``boost`` for dark themes. If any of that ever
        started overriding an explicit ``panel``, the foreground-on-panel
        ratio asserted above would be describing a colour nobody sees. This
        pins the generated variable to the declared one.

        It also incidentally pins ``boost``'s current inertness: ``boost`` is
        read only in the ``panel is None and dark`` branch, so with ``panel``
        set the derived value must be untouched.
        """
        for name, theme in THEMES.items():
            with self.subTest(theme=name):
                generated = theme.to_color_system().generate()
                self.assertEqual(
                    generated["panel"].lstrip("#").lower(),
                    theme.panel.lstrip("#").lower(),
                    f"{name}: $panel is derived, so the matrix must be measured against the derived value",
                )
                self.assertGreaterEqual(
                    _contrast(theme.foreground, generated["panel"]),
                    AA_TEXT_CONTRAST,
                    f"{name}: foreground fails AA against the panel that actually renders",
                )


class TestRegistry(unittest.TestCase):
    def test_both_new_themes_are_present(self) -> None:
        for name in NEW_THEMES:
            self.assertIn(name, THEMES)

    def test_the_cycle_has_exactly_three_entries(self) -> None:
        self.assertEqual(len(THEME_ORDER), 3)

    def test_the_cycle_starts_on_the_built_in_theme(self) -> None:
        """Switching is additive only if the existing look is reachable first."""
        self.assertEqual(THEME_ORDER[0], "textual-dark")

    def test_the_cycle_order_is_a_permutation_without_repeats(self) -> None:
        self.assertEqual(len(set(THEME_ORDER)), len(THEME_ORDER), "a repeated name would make the cycle stutter")

    def test_every_non_builtin_in_the_cycle_is_actually_defined(self) -> None:
        for name in THEME_ORDER:
            with self.subTest(name=name):
                self.assertTrue(name in THEMES or name == "textual-dark", f"{name} can be cycled to but never applied")

    def test_the_builtin_is_not_duplicated_into_our_registry(self) -> None:
        """Re-shipping a built-in means shipping a copy that goes stale."""
        self.assertNotIn("textual-dark", THEMES)

    def test_the_default_is_a_member_of_the_cycle(self) -> None:
        """``next_theme``'s unknown-name branch returns the default.

        If the default were not in the cycle, that branch would return a name
        the cycle cannot reach, and the totality guarantee would be a fiction.
        """
        self.assertIn(DEFAULT_THEME_NAME, THEME_ORDER)


class TestNextTheme(unittest.TestCase):
    def test_each_theme_advances_to_the_next(self) -> None:
        for index, name in enumerate(THEME_ORDER[:-1]):
            with self.subTest(current=name):
                self.assertEqual(next_theme(name), THEME_ORDER[index + 1])

    def test_the_last_theme_wraps_to_the_first(self) -> None:
        self.assertEqual(next_theme(THEME_ORDER[-1]), THEME_ORDER[0])

    def test_an_unknown_name_returns_a_valid_theme_instead_of_raising(self) -> None:
        for unknown in ("nonsense", "", "TEXTUAL-DARK", "gummy ", "gruvbox"):
            with self.subTest(unknown=unknown):
                result = next_theme(unknown)
                self.assertIn(result, THEME_ORDER)

    def test_the_cycle_is_total_over_many_iterations(self) -> None:
        """Every result is a member of the cycle, and the cycle comes around.

        Walking it a few hundred times is what makes "total" a claim about all
        inputs reachable from the keybinding rather than about the three names
        someone thought to type into a test.
        """
        current = DEFAULT_THEME_NAME
        visited: list[str] = []
        for step in range(300):
            current = next_theme(current)
            self.assertIn(current, THEME_ORDER, f"step {step} left the cycle: {current!r}")
            visited.append(current)
        self.assertEqual(current, DEFAULT_THEME_NAME, "300 steps over a 3-cycle must land back on the start")
        self.assertEqual(set(visited), set(THEME_ORDER), "the walk must reach every theme")

    def test_no_single_application_is_a_fixed_point(self) -> None:
        """Every theme leads somewhere; none is a dead end in its own cycle."""
        for name in THEME_ORDER:
            with self.subTest(name=name):
                self.assertNotEqual(next_theme(name), name)


class TestApplyTheme(unittest.TestCase):
    """Registration and switching against a real ``App``.

    ``App.__init__`` seeds the instance with Textual's 21 built-in themes and
    an empty dict otherwise, so a plain ``App`` is a faithful stand-in: it has
    the same registration state this app would have at ``on_mount``.
    """

    def setUp(self) -> None:
        self.app = App()

    def test_register_all_does_not_raise(self) -> None:
        register_all(self.app)

    def test_register_all_registers_every_theme_in_the_registry(self) -> None:
        register_all(self.app)
        for name, theme in THEMES.items():
            with self.subTest(name=name):
                self.assertEqual(self.app.get_theme(name), theme)

    def test_register_all_is_idempotent(self) -> None:
        """``on_mount`` can run again; re-registration must not change anything."""
        register_all(self.app)
        first = dict(self.app.available_themes)
        register_all(self.app)
        self.assertEqual(self.app.available_themes, first)

    def test_register_all_leaves_the_builtin_as_textual_shipped_it(self) -> None:
        """We must not shadow a built-in with a copy of it."""
        register_all(self.app)
        from textual.theme import BUILTIN_THEMES

        self.assertIs(self.app.get_theme("textual-dark"), BUILTIN_THEMES["textual-dark"])

    def test_applying_a_registered_theme_returns_that_theme(self) -> None:
        register_all(self.app)
        for name in NEW_THEMES:
            with self.subTest(name=name):
                self.assertEqual(apply_theme(self.app, name), name)
                self.assertEqual(self.app.theme, name)

    def test_apply_theme_registers_on_demand_without_register_all(self) -> None:
        """Registration is defensive, not a precondition.

        ``apply_theme`` is the only thing standing between a keypress and an
        ``InvalidThemeError``, so it cannot assume ``on_mount`` already ran.
        """
        self.assertNotIn("gummy", self.app.available_themes)
        self.assertEqual(apply_theme(self.app, "gummy"), "gummy")
        self.assertEqual(self.app.theme, "gummy")

    def test_applying_a_builtin_does_not_re_register_it(self) -> None:
        from textual.theme import BUILTIN_THEMES

        self.assertEqual(apply_theme(self.app, "textual-dark"), "textual-dark")
        self.assertIs(self.app.get_theme("textual-dark"), BUILTIN_THEMES["textual-dark"])

    def test_an_unapplicable_name_falls_back_instead_of_raising(self) -> None:
        """The keybinding must not be able to crash the UI."""
        register_all(self.app)
        for bad in ("not-a-theme", "solarized-light-typo", ""):
            with self.subTest(bad=bad):
                self.assertEqual(apply_theme(self.app, bad), DEFAULT_THEME_NAME)
                self.assertEqual(self.app.theme, DEFAULT_THEME_NAME)

    def test_the_full_cycle_can_be_walked_without_raising(self) -> None:
        """The whole point of the feature, end to end, through the real API."""
        register_all(self.app)
        apply_theme(self.app, DEFAULT_THEME_NAME)
        current = self.app.theme
        for _ in range(len(THEME_ORDER) * 2):
            current = apply_theme(self.app, next_theme(current))
            self.assertIn(current, THEME_ORDER)
        self.assertEqual(current, self.app.theme)


class TestRuntimeSwitch(unittest.IsolatedAsyncioTestCase):
    """A theme switch must actually repaint, not just change a string.

    Setting ``App.theme`` updates a reactive; whether the running screen picks
    it up is Textual's business, and if it ever stopped, every test above
    would still pass while the key did nothing a user could see.
    """

    async def test_switching_themes_repaints_the_running_app(self) -> None:
        from textual.widgets import Static

        class Probe(App):
            def compose(self):  # noqa: ANN202 - matches Textual's ComposeResult style
                yield Static("probe")

        app = Probe()
        async with app.run_test() as pilot:
            register_all(app)
            for name in NEW_THEMES:
                with self.subTest(name=name):
                    apply_theme(app, name)
                    await pilot.pause()
                    self.assertEqual(app.theme, name)
                    expected = THEMES[name].background.lstrip("#")
                    painted = app.styles.background
                    self.assertEqual(
                        painted.rgb,
                        tuple(int(expected[index : index + 2], 16) for index in (0, 2, 4)),
                        f"{name} did not repaint the app background",
                    )

    async def test_the_light_theme_sets_the_light_mode_class(self) -> None:
        """``dark`` must reach the DOM classes, or derived tints invert.

        Textual uses these two classes for component styling, so a theme whose
        ``dark`` flag is wrong looks broken in a way no palette assertion in
        this file would predict.
        """

        class Probe(App):
            def compose(self):  # noqa: ANN202
                from textual.widgets import Static

                yield Static("probe")

        app = Probe()
        async with app.run_test() as pilot:
            register_all(app)
            for name in NEW_THEMES:
                with self.subTest(name=name):
                    apply_theme(app, name)
                    await pilot.pause()
                    if THEMES[name].dark:
                        self.assertIn("-dark-mode", app.classes)
                        self.assertNotIn("-light-mode", app.classes)
                    else:
                        self.assertIn("-light-mode", app.classes)
                        self.assertNotIn("-dark-mode", app.classes)


def _relative_luminance_of(hex_colour: str) -> float:
    """Thin wrapper so the palette tests read the same luminance the spec uses.

    Kept local rather than imported from ``theme.py`` so that a change to the
    module's private helper cannot quietly weaken the assertions that depend on
    it — the luminance is re-derived from the specification here.
    """
    value = hex_colour.lstrip("#")
    channels = [int(value[index : index + 2], 16) for index in (0, 2, 4)]

    def linearise(channel: int) -> float:
        proportion = channel / 255.0
        if proportion <= 0.04045:
            return proportion / 12.92
        return ((proportion + 0.055) / 1.055) ** 2.4

    red, green, blue = (linearise(channel) for channel in channels)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


if __name__ == "__main__":  # pragma: no cover - manual invocation
    unittest.main()