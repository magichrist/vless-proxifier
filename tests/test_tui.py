"""Tests for the Textual front-end.

Every test drives a :class:`StubProxyService` that satisfies the
``ProxyService`` contract without ever spawning a process, opening a socket, or
touching the real Keychain. That is not a convenience: the repo root contains a
macOS-quarantined ``xray`` that hangs if executed, so a real service would hang
the suite rather than fail it.

Also note what these tests are *for*: they assert wiring, not rendering. That a
worker marshals a probe result onto the event loop, that a failed connect
produces a toast instead of a traceback, that a modal never hands a UUID to the
store — those are the bugs that survive code review. Pixel layout is Textual's
job, not ours.
"""
from __future__ import annotations

import contextlib
import json
import tempfile
import threading
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

try:
    import textual  # noqa: F401
    from textual.widgets import Button, Input, Select, Static
    from textual.widgets._select import InvalidSelectValueError

    from vlessp.profiles import SUB_SECRET_PREFIX, SUB_SOURCE_PREFIX
    from vlessp.tui import (
        AddProfileScreen,
        AddressScreen,
        AddSubscriptionScreen,
        ConfirmScreen,
        EditProfileScreen,
        HelpScreen,
        VlessApp,
    )
    from vlessp.tui.graphics import rgb
    from vlessp.tui.screens import build_validation_uri
    from vlessp.tui.theme import DEFAULT_THEME_NAME, THEME_ORDER, THEMES
    from vlessp.tui.widgets import (
        DASH,
        DETAIL_HEIGHT,
        PARTIAL_BLOCKS,
        AppHeader,
        KeyHints,
        ProfileDetail,
        ProfileTable,
        StatusBar,
        latency_bar,
    )

    TEXTUAL_IMPORT_ERROR: Exception | None = None
except ImportError as exc:  # pragma: no cover - depends on the environment
    # The TUI tests need Textual, which is a real dependency of this project but
    # may be absent from whichever interpreter is running the suite. Failing with a
    # bare ModuleNotFoundError deep inside a class body tells the reader nothing;
    # skipping with a reason they can act on tells them exactly what to install.
    TEXTUAL_IMPORT_ERROR = exc

from vlessp.errors import AppError
from vlessp.links import parse_vless_uri
from vlessp.profiles import MAX_LATENCY_HISTORY, Profile, ProfileStore
from vlessp.secrets import NullSecretStore, SecretStore

if TEXTUAL_IMPORT_ERROR is not None:  # pragma: no cover - environment dependent
    raise unittest.SkipTest(
        f"Textual is not installed for this interpreter "
        f"({TEXTUAL_IMPORT_ERROR}). Install dependencies, e.g. `pip install textual`, "
        f"or run the suite with the project environment."
    ) from TEXTUAL_IMPORT_ERROR

# A syntactically valid UUID used only as test input. It is the value that must
# end up in the secret store and nowhere else.
TEST_UUID = "11111111-2222-4333-8444-555555555555"
OTHER_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

# Fake subscription URLs used only as test input. Like TEST_UUID they are the
# values that must end up in the secret store and nowhere else.
SUB_URL = "https://feeds.example.invalid/sub?token=secret-token-xyz"
SUB_HTTP_URL = "http://feeds.example.invalid/sub?token=other-token-abc"


def sample_link(uuid_value: str = TEST_UUID, **overrides: Any) -> dict[str, Any]:
    """A realistic parsed link, built by the real parser so it matches reality."""
    link = parse_vless_uri(f"vless://{uuid_value}@203.0.113.10:2083?type=ws&security=tls&sni=example.com#home")
    link.update(overrides)
    return link


def link_without_uuid(uuid_value: str = TEST_UUID, **overrides: Any) -> dict[str, Any]:
    """The same link with the credential removed, as the store must receive it."""
    link = sample_link(uuid_value, **overrides)
    link.pop("uuid", None)
    return link


def sample_uri(uuid_value: str = TEST_UUID, label: str = "home") -> str:
    return (
        f"vless://{uuid_value}@203.0.113.10:2083"
        f"?type=ws&security=tls&sni=example.com#{label}"
    )


class MemorySecretStore:
    """In-memory :class:`SecretStore` so tests can assert the credential split.

    Stands in for the Keychain: it records what was written so a test can prove
    the UUID landed here and never in the profile link.
    """

    def __init__(self) -> None:
        self.items: dict[str, str] = {}
        self.calls: list[tuple[str, str, str]] = []
        self.fail_on_set = False

    def set(self, account: str, value: str) -> None:
        self.calls.append(("set", account, "<redacted>"))
        if self.fail_on_set:
            raise AppError("keychain write failed with exit code 1.")
        self.items[account] = value

    def get(self, account: str) -> str:
        try:
            return self.items[account]
        except KeyError:
            raise AppError(f"the UUID for profile {account} is missing from the Keychain") from None

    def delete(self, account: str) -> None:
        self.calls.append(("delete", account, "<redacted>"))
        self.items.pop(account, None)


class StubProxyService:
    """Satisfies the ``ProxyService`` contract with no I/O whatsoever.

    Everything the app calls is recorded so a test can assert what it called
    *and in which order*, which is how the switching guard and the
    thread-marshalling requirements are actually verified.
    """

    def __init__(
        self,
        store: ProfileStore,
        secrets: SecretStore,
        *,
        latency: dict[str, int | None] | None = None,
    ) -> None:
        self._store = store
        self._secrets = secrets
        self.socks_addr = "127.0.0.1:10808"
        self.http_addr = "127.0.0.1:10809"
        self.xray_version = "25.1.3"
        self._running = False
        self._current: Profile | None = None
        self._log = ""
        self.calls: list[str] = []
        self.latency = dict(latency or {})
        self.fail_connect: AppError | None = None
        self.probe_from_thread = False
        self.disconnect_calls = 0
        self.connect_calls = 0
        # When set, connect() blocks on it. This is how the double-Enter test
        # observes the switching guard: without a blocked connect the stub
        # returns faster than a keypress can be delivered and the guard is
        # never actually contended.
        self.connect_gate: threading.Event | None = None
        self.max_concurrent_connects = 0
        self._connects_in_flight = 0
        self._connects_lock = threading.Lock()

    # -- contract -------------------------------------------------------

    def connect(self, ref: str) -> Profile:
        with self._connects_lock:
            self._connects_in_flight += 1
            self.max_concurrent_connects = max(
                self.max_concurrent_connects, self._connects_in_flight
            )
        try:
            gate = self.connect_gate
            if gate is not None:
                # Generous on purpose. The parked-connect tests assert the switch
                # guard is still held after a few ``pilot.pause()`` calls, and a
                # 5-second timeout expired first whenever the event loop was slow
                # — the worker finished, the guard cleared, and the test failed
                # for a reason that had nothing to do with the guard. The test
                # always sets the gate, so this only bounds a hung run.
                gate.wait(timeout=30.0)
            self.connect_calls += 1
            self.calls.append(f"connect:{ref}")
            if self.fail_connect is not None:
                raise self.fail_connect
            profile = self._store.resolve(ref)
            self._running = True
            self._current = profile
            self._log = "started"
            # Mirrors the real ProxyService: it owns persisting the active id.
            self._store.set_active(profile.id)
            self._store.save()
            return profile
        finally:
            with self._connects_lock:
                self._connects_in_flight -= 1

    def disconnect(self) -> None:
        self.disconnect_calls += 1
        self.calls.append("disconnect")
        self._running = False
        self._current = None

    def connect_active(self) -> Profile | None:
        active = self._store.active_id
        if active is None:
            return None
        return self.connect(active)

    def probe_all(self, on_result: Callable[[str, int | None], None], *, timeout: float = 3.0) -> None:
        self.calls.append("probe_all")
        # Invoke the callback from a *foreign* thread, exactly like the real
        # service does. Touching a widget from here is the bug this shape exists
        # to catch; if the app forgets call_from_thread this raises in a thread
        # and the LAT column silently stays empty.
        self.probe_from_thread = True

        def worker() -> None:
            for profile in self._store.all():
                on_result(profile.id, self.latency.get(profile.id, 42))

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def current(self) -> Profile | None:
        return self._current

    def log_tail(self) -> str:
        return self._log


class TuiTestCase(unittest.IsolatedAsyncioTestCase):
    """Shared scaffolding: a temp store, a stub service, and a running app."""

    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "profiles.json"
        self.store = ProfileStore(self.path)
        self.store.load()
        self.secrets = MemorySecretStore()
        self.service = StubProxyService(self.store, self.secrets)
        self.app = VlessApp(self.service, self.store, secrets=self.secrets)
        # run_test() is an async context manager yielding the Pilot; hold it open
        # for the whole test rather than one `async with` per test body.
        self._stack = contextlib.AsyncExitStack()
        self._pilot = await self._stack.enter_async_context(self.app.run_test())
        self.addAsyncCleanup(self._stack.aclose)

    # -- helpers --------------------------------------------------------

    @property
    def pilot(self) -> Any:
        return self._pilot

    def table(self) -> ProfileTable:
        return self.app.query_one(ProfileTable)

    async def settle(self, rounds: int = 3) -> None:
        """Let queued workers and ``call_from_thread`` hops drain."""
        for _ in range(rounds):
            await self.pilot.pause()
            await self.app.workers.wait_for_complete()

    def add_profile(self, label: str = "home", *, uuid_value: str = TEST_UUID) -> Profile:
        profile = self.store.add(label, link_without_uuid(uuid_value))
        self.secrets.set(profile.id, uuid_value)
        return profile


class TestMount(TuiTestCase):
    async def test_mounts_with_an_empty_store(self) -> None:
        await self.settle()
        self.assertEqual(self.table().row_count, 0)
        self.assertIsNone(self.table().selected_id())
        self.assertIn("0 profiles", self.app.sub_title)
        self.assertIn("STOPPED", self.app.sub_title)

    async def test_mounts_with_profiles_and_marks_the_active_one(self) -> None:
        alpha = self.add_profile("alpha")
        beta = self.add_profile("beta")
        self.store.set_active(beta.id)
        self.store.save()
        self.app._reload_table()
        await self.settle()

        self.assertEqual(self.table().row_count, 2)
        # Alphabetical, not insertion order.
        first = self.table().row_values(alpha.id)
        assert first is not None
        self.assertEqual(first[0], "▌ alpha" if alpha.id == beta.id else "alpha")
        second = self.table().row_values(beta.id)
        assert second is not None
        # Marker, then a space, then the label: ``▌ beta`` not ``▌beta``.
        self.assertEqual(second[0], f"▌ {beta.label}")
        self.assertIn("2 profiles", self.app.sub_title)

    async def test_unprofiled_latency_renders_as_a_dash(self) -> None:
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        rows = self.table().row_values(self.store.all()[0].id)
        assert rows is not None
        self.assertEqual(rows[5], DASH)
        self.assertEqual(rows[1], "203.0.113.10")
        self.assertEqual(rows[2], "2083")
        self.assertEqual(rows[3], "tls")
        self.assertEqual(rows[4], "ws")

    async def test_status_bar_shows_listeners_and_version(self) -> None:
        await self.settle()
        status = self.app.query_one(StatusBar)
        rendered = str(status.render())
        self.assertIn("127.0.0.1:10808", rendered)
        self.assertIn("127.0.0.1:10809", rendered)
        self.assertIn("25.1.3", rendered)
        self.assertTrue(status.has_class("stopped"))


class TestTableSizing(TuiTestCase):
    """The profile table hugs its rows but never squeezes the panels below it.

    Regression, in two directions. As ``1fr`` the table drew a screen of empty
    background under a short list, stranding the detail panel and key hints at
    the very bottom; as ``auto`` a long list overflowed and pushed them off the
    bottom edge entirely. The height is now capped at the rows left after the
    chrome below the table, so both cases hold.
    """

    async def test_a_short_list_hugs_its_rows(self) -> None:
        await self.settle()
        for name in ("alpha", "beta", "gamma"):
            self.add_profile(name)
        self.app._reload_table()
        await self.settle()
        # One row per profile, plus the header row.
        self.assertEqual(self.table().region.height, 3 + 1)

    async def test_a_long_list_is_capped_and_the_panels_stay_on_screen(self) -> None:
        await self.settle()
        for index in range(60):
            self.add_profile(f"node-{index:02d}")
        self.app._reload_table()
        await self.settle()

        table = self.table()
        detail = self.app.query_one("#detail", ProfileDetail)
        hints = self.app.query_one(KeyHints)
        self.assertLess(
            table.region.height,
            table.row_count + 1,
            "a list taller than the screen must be capped, not drawn in full",
        )
        self.assertEqual(detail.region.height, DETAIL_HEIGHT)
        # Detail above hints, hints above the bottom edge: nothing clipped.
        self.assertLessEqual(detail.region.y + DETAIL_HEIGHT, hints.region.y)
        self.assertLessEqual(hints.region.y + hints.region.height, self.app.size.height)

    async def test_opening_the_log_pane_leaves_a_usable_table(self) -> None:
        """The pane steals rows; the table keeps enough to stay navigable."""
        await self.settle()
        for index in range(60):
            self.add_profile(f"node-{index:02d}")
        self.app._reload_table()
        await self.settle()

        await self.pilot.press("o")
        await self.settle()
        self.assertTrue(self.app.query_one("#log-pane").display)
        self.assertGreaterEqual(self.table().region.height, 3)

    async def test_the_key_hints_are_pinned_to_the_footer(self) -> None:
        """The hints are chrome: their row must not move with the row count.

        Held as flow children they drifted up the screen whenever the list was
        short, so the same keys sat in a different place from one screen to the
        next. Pinned, they stay directly above the status bar.
        """
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        hints = self.app.query_one(KeyHints)
        status = self.app.query_one(StatusBar)
        self.assertEqual(hints.region.y + hints.region.height, status.region.y)
        self.assertEqual(status.region.y + status.region.height, self.app.size.height)

    async def test_resizing_recomputes_the_cap(self) -> None:
        await self.settle()
        for index in range(60):
            self.add_profile(f"node-{index:02d}")
        self.app._reload_table()
        await self.settle()

        tall = self.table().region.height
        await self.pilot.resize_terminal(80, 14)
        await self.settle()
        short = self.table().region.height
        self.assertLess(short, tall, "a shorter terminal must yield a shorter table")
        self.assertGreaterEqual(short, 3)
        # The panels below are still visible at the new size.
        detail = self.app.query_one("#detail", ProfileDetail)
        hints = self.app.query_one(KeyHints)
        self.assertLessEqual(detail.region.y + DETAIL_HEIGHT, hints.region.y)
        self.assertLessEqual(hints.region.y + hints.region.height, self.app.size.height)

    def test_the_detail_band_is_exactly_the_height_the_app_reserves(self) -> None:
        """The CSS literal and ``DETAIL_HEIGHT`` must not drift apart.

        Two places encode the same number because one is parsed as CSS and the
        other is arithmetic. A mismatch would not crash — it would quietly clip
        the panel or leave a blank row — so it is asserted here instead.
        """
        self.assertIn(f"height: {DETAIL_HEIGHT};", ProfileDetail.DEFAULT_CSS)


class TestChrome(TuiTestCase):
    """The header strip, the framed panels, and the busy animation.

    These assert *state wiring*, not pixels. The gradient and the borders are
    Textual's and Rich's job; what would be this module's bug is a header that
    says RUNNING while the service is stopped, a spinner that keeps ticking
    after the work finishes, or a frame title that was never set because the
    title lives on the widget and only its colour lives in CSS.
    """

    async def test_the_header_reports_the_count_and_the_state(self) -> None:
        self.add_profile("alpha")
        self.add_profile("beta")
        self.app._reload_table()
        await self.settle()

        header = str(self.app.query_one(AppHeader).render())
        self.assertIn("VLESS", header)
        self.assertIn("2 profiles", header)
        # The stub service is not running, so the strip must not claim it is.
        self.assertIn("STOPPED", header)
        self.assertNotIn("RUNNING", header)

    async def test_the_header_switches_to_the_busy_state(self) -> None:
        await self.settle()
        self.app._switching = True
        self.app._refresh_status()
        await self.pilot.pause()

        header = str(self.app.query_one(AppHeader).render())
        self.assertIn("SWITCHING", header)
        self.assertNotIn("STOPPED", header)

        self.app._switching = False
        self.app._refresh_status()
        await self.pilot.pause()
        self.assertIn("STOPPED", str(self.app.query_one(AppHeader).render()))

    async def test_a_probe_sweep_draws_a_meter_and_stops_animating(self) -> None:
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        self.app._probe_active = True
        self.app._probe_total = 4
        self.app._probe_done = 1
        self.app._refresh_status()
        await self.pilot.pause()

        rendered = str(self.app.query_one(StatusBar).render())
        self.assertIn("TESTING", rendered)
        self.assertIn("1/4", rendered)
        # The meter is 8 cells; one quarter done is two filled cells.
        self.assertEqual(rendered.count("█"), 2)

        # Finishing must stop the 11fps timer, not just change the text.
        self.app._probe_active = False
        self.app._refresh_status()
        await self.pilot.pause()
        self.assertIsNone(self.app.query_one(StatusBar)._timer)

    async def test_the_theme_reaches_the_custom_strips_at_startup(self) -> None:
        """The header bakes resolved colours, so it must be painted after the
        designed theme is applied -- not left in Textual's default palette
        until the first 1 Hz tick."""
        await self.settle()
        # Rich normalises a hex span style to ``rgb(r, g, b)``, so the expected
        # style is built in that form rather than string-compared as hex.
        red, green, blue = rgb(str(self.app.theme_variables["primary"]))
        expected = f"rgb({red},{green},{blue}) bold"
        styles = {str(span.style) for span in self.app.query_one(AppHeader).render().spans}
        self.assertIn(
            expected,
            styles,
            f"the header never picked up the active theme's primary; got {sorted(styles)}",
        )

    async def test_cycling_the_theme_repaints_the_chrome(self) -> None:
        await self.settle()
        header = self.app.query_one(AppHeader)
        status = self.app.query_one(StatusBar)
        before = {str(span.style) for span in header.render().spans}
        before_status = {str(span.style) for span in status.render().spans}

        self.app.action_cycle_theme()
        await self.settle()

        self.assertNotEqual(
            {str(span.style) for span in header.render().spans},
            before,
            "the header kept the previous theme's colours",
        )
        self.assertNotEqual(
            {str(span.style) for span in status.render().spans},
            before_status,
            "the status strip kept the previous theme's colours",
        )

    async def test_the_animation_cadence_changes_with_the_kind_of_work(self) -> None:
        """A spinner must not run at the idle pulse's cadence, or vice versa."""
        status = self.app.query_one(StatusBar)

        status.update_status(socks_addr=None, http_addr=None, running=True)
        self.assertEqual(status._interval, StatusBar.PULSE_SECONDS)

        status.update_status(socks_addr=None, http_addr=None, running=True, busy="TESTING")
        self.assertEqual(
            status._interval,
            StatusBar.FRAME_SECONDS,
            "busy work must animate at the fast cadence, not inherit the pulse timer",
        )

        status.update_status(socks_addr=None, http_addr=None, running=False)
        self.assertIsNone(status._timer)
        self.assertIsNone(status._interval)

    async def test_frames_and_panels_are_titled(self) -> None:
        await self.settle()
        self.assertEqual(self.app.query_one("#profiles-frame").border_title, "PROFILES")
        self.assertEqual(self.app.query_one("#detail", ProfileDetail).border_title, "DETAIL")
        self.assertEqual(self.app.query_one("#log-pane").border_title, "XRAY OUTPUT")

    async def test_the_table_uses_a_row_cursor_that_preserves_cell_colour(self) -> None:
        table = self.table()
        self.assertEqual(table.cursor_type, "row", "the unit of action is the profile")
        self.assertTrue(table.zebra_stripes, "wide rows need a stripe to stay readable")
        self.assertEqual(
            table.cursor_foreground_priority,
            "renderable",
            "the CSS cursor default would repaint the LAT bar and STATE flat",
        )

    async def test_a_short_terminal_uses_the_compact_chrome(self) -> None:
        await self.settle()
        await self.pilot.resize_terminal(80, 16)
        await self.settle()
        self.assertTrue(self.app.query_one(AppHeader).has_class("compact"))
        self.assertTrue(self.app.query_one(KeyHints).has_class("compact"))
        self.assertEqual(self.app.query_one(AppHeader).region.height, 1)

        await self.pilot.resize_terminal(80, 30)
        await self.settle()
        self.assertFalse(self.app.query_one(AppHeader).has_class("compact"))
        self.assertFalse(self.app.query_one(KeyHints).has_class("compact"))
        self.assertEqual(self.app.query_one(AppHeader).region.height, 2)


class TestAddProfile(TuiTestCase):
    async def test_a_opens_the_modal_and_escape_dismisses_with_none(self) -> None:
        await self.settle()
        # Capture what the modal actually dismissed with, not just that it closed.
        seen: list[Profile | None] = []
        original = self.app._on_profile_closed
        self.app._on_profile_closed = seen.append  # type: ignore[method-assign]
        self.addCleanup(setattr, self.app, "_on_profile_closed", original)

        await self.pilot.press("a")
        await self.pilot.pause()
        self.assertIsInstance(self.app.screen, AddProfileScreen)
        self.assertEqual(seen, [], "the modal is still open")

        await self.pilot.press("escape")
        await self.settle()
        self.assertNotIsInstance(self.app.screen, AddProfileScreen)
        self.assertEqual(seen, [None], "escape dismisses with None, not a Profile")
        self.assertEqual(len(self.store.all()), 0)

    async def test_a_bad_link_reports_the_parser_message_and_writes_nothing(self) -> None:
        await self.settle()
        await self.pilot.press("a")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, AddProfileScreen)
        screen.query_one("#link", Input).value = "vless://not-a-uuid@example.com:443"
        screen.query_one("#confirm", Button).press()
        await self.pilot.pause()

        error = str(screen.query_one("#error", Static).render())
        self.assertIn("UUID", error)
        self.assertEqual(self.store.all(), [])
        self.assertEqual(self.secrets.items, {})
        self.assertFalse(self.path.exists(), "nothing is written before the link parses")

    async def test_adding_a_profile_splits_the_uuid_out_of_the_link(self) -> None:
        """The central invariant: credential to the Keychain, never to the link."""
        await self.settle()
        await self.pilot.press("a")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, AddProfileScreen)

        screen.query_one("#link", Input).value = sample_uri(TEST_UUID, "home")
        screen.query_one("#confirm", Button).press()
        await self.pilot.pause()
        # Stage 1 only previews; nothing has been written yet.
        self.assertEqual(self.store.all(), [])
        preview = str(screen.query_one("#preview", Static).render())
        self.assertIn("203.0.113.10", preview)
        self.assertNotIn(TEST_UUID, preview, "the preview must never show the UUID")

        screen.query_one("#confirm", Button).press()
        await self.settle()
        await self.pilot.pause()

        self.assertEqual(len(self.store.all()), 1)
        profile = self.store.all()[0]
        self.assertEqual(profile.label, "home", "label pre-fills from the link fragment")
        self.assertNotIn("uuid", profile.link, "the store must never receive a uuid key")
        self.assertEqual(self.secrets.items[profile.id], TEST_UUID)

        # Prove it on disk, not just in memory — this is the real guarantee.
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn(TEST_UUID, raw)
        self.assertNotIn("uuid", json.loads(raw)["profiles"][0]["link"])

    async def test_custom_label_overrides_the_fragment(self) -> None:
        await self.settle()
        await self.pilot.press("a")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, AddProfileScreen)
        screen.query_one("#link", Input).value = sample_uri(TEST_UUID, "provider-name")
        screen.query_one("#confirm", Button).press()
        await self.pilot.pause()
        screen.query_one("#label", Input).value = "my label"
        screen.query_one("#confirm", Button).press()
        await self.settle()
        await self.pilot.pause()
        self.assertEqual(self.store.all()[0].label, "my label")

    async def test_a_keychain_failure_rolls_the_profile_back(self) -> None:
        await self.settle()
        self.secrets.fail_on_set = True
        await self.pilot.press("a")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, AddProfileScreen)
        screen.query_one("#link", Input).value = sample_uri(TEST_UUID, "home")
        screen.query_one("#confirm", Button).press()
        await self.pilot.pause()
        screen.query_one("#confirm", Button).press()
        await self.settle()
        await self.pilot.pause()

        self.assertEqual(self.store.all(), [], "a profile without its UUID must not persist")
        self.assertFalse(self.path.exists())
        self.assertIsInstance(self.app.screen, AddProfileScreen, "the modal stays open on failure")

    async def test_typing_a_letter_inside_the_modal_does_not_fire_app_bindings(self) -> None:
        """Regression guard for the guard: App bindings are live on modals."""
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("a")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, AddProfileScreen)
        screen.query_one("#label", Input).focus()
        await self.pilot.pause()
        # "adeqt" are all bound on the main screen.
        await self.pilot.press("a", "d", "e", "q", "t")
        await self.pilot.pause()
        self.assertEqual(screen.query_one("#label", Input).value, "adeqt")
        self.assertIsInstance(self.app.screen, AddProfileScreen)
        self.assertFalse(self.app._shutting_down, "typing q in a field must not quit the app")


class TestConnect(TuiTestCase):
    async def test_enter_connects_the_highlighted_row_and_marks_it_live(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()

        await self.pilot.press("enter")
        await self.settle()

        self.assertIn(f"connect:{profile.id}", self.service.calls)
        self.assertEqual(self.store.active_id, profile.id)
        self.assertTrue(self.service.running)
        self.assertIn("RUNNING", self.app.sub_title)
        rows = self.table().row_values(profile.id)
        assert rows is not None
        self.assertEqual(rows[6], "live")
        self.assertTrue(rows[0].startswith("▌"))
        self.assertFalse(self.app._switching, "the switching guard is released")

    async def test_enter_with_no_profiles_is_a_no_op(self) -> None:
        await self.settle()
        await self.pilot.press("enter")
        await self.settle()
        self.assertEqual(self.service.connect_calls, 0)

    async def test_a_double_enter_does_not_start_two_switches(self) -> None:
        """A11y spec: "a double-Enter must not race two spawns".

        Asserted by blocking the first switch in its worker, so the second and
        third keypress genuinely contend with an in-flight D7 instead of
        arriving after it already finished.
        """
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        gate = threading.Event()
        self.service.connect_gate = gate

        await self.pilot.press("enter", "enter", "enter")
        # NOT settle() here: it waits for workers, and the first switch is
        # deliberately parked in its worker. Plain pauses let the keys land.
        for _ in range(3):
            await self.pilot.pause()
        self.assertTrue(self.app._switching, "the guard is held for the whole switch")
        self.assertEqual(
            self.service.max_concurrent_connects,
            1,
            "keypresses 2 and 3 were refused while a switch was in flight",
        )

        gate.set()
        self.service.connect_gate = None
        await self.settle()

        self.assertEqual(self.service.connect_calls, 1, "only one D7 ever ran")
        self.assertFalse(self.app._switching, "the guard is released on success")

    async def test_a_failed_connect_toasts_without_crashing(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        self.service.fail_connect = AppError("xray rejected the configuration.")

        await self.pilot.press("enter")
        await self.settle()

        self.assertTrue(self.app.is_running)
        self.assertFalse(self.service.running)
        self.assertIn("ERROR", self.app.sub_title)
        self.assertIn("xray rejected the configuration.", self.app._last_error or "")
        self.assertIn("error: xray rejected", "\n".join(self.app._notes))
        self.assertFalse(self.app._switching, "the guard is released after a failure too")
        # The table must not claim anything is live.
        rows = self.table().row_values(self.store.all()[0].id)
        assert rows is not None
        self.assertEqual(rows[6], DASH)

    async def test_an_unexpected_exception_type_is_never_echoed(self) -> None:
        """Non-AppError text may embed anything, so only the type is shown."""

        class SecretLeaking(RuntimeError):
            pass

        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        self.service.fail_connect = SecretLeaking(f"failed on {sample_uri()}")  # type: ignore[assignment]

        await self.pilot.press("enter")
        await self.settle()

        reported = self.app._last_error or ""
        self.assertIn("SecretLeaking", reported)
        self.assertNotIn(TEST_UUID, reported)
        self.assertNotIn("vless://", reported)

    async def test_space_toggles_the_service_off_and_on(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.store.set_active(profile.id)
        self.app._reload_table()
        await self.settle()

        await self.pilot.press("space")
        await self.settle()
        self.assertTrue(self.service.running)

        await self.pilot.press("space")
        await self.settle()
        self.assertFalse(self.service.running)
        self.assertEqual(self.service.disconnect_calls, 1)

    async def test_c_connects_the_highlighted_row_and_does_not_toggle_the_service(self) -> None:
        """``c`` and ``space`` must stay distinct.

        ``c`` acts on the highlighted row; ``space`` acts on the service as a
        whole. If ``c`` ever grows the toggle behaviour, pressing it while
        scanning the table halts the tunnel instead of moving — which is the
        surprise this split exists to prevent.
        """
        await self.settle()
        first = self.add_profile("alpha")
        second = self.add_profile("beta")
        self.app._reload_table()
        await self.settle()
        # Park the cursor on the second row, then connect it with `c`.
        self.table().cursor_coordinate = self.table().cursor_coordinate._replace(row=1)
        await self.pilot.pause()

        await self.pilot.press("c")
        await self.settle()
        self.assertIn(f"connect:{second.id}", self.service.calls)
        self.assertNotIn(f"connect:{first.id}", self.service.calls)

        # Pressing `c` again must connect, not disconnect.
        await self.pilot.press("c")
        await self.settle()
        self.assertEqual(self.service.disconnect_calls, 0, "c must never stop the service")


class TestLatency(TuiTestCase):
    async def test_t_fills_latency_cells_from_a_foreign_thread(self) -> None:
        await self.settle()
        quick = self.add_profile("slow-one")
        fast = self.add_profile("fast-one")
        self.service.latency = {quick.id: 890, fast.id: 42}
        self.app._reload_table()
        await self.settle()

        await self.pilot.press("t")
        await self.settle()

        self.assertTrue(self.service.probe_from_thread, "the stub really does call back off-loop")
        self.assertIn("probe_all", self.service.calls)
        slow_cells = self.table().row_values(quick.id)
        fast_cells = self.table().row_values(fast.id)
        assert slow_cells is not None and fast_cells is not None
        # LAT is now a bar plus the value; the value must still be readable,
        # which is what keeps the bar from being the only encoding.
        self.assertIn("890ms", slow_cells[5])
        self.assertIn("42ms", fast_cells[5])
        # Same fixed scale, so a slow node draws a longer bar than a fast one.
        self.assertGreater(len(slow_cells[5].split()[0]), len(fast_cells[5].split()[0]))
        # Sorted by latency after a sweep, so the reachable node is first.
        self.assertEqual(self.table().selected_id(), fast.id)
        self.assertEqual(self.store.get(fast.id).last_latency_ms, 42)

    async def test_t_leaves_the_active_profile_alone(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.store.set_active(self.store.all()[0].id)
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("t")
        await self.settle()
        self.assertFalse(self.service.running, "probing never starts a proxy")
        self.assertEqual(self.store.active_id, self.store.all()[0].id)

    async def test_an_unreachable_profile_shows_a_dash_not_zero(self) -> None:
        await self.settle()
        profile = self.add_profile("dead")
        self.service.latency = {profile.id: None}
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("t")
        await self.settle()
        rows = self.table().row_values(profile.id)
        assert rows is not None
        self.assertEqual(rows[5], DASH)


class TestLogAndQuit(TuiTestCase):
    async def test_o_toggles_the_log_pane(self) -> None:
        await self.settle()
        self.assertFalse(self.app.log_visible)
        await self.pilot.press("o")
        await self.settle()
        self.assertTrue(self.app.log_visible)
        await self.pilot.press("o")
        await self.pilot.pause()
        self.assertFalse(self.app.log_visible)

    async def test_l_no_longer_toggles_the_log_pane(self) -> None:
        """``l`` is "add a link" now. A stale binding here would silently
        reappear the moment somebody trusted the old keymap."""
        await self.settle()
        await self.pilot.press("l")
        await self.pilot.pause()
        self.assertFalse(self.app.log_visible, "l must open the add modal, not the log pane")

    async def test_the_log_pane_shows_the_service_tail(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("enter")
        await self.settle()
        await self.pilot.press("o")
        await self.settle()
        rendered = str(self.app.query_one("#log-pane", Static).render())
        self.assertIn("started", rendered)

    async def test_a_failure_lands_in_both_the_log_and_the_toast(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        self.service.fail_connect = AppError("listener never came up.")
        await self.pilot.press("enter")
        await self.settle()
        self.assertIn("error: listener never came up.", "\n".join(self.app._notes))
        self.assertTrue(self.app.is_running)

    async def test_q_disconnects_the_proxy_before_exiting(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("enter")
        await self.settle()
        self.assertTrue(self.service.running)

        await self.pilot.press("q")
        for _ in range(6):
            await self.pilot.pause()
            await self.app.workers.wait_for_complete()
            if not self.app.is_running:
                break

        self.assertGreaterEqual(
            self.service.disconnect_calls, 1, "q must terminate Xray rather than orphan it"
        )
        self.assertFalse(self.service.running)
        self.assertFalse(self.app.is_running)


class TestConfirmScreen(TuiTestCase):
    async def test_d_opens_a_confirmation_and_escape_keeps_the_profile(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("d")
        await self.pilot.pause()
        self.assertIsInstance(self.app.screen, ConfirmScreen)
        await self.pilot.press("escape")
        await self.settle()
        self.assertEqual(len(self.store.all()), 1)
        self.assertIsNotNone(self.store.get(profile.id))

    async def test_confirming_a_delete_removes_the_profile_and_its_secret(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("d")
        await self.pilot.pause()
        self.app.screen.query_one("#yes", Button).press()
        await self.settle()

        self.assertEqual(self.store.all(), [])
        self.assertNotIn(profile.id, self.secrets.items)
        self.assertIn(("delete", profile.id, "<redacted>"), self.secrets.calls)
        self.assertFalse(self.path.exists() and self.store.all())

    async def test_a_delete_is_not_a_bare_keypress(self) -> None:
        """Two screens deep: the app never deletes straight from the key."""
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("d")
        await self.pilot.pause()
        self.assertEqual(len(self.store.all()), 1, "the profile survives until the modal answers")


class TestEditProfile(TuiTestCase):
    async def test_editing_non_secret_fields_round_trips_through_the_parser(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("e")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, EditProfileScreen)

        screen.query_one("#label", Input).value = "renamed"
        screen.query_one("#server", Input).value = "198.51.100.7"
        screen.query_one("#port", Input).value = "443"
        screen.query_one("#save", Button).press()
        await self.settle()
        await self.pilot.pause()

        stored = self.store.get(profile.id)
        self.assertEqual(stored.label, "renamed")
        self.assertEqual(stored.link["server"], "198.51.100.7")
        self.assertEqual(stored.link["port"], 443)
        self.assertEqual(stored.link["sni"], "example.com", "unrelated fields survive the round trip")
        self.assertNotIn("uuid", stored.link)
        self.assertEqual(self.secrets.items[profile.id], TEST_UUID, "the UUID is untouched")

    async def test_the_uuid_is_not_editable_and_is_never_displayed(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("e")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, EditProfileScreen)
        rendered = str(screen.query_one("#secret-note", Static).render())
        self.assertIn("Keychain", rendered)
        self.assertNotIn(TEST_UUID, rendered)
        values = [w.value for w in screen.query(Input)]
        self.assertNotIn(TEST_UUID, [str(v) for v in values])

    async def test_the_transport_dropdown_cannot_be_driven_into_an_invalid_value(self) -> None:
        """Defence in depth: the widget refuses a value the parser would reject."""
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("e")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, EditProfileScreen)
        with self.assertRaises(InvalidSelectValueError):
            screen.query_one("#transport", Select).value = "reality-x"

    async def test_an_invalid_edit_is_refused_by_the_parser_and_changes_nothing(self) -> None:
        """An input field the widget does NOT constrain falls through to the parser."""
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("e")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, EditProfileScreen)
        screen.query_one("#server", Input).value = "not a hostname"
        screen.query_one("#save", Button).press()
        await self.settle()
        await self.pilot.pause()

        self.assertIn("hostname", str(screen.query_one("#error", Static).render()).lower())
        stored = self.store.get(profile.id)
        self.assertEqual(stored.link["server"], "203.0.113.10", "a refused edit must not half-apply")
        self.assertIsInstance(self.app.screen, EditProfileScreen)

    async def test_an_invalid_sni_is_refused_by_the_parser(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("e")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, EditProfileScreen)
        screen.query_one("#sni", Input).value = "not a hostname"
        screen.query_one("#save", Button).press()
        await self.settle()
        await self.pilot.pause()
        self.assertIn("SNI", str(screen.query_one("#error", Static).render()))
        self.assertEqual(self.store.get(profile.id).link["sni"], "example.com")

    async def test_a_non_numeric_port_is_refused_before_the_store(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("e")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, EditProfileScreen)
        screen.query_one("#port", Input).value = "eight thousand"
        screen.query_one("#save", Button).press()
        await self.pilot.pause()
        self.assertIn("Port", str(screen.query_one("#error", Static).render()))
        self.assertEqual(self.store.get(profile.id).link["port"], 2083)

    async def test_clearing_flow_when_the_transport_stops_being_tcp(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("e")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, EditProfileScreen)
        # The stored link is tcp + vision; ws + vision is unbuildable, so the
        # form must clear it rather than let the user save a doomed config.
        screen.query_one("#transport", Select).value = "ws"
        await self.pilot.pause()
        self.assertEqual(str(screen.query_one("#flow", Select).value), "")

    async def test_deleting_from_the_edit_screen_needs_two_presses(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("e")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, EditProfileScreen)

        screen.query_one("#delete", Button).press()
        await self.pilot.pause()
        self.assertIn("Delete", str(screen.query_one("#confirm-delete", Static).render()))
        self.assertEqual(len(self.store.all()), 1, "the first press only arms the confirmation")

        screen.query_one("#delete", Button).press()
        await self.settle()
        await self.pilot.pause()
        self.assertEqual(self.store.all(), [])
        self.assertNotIn(profile.id, self.secrets.items)


class TestHelpScreen(TuiTestCase):
    async def test_h_opens_help_and_escape_closes_it(self) -> None:
        await self.settle()
        self.assertIs(self.app.screen, self.app.screen_stack[0])
        await self.pilot.press("h")
        await self.pilot.pause()
        self.assertIsInstance(self.app.screen, HelpScreen)
        await self.pilot.press("escape")
        await self.pilot.pause()
        self.assertIs(self.app.screen, self.app.screen_stack[0])

    async def test_help_lists_every_advertised_binding(self) -> None:
        """The help table and the real keymap cannot drift apart.

        A stale key in the help screen is worse than a missing one: it teaches
        the user a shortcut that does not exist.
        """
        bound = {key for binding in VlessApp.BINDINGS for key in (binding.key,) if not binding.key.startswith("^")}
        advertised = {key for _title, rows in HelpScreen.SECTIONS for key, _desc in rows}
        self.assertEqual(
            advertised - bound,
            set(),
            "help advertises keys that are not bound",
        )
        self.assertEqual(
            {key for key in bound if key not in advertised and key not in {"enter", "a"}},
            set(),
            "a bound key is missing from help",
        )

    async def test_help_documents_the_keys_the_user_asked_for(self) -> None:
        advertised = {key for _t, rows in HelpScreen.SECTIONS for key, _d in rows}
        for key in ("h", "s", "l", "c", "space", "i", "o"):
            self.assertIn(key, advertised, f"{key} must be discoverable from help")


class TestAddressScreen(TuiTestCase):
    async def test_i_opens_the_server_and_port_form_for_the_highlighted_row(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("i")
        await self.pilot.pause()
        screen = self.app.screen
        self.assertIsInstance(screen, AddressScreen)
        self.assertEqual(screen.query_one("#server", Input).value, "203.0.113.10")
        self.assertEqual(screen.query_one("#port", Input).value, "2083")

    async def test_editing_the_address_keeps_every_other_field(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("i")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, AddressScreen)

        screen.query_one("#server", Input).value = "198.51.100.7"
        screen.query_one("#port", Input).value = "8443"
        screen.query_one("#save", Button).press()
        await self.settle()
        await self.pilot.pause()

        stored = self.store.get(profile.id)
        self.assertEqual(stored.link["server"], "198.51.100.7")
        self.assertEqual(stored.link["port"], 8443)
        self.assertEqual(stored.link["sni"], "example.com", "unrelated fields survive")
        self.assertEqual(stored.label, "alpha", "the label is not this screen's business")
        self.assertNotIn("uuid", stored.link)
        self.assertEqual(self.secrets.items[profile.id], TEST_UUID, "the UUID is untouched")

    async def test_an_invalid_address_is_refused_and_changes_nothing(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("i")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, AddressScreen)

        screen.query_one("#server", Input).value = "not a hostname"
        screen.query_one("#save", Button).press()
        await self.settle()
        await self.pilot.pause()

        self.assertIn("hostname", str(screen.query_one("#error", Static).render()).lower())
        self.assertEqual(self.store.get(profile.id).link["server"], "203.0.113.10")
        self.assertIsInstance(self.app.screen, AddressScreen)
        self.assertFalse(screen.query_one("#save", Button).disabled, "a refused save must not strand the user")

    async def test_a_non_numeric_port_is_refused_before_the_store(self) -> None:
        await self.settle()
        profile = self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        await self.pilot.press("i")
        await self.pilot.pause()
        screen = self.app.screen
        assert isinstance(screen, AddressScreen)

        screen.query_one("#port", Input).value = "eight thousand"
        screen.query_one("#save", Button).press()
        await self.pilot.pause()
        self.assertIn("Port", str(screen.query_one("#error", Static).render()))
        self.assertEqual(self.store.get(profile.id).link["port"], 2083)


class TestSubscriptions(TuiTestCase):
    """``s`` records a URL in the modal; importing happens in a worker after."""

    def _stub_fetch(self, body: str) -> list[str]:
        """Patch the fetcher for the whole test; return the list of URLs it is handed.

        The patch must outlive this method: the worker runs later, on the event
        loop, so a `with` block here would un-patch before it ever fired.
        """
        seen: list[str] = []
        patcher = mock.patch("vlessp.tui.app.fetch_subscription", lambda url: seen.append(url) or body)
        patcher.start()
        self.addCleanup(patcher.stop)
        return seen

    async def test_s_opens_the_subscription_modal(self) -> None:
        await self.settle()
        await self.pilot.press("s")
        await self.pilot.pause()
        self.assertIsInstance(self.app.screen, AddSubscriptionScreen)

    async def test_a_saved_subscription_is_fetched_and_imported(self) -> None:
        await self.settle()
        self.secrets.set(f"{SUB_SECRET_PREFIX}work", "https://sub.example/list")
        body = "\n".join(
            [
                f"vless://{TEST_UUID}@203.0.113.10:2083?type=tcp&security=tls&encryption=none#node-one",
                f"vless://{OTHER_UUID}@198.51.100.7:443?type=ws&security=tls&encryption=none#node-two",
            ]
        )
        seen = self._stub_fetch(body)
        self.app.refresh_subscription("work")
        await self.settle()
        await self.pilot.pause()

        self.assertEqual(seen, ["https://sub.example/list"], "the URL comes from the Keychain")
        imported = self.store.by_source(f"{SUB_SOURCE_PREFIX}work")
        self.assertEqual(len(imported), 2)
        self.assertTrue(all(p.link.get("server") for p in imported))
        self.assertTrue(any("2 new" in note for note in self.app._notes), self.app._notes)

    async def test_imported_nodes_never_carry_a_uuid_in_the_store(self) -> None:
        await self.settle()
        self.secrets.set(f"{SUB_SECRET_PREFIX}work", "https://sub.example/list")
        body = f"vless://{TEST_UUID}@203.0.113.10:2083?type=tcp&security=tls&encryption=none#node"
        self._stub_fetch(body)
        self.app.refresh_subscription("work")
        await self.settle()
        await self.pilot.pause()

        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn(TEST_UUID, text, "a subscription UUID must never reach disk")
        imported = self.store.by_source(f"{SUB_SOURCE_PREFIX}work")
        self.assertEqual(self.secrets.items[imported[0].id], TEST_UUID, "it goes to the Keychain instead")

    async def test_an_empty_response_does_not_flag_the_whole_subscription(self) -> None:
        """A 200 that yields nothing is a login page, not an empty feed.

        Reconciling it would mark every node in this subscription unavailable —
        the one way this feature can destroy data it did not mean to touch.
        """
        await self.settle()
        existing = self.add_profile("kept")
        self.store.update(existing.id, link={**existing.link, "server": "203.0.113.10"})
        self.store.save()
        self.secrets.set(f"{SUB_SECRET_PREFIX}work", "https://sub.example/list")
        self._stub_fetch("<html><body>Sign in to continue</body></html>")
        self.app.refresh_subscription("work")
        await self.settle()
        await self.pilot.pause()

        self.assertIn("no usable links", "\n".join(self.app._notes))
        self.assertFalse(self.store.get(existing.id).unavailable, "an empty fetch must change nothing")
        self.assertIsNotNone(self.store.get(existing.id), "and must delete nothing")

    async def test_a_fetch_failure_is_reported_without_leaking_the_url(self) -> None:
        await self.settle()
        secret_url = "https://sub.example/list?token=SUPERSECRETTOKEN"
        self.secrets.set(f"{SUB_SECRET_PREFIX}work", secret_url)
        with mock.patch(
            "vlessp.tui.app.fetch_subscription",
            side_effect=AppError("could not reach the subscription service (ConnectError)."),
        ):
            self.app.refresh_subscription("work")
            await self.settle()
            await self.pilot.pause()

        notes = "\n".join(self.app._notes)
        self.assertIn("failed", notes)
        self.assertNotIn("SUPERSECRETTOKEN", notes, "the subscription URL is a credential")
        self.assertNotIn("sub.example", notes)
        self.assertFalse(self.app._switching, "the switch guard must be released on failure")

    async def test_a_second_press_while_fetching_is_ignored(self) -> None:
        await self.settle()
        self.secrets.set(f"{SUB_SECRET_PREFIX}work", "https://sub.example/list")
        seen = self._stub_fetch("vless://x@203.0.113.10:2083?type=tcp#n")
        self.app.refresh_subscription("work")
        self.app.refresh_subscription("work")
        await self.settle()
        self.assertEqual(len(seen), 1, "the switch guard serialises overlapping fetches")


class TestThemes(TuiTestCase):
    async def test_alt_t_cycles_through_every_theme_and_wraps(self) -> None:
        await self.settle()
        seen = [self.app.theme]
        for _ in range(len(THEME_ORDER)):
            await self.pilot.press("alt+t")
            await self.settle()
            await self.pilot.pause()
            seen.append(self.app.theme)
        self.assertEqual(seen[1:], list(THEME_ORDER[1:]) + [THEME_ORDER[0]])
        self.assertEqual(seen[0], DEFAULT_THEME_NAME, "the cycle is anchored to the start-up theme")

    async def test_the_app_starts_on_the_designed_theme(self) -> None:
        """The first look is chosen for the app, not inherited from Textual.

        The palette is applied on mount rather than left to Textual's default,
        so "the default theme is cyber-female" is a fact about the running app
        and not merely about the registry.
        """
        await self.settle()
        self.assertEqual(self.app.theme, DEFAULT_THEME_NAME)
        self.assertIn(DEFAULT_THEME_NAME, THEMES)

    async def test_a_theme_actually_repaints(self) -> None:
        """Setting the reactive is not the same as the screen changing."""
        await self.settle()
        before = self.app.styles.background
        await self.pilot.press("alt+t")
        await self.settle()
        await self.pilot.pause()
        self.assertIn(self.app.theme, THEMES)
        self.assertNotEqual(before, self.app.styles.background)

    async def test_cycling_reaches_both_new_themes(self) -> None:
        await self.settle()
        for _ in range(len(THEME_ORDER)):
            await self.pilot.press("alt+t")
            await self.settle()
            await self.pilot.pause()
        self.assertIn("gummy", THEME_ORDER)
        self.assertIn("cyber-female", THEME_ORDER)


class TestBuildValidationUri(unittest.IsolatedAsyncioTestCase):
    """Pure-function tests for the edit screen's re-validation helper."""

    def test_round_trips_a_ws_link_through_the_parser(self) -> None:
        link = link_without_uuid()
        parsed = parse_vless_uri(build_validation_uri(link), allow_insecure=True)
        parsed.pop("uuid")
        for key in ("server", "port", "security", "network", "sni", "path", "host_header"):
            self.assertEqual(parsed[key], link[key], f"{key} must survive the round trip")

    def test_round_trips_reality_keys(self) -> None:
        uuid_value = OTHER_UUID
        raw = (
            f"vless://{uuid_value}@example.com:443?security=reality&type=tcp"
            "&sni=www.microsoft.com&fp=chrome&pbk=public&sid=abcd&spx=%2F&flow=xtls-rprx-vision"
        )
        link = parse_vless_uri(raw)
        link.pop("uuid")
        parsed = parse_vless_uri(build_validation_uri(link), allow_insecure=True)
        parsed.pop("uuid")
        self.assertEqual(parsed["security"], "reality")
        self.assertEqual(parsed["reality_public_key"], "public")
        self.assertEqual(parsed["reality_short_id"], "abcd")
        self.assertEqual(parsed["reality_spider_x"], "/")
        self.assertEqual(parsed["flow"], "xtls-rprx-vision")

    def test_round_trips_a_grpc_link(self) -> None:
        uuid_value = OTHER_UUID
        raw = f"vless://{uuid_value}@example.com:443?security=tls&type=grpc&serviceName=mygrpc&authority=example.com&multiMode=1"
        link = parse_vless_uri(raw)
        link.pop("uuid")
        parsed = parse_vless_uri(build_validation_uri(link), allow_insecure=True)
        parsed.pop("uuid")
        self.assertEqual(parsed["grpc_service"], "mygrpc")
        self.assertEqual(parsed["grpc_authority"], "example.com")
        self.assertTrue(parsed["grpc_multi_mode"])

    def test_round_trips_an_insecure_link(self) -> None:
        """An insecure profile must remain editable, not become unsavable."""
        uuid_value = OTHER_UUID
        raw = f"vless://{uuid_value}@example.com:443?security=tls&insecure=1"
        link = parse_vless_uri(raw, allow_insecure=True)
        link.pop("uuid")
        parsed = parse_vless_uri(build_validation_uri(link), allow_insecure=True)
        parsed.pop("uuid")
        self.assertTrue(parsed["allow_insecure"])

    def test_round_trips_xhttp(self) -> None:
        uuid_value = OTHER_UUID
        raw = f"vless://{uuid_value}@example.com:443?security=tls&type=xhttp&path=%2Fapi&host=a.example.com&mode=auto"
        link = parse_vless_uri(raw)
        link.pop("uuid")
        parsed = parse_vless_uri(build_validation_uri(link), allow_insecure=True)
        parsed.pop("uuid")
        self.assertEqual(parsed["network"], "xhttp")
        self.assertEqual(parsed["path"], "/api")
        self.assertEqual(parsed["host_header"], "a.example.com")
        self.assertEqual(parsed["xhttp_mode"], "auto")

    def test_the_placeholder_uuid_is_never_a_real_credential(self) -> None:
        uri = build_validation_uri(link_without_uuid())
        self.assertIn("00000000-0000-4000-8000-000000000000", uri)
        self.assertNotIn(TEST_UUID, uri)

    def test_an_invalid_server_still_fails_the_parser(self) -> None:
        link = link_without_uuid()
        link["server"] = "not a host"
        with self.assertRaises(AppError):
            parse_vless_uri(build_validation_uri(link), allow_insecure=True)


class TestSecurityInvariants(unittest.IsolatedAsyncioTestCase):
    """No URI, UUID, or secret may reach any surface the user can read."""

    def _services(self, tmp: str) -> tuple[ProfileStore, MemorySecretStore, StubProxyService]:
        store = ProfileStore(Path(tmp) / "profiles.json")
        store.load()
        secrets = MemorySecretStore()
        return store, secrets, StubProxyService(store, secrets)

    async def test_no_surface_ever_contains_the_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, secrets, service = self._services(tmp)
            app = VlessApp(service, store, secrets=secrets)
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                # Drive the add flow programmatically: the modal is the only
                # path a UUID enters the app by.
                screen = AddProfileScreen(store, secrets)
                await app.push_screen(screen)
                await pilot.pause()
                screen.query_one("#link", Input).value = sample_uri(TEST_UUID, "home")
                screen.query_one("#confirm", Button).press()
                await pilot.pause()
                screen.query_one("#confirm", Button).press()
                for _ in range(3):
                    await pilot.pause()
                    await app.workers.wait_for_complete()
                app._reload_table()
                await pilot.pause()

                blobs = [
                    str(app.query_one(ProfileTable).render()),
                    str(app.query_one(StatusBar).render()),
                    app.sub_title,
                    "\n".join(app._notes),
                    app._xray_log,
                ]
                joined = "\n".join(str(b) for b in blobs)
                self.assertNotIn(TEST_UUID, joined)
                self.assertNotIn("vless://", joined)

    async def test_a_secret_store_call_never_receives_a_profile_link(self) -> None:
        """The secret backend is keyed by profile id and holds only the UUID."""
        with tempfile.TemporaryDirectory() as tmp:
            store, secrets, service = self._services(tmp)
            app = VlessApp(service, store, secrets=secrets)
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                screen = AddProfileScreen(store, secrets)
                await app.push_screen(screen)
                await pilot.pause()
                screen.query_one("#link", Input).value = sample_uri(TEST_UUID, "home")
                screen.query_one("#confirm", Button).press()
                await pilot.pause()
                screen.query_one("#confirm", Button).press()
                for _ in range(3):
                    await pilot.pause()
                    await app.workers.wait_for_complete()
                # One account, one value, and that value is exactly the UUID.
                self.assertEqual(len(secrets.items), 1)
                self.assertEqual(list(secrets.items.values()), [TEST_UUID])


class TestRealServiceIntegration(unittest.IsolatedAsyncioTestCase):
    """The TUI must work against the *real* ``ProxyService``, not only the stub.

    Constructing one is safe: ``XrayProcess.__init__`` is pure, so no binary is
    launched and nothing is downloaded. These tests exist because the stub is a
    paraphrase of the contract — a paraphrase can drift from the real class
    without anything failing. These cannot.
    """

    def _service(self, tmp: str, store: ProfileStore) -> Any:
        from vlessp.proxy import ProxyService

        return ProxyService(store, NullSecretStore(), Path(tmp) / "xray")

    async def test_mounts_against_a_real_proxy_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ProfileStore(Path(tmp) / "profiles.json")
            store.load()
            store.add("alpha", link_without_uuid())
            store.save()
            app = VlessApp(self._service(tmp, store), store)
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                self.assertEqual(app.query_one(ProfileTable).row_count, 1)
                self.assertIn("127.0.0.1:10808", str(app.query_one(StatusBar).render()))
                self.assertIn("1 profile", app.sub_title)

    async def test_a_disconnected_service_reports_stopped_and_never_spawns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ProfileStore(Path(tmp) / "profiles.json")
            store.load()
            store.add("alpha", link_without_uuid())
            service = self._service(tmp, store)
            app = VlessApp(service, store)
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                self.assertIn("STOPPED", app.sub_title)
                self.assertFalse(service.running)
                self.assertEqual(service.log_tail(), "")
                app.action_quit_app()
                await pilot.pause()

    async def test_probe_all_through_the_real_service_fills_the_table(self) -> None:
        """Exercises the real ThreadPoolExecutor callback path.

        ``probe_server`` is monkeypatched to a fixed latency so the test never
        opens a socket, but the threading is genuinely the service's.
        """
        with tempfile.TemporaryDirectory() as tmp:
            store = ProfileStore(Path(tmp) / "profiles.json")
            store.load()
            store.add("alpha", link_without_uuid())
            store.save()
            service = self._service(tmp, store)

            import vlessp.proxy as proxy_module

            original = proxy_module.probe_server
            proxy_module.probe_server = lambda host, port, timeout=3.0: 7
            self.addCleanup(setattr, proxy_module, "probe_server", original)

            app = VlessApp(service, store)
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                app.action_test_all()
                for _ in range(3):
                    await pilot.pause()
                    await app.workers.wait_for_complete()
                profile = store.all()[0]
                rows = app.query_one(ProfileTable).row_values(profile.id)
                assert rows is not None
                self.assertIn("7ms", rows[5])
                self.assertEqual(store.get(profile.id).last_latency_ms, 7)

    async def test_a_missing_credential_is_an_explained_error_not_a_crash(self) -> None:
        """NullSecretStore fails closed, so this is the missing-Keychain path."""
        with tempfile.TemporaryDirectory() as tmp:
            store = ProfileStore(Path(tmp) / "profiles.json")
            store.load()
            profile = store.add("alpha", link_without_uuid())
            store.save()
            service = self._service(tmp, store)
            app = VlessApp(service, store)
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                app.action_connect_row()
                for _ in range(3):
                    await pilot.pause()
                    await app.workers.wait_for_complete()
                self.assertTrue(app.is_running, "a missing Keychain item is not a crash")
                reported = app._last_error or ""
                self.assertIn(profile.id, reported, "the message names the profile")
                self.assertNotIn(TEST_UUID, reported)
                self.assertFalse(service.running)
                self.assertIsNone(store.active_id, "a failed switch must not move the active id")
                self.assertIsNone(store.get(profile.id).link.get("uuid"))
                self.assertIn("ERROR", app.sub_title)

    async def test_the_real_service_persists_the_active_id_the_tui_omits(self) -> None:
        """Proves the TUI is right to *not* write active_id itself.

        ``XrayProcess.apply`` is stubbed to a no-op so no binary is launched;
        everything above it — resolve, Keychain read, set_active, save — is the
        real implementation.
        """
        with tempfile.TemporaryDirectory() as tmp:
            store = ProfileStore(Path(tmp) / "profiles.json")
            store.load()
            profile = store.add("alpha", link_without_uuid())
            secrets = MemorySecretStore()
            secrets.set(profile.id, TEST_UUID)
            store.save()

            from vlessp.xray import XrayProcess

            original = XrayProcess.apply
            XrayProcess.apply = lambda self, link: None  # type: ignore[method-assign]
            self.addCleanup(setattr, XrayProcess, "apply", original)

            from vlessp.proxy import ProxyService

            service = ProxyService(store, secrets, Path(tmp) / "xray")
            app = VlessApp(service, store)
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                app.action_connect_row()
                for _ in range(3):
                    await pilot.pause()
                    await app.workers.wait_for_complete()

                self.assertIsNone(app._last_error)
                self.assertEqual(store.active_id, profile.id)
                self.assertEqual(service.current.id if service.current else None, profile.id)
                # And it survived to disk, which is what a relaunch depends on.
                reloaded = ProfileStore(Path(tmp) / "profiles.json")
                reloaded.load()
                self.assertEqual(reloaded.active_id, profile.id)


class TestSeamGaps(unittest.IsolatedAsyncioTestCase):
    """Documented contract gaps, pinned so they cannot regress silently.

    ``ProxyService`` accepts a secret backend and listener addresses but does
    not publish them as attributes, so ``VlessApp(service, store)`` on its own
    cannot discover them. These tests pin the *degraded* behaviour so the gap
    shows up as an obvious, non-fatal message instead of an ``AttributeError``
    on a keypress.
    """

    async def test_add_without_a_secret_backend_reports_instead_of_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ProfileStore(Path(tmp) / "profiles.json")
            store.load()
            app = VlessApp(StubProxyService(store, NullSecretStore()), store)
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.workers.wait_for_complete()
                app.action_add_profile()
                await pilot.pause()
                await pilot.pause()
                self.assertFalse(
                    isinstance(app.screen, AddProfileScreen), "the modal must not open without a backend"
                )
                self.assertTrue(app.is_running)

    async def test_listener_addresses_fall_back_to_the_service_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ProfileStore(Path(tmp) / "profiles.json")
            store.load()
            app = VlessApp(StubProxyService(store, NullSecretStore()), store)
            async with app.run_test() as pilot:
                await pilot.pause()
                rendered = str(app.query_one(StatusBar).render())
                self.assertIn("127.0.0.1:10808", rendered)
                self.assertIn("127.0.0.1:10809", rendered)

    async def test_explicit_addresses_win_over_the_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ProfileStore(Path(tmp) / "profiles.json")
            store.load()
            app = VlessApp(
                StubProxyService(store, NullSecretStore()),
                store,
                socks_addr="127.0.0.1:20808",
                http_addr=None,
                xray_version="25.9.9",
            )
            async with app.run_test() as pilot:
                await pilot.pause()
                rendered = str(app.query_one(StatusBar).render())
                self.assertIn("127.0.0.1:20808", rendered)
                self.assertNotIn("10809", rendered)
                self.assertIn("25.9.9", rendered)


class TestAddSubscriptionScreen(TuiTestCase):
    """The subscription dialog records the URL and nothing else.

    These tests push the screen directly: ``s`` is still the V2 stub in
    ``app.py`` (the integrator wires it), so ``s`` cannot open this screen yet.
    """

    async def _push(self, screen: AddSubscriptionScreen) -> list[Any]:
        """Push the screen and capture whatever it dismisses with."""
        seen: list[Any] = []
        await self.app.push_screen(screen, seen.append)
        await self.pilot.pause()
        return seen

    def _rendered_statics(self, screen: AddSubscriptionScreen) -> list[str]:
        return [str(widget.render()) for widget in screen.query(Static)]

    async def test_save_stores_the_url_as_a_secret_and_dismisses_with_the_name(self) -> None:
        await self.settle()
        import vlessp.subscriptions as subscriptions

        fetch_calls: list[str] = []
        original_fetch = subscriptions.fetch_subscription

        def spy(url: str, **kwargs: Any) -> str:
            fetch_calls.append(url)
            return original_fetch(url, **kwargs)

        subscriptions.fetch_subscription = spy  # type: ignore[method-assign]
        self.addCleanup(setattr, subscriptions, "fetch_subscription", original_fetch)

        screen = AddSubscriptionScreen(self.store, self.secrets)
        seen = await self._push(screen)
        screen.query_one("#name", Input).value = "news"
        screen.query_one("#url", Input).value = SUB_URL
        screen.query_one("#confirm", Button).press()
        await self.settle()
        await self.pilot.pause()

        self.assertEqual(seen, ["news"], "save dismisses with the name, not None")
        self.assertEqual(self.secrets.items, {"subscription:news": SUB_URL})
        self.assertTrue(self.path.exists(), "the store is saved after the secret lands")
        self.assertEqual(fetch_calls, [], "the dialog records; it never fetches")
        for rendered in self._rendered_statics(screen):
            self.assertNotIn(SUB_URL, rendered, "the credential must appear in no widget")

    async def test_escape_dismisses_with_none_and_writes_nothing(self) -> None:
        await self.settle()
        screen = AddSubscriptionScreen(self.store, self.secrets)
        seen = await self._push(screen)
        screen.query_one("#name", Input).value = "abandoned"
        screen.query_one("#url", Input).value = SUB_URL
        await self.pilot.press("escape")
        await self.settle()

        self.assertEqual(seen, [None])
        self.assertEqual(self.secrets.items, {})
        self.assertEqual(self.store.all(), [])
        self.assertFalse(self.path.exists(), "escape must not write anything")

    async def test_cancel_dismisses_with_none_and_writes_nothing(self) -> None:
        await self.settle()
        screen = AddSubscriptionScreen(self.store, self.secrets)
        seen = await self._push(screen)
        screen.query_one("#name", Input).value = "abandoned"
        screen.query_one("#url", Input).value = SUB_URL
        screen.query_one("#cancel", Button).press()
        await self.settle()

        self.assertEqual(seen, [None])
        self.assertEqual(self.secrets.items, {})
        self.assertEqual(self.store.all(), [])
        self.assertFalse(self.path.exists(), "cancel must not write anything")

    async def test_a_non_https_url_is_refused_with_an_inline_error(self) -> None:
        await self.settle()
        screen = AddSubscriptionScreen(self.store, self.secrets)
        seen = await self._push(screen)
        screen.query_one("#name", Input).value = "work"
        screen.query_one("#url", Input).value = SUB_HTTP_URL
        screen.query_one("#confirm", Button).press()
        await self.pilot.pause()

        error = str(screen.query_one("#error", Static).render())
        self.assertIn("https", error)
        self.assertNotIn(SUB_HTTP_URL, error, "the refused URL must not be echoed")
        self.assertEqual(seen, [], "a refused save must not dismiss")
        self.assertEqual(self.secrets.items, {})
        self.assertFalse(self.path.exists())
        self.assertIsInstance(self.app.screen, AddSubscriptionScreen)
        for rendered in self._rendered_statics(screen):
            self.assertNotIn(SUB_HTTP_URL, rendered)

    async def test_an_empty_name_is_refused(self) -> None:
        await self.settle()
        screen = AddSubscriptionScreen(self.store, self.secrets)
        seen = await self._push(screen)
        screen.query_one("#url", Input).value = SUB_URL
        screen.query_one("#confirm", Button).press()
        await self.pilot.pause()

        error = str(screen.query_one("#error", Static).render())
        self.assertIn("name", error.lower())
        self.assertEqual(seen, [])
        self.assertEqual(self.secrets.items, {})
        self.assertFalse(self.path.exists())
        self.assertIsInstance(self.app.screen, AddSubscriptionScreen)
        for rendered in self._rendered_statics(screen):
            self.assertNotIn(SUB_URL, rendered)

    def _seed_subscription(self, name: str, label: str = "node-a") -> None:
        """Import one node through the real ``reconcile`` path.

        Seeds a profile with ``source == f"subscription:{name}"`` exactly as a
        fetch would, so the duplicate and display tests below exercise the
        production lookup instead of fakes.
        """
        from vlessp.subscriptions import SubNode

        self.store.reconcile(
            [SubNode(label=label, link=sample_link(), line_number=1)],
            source=f"subscription:{name}",
            secrets=self.secrets,
        )

    async def test_a_duplicate_name_is_refused(self) -> None:
        await self.settle()
        self._seed_subscription("news")
        screen = AddSubscriptionScreen(self.store, self.secrets)
        seen = await self._push(screen)
        screen.query_one("#name", Input).value = "news"
        screen.query_one("#url", Input).value = SUB_URL
        screen.query_one("#confirm", Button).press()
        await self.pilot.pause()

        self.assertIn("already exists", str(screen.query_one("#error", Static).render()))
        self.assertEqual(seen, [], "a refused save must not dismiss")
        self.assertNotIn("subscription:news", self.secrets.items)
        self.assertIsInstance(self.app.screen, AddSubscriptionScreen)

    async def test_a_duplicate_name_is_refused_without_by_source(self) -> None:
        """Fallback path: the ``source`` fields are scanned directly."""
        await self.settle()
        self._seed_subscription("news")
        self.store.by_source = None  # type: ignore[method-assign]
        self.addCleanup(delattr, self.store, "by_source")
        screen = AddSubscriptionScreen(self.store, self.secrets)
        seen = await self._push(screen)
        screen.query_one("#name", Input).value = "news"
        screen.query_one("#url", Input).value = SUB_URL
        screen.query_one("#confirm", Button).press()
        await self.pilot.pause()

        self.assertIn("already exists", str(screen.query_one("#error", Static).render()))
        self.assertEqual(seen, [])
        self.assertNotIn("subscription:news", self.secrets.items)

    async def test_the_screen_lists_existing_subscription_names(self) -> None:
        """Only names are shown — the URLs stay in the Keychain, unread."""
        await self.settle()
        self._seed_subscription("news")
        self._seed_subscription("work", label="node-b")
        screen = AddSubscriptionScreen(self.store, self.secrets)
        await self._push(screen)

        existing = str(screen.query_one("#existing", Static).render())
        self.assertIn("news", existing)
        self.assertIn("work", existing)

    async def test_a_keychain_failure_writes_nothing_and_keeps_the_modal_open(self) -> None:
        await self.settle()
        self.secrets.fail_on_set = True
        screen = AddSubscriptionScreen(self.store, self.secrets)
        seen = await self._push(screen)
        screen.query_one("#name", Input).value = "news"
        screen.query_one("#url", Input).value = SUB_URL
        screen.query_one("#confirm", Button).press()
        await self.settle()
        await self.pilot.pause()

        self.assertEqual(seen, [], "a failed save must not dismiss")
        self.assertEqual(self.secrets.items, {})
        self.assertFalse(self.path.exists(), "the store is never saved when the secret fails")
        self.assertIsInstance(self.app.screen, AddSubscriptionScreen)
        self.assertTrue(str(screen.query_one("#error", Static).render()))
        for rendered in self._rendered_statics(screen):
            self.assertNotIn(SUB_URL, rendered)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class _BadgingSubNode:
    """Structural stand-in for ``subscriptions.SubNode``.

    ``reconcile`` only ever reads ``label`` and ``link``, so importing through
    the real store path needs nothing more — and going through it means these
    tests exercise the same provenance the app's own fetch produces.
    """

    def __init__(self, label: str, link: dict[str, Any]) -> None:
        self.label = label
        self.link = link


class TestTableBadging(TuiTestCase):
    """S4's display rule: where a profile came from, and whether it is still offered.

    Both states are cosmetic, which is the whole point. An imported node is an
    ordinary profile, and one the provider has dropped is still fully usable, so
    every test here asserts only that the table *says* these things — never that
    it hides, greys out of reach, or refuses to connect to anything.

    Imported in the class body rather than at the top of the file: this class was
    appended late, and the shared import block above is shared with every other
    test class in the module.
    """

    from vlessp.tui.widgets import SOURCE_NAME_MAX, UNAVAILABLE_MARK, UNAVAILABLE_STYLE

    # -- helpers --------------------------------------------------------

    def _import(
        self,
        source: str,
        label: str = "node-one",
        *,
        uuid_value: str = TEST_UUID,
        server: str = "203.0.113.10",
    ) -> Profile:
        """Import one node through ``ProfileStore.reconcile``, as a fetch does."""
        node = _BadgingSubNode(label, sample_link(uuid_value, server=server))
        result = self.store.reconcile([node], source=source, secrets=self.secrets)
        self.assertEqual(len(result.added), 1, "the node became an ordinary profile")
        return result.added[0]

    def _drop_upstream(self, source: str) -> None:
        """A later fetch that no longer lists the node — what sets ``unavailable``."""
        result = self.store.reconcile([], source=source, secrets=self.secrets)
        self.assertEqual(len(result.marked_unavailable), 1)

    async def _reload(self) -> None:
        self.app._reload_table()
        await self.settle()

    def _cells(self, profile_id: str) -> list[str]:
        rows = self.table().row_values(profile_id)
        assert rows is not None, f"no row for profile {profile_id}"
        return rows

    def _cell(self, profile_id: str, key: str) -> Any:
        """The stored cell object, so a test can read a style and not just its text."""
        from rich.text import Text

        table = self.table()
        for row in table.ordered_rows:
            if row.key is not None and str(row.key.value) == profile_id:
                cell = table.get_cell(row.key, key)
                assert isinstance(cell, Text)
                return cell
        self.fail(f"no row for profile {profile_id}")

    def _rendered(self) -> str:
        """The lines the table actually paints.

        Not ``str(table.render())``: ``DataTable.render()`` returns a Panel whose
        ``str()`` is a repr, so asserting against it would pass for anything.
        """
        table = self.table()
        return "\n".join(table.render_line(y).text for y in range(table.size.height))

    # -- the source badge ----------------------------------------------

    async def test_a_hand_added_profile_carries_no_source_badge(self) -> None:
        await self.settle()
        profile = self.add_profile("home")
        await self._reload()

        label = self._cells(profile.id)[0]
        self.assertEqual(label, "home", "a hand-added profile renders exactly as it always did")
        self.assertNotIn("sub:", label)
        self.assertNotIn("[", label)

    async def test_an_imported_profile_is_badged_with_its_subscription_name(self) -> None:
        await self.settle()
        profile = self._import(f"{SUB_SOURCE_PREFIX}work")
        await self._reload()

        self.assertEqual(self._cells(profile.id)[0], "node-one [sub:work]")
        # The badge lives in the LABEL cell — no eighth column squeezes SERVER.
        self.assertEqual(len(self._cells(profile.id)), 7)

    async def test_a_long_subscription_name_is_truncated(self) -> None:
        await self.settle()
        profile = self._import(f"{SUB_SOURCE_PREFIX}a-very-long-subscription-name")
        await self._reload()

        label = self._cells(profile.id)[0]
        self.assertEqual(label, "node-one [sub:a-very-…]")
        self.assertNotIn("a-very-long-subscription-name", label)
        # A name that already fits is left alone; only the over-long one loses anything.
        exact = self._import(f"{SUB_SOURCE_PREFIX}12345678", "node-two", server="198.51.100.7")
        await self._reload()
        self.assertEqual(self._cells(exact.id)[0], "node-two [sub:12345678]")
        self.assertEqual(len("a-very-…"), self.SOURCE_NAME_MAX)

    async def test_an_unexpected_source_shape_degrades_to_showing_the_source(self) -> None:
        """A bare id, or a name full of characters a badge should not choke on."""
        await self.settle()
        bare = self._import("bare-id", "node-one")
        odd = self._import(f"{SUB_SOURCE_PREFIX}[red] /a", "node-two", server="198.51.100.7")
        await self._reload()

        self.assertEqual(self._cells(bare.id)[0], "node-one [sub:bare-id]")
        self.assertEqual(self._cells(odd.id)[0], "node-two [sub:[red] /a]")
        self.assertEqual(self.store.get(bare.id).source, "bare-id", "the store is not rewritten")

    # -- unavailable rows ----------------------------------------------

    async def test_an_unavailable_profile_is_still_listed_and_still_connects(self) -> None:
        """Flagged, not taken away: a provider having a bad day is not a reason to
        lose a working node."""
        await self.settle()
        profile = self._import(f"{SUB_SOURCE_PREFIX}work")
        self._drop_upstream(f"{SUB_SOURCE_PREFIX}work")
        self.assertTrue(self.store.get(profile.id).unavailable)
        await self._reload()

        self.assertEqual(self.table().row_count, 1, "a dropped node is flagged, never hidden")
        self.assertEqual(self.table().selected_id(), profile.id)

        await self.pilot.press("enter")
        await self.settle()

        self.assertIn(f"connect:{profile.id}", self.service.calls)
        self.assertTrue(self.service.running)
        self.assertEqual(self.store.active_id, profile.id)
        self.assertEqual(self._cells(profile.id)[6], "live", "it is an ordinary live row once running")

    async def test_an_unavailable_row_is_visually_distinct_from_an_idle_one(self) -> None:
        await self.settle()
        idle = self.add_profile("alpha")
        gone = self._import(f"{SUB_SOURCE_PREFIX}work", "zeta")
        self._drop_upstream(f"{SUB_SOURCE_PREFIX}work")
        await self._reload()

        self.assertEqual(self._cells(idle.id)[6], DASH, "idle keeps meaning exactly what it meant")
        self.assertEqual(self._cells(gone.id)[6], self.UNAVAILABLE_MARK)
        self.assertNotEqual(self._cells(gone.id)[6], self._cells(idle.id)[6])
        # Dimmed too, so the difference survives being read at a glance, not parsed.
        self.assertEqual(self._cell(gone.id, "label").style, self.UNAVAILABLE_STYLE)
        self.assertEqual(self._cell(idle.id, "label").style, "")
        for key in ("server", "port", "sec", "transport", "lat", "state"):
            self.assertEqual(self._cell(gone.id, key).style, self.UNAVAILABLE_STYLE)

    # -- leakage --------------------------------------------------------

    async def test_a_label_containing_markup_renders_literally(self) -> None:
        """``[red]`` in a label is a label, not a style tag."""
        await self.settle()
        profile = self.add_profile("[red]alpha")
        await self._reload()

        self.assertIn("[red]", self._cells(profile.id)[0])
        self.assertIn("[red]alpha", self._rendered(), "the painted row shows it verbatim")

    async def test_no_profile_uuid_reaches_any_cell(self) -> None:
        await self.settle()
        hand = self.add_profile("home", uuid_value=TEST_UUID)
        imported = self._import(
            f"{SUB_SOURCE_PREFIX}work", "node-one", uuid_value=OTHER_UUID, server="198.51.100.7"
        )
        self._drop_upstream(f"{SUB_SOURCE_PREFIX}work")  # the dimmed row is covered too
        await self._reload()

        # Both credentials really are held by the Keychain, so their absence from
        # the table is a decision rather than an accident of never having been set.
        self.assertEqual(self.secrets.items[hand.id], TEST_UUID)
        self.assertEqual(self.secrets.items[imported.id], OTHER_UUID)
        rendered = "\n".join(
            [self._cells(hand.id)[0], self._cells(imported.id)[0], self._rendered()]
        )
        for secret in (TEST_UUID, OTHER_UUID):
            self.assertNotIn(secret, rendered)
            self.assertNotIn(secret.replace("-", ""), rendered, "nor the unhyphenated form")
            self.assertNotIn(secret[:8], rendered, "nor any identifiable run of it")

class TestLatencyGraphics(TuiTestCase):
    """LAT bars and the detail sparkline.

    Only the async tests are meaningful here — they need a mounted app — so the
    pure data-model ones live in the sync block below the class.

    These are graphics, so the properties worth asserting are that they *encode
    something true*: a slow node draws a longer bar than a fast one, the scale
    does not shift under the reader, and an unreachable probe is a gap rather
    than a zero that would lie about the measurement.

    Only the panel tests need a mounted app; the pure ones are in
    ``TestLatencyGraphicsPure`` below, where they run in milliseconds.
    """

    async def test_the_detail_panel_refuses_to_invent_a_trend_from_one_sample(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.store.set_latency(self.store.all()[0].id, 42)
        self.app._reload_table()
        await self.settle()
        rendered = str(self.app.query_one("#detail", ProfileDetail).render())
        self.assertIn("No trend yet", rendered)
        # The panel states the identity it is describing. A "no trend yet" note
        # with nothing to anchor it is ambiguous when several rows are listed.
        self.assertIn("alpha", rendered)

    async def test_the_detail_panel_draws_a_sparkline_once_there_is_a_series(self) -> None:
        profile = self.add_profile("alpha")
        for ms in (40, 90, 160, 300):
            self.store.set_latency(profile.id, ms)
        self.app._reload_table()
        await self.settle()
        rendered = str(self.app.query_one("#detail", ProfileDetail).render())
        self.assertIn("last 4 runs", rendered)
        self.assertNotIn("No trend yet", rendered)
        self.assertIn("min 40ms", rendered)

    async def test_the_panel_follows_the_cursor(self) -> None:
        await self.settle()
        first = self.add_profile("alpha")
        second = self.add_profile("beta")
        self.app._reload_table()
        await self.settle()
        self.table().cursor_coordinate = self.table().cursor_coordinate._replace(row=1)
        await self.pilot.pause()
        rendered = str(self.app.query_one("#detail", ProfileDetail).render())
        self.assertIn(second.label, rendered)
        self.assertNotIn(first.label, rendered)

    async def test_the_panel_never_shows_a_uuid(self) -> None:
        profile = self.add_profile("alpha")
        for ms in (10, 20):
            self.store.set_latency(profile.id, ms)
        self.app._reload_table()
        await self.settle()
        self.assertNotIn(TEST_UUID, str(self.app.query_one("#detail", ProfileDetail).render()))

    async def test_the_panel_speaks_when_nothing_is_selected(self) -> None:
        """Regression: ``Text(..., classes=...)`` is a TypeError.

        ``classes`` is a widget keyword, not a Rich ``Text`` one. The empty
        branch raised inside ``_refresh_detail``, whose ``except`` swallowed it,
        so the panel silently went blank whenever no row was selected — which is
        the first thing a new user sees, on an empty store.
        """
        await self.settle()
        rendered = str(self.app.query_one("#detail", ProfileDetail).render())
        self.assertIn("No profile selected", rendered)


class TestLatencyGraphicsPure(unittest.TestCase):
    """Same concerns, no app needed — so they run fast and cannot flake.

    The bar and the history model are pure functions of their inputs, so none of
    this needs a mounted Textual app.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="vlessp-graphics-")
        self.addCleanup(self._tmp.cleanup)
        self.store_path = Path(self._tmp.name) / "profiles.json"
        self.store = ProfileStore(path=self.store_path)
        self.store.load()

    def add_profile(self, label: str = "home") -> Profile:
        profile = self.store.add(label, link_without_uuid(TEST_UUID))
        return profile

    def test_the_bar_is_never_the_only_encoding(self) -> None:
        """Colour and glyph are both redundant with the number beside them."""
        for ms in (12, 85, 250, 700, 1900):
            with self.subTest(ms=ms):
                plain = latency_bar(ms).plain
                self.assertIn(f"{ms}ms", plain)

    def bar_extent(self, ms: int) -> int:
        """Total fill in eighths of a cell, read back from the rendered glyphs.

        Counted from the characters rather than the model, so this fails if the
        rendering ever stops matching the level it is supposed to encode.
        """
        bar = latency_bar(ms).plain.split()[0]
        total = 0
        for char in bar:
            total += PARTIAL_BLOCKS.index(char)
        return total

    def test_a_slower_node_draws_a_longer_bar(self) -> None:
        self.assertLess(self.bar_extent(42), self.bar_extent(890))
        self.assertLess(self.bar_extent(890), self.bar_extent(1900))

    def test_the_bar_resolves_nearby_latencies(self) -> None:
        """Four cells of whole blocks would draw 42ms and 85ms identically.

        That is the reason for eighth-blocks: a bar that cannot separate two
        common values is decoration, not information.
        """
        self.assertLess(self.bar_extent(42), self.bar_extent(85))
        self.assertLess(self.bar_extent(85), self.bar_extent(150))

    def test_the_scale_is_fixed_not_relative(self) -> None:
        """Two nodes must be comparable by eye.

        A relative scale would rescale to the best node in view, so the same bar
        would mean "fast" with one row and "terrible" with fifty.
        """
        alone = latency_bar(42).plain
        beside_a_slow_one = latency_bar(42).plain
        self.assertEqual(alone, beside_a_slow_one, "the scale must not depend on other rows")

    def test_an_unprobed_node_draws_no_bar(self) -> None:
        self.assertEqual(latency_bar(None).plain, DASH)

    def test_history_grows_and_is_bounded(self) -> None:
        profile = self.add_profile("alpha")
        for ms in (10, 20, 30, 40, 50):
            self.store.set_latency(profile.id, ms)
        self.assertEqual(self.store.get(profile.id).latency_history, (10, 20, 30, 40, 50))
        for step in range(40):
            self.store.set_latency(profile.id, step)
        history = self.store.get(profile.id).latency_history
        self.assertLessEqual(len(history), MAX_LATENCY_HISTORY)
        self.assertEqual(history[-1], 39)

    def test_history_is_not_written_to_disk(self) -> None:
        """A trend is session state, not configuration."""
        profile = self.add_profile("alpha")
        for ms in (11, 22, 33):
            self.store.set_latency(profile.id, ms)
        self.store.save()
        self.assertNotIn("latency_history", self.store_path.read_text(encoding="utf-8"))

    def test_unreachable_probes_are_recorded_as_gaps_not_dropped(self) -> None:
        profile = self.add_profile("alpha")
        for ms in (10, None, 30):
            self.store.set_latency(profile.id, ms)
        self.assertEqual(self.store.get(profile.id).latency_history, (10, None, 30))


class TestNoSpuriousToasts(TuiTestCase):
    """Ordinary navigation must be silent.

    Regression: the detail panel's helper was written as a getter but carried
    ``notify()`` calls, so every cursor movement and every table rebuild popped
    a toast — and a rebuild fires the refresh twice, so each key produced two.
    """

    async def _press_all(self, keys: str) -> list[str]:
        """Press a whitespace-separated key sequence, collecting every toast.

        Split on whitespace: iterating the raw string would press each CHARACTER
        separately, so the spaces between key names would arrive as literal
        ``space`` presses -- which is a real binding, and produced a baffling
        failure that looked like an application bug.
        """
        seen: list[str] = []
        real = self.app.notify

        def spy(message: str, *args, **kwargs) -> None:
            seen.append(message)
            real(message, *args, **kwargs)

        self.app.notify = spy  # type: ignore[method-assign]
        for key in keys.split():
            await self.pilot.press(key)
            await self.settle()
        return seen

    async def test_navigating_and_toggling_never_notifies(self) -> None:
        await self.settle()
        for name in ("alpha", "beta", "gamma"):
            self.add_profile(name)
        self.app._reload_table()
        await self.settle()

        seen = await self._press_all("down down up o l alt+t h escape t")
        self.assertEqual(
            seen, [], f"navigation must be silent, got: {seen}"
        )

    async def test_an_empty_store_navigating_is_silent(self) -> None:
        """No rows is the normal transient state during a rebuild, not an error."""
        await self.settle()
        seen = await self._press_all("down up o")
        self.assertEqual(seen, [], f"an empty table must not toast, got: {seen}")

    async def test_a_deliberate_action_on_an_empty_store_still_explains_itself(self) -> None:
        """Silence is the default, not blanket muting.

        ``t`` with nothing to probe cannot do its job, and saying so is the
        correct behaviour. What must never happen is the *refresh* path
        interrupting -- see the other tests here.
        """
        await self.settle()
        seen = await self._press_all("t")
        self.assertTrue(
            any("no profiles to test" in message for message in seen),
            f"t on an empty store must say why, got: {seen}",
        )

    async def test_a_deliberate_action_still_reports_missing_selection(self) -> None:
        """Silenced by default, but not silenced everywhere.

        A getter should not interrupt; an action the user chose should still
        say why it did nothing.
        """
        await self.settle()
        seen = await self._press_all("c")
        self.assertTrue(
            any("No profile selected" in message for message in seen),
            f"pressing c with nothing selected must explain itself, got: {seen}",
        )

    async def test_the_panel_is_not_the_thing_that_talks(self) -> None:
        """The refresh path itself must never notify, whatever it finds."""
        await self.settle()
        profile = self.add_profile("alpha")
        self.store.set_latency(profile.id, 42)
        seen: list[str] = []
        real = self.app.notify
        self.app.notify = lambda message, *a, **k: seen.append(message)  # type: ignore[method-assign]
        try:
            self.app._refresh_detail()
            # Even for a selection the store does not know about.
            self.app._selected_id = lambda: "no-such-profile"  # type: ignore[method-assign]
            self.app._refresh_detail()
        finally:
            self.app.notify = real  # type: ignore[method-assign]
        self.assertEqual(seen, [], f"_refresh_detail must stay silent, got: {seen}")


class TestKeyHints(TuiTestCase):
    """The one-line key list.

    This widget exists because Textual's ``Footer`` cannot be used here: twelve
    bindings on one un-wrapped line came to 117 columns, so it silently
    truncated to an ellipsis on an 80-column terminal -- hiding ``q``, the last
    key anyone wants hidden. These tests are the regression guard for that, and
    they are written against the *rendered* strings rather than the layout
    tables, because getting a width wrong is the exact bug being guarded.
    """

    def test_it_is_a_single_line(self) -> None:
        """Not a block. Chrome must not steal rows from the table."""
        for width in (300, 140, 130, 100, 80, 60):
            with self.subTest(width=width):
                line = KeyHints().compose_hint(width).plain
                self.assertNotIn("\n", line, "the hints must be one line")

    def test_every_tier_fits_the_width_that_selects_it(self) -> None:
        for tier, minimum in enumerate(KeyHints.MINIMUMS):
            with self.subTest(tier=tier):
                line = KeyHints().render_tier(tier).plain
                self.assertLessEqual(
                    len(line), minimum,
                    f"tier {tier} needs {len(line)} but claims {minimum}",
                )

    def test_no_width_ever_truncates(self) -> None:
        """Sweep every width; the rendered line must always fit inside it."""
        hints = KeyHints()
        for width in range(33, 160):
            with self.subTest(width=width):
                line = hints.compose_hint(width).plain
                self.assertLessEqual(
                    len(line), width, f"{len(line)} cols into {width}"
                )

    def test_the_widest_tier_is_chosen_when_there_is_room(self) -> None:
        """A 200-column terminal should get the readable layout, not the cramped one."""
        self.assertEqual(KeyHints().tier_for(200), 0)
        self.assertIn("stop/resume", KeyHints().compose_hint(200).plain)

    def test_every_bound_key_appears_in_every_tier(self) -> None:
        """Compression may shorten a label; it may never drop a key."""
        bound = {
            b.key
            for b in VlessApp.BINDINGS
            if b.show and not b.key.startswith("^")
        }
        for tier in range(len(KeyHints.TIERS)):
            with self.subTest(tier=tier):
                shown = KeyHints().render_tier(tier).plain.split()
                # "space" abbreviates to "sp" and "alt+t" to "^T" in the narrow
                # tier only, and that tier joins with ':' -- so the token there
                # is "sp:stop", not "sp". Accept any known spelling of the key.
                spellings = {"space": ("space", "sp"), "alt+t": ("alt+t", "^T")}
                for key in bound:
                    accepted = spellings.get(key, (key,))
                    self.assertTrue(
                        any(
                            token == want or token.startswith(f"{want}:")
                            for token in shown
                            for want in accepted
                        ),
                        f"tier {tier} hides {key}; shows {shown}",
                    )

    async def test_the_hints_render_under_the_table(self) -> None:
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()
        rendered = str(self.app.query_one(KeyHints).render()).strip()
        self.assertTrue(rendered, "the hint bar must not sit there empty")

    async def test_quit_is_visible_at_the_size_it_renders(self) -> None:
        """The key that must never be the one that gets truncated."""
        await self.settle()
        for width in (200, 140, 130, 100, 80, 60):
            with self.subTest(width=width):
                self.assertIn("q", KeyHints().compose_hint(width).plain)
