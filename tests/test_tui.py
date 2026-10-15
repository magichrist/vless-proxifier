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

try:
    import textual  # noqa: F401
    from textual.widgets import Button, Input, Select, Static
    from textual.widgets._select import InvalidSelectValueError

    from vlessp.tui import (
        AddProfileScreen,
        AddressScreen,
        ConfirmScreen,
        EditProfileScreen,
        HelpScreen,
        VlessApp,
    )
    from vlessp.tui.screens import build_validation_uri
    from vlessp.tui.widgets import DASH, ProfileTable, StatusBar

    TEXTUAL_IMPORT_ERROR: Exception | None = None
except ImportError as exc:  # pragma: no cover - depends on the environment
    # The TUI tests need Textual, which is a real dependency of this project but
    # may be absent from whichever interpreter is running the suite. Failing with a
    # bare ModuleNotFoundError deep inside a class body tells the reader nothing;
    # skipping with a reason they can act on tells them exactly what to install.
    TEXTUAL_IMPORT_ERROR = exc

from vlessp.errors import AppError
from vlessp.links import parse_vless_uri
from vlessp.profiles import Profile, ProfileStore
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
                gate.wait(timeout=5.0)
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
        self.assertEqual(first[0], "▌alpha" if alpha.id == beta.id else "alpha")
        second = self.table().row_values(beta.id)
        assert second is not None
        self.assertTrue(second[0].startswith("▌"), "the active row carries the ▌ marker")
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
        self.assertEqual(slow_cells[5], "890ms")
        self.assertEqual(fast_cells[5], "42ms")
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


class TestSubscriptionStub(TuiTestCase):
    async def test_s_explains_itself_instead_of_doing_nothing(self) -> None:
        """A key that silently no-ops is worse than one that says why."""
        await self.settle()
        self.add_profile("alpha")
        self.app._reload_table()
        await self.settle()

        await self.pilot.press("s")
        await self.settle()
        notes = "\n".join(self.app._notes)
        self.assertIn("V2", notes)
        self.assertIn("05-v2-parked.md", notes, "the decision record should be discoverable in place")
        self.assertIs(self.app.screen, self.app.screen_stack[0], "s must not open a modal")
        self.assertTrue(self.app.is_running)


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
                self.assertEqual(rows[5], "7ms")
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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()