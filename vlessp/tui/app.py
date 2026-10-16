"""The main Textual application.

Threading is the whole design of this file
------------------------------------------
Textual runs one event loop. A ``subprocess``, a ``socket``, a Keychain item,
and a profile file are all *slow* relative to a frame. Every one of them is
therefore called from a ``@work(thread=True)`` worker and every result is
handed back to the loop with ``call_from_thread``. No handler body blocks.

That is most fragile in one place: :meth:`ProxyService.probe_all` invokes its
``on_result`` callback from a *worker thread of its own*. Touching a widget from
there would mutate the widget tree outside the event loop — the kind of bug that
shows up as a mysteriously empty table rather than a traceback. Every callback
in this module goes through :meth:`_on_probe_result`, which does nothing but
``call_from_thread``.

The security invariant, enforced here
-------------------------------------
No URI, no UUID, and no secret is ever interpolated into a ``notify()``, a log
line, the status bar, the header, or a table cell. Two consequences follow:

* ``AppError`` messages *are* rendered, because the project contract guarantees
  they are written from the shape of a problem and never from the link.
* Arbitrary exceptions are **not** rendered. Their text may contain anything a
  subprocess or a library chose to put there, so only the exception *type* is
  ever shown.

Why ``push_screen(..., callback=...)`` and not ``push_screen_wait``
--------------------------------------------------------------------
Textual forbids ``wait_for_dismiss=True`` outside a worker, and a key handler
is not a worker. Making a modal-open action into a worker just to await it would
pretend that opening a form is a slow operation. The callback form pushes the
screen synchronously, does no I/O, and gets the dismiss result delivered to the
event loop when the modal closes.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Header, Static

from vlessp import APP_NAME
from vlessp.errors import AppError
from vlessp.profiles import SUB_SECRET_PREFIX, SUB_SOURCE_PREFIX, ProfileStore
from vlessp.subscriptions import fetch_subscription, parse
from vlessp.tui.screens import (
    AddProfileScreen,
    AddressScreen,
    AddSubscriptionScreen,
    ConfirmScreen,
    EditProfileScreen,
    HelpScreen,
)
from vlessp.tui.theme import apply_theme, next_theme, register_all
from vlessp.tui.widgets import KeyHints, ProfileDetail, ProfileTable, StatusBar

if TYPE_CHECKING:
    from vlessp.profiles import Profile
    from vlessp.proxy import ProxyService
    from vlessp.secrets import SecretStore

# How many probe results are held before the table resorts. Latency sweeps paint
# progressively (the design calls for it) without making the table jump on every
# single completion.
RESORT_EVERY = 1

# Probe timeout, passed through to ``ProxyService.probe_all``.
PROBE_TIMEOUT = 3.0

# Fallback listener addresses, matching ``ProxyService``'s own constructor
# defaults. Used only when neither the app nor the service supplies a value —
# see the note on ``VlessApp.__init__`` about the seam not exposing them.
DEFAULT_SOCKS_ADDR = "127.0.0.1:10808"
DEFAULT_HTTP_ADDR = "127.0.0.1:10809"

# Log pane refresh cadence. Slow enough to be free, fast enough that a failed
# switch is diagnosed without leaving the app.
LOG_REFRESH_SECONDS = 1.0

# Retained length of our own log notes. Xray's own tail is windowed by the
# service, not here.
MAX_LOG_NOTES = 200


class _Unset:
    """Marker for "the caller did not pass this keyword".

    Needed only for ``http_addr``, where ``None`` and "not supplied" mean
    different things: an explicit ``None`` is "no HTTP listener", while an
    absent value should fall back to ``ProxyService``'s own default. Without a
    sentinel the two collapse and a caller cannot turn the HTTP listener off.
    """

    __slots__ = ()


_UNSET = _Unset()


def _safe_message(exc: BaseException) -> str:
    """Describe an exception without ever echoing its text.

    ``AppError`` messages are link-free by project contract, so they are safe
    and actionable enough to show. Everything else gets only its type name: a
    ``subprocess``, a socket, or a library traceback may embed whatever it
    liked — including a link — and this module will not put that in a toast.
    """
    if isinstance(exc, AppError):
        return str(exc)
    return f"unexpected failure ({type(exc).__name__})."


class VlessApp(App[None]):
    """Profile list, connection state, and the three modal screens."""

    TITLE = APP_NAME

    CSS = """
    Screen {
        layers: base;
    }
    #log-pane {
        height: 12;
        border: round $accent;
        padding: 0 1;
        overflow-y: auto;
        color: $text-muted;
    }
    """

    BINDINGS = [
        # Connection. `c` acts on the highlighted row; `space` is the state
        # toggle for the service as a whole. They are separate keys because
        # "switch to this one" and "shut this off" are different intentions, and
        # merging them makes a stop-whenever-you-press-space surprise.
        Binding("c", "connect_row", "Connect", priority=True),
        Binding("space", "toggle_connection", "Stop/Resume"),
        Binding("t", "test_all", "Test"),
        # Profiles. `l` is the single memorable verb for adding a link; `a` is
        # kept as a hidden alias because it was the V1 key and muscle memory
        # outlives a rebrand.
        Binding("l", "add_profile", "Add link"),
        Binding("s", "add_subscription", "Add sub"),
        Binding("e", "edit_profile", "Edit"),
        Binding("i", "edit_address", "IP/Port"),
        Binding("d", "delete_profile", "Delete"),
        # View and app.
        Binding("o", "toggle_log", "Output"),
        Binding("h", "show_help", "Help"),
        Binding("alt+t", "cycle_theme", "Theme"),
        Binding("q", "quit_app", "Quit"),
        # Hidden aliases: advertised in the help overlay rather than the footer.
        Binding("enter", "connect_row", "", show=False, priority=True),
        Binding("a", "add_profile", "", show=False),
    ]

    def __init__(
        self,
        service: ProxyService,
        store: ProfileStore,
        *,
        secrets: SecretStore | None = None,
        allow_insecure: bool = False,
        socks_addr: str | None = None,
        http_addr: str | None | _Unset = _UNSET,
        xray_version: str | None = None,
    ) -> None:
        """Build the app over an existing service and store.

        Every keyword is optional so ``VlessApp(service, store)`` — the
        documented signature — keeps working unchanged.

        ``secrets`` matters most. ``ProxyService`` takes a secret backend in its
        constructor but does not re-expose it, so there is nothing for this app
        to discover on the service. A caller that does not pass it gets an app
        that reads and connects perfectly well but reports add/edit/delete as
        unavailable, rather than raising ``AttributeError`` on a keypress.
        **The CLI must pass ``secrets=self._secrets`` when it builds the app.**

        The listener addresses have the same shape of gap: they are constructor
        arguments of ``ProxyService`` that it does not publish as attributes.
        They are read from the service when present and otherwise fall back to
        ``ProxyService``'s documented defaults, so a caller that overrides the
        ports should pass ``socks_addr``/``http_addr`` here instead of assuming
        the status bar will follow. Pass ``http_addr=None`` for no HTTP
        segment.

        ``allow_insecure`` mirrors the CLI's ``--allow-insecure`` and is
        deliberately *not* defaulted to True — a link that disables certificate
        verification must be a deliberate act.
        """
        super().__init__()
        self._service = service
        self._store = store
        self._secrets: SecretStore | None = (
            secrets if secrets is not None else getattr(service, "secrets", None)
        )
        self._allow_insecure = allow_insecure
        self._socks_addr = socks_addr or getattr(service, "socks_addr", None) or DEFAULT_SOCKS_ADDR
        if isinstance(http_addr, _Unset):
            self._http_addr: str | None = getattr(service, "http_addr", None) or DEFAULT_HTTP_ADDR
        else:
            self._http_addr = http_addr or None
        self._xray_version = xray_version or getattr(service, "xray_version", None)
        self._switching = False
        self._last_error: str | None = None
        self._notes: list[str] = []
        self._xray_log: str = ""
        self._pending_results = 0
        self._shutting_down = False

    # -- accessors used by tests and by the screens ---------------------

    @property
    def service(self) -> ProxyService:
        """The orchestration seam this app drives."""
        return self._service

    @property
    def store(self) -> ProfileStore:
        """The profile store this app reads and writes."""
        return self._store

    @property
    def log_visible(self) -> bool:
        """Whether the collapsible log pane is currently shown."""
        try:
            return bool(self.query_one("#log-pane", Static).display)
        except Exception:
            return False

    # -- composition -----------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        yield ProfileTable(id="profiles")
        # The key hints go directly under the table, where the eye already is,
        # rather than in the footer slot at the very bottom. Textual's Footer is
        # gone on purpose: twelve bindings do not fit one un-wrapped line, and it
        # was silently truncating them — hiding `q` along the way.
        yield KeyHints()
        # The detail panel sits below the table: the log is a diagnostic surface
        # that is hidden by default, so this is the only always-visible readout.
        yield ProfileDetail(id="detail")
        yield Static("", id="log-pane")
        yield StatusBar(id="status")

    def on_mount(self) -> None:
        # Themes register here rather than lazily inside the key handler: the
        # first alt+t would otherwise repaint the whole screen as it registers.
        register_all(self)
        self.query_one(ProfileTable).focus()
        # The log pane starts collapsed: it is a diagnostic surface, not part of
        # the main workflow, and an always-open pane would halve the table.
        self.query_one("#log-pane", Static).display = False
        self._reload_table()
        # A cheap in-memory status tick. The log refresh below it is a worker
        # because ``log_tail()`` may read a file written by the Xray process.
        self.set_interval(LOG_REFRESH_SECONDS, self._tick)

    # -- detail panel -----------------------------------------------------

    def _refresh_detail(self) -> None:
        """Re-render the detail panel for whatever row the cursor is on.

        Best-effort by design: this runs on cursor movement, and a panel that
        fails to refresh must never take the table navigation down with it.
        """
        try:
            self.query_one("#detail", ProfileDetail).show_profile(self._selected_profile())
        except Exception:
            pass

    def _selected_profile(self) -> Profile | None:
        profile_id = self._selected_id()
        if profile_id is None:
            return None
        try:
            return self._store.get(profile_id)
        except AppError:
            return None

    @on(ProfileTable.Highlighted)
    def _row_highlighted(self) -> None:
        """Keep the detail panel in step with the cursor.

        Fires on cursor movement as well as after a reload, so this is the one
        place that has to know the panel exists — every path that changes the
        table ends up triggering it.
        """
        self._refresh_detail()

    # -- key guards ------------------------------------------------------

    def _on_main_screen(self) -> bool:
        """True when the profile list is the topmost screen.

        App-level bindings are visible from modal screens too, so every action
        starts with this check. Without it, typing a label containing ``d`` in
        a text field could delete a profile.
        """
        return bool(self.screen_stack) and self.screen is self.screen_stack[0]

    # -- actions ---------------------------------------------------------

    def action_connect_row(self) -> None:
        """``c`` (or ``Enter``) — switch to the highlighted profile."""
        if not self._on_main_screen() or self._switching:
            return
        profile_id = self._selected_id()
        if profile_id is None:
            self.notify("No profile selected.", severity="warning", markup=False)
            return
        self._begin_switch()
        self._connect_worker(profile_id)

    def action_toggle_connection(self) -> None:
        """``space`` — stop the running service, or resume the active profile.

        Deliberately not bound to ``c``: ``c`` acts on the highlighted row while
        this acts on the service as a whole. A user scanning the table and
        pressing ``c`` expects to move to that row, not to halt their tunnel.
        """
        if not self._on_main_screen() or self._switching:
            return
        if self._service.running:
            self._begin_switch()
            self._disconnect_worker()
            return
        profile_id = self._store.active_id
        if profile_id is None:
            self.notify("No active profile. Select a row and press Enter.", severity="warning", markup=False)
            return
        self._begin_switch()
        self._connect_worker(profile_id)

    def action_add_profile(self) -> None:
        """``l`` (or ``a``) — open the add modal; the table refreshes when it closes."""
        if not self._on_main_screen():
            return
        if self._secrets is None:
            self.notify(
                "No secret backend is available; profiles cannot be added.",
                severity="error",
                markup=False,
            )
            return
        self.push_screen(
            AddProfileScreen(self._store, self._secrets, allow_insecure=self._allow_insecure),
            callback=self._on_profile_closed,
        )

    def action_edit_profile(self) -> None:
        """``e`` — open the non-secret edit form for the highlighted profile."""
        if not self._on_main_screen():
            return
        profile = self._selected_profile()
        if profile is None:
            return
        if self._secrets is None:
            self.notify(
                "No secret backend is available; profiles cannot be edited.",
                severity="error",
                markup=False,
            )
            return
        self.push_screen(
            EditProfileScreen(self._store, self._secrets, profile),
            callback=self._on_profile_closed,
        )

    def action_delete_profile(self) -> None:
        """``d`` — confirm, then delete the Keychain item and the profile."""
        if not self._on_main_screen():
            return
        profile = self._selected_profile()
        if profile is None:
            return
        self.push_screen(
            ConfirmScreen(
                f"Delete profile {profile.label!r}?",
                detail="Its Keychain item is removed too. This cannot be undone.",
                yes_label="Delete",
            ),
            # The id is captured now: by the time the answer arrives the cursor
            # may be pointing somewhere else entirely.
            callback=lambda confirmed: self._delete_after_confirm(profile.id, confirmed),
        )

    def _delete_after_confirm(self, profile_id: str, confirmed: object) -> None:
        if confirmed:
            self._delete_worker(profile_id)

    def _on_profile_closed(self, _result: Profile | None) -> None:
        """Modal result callback: add, edit, or delete may all have changed the store."""
        self._reload_table()

    def action_test_all(self) -> None:
        """``t`` — probe every profile concurrently and fill the LAT column."""
        if not self._on_main_screen():
            return
        if not self._store.all():
            self.notify("There are no profiles to test.", severity="warning", markup=False)
            return
        self._pending_results = 0
        self._note("testing all profiles…")
        self._probe_worker()

    def action_edit_address(self) -> None:
        """``i`` — quick server/port editor for the highlighted profile.

        The short path for the most common edit. ``e`` is still the full form;
        this exists because making someone page through nine fields to fix an
        address is the kind of friction that pushes people back to editing raw
        links by hand, which is exactly what this tool is meant to replace.
        """
        if not self._on_main_screen():
            return
        profile_id = self._selected_id()
        if profile_id is None:
            self.notify("No profile selected.", severity="warning", markup=False)
            return
        profile = self._store.get(profile_id)
        self.push_screen(AddressScreen(self._store, profile), callback=self._on_profile_closed)

    def action_add_subscription(self) -> None:
        """``s`` — add a subscription URL, then import its nodes.

        The modal only records the URL; importing happens here in a worker once
        it closes. Keeping the fetch out of the dialog matters because a slow or
        dead provider would otherwise freeze a form the user is trying to escape.
        """
        if not self._on_main_screen():
            return
        if self._secrets is None:
            self.notify(
                "No secret backend is available; subscriptions cannot be added.",
                severity="error",
                markup=False,
            )
            return
        self.push_screen(
            AddSubscriptionScreen(self._store, self._secrets),
            callback=self._on_subscription_closed,
        )

    def _on_subscription_closed(self, name: str | None) -> None:
        """Modal callback: ``None`` cancelled, otherwise fetch and import."""
        self._reload_table()
        if name is None:
            return
        self.refresh_subscription(name)

    def refresh_subscription(self, name: str) -> None:
        """Fetch one subscription and reconcile its nodes. Safe to call twice."""
        if self._switching:
            return
        self._begin_switch()
        self._note(f"fetching subscription {name}…")
        self._subscription_worker(name)

    @work(thread=True, exclusive=True, group="switch")
    def _subscription_worker(self, name: str) -> None:
        """Fetch + import off the event loop.

        Credential discipline: the URL comes from the Keychain and goes straight
        into httpx. It is never logged, never put in a widget, and never
        interpolated into an error — a subscription URL grants access to the
        user's entire node list. Errors reach the UI by name, never by content.
        """
        try:
            url = self._secrets.get(f"{SUB_SECRET_PREFIX}{name}")
        except AppError as exc:
            self.app.call_from_thread(self._subscription_failed, name, str(exc))
            return
        try:
            body = fetch_subscription(url)
        except AppError as exc:
            self.app.call_from_thread(self._subscription_failed, name, str(exc))
            return
        subscription = parse(body)
        if not subscription.nodes:
            # A 200 that yields nothing is almost always a login page or an
            # error message, not an empty feed. Reconciling it would flag every
            # node in this subscription unavailable, so refuse instead.
            reason = "returned no vless:// links"
            if subscription.issues:
                reason = f"returned no usable links ({len(subscription.issues)} skipped)"
            self.app.call_from_thread(self._subscription_failed, name, reason)
            return
        try:
            result = self._store.reconcile(
                subscription.nodes,
                source=f"{SUB_SOURCE_PREFIX}{name}",
                secrets=self._secrets,
            )
        except AppError as exc:
            self.app.call_from_thread(self._subscription_failed, name, str(exc))
            return
        summary = (
            f"subscription {name}: {len(result.added)} new, {len(result.updated)} updated, "
            f"{len(result.marked_unavailable)} unavailable"
        )
        if subscription.issues:
            summary += f", {len(subscription.issues)} line(s) skipped"
        self.app.call_from_thread(self._subscription_succeeded, summary)

    def _subscription_succeeded(self, summary: str) -> None:
        self._switching = False
        self._last_error = None
        self._note(summary)
        self._reload_table()
        self.notify(summary, severity="information", markup=False)

    def _subscription_failed(self, name: str, reason: str) -> None:
        self._switching = False
        message = f"subscription {name} failed: {reason}"
        self._last_error = message
        self._note(f"error: {message}")
        self.notify(message, title="Subscription failed", severity="error", markup=False)

    def action_cycle_theme(self) -> None:
        """``alt+t`` — step to the next theme.

        Cycles instantly rather than opening a picker: while you are choosing a
        theme, the fastest loop is the one with nothing to dismiss.
        """
        if not self._on_main_screen():
            return
        applied = apply_theme(self, next_theme(self.theme))
        self.notify(f"theme: {applied}", severity="information", markup=False)

    def action_show_help(self) -> None:
        """``h`` — open the key reference."""
        if not self._on_main_screen():
            return
        self.push_screen(HelpScreen())

    def action_toggle_log(self) -> None:
        """``o`` — show or hide the Xray output pane."""
        if not self._on_main_screen():
            return
        pane = self.query_one("#log-pane", Static)
        pane.display = not pane.display
        if pane.display:
            self._refresh_log()

    def action_quit_app(self) -> None:
        """``q`` — stop the proxy, then exit.

        Xray is a child process with listeners bound to loopback; leaving it
        running because the UI closed would leak a tunnel nobody is watching.
        """
        if not self._on_main_screen() or self._shutting_down:
            return
        self._shutting_down = True
        self._shutdown_worker()

    # -- workers ---------------------------------------------------------

    @work(thread=True, exclusive=True, group="switch")
    def _connect_worker(self, profile_id: str) -> None:
        """Run the D7 ordered switch off the event loop.

        Persisting the active id is deliberately NOT done here. ``ProxyService``
        owns that write — its own docstring claims it — and it must be written
        only after ``apply`` succeeds, inside the same lock that serialises
        switches. Duplicating it here would mean a second atomic file rewrite
        per connect and a second place for the active id to go wrong.
        """
        try:
            self._service.connect(profile_id)
        except Exception as exc:  # noqa: BLE001 — the worker must never leak to the loop
            self.call_from_thread(self._switch_failed, _safe_message(exc))
            return
        self.call_from_thread(self._switch_succeeded)

    @work(thread=True, exclusive=True, group="switch")
    def _disconnect_worker(self) -> None:
        """Stop the proxy off the event loop."""
        try:
            self._service.disconnect()
        except Exception as exc:  # noqa: BLE001
            self.call_from_thread(self._switch_failed, _safe_message(exc))
            return
        self.call_from_thread(self._switch_succeeded)

    @work(thread=True, exclusive=True, group="probe")
    def _probe_worker(self) -> None:
        """Run ``probe_all`` in a worker.

        The callback below is invoked from *the service's* worker threads, not
        from this one, and never from the Textual loop. ``call_from_thread`` is
        therefore mandatory rather than merely tidy.
        """

        def on_result(profile_id: str, latency_ms: int | None) -> None:
            self.call_from_thread(self._on_probe_result, profile_id, latency_ms)

        try:
            self._service.probe_all(on_result, timeout=PROBE_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            self.call_from_thread(self._note, f"latency test failed: {_safe_message(exc)}")
        self.call_from_thread(self._probe_finished)

    @work(thread=True, exclusive=True, group="delete")
    def _delete_worker(self, profile_id: str) -> None:
        """Delete the Keychain item then the profile, saving last."""
        secrets = self._secrets
        if secrets is not None:
            try:
                secrets.delete(profile_id)
            except Exception:  # noqa: BLE001 — a row with no secret beats an orphaned secret
                pass
        try:
            self._store.delete(profile_id)
            self._store.save()
        except AppError as exc:
            self.call_from_thread(self._note, f"could not delete profile: {exc}")
            return
        self.call_from_thread(self._reload_table)

    @work(thread=True, exclusive=True, group="log")
    def _refresh_log(self) -> None:
        """Pull the redacted Xray tail in a worker and hand it to the loop."""
        try:
            tail = self._service.log_tail()
        except Exception:  # noqa: BLE001 — a log pane is never worth an exception
            tail = ""
        self.call_from_thread(self._apply_log, tail or "")

    @work(thread=True, group="shutdown")
    def _shutdown_worker(self) -> None:
        """Terminate Xray, then exit. Runs on exit so ``q`` is not instant-lossy."""
        try:
            self._service.disconnect()
        except Exception:  # noqa: BLE001 — never block exit on a cleanup failure
            pass
        self.call_from_thread(self.exit)

    # -- loop-side callbacks ---------------------------------------------

    def _on_probe_result(self, profile_id: str, latency_ms: int | None) -> None:
        """Apply one probe result. Always runs on the event loop.

        ``ProxyService.probe_all`` also calls ``store.set_latency``, but only
        after every probe has finished. The design requires rows to *fill in
        progressively*, which means the UI has to apply each result as it
        arrives. Writing the identical value from two threads cannot diverge:
        both write the same number for the same profile, and the store replaces
        a frozen dataclass rather than mutating one.
        """
        try:
            self._store.set_latency(profile_id, latency_ms)
        except AppError:
            return  # the profile was deleted while the sweep was running
        self._pending_results += 1
        if self._pending_results >= RESORT_EVERY:
            self._reload_table(sort_by_latency=True)

    def _probe_finished(self) -> None:
        self._reload_table(sort_by_latency=True)

    def _begin_switch(self) -> None:
        self._switching = True
        self._last_error = None
        self._refresh_status()

    def _switch_succeeded(self) -> None:
        self._switching = False
        self._last_error = None
        self._reload_table()

    def _switch_failed(self, message: str) -> None:
        """Report a failed switch: toast *and* log, because either alone is lossy."""
        self._switching = False
        self._last_error = message
        self.notify(message, title="Connect failed", severity="error", markup=False)
        self._note(f"error: {message}")
        self._reload_table()

    def _apply_log(self, tail: str) -> None:
        self._xray_log = tail
        self._render_log()

    def _note(self, message: str) -> None:
        """Append an app-level note to the log pane.

        Only ever called with contract-safe text: an ``AppError`` message or an
        exception type name. Never a link, a link dict, or a profile uuid.
        """
        self._notes.append(message)
        del self._notes[:-MAX_LOG_NOTES]
        self._render_log()

    def _render_log(self) -> None:
        try:
            pane = self.query_one("#log-pane", Static)
        except Exception:
            return
        blocks = list(self._notes[-MAX_LOG_NOTES:])
        if self._xray_log:
            blocks.append(self._xray_log)
        # markup is off for this widget and the value is a Text, so Xray output
        # containing square brackets is shown literally instead of being parsed.
        pane.update(Text("\n".join(blocks) if blocks else "(no output yet)"))

    # -- refresh ---------------------------------------------------------

    def _tick(self) -> None:
        """Cheap periodic refresh; the log fetch itself is a worker."""
        self._refresh_status()
        if self.log_visible:
            self._refresh_log()

    def _reload_table(self, *, sort_by_latency: bool | None = None) -> None:
        """Rebuild the table from the store. All reads are in-memory."""
        try:
            table = self.query_one(ProfileTable)
        except Exception:
            return
        current = self._current_id()
        table.reload_profiles(
            self._store.all(),
            active_id=self._store.active_id,
            current_id=current,
            sort_by_latency=sort_by_latency,
        )
        self._refresh_status()
        # A reload can move the cursor onto a different profile, so the panel is
        # refreshed here too. Row-highlight alone is not enough: after a sort the
        # same row index can hold entirely different content.
        self._refresh_detail()

    def _refresh_status(self) -> None:
        """Update the header and status bar. Reads only in-memory service state."""
        count = len(self._store.all())
        dot, word = self._state_indicator()
        # No profile label is interpolated here: the header is the one surface
        # that stays visible behind every modal.
        self.sub_title = f"{count} profile{'' if count == 1 else 's'} · {dot} {word}"
        try:
            status = self.query_one(StatusBar)
        except Exception:
            return
        status.update_status(
            socks_addr=self._socks_addr,
            http_addr=self._http_addr,
            xray_version=self._xray_version,
            running=self._is_running(),
        )

    def _state_indicator(self) -> tuple[str, str]:
        """The header dot. Switching outranks error so it never lies while busy."""
        if self._switching:
            return "⟳", "SWITCHING"
        if self._last_error is not None:
            return "●", "ERROR"
        if self._is_running():
            return "●", "RUNNING"
        return "○", "STOPPED"

    def _is_running(self) -> bool:
        try:
            return bool(self._service.running)
        except Exception:  # noqa: BLE001 — a broken service must not break the header
            return False

    def _current_id(self) -> str | None:
        try:
            current: Profile | None = self._service.current
        except Exception:  # noqa: BLE001
            return None
        return None if current is None else current.id

    # -- selection -------------------------------------------------------

    def _selected_id(self) -> str | None:
        try:
            return self.query_one(ProfileTable).selected_id()
        except Exception:
            return None

    def _selected_profile(self) -> Profile | None:
        """The profile under the cursor, or ``None``. **Silent by contract.**

        A getter that reports its own failures is a bug. This one runs on every
        cursor movement *and* after every table rebuild, so a ``notify()`` here
        fires repeatedly per keypress and fills the screen with toasts nobody
        asked for. Rebuilding briefly empties the table, which made "no
        selection" the normal transient state rather than a problem worth
        interrupting for.

        The actions that genuinely need a selection already say so themselves —
        ``action_connect_row`` and friends notify once, on a deliberate action.
        That is where this belongs.
        """
        profile_id = self._selected_id()
        if profile_id is None:
            return None
        try:
            return self._store.get(profile_id)
        except AppError:
            return None


__all__ = ["VlessApp"]