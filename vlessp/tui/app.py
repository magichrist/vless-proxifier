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
from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Static

from vlessp import APP_NAME
from vlessp.errors import AppError
from vlessp.profiles import (
    SUB_SECRET_PREFIX,
    SUB_SOURCE_PREFIX,
    Listeners,
    ProfileStore,
)
from vlessp.subscriptions import fetch_subscription, parse
from vlessp.tui.screens import (
    AddProfileScreen,
    AddressScreen,
    AddSubscriptionScreen,
    ConfirmScreen,
    EditProfileScreen,
    HelpScreen,
    ListenersScreen,
)
from vlessp.tui.theme import DEFAULT_THEME_NAME, apply_theme, next_theme, register_all
from vlessp.tui.widgets import (
    DETAIL_HEIGHT,
    TABLE_FRAME_ROWS,
    AppHeader,
    KeyHints,
    ProfileDetail,
    ProfileTable,
    StatusBar,
)

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

# Fallback listener addresses now come from ``ProfileStore.listeners`` (which
# itself defaults to loopback — see ``vlessp.profiles``). There is no constant
# here: two sources for "the default port" is exactly how a status bar ends up
# showing something the service is not bound to.

# Log pane refresh cadence. Slow enough to be free, fast enough that a failed
# switch is diagnosed without leaving the app.
LOG_REFRESH_SECONDS = 1.0

# Retained length of our own log notes. Xray's own tail is windowed by the
# service, not here.
MAX_LOG_NOTES = 200

# Fixed chrome around the table, in rows, used to size it. The app header owns
# two rows when there is room (wordmark plus hairline) and one when there is
# not; the footer strip owns the key hints (two rows with their hairline, one
# without) plus the single status row; the detail band DETAIL_HEIGHT; the
# profile frame TABLE_FRAME_ROWS for its top and bottom edge. The table is
# capped at whatever is left, so a long list scrolls instead of pushing the
# panels off-screen.
FULL_HEADER_ROWS = 2
COMPACT_HEADER_ROWS = 1
FULL_FOOTER_ROWS = 3  # key hints (2) + status bar (1)
COMPACT_FOOTER_ROWS = 2

#: Terminal height below which the chrome compacts. Twenty rows is the point at
#: which the framed list would otherwise be shorter than the panels it sits
#: above, which is the layout failing rather than a terminal being small.
COMPACT_HEIGHT = 20

LOG_PANE_ROWS = 12
LOG_MIN_ROWS = 4
MIN_TABLE_ROWS = 3


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
        background: $background;
    }
    /* The list is framed rather than bare. The frame is what supplies the edge
       on the screen's main surface: the table keeps ``height: auto`` and a
       borderless body, so its ``region.height`` is still a count of rows, while
       the frame around it draws the rounded edge and carries the title. The
       frame takes the leftover height (1fr) so a short list sits in a full
       panel instead of leaving a void under it. */
    #profiles-frame {
        height: 1fr;
        border: round $primary;
        border-title-color: $primary;
        border-title-style: bold;
        /* The panel floor is the screen ground, not a raised surface. A list
           that fills the window should read as the window, with the frame
           providing the edge; painting it ``$surface`` made a light theme look
           like one enormous white card. */
        background: $background;
    }
    #profiles-frame ProfileTable {
        height: auto;
        background: $background;
    }
    ProfileTable > .datatable--header {
        background: $panel;
        /* Ink, not the accent. A caption is small text, and the light palette's
           raspberry only clears 4.5:1 against the cream ground -- against the
           pink panel it does not, so the accent belongs on the frame title
           (which sits on the ground) and never here. */
        color: $foreground;
        text-style: bold;
    }
    ProfileTable > .datatable--even-row {
        /* A tint of the foreground rather than a derived surface shade. Textual's
           ``$surface-lighten-N`` clamps to near-identical values on a dark theme
           once a 256-colour terminal quantises it, which is exactly the case this
           stripe exists for; blending the foreground keeps a visible step on both
           the dark and the light palette. */
        background: $foreground 7%;
    }
    /* No colour override on the cursor: the LAT bar and the STATE word carry
       their own colour, and a cursor rule with ``color:`` set would repaint
       every cell in the row flat, erasing both. The tint alone marks the row. */
    ProfileTable > .datatable--cursor {
        background: $primary 22%;
    }
    ProfileTable:focus > .datatable--cursor {
        background: $primary 34%;
    }
    ProfileTable > .datatable--hover {
        background: $accent 18%;
    }
    #log-pane {
        height: 12;
        border: round $accent;
        border-title-color: $accent;
        border-title-style: bold;
        padding: 0 1;
        overflow-y: auto;
        color: $text-muted;
        background: $surface;
    }
    #footer {
        dock: bottom;
        height: 3;
    }
    /* Control look is global, not per-modal: a rule inside a widget's
       DEFAULT_CSS is only injected once that widget mounts, and the confirm
       dialog can be the first modal opened. Rounded fields replace Textual's
       half-block "tall" border, which meets badly in most terminal fonts. */
    Input, Select {
        border: round $panel-lighten-1;
        background: $surface;
    }
    Input:focus, Select:focus {
        border: round $primary;
    }
    /* Buttons as outlined pills: quiet at rest, filled on hover, so the focused
       one is obvious without every button shouting at once. */
    Button {
        border: round $primary;
        background: $panel;
        color: $primary;
        min-width: 12;
    }
    Button:hover {
        background: $primary;
        color: $background;
    }
    Button.-error {
        border: round $error;
        color: $error;
    }
    Button.-error:hover {
        background: $error;
        color: $background;
    }
    Button.-success {
        border: round $success;
        color: $success;
    }
    Button.-success:hover {
        background: $success;
        color: $background;
    }
    Button:disabled {
        border: round $panel;
        color: $text-muted;
        background: $surface;
    }
    /* Modal frames carry their title on the border, styled per screen. */
    .modal-title {
        border-title-style: bold;
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
        Binding("p", "edit_listeners", "Local ports"),
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
        # Listener resolution order: an explicit argument, then the service (a
        # stub or a future ProxyService that publishes them), then what the user
        # saved in the UI. The store is the authority otherwise, so the header
        # never disagrees with the ports the service is bound to.
        self._socks_addr = (
            socks_addr
            or getattr(service, "socks_addr", None)
            or store.listeners.socks
        )
        if isinstance(http_addr, _Unset):
            self._http_addr: str | None = (
                getattr(service, "http_addr", None) or store.listeners.http
            )
        else:
            self._http_addr = http_addr or None
        self._xray_version = xray_version or getattr(service, "xray_version", None)
        self._switching = False
        self._probe_active = False
        self._probe_total = 0
        self._probe_done = 0
        self._header_rows = FULL_HEADER_ROWS
        self._footer_rows = FULL_FOOTER_ROWS
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
        # A custom header replaces Textual's. The built-in one is a title and a
        # clock; this app has a service state and a profile count that matter
        # far more, and one widget keeps them aligned with each other.
        yield AppHeader(id="app-header")
        # The table lives inside a framed container. Frame and table are
        # separate widgets so the table's height stays a pure row count; the
        # frame contributes the edge (see TABLE_FRAME_ROWS).
        with Vertical(id="profiles-frame"):
            yield ProfileTable(id="profiles")
        # Detail directly under the table it describes. With the table now hugging
        # its rows (see ProfileTable.CSS) the panel reads as attached to the data
        # rather than stranded at the bottom. The log pane is a diagnostic surface
        # that is hidden by default, so this is the only always-visible readout.
        yield ProfileDetail(id="detail")
        yield Static("", id="log-pane")
        # Hints and status share one footer strip. Pinned, not in the flow: as
        # flow children they drifted up the screen on a short list, so the keys
        # moved every time the row count changed. Both dock to the same edge, and
        # Textual does not stack same-edge docks, so the strip owns the two rows
        # and the contents stack inside it.
        #
        # Textual's own Footer remains gone on purpose: twelve bindings do not fit
        # one un-wrapped line, and it was silently truncating them — hiding `q`
        # along the way. KeyHints says the same thing without lying about fit.
        with Vertical(id="footer"):
            yield KeyHints()
            yield StatusBar(id="status")

    def on_mount(self) -> None:
        # Themes register here rather than lazily inside the key handler: the
        # first alt+t would otherwise repaint the whole screen as it registers.
        register_all(self)
        # The designed palette is applied explicitly. Textual would otherwise
        # start on its own utility default, and "the default is one of ours"
        # only holds if something actually sets it.
        apply_theme(self, DEFAULT_THEME_NAME)
        # The custom strips bake resolved colours into their Text at draw time,
        # and ``theme_variables`` only catches up on the next refresh, so this
        # repaint is deferred rather than immediate. Without it the header and
        # status bar keep Textual's default palette until the 1 Hz tick.
        self.call_after_refresh(self._refresh_status)
        self.query_one("#profiles-frame", Vertical).border_title = "PROFILES"
        self.query_one("#log-pane", Static).border_title = "XRAY OUTPUT"
        self.query_one(ProfileTable).focus()
        # The log pane starts collapsed: it is a diagnostic surface, not part of
        # the main workflow, and an always-open pane would halve the table.
        self.query_one("#log-pane", Static).display = False
        self._apply_chrome(self.size.height)
        self._fit_table_height()
        self._reload_table()
        # A cheap in-memory status tick. The log refresh below it is a worker
        # because ``log_tail()`` may read a file written by the Xray process.
        self.set_interval(LOG_REFRESH_SECONDS, self._tick)

    def on_resize(self, event: events.Resize) -> None:
        """Re-divide the vertical space whenever the terminal changes size.

        Uses the event's size, not ``self.size``: this handler runs before the
        app's cached size is updated, so reading it here would re-apply the old
        dimensions and the table would keep its stale height.
        """
        self._apply_chrome(event.size.height)
        self._fit_table_height(height=event.size.height)

    def _apply_chrome(self, height: int) -> None:
        """Switch the chrome between its full and compact forms.

        The framed list needs twelve rows of chrome to look right. On a shorter
        terminal that chrome would crowd out the data, so the two decorative
        rows -- the header hairline and the hints hairline -- are dropped and the
        remaining numbers are updated so :meth:`_fit_table_height` divides up the
        space it actually has.
        """
        if height <= 0:
            return
        compact = height < COMPACT_HEIGHT
        self._header_rows = COMPACT_HEADER_ROWS if compact else FULL_HEADER_ROWS
        self._footer_rows = COMPACT_FOOTER_ROWS if compact else FULL_FOOTER_ROWS
        try:
            header = self.query_one("#app-header", AppHeader)
            hints = self.query_one(KeyHints)
            footer = self.query_one("#footer", Vertical)
        except Exception:  # noqa: BLE001 - resize can arrive mid-compose
            return
        header.set_class(compact, "compact")
        hints.set_class(compact, "compact")
        footer.styles.height = self._footer_rows

    def _fit_table_height(self, *, height: int | None = None) -> None:
        """Cap the profile table at the rows left for it.

        A ``1fr`` table filled the screen and pushed the detail panel and key
        hints off the bottom; so did ``auto``, which asks for its full content
        height however tall that is. Neither CSS ``max-height`` form can express
        "the space left after the widgets below me" — ``1fr`` resolves against
        docked siblings only, and a percentage is blind to them — so the number
        is computed here from the terminal height and re-applied on resize.

        The log pane is sized first, from the same budget: it is the one panel
        that is allowed to shrink, so opening it on a short terminal gives up
        pane rows rather than pushing the detail band off the screen.

        The cap is in rows, not cells, because it is subtracted from a row count.
        """
        if height is None:
            height = self.size.height
        if height <= 0:
            return  # before the first layout there is nothing to divide up
        reserved = self._header_rows + self._footer_rows + DETAIL_HEIGHT + TABLE_FRAME_ROWS
        try:
            pane = self.query_one("#log-pane", Static)
        except Exception:  # noqa: BLE001 - sizing can be requested mid-compose
            pane = None
        if pane is not None and pane.display:
            room = height - reserved - MIN_TABLE_ROWS
            pane_rows = max(LOG_MIN_ROWS, min(LOG_PANE_ROWS, room))
            if reserved + pane_rows + MIN_TABLE_ROWS > height:
                pane_rows = max(1, height - reserved - MIN_TABLE_ROWS)
            pane.styles.height = pane_rows
            reserved += pane_rows
        self.query_one(ProfileTable).styles.max_height = max(
            MIN_TABLE_ROWS, height - reserved
        )

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
        profiles = self._store.all()
        if not profiles:
            self.notify("There are no profiles to test.", severity="warning", markup=False)
            return
        self._pending_results = 0
        self._probe_active = True
        self._probe_total = len(profiles)
        self._probe_done = 0
        self._note("testing all profiles…")
        self._refresh_status()
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

    def action_edit_listeners(self) -> None:
        """``p`` — edit the local SOCKS5/HTTP listen addresses and ports.

        The internal counterpart to ``i``: ``i`` changes the remote server the
        tunnel dials, this changes where the tunnel is reachable *here*. Nothing
        about the profile or its UUID is involved, so this screen needs neither
        the store's profiles nor the Keychain.
        """
        if not self._on_main_screen():
            return
        if not callable(getattr(self._service, "set_listeners", None)):
            self.notify(
                "This build cannot change the local listener addresses.",
                severity="error",
                markup=False,
            )
            return
        self.push_screen(
            ListenersScreen(socks=self._socks_addr, http=self._http_addr),
            callback=self._on_listeners_closed,
        )

    def _on_listeners_closed(self, result: Listeners | None) -> None:
        """Modal callback: ``None`` cancelled, otherwise apply and persist."""
        if result is None:
            return
        self._begin_switch()
        self._apply_listeners_worker(result)

    @work(thread=True, exclusive=True, group="switch")
    def _apply_listeners_worker(self, listeners: Listeners) -> None:
        """Rebind the local proxy off the event loop.

        Restarting the tunnel spawns a subprocess, so this cannot run on the
        loop. ``set_listeners`` returns whether a live tunnel was restarted;
        either way the app's own view of the ports only changes once this
        succeeds, so the status bar never lies.
        """
        try:
            restarted = self._service.set_listeners(
                socks_addr=listeners.socks, http_addr=listeners.http
            )
        except Exception as exc:  # noqa: BLE001 — the worker must never leak to the loop
            self.call_from_thread(self._listeners_failed, _safe_message(exc))
            return
        self.call_from_thread(self._listeners_applied, listeners, bool(restarted))

    def _listeners_applied(self, listeners: Listeners, restarted: bool) -> None:
        """Adopt the new ports and persist them. Runs on the event loop."""
        self._switching = False
        self._last_error = None
        self._socks_addr = listeners.socks
        self._http_addr = listeners.http
        # Persist after the apply so a store write cannot record a binding that
        # never happened. A save failure is reported but not fatal: the new
        # ports are live, they just will not survive a restart.
        try:
            self._store.set_listeners(listeners.socks, listeners.http)
            self._store.save()
        except AppError as exc:
            self._note(f"could not save listener settings: {exc}")
        http_note = f", HTTP {listeners.http}" if listeners.http else ", HTTP off"
        summary = f"SOCKS {listeners.socks}{http_note}"
        if restarted:
            self._note(f"tunnel restarted on {summary}")
            self.notify(f"Restarted on {summary}", severity="information", markup=False)
        else:
            self._note(f"listeners set to {summary}")
            self.notify(f"Listeners set to {summary}", severity="information", markup=False)
        self._refresh_status()

    def _listeners_failed(self, message: str) -> None:
        """Report a failed listener change; the ports are left untouched."""
        self._switching = False
        self._last_error = message
        self.notify(message, title="Listener change failed", severity="error", markup=False)
        self._note(f"error: {message}")
        self._refresh_status()

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
        # Repaint the two strips that bake colours into their content, once the
        # new variables are live. Everything else is styled by CSS and restyles
        # itself when the theme changes.
        self.call_after_refresh(self._refresh_status)
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
        self._fit_table_height()
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
        self._probe_done += 1
        if self._pending_results >= RESORT_EVERY:
            self._reload_table(sort_by_latency=True)
        self._refresh_status()

    def _probe_finished(self) -> None:
        self._probe_active = False
        self._probe_done = self._probe_total
        self._reload_table(sort_by_latency=True)
        self._refresh_status()

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

    def _busy_label(self) -> str | None:
        """The label for whatever is running off the event loop, if anything.

        Only one of these can be true at a time in practice: switching holds the
        service lock, and a sweep is not started while one is in flight. The
        order still matters for the moment between a keypress and the worker
        actually starting.
        """
        if self._switching:
            return "SWITCHING"
        if self._probe_active:
            return "TESTING"
        return None

    def _refresh_status(self) -> None:
        """Update the header and status bar. Reads only in-memory service state."""
        count = len(self._store.all())
        dot, word = self._state_indicator()
        # No profile label is interpolated here: the header is the one surface
        # that stays visible behind every modal.
        self.sub_title = f"{count} profile{'' if count == 1 else 's'} · {dot} {word}"
        running = self._is_running()
        try:
            self.query_one(AppHeader).set_state(
                running=running,
                switching=self._switching,
                error=self._last_error is not None,
                count=count,
            )
        except Exception:  # noqa: BLE001 - header may not exist yet
            pass
        try:
            status = self.query_one(StatusBar)
        except Exception:  # noqa: BLE001 - status may not exist yet
            return
        status.update_status(
            socks_addr=self._socks_addr,
            http_addr=self._http_addr,
            xray_version=self._xray_version,
            running=running,
            busy=self._busy_label(),
            done=self._probe_done,
            total=self._probe_total if self._probe_active else 0,
        )

    def _state_indicator(self) -> tuple[str, str]:
        """The header dot. Switching outranks error so it never lies while busy.

        The glyph, not just the colour, separates the states: ``●`` running and
        ``✕`` error must be distinguishable on a monochrome or colour-blind
        terminal, where a red dot and a green dot are the same dot.
        """
        if self._switching:
            return "⟳", "SWITCHING"
        if self._last_error is not None:
            return "✕", "ERROR"
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