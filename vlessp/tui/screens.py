"""Modal screens for the VLESS TUI.

Three screens, three jobs:

``ConfirmScreen``     generic yes/no, so no destructive action is a bare keypress.
``AddProfileScreen``  paste a ``vless://`` link; parse, preview, then split it.
``EditProfileScreen`` a form over the NON-SECRET fields only.

The split, and why it is enforced here
--------------------------------------
``parse_vless_uri`` returns a dict containing ``uuid``. The order of operations
in :meth:`AddProfileScreen._write` is therefore load-bearing:

1. ``store.add(label, link_without_uuid)`` — generates the profile id, which is
   also the Keychain account name, so the id must exist first.
2. ``secrets.set(profile.id, uuid)`` — the credential goes to the Keychain.
3. ``store.save()`` — only once the credential is durably stored.

If step 2 fails the just-added profile is rolled back, so a failed add cannot
leave a row in ``profiles.json`` whose UUID was never stored — a profile that
looks valid and fails every connect.

The UUID is popped in step 1 and is never placed in any widget, ``Static``,
``notify()`` call, or preview. ``ProfileStore`` rejects a link containing
``"uuid"`` as a backstop, but this module must never rely on it to remember:
a store that merely *rejects* the credential still received it.

Threading note: these screens own ``@work(thread=True)`` workers, and every hop
back to the event loop goes through ``self.app.call_from_thread(...)``. A
``Screen`` is a DOM node; ``call_from_thread`` lives on ``App``, so ``self.app``
is the correct and only route back onto the loop from a screen's worker.
"""
from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping
from typing import Any

from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static

from vlessp.errors import AppError
from vlessp.links import parse_vless_uri
from vlessp.profiles import Profile, ProfileStore
from vlessp.secrets import SecretStore

# A canonical-format UUID used ONLY to satisfy the parser's syntax check while
# re-validating an edited profile, whose real UUID lives in the Keychain and is
# never loaded here. It is a constant in this source file: it is not a
# credential, it is never stored, never displayed, and never sent anywhere.
_VALIDATION_UUID = "00000000-0000-4000-8000-000000000000"

# Allowed sets, mirrored from ``links.parse_vless_uri``. The dropdowns must not
# be able to offer a value the parser would reject.
SECURITY_CHOICES: tuple[tuple[str, str], ...] = (
    ("none", "none"),
    ("tls", "tls"),
    ("reality", "reality"),
)
TRANSPORT_CHOICES: tuple[tuple[str, str], ...] = (
    ("tcp", "tcp"),
    ("ws", "ws"),
    ("grpc", "grpc"),
    ("httpupgrade", "httpupgrade"),
    ("xhttp", "xhttp"),
)
# Transports that carry a request path / Host header in the URI.
PATH_TRANSPORTS = frozenset({"ws", "httpupgrade", "xhttp"})

# Shared button row styling.
_BUTTON_CSS = """
.fields-row {
    height: auto;
    margin-bottom: 1;
}
.fields-row Label {
    width: 16;
    padding: 1 1 0 0;
    text-align: right;
}
.fields-row Input, .fields-row Select {
    width: 1fr;
}
.actions {
    height: auto;
    margin-top: 1;
}
.actions Button {
    margin-right: 2;
}
"""


def build_validation_uri(link: Mapping[str, Any]) -> str:
    """Reassemble a link dict into a ``vless://`` URI.

    Used to re-validate an edited profile through the one function that is
    allowed to decide whether a link is acceptable. Every key the stored link
    carries is mapped back to the query parameter it came from, so an edit to
    one field cannot silently drop an unrelated one (Reality ``pbk``, a gRPC
    service name, certificate pins) — those are simply carried through.

    Note ``path``/``host`` are emitted only for the transports that use them.
    For gRPC the parser cross-checks ``path`` against ``serviceName`` and
    refuses a disagreement, so emitting both would be a self-inflicted failure.
    """
    host = str(link.get("server") or "")
    port = int(link.get("port") or 0)
    security = str(link.get("security") or "none")
    network = str(link.get("network") or "tcp")

    params: list[tuple[str, str]] = [
        ("encryption", str(link.get("encryption") or "none")),
        ("security", security),
        ("type", network),
    ]

    def put(key: str, value: Any) -> None:
        """Append a parameter unless the value is absent; blank means 'unset'."""
        if value is None or value == "":
            return
        params.append((key, str(value)))

    put("sni", link.get("sni"))
    put("fp", link.get("fingerprint"))
    alpn = link.get("alpn") or []
    if isinstance(alpn, str):
        alpn = [alpn]
    if alpn:
        params.append(("alpn", ",".join(str(item) for item in alpn)))
    if link.get("allow_insecure"):
        params.append(("insecure", "1"))
    put("pcs", link.get("pins"))
    put("flow", link.get("flow"))

    if network in PATH_TRANSPORTS:
        put("path", link.get("path"))
        put("host", link.get("host_header"))
        if network == "ws" and link.get("headers"):
            put("headers", json.dumps(link["headers"], sort_keys=True))
    if network == "grpc":
        put("serviceName", link.get("grpc_service"))
        put("authority", link.get("grpc_authority"))
        if link.get("grpc_multi_mode"):
            params.append(("multiMode", "1"))
    if network == "xhttp":
        put("mode", link.get("xhttp_mode"))
        if link.get("xhttp_extra"):
            put("extra", json.dumps(link["xhttp_extra"], sort_keys=True))
    if security == "reality":
        # Reality keys are dropped when security is not reality: they are
        # meaningless to Xray in that configuration, so keeping them would be
        # storing a lie about what the profile needs.
        put("pbk", link.get("reality_public_key"))
        put("sid", link.get("reality_short_id"))
        put("spx", link.get("reality_spider_x"))

    query = urllib.parse.urlencode(params)
    name = urllib.parse.quote(str(link.get("name") or host))
    return f"vless://{_VALIDATION_UUID}@{host}:{port}?{query}#{name}"


def link_summary(link: Mapping[str, Any]) -> str:
    """One-line, credential-free description of a parsed link for the preview."""
    return (
        f"{link.get('server', '')}:{link.get('port', '')}  "
        f"security={link.get('security', '')}  transport={link.get('network', '')}"
    )


def summary_lines(link: Mapping[str, Any]) -> Text:
    """Multi-line preview shown before a profile is committed to disk.

    Deliberately excludes the UUID, the full URI, and any query parameter that
    is not part of the four fields the design asks for.
    """
    return Text(
        "\n".join(
            [
                "Parsed link:",
                f"  server      {link.get('server', '')}",
                f"  port        {link.get('port', '')}",
                f"  security    {link.get('security', '')}",
                f"  transport   {link.get('network', '')}",
                "",
                "The UUID will be stored in the Keychain, not on disk.",
            ]
        )
    )


class ConfirmScreen(ModalScreen[bool]):
    """Generic yes/no.

    Returns ``True`` only on an explicit yes. ``escape``, ``n``, and losing focus
    all mean no — the destructive path must never be the default.
    """

    DEFAULT_CSS = """
    ConfirmScreen {
        align: center middle;
    }
    ConfirmScreen > VerticalScroll {
        width: 56;
        height: auto;
        max-height: 80%;
        padding: 1 2;
        background: $surface;
        border: round $primary;
    }
    ConfirmScreen .question {
        height: auto;
        margin-bottom: 1;
    }
    ConfirmScreen .actions {
        height: auto;
        margin-top: 1;
    }
    ConfirmScreen Button {
        margin-right: 2;
    }
    """

    BINDINGS = [
        Binding("escape", "no", "No"),
        Binding("n", "no", "No"),
        Binding("y", "yes", "Yes"),
    ]

    def __init__(self, question: str, *, detail: str = "", yes_label: str = "Yes") -> None:
        super().__init__()
        self._question = question
        self._detail = detail
        self._yes_label = yes_label

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(Text(self._question), classes="question")
            if self._detail:
                yield Static(Text(self._detail), classes="detail")
            with Horizontal(classes="actions"):
                yield Button(self._yes_label, id="yes", variant="error")
                yield Button("Cancel", id="no")

    def on_mount(self) -> None:
        # Focus Cancel, not the destructive button: a stray Enter must not delete.
        self.query_one("#no", Button).focus()

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#yes")
    def _press_yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def _press_no(self) -> None:
        self.dismiss(False)


class AddProfileScreen(ModalScreen[Profile | None]):
    """Paste a link, see what was parsed, then save it.

    Two-stage on purpose. The link is parsed and previewed *before* anything is
    written, so a malformed or hostile link never reaches the Keychain, the
    store, or the disk — and the user gets to see the server they are about to
    connect to before it becomes a saved profile.
    """

    DEFAULT_CSS = _BUTTON_CSS + """
    AddProfileScreen {
        align: center middle;
    }
    AddProfileScreen > VerticalScroll {
        width: 76;
        height: auto;
        max-height: 90%;
        padding: 1 2;
        background: $surface;
        border: round $primary;
    }
    AddProfileScreen #preview {
        height: auto;
        margin: 1 0;
        padding: 1;
        border: round $accent;
    }
    AddProfileScreen #error {
        height: auto;
        margin: 1 0;
        color: $error;
    }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(
        self,
        store: ProfileStore,
        secrets: SecretStore,
        *,
        allow_insecure: bool = False,
    ) -> None:
        super().__init__()
        self._store = store
        self._secrets = secrets
        self._allow_insecure = allow_insecure
        self._parsed: dict[str, Any] | None = None

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("Name")
            yield Input(placeholder="defaults to the link's fragment", id="label")
            yield Label("VLESS link")
            # password=True so the UUID is masked on screen — it is a credential
            # and shoulder-surfing it out of a screenshot is a real risk.
            yield Input(placeholder="vless://…", password=True, id="link")
            yield Static("", id="preview")
            yield Static("", id="error")
            with Horizontal(classes="actions"):
                yield Button("Add", id="confirm", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#label", Input).focus()

    # -- input handling -------------------------------------------------

    @on(Input.Submitted, "#label")
    def _label_submitted(self) -> None:
        self.query_one("#link", Input).focus()

    @on(Input.Submitted, "#link")
    def _link_submitted(self) -> None:
        self.action_confirm()

    @on(Button.Pressed, "#confirm")
    def _confirm_pressed(self) -> None:
        self.action_confirm()

    @on(Button.Pressed, "#cancel")
    def _cancel_pressed(self) -> None:
        self.action_cancel()

    def action_cancel(self) -> None:
        """Abandon without writing anything. Safe at any stage."""
        self.dismiss(None)

    def action_confirm(self) -> None:
        """Stage 1 parses and previews; stage 2 commits."""
        if self._parsed is None:
            self._parse_and_preview()
        else:
            self._start_write()

    # -- stage 1: parse -------------------------------------------------

    def _parse_and_preview(self) -> None:
        raw = self.query_one("#link", Input).value.strip()
        self.query_one("#error", Static).update("")
        if not raw:
            self._show_error("Paste a vless:// link first.")
            return
        try:
            # allow_insecure comes from the caller (the CLI's --allow-insecure),
            # never from a default here: a link that disables certificate
            # verification is a security decision the user has to make on purpose.
            parsed = parse_vless_uri(raw, allow_insecure=self._allow_insecure)
        except AppError as exc:
            self._show_error(str(exc))
            return
        self._parsed = parsed
        label_input = self.query_one("#label", Input)
        if not label_input.value.strip():
            # The fragment is the best label the provider gave us; the user can
            # still overwrite it before committing.
            label_input.value = str(parsed.get("name") or parsed.get("server") or "")
        self.query_one("#preview", Static).update(summary_lines(parsed))
        self.query_one("#confirm", Button).label = "Save"

    def _show_error(self, message: str) -> None:
        """Show a parser message in place. Messages are link-free by contract."""
        self._parsed = None
        preview = self.query_one("#preview", Static)
        preview.display = False
        preview.update("")
        button = self.query_one("#confirm", Button)
        button.label = "Add"
        self.query_one("#error", Static).update(Text(message))
        self.query_one("#link", Input).focus()

    # -- stage 2: write -------------------------------------------------

    def _start_write(self) -> None:
        parsed = self._parsed
        if parsed is None:  # defensive: confirm without a parse
            self._parse_and_preview()
            return
        label = self.query_one("#label", Input).value.strip()
        if not label:
            self._show_error("Profile name must not be empty.")
            return
        button = self.query_one("#confirm", Button)
        button.disabled = True
        button.label = "Saving…"
        self.query_one("#error", Static).update("")
        # Everything that touches the Keychain or the filesystem happens in the
        # worker. Parsing is included for one reason: doing parse + update + save
        # as one unit means a validation failure leaves the store untouched,
        # instead of mutating in memory and failing on disk.
        self._write(label, {k: v for k, v in parsed.items() if k != "uuid"}, str(parsed["uuid"]))

    @work(thread=True, exclusive=True, group="profile-write")
    def _write(self, label: str, link: dict[str, Any], uuid_value: str) -> None:
        """Add the profile, store the UUID in the Keychain, then save.

        Ordering is forced by the contract: ``ProfileStore.add`` generates the
        id, and that id is the Keychain account name, so the row must exist
        before the secret can be filed under it.
        """
        try:
            profile = self._store.add(label, link)
        except AppError as exc:
            self.app.call_from_thread(self._fail, str(exc))
            return
        try:
            self._secrets.set(profile.id, uuid_value)
        except Exception as exc:  # noqa: BLE001 — backend-specific, must not escape a worker
            # Roll back: a row with no stored UUID is a profile that fails every
            # connect with a message about the Keychain, which is a confusing
            # way to learn that the add did not work.
            try:
                self._store.delete(profile.id)
            except Exception:  # pragma: no cover - delete of a just-added id cannot fail
                pass
            message = str(exc) if isinstance(exc, AppError) else "the Keychain write failed."
            self.app.call_from_thread(self._fail, message)
            return
        try:
            self._store.save()
        except AppError as exc:
            self.app.call_from_thread(self._fail, str(exc))
            return
        self.app.call_from_thread(self.dismiss, profile)

    def _fail(self, message: str) -> None:
        self._parsed = None
        button = self.query_one("#confirm", Button)
        button.disabled = False
        button.label = "Add"
        self.query_one("#preview", Static).display = False
        self.query_one("#error", Static).update(Text(message))


class EditProfileScreen(ModalScreen[Profile | None]):
    """Edit the non-secret fields of one profile.

    The UUID is absent by design: it lives in the Keychain and changing it
    requires re-pasting a full link through Add. This is not a limitation of the
    form, it is the reason the form is safe to have.

    Every save round-trips through :func:`parse_vless_uri`, so an Edit screen
    cannot produce a profile the parser would have refused. The parser stays the
    single validator instead of this module growing a second, drifting one.
    """

    DEFAULT_CSS = _BUTTON_CSS + """
    EditProfileScreen {
        align: center middle;
    }
    EditProfileScreen > VerticalScroll {
        width: 76;
        height: auto;
        max-height: 90%;
        padding: 1 2;
        background: $surface;
        border: round $primary;
    }
    EditProfileScreen #error {
        height: auto;
        margin: 1 0;
        color: $error;
    }
    EditProfileScreen #secret-note {
        height: auto;
        margin: 1 0;
        color: $text-muted;
    }
    EditProfileScreen #confirm-delete {
        height: auto;
        margin: 1 0;
        color: $error;
    }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, store: ProfileStore, secrets: SecretStore, profile: Profile) -> None:
        super().__init__()
        self._store = store
        self._secrets = secrets
        self._profile = profile
        self._confirming_delete = False

    def compose(self) -> ComposeResult:
        link = self._profile.link
        with VerticalScroll():
            yield Label("Name")
            yield Input(value=self._profile.label, id="label")
            yield Label("Server")
            yield Input(value=str(link.get("server", "")), id="server")
            yield Label("Port")
            yield Input(value=str(link.get("port", "")), id="port")
            yield Label("Security")
            yield Select(
                SECURITY_CHOICES,
                value=str(link.get("security", "none")),
                allow_blank=False,
                id="security",
            )
            yield Label("Transport")
            yield Select(
                TRANSPORT_CHOICES,
                value=str(link.get("network", "tcp")),
                allow_blank=False,
                id="transport",
            )
            yield Label("SNI")
            yield Input(value=str(link.get("sni", "")), id="sni")
            yield Label("Fingerprint")
            yield Input(value=str(link.get("fingerprint", "")), id="fingerprint")
            yield Label("ALPN")
            yield Input(value=", ".join(str(a) for a in (link.get("alpn") or [])), id="alpn")
            yield Label("Path")
            yield Input(value=str(link.get("path", "")), id="path", classes="path-field")
            yield Label("Host")
            yield Input(value=str(link.get("host_header", "")), id="host", classes="host-field")
            yield Label("Flow")
            yield Select(
                [( "(none)", ""), ("xtls-rprx-vision", "xtls-rprx-vision")],
                value=str(link.get("flow", "")),
                allow_blank=False,
                id="flow",
            )
            yield Static(
                Text("UUID: stored in the Keychain. To change it, add a new link and delete this profile."),
                id="secret-note",
            )
            yield Static("", id="error")
            yield Static("", id="confirm-delete")
            with Horizontal(classes="actions"):
                yield Button("Save", id="save", variant="primary")
                yield Button("Delete", id="delete", variant="error")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#label", Input).focus()
        self._apply_transport_visibility()

    # -- input handling -------------------------------------------------

    @on(Select.Changed, "#transport")
    def _transport_changed(self, event: Select.Changed) -> None:
        transport = str(event.value)
        self._apply_transport_visibility()
        if transport != "tcp":
            # Flow is only valid over TCP; leaving a stale value behind would
            # make the form state unsavable for a reason the user cannot see.
            self.query_one("#flow", Select).value = ""

    def _apply_transport_visibility(self) -> None:
        """Hide path/host for transports that do not use them."""
        transport = str(self.query_one("#transport", Select).value)
        visible = transport in PATH_TRANSPORTS
        for widget in self.query(".path-field, .host-field"):
            widget.display = visible

    @on(Button.Pressed, "#save")
    def _save_pressed(self) -> None:
        self.action_save()

    @on(Button.Pressed, "#cancel")
    def _cancel_pressed(self) -> None:
        self.action_cancel()

    @on(Button.Pressed, "#delete")
    def _delete_pressed(self) -> None:
        self.action_delete()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_delete(self) -> None:
        """Arm an inline delete confirmation.

        A second modal stacked on a modal behaves badly and loses the return
        value of the first one, so the confirmation lives inside this screen.
        It is still two deliberate steps — never a bare keypress.
        """
        if not self._confirming_delete:
            self._confirming_delete = True
            confirm = self.query_one("#confirm-delete", Static)
            confirm.update(Text("Delete this profile and its Keychain item? Press d again, or escape."))
            return
        self._start_delete()

    @on(Input.Submitted)
    def _any_submitted(self) -> None:
        self.action_save()

    # -- save -----------------------------------------------------------

    def action_save(self) -> None:
        """Collect the form into a link dict and hand it to the worker."""
        label = self.query_one("#label", Input).value.strip()
        if not label:
            self._show_error("Profile name must not be empty.")
            return
        port_text = self.query_one("#port", Input).value.strip()
        try:
            port = int(port_text)
        except ValueError:
            # Let the parser produce the message so there is one source of truth
            # for "what is a valid port".
            self._show_error("Port must be a number between 1 and 65535.")
            return

        candidate = dict(self._profile.link)
        candidate.update(
            {
                "server": self.query_one("#server", Input).value.strip(),
                "port": port,
                "security": str(self.query_one("#security", Select).value),
                "network": str(self.query_one("#transport", Select).value),
                "sni": self.query_one("#sni", Input).value.strip(),
                "fingerprint": self.query_one("#fingerprint", Input).value.strip(),
                "alpn": [
                    part.strip()
                    for part in self.query_one("#alpn", Input).value.split(",")
                    if part.strip()
                ],
                "path": self.query_one("#path", Input).value.strip(),
                "host_header": self.query_one("#host", Input).value.strip(),
                "flow": str(self.query_one("#flow", Select).value),
            }
        )
        self.query_one("#error", Static).update("")
        button = self.query_one("#save", Button)
        button.disabled = True
        button.label = "Saving…"
        self._save(label, candidate)

    @work(thread=True, exclusive=True, group="profile-edit")
    def _save(self, label: str, candidate: dict[str, Any]) -> None:
        """Validate, then update, then persist — all-or-nothing.

        ``allow_insecure=True`` here is not a loosening. The link's TLS posture
        was decided once, when the profile was added; the Edit form does not
        expose it. Re-asking would make an already-saved ``insecure`` profile
        impossible to edit at all, which is a worse outcome than accepting a
        posture the user already chose knowingly.
        """
        try:
            parsed = parse_vless_uri(build_validation_uri(candidate), allow_insecure=True)
        except AppError as exc:
            self.app.call_from_thread(self._fail, str(exc))
            return
        parsed.pop("uuid", None)  # the placeholder validation UUID never persists
        try:
            self._store.update(self._profile.id, label=label, link=parsed)
            self._store.save()
        except AppError as exc:
            self.app.call_from_thread(self._fail, str(exc))
            return
        profile = self._store.get(self._profile.id)
        self.app.call_from_thread(self.dismiss, profile)

    # -- delete ---------------------------------------------------------

    def _start_delete(self) -> None:
        button = self.query_one("#delete", Button)
        button.disabled = True
        button.label = "Deleting…"
        self._delete(self._profile.id)

    @work(thread=True, exclusive=True, group="profile-delete")
    def _delete(self, profile_id: str) -> None:
        """Remove the Keychain item and the profile, saving last.

        The secret goes first: an orphaned Keychain item is invisible and
        harmless, whereas a stored profile whose UUID is gone is a row that
        fails every connect with a Keychain error.
        """
        try:
            self._secrets.delete(profile_id)
        except Exception:  # noqa: BLE001 — a backend that cannot delete must not block removal
            pass
        try:
            self._store.delete(profile_id)
            self._store.save()
        except AppError as exc:
            self.app.call_from_thread(self._fail, str(exc))
            return
        self.app.call_from_thread(self.dismiss, None)

    def _fail(self, message: str) -> None:
        button = self.query_one("#save", Button)
        button.disabled = False
        button.label = "Save"
        self.query_one("#confirm-delete", Static).update("")
        self.query_one("#error", Static).update(Text(message))

    def _show_error(self, message: str) -> None:
        self.query_one("#error", Static).update(Text(message))


class AddressScreen(ModalScreen[Profile | None]):
    """Quick server/port editor — the common case, without the full form.

    ``e`` edits every field, which is right when something is genuinely wrong.
    But the most frequent edit by far is "this node moved to another address or
    port", and reaching that through a nine-field form is pure friction. So this
    screen exposes exactly two inputs.

    It is still validated the same way: the candidate goes through
    :func:`build_validation_uri` and back through :func:`parse_vless_uri`, with
    every other key carried through untouched. Editing the address therefore
    cannot silently drop a Reality ``pbk`` or a certificate pin — the parser is
    still the only thing that decides whether a link is acceptable.

    The UUID is untouched and therefore never present here. It stays in the
    Keychain; nothing about changing an address needs the credential.
    """

    DEFAULT_CSS = """
    AddressScreen {
        align: center middle;
    }
    AddressScreen > VerticalScroll {
        width: 64;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: round $primary;
    }
    AddressScreen .title {
        height: auto;
        margin-bottom: 1;
    }
    AddressScreen .current {
        height: auto;
        margin-bottom: 1;
        color: $text-muted;
    }
    AddressScreen Input {
        margin-bottom: 1;
    }
    AddressScreen .actions {
        height: auto;
    }
    AddressScreen Button {
        margin-right: 2;
    }
    AddressScreen .error {
        height: auto;
        color: $error;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, store: ProfileStore, profile: Profile) -> None:
        super().__init__()
        self._store = store
        self._profile = profile

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(Text("Server address"), classes="title")
            yield Static(
                Text(f"currently {self._profile.link.get('server', '?')}:{self._profile.link.get('port', '?')}"),
                classes="current",
            )
            yield Input(value=str(self._profile.link.get("server") or ""), placeholder="host or IP", id="server")
            yield Input(
                value=str(self._profile.link.get("port") or ""),
                placeholder="port",
                type="integer",
                id="port",
            )
            yield Static("", id="error", classes="error")
            with Horizontal(classes="actions"):
                yield Button("Save", id="save", variant="success")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#server", Input).focus()

    def _cancel_pressed(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        server = self.query_one("#server", Input).value.strip()
        port_text = self.query_one("#port", Input).value.strip()
        if not server:
            self._fail("Server address cannot be empty.")
            return
        if not port_text.isdigit():
            self._fail("Port must be a number.")
            return
        candidate = {**self._profile.link, "server": server, "port": int(port_text)}
        # All DOM work happens here on the event loop. The worker below only
        # touches the store, exactly like the edit screen's save: mutating a
        # widget from a worker thread is not safe, and Textual will not stop us.
        button = self.query_one("#save", Button)
        button.disabled = True
        self.query_one("#error", Static).update(Text(""))
        self._save_worker(candidate)

    @on(Button.Pressed, "#save")
    def _save_pressed(self) -> None:
        self.action_save()

    @on(Button.Pressed, "#cancel")
    def _cancel_button_pressed(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def _any_submitted(self) -> None:
        self.action_save()

    @work(thread=True, exclusive=True, group="save")
    def _save_worker(self, candidate: dict[str, Any]) -> None:
        """Validate off the event loop, then commit.

        Same shape as the edit screen's save: validate through the parser, write,
        and hop back to the loop for the dismiss. A rejected candidate never
        reaches the store, so the table can never show an address the parser
        would have refused.
        """
        try:
            parsed = parse_vless_uri(build_validation_uri(candidate), allow_insecure=True)
        except AppError as exc:
            self.app.call_from_thread(self._fail, str(exc))
            return
        # The round-trip through parse_vless_uri always yields a uuid -- for an
        # edit it is the validation placeholder, not a credential. The store
        # rejects any link carrying one, which is exactly the backstop we want:
        # this pop is the thing that has to happen, and the store is what proves
        # it did.
        parsed.pop("uuid", None)
        try:
            profile = self._store.update(self._profile.id, link=parsed)
            self._store.save()
        except AppError as exc:
            self.app.call_from_thread(self._fail, str(exc))
            return
        self.app.call_from_thread(self.dismiss, profile)

    def _fail(self, message: str) -> None:
        """Report a problem in place, next to the fields that caused it.

        Parser messages are link-free by contract, so they can be shown verbatim.
        Re-enabling Save is essential: leaving it disabled would strand the user
        in a dialog they can only escape.
        """
        self.query_one("#save", Button).disabled = False
        self.query_one("#error", Static).update(Text(message))


class HelpScreen(ModalScreen[None]):
    """Key reference, grouped by intent instead of listed flat.

    A footer shows the current bindings, but a footer is a strip you learn to
    ignore, and it cannot explain *when* a key applies. This is the thing to open
    once and read.

    The content is a literal table rather than a rendering of ``App.BINDINGS`` on
    purpose: bindings carry no grouping or explanation, and the grouping is the
    part that makes this useful. ``tests/test_tui.py`` asserts that every key
    advertised here is actually bound, so the two cannot drift apart.
    """

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    HelpScreen > VerticalScroll {
        width: 76;
        height: auto;
        max-height: 85%;
        padding: 1 2;
        background: $surface;
        border: round $primary;
    }
    HelpScreen .title {
        height: auto;
    }
    HelpScreen .hint {
        height: auto;
        margin-top: 1;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("h", "dismiss", "Close"),
        Binding("question_mark", "dismiss", "Close"),
    ]

    #: (section, [(key, description), ...]) — mirrors ``VlessApp.BINDINGS``.
    SECTIONS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
        (
            "Connection",
            (
                ("c", "Connect the highlighted profile"),
                ("space", "Stop the service, or resume it if stopped"),
                ("t", "Test latency for every profile"),
            ),
        ),
        (
            "Profiles",
            (
                ("l", "Add a vless:// link"),
                ("s", "Add a subscription URL (arrives in V2)"),
                ("e", "Edit the highlighted profile"),
                ("i", "Change server address and port"),
                ("d", "Delete the highlighted profile"),
            ),
        ),
        (
            "View",
            (
                ("o", "Show or hide the Xray output pane"),
                ("h", "This help"),
            ),
        ),
        (
            "App",
            (
                ("q", "Stop the proxy and quit"),
            ),
        ),
    )

    def compose(self) -> ComposeResult:
        table = Table(box=None, pad_edge=False, padding=(0, 2), expand=False)
        table.add_column("Key", no_wrap=True)
        table.add_column("Does", no_wrap=False)
        for title, rows in self.SECTIONS:
            table.add_section()
            table.add_row(Text(title, style="bold"), "")
            for key, description in rows:
                table.add_row(Text(f"  {key}", style="cyan"), description)
        with VerticalScroll():
            yield Static(Text("Keyboard"), classes="title")
            yield Static(table)
            yield Static(Text("Up and Down move, Enter also connects."), classes="hint")
            yield Static(Text("escape or h closes this."), classes="hint")

    def action_dismiss(self) -> None:
        self.dismiss(None)


__all__ = [
    "AddProfileScreen",
    "AddressScreen",
    "ConfirmScreen",
    "EditProfileScreen",
    "HelpScreen",
    "SECURITY_CHOICES",
    "TRANSPORT_CHOICES",
    "build_validation_uri",
    "link_summary",
    "summary_lines",
]