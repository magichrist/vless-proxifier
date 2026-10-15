"""Display widgets for the VLESS TUI.

Both widgets in this module are *pure display*. Neither is ever handed a
credential, and that is not an accident of the current call sites — it is
structural:

* The profile link dicts these widgets read come straight out of
  :class:`~vlessp.profiles.ProfileStore`, which rejects any link dict carrying
  a ``uuid`` key. A credential cannot reach a cell even if a future caller
  forgets to pop it.
* Every cell is wrapped in :class:`rich.text.Text` rather than passed as a raw
  string. Textual renders bare ``str`` cells as markup, so a profile label
  containing ``[red]`` would otherwise be interpreted as a style tag. Wrapping
  makes the label literal — a display bug, not a crash, but still a bug worth
  designing out.

``rich`` is imported rather than ``textual.widgets.Text`` because ``rich`` is
Textual's own rendering substrate and is guaranteed present wherever Textual
imports; nothing new is added to the dependency set.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from rich.text import Text
from textual.widgets import DataTable, Static

from vlessp.profiles import Profile

# Em-dash placeholder. Design calls for it in LAT ("not probed yet") and STATE
# ("not the live profile"), so an unprobed row is visually distinct from a probe
# that actually returned nothing.
DASH = "—"

# Marker drawn in front of the active profile's label.
ACTIVE_MARK = "▌"

# Column keys are stable strings rather than the display labels so an update can
# address a column without re-deriving its caption.
COLUMN_KEYS: tuple[tuple[str, str], ...] = (
    ("LABEL", "label"),
    ("SERVER", "server"),
    ("PORT", "port"),
    ("SEC", "sec"),
    ("TRANSPORT", "transport"),
    ("LAT", "lat"),
    ("STATE", "state"),
)

# Column positions, used by tests and by the app when it needs to read a cell back.
COL_LABEL = 0
COL_SERVER = 1
COL_PORT = 2
COL_SEC = 3
COL_TRANSPORT = 4
COL_LAT = 5
COL_STATE = 6

CSS = """
ProfileTable {
    height: 1fr;
}
"""


def format_latency(latency_ms: int | None) -> str:
    """Render a cached latency, distinguishing "never probed" from "unreachable".

    ``None`` is overloaded in :class:`Profile` — it means both "not probed yet"
    and "probe timed out". The design only calls for one placeholder glyph, so
    both render as ``—``; the distinction is deliberately not invented here.
    """
    return DASH if latency_ms is None else f"{latency_ms}ms"


def order_profiles(profiles: Iterable[Profile], *, by_latency: bool) -> list[Profile]:
    """Alphabetical by label normally; by ascending latency after a test run.

    Unreachable profiles (``last_latency_ms is None``) sort last either way,
    because a column of unknowns at the top of the table reads as "these are the
    good ones".
    """
    items = list(profiles)
    if by_latency:
        return sorted(
            items,
            key=lambda p: (p.last_latency_ms is None, p.last_latency_ms or 0, p.label.lower()),
        )
    return sorted(items, key=lambda p: p.label.lower())


class ProfileTable(DataTable):
    """The profile list.

    Rows are keyed by profile id, so :meth:`selected_id` can hand the app a
    stable handle without the app ever needing to parse a cell back out of the
    rendered text.
    """

    DEFAULT_CSS = CSS

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._columns_ready = False
        self._sort_by_latency = False
        self._active_id: str | None = None
        self._current_id: str | None = None

    @property
    def sort_by_latency(self) -> bool:
        """Whether rows are currently ordered by latency instead of by label."""
        return self._sort_by_latency

    def on_mount(self) -> None:
        """Add columns once; ``reload_profiles`` then clears rows but keeps them."""
        if not self._columns_ready:
            for caption, key in COLUMN_KEYS:
                self.add_column(Text(caption), key=key)
            self._columns_ready = True

    def reload_profiles(
        self,
        profiles: Sequence[Profile],
        *,
        active_id: str | None = None,
        current_id: str | None = None,
        sort_by_latency: bool | None = None,
    ) -> None:
        """Rebuild every row from ``profiles``.

        A full rebuild (rather than per-cell updates) is what makes the
        latency sort possible at all, and a profile list is small enough that
        the cost is irrelevant. The cursor's *index* is preserved across the
        rebuild so a latency sweep arriving mid-navigation does not throw the
        user back to the top of the list.
        """
        if not self._columns_ready:  # tolerate reloads before mount in tests
            for caption, key in COLUMN_KEYS:
                self.add_column(Text(caption), key=key)
            self._columns_ready = True
        if sort_by_latency is not None:
            self._sort_by_latency = sort_by_latency
        self._active_id = active_id
        self._current_id = current_id

        previous_row = self.cursor_row if self.row_count else 0
        self.clear(columns=False)
        for profile in order_profiles(profiles, by_latency=self._sort_by_latency):
            link = profile.link
            self.add_row(
                self._label_cell(profile),
                Text(str(link.get("server", ""))),
                Text(str(link.get("port", ""))),
                Text(str(link.get("security", ""))),
                Text(str(link.get("network", ""))),
                Text(format_latency(profile.last_latency_ms)),
                Text("live" if profile.id == current_id else DASH),
                key=profile.id,
            )
        self._restore_cursor(previous_row)

    def _restore_cursor(self, previous_row: int) -> None:
        """Re-place the cursor after a rebuild, clamped into the new row range."""
        if self.row_count == 0:
            return
        target = min(max(previous_row, 0), self.row_count - 1)
        try:
            self.move_cursor(row=target)
        except Exception:
            # A rebuild racing an unmount is not worth failing a UI refresh over.
            pass

    def _label_cell(self, profile: Profile) -> Text:
        """Label cell, prefixed with the active marker when this row is active."""
        label = profile.label or profile.id[:8]
        return Text(f"{ACTIVE_MARK}{label}" if profile.id == self._active_id else label)

    def selected_id(self) -> str | None:
        """Profile id under the cursor, or ``None`` on an empty table."""
        if self.row_count == 0:
            return None
        index = self.cursor_row
        rows = self.ordered_rows
        if not (0 <= index < len(rows)):
            return None
        key = rows[index].key
        return None if key is None else str(key.value)

    def row_values(self, profile_id: str) -> list[str] | None:
        """Plain-text cells for one profile row; used by tests and assertions."""
        for row in self.ordered_rows:
            if row.key is not None and str(row.key.value) == profile_id:
                # get_cell is the public accessor for a single cell and returns
                # the Text we stored, so str() recovers exactly what is shown.
                return [str(self.get_cell(row.key, key)) for _caption, key in COLUMN_KEYS]
        return None


class StatusBar(Static):
    """Listener addresses and Xray version, red while nothing is listening.

    Red-when-stopped is the point of this widget: a stopped proxy that still
    looks normal is the failure users actually report.
    """

    DEFAULT_CSS = """
    StatusBar {
        dock: bottom;
        height: 1;
        background: $panel;
        color: $text;
    }
    StatusBar.stopped {
        color: $error;
    }
    """

    def update_status(
        self,
        *,
        socks_addr: str | None,
        http_addr: str | None,
        xray_version: str | None = None,
        running: bool = False,
    ) -> None:
        """Render the status line.

        Markup is disabled for the lifetime of the widget and values are wrapped
        in ``Text``, so an address or version string can never be interpreted as
        Textual markup.
        """
        parts: list[str] = []
        if socks_addr:
            parts.append(f"SOCKS {socks_addr}")
        if http_addr:
            parts.append(f"HTTP {http_addr}")
        if xray_version:
            parts.append(f"xray {xray_version}")
        text = Text("   ".join(parts) if parts else "no proxy configured")
        text.append("   " + ("running" if running else "stopped"))
        self.update(text)
        self.set_class(not running, "stopped")


__all__ = [
    "ACTIVE_MARK",
    "DASH",
    "ProfileTable",
    "StatusBar",
    "format_latency",
    "order_profiles",
]