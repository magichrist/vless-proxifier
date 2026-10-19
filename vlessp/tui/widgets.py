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
* The only strings a cell ever carries are ones the user typed: the label, and
  a subscription's NAME (``subscription:<name>``). A profile's id is never
  rendered — not even as a fallback for an empty label — and neither is a link,
  so there is no second, subtler version of the leak above.

``rich`` is imported rather than ``textual.widgets.Text`` because ``rich`` is
Textual's own rendering substrate and is guaranteed present wherever Textual
imports; nothing new is added to the dependency set.
"""
from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import Any

from rich.text import Text
from textual.coordinate import Coordinate
from textual.message import Message
from textual.widgets import DataTable, Static

from vlessp.profiles import SUB_SOURCE_PREFIX, Profile

# Width of the block-character bar in the LAT column. Four keeps the existing
# seven-column table inside 80 characters, which is the width this thing has to
# survive; the value sits next to the bar so nothing is bar-only.
LAT_BAR_WIDTH = 4

# Fixed upper bound for the latency scale. See :func:`latency_bar` — the scale
# must not be relative, or the same bar would mean different things per row.
LATENCY_SCALE_MAX = 2000

# How many samples the detail sparkline plots. Matches the history bound so a
# long session shows everything it kept rather than silently truncating.
SPARK_WIDTH = 20

# Em-dash placeholder. Design calls for it in LAT ("not probed yet") and STATE
# ("not the live profile"), so an unprobed row is visually distinct from a probe
# that actually returned nothing.
DASH = "—"

# Marker drawn in front of the active profile's label.
ACTIVE_MARK = "▌"

# STATE cell wording. ``—`` means "not connected"; the other two must never be
# confused with it, because "idle" and "your provider dropped this" call for
# opposite reactions (do nothing vs. check the subscription).
LIVE_MARK = "live"
UNAVAILABLE_MARK = "gone"

# Source badge appended to the LABEL cell rather than a column of its own: an
# eighth column squeezes LABEL and SERVER on an 80-column terminal, and both
# carry information the user actually needs.
SOURCE_OPEN = "[sub:"
SOURCE_CLOSE = "]"
# The subscription name is user-supplied and can be any length; the badge is a
# marker, not a column, so it is capped and the rest is elided. Eight characters
# covers every name a person would plausibly type.
SOURCE_NAME_MAX = 8

# Style applied to every cell of a profile the provider no longer lists. It is
# de-emphasis only: the row stays selectable and connectable, because an upstream
# omission is usually a transient outage (S5) and taking a working node away from
# the user would be a worse bug than the one being flagged.
UNAVAILABLE_STYLE = "dim"

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
    /* Hug the rows instead of eating the whole screen. With a handful of
       profiles a 1fr table drew twenty rows of empty background and pushed the
       detail panel and key hints to the very bottom, far from the data.

       ``auto`` alone would overflow a long list and shove the panels below it
       off-screen, so the ceiling is applied in *rows* at runtime
       (``VlessApp._fit_table_height``): ``max-height`` cannot express "the space
       left after the widgets below me", and both ``1fr`` and a percentage cap
       get that wrong. The app knows the terminal height and the chrome heights,
       so it computes the number the layout engine cannot. */
    height: auto;
}
"""

#: Rows the detail panel occupies: one border rule plus three content lines.
#: Fixed so the table above it has a predictable height to reserve, and so the
#: panel does not jump between a profile with a trend and one without. Kept here
#: rather than inline in the CSS so ``VlessApp._fit_table_height`` subtracts the
#: same number the stylesheet uses.
DETAIL_HEIGHT = 4


def format_latency(latency_ms: int | None) -> str:
    """Render a cached latency, distinguishing "never probed" from "unreachable".

    ``None`` is overloaded in :class:`Profile` — it means both "not probed yet"
    and "probe timed out". The design only calls for one placeholder glyph, so
    both render as ``—``; the distinction is deliberately not invented here.
    """
    return DASH if latency_ms is None else f"{latency_ms}ms"


#: Sub-cell block characters, lightest to full. Index 0 is blank and index 8
#: is a full block, so ``PARTIAL_BLOCKS[n]`` fills exactly ``n`` eighths of a
#: cell. This is what gives the bar resolution: four cells of whole blocks give
#: only five distinct values across the whole latency range, which is far too
#: coarse to compare nodes -- 42 ms and 85 ms would draw the same bar. Four
#: cells of eighth-blocks give thirty-two.
PARTIAL_BLOCKS = " ▏▎▍▌▋▊▉█"


def latency_bar(latency_ms: int | None, *, width: int = LAT_BAR_WIDTH) -> Text:
    """Render latency as a bar plus its value: ``▊██▌ 142ms``.

    Why a bar and not just the number. A column of ``42ms``/``118ms``/``890ms``
    makes the reader do the comparison; a bar makes it pre-attentive. The number
    stays beside it so the bar is never the only encoding — which also keeps
    this usable where colour is unavailable.

    The scale is **fixed, not relative**. A relative scale would rescale itself
    to the best and worst node in the list, so the same bar would mean "fast"
    when one node is in view and "terrible" when fifty are. Comparing nodes is
    the entire reason to put a bar in a column, so the scale has to mean the
    same thing on every row.

    It is logarithmic because latency is *perceived* logarithmically: 40 ms to
    80 ms matters far more than 540 ms to 580 ms, and a linear bar would spend
    three-quarters of its travel on that uninteresting end.
    """
    if latency_ms is None:
        return Text(DASH, style="dim")
    level, style = _latency_level(latency_ms)
    eighths = max(1, min(width * 8, round(level * width * 8)))
    full, remainder = divmod(eighths, 8)

    bar = Text("█" * full, style=style)
    if remainder and full < width:
        bar.append(PARTIAL_BLOCKS[remainder], style=style)
        bar.append(" " * (width - full - 1))
    elif full < width:
        bar.append(" " * (width - full))
    bar.append(f" {latency_ms}ms")
    return bar


def _latency_level(latency_ms: int) -> tuple[float, str]:
    """Map a latency onto 0.0-1.0 and a colour, using the fixed thresholds above.

    The curve is logarithmic rather than linear because latency is perceived
    logarithmically — the difference between 40 ms and 80 ms matters far more
    than the difference between 540 ms and 580 ms, and a linear bar would spend
    three-quarters of its travel on that uninteresting end.
    """
    upper = LATENCY_SCALE_MAX
    clamped = max(1, min(latency_ms, upper))
    level = math.log10(clamped + 1) / math.log10(upper + 1)
    if latency_ms <= 50:
        return level, "bold green"
    if latency_ms <= 150:
        return level, "green"
    if latency_ms <= 300:
        return level, "yellow"
    if latency_ms <= 600:
        return level, "dark_orange3"
    return level, "bold red"


def format_source(source: str) -> str:
    """The ``[sub:<name>]`` badge for a profile's source; ``""`` when hand-added.

    ``source`` is ``SUB_SOURCE_PREFIX + <name>``, but nothing here requires that
    to be true: a hand-edited store, or one written by a version that disagreed
    about the shape, can hold any string. ``partition`` cannot raise, and any
    shape it cannot take apart degrades to showing ``source`` itself — a badge
    that reads oddly is recoverable, a table that raises is not.

    The name is the only part rendered, and it is a name the user typed when
    saving the subscription. The URL behind it is a credential and lives in the
    Keychain, so it cannot reach this string by construction.
    """
    if not source:
        return ""
    _prefix, _separator, name = source.partition(SUB_SOURCE_PREFIX)
    if not name:
        name = source
    if len(name) > SOURCE_NAME_MAX:
        name = name[: SOURCE_NAME_MAX - 1] + "…"
    return f"{SOURCE_OPEN}{name}{SOURCE_CLOSE}"


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

    Posts :class:`Highlighted` whenever the cursor moves. ``DataTable`` has a
    ``RowHighlighted`` message, but it fires only when ``cursor_type`` is
    ``"row"`` — and this table uses the default ``"cell"``, so subscribing to it
    would silently never fire. Watching ``cursor_coordinate`` covers every cursor
    type instead of depending on one.
    """

    class Highlighted(Message):
        """The cursor moved to another profile."""

        def __init__(self, table: ProfileTable) -> None:
            super().__init__()
            self.table = table

    def watch_cursor_coordinate(
        self, old: Coordinate, new: Coordinate
    ) -> None:
        self.post_message(self.Highlighted(self))
        super().watch_cursor_coordinate(old, new)
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

        Every profile passed in becomes a row, ``unavailable`` ones included.
        Availability is drawn, never enforced: flagging a node a provider
        dropped is reversible, and hiding it would take a working proxy away
        from a user because someone else's server had a bad day.
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
            style = UNAVAILABLE_STYLE if profile.unavailable else ""
            self.add_row(
                self._label_cell(profile),
                Text(str(link.get("server", "")), style=style),
                Text(str(link.get("port", "")), style=style),
                Text(str(link.get("security", "")), style=style),
                Text(str(link.get("network", "")), style=style),
                self._latency_cell(profile, style),
                self._state_text(profile, style),
                key=profile.id,
            )
        self._restore_cursor(previous_row)

    def _latency_cell(self, profile: Profile, style: str = "") -> Text:
        """LAT cell: a block bar plus the value, dimmed when the row is unavailable.

        The bar is built first and the dim style applied over the whole cell, so
        an unavailable node reads as de-emphasised without losing its latency —
        the number is still useful, it just should not draw the eye.
        """
        bar = latency_bar(profile.last_latency_ms)
        if style:
            bar.stylize(style)
        return bar

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
        """Label cell: the active marker, the label, then the source badge.

        The badge lives here rather than in its own column because an eighth
        column squeezes the two that matter most on a narrow terminal. An empty
        label falls back to :data:`DASH` rather than to the profile id — the
        store rejects blank labels, so this is only reachable from a hand-edited
        file, and an id is a handle, not something to put on screen.
        """
        label = profile.label or DASH
        if profile.id == self._active_id:
            # A space after the bar: ``▌home`` reads as one token, ``▌ home``
            # reads as "this row is marked, and the label is home".
            label = f"{ACTIVE_MARK} {label}"
        cell = Text(label, style=UNAVAILABLE_STYLE if profile.unavailable else "")
        badge = format_source(profile.source)
        if badge:
            # Appended onto the same Text, so the badge is literal text exactly
            # as the label is — a subscription named "[red]" stays readable.
            cell.append(f" {badge}")
        return cell

    def _state_text(self, profile: Profile, style: str = "") -> Text:
        """STATE cell as a styled Text: ``live`` / ``gone`` / ``—``.

        ``live`` wins over ``gone``: a node carrying traffic right now is
        carrying it, and the dim styling still tells the user it is no longer
        offered upstream. Every other row reads ``—``, which is "idle".

        Only ``live`` gets its own colour. A ``gone`` row stays uniformly dimmed
        like the rest of its cells: the *word* is what distinguishes it, so it
        survives a monochrome terminal, and a lone yellow cell under a dim row
        read as a second, competing signal.
        """
        if profile.id == self._current_id:
            text = Text(LIVE_MARK, style="bold green")
            if style:
                text.stylize(style)
            return text
        mark = UNAVAILABLE_MARK if profile.unavailable else DASH
        return Text(mark, style=style)

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
        # Same wording and casing as the header's state word, so the two surfaces
        # do not describe the same service with different vocabularies.
        if running:
            text.append("   ")
            text.append("RUNNING", style="bold green")
        else:
            text.append("   STOPPED")
        self.update(text)
        self.set_class(not running, "stopped")


class KeyHints(Static):
    """Every key, on one line, never truncated.

    This replaces Textual's ``Footer``, which was the wrong tool here. The
    footer renders one ``key description`` pair per binding on a single line
    with no wrapping: twelve bindings came to **117 columns**, so on an
    80-column terminal the tail was silently cut to an ellipsis. That hid
    ``q``, which is the last key anyone wants hidden, and made the footer worse
    than useless: it looked complete while lying about what was available.

    So this is a deliberate replacement rather than an addition, and it is
    strictly **one line**. Stacking the hints over three rows worked but spent
    scarce vertical space on chrome — the table is what the user came for.

    The line adapts to the terminal rather than picking one compromise layout.
    Twelve keys with readable labels need 138 columns, which most terminals do
    not have; a fixed choice is either too cramped to read or too wide to fit.
    So three tiers are defined, longest first, and the widest one that fits is
    used. A test measures every tier against the width that selects it, so a
    tier can never claim a space it does not have.
    """

    DEFAULT_CSS = """
    KeyHints {
        height: 1;
        padding: 0 1;
        color: $text-muted;
    }
    """

    #: Terminal width below which each tier is used. The first tier whose
    #: requirement is <= the available width wins, so these are minimums.
    #: Measured from the rendered strings, not estimated — see the test.
    WIDE_MIN = 138
    MEDIUM_MIN = 128
    NARROW_MIN = 80

    #: (keys, labels, separator) per tier. Narrow uses colon separators and
    #: abbreviated keys ("sp", "^T") because at 80 columns those three
    #: characters are the difference between fitting and hiding `q`.
    TIERS: tuple[tuple[list[str], list[str], str], ...] = (
        (
            ["c", "space", "t", "l", "s", "e", "i", "d", "o", "alt+t", "h", "q"],
            ["connect", "stop/resume", "test", "add link", "add sub", "edit",
             "ip/port", "delete", "output", "theme", "help", "quit"],
            " · ",
        ),
        (
            ["c", "space", "t", "l", "s", "e", "i", "d", "o", "alt+t", "h", "q"],
            ["conn", "stop", "test", "add link", "add sub", "edit",
             "ip/port", "delete", "output", "theme", "help", "quit"],
            " · ",
        ),
        (
            ["c", "sp", "t", "l", "s", "e", "i", "d", "o", "^T", "h", "q"],
            ["conn", "stop", "test", "add", "sub", "edit",
             "ip", "del", "out", "theme", "help", "quit"],
            " ",
        ),
        # Floor: keys only, no labels. For a terminal narrower than the narrow
        # tier. Dropping the *labels* is the right thing to lose — a key with no
        # description is still pressable and still honest about what exists,
        # whereas a truncated line silently hides keys the user cannot find.
        (
            ["c", "space", "t", "l", "s", "e", "i", "d", "o", "alt+t", "h", "q"],
            [""] * 12,
            " ",
        ),
    )

    #: Minimum width each tier needs, matching ``TIERS`` order.
    MINIMUMS = (138, 128, 80, 33)

    #: Tiers that join key and label with a colon rather than a space.
    COLON_TIERS = frozenset({2})

    def tier_for(self, width: int) -> int:
        """Index of the widest tier that fits in ``width`` columns."""
        for index, minimum in enumerate(self.MINIMUMS):
            if width >= minimum:
                return index
        return len(self.TIERS) - 1  # narrower than anything planned: keys only

    def render_tier(self, tier: int) -> Text:
        keys, labels, separator = self.TIERS[tier]
        joiner = ":" if tier in self.COLON_TIERS else " "
        out = Text()
        for index, (key, label) in enumerate(zip(keys, labels, strict=True)):
            if index:
                out.append(separator, style="dim")
            out.append(key, style="bold reverse")
            if label:
                out.append(joiner + label, style="dim")
        return out

    def compose_hint(self, width: int = WIDE_MIN) -> Text:
        """Render one line sized for ``width`` columns.

        Callers pass the real width; the default is the widest tier so that a
        caller who forgets still gets the readable layout rather than a
        truncated one.
        """
        return self.render_tier(self.tier_for(width))

    def on_mount(self) -> None:
        self.update(self.compose_hint(self.size.width or self.WIDE_MIN))
        self.watch(self, "size", self._on_resize, init=False)

    def _on_resize(self) -> None:
        """Re-tier when the window changes width.

        A terminal resized smaller is exactly when truncation would bite, so the
        hints must not be pinned to whatever width they were built at.
        """
        self.update(self.compose_hint(self.size.width or self.WIDE_MIN))


class ProfileDetail(Static):
    """Sparkline and stats for one profile: the answer to "is it getting worse?".

    A single cached latency answers "how slow is it right now" and nothing else.
    Two runs of ``t`` five minutes apart, side by side, answer a different
    question — whether the node is degrading, which is the one that decides
    whether you go looking for a new subscription. That needs a series, so this
    renders ``Profile.latency_history``.

    The history is session-scoped (see :class:`Profile`), so the panel says so
    rather than implying a trend record longer than it has.

    Unreachable probes are drawn as gaps, not as zero. A zero would drag the
    scale to the floor and make every real latency look like a spike, and it
    would also be a lie: we did not measure zero, we measured nothing.
    """

    DEFAULT_CSS = """
    ProfileDetail {
        /* A fixed band: one border rule plus three content lines (identity /
           trend / stats). Fixed rather than ``auto`` for two reasons. It gives
           the table above a height to reserve against, so a long list can never
           push the panel off-screen; and the panel does not change size as the
           cursor moves between a profile with a trend and one without, so the
           table never jumps under the reader's eye. Kept in step with
           :data:`DETAIL_HEIGHT`, which the app subtracts when sizing the table. */
        height: 4;
        padding: 0 1;
        border-top: solid $panel;
    }
    ProfileDetail .spark {
        height: 1;
    }
    ProfileDetail .empty {
        color: $text-muted;
    }
    """

    #: Braille heights, lightest first. Braille gives 8 vertical steps per cell
    #: where block characters give 8 across the full cell, so a trend over 20
    #: probes stays readable in one line without stealing table rows.
    SPARK_CHARS = "▁▂▃▄▅▆▇█"

    def show_profile(self, profile: Profile | None) -> None:
        """Render ``profile``, or a hint when nothing is selected.

        The empty branch builds a plain ``Text`` and marks the *widget* with the
        ``empty`` class. It must not pass ``classes=`` to ``Text`` — that keyword
        belongs to widget construction, not Rich text, and raising it here (inside
        a refresh path that swallows exceptions) silently blanked the panel
        whenever no row was selected.
        """
        if profile is None:
            self.set_class(True, "empty")
            self.update(Text("No profile selected — press l to add a link."))
            return
        self.set_class(False, "empty")
        # Named _build, not _render: Static already has an internal _render with
        # a different signature, and shadowing it breaks the widget.
        self.update(self._build(profile))

    def _build(self, profile: Profile) -> Text:
        link = profile.link
        out = Text()
        out.append(f"{profile.label}", style="bold")
        host = f"{link.get('server', '?')}:{link.get('port', '?')}"
        out.append(f"  {host}", style="dim")
        if profile.source:
            out.append(f"  {format_source(profile.source)}", style="dim")
        if profile.unavailable:
            out.append("  gone", style="yellow")

        history = profile.latency_history
        out.append("\n")
        if len(history) < 2:
            # One sample has no shape. Saying so is more honest than drawing a
            # flat line that looks like a stable measurement.
            out.append(
                "No trend yet — press t twice to compare runs.",
                style="dim",
            )
            return out

        spark, gaps = _sparkline(history, width=SPARK_WIDTH)
        out.append(spark)
        out.append(f"  last {len(history)} runs this session", style="dim")
        if gaps:
            out.append(f" ({gaps} unreachable)", style="yellow")

        measured = [ms for ms in history if ms is not None]
        if measured:
            out.append(
                f"\nmin {min(measured)}ms   avg {round(sum(measured) / len(measured))}ms"
                f"   max {max(measured)}ms",
                style="dim",
            )
            # The bar height is otherwise unanchored: a reader cannot tell whether
            # a tall glyph means 90 ms or 900 ms without the scale it is drawn to.
            # It is logarithmic (see ``latency_bar``), and saying so matters —
            # "0–2000ms" alone would read as a linear axis and make the bars lie.
            out.append(f"   ·   log scale 0–{LATENCY_SCALE_MAX}ms", style="dim")
        return out


def _sparkline(history: Sequence[int | None], *, width: int) -> tuple[Text, int]:
    """Draw ``history`` as a bar chart. Returns the cell and the gap count.

    Gaps — an unreachable probe — are left blank rather than plotted at zero, and
    the caller reports how many there were so the blank is never mistaken for
    missing data.

    The scale is again fixed (:data:`LATENCY_SCALE_MAX`), so two profiles'
    trends are visually comparable rather than each flattering itself.
    """
    samples = list(history[-width:])
    measured = [ms for ms in samples if ms is not None]
    out = Text()
    if not measured:
        return Text("·" * len(samples), style="dim"), 0

    ceiling = max(LATENCY_SCALE_MAX, max(measured))
    gaps = 0
    for ms in samples:
        if ms is None:
            out.append(" ")
            gaps += 1
            continue
        ratio = min(1.0, max(0.0, math.log10(ms + 1) / math.log10(ceiling + 1)))
        index = min(len(ProfileDetail.SPARK_CHARS) - 1, int(ratio * len(ProfileDetail.SPARK_CHARS)))
        _, style = _latency_level(ms)
        out.append(ProfileDetail.SPARK_CHARS[index], style=style)
    return out, gaps


__all__ = [
    "ACTIVE_MARK",
    "DASH",
    "DETAIL_HEIGHT",
    "LATENCY_SCALE_MAX",
    "LAT_BAR_WIDTH",
    "LIVE_MARK",
    "SOURCE_NAME_MAX",
    "UNAVAILABLE_MARK",
    "UNAVAILABLE_STYLE",
    "KeyHints",
    "ProfileDetail",
    "ProfileTable",
    "StatusBar",
    "format_latency",
    "format_source",
    "latency_bar",
    "order_profiles",
]