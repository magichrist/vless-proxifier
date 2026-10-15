"""Orchestration between saved profiles and the supervised Xray process.

Why this layer exists: the TUI must never touch ``XrayProcess`` directly (see
"the switching seam" in ``docs/V1/01-architecture.md``). This class is the only
place that knows the connect sequence — resolve the ref, re-attach the UUID
from the secret store, hand the complete link to ``XrayProcess.apply``, then
persist which profile is active — so a future hot-swap implementation changes
nothing above this line.

Ownership rule: this class owns persisting the *active profile id*. It does
NOT own writing profiles themselves; callers use ``ProfileStore.add`` /
``update`` / ``delete`` directly, and this class never invents profiles.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .errors import AppError
from .latency import probe_server
from .profiles import Profile, ProfileStore, resolve_link
from .secrets import SecretStore
from .xray import XrayProcess

# Upper bound on simultaneous probe sockets. One thread per profile is the
# natural shape, but an uncapped pool against a 200-profile store would open
# 200 sockets at once — trivially rate-limited by the network and rude to it.
_PROBE_POOL_SIZE = 8

__all__ = ["ProxyService"]


class ProxyService:
    """Connects saved profiles through one supervised Xray process.

    ``connect`` is serialized with a lock so a double-Enter (two Textual
    workers racing) cannot interleave two spawns. ``XrayProcess`` has its own
    internal lock, but the lock here covers the wider critical section —
    resolve, apply, *then* persist — so the recorded active profile can never
    disagree with what was actually applied.
    """

    def __init__(
        self,
        store: ProfileStore,
        secrets: SecretStore,
        xray_path: Path,
        *,
        socks_addr: str = "127.0.0.1:10808",
        http_addr: str | None = "127.0.0.1:10809",
    ) -> None:
        self._store = store
        self._secrets = secrets
        self._xray = XrayProcess(xray_path, socks_addr=socks_addr, http_addr=http_addr)
        self._lock = threading.Lock()
        # Id of the profile currently serving, None when stopped. Kept
        # separately from store.active_id on purpose: active_id is "reconnect
        # this on next launch", _current_id is "this is live right now".
        self._current_id: str | None = None

    @property
    def running(self) -> bool:
        """True while the supervised process is alive and serving."""
        return self._xray.running

    @property
    def current(self) -> Profile | None:
        """The profile currently serving, or None when disconnected."""
        if self._current_id is None:
            return None
        try:
            return self._store.get(self._current_id)
        except AppError:
            # The serving profile was deleted out from under us; report
            # nothing rather than raise out of a status-bar read.
            return None

    def connect(self, ref: str) -> Profile:
        """Switch the proxy to the profile named by ``ref`` (id or label).

        Ordered so that a failure leaves nothing behind: the ref is resolved and
        the UUID re-attached before ``XrayProcess.apply`` is touched, and
        ``XrayProcess`` itself validates the new config before stopping the old
        process, so a rejected profile leaves the old tunnel still serving AND
        still recorded as active.

        The one genuinely awkward window is between ``apply`` succeeding and the
        new active id reaching disk. At that point the old process is already
        gone, so the old ``active_id`` on disk names a node we are no longer on —
        and next launch would reconnect *that* node without the user choosing it.
        Silently routing traffic somewhere they did not pick is worse than a
        dropped connection, so this path tears the new tunnel down and re-raises.
        Doing the teardown here rather than in each caller is the point: it makes
        "no live child after a failed connect" an invariant of the class instead
        of a rule every caller has to remember.
        """
        with self._lock:
            profile = self._store.resolve(ref)
            link: dict[str, Any] = resolve_link(profile, self._secrets)
            self._xray.apply(link)
            # _current_id tracks what is serving, and is set before the persist
            # so the rollback below knows there is something to roll back.
            self._current_id = profile.id
            try:
                self._store.set_active(profile.id)
                self._store.save()
            except (OSError, AppError):
                self._current_id = None
                try:
                    self._xray.stop()
                except Exception:  # pragma: no cover - never mask the real error
                    pass
                raise
            return profile

    def disconnect(self) -> None:
        """Stop the proxy but keep the recorded active profile.

        ``active_id`` is deliberately NOT cleared: reconnecting to it on the
        next launch is the point of recording it.
        """
        with self._lock:
            self._xray.stop()
            self._current_id = None

    def connect_active(self) -> Profile | None:
        """Reconnect the last-active profile, or None when none is recorded.

        Called once at launch. An AppError (missing secret, rejected config)
        propagates to the caller — silently swallowing it would leave the user
        believing the proxy is up when it is not.
        """
        active = self._store.active_id
        if active is None:
            return None
        return self.connect(active)

    def probe_all(
        self,
        on_result: Callable[[str, int | None], None],
        *,
        timeout: float = 3.0,
    ) -> None:
        """Measure every profile's server latency without touching the proxy.

        One worker thread per profile, capped at ``_PROBE_POOL_SIZE`` workers.
        ``on_result(profile_id, ms_or_None)`` is called from a *worker*
        thread, so UI callers must marshal to their event loop themselves
        (the TUI uses Textual's ``call_from_thread``).

        Results are written back with ``store.set_latency`` and persisted with
        a single ``save()`` at the end — not once per profile — so a sweep over
        many profiles costs one atomic rewrite. Never starts a proxy and never
        changes the active profile.
        """
        profiles = self._store.all()
        if not profiles:
            return

        def _probe(profile: Profile) -> tuple[str, int | None]:
            link = profile.link
            host = link.get("server")
            port = link.get("port")
            try:
                # Any malformed stored shape counts as unreachable rather than
                # killing the sweep; probe_server already returns None for
                # network failures, this guards the dict access around it.
                ms = probe_server(host, port, timeout=timeout)
            except Exception:
                ms = None
            # Documented: this runs on the worker thread; the caller marshals.
            on_result(profile.id, ms)
            return (profile.id, ms)

        results: list[tuple[str, int | None]]
        workers = min(_PROBE_POOL_SIZE, len(profiles))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(_probe, profiles))
        for profile_id, ms in results:
            self._store.set_latency(profile_id, ms)
        self._store.save()

    def log_tail(self) -> str:
        """Redacted tail of the supervised process's output, for a log pane.

        Delegates to ``XrayProcess.last_log``, which is already redacted
        (UUIDs and ``vless://`` URIs stripped) — nothing here re-adds secrets.
        """
        return self._xray.last_log
