"""Tests for vlessp.proxy — profile switching over a fake Xray binary.

CRITICAL: these tests NEVER execute the real Xray binary (the vendored macOS
copy hangs under quarantine). Every test points ``ProxyService`` at a tiny
Python fake written into a tmpdir (see ``_FAKE_XRAY_SOURCE``). The fake honors
the two argv shapes ``XrayProcess`` uses — ``run -test -config PATH`` and
``run -config PATH`` — and its behaviour is switched per-test through the
``FAKE_XRAY_MODE`` environment variable, which the fake reads at startup:

- ``ok`` (default): ``-test`` validates the config JSON and exits 0; ``run``
  binds the config's inbound ports and serves until killed.
- ``reject``: ``-test`` exits non-zero, simulating a profile Xray refuses.
- ``reject-echo``: like ``reject`` but deliberately prints the config's user
  id and a ``vless://`` string, so the redaction of ``log_tail()`` is tested
  against an adversary that actually leaks.
"""
from __future__ import annotations

import os
import socket
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from vlessp.errors import AppError
from vlessp.links import parse_vless_uri
from vlessp.profiles import ProfileStore
from vlessp.proxy import ProxyService
from vlessp.secrets import NullSecretStore

TEST_UUID = "01234567-89ab-cdef-0123-456789abcdef"
TEST_UUID_2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
REALITY_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

_FAKE_XRAY_SOURCE = """#!/usr/bin/env python3
import json
import os
import socket
import sys


def _config_path(argv):
    if "-config" in argv:
        return argv[argv.index("-config") + 1]
    return None


def _test_mode(cfg_path, mode):
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            config = json.load(fh)
    except Exception as exc:
        print(f"fake-xray: cannot read config ({type(exc).__name__})")
        return 1
    if mode in ("reject", "reject-echo"):
        if mode == "reject-echo":
            try:
                uid = config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"]
            except (KeyError, IndexError, TypeError):
                uid = "unknown"
            # Deliberately leaks: the redaction layer under test must strip
            # these before they reach log_tail().
            print(f"fake-xray: rejected user {uid}")
            print("fake-xray: see vless://fake-link-in-error-output")
        else:
            print("fake-xray: configuration rejected (simulated)")
        return 1
    return 0


def _run_mode(cfg_path):
    log_path = os.environ.get("FAKE_XRAY_SPAWN_LOG")
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(f"{os.getpid()}\\n")
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            config = json.load(fh)
    except Exception as exc:
        print(f"fake-xray: cannot read config ({type(exc).__name__})")
        return 1
    listeners = []
    try:
        for inbound in config.get("inbounds", []):
            family = socket.AF_INET6 if ":" in inbound["listen"] else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((inbound["listen"], inbound["port"]))
            except OSError as exc:
                print(f"fake-xray: bind failed ({type(exc).__name__})")
                return 1
            sock.listen(16)
            listeners.append(sock)
    except Exception as exc:
        print(f"fake-xray: setup failed ({type(exc).__name__})")
        return 1
    for sock in listeners:
        sock.settimeout(0.5)
    while True:  # serve until killed by SIGTERM/SIGKILL from stop()
        for sock in listeners:
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            try:
                conn.close()
            except OSError:
                pass
    return 0


def main(argv):
    mode = os.environ.get("FAKE_XRAY_MODE", "ok")
    cfg = _config_path(argv)
    if cfg is None:
        print("fake-xray: no -config given")
        return 2
    if "-test" in argv:
        return _test_mode(cfg, mode)
    return _run_mode(cfg)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
"""


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just not ours to signal
    return True


class DictSecretStore:
    """In-memory SecretStore: a complete substitute that never touches Keychain."""

    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values = dict(values or {})

    def set(self, account: str, value: str) -> None:
        self._values[account] = value

    def get(self, account: str) -> str:
        try:
            return self._values[account]
        except KeyError:
            raise AppError(f"the UUID for profile {account} is missing from the Keychain") from None

    def delete(self, account: str) -> None:
        self._values.pop(account, None)


def _profile_uri(uuid_value: str, label: str) -> str:
    return (
        f"vless://{uuid_value}@example.com:443?security=reality&type=tcp"
        f"&sni=example.com&fp=chrome&pbk={REALITY_KEY}&sid=abcd#{label}"
    )


class ProxyTestCase(unittest.TestCase):
    """Per-test tmpdir holding the store file, the fake binary, and spawn log."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="vlessp-proxy-test-")
        self.addCleanup(self._tmp.cleanup)
        tmp_path = Path(self._tmp.name)

        fake = tmp_path / "fake-xray"
        fake.write_text(_FAKE_XRAY_SOURCE, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.fake_xray = fake

        self.spawn_log = tmp_path / "spawns.log"
        self.store = ProfileStore(path=tmp_path / "profiles.json")
        self.secrets = DictSecretStore()
        # Env the fake reads at ITS startup; patch.dict restores afterwards.
        # (Addressed per-test so modes never leak between tests.)
        self._env = mock.patch.dict(
            os.environ,
            {
                "FAKE_XRAY_MODE": "ok",
                "FAKE_XRAY_SPAWN_LOG": str(self.spawn_log),
            },
        )
        self._env.start()
        self.addCleanup(self._env.stop)

    def make_service(self) -> ProxyService:
        socks = f"127.0.0.1:{_free_port()}"
        http = f"127.0.0.1:{_free_port()}"
        service = ProxyService(
            self.store, self.secrets, self.fake_xray,
            socks_addr=socks, http_addr=http,
        )
        # Nothing may be left running: disconnect is idempotent, so calling
        # it unconditionally is safe even when the test never connected.
        self.addCleanup(service.disconnect)
        return service

    def add_profile(self, label: str, uuid_value: str = TEST_UUID) -> str:
        """Parse a URI, split off the UUID like the real add-flow, store both halves."""
        link = parse_vless_uri(_profile_uri(uuid_value, label))
        secret = link.pop("uuid")
        profile = self.store.add(label, link)
        self.secrets.set(profile.id, secret)
        return profile.id

    def spawn_pids(self) -> list[int]:
        if not self.spawn_log.is_file():
            return []
        return [int(line) for line in self.spawn_log.read_text().split()]


class TestConnect(ProxyTestCase):
    def test_connect_valid_profile_serves_and_persists(self) -> None:
        service = self.make_service()
        pid = self.add_profile("home")
        profile = service.connect("home")
        self.assertTrue(service.running)
        self.assertEqual(profile.id, pid)
        self.assertIsNotNone(service.current)
        assert service.current is not None
        self.assertEqual(service.current.id, pid)
        self.assertEqual(self.store.active_id, pid)
        # The active id reached the disk, not just memory.
        reloaded = ProfileStore(path=self.store.path)
        reloaded.load()
        self.assertEqual(reloaded.active_id, pid)

    def test_connect_by_id_also_works(self) -> None:
        service = self.make_service()
        pid = self.add_profile("home")
        service.connect(pid)
        self.assertTrue(service.running)
        assert service.current is not None
        self.assertEqual(service.current.id, pid)

    def test_connect_unknown_ref_raises_without_side_effects(self) -> None:
        service = self.make_service()
        with self.assertRaises(AppError):
            service.connect("no-such-profile")
        self.assertFalse(service.running)
        self.assertIsNone(service.current)
        self.assertIsNone(self.store.active_id)

    def test_connect_missing_uuid_keeps_old_profile_serving(self) -> None:
        service = self.make_service()
        old_id = self.add_profile("good")
        service.connect("good")
        old_pid = service._xray._process.pid  # type: ignore[union-attr]
        # A profile whose secret was never stored: resolve_link must fail.
        link = parse_vless_uri(_profile_uri(TEST_UUID_2, "bad"))
        link.pop("uuid")
        self.store.add("bad", link)
        with self.assertRaises(AppError) as ctx:
            service.connect("bad")
        # Central invariant: the failure names the shape, never the secret.
        self.assertNotIn(TEST_UUID_2, str(ctx.exception))
        self.assertNotIn("vless://", str(ctx.exception))
        # The old tunnel is untouched and still recorded as active.
        self.assertTrue(service.running)
        self.assertEqual(service._xray._process.pid, old_pid)  # type: ignore[union-attr]
        assert service.current is not None
        self.assertEqual(service.current.id, old_id)
        self.assertEqual(self.store.active_id, old_id)

    def test_connect_with_null_secret_store_raises(self) -> None:
        # The null backend fails closed: no UUID can ever be re-attached.
        null_service = ProxyService(
            self.store, NullSecretStore(), self.fake_xray,  # type: ignore[arg-type]
            socks_addr=f"127.0.0.1:{_free_port()}",
            http_addr=f"127.0.0.1:{_free_port()}",
        )
        self.addCleanup(null_service.disconnect)
        self.add_profile("home")
        with self.assertRaises(AppError):
            null_service.connect("home")
        self.assertFalse(null_service.running)
        self.assertIsNone(self.store.active_id)

    def test_connect_rejected_config_leaves_old_process_untouched(self) -> None:
        service = self.make_service()
        old_id = self.add_profile("good")
        new_id = self.add_profile("bad", TEST_UUID_2)
        service.connect("good")
        # Reading the private handle is deliberate: "untouched" means the very
        # same OS process, not merely "something is running".
        old_pid = service._xray._process.pid  # type: ignore[union-attr]
        spawns_before = len(self.spawn_pids())
        with mock.patch.dict(os.environ, {"FAKE_XRAY_MODE": "reject"}):
            with self.assertRaises(AppError) as ctx:
                service.connect("bad")
        self.assertNotIn(TEST_UUID_2, str(ctx.exception))
        self.assertNotIn("vless://", str(ctx.exception))
        self.assertTrue(service.running)
        self.assertEqual(service._xray._process.pid, old_pid)  # type: ignore[union-attr]
        self.assertEqual(len(self.spawn_pids()), spawns_before)  # no new spawn attempted
        assert service.current is not None
        self.assertEqual(service.current.id, old_id)
        self.assertEqual(self.store.active_id, old_id)
        self.assertEqual(new_id, self.store.resolve("bad").id)  # failed target still stored

    def test_connect_persist_failure_tears_down_the_new_tunnel(self) -> None:
        """A switch that cannot be recorded must not stay up.

        ``apply`` has already killed the old process by the time the store is
        written, so a stale ``active_id`` on disk names a node we are no longer
        on -- and the next launch would reconnect it without the user choosing
        it. Silently rerouting traffic is worse than dropping the connection, so
        this path must leave nothing running.

        The teardown lives in ``connect`` rather than in each caller, so this is
        an invariant of the class: no caller can leak a child by forgetting.
        """
        service = self.make_service()
        self.add_profile("home")
        spawns_before = len(self.spawn_pids())

        def failing_save(_store):
            raise AppError("cannot write profiles file: simulated.")

        with mock.patch.object(ProfileStore, "save", failing_save):
            with self.assertRaises(AppError):
                service.connect("home")

        self.assertFalse(service.running)
        self.assertIsNone(service.current)
        # A child was spawned and then reaped: one more spawn than before, but
        # nothing left alive.
        self.assertEqual(len(self.spawn_pids()), spawns_before + 1)

    def test_concurrent_connects_leave_exactly_one_live_child(self) -> None:
        service = self.make_service()
        self.add_profile("a")
        self.add_profile("b")
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def _go(ref: str) -> None:
            try:
                barrier.wait(timeout=10.0)
                service.connect(ref)
            except BaseException as exc:  # collected, then asserted in-thread
                errors.append(exc)

        first = threading.Thread(target=_go, args=("a",))
        second = threading.Thread(target=_go, args=("b",))
        first.start()
        second.start()
        first.join(timeout=30.0)
        second.join(timeout=30.0)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(service.running)
        # Both applies ran (serialized by the service lock: the loser stopped
        # the winner's process and respawned), so exactly one child is alive.
        pids = self.spawn_pids()
        living = [pid for pid in pids if _is_alive(pid)]
        self.assertEqual(len(living), 1)
        self.assertEqual(service._xray._process.pid, living[0])  # type: ignore[union-attr]

    def test_no_add_profile_method(self) -> None:
        # Ownership rule: the TUI writes profiles via the store; the service
        # must not grow a parallel write path that could drift from it.
        self.assertFalse(hasattr(ProxyService, "add_profile"))


class TestDisconnect(ProxyTestCase):
    def test_disconnect_stops_but_keeps_active_id(self) -> None:
        service = self.make_service()
        pid = self.add_profile("home")
        service.connect("home")
        service.disconnect()
        self.assertFalse(service.running)
        self.assertIsNone(service.current)
        # Reconnect-on-launch depends on this surviving a disconnect.
        self.assertEqual(self.store.active_id, pid)
        reloaded = ProfileStore(path=self.store.path)
        reloaded.load()
        self.assertEqual(reloaded.active_id, pid)

    def test_disconnect_without_connect_is_safe(self) -> None:
        service = self.make_service()
        service.disconnect()  # must not raise
        self.assertFalse(service.running)


class TestConnectActive(ProxyTestCase):
    def test_no_active_returns_none(self) -> None:
        service = self.make_service()
        self.assertIsNone(service.connect_active())
        self.assertFalse(service.running)

    def test_reconnects_recorded_profile(self) -> None:
        service = self.make_service()
        pid = self.add_profile("home")
        service.connect("home")
        service.disconnect()
        self.assertFalse(service.running)
        profile = service.connect_active()
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertEqual(profile.id, pid)
        self.assertTrue(service.running)


class TestProbeAll(ProxyTestCase):
    def test_reports_every_profile_without_touching_proxy(self) -> None:
        # One reachable server: bind+listen is enough, the backlog accepts it.
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        live_port = int(listener.getsockname()[1])
        try:
            service = self.make_service()
            live_id = self.add_profile("live")
            dead_id = self.add_profile("dead", TEST_UUID_2)
            ghost_id = self.store.add(
                "ghost",
                {**self.store.get(dead_id).link, "server": "nonexistent.invalid"},
            ).id
            self.secrets.set(ghost_id, TEST_UUID_2)
            # Point the links where the test needs them (ports/servers only;
            # no secret material is ever altered here).
            for profile_id, server, port in (
                (live_id, "127.0.0.1", live_port),
                (dead_id, "127.0.0.1", _free_port()),  # closed: refused
                (ghost_id, "nonexistent.invalid", 443),  # DNS: unresolvable
            ):
                current = self.store.get(profile_id)
                link = dict(current.link)
                link["server"] = server
                link["port"] = port
                self.store.update(profile_id, link=link)
            self.store.set_active(live_id)
            self.store.save()

            seen: dict[str, int | None] = {}
            seen_lock = threading.Lock()

            def _on_result(profile_id: str, ms: int | None) -> None:
                # May run on any worker thread: only touch the local dict,
                # under a lock, never the store or the UI.
                with seen_lock:
                    seen[profile_id] = ms

            service.probe_all(_on_result, timeout=2.0)

            self.assertEqual(set(seen), {live_id, dead_id, ghost_id})
            live_ms = seen[live_id]
            self.assertIsInstance(live_ms, int)
            assert live_ms is not None
            self.assertGreaterEqual(live_ms, 0)
            self.assertIsNone(seen[dead_id])
            self.assertIsNone(seen[ghost_id])
            # Latencies written back and persisted with a single save...
            self.assertIsInstance(self.store.get(live_id).last_latency_ms, int)
            self.assertIsNone(self.store.get(dead_id).last_latency_ms)
            reloaded = ProfileStore(path=self.store.path)
            reloaded.load()
            self.assertIsInstance(reloaded.get(live_id).last_latency_ms, int)
            # ...while the proxy and the active profile are untouched.
            self.assertFalse(service.running)
            self.assertIsNone(service.current)
            self.assertEqual(self.store.active_id, live_id)
            self.assertEqual(self.spawn_pids(), [])
        finally:
            listener.close()

    def test_empty_store_calls_back_nothing(self) -> None:
        service = self.make_service()
        calls: list[tuple[str, int | None]] = []
        service.probe_all(lambda pid, ms: calls.append((pid, ms)))
        self.assertEqual(calls, [])


class TestLogTail(ProxyTestCase):
    def test_log_tail_never_carries_secrets(self) -> None:
        service = self.make_service()
        self.add_profile("home")
        with mock.patch.dict(os.environ, {"FAKE_XRAY_MODE": "reject-echo"}):
            with self.assertRaises(AppError):
                service.connect("home")
        tail = service.log_tail()
        # The fake printed the raw UUID and a vless:// URI; both shapes must
        # be redacted before they reach any log pane.
        self.assertNotIn(TEST_UUID, tail)
        self.assertNotIn("vless://", tail)
        self.assertIn("<redacted-uuid>", tail)

    def test_log_tail_quiet_when_nothing_ran(self) -> None:
        service = self.make_service()
        tail = service.log_tail()
        self.assertNotIn("vless://", tail)
        self.assertNotRegex(tail, r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-")


if __name__ == "__main__":
    unittest.main()
