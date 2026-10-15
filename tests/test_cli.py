"""Tests for vlessp.cli — argument routing, flag parity, and the headless run loop.

**These tests never execute the real Xray binary.** The repository root contains a
macOS copy that is Gatekeeper-quarantined and hangs when spawned, so anything that
could reach it is fatal to the suite. Two independent guards enforce that:

1. Every test that needs a binary passes ``--xray`` pointing at a fake written into
   a tmpdir, or patches ``vlessp.cli.resolve_xray`` to return that fake. An explicit
   ``--xray`` short-circuits the vendored-binary lookup inside ``resolve_xray``.
2. :class:`CliTestCase` patches ``vlessp.cli.resolve_xray`` by default, so a test that
   forgets to stub it fails loudly instead of reaching the network or the vendored copy.

The fake (``_FAKE_XRAY_SOURCE``) honours the two argv shapes the supervisor uses --
``run -test -config PATH`` and ``run -config PATH`` -- and switches behaviour through
the ``FAKE_XRAY_MODE`` environment variable:

- ``ok`` (default): ``-test`` validates the config JSON and exits 0; ``run`` binds the
  config's inbound ports and serves until killed.
- ``reject``: ``-test`` exits non-zero, simulating a config Xray refuses.
- ``reject-echo``: like ``reject``, but deliberately echoes the config's user id and a
  ``vless://`` string, so redaction of the CLI's own output is tested against an
  adversary that actually leaks.
"""
from __future__ import annotations

import contextlib
import io
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vlessp import cli
from vlessp.errors import AppError
from vlessp.links import parse_vless_uri
from vlessp.profiles import ProfileStore
from vlessp.xray import resolve_xray as real_resolve_xray

TEST_UUID = "01234567-89ab-cdef-0123-456789abcdef"
TEST_UUID_2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
REALITY_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# A syntactically valid link built entirely from documentation-reserved values.
# 203.0.113.0/24 is TEST-NET-3 and example.com is reserved by RFC 2606, so this
# points at nothing.
EXAMPLE_LINK = (
    f"vless://{TEST_UUID}@203.0.113.10:2083?"
    "sni=example.com&type=ws&encryption=none&security=tls&allowInsecure=0&insecure=0"
    "&fp=chrome&alpn=http%2F1.1&path=%2F&host=s7r.example.com#example-profile"
)

_FAKE_XRAY_SOURCE = '''#!/usr/bin/env python3
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
            # Deliberately leaks: whatever redaction is under test must strip these
            # before they reach a terminal.
            print(f"fake-xray: rejected user {uid}")
            print("fake-xray: offending link vless://leaked-link-in-output")
        else:
            print("fake-xray: configuration rejected (simulated)")
        return 1
    return 0


def _run_mode(cfg_path):
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            config = json.load(fh)
    except Exception as exc:
        print(f"fake-xray: cannot read config ({type(exc).__name__})")
        return 1
    listeners = []
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
    for sock in listeners:
        sock.settimeout(0.5)
    while True:  # serve until killed by stop()
        for sock in listeners:
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            with conn:
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
'''


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


class _Tty:
    """Stand-in for an interactive stdin (the test runner's stdin is never a TTY)."""

    def isatty(self) -> bool:
        return True


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _profile_link(
    uuid_value: str = TEST_UUID, server: str = "example.com", port: int = 443, label: str = "home"
) -> str:
    return (
        f"vless://{uuid_value}@{server}:{port}?security=reality&type=tcp"
        f"&sni={server}&fp=chrome&pbk={REALITY_KEY}&sid=abcd#{label}"
    )


class CliTestCase(unittest.TestCase):
    """Per-test tmpdir with a fake binary, a store file, and a stubbed resolver."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="vlessp-cli-test-")
        self.addCleanup(self._tmp.cleanup)
        tmp_path = Path(self._tmp.name)

        # Nested one level deep under a version-shaped directory so the status
        # bar's version label is exercised without spawning anything.
        version_dir = tmp_path / "v1.2.3"
        version_dir.mkdir()
        fake = version_dir / "xray"
        fake.write_text(_FAKE_XRAY_SOURCE, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.fake_xray = fake

        self.store_path = tmp_path / "profiles.json"
        self.store = ProfileStore(path=self.store_path)
        self.store.load()
        self.secrets = DictSecretStore()

        patcher = mock.patch.dict(os.environ, {"FAKE_XRAY_MODE": "ok"})
        patcher.start()
        self.addCleanup(patcher.stop)

        # The store, the secret backend, and the binary resolver are all wired by
        # main() to real defaults; every test overrides them here so nothing can
        # reach ~/Library/Application Support, the Keychain, or a vendored binary.
        patcher = mock.patch("vlessp.cli.ProfileStore", lambda: ProfileStore(path=self.store_path))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("vlessp.cli._secret_backend", return_value=self.secrets)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.resolve_calls: list[tuple[str | None, bool]] = []
        patcher = mock.patch(
            "vlessp.cli.resolve_xray", side_effect=self._fake_resolve
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _fake_resolve(self, xray_arg: str | None, *, update: bool = False) -> Path:
        self.resolve_calls.append((xray_arg, update))
        return self.fake_xray

    # -- running main -----------------------------------------------------

    def run_main(self, argv: list[str]) -> tuple[int, str, str]:
        """Run ``cli.main(argv)``, returning (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def set_mode(self, mode: str) -> None:
        os.environ["FAKE_XRAY_MODE"] = mode

    def add_profile(
        self, label: str, *, uuid_value: str = TEST_UUID, server: str = "example.com"
    ) -> str:
        """Store a profile the way the add-flow does: UUID split out to the backend."""
        link = parse_vless_uri(_profile_link(uuid_value=uuid_value, server=server, label=label))
        secret = link.pop("uuid")
        self.assertEqual(secret, uuid_value.lower())
        profile = self.store.add(label, link)
        self.store.set_active(profile.id)
        self.store.save()
        self.secrets.set(profile.id, secret)
        return profile.id


class TestFlagParsing(CliTestCase):
    """Every V0 flag survives, and the parser advertises every documented one."""

    EXPECTED_FLAGS = (
        "--link", "--link-file", "--xray", "--socks", "--http", "--no-http",
        "--allow-insecure", "--check", "--update-xray",
        "--profile", "--list", "--tui",
    )

    def test_help_exits_zero_and_lists_every_flag(self) -> None:
        out = io.StringIO()
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stdout(out):
                cli.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        text = out.getvalue()
        for flag in self.EXPECTED_FLAGS:
            with self.subTest(flag=flag):
                self.assertIn(flag, text)

    def test_every_documented_flag_parses(self) -> None:
        cases = {
            "--link": ["--link", EXAMPLE_LINK],
            "--link-file": ["--link-file", "/tmp/x"],
            "--profile": ["--profile", "home"],
            "--list": ["--list"],
            "--tui": ["--tui"],
            "--xray": ["--xray", "/tmp/x"],
            "--socks": ["--socks", "127.0.0.1:10808"],
            "--http": ["--http", "127.0.0.1:10809"],
            "--no-http": ["--no-http"],
            "--allow-insecure": ["--allow-insecure"],
            "--check": ["--check"],
            "--update-xray": ["--update-xray"],
        }
        self.assertEqual(set(cases), set(self.EXPECTED_FLAGS))
        parser = cli.build_parser()
        for flag, argv in cases.items():
            with self.subTest(flag=flag):
                # parse_args raises SystemExit on an unknown flag; that is the point.
                self.assertTrue(parser.parse_args(argv))

    def test_defaults_match_v0(self) -> None:
        args = cli.build_parser().parse_args([])
        self.assertEqual(args.socks, "127.0.0.1:10808")
        self.assertEqual(args.http, "127.0.0.1:10809")
        self.assertIsNone(args.xray)
        self.assertFalse(args.no_http)
        self.assertFalse(args.allow_insecure)
        self.assertFalse(args.check)
        self.assertFalse(args.update_xray)

    def test_link_and_link_file_are_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["--link", EXAMPLE_LINK, "--link-file", "/tmp/x"])

    def test_conflicting_modes_are_rejected_with_exit_2(self) -> None:
        cases = (
            ["--profile", "home", "--link", EXAMPLE_LINK],
            ["--profile", "home", "--link-file", "/tmp/x"],
            ["--list", "--link", EXAMPLE_LINK],
            ["--check", "--profile", "home"],
            ["--check", "--list"],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                code, _out, err = self.run_main(argv)
                self.assertEqual(code, 2)
                self.assertIn("cannot be combined", err)


class TestCheckMode(CliTestCase):
    """--check validates without opening a listener. V0 behaviour, exactly."""

    def test_check_with_link_succeeds_and_says_so(self) -> None:
        code, out, err = self.run_main(["--check", "--link", EXAMPLE_LINK])
        self.assertEqual(code, 0)
        self.assertIn("validated", out)
        self.assertIn("does not test reachability", out)

    def test_check_passes_the_xray_flag_through_to_the_resolver(self) -> None:
        self.run_main(["--check", "--link", EXAMPLE_LINK, "--xray", str(self.fake_xray)])
        self.assertEqual(self.resolve_calls, [(str(self.fake_xray), False)])

    def test_update_xray_is_forwarded_as_the_update_keyword(self) -> None:
        self.run_main(["--check", "--link", EXAMPLE_LINK, "--update-xray"])
        self.assertEqual(self.resolve_calls, [(None, True)])

    def test_link_warns_that_it_is_visible_in_process_listings(self) -> None:
        code, _out, err = self.run_main(["--check", "--link", EXAMPLE_LINK])
        self.assertEqual(code, 0)
        self.assertIn("process", err.lower())

    def test_rejected_config_exits_2_and_prints_the_reason(self) -> None:
        self.set_mode("reject")
        code, _out, err = self.run_main(["--check", "--link", EXAMPLE_LINK])
        self.assertEqual(code, 2)
        self.assertIn("Xray rejected the generated configuration", err)
        self.assertIn("fake-xray: configuration rejected", err)

    def test_check_output_never_contains_the_uuid(self) -> None:
        self.set_mode("reject-echo")
        code, out, err = self.run_main(["--check", "--link", EXAMPLE_LINK])
        self.assertEqual(code, 2)
        combined = out + err
        self.assertIn("<redacted", combined)  # the leak was caught and replaced
        self.assertNotIn(TEST_UUID, combined)
        self.assertNotIn("vless://leaked-link", combined)
        self.assertNotIn(EXAMPLE_LINK, combined)

    def test_allow_insecure_is_required_for_an_insecure_link(self) -> None:
        insecure = EXAMPLE_LINK.replace("allowInsecure=0&insecure=0", "allowInsecure=1&insecure=1")
        code, _out, err = self.run_main(["--check", "--link", insecure])
        self.assertEqual(code, 2)
        self.assertIn("--allow-insecure", err)
        code, out, _err = self.run_main(["--check", "--link", insecure, "--allow-insecure"])
        self.assertEqual(code, 0)
        self.assertIn("validated", out)

    def test_no_http_disables_the_http_listener(self) -> None:
        code, _out, _err = self.run_main(["--check", "--link", EXAMPLE_LINK, "--no-http"])
        self.assertEqual(code, 0)
        self.assertEqual(cli._http_addr(cli.build_parser().parse_args(["--no-http"])), None)

    def test_identical_socks_and_http_ports_are_rejected(self) -> None:
        code, _out, err = self.run_main(
            ["--check", "--link", EXAMPLE_LINK, "--socks", "127.0.0.1:10899", "--http", "127.0.0.1:10899"]
        )
        self.assertEqual(code, 2)
        self.assertIn("identical", err)

    def test_identical_ports_are_fine_when_http_is_disabled(self) -> None:
        code, out, _err = self.run_main(
            [
                "--check", "--link", EXAMPLE_LINK, "--no-http",
                "--socks", "127.0.0.1:10899", "--http", "127.0.0.1:10899",
            ]
        )
        self.assertEqual(code, 0)
        self.assertIn("validated", out)

    def test_distinct_custom_ports_are_accepted(self) -> None:
        # --check validates the config but binds nothing, so fixed distinct
        # loopback ports are enough and nothing needs to be free.
        code, out, err = self.run_main(
            ["--check", "--link", EXAMPLE_LINK, "--socks", "127.0.0.1:10808", "--http", "127.0.0.1:11808"]
        )
        self.assertEqual(code, 0, err)
        self.assertIn("validated", out)

    def test_non_loopback_listener_is_refused(self) -> None:
        code, _out, err = self.run_main(["--check", "--link", EXAMPLE_LINK, "--socks", "0.0.0.0:10808"])
        self.assertEqual(code, 2)
        self.assertIn("loopback", err)

    def test_explicit_xray_path_is_validated_by_the_real_resolver(self) -> None:
        # Patches back through to the real resolve_xray: with an explicit path it
        # must fail before any download or vendored lookup happens.
        with mock.patch("vlessp.cli.resolve_xray", new=real_resolve_xray):
            code, _out, err = self.run_main(
                ["--check", "--link", EXAMPLE_LINK, "--xray", "/nonexistent/xray"]
            )
        self.assertEqual(code, 2)
        self.assertIn("not found or not executable", err)


class TestLinkFile(CliTestCase):
    """--link-file keeps its 0600 requirement and its three checks, in order."""

    def _write_link_file(self, mode: int, content: str = EXAMPLE_LINK) -> Path:
        path = Path(self._tmp.name) / "link.txt"
        path.write_text(content, encoding="utf-8")
        os.chmod(path, mode)
        return path

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_world_readable_file_is_rejected(self) -> None:
        path = self._write_link_file(0o644)
        code, _out, err = self.run_main(["--check", "--link-file", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("chmod 600", err)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_private_file_is_accepted(self) -> None:
        path = self._write_link_file(0o600)
        code, out, err = self.run_main(["--check", "--link-file", str(path)])
        self.assertEqual(code, 0)
        self.assertIn("validated", out)
        self.assertNotIn("Warning: --link", err)

    def test_missing_file_is_rejected(self) -> None:
        code, _out, err = self.run_main(["--check", "--link-file", "/nonexistent/link.txt"])
        self.assertEqual(code, 2)
        self.assertIn("Could not open the VLESS link file", err)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_oversized_file_is_rejected(self) -> None:
        path = self._write_link_file(0o600, content="v" * (16 * 1024 + 1))
        code, _out, err = self.run_main(["--check", "--link-file", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("no larger than 16 KiB", err)

    def test_non_utf8_file_is_rejected_without_a_traceback(self) -> None:
        path = Path(self._tmp.name) / "binary.txt"
        path.write_bytes(b"\xff\xfe\x00vless")
        os.chmod(path, 0o600)
        code, _out, err = self.run_main(["--check", "--link-file", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("UTF-8", err)

    def test_non_interactive_stdin_without_a_source_is_rejected(self) -> None:
        code, _out, err = self.run_main(["--check"])
        self.assertEqual(code, 2)
        self.assertIn("--link-file", err)


class TestList(CliTestCase):
    """--list answers without a binary, and never prints a credential."""

    def test_lists_labels_and_servers(self) -> None:
        self.add_profile("home", server="example.com")
        self.add_profile("work", uuid_value=TEST_UUID_2, server="203.0.113.99")
        code, out, _err = self.run_main(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("home", out)
        self.assertIn("example.com", out)
        self.assertIn("work", out)
        self.assertIn("203.0.113.99", out)

    def test_never_prints_a_uuid_or_the_profile_id(self) -> None:
        profile_id = self.add_profile("home")
        _code, out, err = self.run_main(["--list"])
        for stream in (out, err):
            self.assertNotIn(TEST_UUID, stream)
            # The profile id is a uuid4 hex string and doubles as the Keychain
            # account name. Neither belongs in a listing: a label is the
            # reference --profile is meant to be used with.
            self.assertNotIn(profile_id, stream)

    def test_no_uuid_of_any_profile_appears(self) -> None:
        self.add_profile("home", uuid_value=TEST_UUID)
        self.add_profile("work", uuid_value=TEST_UUID_2, server="203.0.113.99")
        _code, out, err = self.run_main(["--list"])
        for stream in (out, err):
            self.assertNotIn(TEST_UUID, stream)
            self.assertNotIn(TEST_UUID_2, stream)

    def test_shows_security_transport_and_latency(self) -> None:
        self.add_profile("home")
        self.store.set_latency(self.store.active_id, 42)
        self.store.save()
        _code, out, _err = self.run_main(["--list"])
        self.assertIn("reality", out)
        self.assertIn("tcp", out)
        self.assertIn("42ms", out)

    def test_empty_store_explains_what_to_do(self) -> None:
        code, out, _err = self.run_main(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("No profiles saved yet", out)

    def test_does_not_resolve_a_binary(self) -> None:
        self.add_profile("home")
        self.run_main(["--list"])
        self.assertEqual(self.resolve_calls, [])


class TestProfileMode(CliTestCase):
    """--profile connects a saved profile headlessly."""

    def test_unknown_profile_exits_2_with_a_clear_message(self) -> None:
        code, _out, err = self.run_main(["--profile", "does-not-exist"])
        self.assertEqual(code, 2)
        self.assertIn("--list", err)
        self.assertNotIn("does-not-exist", err)  # argv is never echoed back

    def test_missing_secret_exits_2(self) -> None:
        self.add_profile("home")
        self.secrets._values.clear()
        code, _out, err = self.run_main(["--profile", "home"])
        self.assertEqual(code, 2)
        self.assertIn("Keychain", err)

    def test_failed_connect_prints_the_error_and_the_xray_log_tail(self) -> None:
        """The integration point: XrayProcess keeps its output, so the CLI must show it."""
        self.add_profile("home")
        self.set_mode("reject")
        code, _out, err = self.run_main(["--profile", "home"])
        self.assertEqual(code, 2)
        # Both halves: the message...
        self.assertIn("Xray rejected the generated configuration", err)
        # ...and the output that explains it, which nothing else will ever print.
        self.assertIn("fake-xray: configuration rejected", err)

    def test_failed_connect_output_is_redacted(self) -> None:
        self.add_profile("home")
        self.set_mode("reject-echo")
        code, out, err = self.run_main(["--profile", "home"])
        self.assertEqual(code, 2)
        combined = out + err
        self.assertNotIn(TEST_UUID, combined)
        self.assertNotIn("vless://leaked-link", combined)

    def test_connect_serves_and_stops_cleanly_on_interrupt(self) -> None:
        self.add_profile("home")
        socks, http = f"127.0.0.1:{_free_port()}", f"127.0.0.1:{_free_port()}"
        # cli.time is replaced (not time.sleep) so only the CLI's poll loop is
        # affected; the supervisor's own readiness polling keeps working.
        fake_time = mock.MagicMock()
        fake_time.sleep.side_effect = KeyboardInterrupt
        with mock.patch.object(cli, "time", fake_time):
            code, out, _err = self.run_main(["--profile", "home", "--socks", socks, "--http", http])
        self.assertEqual(code, 0)  # V0: a deliberate stop is a success
        self.assertIn("Proxy is ready.", out)
        self.assertIn(f"SOCKS5: {socks}", out)
        self.assertIn(f"HTTP:   http://{http}", out)
        self.assertIn("home", out)

    def test_successful_connect_persists_the_active_profile(self) -> None:
        profile_id = self.add_profile("home")
        socks, http = f"127.0.0.1:{_free_port()}", f"127.0.0.1:{_free_port()}"
        fake_time = mock.MagicMock()
        fake_time.sleep.side_effect = KeyboardInterrupt
        with mock.patch.object(cli, "time", fake_time):
            self.run_main(["--profile", "home", "--socks", socks, "--http", http])
        self.assertEqual(self.store.active_id, profile_id)

    def test_connect_failure_does_not_leave_a_tunnel_running(self) -> None:
        """A failure after the switch succeeded must not exit with a live child."""
        self.add_profile("home")
        socks, http = f"127.0.0.1:{_free_port()}", f"127.0.0.1:{_free_port()}"
        # The store write is the one step of connect() that can fail after Xray
        # is already serving, so it is the case worth simulating. The profile is
        # written before the patch goes up, so every save inside the block is
        # connect()'s.
        def failing_save(self_store):
            raise AppError("cannot write profiles file: simulated.")

        with mock.patch.object(ProfileStore, "save", failing_save):
            code, _out, err = self.run_main(["--profile", "home", "--socks", socks, "--http", http])
        self.assertEqual(code, 2)
        self.assertIn("simulated", err)
        # The child is gone: nothing is listening on the port it was given.
        with self.assertRaises(OSError):
            with socket.create_connection(("127.0.0.1", int(socks.rsplit(":", 1)[-1])), timeout=1):
                self.fail("the proxy is still accepting connections after a failed connect")

    def test_custom_listeners_reach_the_service(self) -> None:
        self.add_profile("home")
        socks = f"127.0.0.1:{_free_port()}"
        captured: dict[str, object] = {}

        def capture(store, secrets, xray, *, socks_addr, http_addr):
            captured.update(socks=socks_addr, http=http_addr, secrets=secrets)
            raise AppError("stop here")  # the constructor is all this test needs

        with mock.patch.object(cli, "ProxyService", capture):
            code, _out, _err = self.run_main(
                ["--profile", "home", "--socks", socks, "--no-http"]
            )
        self.assertEqual(code, 2)
        self.assertEqual(captured["socks"], socks)
        self.assertIsNone(captured["http"])
        self.assertIs(captured["secrets"], self.secrets)


class TestLinkModeRun(CliTestCase):
    """The serving path for a raw link: banner, then a clean stop."""

    def test_serves_and_stops_cleanly_on_interrupt(self) -> None:
        socks, http = f"127.0.0.1:{_free_port()}", f"127.0.0.1:{_free_port()}"
        fake_time = mock.MagicMock()
        fake_time.sleep.side_effect = KeyboardInterrupt
        with mock.patch.object(cli, "time", fake_time):
            code, out, _err = self.run_main(["--link", EXAMPLE_LINK, "--socks", socks, "--http", http])
        self.assertEqual(code, 0)
        self.assertIn("Starting local proxy", out)
        self.assertIn("Proxy is ready.", out)
        self.assertIn("Stopping proxy", out)

    def test_rejected_link_exits_2_and_shows_the_xray_reason(self) -> None:
        self.set_mode("reject")
        code, _out, err = self.run_main(["--link", EXAMPLE_LINK])
        self.assertEqual(code, 2)
        self.assertIn("Xray rejected the generated configuration", err)
        self.assertIn("fake-xray: configuration rejected", err)

    def test_banner_omits_the_http_line_when_disabled(self) -> None:
        socks = f"127.0.0.1:{_free_port()}"
        fake_time = mock.MagicMock()
        fake_time.sleep.side_effect = KeyboardInterrupt
        with mock.patch.object(cli, "time", fake_time):
            code, out, _err = self.run_main(["--link", EXAMPLE_LINK, "--socks", socks, "--no-http"])
        self.assertEqual(code, 0)
        self.assertIn(f"SOCKS5: {socks}", out)
        self.assertNotIn("HTTP:   http://", out)


class TestTuiMode(CliTestCase):
    """The default and --tui build the app over the same service."""

    def _run_tui(
        self, extra: list[str]
    ) -> tuple[int, str, str, dict[str, object]]:
        captured: dict[str, object] = {}

        class FakeApp:
            def run(self) -> None:
                captured["ran"] = True

        def fake_build(service, store, **kwargs):
            captured["service"] = service
            captured["store"] = store
            captured.update(kwargs)
            return FakeApp()

        with mock.patch("sys.stdin", _Tty()):
            with mock.patch.object(cli, "_build_app", side_effect=fake_build):
                code, out, err = self.run_main(extra)
        return code, out, err, captured

    def test_bare_invocation_launches_the_tui(self) -> None:
        code, _out, _err, captured = self._run_tui([])
        self.assertEqual(code, 0)
        self.assertTrue(captured["ran"])

    def test_tui_flag_forces_the_ui_even_with_a_link(self) -> None:
        code, _out, _err, captured = self._run_tui(["--tui", "--link", EXAMPLE_LINK])
        self.assertEqual(code, 0)
        self.assertTrue(captured["ran"])

    def test_tui_refuses_without_a_terminal(self) -> None:
        code, _out, err = self.run_main(["--tui"])
        self.assertEqual(code, 2)
        self.assertIn("interactive terminal", err)

    def test_app_is_built_with_secrets_and_the_real_listeners(self) -> None:
        """Without secrets= the app silently degrades add/edit/delete."""
        socks, http = f"127.0.0.1:{_free_port()}", f"127.0.0.1:{_free_port()}"
        _code, _out, _err, captured = self._run_tui(["--socks", socks, "--http", http])
        self.assertIs(captured["secrets"], self.secrets)
        self.assertEqual(captured["socks_addr"], socks)
        self.assertEqual(captured["http_addr"], http)
        self.assertEqual(captured["store"].path, self.store_path)

    def test_app_receives_no_http_listener_as_none(self) -> None:
        _code, _out, _err, captured = self._run_tui(["--no-http"])
        self.assertIsNone(captured["http_addr"])

    def test_app_receives_the_resolved_version_label(self) -> None:
        _code, _out, _err, captured = self._run_tui([])
        self.assertEqual(captured["xray_version"], "v1.2.3")

    def test_allow_insecure_is_forwarded_to_the_app(self) -> None:
        _code, _out, _err, captured = self._run_tui(["--allow-insecure"])
        self.assertTrue(captured["allow_insecure"])
        _code, _out, _err, off = self._run_tui([])
        self.assertFalse(off["allow_insecure"])

    def test_tui_does_not_autoconnect(self) -> None:
        """Launching a window must not start moving traffic on its own."""
        self.add_profile("home")
        _code, _out, _err, captured = self._run_tui([])
        self.assertFalse(captured["service"].running)


class TestExitCodes(CliTestCase):
    """0 / 1 / 2 / 130, because scripts branch on them."""

    def test_zero_on_success(self) -> None:
        code, _out, _err = self.run_main(["--check", "--link", EXAMPLE_LINK])
        self.assertEqual(code, 0)

    def test_two_on_app_error(self) -> None:
        code, _out, err = self.run_main(["--profile", "nope"])
        self.assertEqual(code, 2)
        self.assertIn(cli.APP_NAME, err)

    def test_one_on_unexpected_os_error(self) -> None:
        with mock.patch("vlessp.cli.resolve_xray", side_effect=OSError("disk on fire")):
            code, _out, err = self.run_main(["--check", "--link", EXAMPLE_LINK])
        self.assertEqual(code, 1)
        self.assertIn("OSError", err)

    def test_one_on_unexpected_json_error(self) -> None:
        import json as _json

        with mock.patch("vlessp.cli.resolve_xray", side_effect=_json.JSONDecodeError("bad", "doc", 0)):
            code, _out, err = self.run_main(["--check", "--link", EXAMPLE_LINK])
        self.assertEqual(code, 1)
        self.assertIn("JSONDecodeError", err)

    def test_130_on_interrupt_before_serving(self) -> None:
        with mock.patch("vlessp.cli.resolve_xray", side_effect=KeyboardInterrupt):
            code, _out, err = self.run_main(["--check", "--link", EXAMPLE_LINK])
        self.assertEqual(code, 130)
        self.assertIn("Cancelled", err)

    def test_corrupt_store_exits_2_not_a_traceback(self) -> None:
        self.store_path.write_text("{not json", encoding="utf-8")
        code, _out, err = self.run_main(["--list"])
        self.assertEqual(code, 2)
        self.assertIn("malformed", err)


class TestShim(unittest.TestCase):
    """vless_proxy.py is a shim; tests/test_vless_proxy.py depends on it staying one."""

    def test_reexports_the_three_names_the_v0_tests_import(self) -> None:
        import vless_proxy
        from vlessp.errors import AppError as PackageAppError
        from vlessp.links import build_xray_config as pkg_build
        from vlessp.links import parse_vless_uri as pkg_parse

        self.assertIs(vless_proxy.AppError, PackageAppError)
        self.assertIs(vless_proxy.build_xray_config, pkg_build)
        self.assertIs(vless_proxy.parse_vless_uri, pkg_parse)

    def test_delegates_main_to_the_cli_module(self) -> None:
        import vless_proxy

        self.assertIs(vless_proxy.main, cli.main)


class TestSupervisionLoop(unittest.TestCase):
    """The poll loop on its own, so both exits are exercised deterministically."""

    def test_interrupt_stops_the_child_and_returns_zero(self) -> None:
        stopped: list[str] = []
        fake_time = mock.MagicMock()
        fake_time.sleep.side_effect = KeyboardInterrupt
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "time", fake_time):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli._supervise_until_stopped(
                    is_running=lambda: True,
                    stop=lambda: stopped.append("stopped"),
                    log_tail=lambda: "unreachable",
                    socks_addr="127.0.0.1:10808",
                    http_addr="127.0.0.1:10809",
                )
        self.assertEqual(code, 0)
        self.assertEqual(stopped, ["stopped"])
        self.assertEqual(err.getvalue(), "")

    def test_child_dying_returns_one_and_prints_its_output(self) -> None:
        states = iter([True, True, False])
        stopped: list[str] = []
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "time", mock.MagicMock()):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli._supervise_until_stopped(
                    is_running=lambda: next(states),
                    stop=lambda: stopped.append("stopped"),
                    log_tail=lambda: "fake-xray: exited unexpectedly",
                    socks_addr="127.0.0.1:10808",
                    http_addr=None,
                )
        self.assertEqual(code, 1)
        self.assertEqual(stopped, ["stopped"])
        self.assertIn("exited unexpectedly", err.getvalue())
        self.assertIn("fake-xray: exited unexpectedly", err.getvalue())


if __name__ == "__main__":
    unittest.main()