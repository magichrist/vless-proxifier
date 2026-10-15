"""Command-line entry point: argument parsing, flag routing, and the headless run loop.

Three front-ends share one process supervisor:

* a **link mode** (``--link`` / ``--link-file``) that keeps V0's behaviour flag for flag,
  because scripts depend on it;
* a **profile mode** (``--profile``) that connects a saved profile and prints the same banner,
  with the UUID re-attached from the Keychain by :mod:`vlessp.profiles`;
* a **TUI mode** (the default, or forced with ``--tui``) that builds a
  :class:`~vlessp.tui.app.VlessApp` over the same :class:`~vlessp.proxy.ProxyService`.

Three rules shape the code below.

**No link, no UUID, no secret in any output.** Every message is written from the *shape* of a
problem, never from argv, a parsed link dict, or a config file. That includes refusing to echo
a user-supplied ``--profile`` reference, which is the one argv value here that a user could
type anything into.

**Xray's own output is captured, never inherited.** :class:`~vlessp.xray.XrayProcess` runs
under a TUI where writing to the console would corrupt the interface, so it keeps the ``-test``
rejection text in :attr:`~vlessp.xray.XrayProcess.last_log` instead of printing it. The
consequence for this module is that it MUST print that tail itself: an error saying "review the
preceding Xray error" points at output the user cannot see. :func:`_report_failure` is the one
place that pairs a message with its tail, and both link and profile mode go through it.

**The composition root is here.** This is the only module that decides *which* secret backend,
*which* Xray binary, and *which* ports everything else gets. ``ProxyService`` and the TUI take
their dependencies as constructor arguments and never go looking for them.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import APP_NAME
from .errors import AppError
from .links import MAX_URI_BYTES, build_xray_config, parse_vless_uri
from .profiles import ProfileStore
from .proxy import ProxyService
from .secrets import MacOSKeychain, NullSecretStore, SecretStore
from .xray import XrayProcess, app_data_dir, resolve_xray

__all__ = ["build_parser", "main"]

# How often the headless run loop asks "is the child still alive?". The supervisor
# exposes `running` rather than a blocking wait (see the note on the poll loop in
# `_supervise_until_stopped`), so this is the only knob involved.
_POLL_SECONDS = 0.25

# `install_xray` lays binaries out as <app data>/xray/<tag>/xray, so the parent
# directory name is the version. A vendored build's parent is a platform directory,
# which is not a version -- hence the match rather than trusting the name.
_VERSION_TAG_RE = re.compile(r"^v\d+\.\d+")

# Redaction for the one path that is NOT XrayProcess: `--check` runs `xray run
# -test` itself, because the supervisor exposes no validate-only entry point. The
# patterns match vlessp.xray's private pair; they are repeated rather than imported
# because that module does not publish them, and a captured subprocess stream must
# never reach a terminal unfiltered -- Xray prints config fragments on some parse
# errors, which is exactly how the UUID would escape.
_URI_IN_TEXT_RE = re.compile(r"(?i)vless://\S+")
_UUID_IN_TEXT_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)

_warned_no_keychain = False


# --------------------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the parser.

    ``--link``/``--link-file`` stay mutually exclusive exactly as in V0. The new
    flags are separate and the conflicts between a profile reference and a link
    source are rejected in :func:`_dispatch` rather than by argparse, so the
    rejection can be an ``AppError`` (exit 2) with a message that explains the fix
    rather than a usage dump.
    """
    parser = argparse.ArgumentParser(
        prog="vless_proxy.py",
        description=(
            "Manage VLESS profiles and expose a local SOCKS5/HTTP proxy. "
            "With no arguments, launches the Textual UI."
        ),
        epilog=(
            "Links are never printed. Prefer --link-file (mode 600) over --link, "
            "which is visible in process listings."
        ),
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--link",
        help="VLESS URI (visible in process listings; --link-file is safer)",
    )
    source.add_argument(
        "--link-file",
        help="read VLESS URI from a private local file (must be mode 600 on POSIX)",
    )
    parser.add_argument(
        "--profile",
        metavar="ID_OR_LABEL",
        help="connect to a saved profile headlessly (no UI)",
    )
    parser.add_argument(
        "--list",
        dest="list_profiles",
        action="store_true",
        help="print the saved profiles and exit (never prints a UUID)",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="force the Textual UI (the default when no link source is given)",
    )
    parser.add_argument("--xray", help="path to an existing Xray executable")
    parser.add_argument(
        "--socks",
        default="127.0.0.1:10808",
        help="SOCKS5 listen address (loopback only; default 127.0.0.1:10808)",
    )
    parser.add_argument(
        "--http",
        default="127.0.0.1:10809",
        help="HTTP listen address (loopback only; default 127.0.0.1:10809)",
    )
    parser.add_argument("--no-http", action="store_true", help="disable the HTTP proxy listener")
    parser.add_argument(
        "--allow-insecure",
        action="store_true",
        help="allow a link with certificate verification disabled (unsafe)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate URI/config with Xray, but don't start listeners",
    )
    parser.add_argument(
        "--update-xray",
        action="store_true",
        help="download and verify the latest stable official Xray release",
    )
    return parser


def _dispatch(args: argparse.Namespace) -> int:
    """Route parsed arguments to exactly one front-end.

    Order is the precedence a user would expect: an explicit ``--tui`` wins over
    everything, then ``--list``, then ``--profile``, then the V0 link mode, and
    the bare invocation falls through to the UI.
    """
    if args.link or args.link_file:
        if args.list_profiles:
            raise AppError("--list cannot be combined with --link or --link-file.")
        if args.profile:
            raise AppError("--profile cannot be combined with --link or --link-file.")
    if args.check and args.profile:
        raise AppError(
            "--check cannot be combined with --profile; "
            "it validates a link from --link or --link-file."
        )
    if args.check and args.list_profiles:
        raise AppError("--check cannot be combined with --list.")

    http_addr = _http_addr(args)
    if args.tui:
        return _run_tui(args, http_addr)
    if args.list_profiles:
        return _run_list()
    if args.profile:
        return _run_profile(args, http_addr)
    if args.link or args.link_file or args.check:
        return _run_link(args, http_addr)
    return _run_tui(args, http_addr)


def _http_addr(args: argparse.Namespace) -> str | None:
    """The HTTP listener address, or None when ``--no-http`` disabled it."""
    return None if args.no_http else args.http


def _reject_identical_listeners(socks_addr: str, http_addr: str | None) -> None:
    """Refuse to give SOCKS and HTTP the same port.

    Lives here rather than in ``build_xray_config`` for two reasons: the config
    generator is pure and has no notion of "the two listeners", and this is the V0
    behaviour that must not move. Compared only when HTTP is in effect, and the
    message names the shape of the problem without echoing either address.
    """
    if http_addr and socks_addr.rsplit(":", 1)[-1] == http_addr.rsplit(":", 1)[-1]:
        raise AppError("The SOCKS5 and HTTP listeners are identical; give them different ports.")


# --------------------------------------------------------------------------------------
# front-ends
# --------------------------------------------------------------------------------------


def _run_list() -> int:
    """Print the saved profiles.

    Reads only ``profiles.json`` -- no Xray binary is resolved and no network is
    touched, because a query about what is saved should work on a machine with no
    binary and no connectivity. No UUID is printed, and no profile id either: a
    label is the intended reference and the id is an implementation detail.
    """
    store = _load_store()
    profiles = store.all()
    if not profiles:
        print("No profiles saved yet. Run the UI to add one: python3 vless_proxy.py")
        return 0
    header = f"{'LABEL':<18} {'SERVER':<18} {'PORT':>5}  {'SEC':<7} {'TRANSPORT':<10} {'LATENCY':>7}  STATE"
    print(header)
    print("-" * len(header))
    for profile in profiles:
        link = profile.link
        latency = "—" if profile.last_latency_ms is None else f"{profile.last_latency_ms}ms"
        state = []
        if profile.id == store.active_id:
            state.append("active")
        if profile.last_latency_ms is None:
            state.append("untested")
        print(
            f"{_cell(profile.label, 18):<18} "
            f"{_cell(str(link.get('server', '')), 18):<18} "
            f"{str(link.get('port', '')):>5}  "
            f"{_cell(str(link.get('security', '')), 7):<7} "
            f"{_cell(str(link.get('network', '')), 10):<10} "
            f"{latency:>7}  {','.join(state)}"
        )
    print(f"\n{len(profiles)} profile(s) in {store.path}")
    return 0


def _run_profile(args: argparse.Namespace, http_addr: str | None) -> int:
    """Connect a saved profile and serve until interrupted.

    Mirrors link mode's banner and interrupt behaviour so a script can move from
    ``--link`` to ``--profile`` without its exit codes changing.
    """
    store = _load_store()
    secrets = _secret_backend()
    # Resolve first so an unknown reference gets a message that says what to do.
    # The reference itself is argv and is never echoed: a user could type
    # anything, including a link, and this program does not put argv in errors.
    try:
        resolved = store.resolve(args.profile)
    except AppError:
        raise AppError(
            "no saved profile matches that reference; run --list to see what is saved."
        ) from None
    xray = resolve_xray(args.xray, update=args.update_xray)
    print(f"Using Xray executable: {xray}")
    service = ProxyService(store, secrets, xray, socks_addr=args.socks, http_addr=http_addr)
    print(f"Starting local proxy for profile {resolved.label!r}…", flush=True)
    try:
        # By id, not by the original ref: the ref has been resolved once already
        # and a label lookup could in principle match a different profile.
        service.connect(resolved.id)
    except AppError as exc:
        # Stop before reporting. Most failures happen inside the D7 validate
        # step, where nothing was started and `disconnect` is a no-op; but a
        # failure *after* the switch succeeded -- a store write can fail once
        # the tunnel is already live -- would otherwise exit this process with a
        # child still holding its listeners. Nothing else is using them: this is
        # a fresh run with no previous tunnel to protect, unlike the TUI.
        try:
            service.disconnect()
        except Exception:  # noqa: BLE001 - cleanup must never mask the real error
            pass
        _report_failure(exc, service.log_tail())
        return 2
    return _supervise_until_stopped(
        is_running=lambda: service.running,
        stop=service.disconnect,
        log_tail=service.log_tail,
        socks_addr=args.socks,
        http_addr=http_addr,
    )


def _run_link(args: argparse.Namespace, http_addr: str | None) -> int:
    """The V0 path: one link from a flag, a file, or stdin, then serve.

    Behaviour-preserving on purpose. In particular the order of operations is
    unchanged -- parse, build config, reject identical listeners, *then* resolve
    the binary -- so a bad address fails before a download is attempted, exactly
    as before.
    """
    raw = _read_link_source(args)
    parsed = parse_vless_uri(raw, allow_insecure=args.allow_insecure)
    # Drop the raw credential-bearing URI promptly.
    del raw
    config = build_xray_config(parsed, args.socks, http_addr)
    _reject_identical_listeners(args.socks, http_addr)
    xray = resolve_xray(args.xray, update=args.update_xray)
    print(f"Using Xray executable: {xray}")
    if args.check:
        _check_config(xray, config)
        print(
            "VLESS link parsed and Xray configuration validated. "
            "This does not test reachability of the remote server."
        )
        return 0
    print("Starting local proxy…", flush=True)
    process = XrayProcess(xray, socks_addr=args.socks, http_addr=http_addr)
    try:
        process.apply(parsed)
    except AppError as exc:
        _report_failure(exc, process.last_log)
        return 2
    return _supervise_until_stopped(
        is_running=lambda: process.running,
        stop=process.stop,
        log_tail=lambda: process.last_log,
        socks_addr=args.socks,
        http_addr=http_addr,
    )


def _run_tui(args: argparse.Namespace, http_addr: str | None) -> int:
    """Launch the Textual UI over the same service the headless modes use.

    The UI is *not* told to reconnect the last active profile. `c` reconnects it
    from the recorded id, and starting a tunnel the moment a window opens would
    move the user's traffic without being asked -- the same objection that killed
    automatic failover in decision D5. `connect_active()` exists on the service
    for a caller that wants that policy.
    """
    if not sys.stdin.isatty():
        raise AppError(
            "The Textual UI needs an interactive terminal. "
            "Use --link, --link-file, or --profile for headless use."
        )
    store = _load_store()
    secrets = _secret_backend()
    xray = resolve_xray(args.xray, update=args.update_xray)
    service = ProxyService(store, secrets, xray, socks_addr=args.socks, http_addr=http_addr)
    app = _build_app(
        service,
        store,
        secrets=secrets,
        allow_insecure=args.allow_insecure,
        socks_addr=args.socks,
        http_addr=http_addr,
        xray_version=_xray_version_label(xray),
    )
    app.run()
    return 0


def _build_app(
    service: ProxyService,
    store: ProfileStore,
    *,
    secrets: SecretStore,
    allow_insecure: bool,
    socks_addr: str,
    http_addr: str | None,
    xray_version: str | None,
) -> Any:
    """Construct :class:`VlessApp`, importing Textual lazily.

    Two things must be passed explicitly, and both are silent failures if they are
    not:

    * ``secrets`` -- ``ProxyService`` does not re-expose its backend, so an app
      built without it reports add/edit/delete as "No secret backend is
      available".
    * ``socks_addr`` / ``http_addr`` -- the same applies to the ports; the status
      bar would otherwise display ``ProxyService``'s defaults while the listeners
      were somewhere else. ``http_addr=None`` is meaningful ("no HTTP listener"),
      which is why it is passed as-is rather than defaulted.
    """
    try:
        from .tui.app import VlessApp
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise AppError("The Textual UI needs the 'textual' package: pip install textual") from exc
    return VlessApp(
        service,
        store,
        secrets=secrets,
        allow_insecure=allow_insecure,
        socks_addr=socks_addr,
        http_addr=http_addr,
        xray_version=xray_version,
    )


# --------------------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------------------


def _load_store() -> ProfileStore:
    """Load ``profiles.json`` from its default location.

    Every front-end goes through here rather than constructing its own, so the
    store is read once per run and a malformed file fails the same way in every
    mode.
    """
    store = ProfileStore()
    store.load()
    return store


def _secret_backend() -> SecretStore:
    """Pick the secret backend for this platform.

    macOS gets the real Keychain. Anywhere else gets ``NullSecretStore``, which
    fails closed on every read, plus a loud warning -- never a silent pretend.
    A user on an unsupported platform can still list profiles and read errors;
    they just cannot connect, and they are told so on stderr rather than finding
    out from an opaque Keychain failure later. Decision D6 chose macOS-only, so
    this is the supported-platform guard, not a best-effort fallback.
    """
    global _warned_no_keychain
    if sys.platform == "darwin":
        return MacOSKeychain()
    if not _warned_no_keychain:
        _warned_no_keychain = True
        print(
            f"{APP_NAME}: no secret backend on {sys.platform} — profiles can be listed "
            "but not connected. UUIDs are stored in the macOS Keychain; there is no "
            "equivalent here, so this build refuses to keep them anywhere else.",
            file=sys.stderr,
        )
    return NullSecretStore()


def _report_failure(exc: BaseException, tail: str) -> None:
    """Print a failure and, underneath it, the output that explains it.

    ``XrayProcess`` cannot print: it runs under a TUI that would be corrupted by
    a child writing to the console. So the reason a switch failed lives only in
    ``last_log``, and an error message that refers to "the preceding Xray error"
    would point at nothing. Printing the tail here is what makes the failure
    diagnosable. The tail is already redacted upstream; the URI filter below is
    belt-and-braces for the ``--check`` path, which builds its own output.
    """
    print(f"{APP_NAME}: {exc}", file=sys.stderr)
    _print_log_tail(tail)


def _print_log_tail(tail: str) -> None:
    """Print the supervisor's captured output, if there is any."""
    text = _redact(tail)
    if text.strip():
        print("--- Xray output ---", file=sys.stderr)
        print(text.rstrip(), file=sys.stderr)
        print("--------------------", file=sys.stderr)


def _redact(text: str) -> str:
    """Strip UUID and ``vless://`` shapes out of text bound for a terminal."""
    return _UUID_IN_TEXT_RE.sub("<redacted-uuid>", _URI_IN_TEXT_RE.sub("<redacted-uri>", text))


def _supervise_until_stopped(
    *,
    is_running: Callable[[], bool],
    stop: Callable[[], None],
    log_tail: Callable[[], str],
    socks_addr: str,
    http_addr: str | None,
) -> int:
    """Block while the proxy serves; return the process exit code for the shell.

    ``XrayProcess`` publishes ``running`` rather than a blocking ``wait``, which
    is the right seam for a TUI worker and slightly awkward here: this loop polls
    every ``_POLL_SECONDS``. Twenty-five milliseconds of a property call is free,
    and the alternative -- reaching past the supervisor for the child -- would
    break the boundary that lets a hot-swap implementation replace it.

    Ctrl+C stops the proxy and returns 0, which is the V0 behaviour: a deliberate
    stop is a success, not a cancellation. A Ctrl+C *before* the proxy is running
    (during download, parse, or validation) is not caught here and becomes 130 in
    :func:`main`. A child that dies on its own is a failure, and its output is
    printed because nothing else will ever show it.
    """
    print("\nProxy is ready.")
    print(f"  SOCKS5: {socks_addr}")
    if http_addr:
        print(f"  HTTP:   http://{http_addr}")
    print("Only applications explicitly configured to use these endpoints will use VLESS.")
    print("Press Ctrl+C to stop.\n", flush=True)
    try:
        while is_running():
            time.sleep(_POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nStopping proxy…", flush=True)
        stop()
        return 0
    stop()
    # The child died by itself. Whatever it said is now unreachable -- there is no
    # log pane on a terminal -- so it is printed here or not at all.
    print(f"{APP_NAME}: the Xray process exited unexpectedly.", file=sys.stderr)
    _print_log_tail(log_tail())
    return 1


def _read_link_source(args: argparse.Namespace) -> str:
    """Return the raw link text from ``--link-file``, ``--link``, or stdin.

    Unchanged from V0, including the ordering of the three checks on a link file:
    stat, then type/size, then permission. The permission check is the point of
    recommending ``--link-file`` at all -- a world-readable credential file is
    not private no matter how carefully the rest of this program behaves.
    """
    if args.link_file:
        path = Path(args.link_file).expanduser()
        try:
            st = path.stat()
        except OSError:
            raise AppError("Could not open the VLESS link file.") from None
        if not path.is_file() or st.st_size > MAX_URI_BYTES:
            raise AppError("VLESS link file must be a regular file no larger than 16 KiB.")
        if os.name != "nt" and st.st_mode & 0o077:
            raise AppError("VLESS link file is accessible by group/others; run chmod 600 on it.")
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            # V0 let a non-UTF-8 file escape as an uncaught UnicodeDecodeError,
            # which prints a traceback rather than a message. Same rejection, said
            # the way every other failure here is said.
            raise AppError("Could not read the VLESS link file as UTF-8 text.") from None
    if args.link:
        print(
            "Warning: --link may be visible to local process inspection; "
            "use --link-file for privacy.",
            file=sys.stderr,
        )
        return args.link
    if not sys.stdin.isatty():
        raise AppError("Run interactively to paste your VLESS link, or pass --link-file PATH.")
    print("Paste your complete VLESS link (vless://...) and press Enter.", flush=True)
    return input("> ").strip()


def _check_config(xray: Path, config: dict[str, Any]) -> None:
    """Run ``xray run -test`` on a generated config without starting anything.

    The one code path here that drives the binary directly instead of through
    :class:`XrayProcess`, because that class deliberately has no validate-only
    entry point -- ``apply`` either ends with a running proxy or not at all. The
    cost is a small amount of duplicated plumbing (a private config file, one
    subprocess call), which is why the output is redacted here: it is the only
    place in the project where a child's stream is captured by hand.

    The child's own explanation is printed to stderr *before* the AppError
    propagates, which is V0's ordering and is deliberate. The reason is also kept
    out of the exception text, so an AppError message stays as link-free as every
    other one in the project even though this one has real subprocess output
    attached to it.
    """
    runtime, config_path = _write_private_config(config)
    try:
        try:
            test = subprocess.run(
                [str(xray), "run", "-test", "-config", str(config_path)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
        except OSError:
            raise AppError("Could not execute the Xray binary.") from None
        output = _redact(test.stdout or "")
    finally:
        runtime.cleanup()
    if test.returncode != 0:
        # Show the reason inline: on a terminal there is no log pane to defer to.
        if output.strip():
            print("--- Xray output ---", file=sys.stderr)
            print(output.rstrip(), file=sys.stderr)
            print("--------------------", file=sys.stderr)
        raise AppError("Xray rejected the generated configuration.")


def _write_private_config(config: dict[str, Any]) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    """Write ``config`` to a ``0600`` file in a ``0700`` directory under app data.

    Mirrors ``XrayProcess._write_config``, which is private. The config carries the
    UUID, so the permissions are the security property and they are not negotiable;
    the ``TemporaryDirectory`` object is returned as well as the path because the
    caller must keep it alive for as long as the file is needed.
    """
    data_dir = app_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(data_dir, 0o700)
    runtime = tempfile.TemporaryDirectory(prefix="runtime-", dir=data_dir)
    try:
        os.chmod(runtime.name, 0o700)
        config_path = Path(runtime.name) / "config.json"
        config_path.write_text(
            json.dumps(config, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
        )
        os.chmod(config_path, 0o600)
    except OSError:
        runtime.cleanup()
        raise
    return runtime, config_path


def _xray_version_label(xray: Path) -> str | None:
    """Derive a display version from the install path, e.g. ``v26.3.27``.

    A directory name rather than running ``xray version``: the status bar is
    decoration, and spawning a subprocess to decorate it would add a failure mode
    and a launch delay to every UI start.
    """
    tag = xray.parent.name
    return tag if _VERSION_TAG_RE.match(tag) else None


def _cell(value: str, width: int) -> str:
    """Truncate a table cell so one long label cannot break the column layout."""
    text = value if len(value) <= width else value[: width - 1] + "…"
    return text.replace("\n", " ").replace("\t", " ")


# --------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Parse ``argv`` and run the selected front-end.

    Exit codes are V0's and are contractual for scripts:

    * ``0`` -- served until interrupted, or a successful ``--check`` / ``--list``.
    * ``1`` -- an unexpected OS/JSON/zip failure. Distinct from 2 on purpose:
      2 means "you asked for something impossible", 1 means "the machine
      misbehaved".
    * ``2`` -- an :class:`AppError`: a rejected link, an unknown profile, a
      duplicate port, an unwritable store.
    * ``130`` -- interrupted by Ctrl+C before anything was serving.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except AppError as exc:
        print(f"{APP_NAME}: {exc}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"{APP_NAME}: operation failed ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())