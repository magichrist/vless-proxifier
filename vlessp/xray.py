"""Xray binary acquisition and process supervision. Everything here is subprocess-based.

Two jobs, deliberately kept together because they share one external program:

1. Getting an Xray binary that is verifiably the official one — HTTPS-only, host
   allowlisted, size capped, SHA-256 checked against the upstream ``.dgst``, and
   the executable pulled out of the zip by basename rather than extracted.
2. Supervising one long-lived Xray process and switching it between profiles in
   the order that guarantees a bad profile never takes down a working tunnel.

``XrayProcess`` is the project's switching seam (decision D3). Everything above it
talks to this class and nothing else; a future zero-downtime hot-swap satisfies
the same four members and requires no change above.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import deque
from pathlib import Path
from typing import IO, Any

from . import APP_NAME
from .errors import AppError
from .links import build_xray_config

GITHUB_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024

# Vendored Xray builds are deliberately NOT committed to this repo -- a 34 MB
# stripped Go binary in permanent git history is not worth the convenience, and
# the directories are gitignored. A local copy is still *used* when one sits
# next to the repo, because it makes an offline run instant and skips a 40 MB
# download.
#
# The catch: a vendored binary cannot be verified the way a downloaded one is,
# since there is no upstream .dgst to check it against at runtime. So it is only
# adopted when its SHA-256 matches a build pinned here, and an unrecognised
# binary is silently ignored in favour of a freshly downloaded one. The
# downloader stays the source of truth; vendoring is a cache it happens to
# satisfy.
_BUNDLED_SHA256 = frozenset({
    # v26.3.27, verified against the official Xray-macos-arm64-v8a.zip.dgst
    "5d9dd24c0aba4b6cfcc6a33a5d67f854816ee17f392bf932ec8176da46f7e404",
})
_BUNDLED_DIR_NAMES = (
    "xray-macos-arm64-v8a", "xray-macos-arm64", "xray-macos-64",
    "xray-linux-arm64-v8a", "xray-linux-64",
)

# Hosts we are willing to end up talking to after a redirect. Release metadata
# points at github.com; the actual bytes come from the release-assets CDN.
_DOWNLOAD_HOSTS = {"api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}

# Bounds for the stderr/stdout tail kept in memory. Xray is chatty and this is a
# log pane, not an audit log: a bounded ring means a long-running proxy cannot
# grow the process's memory without limit.
LOG_TAIL_LINES = 200
LOG_TAIL_BYTES = 16 * 1024

_GRACE_SECONDS = 4.0
_KILL_SECONDS = 2.0

__all__ = [
    "GITHUB_API",
    "MAX_DOWNLOAD_BYTES",
    "XrayProcess",
    "app_data_dir",
    "find_latest_release_asset",
    "install_xray",
    "platform_asset",
    "request_bytes",
    "resolve_xray",
    "wait_for_listener",
]


def app_data_dir() -> Path:
    """Return the per-user data directory, without creating it.

    Creating it is a side effect each caller performs explicitly, because the
    permissions it will be created with matter and are asserted at the point of
    creation rather than inferred here.
    """
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME


def request_bytes(url: str, *, limit: int, timeout: float = 30.0, json_api: bool = False) -> bytes:
    """Fetch a URL into memory, refusing anything that is not an official, bounded download.

    Three controls live here and nowhere else: the connection must be HTTPS, the
    host we end up on after redirects must be on the allowlist, and the body
    must not exceed ``limit`` — checked against the declared Content-Length and
    again while streaming, since the header is a claim, not a fact.

    Errors are reported by shape (``type(exc).__name__``), never by echoing the
    URL's contents, so no part of a download can reach a log line.
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "vless-python-proxy/1.0",
            "Accept": "application/vnd.github+json" if json_api else "application/octet-stream",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                raise AppError(f"Download failed with HTTP status {response.status}.")
            final_url = urllib.parse.urlparse(response.geturl())
            allowed_final_hosts = _DOWNLOAD_HOSTS
            if final_url.scheme != "https" or final_url.hostname not in allowed_final_hosts:
                raise AppError("Download redirected to an unexpected host; refusing to continue.")
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > limit:
                raise AppError("Download is larger than the configured size limit.")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(min(1024 * 1024, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise AppError("Download is larger than the configured size limit.")
                chunks.append(chunk)
            return b"".join(chunks)
    except AppError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise AppError(f"Could not download from the official Xray release service ({type(exc).__name__}). Check your internet connection or use --xray with an existing binary.") from None


def platform_asset() -> str:
    """Return the release asset filename for this machine.

    Refuses anything not explicitly mapped rather than guessing: installing the
    wrong architecture would fail confusingly much later, at run time.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin" and machine in {"arm64", "aarch64"}:
        return "Xray-macos-arm64-v8a.zip"
    if system == "darwin" and machine in {"x86_64", "amd64"}:
        return "Xray-macos-64.zip"
    if system == "linux" and machine in {"aarch64", "arm64"}:
        return "Xray-linux-arm64-v8a.zip"
    if system == "linux" and machine in {"x86_64", "amd64"}:
        return "Xray-linux-64.zip"
    raise AppError(f"Automatic Xray install is not configured for {platform.system()} {platform.machine()}; provide --xray /path/to/xray.")


def find_latest_release_asset(asset_name: str) -> tuple[str, str, str]:
    """Resolve the latest stable release to (tag, archive_url, digest_url).

    Refuses drafts and pre-releases — an automatic installer should never hand a
    user an unreviewed binary — and re-checks each URL's scheme and host before
    it is handed to the downloader, so a compromised or spoofed API response
    cannot redirect the download.
    """
    raw = request_bytes(GITHUB_API, limit=5 * 1024 * 1024, json_api=True)
    try:
        release = json.loads(raw)
        tag = release["tag_name"]
        assets = {item["name"]: item["browser_download_url"] for item in release["assets"]}
    except (KeyError, TypeError, json.JSONDecodeError):
        raise AppError("The official Xray release response had an unexpected format.") from None
    if release.get("draft") or release.get("prerelease"):
        raise AppError("GitHub returned a draft or pre-release; refusing automatic install.")
    archive_url = assets.get(asset_name)
    digest_url = assets.get(asset_name + ".dgst")
    if not archive_url or not digest_url:
        raise AppError(f"The latest stable Xray release ({tag}) does not contain the expected asset {asset_name} and its .dgst file.")
    for url in (archive_url, digest_url):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}:
            raise AppError("Unexpected download host in release metadata; refusing download.")
    return tag, archive_url, digest_url


def install_xray(*, force: bool = False) -> Path:
    """Download, verify, and install the official Xray binary; return its path.

    Nothing is installed until the archive's SHA-256 matches the ``.dgst`` file
    published next to it, so a tampered mirror or a corrupted transfer cannot
    produce a working-looking executable. The install is staged in a temporary
    directory and moved into place with a rename, which is atomic within a
    filesystem — an interrupted install never leaves a half-written binary that a
    later run would treat as cached.

    ``force`` skips the cached-version and already-installed-binary short cuts.
    """
    asset_name = platform_asset()
    root = app_data_dir() / "xray"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)

    current_file = root / "current-version.txt"
    if not force and current_file.is_file():
        cached_tag = current_file.read_text(encoding="utf-8").strip()
        if cached_tag and re.fullmatch(r"v?[A-Za-z0-9._-]{1,64}", cached_tag):
            cached_binary = root / cached_tag / "xray"
            if cached_binary.is_file() and os.access(cached_binary, os.X_OK):
                return cached_binary

    tag, archive_url, digest_url = find_latest_release_asset(asset_name)
    install_dir = root / tag
    xray_path = install_dir / "xray"
    if xray_path.is_file() and os.access(xray_path, os.X_OK) and not force:
        current_file.write_text(tag + "\n", encoding="utf-8")
        os.chmod(current_file, 0o600)
        return xray_path

    print(f"Downloading official Xray-core {tag} for {asset_name.removesuffix('.zip')}…", flush=True)
    archive = request_bytes(archive_url, limit=MAX_DOWNLOAD_BYTES)
    digest_text = request_bytes(digest_url, limit=128 * 1024).decode("utf-8", errors="replace")
    # Upstream .dgst manifests contain lines like: SHA256 (filename.zip) = <hex>.
    expected: str | None = None
    for line in digest_text.splitlines():
        if "SHA256" in line.upper() and asset_name in line:
            match = re.search(r"([0-9a-fA-F]{64})\s*$", line)
            if match:
                expected = match.group(1).lower()
                break
    if not expected:
        raise AppError("Could not find the archive's SHA-256 in the official .dgst file; refusing to install it.")
    actual = hashlib.sha256(archive).hexdigest()
    if actual.lower() != expected:
        raise AppError("Xray archive SHA-256 verification failed; the file was not installed.")

    temp_dir = Path(tempfile.mkdtemp(prefix=".xray-install-", dir=root))
    try:
        binary: bytes | None = None
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            for item in zf.infolist():
                # Only read the expected binary by basename; never extract arbitrary paths.
                if Path(item.filename).name == "xray" and not item.is_dir():
                    if item.file_size > 100 * 1024 * 1024:
                        raise AppError("Xray binary in archive exceeds the size limit.")
                    binary = zf.read(item)
                    break
        # Explicit parentheses: `and` binds tighter than `or`, so the bare chain
        # happened to be correct but read as if it were not. Accept ELF, or Mach-O
        # 64-bit in either byte order.
        if (
            not binary
            or not binary.startswith(b"\x7fELF")
            and not binary.startswith(b"\xcf\xfa\xed\xfe")
            and not binary.startswith(b"\xfe\xed\xfa\xcf")
        ):
            raise AppError("The downloaded archive did not contain a recognizable Xray executable.")
        os.chmod(temp_dir, 0o700)
        temp_binary = temp_dir / "xray"
        temp_binary.write_bytes(binary)
        os.chmod(temp_binary, 0o700)
        install_dir_tmp = root / (tag + ".installing")
        if install_dir_tmp.exists():
            shutil.rmtree(install_dir_tmp)
        install_dir_tmp.mkdir(mode=0o700)
        shutil.copy2(temp_binary, install_dir_tmp / "xray")
        os.chmod(install_dir_tmp / "xray", 0o700)
        if install_dir.exists():
            shutil.rmtree(install_dir)
        install_dir_tmp.rename(install_dir)
        current_file.write_text(tag + "\n", encoding="utf-8")
        os.chmod(current_file, 0o600)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    return xray_path


def wait_for_listener(process: subprocess.Popen[bytes], addresses: list[str], timeout: float = 10.0) -> None:
    """Block until every address accepts a TCP connection, or raise AppError.

    A spawned process is not a working proxy. This is the readiness gate: it also
    detects the case where Xray exited immediately, and reports the exit code
    rather than timing out on a port that will never open.
    """
    deadline = time.monotonic() + timeout
    last_error = "not listening yet"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AppError(f"Xray exited before opening the local proxy (exit code {process.returncode}). Check the Xray output above.")
        all_ready = True
        for address in addresses:
            host, port_s = address.rsplit(":", 1)
            try:
                with socket.create_connection((host.strip("[]"), int(port_s)), timeout=0.25):
                    pass
            except OSError as exc:
                all_ready = False
                last_error = str(exc)
                break
        if all_ready:
            return
        time.sleep(0.15)
    raise AppError(f"Xray did not open the requested local port(s) within {timeout:.0f}s ({last_error}). Check the Xray output above.")


def repo_root() -> Path:
    """The checkout this module lives in. Vendored binaries are looked up beside it."""
    return Path(__file__).resolve().parent.parent


def _sha256_file(path: Path) -> str:
    """Stream a file through SHA-256.

    Streamed rather than read whole: the thing being hashed is a 34 MB binary,
    and reading it into memory to compare one hash is a needless spike.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _warn_if_quarantined(path: Path) -> None:
    """Warn when macOS will block the binary before we hand it to subprocess.

    A binary that arrived through a browser carries ``com.apple.quarantine`` and
    the kernel stops it dead -- or, worse, blocks the spawning process on a
    Gatekeeper prompt that nobody sees when the launch came from a TUI. That
    failure is very hard to read, so name it up front.
    """
    if sys.platform != "darwin":
        return
    try:
        result = subprocess.run(
            ["xattr", "-p", "com.apple.quarantine", str(path)],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return
    if result.returncode == 0 and result.stdout.strip():
        print(
            f"note: {path.name} is quarantined and macOS may refuse to run it. Clear it with:\n"
            f"  xattr -dr com.apple.quarantine {path.parent}",
            file=sys.stderr,
        )


def bundled_xray() -> Path | None:
    """Return a hash-verified vendored Xray beside the repo, or ``None``.

    An unrecognised binary is never executed. Falling through to the downloader
    is slower but correct, and the user is never left running something this
    project cannot vouch for.
    """
    root = repo_root()
    name = "xray.exe" if os.name == "nt" else "xray"
    for directory in _BUNDLED_DIR_NAMES:
        candidate = root / directory / name
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        try:
            if _sha256_file(candidate) not in _BUNDLED_SHA256:
                continue
        except OSError:
            continue
        _warn_if_quarantined(candidate)
        return candidate
    return None


def resolve_xray(xray_arg: str | None, *, update: bool = False) -> Path:
    """Resolve the Xray executable to use, or install one.

    Precedence is explicit argument, then ``XRAY_BIN``, then a hash-verified
    vendored build beside the repo, then an automatic install of the latest
    stable release. An explicitly named binary is never downloaded over — if the
    user pointed at a path, that is the binary they want, and a silent
    replacement would be a surprise.

    ``update=True`` skips the vendored build, since the user asked to refresh
    from upstream and honouring a stale local copy would ignore that.

    Takes plain values rather than an ``argparse.Namespace`` so it can be called
    (and tested) from a TUI or the profile layer with no CLI in the picture.
    """
    candidate = xray_arg or os.environ.get("XRAY_BIN")
    if candidate:
        path = Path(candidate).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise AppError(f"Xray executable not found or not executable: {path}")
        return path
    if not update:
        bundled = bundled_xray()
        if bundled is not None:
            return bundled
    # Reuse installed version if one exists. For a first run, install the latest stable release.
    return install_xray(force=update)


_URI_IN_LOG_RE = re.compile(r"(?i)vless://\S+")
_UUID_IN_LOG_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


def _redact(text: str) -> str:
    """Strip credential shapes out of Xray's own output before it is displayed.

    ``last_log`` feeds a log pane that is written to disk and screenshotted, so it
    gets the same rule as every other log line in the project: no UUID, no link.
    Xray does not normally echo either, but it does print config snippets on some
    parse errors, and this is the cheap place to be certain.
    """
    return _UUID_IN_LOG_RE.sub("<redacted-uuid>", _URI_IN_LOG_RE.sub("<redacted-uri>", text))


def _drain(stream: IO[bytes] | None, buffer: deque[str]) -> None:
    """Read a child process's output into ``buffer`` until EOF. Runs on its own thread.

    A bounded deque is the buffer: when it is full the oldest line is dropped, so
    a process that logs all day cannot grow this process's memory.
    """
    if stream is None:
        return
    try:
        for line in iter(stream.readline, b""):
            buffer.append(line.decode("utf-8", "replace").rstrip("\n"))
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _terminate(process: subprocess.Popen[bytes]) -> None:
    """Terminate a child, escalating to SIGKILL only if it ignores the polite request."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=_KILL_SECONDS)
        except subprocess.TimeoutExpired:
            pass  # Nothing further we can do; do not raise over a dying child.


class XrayProcess:
    """Supervises at most one Xray process and switches it between profiles.

    The whole point of this class is ``apply``'s ordering (decision D7). A typo in
    a new profile is caught by ``xray run -test`` *before* the working process is
    touched, so a failed switch leaves the current tunnel up and serving. Only
    after the new config is known good is the old process stopped, and if the new
    one never opens its ports it is stopped again rather than left half-alive.

    One instance is owned by one thread at a time (``ProxyService`` serializes
    switches), but an internal lock makes a double-apply safe rather than racy.
    """

    def __init__(self, xray_path: Path, *, socks_addr: str, http_addr: str | None) -> None:
        self._xray_path = xray_path
        self._socks_addr = socks_addr
        self._http_addr = http_addr
        self._process: subprocess.Popen[bytes] | None = None
        self._reader: threading.Thread | None = None
        self._runtime: tempfile.TemporaryDirectory[str] | None = None
        self._log: deque[str] = deque(maxlen=LOG_TAIL_LINES)
        self._lock = threading.RLock()

    @property
    def running(self) -> bool:
        """True while a child process is alive and serving.

        A process that died on its own reports False immediately, even though its
        handle is not cleaned up until the next ``apply`` or ``stop``.
        """
        return self._process is not None and self._process.poll() is None

    @property
    def last_log(self) -> str:
        """The redacted tail of the current process's output, for a log pane.

        Also carries the output of the most recent failed ``-test``, so a rejected
        profile leaves its reason behind after the switch aborts.
        """
        with self._lock:
            text = "\n".join(self._log)
        text = _redact(text)
        return text[-LOG_TAIL_BYTES:]

    def apply(self, link: dict[str, Any]) -> None:
        """D7 ordered switch: build config -> xray -test -> stop old -> spawn -> wait.

        Raises AppError on any failure. MUST NOT leave a half-started process.
        If -test fails, the currently-running process is untouched and still serving.
        """
        with self._lock:
            # 1. Pure: may raise for a bad listener address, before anything exists.
            config = build_xray_config(link, self._socks_addr, self._http_addr)
            # 2. The config carries the UUID, so it gets a private directory and 0600.
            try:
                runtime, config_path = self._write_config(config)
            except OSError:
                # The contract is that apply() only ever raises AppError, so an
                # unwritable app data directory is reported in the same terms.
                raise AppError("Could not write the private Xray runtime configuration.") from None
            try:
                # 3. Validate first. If this raises, the old process is untouched
                #    and still serving — the reason the ordering is this way.
                self._validate(config_path)
            except BaseException:
                runtime.cleanup()
                raise
            # 4. Only now is the working tunnel at risk.
            self.stop()
            try:
                process = self._spawn(config_path)  # 5
            except OSError:
                runtime.cleanup()
                raise AppError("Could not start the Xray process.") from None
            try:
                # 6. Readiness gate; a timeout must not leave a process behind.
                wait_for_listener(process, self._addresses())
            except BaseException:
                _terminate(process)
                self._close_reader()
                runtime.cleanup()
                raise
            self._runtime = runtime
            self._process = process

    def stop(self) -> None:
        """Idempotent. Terminate (4s grace) then kill (2s grace)."""
        with self._lock:
            self._teardown()

    def _addresses(self) -> list[str]:
        return [self._socks_addr] + ([self._http_addr] if self._http_addr else [])

    def _write_config(self, config: dict[str, Any]) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        """Write the config to a 0600 file inside a 0700 directory under the app data dir.

        Returns the ``TemporaryDirectory`` object as well as the path: the caller
        must keep it alive for as long as the process that reads the file, or the
        directory (and config) would be deleted out from under it.
        """
        data_dir = app_data_dir()
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(data_dir, 0o700)
        runtime = tempfile.TemporaryDirectory(prefix="runtime-", dir=data_dir)
        try:
            os.chmod(runtime.name, 0o700)
            config_path = Path(runtime.name) / "config.json"
            config_path.write_text(json.dumps(config, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            os.chmod(config_path, 0o600)
        except OSError:
            # Deterministic cleanup: relying on the TemporaryDirectory finalizer
            # would leave the directory behind until the GC got round to it.
            runtime.cleanup()
            raise
        return runtime, config_path

    def _validate(self, config_path: Path) -> None:
        """Run ``xray run -test``; raise AppError if Xray rejects the config.

        The rejection output is kept in the log tail instead of being printed: this
        class is driven from TUI worker threads, where writing to the console would
        corrupt the interface. The CLI prints ``last_log`` on failure.
        """
        try:
            test = subprocess.run(
                [str(self._xray_path), "run", "-test", "-config", str(config_path)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except OSError:
            raise AppError(f"Could not execute the Xray binary at {self._xray_path}.") from None
        output = test.stdout.decode("utf-8", "replace")
        for line in output.splitlines():
            self._log.append(line)
        if test.returncode != 0:
            raise AppError("Xray rejected the generated configuration. Review the preceding Xray error; the link itself is not printed.")

    def _spawn(self, config_path: Path) -> subprocess.Popen[bytes]:
        """Start Xray on the validated config and begin draining its output.

        stdout and stderr are merged into one pipe: Xray logs to both depending on
        version, and one reader thread is simpler than two.
        """
        self._log.clear()
        process = subprocess.Popen(
            [str(self._xray_path), "run", "-config", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._reader = threading.Thread(
            target=_drain,
            args=(process.stdout, self._log),
            name="vlessp-xray-log",
            daemon=True,
        )
        self._reader.start()
        return process

    def _teardown(self) -> None:
        """Drop the current process, its reader, and its private config directory."""
        process, self._process = self._process, None
        runtime, self._runtime = self._runtime, None
        if process is not None:
            _terminate(process)
        self._close_reader()
        if runtime is not None:
            runtime.cleanup()

    def _close_reader(self) -> None:
        reader, self._reader = self._reader, None
        if reader is not None:
            # Bounded: EOF arrives once the child is gone; the join timeout exists
            # only so a wedged read can never block a switch.
            reader.join(timeout=_KILL_SECONDS)