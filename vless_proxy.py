#!/usr/bin/env python3
"""Python launcher for a local VLESS -> Xray -> SOCKS5/HTTP proxy.

The control plane, URI parser, config generation, download verification, and
process lifecycle are Python. Actual VLESS transport is handled by the official
prebuilt Xray-core executable; no Go compiler/toolchain is required.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

APP_NAME = "vless-python-proxy"
GITHUB_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
MAX_URI_BYTES = 16 * 1024
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
UUID_RE = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"(?i)^[0-9a-f]{64}$")


class AppError(Exception):
    """Expected, user-facing error that does not disclose the link."""


def app_data_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME


def request_bytes(url: str, *, limit: int, timeout: float = 30.0, json_api: bool = False) -> bytes:
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
            allowed_final_hosts = {"api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
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
        with zipfile.ZipFile(__import__("io").BytesIO(archive)) as zf:
            for item in zf.infolist():
                # Only read the expected binary by basename; never extract arbitrary paths.
                if Path(item.filename).name == "xray" and not item.is_dir():
                    if item.file_size > 100 * 1024 * 1024:
                        raise AppError("Xray binary in archive exceeds the size limit.")
                    binary = zf.read(item)
                    break
        if not binary or not binary.startswith(b"\x7fELF") and not binary.startswith(b"\xcf\xfa\xed\xfe") and not binary.startswith(b"\xfe\xed\xfa\xcf"):
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


def is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253 or host.endswith("."):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return all(1 <= len(label) <= 63 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) for label in labels)


def query_params(query: str) -> dict[str, str]:
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=128)
    except (ValueError, UnicodeError):
        raise AppError("Malformed VLESS query parameters.") from None
    result: dict[str, str] = {}
    for key, value in pairs:
        if key in result:
            raise AppError(f"Duplicate VLESS parameter {key!r} is ambiguous.")
        if len(key) > 64 or len(value.encode("utf-8")) > 4096:
            raise AppError(f"VLESS parameter {key!r} is too long.")
        result[key] = value
    aliases = [("type", "network"), ("sni", "serverName"), ("fp", "fingerprint"), ("pcs", "pinnedPeerCertSha256"), ("pbk", "publicKey"), ("sid", "shortId")]
    for first, second in aliases:
        if first in result and second in result and result[first] != result[second]:
            raise AppError(f"Conflicting aliases for {first!r} and {second!r}.")
    if "insecure" in result and "allowInsecure" in result:
        truthy = {"1", "true", "yes"}
        falsy = {"0", "false", "no"}
        a, b = result["insecure"].lower(), result["allowInsecure"].lower()
        if a not in truthy | falsy or b not in truthy | falsy or (a in truthy) != (b in truthy):
            raise AppError("Conflicting or invalid insecure/allowInsecure parameters.")
    return result


def parse_vless_uri(raw: str, *, allow_insecure: bool = False) -> dict[str, Any]:
    raw = raw.strip()
    if not raw or len(raw.encode("utf-8")) > MAX_URI_BYTES:
        raise AppError("VLESS link is empty or exceeds the 16 KiB input limit.")
    if any(ord(c) < 0x20 for c in raw):
        raise AppError("VLESS link contains control characters.")
    try:
        url = urllib.parse.urlsplit(raw)
    except ValueError:
        raise AppError("Invalid VLESS URI syntax.") from None
    if url.scheme.lower() != "vless" or not url.username or url.password is not None:
        raise AppError("Expected vless://UUID@host:port.")
    uuid = urllib.parse.unquote(url.username)
    if not UUID_RE.fullmatch(uuid):
        raise AppError("Invalid VLESS UUID; expected canonical UUID format.")
    try:
        host = url.hostname or ""
        port = url.port
    except ValueError:
        raise AppError("Invalid VLESS host or port.") from None
    if not is_valid_hostname(host):
        raise AppError("VLESS server host is not a valid hostname or IP address.")
    if port is None or not 1 <= port <= 65535:
        raise AppError("VLESS server port must be between 1 and 65535.")
    q = query_params(url.query)
    get = lambda *keys, default="": next((q[k] for k in keys if k in q), default)
    security = get("security", default="none").lower()
    network = get("type", "network", default="tcp").lower()
    if security not in {"none", "tls", "reality"}:
        raise AppError(f"Unsupported security mode {security!r}; supported modes are none, tls, and reality.")
    if network not in {"tcp", "ws", "grpc", "httpupgrade", "xhttp"}:
        raise AppError(f"Unsupported transport {network!r}.")
    insecure_raw = get("allowInsecure", "insecure", default="0").lower()
    if insecure_raw not in {"0", "1", "false", "true", "no", "yes"}:
        raise AppError("The insecure/allowInsecure parameter must be a boolean.")
    insecure = insecure_raw in {"1", "true", "yes"}
    if insecure and not allow_insecure:
        raise AppError("The link disables TLS certificate verification. Use --allow-insecure only if you accept the security risk.")
    encryption = get("encryption", default="none")
    if not encryption:
        raise AppError("VLESS encryption parameter is empty.")
    sni = get("sni", "serverName")
    fingerprint = get("fp", "fingerprint")
    alpn = [item.strip() for item in get("alpn").split(",") if item.strip()]
    if sni and not is_valid_hostname(sni):
        raise AppError("Invalid SNI/serverName.")
    if security == "reality":
        if not sni or not fingerprint or not get("pbk", "publicKey"):
            raise AppError("Reality links require sni, fp, and pbk/publicKey parameters.")
    pin = get("pcs", "pinnedPeerCertSha256")
    if pin:
        for item in pin.split(","):
            if not SHA256_RE.fullmatch(item.replace(":", "").strip()):
                raise AppError("Certificate pin must be a 64-character SHA-256 hex digest.")
        if security != "tls":
            raise AppError("Certificate pinning in pcs is supported only with security=tls in this launcher.")
        if insecure:
            raise AppError("Do not combine disabled TLS verification with certificate pinning.")

    out: dict[str, Any] = {
        "server": host,
        "port": port,
        "uuid": uuid.lower(),
        "security": security,
        "network": network,
        "name": urllib.parse.unquote(url.fragment)[:128],
        "encryption": encryption,
        "sni": sni,
        "fingerprint": fingerprint,
        "alpn": alpn,
        "allow_insecure": insecure,
        "pins": ",".join(item.replace(":", "").strip().lower() for item in pin.split(",") if item.strip()) if pin else "",
        "flow": get("flow"),
        "path": get("path", default="/"),
        "host_header": get("host"),
        "headers": {},
        "grpc_service": get("serviceName", "service_name"),
        "grpc_authority": get("authority"),
        "grpc_multi_mode": get("multiMode").lower() in {"1", "true"},
        "httpupgrade_path": get("path", default="/"),
        "httpupgrade_host": get("host"),
        "xhttp_path": get("path", default="/"),
        "xhttp_host": get("host"),
        "xhttp_mode": get("mode"),
        "reality_public_key": get("pbk", "publicKey"),
        "reality_short_id": get("sid", "shortId"),
        "reality_spider_x": get("spx", "spiderX"),
    }
    if out["flow"] and out["flow"] != "xtls-rprx-vision":
        raise AppError("Unsupported VLESS flow; only xtls-rprx-vision is supported.")
    if out["flow"] and network != "tcp":
        raise AppError("VLESS Vision flow is only supported with TCP transport.")
    if network == "grpc":
        path_service = get("path").lstrip("/")
        if out["grpc_service"] and path_service and out["grpc_service"] != path_service:
            raise AppError("Conflicting gRPC serviceName and path values.")
        out["grpc_service"] = out["grpc_service"] or path_service
        out["grpc_authority"] = out["grpc_authority"] or out["host_header"]
    if network == "ws":
        headers_text = get("headers")
        if headers_text:
            try:
                headers = json.loads(headers_text)
            except json.JSONDecodeError:
                raise AppError("WebSocket headers must be valid JSON.") from None
            if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
                raise AppError("WebSocket headers must be a JSON object with string keys and values.")
            out["headers"] = headers
        if out["host_header"]:
            for existing in list(out["headers"]):
                if existing.lower() == "host":
                    del out["headers"][existing]
            out["headers"]["Host"] = out["host_header"]
    if network == "xhttp" and get("extra"):
        try:
            extra = json.loads(get("extra"))
        except json.JSONDecodeError:
            raise AppError("XHTTP extra parameter must be valid JSON.") from None
        if not isinstance(extra, dict):
            raise AppError("XHTTP extra parameter must be a JSON object.")
        out["xhttp_extra"] = extra
    if security == "reality":
        out["reality"] = True
    return out


def build_xray_config(link: dict[str, Any], socks_addr: str, http_addr: str | None) -> dict[str, Any]:
    inbounds: list[dict[str, Any]] = []
    tags: list[str] = []
    for tag, address, protocol in (("socks-in", socks_addr, "socks"), ("http-in", http_addr, "http")):
        if not address:
            continue
        host, sep, port_s = address.rpartition(":")
        if not sep or not host or not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
            raise AppError(f"Invalid local listener address for {tag}.")
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            raise AppError("Proxy listeners must bind to loopback only (127.0.0.1 or ::1).") from None
        if not ip.is_loopback:
            raise AppError("Proxy listeners must bind to loopback only (127.0.0.1 or ::1).")
        inbound: dict[str, Any] = {
            "tag": tag, "listen": str(ip), "port": int(port_s), "protocol": protocol,
            "settings": {"auth": "noauth", "udp": True, "userLevel": 0} if protocol == "socks" else {},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }
        inbounds.append(inbound)
        tags.append(tag)

    user: dict[str, Any] = {"id": link["uuid"], "encryption": link["encryption"] or "none"}
    if link["flow"]:
        user["flow"] = link["flow"]
    stream: dict[str, Any] = {"network": link["network"], "security": link["security"]}
    if link["security"] == "tls":
        tls: dict[str, Any] = {"allowInsecure": link["allow_insecure"]}
        if link["sni"]: tls["serverName"] = link["sni"]
        if link["fingerprint"]: tls["fingerprint"] = link["fingerprint"]
        if link["alpn"]: tls["alpn"] = link["alpn"]
        if link["pins"]: tls["pinnedPeerCertSha256"] = link["pins"]
        stream["tlsSettings"] = tls
    elif link["security"] == "reality":
        reality = {"serverName": link["sni"], "fingerprint": link["fingerprint"], "publicKey": link["reality_public_key"], "shortId": link["reality_short_id"]}
        if link["reality_spider_x"]: reality["spiderX"] = link["reality_spider_x"]
        stream["realitySettings"] = reality
    if link["network"] == "ws":
        ws: dict[str, Any] = {"path": link["path"] or "/"}
        if link["headers"]: ws["headers"] = link["headers"]
        stream["wsSettings"] = ws
    elif link["network"] == "grpc":
        grpc: dict[str, Any] = {"serviceName": link["grpc_service"], "multiMode": link["grpc_multi_mode"]}
        if link["grpc_authority"]: grpc["authority"] = link["grpc_authority"]
        stream["grpcSettings"] = grpc
    elif link["network"] == "httpupgrade":
        upgrade: dict[str, Any] = {"path": link["httpupgrade_path"] or "/"}
        if link["httpupgrade_host"]: upgrade["host"] = link["httpupgrade_host"]
        stream["httpupgradeSettings"] = upgrade
    elif link["network"] == "xhttp":
        xhttp: dict[str, Any] = {"path": link["xhttp_path"] or "/"}
        if link["xhttp_host"]: xhttp["host"] = link["xhttp_host"]
        if link["xhttp_mode"]: xhttp["mode"] = link["xhttp_mode"]
        if link.get("xhttp_extra") is not None: xhttp["extra"] = link["xhttp_extra"]
        stream["xhttpSettings"] = xhttp

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": link["server"], "port": link["port"], "users": [user]}]}, "streamSettings": stream},
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": tags, "outboundTag": "proxy"}]},
    }


def wait_for_listener(process: subprocess.Popen[bytes], addresses: list[str], timeout: float = 10.0) -> None:
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


def start_proxy(xray_path: Path, config: dict[str, Any], socks_addr: str, http_addr: str | None, *, check_only: bool = False) -> int:
    data_dir = app_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(data_dir, 0o700)
    with tempfile.TemporaryDirectory(prefix="runtime-", dir=data_dir) as temp:
        os.chmod(temp, 0o700)
        config_path = Path(temp) / "config.json"
        config_path.write_text(json.dumps(config, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        os.chmod(config_path, 0o600)
        test = subprocess.run([str(xray_path), "run", "-test", "-config", str(config_path)], check=False)
        if test.returncode != 0:
            raise AppError("Xray rejected the generated configuration. Review the preceding Xray error; the link itself is not printed.")
        if check_only:
            print("VLESS link parsed and Xray configuration validated. This does not test reachability of the remote server.")
            return 0
        print("Starting local proxy…", flush=True)
        process = subprocess.Popen([str(xray_path), "run", "-config", str(config_path)])
        try:
            addresses = [socks_addr] + ([http_addr] if http_addr else [])
            wait_for_listener(process, addresses)
            print("\nProxy is ready.")
            print(f"  SOCKS5: {socks_addr}")
            if http_addr:
                print(f"  HTTP:   http://{http_addr}")
            print("Only applications explicitly configured to use these endpoints will use VLESS.")
            print("Press Ctrl+C to stop.\n", flush=True)
            return process.wait()
        except KeyboardInterrupt:
            print("\nStopping proxy…", flush=True)
            return 0
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)


def resolve_xray(args: argparse.Namespace) -> Path:
    candidate = args.xray or os.environ.get("XRAY_BIN")
    if candidate:
        path = Path(candidate).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise AppError(f"Xray executable not found or not executable: {path}")
        return path
    # Reuse installed version if one exists. For a first run, install the latest stable release.
    return install_xray(force=args.update_xray)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Paste one VLESS link and expose local SOCKS5/HTTP proxies.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--link", help="VLESS URI (visible in process listings; interactive prompt is safer)")
    source.add_argument("--link-file", help="read VLESS URI from a private local file")
    parser.add_argument("--xray", help="path to an existing Xray executable")
    parser.add_argument("--socks", default="127.0.0.1:10808", help="SOCKS5 listen address (loopback only; default 127.0.0.1:10808)")
    parser.add_argument("--http", default="127.0.0.1:10809", help="HTTP listen address (loopback only; default 127.0.0.1:10809)")
    parser.add_argument("--no-http", action="store_true", help="disable the HTTP proxy listener")
    parser.add_argument("--allow-insecure", action="store_true", help="allow a link with certificate verification disabled (unsafe)")
    parser.add_argument("--check", action="store_true", help="validate URI/config with Xray, but don't start listeners")
    parser.add_argument("--update-xray", action="store_true", help="download and verify the latest stable official Xray release")
    args = parser.parse_args(argv)

    try:
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
            raw = path.read_text(encoding="utf-8")
        elif args.link:
            raw = args.link
            print("Warning: --link may be visible to local process inspection; use the interactive prompt for privacy.", file=sys.stderr)
        else:
            if not sys.stdin.isatty():
                raise AppError("Run interactively to paste your VLESS link, or pass --link-file PATH.")
            print("Paste your complete VLESS link (vless://...) and press Enter.", flush=True)
            raw = input("> ").strip()
        parsed = parse_vless_uri(raw, allow_insecure=args.allow_insecure)
        # Drop the raw credential-bearing URI promptly.
        del raw
        http_addr = None if args.no_http else args.http
        config = build_xray_config(parsed, args.socks, http_addr)
        # Reject identical listener ports up front.
        if http_addr and args.socks.rsplit(":", 1)[-1] == http_addr.rsplit(":", 1)[-1]:
            raise AppError("SOCKS5 and HTTP listeners must use different ports.")
        xray = resolve_xray(args)
        print(f"Using Xray executable: {xray}")
        return start_proxy(xray, config, args.socks, http_addr, check_only=args.check)
    except AppError as exc:
        print(f"{APP_NAME}: {exc}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"{APP_NAME}: operation failed ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
