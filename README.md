# VLESS Python Proxy

A small, standard-library-only Python CLI: paste **one** `vless://` link and receive a local SOCKS5 proxy plus an optional HTTP proxy.

**Important architecture note:** the application, URI validation, Xray config generation, release download, SHA-256 validation, and process lifecycle are Python. The actual VLESS network engine is the official prebuilt Xray-core executable. You do not install Go, compile Go, or maintain Go source. Implementing the modern VLESS wire protocol, Xray's uTLS fingerprinting, Reality, and your `mlkem768x25519plus...` VLESS encryption setting from scratch in pure Python would be a substantially different protocol implementation and is not what this project claims to do.

## Quick start (macOS M1/M2/M3/M4)

Requires Python 3.10+ and an internet connection on first run to download the official Xray binary.

```bash
python3 vless_proxy.py
```

It prompts visibly for one complete link. On first run it:

1. Detects Apple Silicon.
2. Queries the official Xray-core GitHub API for the latest stable release.
3. Downloads `Xray-macos-arm64-v8a.zip` and its official `.dgst` checksum file.
4. Verifies SHA-256 before installing the executable in `~/Library/Application Support/vless-python-proxy/xray/`.
5. Validates the generated configuration with Xray and starts local listeners.

No link is saved by default. The app creates a short-lived, permission-restricted runtime config in Application Support and deletes it on exit. This temporary file is necessary because Xray expects a config file.

The app exposes:

- SOCKS5: `127.0.0.1:10808`
- HTTP CONNECT: `http://127.0.0.1:10809`

Keep the terminal window open. Press Ctrl+C to stop.

## Test from another terminal

```bash
curl --socks5-hostname 127.0.0.1:10808 https://api.ipify.org
curl --proxy http://127.0.0.1:10809 https://api.ipify.org
```

Both should show the public IP of the VLESS egress. A proxy being bound locally is not proof the upstream is reachable; the curl tests perform the end-to-end check.

## Options

```bash
# Explicit link (less private: may be visible in process listings)
python3 vless_proxy.py --link 'vless://...'

# Link file: on macOS/Linux ensure mode 600
chmod 600 ~/.config/vless-client/link.txt
python3 vless_proxy.py --link-file ~/.config/vless-client/link.txt

# Use an existing Xray executable; no downloader needed
python3 vless_proxy.py --xray /path/to/xray

# Use SOCKS5 only
python3 vless_proxy.py --no-http

# Validate link and config but don't open listeners
python3 vless_proxy.py --check

# Refresh the cached Xray binary from the latest stable official release
python3 vless_proxy.py --update-xray
```

`XRAY_BIN=/path/to/xray` can also specify an existing executable. Only use Xray binaries from the official project or a source you trust.

## Supported fields

VLESS URI parsing/config translation supports `security=none|tls|reality`, `type=tcp|ws|grpc|httpupgrade|xhttp`, TLS SNI, fingerprint, ALPN, `pcs` certificate pin, VLESS `encryption`, Vision flow for supported TCP links, WebSocket `path` and `host`, gRPC service and authority, HTTP Upgrade fields, XHTTP mode and JSON `extra`, and Reality `pbk`, `sid`, `spx`.

The user's URI parameters are not printed intentionally. TLS verification is enabled by default. A link requesting `insecure=1` is refused unless the operator explicitly passes `--allow-insecure`.

This initial Python wrapper intentionally focuses on one VLESS link. It does not implement subscription refresh, WireGuard, Hysteria2, Trojan, TUN/system-wide routing, or automatic per-process interception. Use Proxifier/ProxyBridge and point them at the local SOCKS5 endpoint for app-by-app routing.

## Debugging

- If first-run download fails, use `--xray /absolute/path/to/xray` with a trusted Xray binary already installed.
- If configuration validation fails, read Xray's error printed immediately before the Python error. It should not contain the VLESS URI.
- If listeners start but curl fails, verify that the server and parameters are valid and reachable from your network.
- Check whether ports are free: `lsof -nP -iTCP:10808 -sTCP:LISTEN`.
- Stop with Ctrl+C.

## Tests

Python 3.10+ is recommended. No third-party Python packages are needed.

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile vless_proxy.py
```

The tests use synthetic hostnames and fake keys; they do not connect to a real VLESS endpoint.
