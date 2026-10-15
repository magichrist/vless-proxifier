# vlessp — a VLESS profile manager

Save many `vless://` profiles, switch between them from a terminal UI, and get a local
SOCKS5 / HTTP proxy pointing at whichever one is active.

**Architecture note, stated up front.** This repository holds the *control plane*: URI
parsing and validation, profile storage, Xray config generation, binary acquisition and
verification, and process supervision — all Python. The actual VLESS network engine is the
official prebuilt **Xray-core** executable. You do not install Go, build Go, or maintain Go
source. Reimplementing the modern VLESS wire protocol, uTLS fingerprinting, Reality, and
post-quantum VLESS encryption in pure Python would be a different protocol implementation,
and this project does not claim to be one.

V1 depends on [`textual`](https://textual.textualize.io/) for the UI. It is **not**
standard-library-only any more — that trade is recorded in
[`docs/V1/00-decisions.md`](docs/V1/00-decisions.md) (D1) and it is the only runtime
dependency.

---

## Install

Requires Python 3.10+. On macOS, also needs the `security` CLI, which ships with the
system — that is where UUIDs are stored.

```bash
# from a checkout
pip install -e .

# or just the one dependency
pip install "textual>=1.0"
```

## Run

```bash
python3 vless_proxy.py
```

That launches the terminal UI. It resolves an Xray binary first (see
[the Xray binary](#the-xray-binary)) — downloading on a first run — then shows the
profile table.

The first profile is added in the UI — press `a` and paste a link. The UUID is split off
and written to the Keychain; everything else goes to `profiles.json`.

### Test from another terminal

```bash
curl --socks5-hostname 127.0.0.1:10808 https://api.ipify.org
curl --proxy http://127.0.0.1:10809 https://api.ipify.org
```

Both should return the public IP of the VLESS egress. A bound listener is not proof the
upstream is reachable; the curl calls are the end-to-end check.

---

## The UI

| Key | Action | Notes |
|---|---|---|
| `Enter` | Connect the highlighted profile | validates the new config before stopping the old one |
| `a` | Add a profile | pastes a `vless://` link; masked input, preview before saving |
| `e` | Edit a profile | non-secret fields only — the UUID is not editable here |
| `d` | Delete a profile | asks first; removes the Keychain item too |
| `t` | Test all | one TCP latency probe per profile, sorts the table |
| `c` | Connect / disconnect | reconnect the last active profile, or stop |
| `l` | Toggle the log pane | shows Xray's last output |
| `q` | Quit | terminates Xray cleanly |

Two behaviours worth knowing because they are easy to assume otherwise:

- **Latency is reachability, not throughput.** `t` measures a TCP connect to each profile's
  server. It does not measure speed through the tunnel, because that would require the proxy
  to already be running on that profile.
- **Nothing connects automatically.** Launching the UI does not start a tunnel, and `t` never
  changes which profile is active. Press `Enter` or `c`.

---

## Command line

The UI is a front end, not a replacement. Every flag below is the headless path.

```bash
# List saved profiles. Prints labels and servers; never a UUID.
python3 vless_proxy.py --list

# Start a saved profile by label (or by id) and stay in the foreground.
python3 vless_proxy.py --profile home

# One-off link, no profile saved. Visible in process listings.
python3 vless_proxy.py --link 'vless://…'

# Same, from a private file. Must be mode 600 on POSIX.
chmod 600 ~/.config/vless/link.txt
python3 vless_proxy.py --link-file ~/.config/vless/link.txt

# Validate a link and the generated config, open no listeners.
python3 vless_proxy.py --check --link-file ~/.config/vless/link.txt

# Force the UI even when other flags are present.
python3 vless_proxy.py --tui
```

| Flag | Default | Meaning |
|---|---|---|
| `--link URI` | — | VLESS link as an argument. **Least private option**: argv is readable by other processes on the machine. |
| `--link-file PATH` | — | Read the link from a file. Rejected on POSIX unless the file is mode `600`. |
| `--profile ID_OR_LABEL` | — | Connect to a saved profile headlessly. |
| `--list` | — | Print the profile table and exit. No binary is resolved and no network is touched. |
| `--tui` | — | Force the Textual UI. The default when no link source is given. |
| `--xray PATH` | — | Use an existing Xray executable instead of resolving one. |
| `--socks ADDR` | `127.0.0.1:10808` | SOCKS5 listener. Loopback only. |
| `--http ADDR` | `127.0.0.1:10809` | HTTP listener. Loopback only. |
| `--no-http` | off | Disable the HTTP listener. |
| `--allow-insecure` | off | Permit a link that disables TLS certificate verification. Unsafe. |
| `--check` | off | Validate the URI and the generated config with Xray; open nothing. |
| `--update-xray` | off | Skip the vendored copy and re-download the latest stable official release. |

`XRAY_BIN=/path/to/xray` is honoured as a fallback for `--xray`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Served until interrupted, or a successful `--check` / `--list`. Ctrl+C while serving is a success. |
| `1` | An unexpected OS, JSON, or zip failure — the machine misbehaved. |
| `2` | A refused request: bad link, unknown profile, identical listener ports, unwritable store. |
| `130` | Interrupted by Ctrl+C before anything was serving. |

### Not implemented

No subscription refresh, no WireGuard / Hysteria2 / Trojan, no TUN or system-wide routing,
no per-process interception, and no automatic failover. Use Proxifier or ProxyBridge pointed
at the local SOCKS5 endpoint for app-by-app routing.

---

## The Xray binary

Resolution order, highest first:

1. `--xray PATH`
2. `$XRAY_BIN`
3. a vendored `xray-<platform>/xray` directory beside the repository, **only if its SHA-256
   matches a pinned official build**
4. download the latest stable official release and verify its SHA-256 against the upstream
   `.dgst` file

Installed binaries live in `~/Library/Application Support/vless-python-proxy/xray/<tag>/`.

**The vendored copy is not committed.** 34 MB of stripped Go in permanent git history is not
worth the convenience, so `xray-macos-arm64/` and friends are gitignored. A vendored binary
cannot be verified the way a downloaded one is — there is no upstream `.dgst` to check it
against at runtime — so an unrecognised hash is **ignored in favour of the downloader**, never
executed. The downloader stays the source of truth; vendoring is a cache it happens to
satisfy.

### If macOS refuses to run it

A binary downloaded through a browser carries the `com.apple.quarantine` attribute, and the
kernel stops it — or blocks the launching process on a Gatekeeper prompt that nobody sees.
The resolver prints a note when it detects this. The fix:

```bash
xattr -dr com.apple.quarantine xray-macos-arm64/
```

Only do this for a binary you trust. It removes the check that was protecting you.

---

## Supported fields

`security=none|tls|reality`, `type=tcp|ws|grpc|httpupgrade|xhttp`, TLS `sni`, `fp`, `alpn`,
`pcs` certificate pins, VLESS `encryption`, Vision flow on TCP links, WebSocket `path`/`host`,
gRPC service and authority, HTTP Upgrade fields, XHTTP `mode` and JSON `extra`, and Reality
`pbk` / `sid` / `spx`.

Links are never printed — not on success, not in an error, not in a log. TLS verification is
on by default, and a link carrying `insecure=1` is refused unless you pass
`--allow-insecure`.

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

237 tests. The TUI tests need `textual` installed and skip themselves cleanly without it, so
a machine without the dependency runs fewer tests rather than failing.

No test executes a real Xray binary — the supervisor tests substitute a small fake script
written into a tmpdir, because a real one would bind real ports and the repo copy is
Gatekeeper-quarantined. Tests use documentation-reserved addresses and synthetic UUIDs, and
never contact a real endpoint.

## Layout

```
vless_proxy.py     thin shim: re-exports three names, delegates to vlessp.cli
vlessp/
  links.py         parse_vless_uri / build_xray_config   (pure, no I/O)
  profiles.py      Profile model + ProfileStore          (JSON, never sees a UUID)
  secrets.py       SecretStore + macOS Keychain + null   (the only Keychain caller)
  xray.py          binary install + process supervision   (subprocess)
  proxy.py         ProxyService, the orchestration seam
  latency.py       one-shot server reachability probe
  cli.py           argument parsing and the headless run loop
  tui/             Textual front-end
```

See [`SECURITY.md`](SECURITY.md) for what is stored where, and
[`docs/V1/`](docs/V1/) for the design record behind all of it.