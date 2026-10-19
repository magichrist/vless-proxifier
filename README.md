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

### Changing the local ports

Press `p` in the UI to move the local SOCKS5/HTTP listeners — the *internal* ends your
apps connect to — without touching any profile. It edits the listen host and port for each
protocol (and can turn the HTTP listener off). The change is applied immediately: if a
tunnel is running it is restarted on the new ports, otherwise the new addresses are used at
the next connect.

The setting is saved in `profiles.json` beside an `active` id, so it survives a restart.
`--socks` / `--http` override it for a single run, and a scripted `--link` run ignores it
entirely (that mode never reads the store).

The default is loopback, because the proxy has no authentication. Binding `0.0.0.0` or a
LAN address is allowed — for example to share the tunnel with another device on your own
network — but the dialog warns when you do, since it exposes an open proxy to everything
that can reach that interface.

---

## The UI

| Key | Action | Notes |
|---|---|---|
| `c` | Connect the highlighted profile | validates the new config before stopping the old one |
| `space` | Stop, or resume if stopped | acts on the service as a whole, not the row |
| `l` | Add a `vless://` link | masked input, preview before saving |
| `s` | Add a subscription URL | imports every node in the feed; masked input |
| `e` | Edit a profile | non-secret fields only — the UUID is not editable here |
| `i` | Change server and port | short form for the most common edit; every other field is carried through |
| `p` | Change the **local** SOCKS5/HTTP ports | where your apps connect; never touches the profile or its UUID |
| `d` | Delete a profile | asks first; removes the Keychain item too |
| `t` | Test all | one TCP latency probe per profile, sorts the table |
| `o` | Show/hide the output pane | Xray's last output |
| `alt+t` | Cycle the colour theme | `textual-dark` → `gummy` → `cyber-female` |
| `h` | Help | the full key reference, grouped by intent |
| `q` | Quit | terminates Xray cleanly |

`Enter` still connects the highlighted row and `a` still adds a link, so the V1 muscle memory
keeps working. Both are aliases and are not advertised in the key hints — `h` lists them.

### The key hints

One line, pinned above the status bar, every key:

```
c connect · space stop/resume · t test · l add link · s add sub · e edit · i ip/port · p local ports · d delete · o output · alt+t theme · h help · q quit
```

It replaces Textual's built-in `Footer`, which was the wrong tool: the footer renders one
key/label pair per binding on a single un-wrapped line, and twelve bindings came to **117
columns**, so on an 80-column terminal the tail was silently cut to an ellipsis — hiding `q`, the
last key anyone wants hidden. It looked complete while lying about what was available.

Thirteen readable keys need 154 columns, so rather than pick one compromised layout the line
**adapts to the terminal**, taking the widest tier that fits:

| Width | Rendered |
|---|---|
| ≥154 | `c connect · space stop/resume · t test · l add link · …` |
| ≥138 | `c conn · space stop · t test · l add link · …` |
| ≥88 | `c:conn sp:stop t:test l:add s:sub e:edit i:ip p:ports d:del o:out ^T:theme h:help q:quit` |
| <88 | `c space t l s e i p d o alt+t h q` (keys only) |

Below 88 it drops the *labels* rather than truncating: a key with no description is still
pressable and still honest, whereas a cut-off line silently hides keys nobody can find. A test
sweeps every width from 33 to 160 and asserts the rendered line always fits.

### Themes

`alt+t` cycles instantly — no modal, because the fastest way to compare themes is with nothing
to dismiss. `textual-dark` is deliberately first: a user who never presses the key sees exactly
what they saw before.

Every theme is held to **WCAG 2.1 AA at 4.5:1**, which is why `gummy` is less bright than the
name suggests. Its original bubblegum pink measured 2.65:1 on cream, and a tangerine 2.19:1 —
both unreadable as text. The colours were deepened along the lightness axis with hue and
saturation held constant, so `#517516` is still recognisably the same lime as the `#8AC926` it
started as. "Candy" lives in the borders, fills, and Textual's derived tints instead.
`tests/test_theme.py` asserts the whole contrast matrix, and also asserts the *original*
colours fail — so the pastel version cannot be quietly restored.

### Subscriptions

`s` records a subscription URL in the Keychain and imports its nodes. The format is a plain-text
list of `vless://` links, with a base64 decode attempted once if the body does not start with
`vless://` — providers serve both under the same URL.

```
python3 vless_proxy.py --sub work      # fetch and import one
python3 vless_proxy.py --refresh-subs  # re-fetch every stored subscription
python3 vless_proxy.py --list          # shows each profile's source
```

**Subscriptions are fetched when you ask, and never on a timer.** A subscription URL embeds a
token granting access to your entire node list, so every fetch is a credential-bearing request
to a third party. There is deliberately no flag that takes a URL — argv is visible to every
process on the machine — so `--sub NAME` prompts for it once and stores it in the Keychain.

Refreshing is **non-destructive by design** (decision S5 in `docs/V1/05-v2-parked.md`):

- A node whose UUID rotated is **updated**, never duplicated. Identity is
  `(server, port, transport, SNI)` — deliberately not the UUID, which is the thing that rotates.
- A node your provider stopped offering is **flagged `gone`**, not deleted. An upstream omission
  is usually a transient outage, and deletion is irreversible. Flagged profiles stay fully
  usable; the table dims them rather than hiding them.
- A local rename survives a refresh.
- A response with no usable links changes **nothing** — a 200 returning a login page would
  otherwise mark every node in that subscription unavailable.

Three behaviours worth knowing because they are easy to assume otherwise:

### Latency graphics

The `LAT` column is a bar, not a bare number:

```
  LABEL      SERVER            PORT  SEC  TRANSPORT  LAT         STATE
▌tokyo-1     203.0.113.10       443  TLS  ws        ██▍ 42ms    live
  frankfurt  198.51.100.7      8443  TLS  tcp       ███▋ 890ms   —
  singapore  203.0.113.44       443  REALITY grpc  █▎   18ms    —
```

Bars use **eighth-blocks**, not whole blocks. Four cells of `█` give only five distinct values
across the whole range, which would draw 42 ms and 85 ms identically — decoration, not
information. Eighth-blocks give thirty-two, enough to separate values you actually care about.

The scale is **fixed, not relative to the best node in view**. A relative scale would rescale
itself per row, so the same bar would mean "fast" with one node listed and "terrible" with
fifty. Comparing nodes is the whole reason for a bar, so it has to mean the same thing on every
row. It is logarithmic because latency is perceived logarithmically — 40 ms to 80 ms matters far
more than 540 ms to 580 ms.

Beneath the table, a **detail panel** shows the highlighted profile and its trend across recent
probe runs:

```
tokyo-1  203.0.113.10:443  [sub:work]
▄▅▄▅▆▆▇▇▇▇▇ ▇▇█▇▇▇▇▇  last 20 runs this session (1 unreachable)
min 38ms   avg 454ms   max 800ms
```

A single cached latency answers "how slow is it now". A trend answers whether the node is
*degrading*, which is the question that decides whether you go looking for a new subscription.

Two things it will not do. An unreachable probe is a **gap**, not a zero — we did not measure
zero, we measured nothing, and plotting it at zero would drag the scale to the floor. And with
only one sample it says so instead of drawing a flat line that looks like a stable measurement.

History is **session-scoped**: the last 20 probes per profile, in memory, discarded on quit.
`profiles.json` stays a config file and not a metrics log. The number beside each bar is always
present, so colour and glyph are never the only encoding.

- **`c` and `space` are different on purpose.** `c` acts on the highlighted row; `space` acts on
  the service as a whole. Pressing `c` while scanning the table moves to that row — it never
  silently halts your tunnel.
- **Latency is reachability, not throughput.** `t` measures a TCP connect to each profile's
  server. It does not measure speed through the tunnel, because that would require the proxy
  to already be running on that profile.
- **Nothing connects automatically.** Launching the UI does not start a tunnel, and `t` never
  changes which profile is active. Press `c`, or `space` to resume the last active profile.

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
| `--socks ADDR` | saved setting (loopback `127.0.0.1:10808`) | SOCKS5 listener. An IP literal `HOST:PORT`; overrides the address saved in the UI. |
| `--http ADDR` | saved setting (loopback `127.0.0.1:10809`) | HTTP listener. Same rule; overrides the saved address. |
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

The TUI tests need `textual` installed and skip themselves cleanly without it, so a machine
without the dependency runs fewer tests rather than failing. They are also the slow part: the
full suite takes several minutes, almost all of it in `tests/test_tui.py` driving a real
headless Textual app. The non-TUI modules finish in seconds.

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