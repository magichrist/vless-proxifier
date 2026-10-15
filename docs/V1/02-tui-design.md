# V1 — TUI design

Framework: **Textual**. Rationale in [`00-decisions.md` D1](00-decisions.md#d1--dependencies-are-allowed-textual-httpx-from-v2).

---

## Main screen

```
┌──────────────────────────────────────────────────────────────────────┐
│ vless · 4 profiles                                   ● RUNNING      │  header
├──────────────────────────────────────────────────────────────────────┤
│  LABEL          SERVER            PORT  SEC  TRANSPORT  LAT   STATE  │
│ ▌home           203.0.113.10       2083  TLS  ws          42ms  live   │
│  work-eu        198.51.100.7       443   REALITY tcp      118ms  —     │
│  backup         203.0.113.44       2053  TLS  grpc        —     —     │
│  slow           198.51.100.9       8443  TLS  tcp         890ms  —     │
├──────────────────────────────────────────────────────────────────────┤
│ SOCKS 127.0.0.1:10808   HTTP 127.0.0.1:10809   xray v25.1.3        │  status bar
└──────────────────────────────────────────────────────────────────────┘
```

- **Header** — app name, profile count, and a state dot (`●` running / `○` stopped / `●` error).
- **ProfileTable** — a `DataTable`. The `▌` marks the active profile. `—` in LAT means not probed
  yet. Rows sort by latency after `t`, alphabetically otherwise.
- **StatusBar** — live listener addresses and the resolved Xray version. Red when stopped.

A **log pane** sits below the table, collapsible with `l`, showing Xray's last output. Xray
writes diagnostics to stderr; without this, a failed switch is a silent mystery.

---

## Keybindings

Revised after usability review. The original draft used `a` for add and `l` for the log pane,
which made the two most frequent actions the hardest to reach.

| Key | Action | Notes |
|---|---|---|
| `c` | Connect highlighted profile | Acts on the row |
| `space` | Stop / resume | Acts on the service as a whole — deliberately not `c` |
| `l` | Add a `vless://` link | `a` kept as a hidden alias |
| `s` | Add a subscription URL | V2 stub; explains itself rather than no-oping |
| `e` | Edit profile | Non-secret fields only |
| `i` | Change server + port | Short form; all other fields carried through the parser |
| `d` | Delete profile | Confirmation modal |
| `t` | Test all (latency) | Concurrent, sorted on completion |
| `o` | Toggle output pane | Was `l` in the first draft |
| `h` | Help | Grouped by intent, not listed flat |
| `q` | Quit | Terminates Xray cleanly |

`Enter` (connect row) and `a` (add link) remain bound but hidden from the footer.

**Why `c` and `space` are separate.** A user scanning the table and pressing `c` expects to
move to that row. Folding the stop action into the same key means a mis-press halts the tunnel
instead of selecting. The two intents — "switch to this one" and "shut this off" — stay
separate keys.

**Why `i` exists alongside `e`.** The full edit form has nine fields, and the edit made most
often is "this node moved to a different address or port". A two-field screen for that is not
duplication, it is the common path. It still validates through `build_validation_uri` →
`parse_vless_uri`, so editing the address cannot drop a Reality `pbk` or a certificate pin.

---

## Modals

### AddProfileScreen

1. `Input` for the label (pre-filled from the link fragment).
2. `Input` for the full `vless://` link, `password`-masked.
3. On confirm: parse → show a **read-only preview** (server, port, security, transport) → save.
4. Parse failure shows the parser's error message in place. The link is never written anywhere
   before it parses.

### EditProfileScreen

A form over the **non-secret** fields only:

| Field | Editable | Notes |
|---|---|---|
| Label | yes | |
| Server, Port | yes | re-validated by `parse_vless_uri` on the reassembled link |
| Security, Transport | yes | dropdown, same allowed sets as the parser |
| SNI, Fingerprint, ALPN | yes | |
| Path, Host | yes | when transport uses them |
| Flow | yes | `xtls-rprx-vision`, TCP only |
| UUID | **no** | Keychain-only; edit requires re-pasting a full link via Add → replace |

Because edits round-trip through `parse_vless_uri`, an Edit screen cannot produce a config the
parser would have rejected. The parser stays the single validator.

### ConfirmScreen

Generic yes/no for delete. Destructive actions are never a bare keystroke.

---

## Async behaviour

Every slow operation is a Textual worker:

| Operation | Worker | UI while running |
|---|---|---|
| Latency probe (`t`) | `@work(thread=True)`, thread pool | table stays navigable, rows fill in progressively |
| Switch profile (`Enter`) | `@work(thread=True)` | state dot → `⟳`, rows disabled |
| Add / edit save | `@work(thread=True)` | modal spinner |

Events are pushed back with `call_from_thread`. The event loop is never blocked by a socket or a
subprocess.

---

## Failure display

Errors go to the log pane **and** a `notify` toast. A toast alone disappears; the log alone is
easy to miss. Neither ever prints the VLESS URI — the parser and supervisor raise `AppError`
messages that are already written to be link-free, and that property is preserved.

---

## Headless mode is not deprecated

`vless_proxy.py --link … ` continues to work for scripts, and `--profile <name>` is added so a
saved profile can be started without the TUI. The TUI is a front-end over the same service, not a
replacement for it.