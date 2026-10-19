# V1 — Security model delta

The current code has one security posture: **nothing is persisted**. V1's entire purpose is to
persist profiles. That inverts the default, so this file exists to state exactly what changed and
what is now owed.

---

## What is now stored

| Item | Where | Protection |
|---|---|---|
| **UUID** (the credential) | macOS Keychain, one item per profile | OS keychain ACL — available to processes running as you, not to other users |
| Server, port, security, transport, SNI, fingerprint, ALPN, path, host, flow, gRPC service, Reality `pbk`/`sid`/`spx`, `encryption`, cert pins | `profiles.json` | `0600` file in a `0700` directory |
| Active profile id, labels, latency cache | `profiles.json` | same |
| Runtime Xray config | temp dir under Application Support | `0600`, deleted on exit — **unchanged** |
| Xray binary | `~/Library/Application Support/vless-python-proxy/xray/` | `0700` dirs, SHA-256 verified at install — **unchanged** |

Only the UUID is treated as secret, because only the UUID is a credential. Reality's `pbk` is a
public key by construction.

---

## Preserved from V0

Every control in [`SECURITY.md`](../../SECURITY.md) still holds, and each is asserted by a test:

- Listeners bind to an **IP literal**; `build_xray_config` refuses a hostname, because it could
  resolve somewhere different at spawn time than the text the user read. The default is loopback
  (`127.0.0.1`), and the TUI warns when a listener is bound beyond it.
- TLS verification on by default; `insecure=1` refused without `--allow-insecure`.
- `pcs` pinning refused when combined with `insecure`.
- Download allowlists hosts, caps size, and verifies the archive SHA-256 before install.
- Runtime config is `0600` in a `0700` directory and removed on exit.
- Link files must be `0600` on POSIX.
- **No `AppError` message contains the URI.** Now also true of the TUI log pane.

---

## New obligations V1 takes on

1. **`profiles.json` must be written atomically.** Temp file + `os.replace()`. A crash mid-write
   leaves the previous file, not a truncated one.
2. **`profiles.json` must never contain a UUID.** Enforced by a test that serializes a
   `ProfileStore` and asserts no value in the tree equals the test UUID.
3. **Keychain lookups go through one function.** No module reaches the `security` CLI directly, so
   the `null` test backend is a complete substitute and tests never touch the real keychain.
4. **The TUI log pane is treated as untrusted output.** It displays Xray stderr, so it is
   redacted through the same filter the CLI error path uses.
5. **A missing Keychain item is a normal, explained error** — "UUID for profile X is missing from
   the Keychain", not a crash and not a silent empty link.

---

## Known residual risk, stated plainly

**The Keychain protects against other local users, not against other processes running as you.**
Any program you run — including anything in your `.venv` — can read an item from your login
keychain unless you set an ACL on it. This is a macOS property, not a bug in this tool.

`profiles.json` is the weaker half of the split: it names your provider, your servers, and your
nodes. It is not a credential, and it is readable by anything running as you.

Neither half is a defence against a compromised machine. Do not treat either as one.

---

## Still true

Do not expose the SOCKS or HTTP ports beyond loopback. V1 adds no proxy authentication, so
anything that can reach the port can use the tunnel. The tools *allow* a wider bind — `p` in the
UI, or `--socks` / `--http` — but that is a deliberate exposure the user opts into, and the UI
warns inline when an enabled host is not loopback.