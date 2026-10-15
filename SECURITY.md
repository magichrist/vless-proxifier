# Security notes

The design record behind this file is [`docs/V1/03-security.md`](docs/V1/03-security.md).
This page is the short version; it says what is stored, where, and what that does and does
not buy you.

---

## What is stored, and where

V0 stored nothing. V1's whole purpose is to store profiles, so the storage layout is the
security model and it is written out in full.

| Item | Where | Protection |
|---|---|---|
| **UUID** — the one credential | macOS Keychain, one item per profile, account = profile id | Keychain ACL: available to processes running as you, not to other users |
| Server, port, security, transport, SNI, fingerprint, ALPN, path, host, flow, gRPC service, Reality `pbk` / `sid` / `spx`, `encryption`, certificate pins | `~/Library/Application Support/vless-python-proxy/profiles.json` | `0600` file in a `0700` directory, written atomically |
| Active profile id, labels, latency cache | same file | same |
| Runtime Xray config (carries the UUID) | temp dir under Application Support | `0600` in `0700`, deleted when the process stops |
| Xray binary | `~/Library/Application Support/vless-python-proxy/xray/<tag>/` | `0700` directories, SHA-256 verified against the upstream `.dgst` before install |

**Only the UUID is treated as a secret**, because only the UUID is a credential. Reality's
`pbk` is a *public* key by construction — the server publishes it in the link precisely so
the client can encrypt to it. `sid` is a short id, not an authentication credential. Neither
is stored in the Keychain, and neither is a secret.

The store enforces the split rather than trusting callers: `ProfileStore.add` and
`.update` raise if a link dict still carries a `uuid` key, and the loader rejects a file
that contains one.

---

## Residual risk, stated plainly

**The Keychain protects against other local users, not against other processes running as
you.** Any program you run — including anything in your `.venv` — can read an item from your
login keychain unless you set an ACL on it. This is a property of macOS, not a defect in
this tool.

**`profiles.json` is the weaker half of the split.** It names your provider, your servers,
and your nodes. It is not a credential, and it is readable by anything running as you.
`0600` stops other *users*; it does not stop other *processes you own*.

Neither half defends against a compromised machine. Do not treat either as if it did.

---

## The vendored binary moves the trust boundary

A downloaded binary is verified: HTTPS only, host allowlisted after redirects, size capped,
and the archive's SHA-256 checked against the `.dgst` published beside it. That is the
strongest statement this project can make about a binary it did not build.

A **vendored** `xray-<platform>/xray` beside the repository cannot be verified that way —
there is no upstream `.dgst` to check it against at runtime. Adopting one moves the trust
boundary from *"verified at download, from the official source"* to *"trusted as part of this
checkout"*.

That is why a vendored binary is only used when its SHA-256 matches a build pinned in
`vlessp/xray.py`, and an unrecognised hash falls back to the downloader instead of being
executed. The directories are gitignored, so a binary that arrives that way arrived from
your disk, not from this repository.

Related, and worth repeating: only clear the quarantine flag on a binary you trust.

```bash
xattr -dr com.apple.quarantine xray-macos-arm64/
```

---

## Controls that still hold

Each of these is asserted by a test, not just described here.

- **Loopback-only listeners.** `build_xray_config` refuses any address that is not a
  loopback IP, so `--socks 0.0.0.0:10808` is an error rather than a silent exposure.
- **TLS verification on by default.** A link carrying `insecure=1` is refused unless you
  pass `--allow-insecure`, and certificate pinning (`pcs`) is refused in combination with
  disabled verification.
- **No proxy authentication.** Anything that can reach the port can use the tunnel.
  **Do not expose the SOCKS or HTTP ports beyond loopback.** V1 adds no authentication and
  no access control list.
- **Link files must be private.** `--link-file` is rejected on POSIX unless the file is mode
  `600`; keep the parent directory `700` as well.
- **`--link` is the least private option.** The link sits in argv, where other processes on
  the machine can read it. It warns on stderr; prefer `--link-file`.
- **No `AppError` message contains a link.** Not the URI, not the UUID, not the query
  string. Every message is written from the shape of the problem. The same filter is applied
  to Xray's own output before it reaches the CLI's stderr or the UI's log pane, because
  Xray prints config fragments on some parse errors.
- **Downloads** accept only the official XTLS/Xray-core release API and assets, cap the
  size, and verify the SHA-256 before installing.
- **No signed provenance is checked.** A checksum published by the same host that served the
  file is not independent verification. For high assurance, verify the release signature by
  the upstream project's documented method.

---

## Reporting

Not published yet — this is a single-operator tool. If you fork it, put your own contact
here rather than inheriting a silent one.