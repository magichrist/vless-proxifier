# V2 — Parked decisions

Subscriptions were deferred from V1, not forgotten. Their key choices were already made during the
V1 intake interview. They are recorded here so V2 starts from settled answers instead of re-litigating them.

**These decisions are committed but not built. Do not start implementing them until V1 is green.**

---

## S1 — Format: plain-text `vless://` lines

The subscription serves **newline-separated `vless://` URIs, no base64 wrapper**.

**Why this matters for the design.** The fetch/parse path is thin — split on newlines, drop blanks
and `#` comments, run each line through the **existing `parse_vless_uri`**. No new URI grammar, no
new normalizer.

**Do this anyway, because it is nearly free.** Sniff the first non-whitespace characters. If they
do not look like `vless://`, attempt a base64 decode and retry once. A surprising number of
providers serve base64 under the same URL, and handling it costs about eight lines. Treat it as a
fallback, not the primary path.

**Explicitly not supported in V2.** Clash / Clash.Meta YAML (pulls in PyYAML and a whole second
config model), sing-box JSON (a shape that is not a URI, so a second config path). Both are
possible later; neither is needed for the stated use case.

---

## S2 — Refresh: on launch + manual only

No background timers, no polling interval.

**Why.** Every fetch is a secret-bearing request to a third party — the subscription URL *is* a
credential. A background timer means your proxy phones home periodically whether or not you are
using it. On-launch-plus-manual keeps that traffic visible and intentional.

**If staleness becomes a complaint,** the next step is TTL-based: cache with an expiry, re-fetch on
launch only if older than N hours. That halves the traffic without adding a scheduler. A full
background timer stays off the table.

---

## S3 — Storage: subscription URLs are secrets

A subscription URL typically embeds a token that grants access to your entire node list. It gets
the **same Keychain treatment as a profile UUID** — one item per subscription, account = generated
id, referenced from JSON by id only.

This means `profiles.json` never holds a subscription URL, and the `NullSecretStore` test backend
covers this path exactly as it covers the profile path.

---

## S4 — Imported nodes are ordinary profiles

A fetched node becomes a standard `Profile` with `source = "subscription:<id>"`. There is no
separate imported-node type.

**Why.** Nodes get edited, renamed, and reordered like any other profile, and the profile store
already handles them. A parallel concept would double the code paths in the TUI and the store.

**Display rule.** Group or badge them by source so subscription nodes are visually distinct from
hand-added ones. A purely cosmetic concern — it must not affect behaviour.

---

## S5 — Conflict policy: last fetch wins, but never clobber local edits silently

On each fetch, reconcile by the node's identity — server + port + transport + network + sni.

| Case | Action |
|---|---|
| Node unchanged upstream | Update latency cache only |
| Node changed upstream (rotated UUID) | **Update** — rotation is the point of a subscription |
| Node deleted upstream | Mark as unavailable, do **not** delete |
| Local rename | **Preserve** the label |
| Node absent from the store (new) | Add it |

Deleting locally is destructive and irreversible; an upstream deletion is usually a temporary
outage or a bad fetch. Marking is reversible; deleting is not. Never silently discard a local label.

---

## S6 — Health checking stays one-shot

Manual selection plus a `test all` probe, exactly as in
[`00-decisions.md` D5](00-decisions.md#d5--one-shot-latency-sort-manual-selection). The answer is
unchanged by the existence of subscriptions: **no automatic failover in V2.**

Re-importing a node list is not a reason to start moving traffic on its own. If auto-failover is
ever wanted, it is a separate decision with its own spec — it changes where your traffic goes
without asking you.

---

## V2 dependency delta

`httpx` enters the dependency list. Version `0.28.x`, per current documentation.

Use it rather than `urllib` for the fetch because of timeout handling, redirect control, and
streaming response reads. Constraints to apply when it is written:

- Reuse the **host allowlist** from `request_bytes` — the subscription host must be allowlisted
  just as the Xray download hosts are.
- Cap the response size (subscription bodies are small; a multi-megabyte response is a red flag).
- Hard timeout. No retries — a retry against a credential URL doubles the exposure for no benefit.
- **Never log the request URL.** It is the credential.