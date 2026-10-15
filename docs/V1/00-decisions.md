# V1 — Decision record

Answers to the intake interview, with the reasoning kept so a later change knows what it is
overturning.

---

## D1 — Dependencies are allowed: `textual` (+ `httpx` from V2)

**Decision.** Abandon the stdlib-only constraint. Add `textual` for the UI. `httpx` joins the
dependency list when subscriptions arrive in V2.

**Why.** The stdlib-only property was a real strength of the current code and is now traded away
deliberately. It was affordable when the program was one link and one config dict. It is not
affordable for a TUI: there is no reasonable way to get key handling, focus management, resize,
scrollback, and a widget tree out of `curses` and `print` at a quality worth shipping.

**Cost, stated plainly.** The README's headline claim changes. So does the zero-install promise.

**Rejected.**
- *Keep stdlib-only, hand-roll ANSI.* Weeks of work for a visibly worse UI, and macOS-terminal
  hostile. Rejected on cost-to-quality.
- *Stdlib core + optional TUI extra.* Preserves both stories but doubles the test surface and
  means every UI path is only sometimes tested. Rejected as cleverness.

**Note on the environment.** `.venv` in this repo is a symlink to
`Digital-Prophet/backend/.venv`. `httpx` is present there; **`textual` is not** and must be
installed before any TUI work runs. Per owner decision, the existing `.venv` is used as-is rather
than replaced with a dedicated environment.

---

## D2 — V1 scope: profiles + switching + TUI

**Decision.** V1 = store many profiles, switch the active one, drive it all from a TUI.

**Why.** This is the smallest slice that fixes the stated pain ("easy changing in the vless
links"). Everything else in the request — subscriptions, routing, failover — is a separate
subsystem with its own failure modes.

**Rejected.** *Everything at once.* Five subsystems sharing one release means no part is
independently verifiable, and a regression in any one blocks shipping the rest.

---

## D3 — Switching restarts Xray with a regenerated config

**Decision.** One long-lived Xray process. Switching profiles = write a new config, validate it,
terminate the old process, spawn a new one. ~200–400 ms listener gap.

**Why.** Reuses the config generator and supervisor that already exist. No new RPC surface, no
new dependency, no new failure modes. SOCKS and HTTP clients reconnect across a short gap.

**Design rule that keeps this cheap to reverse.** Everything above `XrayProcess` talks to an
interface with two methods — `apply(profile)` and `stop()`. A future hot-swap implementation
satisfies the same interface, so the TUI and profile layers do not change. The cost of D3 being
wrong later is bounded by that seam.

**Rejected.**
- *Xray HandlerService API (gRPC) for zero-downtime swap.* Genuinely better UX, but needs gRPC
  plumbing, an `api` config block, and roughly 2–3× the complexity — for a 300 ms gain.
- *One Xray process per profile, all live, switch by changing ports.* No restart ever, but N
  processes, N port pairs, and resource use that grows with profile count. Wrong shape for
  "usually exactly one node is active."

---

## D4 — macOS Keychain holds the UUID; JSON holds everything else

**Decision.** In a VLESS link, **the UUID is the only true secret.** It goes into the macOS
Keychain. Every other field — server, port, `security`, transport, SNI, fingerprint, ALPN, path,
host, flow, gRPC service, Reality `pbk`/`sid`/`spx`, `encryption`, cert pins — is non-secret and
lives in a readable `profiles.json` at mode `0600`.

Reality's `pbk` is a *public* key by definition; `sid` is a short id, not an authentication
credential. Neither is treated as a secret.

**Why.** This keeps the Keychain to exactly one item per profile, keeps the profile list
diffable and greppable, and confines keychain access to the single operation that needs it:
"give me the UUID for profile X."

**Backends.** `macos_keychain` (implemented, via the `security` CLI) and `null` (writes nothing,
always errors — used in tests). The interface exists so a Linux secretstore or a `0600`-only mode
can be added without touching callers.

**Rejected.** *Whole-store encryption with a passphrase.* Adds a startup password prompt, which
directly fights the "easy connecting" goal. *Plain `0600` JSON for everything.* Acceptable and
portable, but it is a strictly weaker guarantee on a machine where a Keychain is sitting right
there.

---

## D5 — One-shot latency sort, manual selection

**Decision.** A `test all` action probes every profile's `host:port` with a TCP connect, sorts the
table by result, and caches the number until the next run. No background polling. The user picks
the active node; nothing ever changes it automatically.

**Why.** It answers "which of these is alive and closest" in one keystroke, with no timer, no
scheduler, and no surprise traffic.

**Known limitation, documented on purpose.** This measures *reachability and TCP latency to the
server*, not end-to-end throughput through the tunnel. True end-to-end measurement requires the
proxy to already be running on that profile, which makes it a different (and slower) operation.

**Rejected.** *Continuous monitoring* and *automatic failover.* Both move your traffic or generate
traffic without being asked. Automatic failover is the most dangerous of the options: a silent
switch sends traffic to a different host than the one you chose.

---

## D6 — macOS only

**Decision.** V1 targets macOS. Linux paths in `platform_asset()` are left alone but untested and
undocumented.

**Why.** D4 uses the macOS Keychain. Supporting Linux means either dropping that guarantee or
building a storage abstraction now — for a platform nobody has asked for.

**Rejected.** *macOS + Linux with POSIX-portable `0600` storage.* Wider reach, but it gives up the
stronger secret protection that was chosen on purpose.

---

## D7 — Validate the new profile *before* stopping the working one

**Decision.** Switch order is: generate config → `xray run -test` → stop old → start new → wait
for listener. Validation happens first.

**Why.** A typo in a new profile must never take down a proxy that is currently working. If
validation fails, the old process keeps serving and the UI shows the error. Costs nothing;
avoids the single most annoying failure mode a profile manager can have.