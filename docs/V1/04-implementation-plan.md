# V1 — Implementation plan

Seven phases. Each ends with passing tests and a working manual check. No phase begins until the
previous one is green.

---

## Phase 0 — Environment (blocks everything)

The `.venv` symlink is reused as instructed, but `textual` is not in it.

- [ ] Install `textual` into the existing environment
- [ ] Set `dependencies = ["textual>=1.0"]` in `pyproject.toml`
- [ ] Rewrite the README's `standard-library-only` claim **in the same change** — the docs must
      not claim something the code no longer does

**Done when:** `python3 -c "import textual"` succeeds and the README no longer says stdlib-only.

---

## Phase 1 — Extract the core, change nothing

Split the file. **No behaviour changes. Existing tests must pass untouched.**

- [ ] `errors.py` → `AppError`
- [ ] `links.py` → `parse_vless_uri`, `build_xray_config`, `is_valid_hostname`, `query_params`,
      and the `re` constants they use
- [ ] `xray.py` → `request_bytes`, `platform_asset`, `find_latest_release_asset`, `install_xray`,
      `resolve_xray`, `wait_for_listener`
- [ ] `vless_proxy.py` becomes a shim that re-exports `AppError`, `parse_vless_uri`,
      `build_xray_config` and delegates to `vlessp.cli`

**Done when:** `python3 -m unittest discover -s tests -v` passes 9/9 with `tests/test_vless_proxy.py`
unmodified, and `python3 vless_proxy.py --check --link 'vless://…'` behaves exactly as before.

---

## Phase 2 — Profiles + secrets

- [ ] `Profile` dataclass, frozen, with `link` excluding `uuid`
- [ ] `resolve_link(profile, secrets)` — the only place a UUID is re-attached
- [ ] `ProfileStore` — load/save/list/active, atomic write, `0700` dir / `0600` file
- [ ] `secrets.py` — `SecretStore` Protocol, `MacOSKeychain` (via `security` CLI), `NullSecretStore`
- [ ] Keychain item naming: service `vless-python-proxy`, account = profile id

**Tests.** Round-trip; atomic write leaves the old file on simulated failure; **store never
contains the UUID**; `null` backend raises a clear `AppError`; a real Keychain round-trip behind a
`@unittest.skipUnless(os.environ.get("VLESP_KEYCHAIN_TESTS"))` guard.

**Done when:** profiles persist across runs, no UUID is found on disk, and the suite is green.

---

## Phase 3 — Supervisor + switch

- [ ] `XrayProcess` with `apply(link, socks, http)` and `stop()`, matching
      [`01-architecture.md`](01-architecture.md#the-switching-seam)
- [ ] D7 ordering: generate → `-test` → stop old → spawn → wait for listener
- [ ] `ProxyService` — orchestration only, knows about profiles and ports, not about subprocesses
- [ ] `latency.probe_server(host, port, timeout)` — TCP connect, ms or `None`

**Tests.** `apply` validates before stopping (assert the old process is untouched when `-test`
fails); `stop` is idempotent; `apply` twice leaves exactly one child; probe returns `None` on a
closed port. Use a fake Xray binary — a shell script that records its argv and exits — not the real
one.

**Done when:** switching a profile in a test harness restarts the fake binary exactly once and
leaves no orphan process.

---

## Phase 4 — CLI parity

- [ ] `--profile <label-or-id>` to start a saved profile headlessly
- [ ] `--list` to print profiles without printing UUIDs
- [ ] Every V0 flag still works
- [ ] Keep `--link`; it is still the least private option and still says so

**Done when:** each V0 flag is exercised once against the refactored core.

---

## Phase 5 — TUI

- [ ] `tui/widgets.py` — `ProfileTable` (DataTable), `StatusBar`, collapsible log pane
- [ ] `tui/screens.py` — Add / Edit / Confirm modals
- [ ] `tui/app.py` — bindings, reactive state, workers
- [ ] **All subprocess, socket, and Keychain work inside `@work(thread=True)`**
- [ ] Results returned with `call_from_thread`
- [ ] Switch serialization guard — double-`Enter` cannot race two spawns
- [ ] Log pane redacted through the same filter as CLI errors

**Tests.** Textual provides `App.run_test()` — use it for headless interaction tests: mount,
select a row, press `Enter`, assert the fake Xray was restarted. These are worth writing; the TUI
holds the only coordination logic in the project.

**Done when:** `run_test` covers add → connect → switch → disconnect → quit with no orphan process
after `q`.

---

## Phase 6 — Docs

- [ ] README: new lead, TUI section, `--profile` / `--list`, install step for `textual`
- [ ] `SECURITY.md`: persistence table, the UUID-in-Keychain split, the residual risk
- [ ] Remove the "does not persist the URI" claim — it is no longer true

---

## Test strategy

| Layer | Approach |
|---|---|
| `links.py` | Existing 9 tests, unmodified. Pure functions, keep them pure |
| `profiles`, `secrets` | Plain `unittest`, `null` backend, tmpdir fixtures |
| `xray`, `ProxyService` | Fake Xray binary script; assert argv and process count |
| `latency` | Closed port → `None`; bound port → int |
| `tui` | `App.run_test()` for headless interaction |
| Security invariants | Explicit tests for loopback-only, TLS verify, and **no UUID on disk** |

Do not mock what you can substitute. A fake binary proves more than a mocked `Popen`.

---

## Risk register

| Risk | Mitigation |
|---|---|
| Textual API drift (0.x → 1.x renames) | Pin `textual>=1.0`; check current docs before writing widgets |
| Phase 1 refactor breaks the CLI | Tests unmodified + manual `--check` gate before Phase 2 |
| Keychain prompts annoy on every run | One item per profile, read once per connect, cached in-memory for the session |
| Switching races on double-`Enter` | Serialize through a guard flag in `ProxyService` |
| Scope creep back toward subscriptions | [`05-v2-parked.md`](05-v2-parked.md) — the decisions are made; building them early is the risk |

---

## Definition of done for V1

- [ ] N profiles persist; UUIDs live only in the Keychain
- [ ] `Enter` switches the live tunnel in under ~500 ms with a sub-second gap
- [ ] A bad new profile leaves the working proxy untouched
- [ ] Every V0 CLI flag still works
- [ ] Test suite green, including the untouched V0 parser tests
- [ ] No README or SECURITY.md claim that the code does not honour