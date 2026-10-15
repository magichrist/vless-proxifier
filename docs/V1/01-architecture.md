# V1 — Architecture

## The problem with the current shape

`vless_proxy.py` is 557 lines holding five unrelated jobs: network download, checksum
verification, URI parsing, config generation, and process lifecycle. It is internally consistent
and reasonably well-factored *within* each job, but there are no seams between them. V1 needs
profiles to be stored, retrieved, and re-pointed without going through a CLI argument — which
means the parser and the supervisor need boundaries they currently do not have.

V1 splits along job boundaries. Not for tidiness: because the profile layer must be able to call
the config generator and the process supervisor without importing `main()`.

---

## Module map

```
vless_proxy.py            thin CLI shim — preserves every existing flag, delegates to vlessp.cli
src/vlessp/
  errors.py               AppError — the shared error contract
  links.py                parse_vless_uri, build_xray_config      (pure, no I/O)
  profiles.py             Profile model, ProfileStore (JSON)       (I/O, no secrets)
  secrets.py              SecretStore interface + macOS + null    (I/O, Keychain)
  xray.py                 install_xray, resolve_xray, XrayProcess (subprocess)
  latency.py              probe_server                           (sockets)
  cli.py                  argparse, headless entry point
  tui/
    app.py                VlessApp(App)
    widgets.py            ProfileTable, StatusBar
    screens.py            AddProfileScreen, EditProfileScreen, ConfirmScreen
```

Each module owns exactly one job and can be read without reading the others. `links.py` has no
imports from the package beyond `errors`. That is what makes the existing parser tests keep
working untouched.

---

## Data model

### Profile — the thing stored

```python
@dataclass(frozen=True)
class Profile:
    id: str                 # uuid4 hex, also the Keychain account name
    label: str              # human name, defaults to the link fragment
    link: dict[str, Any]    # parsed link, MINUS uuid
    last_latency_ms: int | None = None   # cache, overwritten by "test all"
```

`link` is exactly the dict `parse_vless_uri` already returns. It is JSON-serializable by
construction (headers and `xhttp_extra` are `dict[str, str]` / `dict`). Reusing the parser's own
output avoids a second normalization format that could drift out of sync with the first.

### The uuid split

The store **never** sees a UUID.

```
parse_vless_uri(raw) ──► parsed["uuid"] ──► secrets.set(profile.id, uuid) ──► Keychain
                                         └► parsed.pop("uuid") ─────────────► profiles.json
```

Resolution is the inverse, in exactly one place:

```python
def resolve_link(profile, secrets) -> dict:
    link = dict(profile.link)
    link["uuid"] = secrets.get(profile.id)   # raises AppError if missing
    return link
```

Every consumer of a link goes through `resolve_link`. There is no path that reads `profile.link`
and hands it to `build_xray_config` without the UUID restored.

### profiles.json

```json
{
  "version": 1,
  "active": "9f1c…",
  "profiles": [
    { "id": "9f1c…", "label": "home", "link": { "server": "…", "port": 2083, "…": "…" } }
  ]
}
```

Written atomically: temp file in the same directory → `os.replace()`. A crash mid-write leaves the
previous file intact rather than a truncated one. Directory `0700`, file `0600`.

`active` is a profile id, not an index — indexes shift when profiles are deleted.

---

## The switching seam

This is the interface D3 deliberately isolates. The TUI never talks to Xray.

```python
class XrayProcess(Protocol):
    def apply(self, link: dict, *, socks: str, http: str | None) -> None: ...
    def stop(self) -> None: ...
```

`apply` performs D7's ordered switch and raises `AppError` on failure. Today it is implemented by
regenerating the config and respawning. A future hot-swap implementation satisfies the same
signature; nothing above this line changes.

```
  TUI (app.py)                  never imports xray.py
      │
      ▼
  ProxyService                  orchestration only: which profile, which ports
      │  resolve_link → build_xray_config → XrayProcess.apply
      ▼
  XrayProcess                   subprocess, config lifecycle, listener readiness
      │
      ▼
  Xray (external process)
```

---

## Control flow — switching profiles

```
User presses Enter on a row
  │
  ├─ 1. resolve_link(profile)          Keychain read; AppError if the UUID is gone
  ├─ 2. build_xray_config(link, …)     pure; same call the CLI already makes
  ├─ 3. write config 0600 → xray -test → FAIL? show error, old proxy still running, STOP
  ├─ 4. terminate old process (4 s grace, then kill)
  ├─ 5. spawn new process
  ├─ 6. wait_for_listener(both ports)  FAIL? show error, leave stopped, do not half-start
  └─ 7. persist active id to profiles.json
```

Step 3 before step 4 is the whole point of D7.

---

## Latency probe

`latency.py` exposes one function:

```python
def probe_server(host: str, port: int, *, timeout: float = 3.0) -> int | None:
    """TCP connect latency in ms, or None if unreachable."""
```

Plain `socket.create_connection` against the profile's server — no TLS handshake, no tunnel, no
proxy. Cheap enough to run for every profile on demand from a thread pool.

The TUI runs probes in a Textual worker (`@work(thread=True)`) and pushes each result back with
`call_from_thread`. The event loop is never blocked, so the UI stays responsive while 20 nodes
time out.

Results write back into `Profile.last_latency_ms` and are sorted by the table. **Probing never
starts a proxy and never changes the active profile.**

---

## Threading rules

Textual is single-threaded on its event loop. Rules:

1. No `subprocess`, `socket`, or Keychain call in a handler body. All go in `@work(thread=True)`.
2. Worker → UI only via `call_from_thread`.
3. `XrayProcess` is owned by exactly one worker at a time; the TUI serializes switches through a
   single guard flag so a double-Enter cannot race two spawns.

---

## Backwards compatibility

`vless_proxy.py` keeps every existing flag (`--link`, `--link-file`, `--xray`, `--socks`,
`--http`, `--no-http`, `--allow-insecure`, `--check`, `--update-xray`) and delegates to
`vlessp.cli`. It also re-exports `AppError`, `parse_vless_uri`, and `build_xray_config` so the
current `tests/test_vless_proxy.py` keeps passing unmodified during the refactor.

The only intended behaviour change is the dependency list. Nothing about link handling, config
generation, or TLS policy changes in V1.