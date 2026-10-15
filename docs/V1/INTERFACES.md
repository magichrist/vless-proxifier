# V1 — Interface contract

**Read this before writing code.** Six agents work in parallel on disjoint files. This
document is the contract that lets them do that safely. If a signature here does not match
what you were asked to build, stop and raise it — do not silently change the signature,
because the other agents are coding against it already.

Authored before any implementation. Deviating from it requires updating this file first.

---

## Fixed ground truth (do not modify)

### `vlessp/errors.py` — DONE, do not touch

```python
class AppError(Exception): ...
```

**Invariant:** an `AppError` message must never contain any part of a VLESS URI. Format from
the *shape* of the problem, never from the URI, a parsed link dict, or a config file.

### `vlessp/__init__.py` — DONE, do not touch

Exports `__version__` and `APP_NAME`.

---

## Module 1 — `vlessp/links.py`  · owner: CORE agent

Extracted from `vless_proxy.py` with **behaviour unchanged**. The existing 9 tests in
`tests/test_vless_proxy.py` must still pass unmodified.

```python
MAX_URI_BYTES: int
UUID_RE: re.Pattern[str]
SHA256_RE: re.Pattern[str]

def is_valid_hostname(host: str) -> bool: ...
def query_params(query: str) -> dict[str, str]: ...
def parse_vless_uri(raw: str, *, allow_insecure: bool = False) -> dict[str, Any]: ...
def build_xray_config(link: dict[str, Any], socks_addr: str, http_addr: str | None) -> dict[str, Any]: ...
```

`parse_vless_uri` returns the exact dict it returns today — do not add, rename, or drop keys.
`build_xray_config` is pure: no I/O, no secrets, no logging.

---

## Module 2 — `vlessp/xray.py`  · owner: CORE agent

Binary install + process supervision. Two distinct responsibilities, both subprocess-based.

```python
GITHUB_API: str
MAX_DOWNLOAD_BYTES: int

def app_data_dir() -> Path: ...
def request_bytes(url: str, *, limit: int, timeout: float = 30.0, json_api: bool = False) -> bytes: ...
def platform_asset() -> str: ...
def find_latest_release_asset(asset_name: str) -> tuple[str, str, str]: ...
def install_xray(*, force: bool = False) -> Path: ...
def resolve_xray(xray_arg: str | None, *, update: bool = False) -> Path: ...
def wait_for_listener(process: subprocess.Popen[bytes], addresses: list[str], timeout: float = 10.0) -> None: ...
```

`XrayProcess` — the **switching seam**. See `01-architecture.md`. This is the single most
important interface in the project: a future hot-swap implementation must satisfy it unchanged.

```python
class XrayProcess:
    def __init__(self, xray_path: Path, *, socks_addr: str, http_addr: str | None) -> None: ...
    def apply(self, link: dict[str, Any]) -> None:
        """D7 ordered switch: build config -> xray -test -> stop old -> spawn -> wait.

        Raises AppError on any failure. MUST NOT leave a half-started process.
        If -test fails, the currently-running process is untouched and still serving.
        """
    def stop(self) -> None:
        """Idempotent. Terminate (4s grace) then kill (2s grace)."""
    @property
    def running(self) -> bool: ...
    @property
    def last_log(self) -> str: ...   # redacted Xray stderr tail, for the TUI log pane
```

`resolve_xray` note: the old signature was `resolve_xray(args: argparse.Namespace)`. The new one
takes plain values so it is testable without argparse. The CLI adapts.

---

## Module 3 — `vlessp/profiles.py`  · owner: STATE agent

```python
STORE_VERSION: int

@dataclass(frozen=True)
class Profile:
    id: str                    # uuid4().hex; also the Keychain account name
    label: str                 # human name, defaults to the URI fragment
    link: dict[str, Any]       # parsed link MINUS uuid — never holds a UUID
    last_latency_ms: int | None = None

def resolve_link(profile: Profile, secrets: "SecretStore") -> dict[str, Any]:
    """The ONLY place a UUID is re-attached. Raises AppError if the Keychain item is gone."""

class ProfileStore:
    def __init__(self, path: Path | None = None) -> None: ...
    def load(self) -> None: ...
    def save(self) -> None: ...            # atomic: temp file + os.replace()
    def all(self) -> list[Profile]: ...
    def get(self, profile_id: str) -> Profile: ...        # raises AppError if unknown
    def add(self, label: str, link: dict[str, Any]) -> Profile: ...   # link must have no uuid
    def update(self, profile_id: str, *, label: str | None = None,
               link: dict[str, Any] | None = None) -> Profile: ...
    def delete(self, profile_id: str) -> None: ...
    def resolve(self, ref: str) -> Profile: ...   # by id OR label
    @property
    def active_id(self) -> str | None: ...
    def set_active(self, profile_id: str) -> None: ...
```

`add`/`update` MUST raise `AppError` if `link` contains a `uuid` key. Defence in depth against a
caller forgetting to pop it — the disk invariant is tested, not trusted.

Atomic save: temp file in the same directory, then `os.replace()`. Directory `0700`, file `0600`.

---

## Module 4 — `vlessp/secrets.py`  · owner: STATE agent

The **only** module permitted to touch the Keychain.

```python
KEYCHAIN_SERVICE: str   # "vless-python-proxy"

class SecretStore(Protocol):
    def set(self, account: str, value: str) -> None: ...
    def get(self, account: str) -> str: ...          # raises AppError if absent
    def delete(self, account: str) -> None: ...

class MacOSKeychain:   # via the `security` CLI, stdlib subprocess
    ...

class NullSecretStore:
    """Always raises AppError on get. Used by every test — tests never touch the real Keychain."""
```

Missing-item error message: `"the UUID for profile X is missing from the Keychain"`.
Never include the UUID itself in the message.

---

## Module 5 — `vlessp/proxy.py` + `vlessp/latency.py`  · owner: RUNTIME agent

```python
# latency.py
def probe_server(host: str, port: int, *, timeout: float = 3.0) -> int | None:
    """TCP connect latency in ms, or None if unreachable. Never starts a proxy."""

# proxy.py
class ProxyService:
    def __init__(self, store: ProfileStore, secrets: SecretStore,
                 xray_path: Path, *, socks_addr: str = "127.0.0.1:10808",
                 http_addr: str | None = "127.0.0.1:10809") -> None: ...
    def connect(self, ref: str) -> Profile: ...     # full D7 switch; raises AppError
    def disconnect(self) -> None: ...
    def connect_active(self) -> Profile | None: ... # reconnect last active on launch
    def probe_all(self, on_result: Callable[[str, int | None], None],
                  *, timeout: float = 3.0) -> None:
        """Threads, one per profile. Calls on_result(profile_id, ms_or_None).
        NEVER starts a proxy and NEVER changes the active profile."""
    @property
    def running(self) -> bool: ...
    @property
    def current(self) -> Profile | None: ...
    def log_tail(self) -> str: ...
```

**Threading:** `ProxyService` is called from Textual worker threads. `connect` must be
serialized — use a `threading.Lock`. A double-Enter must not race two spawns.

---

## Module 6 — `vlessp/tui/`  · owner: TUI agent

```python
# tui/app.py
class VlessApp(App):
    def __init__(self, service: ProxyService, store: ProfileStore) -> None: ...

# tui/screens.py
class AddProfileScreen(ModalScreen[Profile | None]): ...
class EditProfileScreen(ModalScreen[Profile | None]): ...
class ConfirmScreen(ModalScreen[bool]): ...

# tui/widgets.py
class ProfileTable(DataTable): ...
class StatusBar(Static): ...
```

**Textual 8.x API — non-negotiable:**
- `compose()` uses context managers: `with Horizontal(): yield ...`
- `@work(thread=True)` for anything touching a socket, subprocess, or the Keychain
- `self.call_from_thread(...)` to push results back to the UI
- `ModalScreen` + `self.dismiss(result)`; parent uses `await self.push_screen_wait(...)`
- Never block the event loop. Never touch the filesystem outside a worker.
- Bindings per `02-tui-design.md`: `Enter a e d t c l q`

---

## Module 7 — `vlessp/cli.py` + `vless_proxy.py`  · owner: CLI agent

```python
# cli.py
def main(argv: list[str] | None = None) -> int: ...
```

Flags — **every V0 flag must still work**, plus two new ones:

| Flag | Status |
|---|---|
| `--link`, `--link-file`, `--xray`, `--socks`, `--http`, `--no-http`, `--allow-insecure`, `--check`, `--update-xray` | preserved |
| `--profile <id-or-label>` | new — start a saved profile headlessly |
| `--list` | new — print profiles, never print UUIDs |
| `--tui` | new — default when no link source is given |

`vless_proxy.py` at the repo root becomes a **thin shim**: re-export `AppError`,
`parse_vless_uri`, `build_xray_config` (so `tests/test_vless_proxy.py` keeps passing
unmodified) and delegate to `vlessp.cli.main`.

---

## Rules for every agent

1. **Touch only the files assigned to you.** Other agents own the rest, concurrently.
2. **Never edit `pyproject.toml`, `.gitignore`, `docs/`, or `vlessp/errors.py`.**
3. **Never weaken an existing test** to make your code pass.
4. **Never put a URI in an `AppError` message or a log line.**
5. Use `from __future__ import annotations` at the top of every module.
6. Standard library plus `textual` (TUI agent only). No new dependencies.
7. If the spec is ambiguous, choose, add a one-line comment saying why, and move on.
   Do not block — the integrator resolves conflicts at the end.