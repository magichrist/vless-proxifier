"""Profile model and JSON store.

The store holds everything about a profile EXCEPT the UUID. The UUID is the
only true credential in a VLESS link (Reality's ``pbk`` is a public key by
definition, ``sid`` is a short id), so it lives in the macOS Keychain under
one item per profile and is re-attached in exactly one place,
:func:`resolve_link`.

Why this split: ``profiles.json`` is readable by anything running as you, so
it must never become a credential file. Defence in depth — :meth:`ProfileStore.add`
and :meth:`ProfileStore.update` reject any link dict that still carries a
``"uuid"`` key instead of trusting callers to pop it.
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from vlessp.errors import AppError

if TYPE_CHECKING:
    from vlessp.secrets import SecretStore

STORE_VERSION: int = 1

APP_NAME = "vless-python-proxy"


def app_data_dir() -> Path:
    """Per-platform application data directory.

    Local copy of the logic already in ``vless_proxy.py`` (and owned by the
    CORE agent in ``vlessp.xray``) — duplicated here deliberately so this
    module never imports ``vlessp.xray`` and cannot form a circular import.
    """
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / APP_NAME


DEFAULT_STORE_PATH = app_data_dir() / "profiles.json"


@dataclass(frozen=True)
class Profile:
    """One saved proxy profile.

    ``link`` is the parsed link dict MINUS the uuid — it must never hold a
    UUID. Frozen so mutating a profile always means building a new one, which
    keeps the in-memory store and the on-disk JSON from aliasing each other.
    """

    id: str
    label: str
    link: dict[str, Any] = field(default_factory=dict)
    last_latency_ms: int | None = None


def resolve_link(profile: Profile, secrets: SecretStore) -> dict[str, Any]:
    """Re-attach the UUID to a stored profile link.

    The ONLY place a UUID re-enters a link dict. Raises AppError (never
    echoing the UUID) when the Keychain item is gone.
    """
    link = copy.deepcopy(profile.link)
    try:
        uuid_value = secrets.get(profile.id)
    except AppError:
        raise
    except Exception as exc:
        raise AppError(f"the UUID for profile {profile.id} is missing from the Keychain") from exc
    if not uuid_value:
        raise AppError(f"the UUID for profile {profile.id} is missing from the Keychain")
    link["uuid"] = uuid_value
    return link


def _profile_to_json(profile: Profile) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": profile.id,
        "label": profile.label,
        "link": copy.deepcopy(profile.link),
    }
    if profile.last_latency_ms is not None:
        data["last_latency_ms"] = profile.last_latency_ms
    return data


def _profile_from_json(data: Any) -> Profile:
    # Validate shape without echoing file content into the error message.
    if not isinstance(data, dict):
        raise AppError("profiles file has an invalid profile entry: expected an object.")
    pid = data.get("id")
    label = data.get("label")
    link = data.get("link")
    latency = data.get("last_latency_ms", None)
    if not isinstance(pid, str) or not pid:
        raise AppError("profiles file has an invalid profile entry: bad or missing id.")
    if not isinstance(label, str) or not label:
        raise AppError("profiles file has an invalid profile entry: bad or missing label.")
    if not isinstance(link, dict):
        raise AppError("profiles file has an invalid profile entry: bad or missing link.")
    if "uuid" in link:
        raise AppError("profiles file has an invalid profile entry: link must not contain credentials.")
    if latency is not None and (not isinstance(latency, int) or isinstance(latency, bool) or latency < 0):
        raise AppError("profiles file has an invalid profile entry: bad latency value.")
    return Profile(id=pid, label=label, link=link, last_latency_ms=latency)


class ProfileStore:
    """In-memory profile collection with atomic JSON persistence."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else DEFAULT_STORE_PATH
        self._profiles: dict[str, Profile] = {}
        self._active_id: str | None = None

    @property
    def path(self) -> Path:
        """Filesystem location of ``profiles.json``."""
        return self._path

    @property
    def active_id(self) -> str | None:
        """Id of the active profile, or None when none is selected."""
        return self._active_id

    def load(self) -> None:
        """Load state from disk; a missing file means an empty store."""
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._profiles = {}
            self._active_id = None
            return
        except OSError as exc:
            raise AppError(f"cannot read profiles file: {type(exc).__name__}.") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AppError("profiles file is malformed: invalid JSON.") from exc
        if not isinstance(data, dict):
            raise AppError("profiles file is malformed: top level must be an object.")
        version = data.get("version", STORE_VERSION)
        if not isinstance(version, int) or isinstance(version, bool):
            raise AppError("profiles file is malformed: bad version field.")
        if version > STORE_VERSION:
            raise AppError(
                f"profiles file version {version} is newer than supported version {STORE_VERSION}."
            )
        if version < STORE_VERSION:
            raise AppError(
                f"profiles file version {version} is older than supported version {STORE_VERSION}."
            )
        profiles_raw = data.get("profiles", [])
        if not isinstance(profiles_raw, list):
            raise AppError("profiles file is malformed: profiles must be a list.")
        active = data.get("active", None)
        if active is not None and not isinstance(active, str):
            raise AppError("profiles file is malformed: active must be a profile id or null.")
        profiles: dict[str, Profile] = {}
        for entry in profiles_raw:
            profile = _profile_from_json(entry)
            if profile.id in profiles:
                raise AppError("profiles file is malformed: duplicate profile id.")
            profiles[profile.id] = profile
        if active is not None and active not in profiles:
            raise AppError("profiles file is malformed: active id matches no profile.")
        self._profiles = profiles
        self._active_id = active

    def save(self) -> None:
        """Persist state atomically with 0700 dir / 0600 file permissions."""
        parent = self._path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AppError(f"cannot create profiles directory: {type(exc).__name__}.") from exc
        try:
            os.chmod(parent, 0o700)
        except OSError as exc:
            raise AppError(f"cannot secure profiles directory: {type(exc).__name__}.") from exc
        payload = {
            "version": STORE_VERSION,
            "active": self._active_id,
            "profiles": [_profile_to_json(p) for p in self._profiles.values()],
        }
        try:
            text = json.dumps(payload, indent=2, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise AppError("profiles cannot be serialised: unsupported value shape.") from exc
        # Temp file in the SAME directory so os.replace() is atomic on one filesystem.
        fd, tmp_name = tempfile.mkstemp(dir=str(parent), prefix=".profiles-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass  # fsync is best-effort on exotic filesystems; replace is still atomic.
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self._path)
        except AppError:
            raise
        except Exception as exc:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            if isinstance(exc, OSError):
                raise AppError(f"cannot write profiles file: {type(exc).__name__}.") from exc
            raise AppError("cannot write profiles file: unexpected failure.") from exc
        try:
            dir_fd = os.open(str(parent), os.O_RDONLY)
        except OSError:
            return  # best-effort only; the atomic replace above already succeeded.
        try:
            try:
                os.fsync(dir_fd)
            except OSError:
                pass
        finally:
            os.close(dir_fd)

    def all(self) -> list[Profile]:
        """All profiles in insertion order."""
        return list(self._profiles.values())

    def get(self, profile_id: str) -> Profile:
        """Return one profile by id; unknown ids raise AppError (id is safe to echo)."""
        try:
            return self._profiles[profile_id]
        except KeyError:
            raise AppError(f"unknown profile: {profile_id}.") from None

    def add(self, label: str, link: dict[str, Any]) -> Profile:
        """Add a profile; ``link`` must already have its uuid popped (enforced)."""
        if not isinstance(label, str) or not label.strip():
            raise AppError("profile label must be a non-empty string.")
        if not isinstance(link, dict):
            raise AppError("profile link must be an object.")
        if "uuid" in link:
            raise AppError("profile link must not contain credentials.")
        profile_id = uuid.uuid4().hex
        while profile_id in self._profiles:
            profile_id = uuid.uuid4().hex  # avoid the astronomically unlikely collision.
        profile = Profile(id=profile_id, label=label, link=copy.deepcopy(link))
        self._profiles[profile.id] = profile
        return profile

    def update(
        self,
        profile_id: str,
        *,
        label: str | None = None,
        link: dict[str, Any] | None = None,
    ) -> Profile:
        """Replace label and/or link of one profile, returning the new frozen Profile."""
        current = self.get(profile_id)
        new_label = current.label if label is None else label
        new_link = current.link if link is None else link
        if label is not None and (not isinstance(label, str) or not label.strip()):
            raise AppError("profile label must be a non-empty string.")
        if link is not None:
            if not isinstance(link, dict):
                raise AppError("profile link must be an object.")
            if "uuid" in link:
                raise AppError("profile link must not contain credentials.")
            new_link = copy.deepcopy(link)
        else:
            new_link = copy.deepcopy(current.link)
        updated = Profile(
            id=current.id,
            label=new_label,
            link=new_link,
            last_latency_ms=current.last_latency_ms,
        )
        self._profiles[profile_id] = updated
        return updated

    def delete(self, profile_id: str) -> None:
        """Remove a profile; clears ``active_id`` when it pointed at the deleted profile."""
        if profile_id not in self._profiles:
            raise AppError(f"unknown profile: {profile_id}.")
        del self._profiles[profile_id]
        if self._active_id == profile_id:
            self._active_id = None

    def resolve(self, ref: str) -> Profile:
        """Find a profile by id first, then by label; unknown refs raise AppError."""
        if ref in self._profiles:
            return self._profiles[ref]
        for profile in self._profiles.values():
            if profile.label == ref:
                return profile
        raise AppError("unknown profile reference.")

    def set_active(self, profile_id: str) -> None:
        """Mark a profile active; unknown ids are rejected so active never dangles."""
        if profile_id not in self._profiles:
            raise AppError(f"unknown profile: {profile_id}.")
        self._active_id = profile_id

    def set_latency(self, profile_id: str, latency_ms: int | None) -> Profile:
        """Update the cached latency for one profile, returning the new Profile."""
        current = self.get(profile_id)
        if latency_ms is not None and (
            not isinstance(latency_ms, int) or isinstance(latency_ms, bool) or latency_ms < 0
        ):
            raise AppError("latency must be a non-negative integer or null.")
        updated = Profile(
            id=current.id,
            label=current.label,
            link=copy.deepcopy(current.link),
            last_latency_ms=latency_ms,
        )
        self._profiles[profile_id] = updated
        return updated


__all__ = [
    "STORE_VERSION",
    "APP_NAME",
    "DEFAULT_STORE_PATH",
    "Profile",
    "ProfileStore",
    "app_data_dir",
    "resolve_link",
]
