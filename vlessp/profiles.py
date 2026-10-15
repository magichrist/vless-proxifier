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

Subscription nodes live here too (S4): a fetched node is an ordinary
``Profile`` with a ``source``, and :meth:`ProfileStore.reconcile` performs the
same split — store the link minus the UUID, put the UUID in the Keychain — so
there is exactly one code path and one secret boundary to audit.
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from vlessp.errors import AppError

if TYPE_CHECKING:
    from vlessp.secrets import SecretStore

STORE_VERSION: int = 1

APP_NAME = "vless-python-proxy"

# An imported profile's ``source``. A subscription's NAME goes after the
# prefix: "subscription:<name>". Empty ``source`` means hand-added, and that
# emptiness is what keeps a refresh of one subscription from touching profiles
# that belong to another one — or to the user.
#
# Keyed by name, not by a generated id. An id would need a registry mapping id
# to name (or to URL) for a refresh to find its way back, and there isn't one;
# the name is the only identifier that closes the loop without inventing a
# second table to keep in sync.
SUB_SOURCE_PREFIX: str = "subscription:"

# Keychain account prefix for the subscription URL items themselves (S3: a
# subscription URL is a credential and gets the same treatment as a profile
# UUID). Deliberately the same string as SUB_SOURCE_PREFIX but a DIFFERENT
# namespace: this one keys URL items by subscription name, while reconcile
# keys each node's UUID by its profile id, exactly like every hand-added
# profile. Same service, two account namespaces, no collision.
SUB_SECRET_PREFIX: str = "subscription:"


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

    ``source`` is empty for a hand-added profile and ``"subscription:<id>"``
    for one imported from a subscription (S4: imported nodes are ordinary
    profiles, there is no separate imported type). ``unavailable`` marks an
    imported profile that stopped appearing upstream: it is kept and flagged,
    never deleted, because an upstream omission is usually a transient outage
    or a bad fetch and the user may have edited that node (S5).

    Both carry defaults so every hand-added profile and every existing store
    written before subscriptions existed keeps working untouched.
    """

    id: str
    label: str
    link: dict[str, Any] = field(default_factory=dict)
    last_latency_ms: int | None = None
    source: str = ""
    unavailable: bool = False


def node_identity(link: Mapping[str, Any]) -> tuple[str, str, str, str]:
    """(server, port, network, sni) — the identity used to match an incoming node
    to a stored profile. Stable across UUID rotation and across local renames.

    Why exactly these four. The label is user-owned, and S5 requires a local
    rename to survive, so matching on it would discard the user's edit on the
    next fetch. The uuid is *the thing that rotates*, so matching on it would
    make every rotation look like a brand new node. Everything else either
    travels with the server or is cosmetic.

    Hostnames and SNI are compared case-insensitively (DNS and RFC 6066 both
    are); the port is stringified so an int from JSON and a str from a URI
    compare equal. Values are coerced to ``str`` and total — a link missing a
    key yields ``""`` rather than raising, so identity is computable on any
    stored profile, including ones written by an older version.

    Accepts any ``Mapping`` so callers need not copy the link first.
    """
    return (
        str(link.get("server", "")).strip().lower(),
        str(link.get("port", "")).strip(),
        str(link.get("network", "")).strip().lower(),
        str(link.get("sni", "")).strip().lower(),
    )


class ParsedNode(Protocol):
    """Structural type for what `vlessp.subscriptions.parse` returns.

    Declared here rather than imported so that profiles.py has no dependency on
    subscriptions.py, and the store stays testable without the fetch layer.

    ``link`` is the full ``parse_vless_uri`` output, uuid included: splitting
    that secret from the config is this module's job, not the fetch layer's.
    """

    label: str
    link: dict[str, Any]


@dataclass(frozen=True)
class ReconcileResult:
    """What one :meth:`ProfileStore.reconcile` did, bucketed for the UI.

    Buckets are mutually exclusive per profile, so ``changed`` is a true count
    of profiles the fetch altered rather than a double count of events. A
    profile that reappears *and* changed is reported as ``updated`` (with
    ``unavailable`` cleared); ``restored`` is for the pure reappearance.
    """

    added: tuple[Profile, ...]
    updated: tuple[Profile, ...]  # uuid rotated, or other fields changed
    unchanged: tuple[Profile, ...]
    marked_unavailable: tuple[Profile, ...]
    restored: tuple[Profile, ...]  # was flagged missing, reappeared upstream

    @property
    def changed(self) -> int:
        """Number of profiles this fetch altered (availability flags included)."""
        return (
            len(self.added)
            + len(self.updated)
            + len(self.restored)
            + len(self.marked_unavailable)
        )


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
    # Both new fields are written only when they carry information, so a store
    # of hand-added profiles still serialises byte-for-byte as it did before
    # subscriptions existed.
    if profile.source:
        data["source"] = profile.source
    if profile.unavailable:
        data["unavailable"] = True
    return data


def _profile_from_json(data: Any) -> Profile:
    # Validate shape without echoing file content into the error message.
    if not isinstance(data, dict):
        raise AppError("profiles file has an invalid profile entry: expected an object.")
    pid = data.get("id")
    label = data.get("label")
    link = data.get("link")
    latency = data.get("last_latency_ms", None)
    # Both fields are absent from a store written before subscriptions existed;
    # absence means hand-added and available, which is what they were.
    source = data.get("source", "")
    unavailable = data.get("unavailable", False)
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
    if not isinstance(source, str):
        raise AppError("profiles file has an invalid profile entry: bad source.")
    if not isinstance(unavailable, bool):
        raise AppError("profiles file has an invalid profile entry: bad availability flag.")
    return Profile(
        id=pid,
        label=label,
        link=link,
        last_latency_ms=latency,
        source=source,
        unavailable=unavailable,
    )


def _validate_new_profile(label: Any, link: Any) -> None:
    """Shared gate for anything entering the store as a new profile.

    Kept in one place so :meth:`ProfileStore.add` and
    :meth:`ProfileStore.reconcile` reject the same shapes with the same
    messages — an imported node gets no softer a contract than a typed one.
    """
    if not isinstance(label, str) or not label.strip():
        raise AppError("profile label must be a non-empty string.")
    if not isinstance(link, dict):
        raise AppError("profile link must be an object.")
    if "uuid" in link:
        raise AppError("profile link must not contain credentials.")


class ProfileStore:
    """In-memory profile collection with atomic JSON persistence."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else DEFAULT_STORE_PATH
        self._profiles: dict[str, Profile] = {}
        self._active_id: str | None = None
        # Names of subscriptions the user has added. Kept as their own list
        # rather than derived from profile sources because a subscription that
        # currently imports zero nodes leaves no profile behind -- and that is
        # precisely the one a refresh should still retry.
        self._subscriptions: list[str] = []

    @property
    def subscriptions(self) -> list[str]:
        """Names of every subscription this store knows about, in insertion order."""
        return list(self._subscriptions)

    def remember_subscription(self, name: str) -> bool:
        """Record a subscription name. Returns True if it was newly added."""
        if not name or name in self._subscriptions:
            return False
        self._subscriptions.append(name)
        return True

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
        # Absent in stores written before subscriptions existed; that is not an
        # error, it just means nothing has been imported yet.
        subscriptions_raw = data.get("subscriptions", [])
        if not isinstance(subscriptions_raw, list) or not all(
            isinstance(name, str) for name in subscriptions_raw
        ):
            raise AppError("profiles file is malformed: subscriptions must be a list of names.")
        self._subscriptions = list(dict.fromkeys(subscriptions_raw))

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
            "subscriptions": list(self._subscriptions),
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

    def _new_id(self) -> str:
        """A profile id that no existing profile is using."""
        profile_id = uuid.uuid4().hex
        while profile_id in self._profiles:
            profile_id = uuid.uuid4().hex  # avoid the astronomically unlikely collision.
        return profile_id

    def add(self, label: str, link: dict[str, Any]) -> Profile:
        """Add a profile; ``link`` must already have its uuid popped (enforced)."""
        _validate_new_profile(label, link)
        profile = Profile(id=self._new_id(), label=label, link=copy.deepcopy(link))
        self._profiles[profile.id] = profile
        return profile

    def by_source(self, source: str) -> list[Profile]:
        """Every profile imported from ``source``, in insertion order.

        ``source == ""`` returns the hand-added profiles, which is the same
        empty-source default :meth:`reconcile` uses to leave them alone.
        """
        return [p for p in self._profiles.values() if p.source == source]

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
            # Carry provenance and availability: a rename in the TUI must not
            # quietly turn a subscription node into a hand-added one.
            source=current.source,
            unavailable=current.unavailable,
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

    def reconcile(
        self,
        nodes: Sequence[ParsedNode],
        *,
        source: str,
        secrets: SecretStore,
    ) -> ReconcileResult:
        """Fold one subscription fetch into the store, then persist once.

        This is the same split as :meth:`add` — ``store.add(label, link)`` plus
        ``secrets.set(id, uuid)`` — except that a subscription is re-fetched, so
        the operation must be idempotent and non-destructive. Per node
        (S5):

        * identity match, uuid unchanged → ``unchanged``, nothing touched
        * identity match, uuid rotated → ``updated``, credential rewritten
        * identity match, any other link field changed → ``updated``, uuid kept
        * no identity match under this ``source`` → ``added``
        * a profile of this ``source`` missing from ``nodes`` → ``unavailable``

        **Nothing is ever deleted.** An upstream omission is usually a
        transient outage or a bad fetch, and the user may have edited that node;
        flagging is reversible, deleting is not. **A local label is never
        overwritten** — a rename survives every fetch.

        Only profiles whose ``source`` matches are considered, so one
        subscription's refresh cannot touch another subscription's nodes or the
        user's hand-added ones.

        All-or-nothing, like a single ``add``: the whole batch is validated
        before anything is written, credentials go to the Keychain before the
        store is touched, and a failure anywhere raises :class:`AppError` with
        the store unmodified on disk and in memory (a best-effort rollback
        returns the Keychain to its prior state too). No message names a UUID,
        a URI, or any part of a node's fields.

        Notes for callers:

        * ``source`` must be non-empty; build it as
          ``SUB_SOURCE_PREFIX + subscription_id``. An empty ``source`` would
          make imported nodes indistinguishable from hand-added ones.
        * ``secrets`` must support ``get``. Deciding rotation requires reading
          the stored UUID, so a read-fails-closed backend (NullSecretStore)
          reports every node as ``updated`` rather than ``unchanged``.
        * An empty ``nodes`` list flags every profile of this ``source``
          unavailable. Check the fetch before calling if a zero-node result
          might mean a bad response rather than an emptied subscription.
        * Two nodes with the same identity in one fetch are ambiguous; the first
          wins and the rest are ignored rather than becoming profiles that would
          collide on every later fetch.
        """
        if not isinstance(source, str) or not source:
            raise AppError("subscription refresh needs a non-empty source id.")

        stored_by_id = {p.id: p for p in self._profiles.values() if p.source == source}
        stored_by_identity: dict[tuple[str, str, str, str], Profile] = {}
        for profile in stored_by_id.values():
            stored_by_identity.setdefault(node_identity(profile.link), profile)

        added: list[Profile] = []
        updated: list[Profile] = []
        unchanged: list[Profile] = []
        restored: list[Profile] = []
        marked: list[Profile] = []
        # (account, value, previous value or None) — applied only once the whole
        # batch has been validated.
        credential_writes: list[tuple[str, str, str | None]] = []
        next_profiles = dict(self._profiles)
        matched_ids: set[str] = set()
        claimed_identities: set[tuple[str, str, str, str]] = set()

        for node in nodes:
            if not isinstance(getattr(node, "link", None), dict):
                raise AppError("a subscription node has no usable link.")
            link = copy.deepcopy(node.link)
            node_uuid = link.pop("uuid", None)
            if not isinstance(node_uuid, str) or not node_uuid.strip():
                raise AppError("a subscription node is missing its UUID.")
            label = getattr(node, "label", None)
            _validate_new_profile(label, link)  # the same gate as a hand-added node.

            identity = node_identity(link)
            if identity in claimed_identities:
                continue  # duplicate identity within one fetch: the first node wins.
            claimed_identities.add(identity)

            current = stored_by_identity.get(identity)
            if current is None:
                profile_id = uuid.uuid4().hex
                while profile_id in next_profiles:
                    profile_id = uuid.uuid4().hex  # avoid the astronomically unlikely collision.
                profile = Profile(
                    id=profile_id,
                    label=label,
                    link=link,
                    source=source,
                )
                next_profiles[profile_id] = profile
                credential_writes.append((profile_id, node_uuid, None))
                added.append(profile)
                matched_ids.add(profile_id)
                continue

            matched_ids.add(current.id)
            try:
                stored_uuid = secrets.get(current.id)
            except Exception:
                # The item is gone or the backend refuses to read (NullSecretStore).
                # Either way the incoming UUID is authoritative, so the credential
                # is rewritten — this repairs a lost item instead of bricking the
                # whole fetch.
                stored_uuid = None
            link_changed = link != current.link
            uuid_changed = stored_uuid != node_uuid
            if not link_changed and not uuid_changed and not current.unavailable:
                unchanged.append(current)
                continue

            updated_profile = Profile(
                id=current.id,
                label=current.label,  # a local rename always survives
                link=link,
                last_latency_ms=current.last_latency_ms,
                source=current.source,
                unavailable=False,
            )
            next_profiles[current.id] = updated_profile
            if current.unavailable and not (link_changed or uuid_changed):
                restored.append(updated_profile)
            else:
                updated.append(updated_profile)
            if uuid_changed:
                credential_writes.append((current.id, node_uuid, stored_uuid))

        for profile_id, profile in stored_by_id.items():
            if profile_id in matched_ids or profile.unavailable:
                continue  # present upstream, or already flagged (stay quiet, not news)
            flagged = Profile(
                id=profile.id,
                label=profile.label,
                link=copy.deepcopy(profile.link),
                last_latency_ms=profile.last_latency_ms,
                source=profile.source,
                unavailable=True,
            )
            next_profiles[profile_id] = flagged
            marked.append(flagged)

        written = 0
        try:
            for account, value, _previous in credential_writes:
                secrets.set(account, value)
                written += 1
        except AppError:
            self._rollback_credentials(secrets, credential_writes, written)
            raise
        except Exception as exc:
            self._rollback_credentials(secrets, credential_writes, written)
            raise AppError(f"could not store a node credential: {type(exc).__name__}.") from exc

        self._profiles = next_profiles
        self.save()
        return ReconcileResult(
            added=tuple(added),
            updated=tuple(updated),
            unchanged=tuple(unchanged),
            marked_unavailable=tuple(marked),
            restored=tuple(restored),
        )

    @staticmethod
    def _rollback_credentials(
        secrets: SecretStore,
        writes: Sequence[tuple[str, str, str | None]],
        written: int,
    ) -> None:
        """Best-effort undo of the credential writes already applied.

        The store itself is untouched at this point, so without this a failed
        fetch would leave Keychain items behind that no profile references.
        Restoring a rotation's previous value is what keeps a *partial* failure
        from destroying a working credential. Every step may itself fail (the
        Keychain may be what just failed), so nothing here raises.
        """
        for account, _value, previous in reversed(list(writes[:written])):
            try:
                if previous is None:
                    secrets.delete(account)
                else:
                    secrets.set(account, previous)
            except Exception:
                pass

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
            source=current.source,
            unavailable=current.unavailable,
        )
        self._profiles[profile_id] = updated
        return updated


__all__ = [
    "STORE_VERSION",
    "APP_NAME",
    "DEFAULT_STORE_PATH",
    "SUB_SECRET_PREFIX",
    "SUB_SOURCE_PREFIX",
    "ParsedNode",
    "Profile",
    "ProfileStore",
    "ReconcileResult",
    "app_data_dir",
    "node_identity",
    "resolve_link",
]
