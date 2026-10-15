"""Tests for vlessp.profiles — JSON store, no-UUID invariant, atomic saves."""
from __future__ import annotations

import dataclasses
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vlessp.errors import AppError
from vlessp.profiles import (
    STORE_VERSION,
    Profile,
    ProfileStore,
    app_data_dir,
    resolve_link,
)
from vlessp.secrets import NullSecretStore

TEST_UUID = "11111111-2222-4333-8444-555555555555"

SAMPLE_LINK = {
    "server": "example.com",
    "port": 443,
    "security": "reality",
    "transport": "tcp",
    "sni": "example.com",
    "fingerprint": "chrome",
    "pbk": "publickeyvalue",
    "sid": "abc123",
}

SAMPLE_LINK_2 = {
    "server": "other.example.org",
    "port": 8443,
    "security": "tls",
    "transport": "ws",
    "path": "/ws",
    "host": "other.example.org",
}


def make_store() -> tuple[ProfileStore, tempfile.TemporaryDirectory]:
    tmp = tempfile.TemporaryDirectory()
    store = ProfileStore(path=Path(tmp.name) / "profiles.json")
    return store, tmp


class DictSecretStore:
    """Minimal in-memory SecretStore for resolve_link tests."""

    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values = dict(values or {})

    def set(self, account: str, value: str) -> None:
        self._values[account] = value

    def get(self, account: str) -> str:
        try:
            return self._values[account]
        except KeyError:
            raise AppError(f"the UUID for profile {account} is missing from the Keychain") from None

    def delete(self, account: str) -> None:
        self._values.pop(account, None)


class TestRoundTrip(unittest.TestCase):
    def test_add_save_load_identical(self) -> None:
        store, tmp = make_store()
        try:
            p1 = store.add("home", SAMPLE_LINK)
            p2 = store.add("work", SAMPLE_LINK_2)
            store.set_active(p1.id)
            store.set_latency(p2.id, 42)
            store.save()
            reloaded = ProfileStore(path=store.path)
            reloaded.load()
            self.assertEqual(reloaded.active_id, p1.id)
            got = {p.id: p for p in reloaded.all()}
            self.assertEqual(set(got), {p1.id, p2.id})
            self.assertEqual(got[p1.id].label, "home")
            self.assertEqual(got[p1.id].link, SAMPLE_LINK)
            self.assertIsNone(got[p1.id].last_latency_ms)
            self.assertEqual(got[p2.id].link, SAMPLE_LINK_2)
            self.assertEqual(got[p2.id].last_latency_ms, 42)
            # Caller mutation must not alias stored state.
            evil = dict(SAMPLE_LINK)
            store2, tmp2 = make_store()
            try:
                p3 = store2.add("x", evil)
                evil["server"] = "mutated.example"
                self.assertNotEqual(p3.link["server"], "mutated.example")
            finally:
                tmp2.cleanup()
        finally:
            tmp.cleanup()


class TestNoUuidInvariant(unittest.TestCase):
    def test_add_rejects_link_with_uuid(self) -> None:
        store, tmp = make_store()
        try:
            bad = dict(SAMPLE_LINK)
            bad["uuid"] = TEST_UUID
            with self.assertRaises(AppError):
                store.add("bad", bad)
        finally:
            tmp.cleanup()

    def test_update_rejects_link_with_uuid(self) -> None:
        store, tmp = make_store()
        try:
            p = store.add("ok", SAMPLE_LINK)
            bad = dict(SAMPLE_LINK)
            bad["uuid"] = TEST_UUID
            with self.assertRaises(AppError):
                store.update(p.id, link=bad)
            # Stored profile unchanged.
            self.assertEqual(store.get(p.id).link, SAMPLE_LINK)
        finally:
            tmp.cleanup()

    def test_serialised_store_contains_uuid_nowhere(self) -> None:
        store, tmp = make_store()
        try:
            store.add("home", SAMPLE_LINK)
            store.add("work", SAMPLE_LINK_2)
            store.save()
            text = store.path.read_text(encoding="utf-8")
            self.assertNotIn(TEST_UUID, text)
            self.assertNotIn("uuid", text)
            # Belt and braces: no value anywhere in the decoded tree equals a uuid.
            data = json.loads(text)

            def walk(node: object) -> None:
                if isinstance(node, dict):
                    for key, value in node.items():
                        self.assertNotEqual(key, "uuid")
                        walk(value)
                elif isinstance(node, list):
                    for item in node:
                        walk(item)

            walk(data)
        finally:
            tmp.cleanup()


class TestAtomicSave(unittest.TestCase):
    def test_failed_replace_leaves_previous_file_intact(self) -> None:
        store, tmp = make_store()
        try:
            store.add("home", SAMPLE_LINK)
            store.save()
            before = store.path.read_text(encoding="utf-8")
            store.add("work", SAMPLE_LINK_2)
            with mock.patch("os.replace", side_effect=OSError("boom")):
                with self.assertRaises(AppError):
                    store.save()
            after = store.path.read_text(encoding="utf-8")
            self.assertEqual(before, after)
            reloaded = ProfileStore(path=store.path)
            reloaded.load()
            self.assertEqual(len(reloaded.all()), 1)
        finally:
            tmp.cleanup()


class TestPermissions(unittest.TestCase):
    def test_dir_0700_and_file_0600(self) -> None:
        store, tmp = make_store()
        try:
            store.add("home", SAMPLE_LINK)
            store.save()
            dir_mode = stat.S_IMODE(os.stat(store.path.parent).st_mode)
            file_mode = stat.S_IMODE(os.stat(store.path).st_mode)
            self.assertEqual(dir_mode, 0o700)
            self.assertEqual(file_mode, 0o600)
        finally:
            tmp.cleanup()


class TestResolve(unittest.TestCase):
    def test_resolve_by_id_and_label(self) -> None:
        store, tmp = make_store()
        try:
            p1 = store.add("home", SAMPLE_LINK)
            p2 = store.add("work", SAMPLE_LINK_2)
            self.assertEqual(store.resolve(p1.id), p1)
            self.assertEqual(store.resolve("work"), p2)
            # Id wins over label when both match different profiles.
            store.update(p2.id, label=p1.id)
            self.assertEqual(store.resolve(p1.id).id, p1.id)
        finally:
            tmp.cleanup()

    def test_resolve_unknown_raises(self) -> None:
        store, tmp = make_store()
        try:
            store.add("home", SAMPLE_LINK)
            with self.assertRaises(AppError):
                store.resolve("no-such-profile")
        finally:
            tmp.cleanup()


class TestDeleteActive(unittest.TestCase):
    def test_delete_clears_active_id(self) -> None:
        store, tmp = make_store()
        try:
            p1 = store.add("home", SAMPLE_LINK)
            p2 = store.add("work", SAMPLE_LINK_2)
            store.set_active(p1.id)
            store.delete(p1.id)
            self.assertIsNone(store.active_id)
            with self.assertRaises(AppError):
                store.get(p1.id)
            self.assertEqual(store.get(p2.id).label, "work")
        finally:
            tmp.cleanup()

    def test_delete_unknown_raises(self) -> None:
        store, tmp = make_store()
        try:
            with self.assertRaises(AppError):
                store.delete("missing")
        finally:
            tmp.cleanup()

    def test_set_active_rejects_unknown(self) -> None:
        store, tmp = make_store()
        try:
            with self.assertRaises(AppError):
                store.set_active("missing")
        finally:
            tmp.cleanup()


class TestLoadEdgeCases(unittest.TestCase):
    def test_missing_file_is_empty_store(self) -> None:
        store, tmp = make_store()
        try:
            store.load()  # file does not exist yet
            self.assertEqual(store.all(), [])
            self.assertIsNone(store.active_id)
        finally:
            tmp.cleanup()

    def test_malformed_json_raises(self) -> None:
        store, tmp = make_store()
        try:
            store.path.parent.mkdir(parents=True, exist_ok=True)
            store.path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(AppError) as ctx:
                store.load()
            self.assertNotIn("{not json", str(ctx.exception))
        finally:
            tmp.cleanup()

    def test_unknown_version_raises(self) -> None:
        store, tmp = make_store()
        try:
            store.path.parent.mkdir(parents=True, exist_ok=True)
            store.path.write_text(
                json.dumps({"version": STORE_VERSION + 1, "active": None, "profiles": []}),
                encoding="utf-8",
            )
            with self.assertRaises(AppError):
                store.load()
        finally:
            tmp.cleanup()

    def test_bad_shape_raises_without_echo(self) -> None:
        store, tmp = make_store()
        try:
            store.path.parent.mkdir(parents=True, exist_ok=True)
            store.path.write_text(json.dumps({"version": 1, "profiles": "oops"}), encoding="utf-8")
            with self.assertRaises(AppError):
                store.load()
        finally:
            tmp.cleanup()

    def test_stored_uuid_rejected_on_load(self) -> None:
        store, tmp = make_store()
        try:
            bad = dict(SAMPLE_LINK)
            bad["uuid"] = TEST_UUID
            store.path.parent.mkdir(parents=True, exist_ok=True)
            store.path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "active": None,
                        "profiles": [{"id": "abc", "label": "x", "link": bad}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(AppError) as ctx:
                store.load()
            self.assertNotIn(TEST_UUID, str(ctx.exception))
        finally:
            tmp.cleanup()


class TestResolveLink(unittest.TestCase):
    def test_resolve_link_reattaches_uuid(self) -> None:
        store, tmp = make_store()
        try:
            profile = store.add("home", SAMPLE_LINK)
            secrets = DictSecretStore({profile.id: TEST_UUID})
            link = resolve_link(profile, secrets)
            self.assertEqual(link["uuid"], TEST_UUID)
            self.assertEqual(link["server"], "example.com")
            # Stored profile itself gains no uuid.
            self.assertNotIn("uuid", store.get(profile.id).link)
        finally:
            tmp.cleanup()

    def test_resolve_link_missing_secret_raises_without_uuid(self) -> None:
        store, tmp = make_store()
        try:
            profile = store.add("home", SAMPLE_LINK)
            with self.assertRaises(AppError) as ctx:
                resolve_link(profile, NullSecretStore())
            self.assertNotIn(TEST_UUID, str(ctx.exception))
        finally:
            tmp.cleanup()

    def test_profile_is_frozen(self) -> None:
        profile = Profile(id="x", label="y", link={})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            profile.label = "z"  # type: ignore[misc]

    def test_app_data_dir_returns_path(self) -> None:
        self.assertIsInstance(app_data_dir(), type(Path()))


if __name__ == "__main__":
    unittest.main()
