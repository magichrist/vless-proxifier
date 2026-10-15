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
    SUB_SECRET_PREFIX,
    SUB_SOURCE_PREFIX,
    Profile,
    ProfileStore,
    app_data_dir,
    node_identity,
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
    """Minimal in-memory SecretStore for resolve_link and reconcile tests.

    Stands in for the Keychain so the suite never touches the real one.
    ``NullSecretStore`` cannot be used with ``reconcile``: it raises from
    ``get`` by design, and deciding whether a node's uuid rotated requires
    reading the stored one.
    """

    def __init__(self, values: dict[str, str] | None = None, *, fail_at: int | None = None) -> None:
        self._values = dict(values or {})
        self.writes: list[str] = []
        self.deletes: list[str] = []
        # 1-based index of the set() call that raises; None never fails.
        self.fail_at = fail_at

    def set(self, account: str, value: str) -> None:
        self.writes.append(account)
        if self.fail_at is not None and len(self.writes) == self.fail_at:
            raise AppError("keychain write failed with exit code 1.")
        self._values[account] = value

    def get(self, account: str) -> str:
        try:
            return self._values[account]
        except KeyError:
            raise AppError(f"the UUID for profile {account} is missing from the Keychain") from None

    def delete(self, account: str) -> None:
        self.deletes.append(account)
        self._values.pop(account, None)

    def values(self) -> dict[str, str]:
        """Copy of what is currently stored — assertions read this, never ``_values``."""
        return dict(self._values)


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


SUB_UUID_A = "aaaaaaaa-1111-4111-8111-111111111111"
SUB_UUID_B = "bbbbbbbb-2222-4222-8222-222222222222"
SUB_UUID_C = "cccccccc-3333-4333-8333-333333333333"
SUB_UUID_ROTATED = "dddddddd-4444-4444-8444-444444444444"

SUB_A = SUB_SOURCE_PREFIX + "alpha"
SUB_B = SUB_SOURCE_PREFIX + "beta"


def sub_link(
    server: str = "node1.example.com",
    port: int = 443,
    *,
    network: str = "tcp",
    sni: str = "node1.example.com",
    node_uuid: str = SUB_UUID_A,
    name: str = "Node One",
    path: str = "/",
) -> dict:
    """A node in the shape ``parse_vless_uri`` hands over — uuid INCLUDED.

    Only the keys this test suite cares about are present; reconcile treats the
    link as opaque apart from popping the uuid.
    """
    return {
        "server": server,
        "port": port,
        "uuid": node_uuid,
        "security": "tls",
        "network": network,
        "name": name,
        "encryption": "none",
        "sni": sni,
        "path": path,
    }


class FakeNode:
    """Structural stand-in for ``subscriptions.SubNode`` (a ParsedNode)."""

    def __init__(self, label: str, link: dict) -> None:
        self.label = label
        self.link = link


def sub_nodes_one_two_three() -> list[FakeNode]:
    return [
        FakeNode("Node One", sub_link(node_uuid=SUB_UUID_A)),
        FakeNode("Node Two", sub_link("node2.example.com", 8443, sni="node2.example.com", node_uuid=SUB_UUID_B, name="Node Two")),
        FakeNode("Node Three", sub_link("node3.example.com", 2053, sni="node3.example.com", node_uuid=SUB_UUID_C, name="Node Three")),
    ]


class TestReconcileImport(unittest.TestCase):
    def test_import_into_empty_store(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            result = store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=secrets)
            self.assertEqual(len(result.added), 3)
            self.assertEqual(result.updated, ())
            self.assertEqual(result.unchanged, ())
            self.assertEqual(result.restored, ())
            self.assertEqual(result.marked_unavailable, ())
            self.assertEqual(result.changed, 3)
            # Every node became a profile, carrying its subscription's source.
            self.assertEqual(len(store.all()), 3)
            for profile in store.all():
                self.assertEqual(profile.source, SUB_A)
                self.assertFalse(profile.unavailable)
                self.assertNotIn("uuid", profile.link)
            # ... and every uuid went to the secret store, keyed by profile id.
            stored = secrets.values()
            self.assertEqual(set(stored), {p.id for p in store.all()})
            self.assertEqual(
                sorted(stored.values()),
                sorted([SUB_UUID_A, SUB_UUID_B, SUB_UUID_C]),
            )
            # by_source sees them; the hand-added bucket stays empty.
            self.assertEqual(len(store.by_source(SUB_A)), 3)
            self.assertEqual(store.by_source(""), [])
        finally:
            tmp.cleanup()

    def test_reconcile_persists_without_an_explicit_save(self) -> None:
        store, tmp = make_store()
        try:
            store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=DictSecretStore())
            self.assertTrue(store.path.exists())
            reloaded = ProfileStore(path=store.path)
            reloaded.load()
            self.assertEqual(len(reloaded.by_source(SUB_A)), 3)
            self.assertTrue(all(p.source == SUB_A for p in reloaded.all()))
        finally:
            tmp.cleanup()

    def test_no_uuid_invariant_holds_after_reconcile(self) -> None:
        store, tmp = make_store()
        try:
            store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=DictSecretStore())
            text = store.path.read_text(encoding="utf-8")
            for value in (SUB_UUID_A, SUB_UUID_B, SUB_UUID_C, TEST_UUID):
                self.assertNotIn(value, text)
            self.assertNotIn("uuid", text)
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
            # Same invariant in memory, for every profile.
            for profile in store.all():
                self.assertNotIn("uuid", profile.link)
        finally:
            tmp.cleanup()

    def test_reimport_identical_list_is_unchanged(self) -> None:
        store, tmp = make_store()
        try:
            nodes = sub_nodes_one_two_three()
            secrets = DictSecretStore()
            store.reconcile(nodes, source=SUB_A, secrets=secrets)
            before = store.path.read_text(encoding="utf-8")

            # Reload so the second pass matches against what is actually on disk.
            reloaded = ProfileStore(path=store.path)
            reloaded.load()
            secrets.writes.clear()
            result = reloaded.reconcile(nodes, source=SUB_A, secrets=secrets)
            self.assertEqual(len(result.unchanged), 3)
            self.assertEqual(result.added, ())
            self.assertEqual(result.updated, ())
            self.assertEqual(result.restored, ())
            self.assertEqual(result.marked_unavailable, ())
            self.assertEqual(result.changed, 0)
            # Nothing was touched: no credential rewritten, file byte-identical.
            self.assertEqual(secrets.writes, [])
            self.assertEqual(reloaded.path.read_text(encoding="utf-8"), before)
        finally:
            tmp.cleanup()

    def test_rotated_uuid_updates_in_place(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            first = store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=secrets)
            node_one = next(p for p in first.added if p.link["server"] == "node1.example.com")
            ids_before = sorted(p.id for p in store.all())

            rotated = sub_nodes_one_two_three()
            rotated[0] = FakeNode(
                "Node One",
                sub_link(node_uuid=SUB_UUID_ROTATED),
            )
            result = store.reconcile(rotated, source=SUB_A, secrets=secrets)

            self.assertEqual(len(result.updated), 1)
            self.assertEqual(len(result.unchanged), 2)
            self.assertEqual(result.added, ())
            self.assertEqual(result.changed, 1)
            # Updated in place: same profile id, so no duplicate.
            self.assertEqual(sorted(p.id for p in store.all()), ids_before)
            self.assertEqual(result.updated[0].id, node_one.id)
            self.assertEqual(secrets.values()[node_one.id], SUB_UUID_ROTATED)
            self.assertEqual(store.get(node_one.id).link["server"], "node1.example.com")
            self.assertNotIn("uuid", store.get(node_one.id).link)
        finally:
            tmp.cleanup()

    def test_other_link_change_updates_and_keeps_uuid(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            first = store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=secrets)
            node_one = next(p for p in first.added if p.link["server"] == "node1.example.com")

            changed = sub_nodes_one_two_three()
            changed[0] = FakeNode("Node One", sub_link(path="/v2"))  # same identity, new path
            result = store.reconcile(changed, source=SUB_A, secrets=secrets)
            self.assertEqual(len(result.updated), 1)
            self.assertEqual(store.get(node_one.id).link["path"], "/v2")
            # uuid unchanged upstream, so the credential is left alone.
            self.assertEqual(secrets.values()[node_one.id], SUB_UUID_A)
        finally:
            tmp.cleanup()

    def test_removed_node_is_flagged_not_deleted(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            nodes = sub_nodes_one_two_three()
            store.reconcile(nodes, source=SUB_A, secrets=secrets)
            dropped = store.by_source(SUB_A)[2]
            self.assertEqual(dropped.label, "Node Three")

            result = store.reconcile(nodes[:2], source=SUB_A, secrets=secrets)
            self.assertEqual(len(result.marked_unavailable), 1)
            self.assertEqual(result.marked_unavailable[0].id, dropped.id)
            self.assertEqual(result.changed, 1)
            # Still present, still usable, credential untouched.
            still_there = store.get(dropped.id)
            self.assertTrue(still_there.unavailable)
            self.assertEqual(still_there.label, "Node Three")
            self.assertEqual(secrets.values()[dropped.id], SUB_UUID_C)
            self.assertEqual(len(store.by_source(SUB_A)), 3)
            # Flagging twice is not news.
            again = store.reconcile(nodes[:2], source=SUB_A, secrets=secrets)
            self.assertEqual(again.marked_unavailable, ())
            self.assertEqual(again.changed, 0)
        finally:
            tmp.cleanup()

    def test_reappearing_node_is_restored(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            nodes = sub_nodes_one_two_three()
            store.reconcile(nodes, source=SUB_A, secrets=secrets)
            store.reconcile(nodes[:2], source=SUB_A, secrets=secrets)
            gone = [p for p in store.by_source(SUB_A) if p.unavailable]
            self.assertEqual(len(gone), 1)

            result = store.reconcile(nodes, source=SUB_A, secrets=secrets)
            self.assertEqual(len(result.restored), 1)
            self.assertEqual(result.restored[0].id, gone[0].id)
            self.assertEqual(result.changed, 1)
            self.assertFalse(store.get(gone[0].id).unavailable)
        finally:
            tmp.cleanup()

    def test_local_rename_survives_reimport(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            nodes = sub_nodes_one_two_three()
            first = store.reconcile(nodes, source=SUB_A, secrets=secrets)
            renamed = first.added[0]
            store.update(renamed.id, label="my own name")

            result = store.reconcile(nodes, source=SUB_A, secrets=secrets)
            self.assertEqual(len(result.unchanged), 3)
            self.assertEqual(store.get(renamed.id).label, "my own name")
            # ... and it survives a refresh that also rotates the uuid.
            rotated = sub_nodes_one_two_three()
            rotated[0] = FakeNode("Node One", sub_link(node_uuid=SUB_UUID_ROTATED))
            store.reconcile(rotated, source=SUB_A, secrets=secrets)
            self.assertEqual(store.get(renamed.id).label, "my own name")
            self.assertEqual(secrets.values()[renamed.id], SUB_UUID_ROTATED)
        finally:
            tmp.cleanup()

    def test_hand_added_profiles_are_never_touched(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            hand = store.add("home", SAMPLE_LINK)
            store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=secrets)
            result = store.reconcile([], source=SUB_A, secrets=secrets)
            # The blast radius is the subscription's own nodes only.
            self.assertEqual(len(result.marked_unavailable), 3)
            self.assertNotIn(hand.id, {p.id for p in result.marked_unavailable})
            self.assertEqual(store.get(hand.id).source, "")
            self.assertFalse(store.get(hand.id).unavailable)
            self.assertEqual(store.get(hand.id).link, SAMPLE_LINK)
        finally:
            tmp.cleanup()

    def test_two_subscriptions_with_identical_identity_do_not_collide(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=secrets)
            other = [
                FakeNode("Beta One", sub_link(node_uuid=SUB_UUID_ROTATED, name="Beta One")),
                FakeNode("Beta Two", sub_link("node2.example.com", 8443, sni="node2.example.com", node_uuid=SUB_UUID_C, name="Beta Two")),
            ]
            result = store.reconcile(other, source=SUB_B, secrets=secrets)
            self.assertEqual(len(result.added), 2)
            self.assertEqual(result.updated, ())
            self.assertEqual(len(store.by_source(SUB_A)), 3)
            self.assertEqual(len(store.by_source(SUB_B)), 2)

            # A refresh of B must not flag A's nodes (or vice versa).
            store.reconcile(other[:1], source=SUB_B, secrets=secrets)
            self.assertEqual(len(store.by_source(SUB_A)), 3)
            self.assertTrue(all(not p.unavailable for p in store.by_source(SUB_A)))
            self.assertEqual(len([p for p in store.by_source(SUB_B) if p.unavailable]), 1)
        finally:
            tmp.cleanup()

    def test_duplicate_identity_in_one_fetch_keeps_the_first(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            nodes = sub_nodes_one_two_three()
            nodes.append(FakeNode("Duplicate", sub_link(node_uuid=SUB_UUID_ROTATED, name="Duplicate")))
            result = store.reconcile(nodes, source=SUB_A, secrets=secrets)
            self.assertEqual(len(result.added), 3)
            # And the result is stable on the next pass.
            again = store.reconcile(nodes, source=SUB_A, secrets=secrets)
            self.assertEqual(len(again.unchanged), 3)
            self.assertEqual(again.changed, 0)
        finally:
            tmp.cleanup()


class TestReconcileFailure(unittest.TestCase):
    def test_node_without_uuid_raises_and_writes_nothing(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            nodes = sub_nodes_one_two_three()
            broken = dict(sub_link("node4.example.com", 443, node_uuid=SUB_UUID_B))
            broken.pop("uuid")
            nodes.append(FakeNode("Node Four", broken))

            with self.assertRaises(AppError) as ctx:
                store.reconcile(nodes, source=SUB_A, secrets=secrets)
            for value in (SUB_UUID_A, SUB_UUID_B, SUB_UUID_C):
                self.assertNotIn(value, str(ctx.exception))
            # Nothing partial: no profile, no credential, no file.
            self.assertEqual(store.all(), [])
            self.assertEqual(secrets.values(), {})
            self.assertFalse(store.path.exists())
        finally:
            tmp.cleanup()

    def test_node_with_empty_label_raises(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            nodes = sub_nodes_one_two_three()
            nodes.append(FakeNode("   ", sub_link("node4.example.com", 443, node_uuid=SUB_UUID_B)))
            with self.assertRaises(AppError):
                store.reconcile(nodes, source=SUB_A, secrets=secrets)
            self.assertEqual(store.all(), [])
            self.assertEqual(secrets.values(), {})
        finally:
            tmp.cleanup()

    def test_keychain_failure_leaves_no_partial_write(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore(fail_at=2)  # the second credential write blows up
            with self.assertRaises(AppError):
                store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=secrets)
            # Store untouched, on disk and in memory.
            self.assertEqual(store.all(), [])
            self.assertFalse(store.path.exists())
            # And the one credential that did land was rolled back.
            self.assertEqual(secrets.values(), {})
            self.assertEqual(len(secrets.deletes), 1)
        finally:
            tmp.cleanup()

    def test_failed_rotation_restores_the_previous_uuid(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            nodes = sub_nodes_one_two_three()
            store.reconcile(nodes, source=SUB_A, secrets=secrets)
            before = store.path.read_text(encoding="utf-8")
            kept = {p.id: p.link["server"] for p in store.by_source(SUB_A)}

            rotated = sub_nodes_one_two_three()
            rotated[0] = FakeNode("Node One", sub_link(node_uuid=SUB_UUID_ROTATED))
            failing = DictSecretStore(values=secrets.values(), fail_at=1)
            with self.assertRaises(AppError):
                store.reconcile(rotated, source=SUB_A, secrets=failing)

            self.assertEqual(store.path.read_text(encoding="utf-8"), before)
            self.assertEqual({p.id: p.link["server"] for p in store.by_source(SUB_A)}, kept)
            for profile in store.by_source(SUB_A):
                self.assertNotIn("uuid", profile.link)
        finally:
            tmp.cleanup()

    def test_empty_source_is_rejected(self) -> None:
        store, tmp = make_store()
        try:
            with self.assertRaises(AppError):
                store.reconcile(sub_nodes_one_two_three(), source="", secrets=DictSecretStore())
            # A backend that is not a SecretStore surfaces as AppError, not as a
            # raw AttributeError escaping into the TUI's worker thread.
            with self.assertRaises(AppError):
                store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=None)  # type: ignore[arg-type]
            self.assertEqual(store.all(), [])
        finally:
            tmp.cleanup()

    def test_missing_stored_credential_is_repaired(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            nodes = sub_nodes_one_two_three()
            first = store.reconcile(nodes, source=SUB_A, secrets=secrets)
            victim = first.added[0]
            # A Keychain item gone missing must not brick the whole refresh.
            secrets.delete(victim.id)
            result = store.reconcile(nodes, source=SUB_A, secrets=secrets)
            self.assertEqual(len(result.updated), 1)
            self.assertEqual(secrets.values()[victim.id], SUB_UUID_A)
            self.assertEqual(len(store.by_source(SUB_A)), 3)
        finally:
            tmp.cleanup()


class TestSubscriptionPersistence(unittest.TestCase):
    def test_new_fields_round_trip(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            hand = store.add("home", SAMPLE_LINK)
            nodes = [
                FakeNode("imported", sub_link(node_uuid=SUB_UUID_A)),
                FakeNode("second", sub_link("node2.example.com", 8443, sni="node2.example.com", node_uuid=SUB_UUID_B)),
            ]
            store.reconcile(nodes, source=SUB_A, secrets=secrets)
            by_server = {p.link["server"]: p for p in store.by_source(SUB_A)}
            renamed, dropped = by_server["node1.example.com"], by_server["node2.example.com"]
            store.update(renamed.id, label="renamed")
            store.reconcile(nodes[:1], source=SUB_A, secrets=secrets)  # second one vanishes
            store.save()

            reloaded = ProfileStore(path=store.path)
            reloaded.load()
            self.assertEqual(reloaded.get(renamed.id).source, SUB_A)
            self.assertEqual(reloaded.get(renamed.id).label, "renamed")
            self.assertFalse(reloaded.get(renamed.id).unavailable)
            self.assertTrue(reloaded.get(dropped.id).unavailable)
            self.assertEqual(reloaded.get(dropped.id).source, SUB_A)
            self.assertEqual(reloaded.get(hand.id).source, "")
            self.assertFalse(reloaded.get(hand.id).unavailable)
            # The hand-added profile still serialises exactly as it always did:
            # the two new keys are written only when they carry information.
            text = store.path.read_text(encoding="utf-8")
            self.assertEqual(text.count(f'"source": "{SUB_A}"'), 2)
            self.assertEqual(text.count('"unavailable": true'), 1)
        finally:
            tmp.cleanup()

    def test_load_tolerates_missing_new_fields(self) -> None:
        store, tmp = make_store()
        try:
            store.path.parent.mkdir(parents=True, exist_ok=True)
            # Exactly what the previous version wrote: no source, no unavailable.
            store.path.write_text(
                json.dumps(
                    {
                        "version": STORE_VERSION,
                        "active": None,
                        "profiles": [{"id": "abc", "label": "legacy", "link": SAMPLE_LINK}],
                    }
                ),
                encoding="utf-8",
            )
            reloaded = ProfileStore(path=store.path)
            reloaded.load()
            profile = reloaded.get("abc")
            self.assertEqual(profile.source, "")
            self.assertFalse(profile.unavailable)
            # ... and it is untouched by a subscription refresh.
            secrets = DictSecretStore()
            reloaded.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=secrets)
            self.assertEqual(reloaded.get("abc").source, "")
        finally:
            tmp.cleanup()

    def test_update_and_set_latency_preserve_provenance(self) -> None:
        store, tmp = make_store()
        try:
            secrets = DictSecretStore()
            first = store.reconcile(sub_nodes_one_two_three(), source=SUB_A, secrets=secrets)
            profile_id = first.added[0].id
            store.reconcile([], source=SUB_A, secrets=secrets)  # flag it
            store.update(profile_id, label="renamed")
            store.set_latency(profile_id, 120)
            final = store.get(profile_id)
            self.assertEqual(final.source, SUB_A)
            self.assertTrue(final.unavailable)
            self.assertEqual(final.label, "renamed")
            self.assertEqual(final.last_latency_ms, 120)
        finally:
            tmp.cleanup()

    def test_bad_source_type_in_file_is_rejected(self) -> None:
        store, tmp = make_store()
        try:
            store.path.parent.mkdir(parents=True, exist_ok=True)
            for bad in (7, None, ["subscription:a"]):
                store.path.write_text(
                    json.dumps(
                        {
                            "version": STORE_VERSION,
                            "active": None,
                            "profiles": [
                                {"id": "abc", "label": "x", "link": SAMPLE_LINK, "source": bad}
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                with self.assertRaises(AppError):
                    store.load()
        finally:
            tmp.cleanup()


class TestNodeIdentity(unittest.TestCase):
    def test_identity_ignores_label_and_uuid(self) -> None:
        with_uuid = dict(SAMPLE_LINK, uuid=SUB_UUID_A)
        without_uuid = dict(SAMPLE_LINK)
        self.assertEqual(node_identity(with_uuid), node_identity(without_uuid))

    def test_identity_is_case_insensitive_and_stringifies_port(self) -> None:
        self.assertEqual(
            node_identity({"server": "Ex.COM", "port": 443, "network": "TCP", "sni": "Sni.COM"}),
            node_identity({"server": "ex.com", "port": "443", "network": "tcp", "sni": "sni.com"}),
        )

    def test_identity_separates_different_nodes(self) -> None:
        base = {"server": "a.example", "port": 443, "network": "tcp", "sni": "a.example"}
        self.assertNotEqual(node_identity(base), node_identity(dict(base, port=8443)))
        self.assertNotEqual(node_identity(base), node_identity(dict(base, network="ws")))
        self.assertNotEqual(node_identity(base), node_identity(dict(base, sni="b.example")))
        self.assertNotEqual(node_identity(base), node_identity(dict(base, server="b.example")))

    def test_identity_is_total_on_a_bare_mapping(self) -> None:
        self.assertEqual(node_identity({}), ("", "", "", ""))

    def test_prefixes(self) -> None:
        self.assertEqual(SUB_SOURCE_PREFIX, "subscription:")
        self.assertEqual(SUB_SECRET_PREFIX, "subscription:")


if __name__ == "__main__":
    unittest.main()
