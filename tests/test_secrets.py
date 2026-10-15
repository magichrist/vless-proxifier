"""Tests for vlessp.secrets — Keychain backend construction and secrecy."""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from vlessp.errors import AppError
from vlessp.secrets import KEYCHAIN_SERVICE, MacOSKeychain, NullSecretStore

FAKE_SECRET = "super-secret-uuid-value-1234"
FAKE_ACCOUNT = "profile-id-abc123"


def completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["security"], returncode=returncode, stdout=stdout, stderr=stderr)


class TestNullSecretStore(unittest.TestCase):
    def test_get_always_raises(self) -> None:
        store = NullSecretStore()
        with self.assertRaises(AppError):
            store.get("anything")

    def test_set_and_delete_do_not_raise(self) -> None:
        store = NullSecretStore()
        store.set("a", "b")
        store.delete("a")


class TestMissingItemMessage(unittest.TestCase):
    def test_missing_message_contains_account_not_secret(self) -> None:
        store = NullSecretStore()
        with self.assertRaises(AppError) as ctx:
            store.get(FAKE_ACCOUNT)
        message = str(ctx.exception)
        self.assertIn(FAKE_ACCOUNT, message)
        self.assertNotIn(FAKE_SECRET, message)

    def test_keychain_get_failure_contains_account_not_secret(self) -> None:
        backend = MacOSKeychain()
        with mock.patch(
            "subprocess.run",
            return_value=completed(returncode=1, stdout="", stderr="oops"),
        ):
            with self.assertRaises(AppError) as ctx:
                backend.get(FAKE_ACCOUNT)
        message = str(ctx.exception)
        self.assertIn(FAKE_ACCOUNT, message)
        self.assertNotIn(FAKE_SECRET, message)


class TestArgvConstruction(unittest.TestCase):
    def test_set_argv(self) -> None:
        backend = MacOSKeychain()
        with mock.patch("subprocess.run", return_value=completed()) as fake:
            backend.set(FAKE_ACCOUNT, FAKE_SECRET)
        argv = fake.call_args[0][0]
        self.assertEqual(
            argv,
            [
                "security",
                "add-generic-password",
                "-U",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                FAKE_ACCOUNT,
                "-w",
                FAKE_SECRET,
            ],
        )
        # List argv, never a shell string.
        self.assertIsInstance(argv, list)
        kwargs = fake.call_args[1]
        self.assertFalse(kwargs.get("shell", False))
        self.assertIn("timeout", kwargs)

    def test_get_argv(self) -> None:
        backend = MacOSKeychain()
        with mock.patch(
            "subprocess.run", return_value=completed(stdout=FAKE_SECRET + "\n")
        ) as fake:
            value = backend.get(FAKE_ACCOUNT)
        argv = fake.call_args[0][0]
        self.assertEqual(
            argv,
            [
                "security",
                "find-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                FAKE_ACCOUNT,
                "-w",
            ],
        )
        self.assertEqual(value, FAKE_SECRET)

    def test_delete_argv(self) -> None:
        backend = MacOSKeychain()
        with mock.patch("subprocess.run", return_value=completed()) as fake:
            backend.delete(FAKE_ACCOUNT)
        argv = fake.call_args[0][0]
        self.assertEqual(
            argv,
            [
                "security",
                "delete-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                FAKE_ACCOUNT,
            ],
        )


class TestSecretNeverInExceptions(unittest.TestCase):
    def test_failed_set_sanitises_stderr_containing_secret(self) -> None:
        backend = MacOSKeychain()
        with mock.patch(
            "subprocess.run",
            return_value=completed(returncode=1, stderr=f"denied for {FAKE_SECRET}"),
        ):
            with self.assertRaises(AppError) as ctx:
                backend.set(FAKE_ACCOUNT, FAKE_SECRET)
        self.assertNotIn(FAKE_SECRET, str(ctx.exception))

    def test_failed_delete_sanitises_stderr_containing_secret(self) -> None:
        backend = MacOSKeychain()
        with mock.patch(
            "subprocess.run",
            return_value=completed(returncode=1, stderr=f"nope {FAKE_SECRET}"),
        ):
            with self.assertRaises(AppError) as ctx:
                backend.delete(FAKE_ACCOUNT)
        self.assertNotIn(FAKE_SECRET, str(ctx.exception))

    def test_failed_get_with_secret_in_stderr_stays_sanitised(self) -> None:
        backend = MacOSKeychain()
        with mock.patch(
            "subprocess.run",
            return_value=completed(returncode=44, stderr=f"missing {FAKE_SECRET}"),
        ):
            with self.assertRaises(AppError) as ctx:
                backend.get(FAKE_ACCOUNT)
        message = str(ctx.exception)
        self.assertNotIn(FAKE_SECRET, message)
        self.assertIn(FAKE_ACCOUNT, message)

    def test_keychain_service_constant(self) -> None:
        self.assertEqual(KEYCHAIN_SERVICE, "vless-python-proxy")


if __name__ == "__main__":
    unittest.main()
