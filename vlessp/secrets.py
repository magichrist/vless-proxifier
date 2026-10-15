"""Keychain-backed secret storage.

This is the ONLY module permitted to touch the Keychain. The credential (the
VLESS UUID) lives here, one generic-password item per profile, so that
``profiles.json`` never becomes a credential file.

Why the ``security`` CLI instead of a binding: it is present on every macOS,
needs no new dependency, and keeps this module stdlib-only.
"""
from __future__ import annotations

import subprocess
from typing import Protocol

from vlessp.errors import AppError

KEYCHAIN_SERVICE: str = "vless-python-proxy"

_SECURITY_TIMEOUT = 10.0


class SecretStore(Protocol):
    """Minimal key-value secret backend keyed by profile id."""

    def set(self, account: str, value: str) -> None: ...
    def get(self, account: str) -> str: ...
    def delete(self, account: str) -> None: ...


def _missing_message(account: str) -> str:
    # Account is the profile id/label — safe to echo. Never the UUID itself.
    return f"the UUID for profile {account} is missing from the Keychain"


class MacOSKeychain:
    """macOS Keychain backend via the ``security`` CLI (stdlib subprocess only)."""

    def __init__(self, service: str = KEYCHAIN_SERVICE, *, timeout: float = _SECURITY_TIMEOUT) -> None:
        self._service = service
        self._timeout = timeout

    @property
    def service(self) -> str:
        """Keychain service name grouping this app's items."""
        return self._service

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AppError("keychain lookup timed out.") from exc
        except OSError as exc:
            raise AppError(f"keychain is unavailable: {type(exc).__name__}.") from exc

    def set(self, account: str, value: str) -> None:
        """Create or update the Keychain item for ``account``."""
        # NOTE: -w places the secret on argv where it is briefly visible in the
        # process table; accepted because the interactive-stdin alternative adds
        # complexity for a short-lived local process.
        argv = [
            "security",
            "add-generic-password",
            "-U",
            "-s",
            self._service,
            "-a",
            account,
            "-w",
            value,
        ]
        result = self._run(argv)
        if result.returncode != 0:
            # stderr from `security` can echo the account, so surface only the exit code.
            raise AppError(f"keychain write failed with exit code {result.returncode}.")

    def get(self, account: str) -> str:
        """Return the secret for ``account``; missing items get an actionable error."""
        argv = [
            "security",
            "find-generic-password",
            "-s",
            self._service,
            "-a",
            account,
            "-w",
        ]
        result = self._run(argv)
        if result.returncode != 0:
            # Any get failure (including item-not-found) surfaces as the missing-item
            # message; only the exit code is real signal and stderr is never repeated.
            raise AppError(_missing_message(account))
        secret = result.stdout.strip()
        if not secret:
            raise AppError(_missing_message(account))
        return secret

    def delete(self, account: str) -> None:
        """Delete the Keychain item for ``account``; idempotent on missing items."""
        argv = [
            "security",
            "delete-generic-password",
            "-s",
            self._service,
            "-a",
            account,
        ]
        result = self._run(argv)
        if result.returncode != 0:
            raise AppError(f"keychain delete failed with exit code {result.returncode}.")


class NullSecretStore:
    """Test backend: holds nothing and always fails closed on ``get``.

    Why: the whole test suite must run without ever touching the real
    Keychain, so every test uses this instead of ``MacOSKeychain``.
    """

    def set(self, account: str, value: str) -> None:
        """Accept and discard; tests never need persistence from the null backend."""
        _ = (account, value)

    def get(self, account: str) -> str:
        """Always raise — there is no backing store by design."""
        raise AppError(f"secret backend is unavailable (null backend) for profile {account}.")

    def delete(self, account: str) -> None:
        """Accept and discard; nothing is stored so there is nothing to remove."""
        _ = account


__all__ = ["KEYCHAIN_SERVICE", "SecretStore", "MacOSKeychain", "NullSecretStore"]
