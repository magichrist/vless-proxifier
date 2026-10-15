"""The shared error contract.

Exists as its own leaf module so `errors` has no package imports and every other
module can raise `AppError` without a circular import.

INVARIANT — the whole project's security story depends on it:

    An AppError message MUST NEVER contain any part of a VLESS URI.

Not the UUID, not the full link, not the query string. The original code
maintained this by writing every message by hand. With profiles, the TUI log
pane, and worker threads, that property becomes easy to break accidentally — a
`repr()` of a parsed dict or an f-string of a URL would leak the credential into
a log file.

`tests/test_errors.py` asserts the invariant on a corpus of real failure paths.
If you add an AppError, add it to that corpus.

Do NOT format an AppError from a URI, a parsed link dict, or a config file.
Format from the *shape* of the problem: "invalid port", "unsupported transport",
"the link disables TLS verification".
"""
from __future__ import annotations


class AppError(Exception):
    """Expected, user-facing error that must not disclose the link."""


__all__ = ["AppError"]