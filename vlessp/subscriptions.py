"""Subscription fetch and parse: the fetch-and-parse half of subscription import.

A subscription URL is itself a credential — it typically embeds a token that
grants access to the user's whole node list. So this module is built around one
rule inherited from ``errors.AppError``: no ``AppError`` message, log line, or
repr produced here may contain the subscription URL, a fetched ``vless://``
URI, or a UUID. Failures are reported by shape ("line 12 of the subscription
is malformed", "the redirect left https"), and httpx exceptions — whose string
form carries the request URL — are surfaced by type name only.

The module deliberately stops at parsed nodes. It never writes to disk or to
the Keychain: ``link`` keeps the full ``parse_vless_uri`` output *including*
``uuid`` so the caller can split the secret (Keychain) from the config
(store). Splitting here would drag I/O into a module whose parse path must
stay pure and thread-safe.

On the missing host allowlist: ``xray.request_bytes`` allowlists hosts because
the Xray download host is known in advance. Here the user supplies the URL, so
an allowlist is meaningless — any host the user names would have to be
"allowed". HTTPS + streaming size cap + hard timeout is the right control, and
a future reader should not "fix" this by adding an allowlist.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx

from .errors import AppError
from .links import parse_vless_uri

MAX_SUBSCRIPTION_BYTES: int = 2 * 1024 * 1024

_USER_AGENT = "vless-python-proxy/1.0"

# Same two shapes xray._redact guards: the scheme prefix and anything
# UUID-shaped. Applied to per-line reasons at this module's boundary (see
# _safe_reason) so issue text shown in the TUI can never carry a credential.
_URI_PREFIX_RE = re.compile(r"(?i)vless://")
_UUID_LIKE_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")

__all__ = [
    "MAX_SUBSCRIPTION_BYTES",
    "ParseIssue",
    "SubNode",
    "Subscription",
    "fetch_subscription",
    "parse",
    "parse_subscription",
]


def fetch_subscription(url: str, *, timeout: float = 20.0) -> str:
    """Fetch a subscription and return its body as text.

    Every fetch is a secret-bearing request (the URL is the credential), so:
    https-only including every redirect hop, a size cap enforced while
    streaming rather than after buffering, one hard timeout, and no retry of
    any kind — httpx does not retry by default and a retry would double the
    exposure for no benefit. Redirects are followed (providers move URLs) but
    any hop that leaves https aborts the fetch.

    Raises AppError on any failure. The message never contains the URL.
    """
    target = url.strip()
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise AppError("Subscription URL must be an https:// URL.")
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": _USER_AGENT, "Accept": "text/plain"},
        ) as client:
            with client.stream("GET", target) as response:
                hops = [*response.history, response]
                if any(hop.request.url.scheme != "https" for hop in hops):
                    raise AppError("Subscription redirect left https; refusing to continue.")
                if response.status_code != 200:
                    raise AppError(f"Subscription fetch failed with HTTP status {response.status_code}.")
                # Defense in depth: the header is a claim, not a fact, so a
                # lying Content-Length is ignored and the streaming cap below
                # remains the real control.
                declared = response.headers.get("content-length")
                if declared:
                    try:
                        if int(declared) > MAX_SUBSCRIPTION_BYTES:
                            raise AppError("Subscription body exceeds the size limit.")
                    except ValueError:
                        pass
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    total += len(chunk)
                    if total > MAX_SUBSCRIPTION_BYTES:
                        raise AppError("Subscription body exceeds the size limit.")
                    chunks.append(chunk)
                raw = b"".join(chunks)
    except AppError:
        raise
    except (httpx.HTTPError, TimeoutError, OSError, ValueError) as exc:
        # httpx renders the request URL into str(exc); the URL is the
        # credential, so only the exception type crosses into the message.
        raise AppError(
            f"Could not fetch the subscription ({type(exc).__name__}). "
            "Check the URL and your connection."
        ) from None
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise AppError("Subscription body is not decodable text.") from None


@dataclass(frozen=True)
class SubNode:
    """One node from a subscription, not yet a Profile.

    ``link`` is exactly what ``parse_vless_uri`` returned, uuid included —
    the caller owns splitting it into the Keychain and the store.
    """

    label: str
    link: dict[str, Any]
    line_number: int


@dataclass(frozen=True)
class ParseIssue:
    """One skipped line, so the user can learn why a node is missing.

    ``reason`` is the parser's own message, which is link-free by contract —
    never the line's content, so a UUID can never leak through here.
    """

    line_number: int
    reason: str


@dataclass(frozen=True)
class Subscription:
    """The full result of parsing: good nodes plus per-line issues."""

    nodes: tuple[SubNode, ...]
    issues: tuple[ParseIssue, ...]
    was_base64: bool


def _maybe_base64_decode(body: str) -> tuple[str, bool]:
    """Unwrap a base64-encoded body, or return the body unchanged.

    The primary format is plain-text ``vless://`` lines, so anything whose
    first non-whitespace characters already look like ``vless://`` is left
    alone. Otherwise one decode is attempted — providers serve base64 under
    the same URL surprisingly often — and the decoded text is adopted only if
    it actually contains a ``vless://`` line. Anything else (bad base64,
    non-UTF-8 bytes, decoded garbage) falls back to the original body, which
    the line parser will then report on per line. Never raises.
    """
    stripped = body.lstrip()
    if stripped[:8].lower() == "vless://":
        return body, False
    compact = "".join(stripped.split())
    if not compact:
        return body, False
    try:
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (binascii.Error, ValueError):
        return body, False
    try:
        text = decoded.decode("utf-8")
    except UnicodeError:
        return body, False
    if "vless://" not in text.lower():
        return body, False
    return text, True


def _safe_reason(exc: BaseException) -> str:
    """Render a parser failure as link-free issue text.

    The reason is the parser's own message — except that one ``links.py``
    message names the expected shape as ``vless://UUID@host:port``, which
    trips this repo's own substring invariant (``test_links.py`` bans even the
    bare scheme prefix in error text). And ``query_params`` echoes offending
    parameter *keys*, so a hostile line could in principle smuggle a
    UUID-shaped string into the message. Both shapes are reworded/redacted
    here, at this module's boundary, since ``links.py`` is owned elsewhere.
    Never includes the line's content.
    """
    text = _URI_PREFIX_RE.sub("VLESS ", str(exc))
    return _UUID_LIKE_RE.sub("<redacted-uuid>", text)


def parse(body: str) -> Subscription:
    """Parse a subscription body into nodes plus per-line issues.

    Blank lines and ``#`` comments are skipped silently — they carry no
    information. A malformed line is skipped with an issue recorded against
    its 1-based line number (of the decoded body, when base64 applied) and
    parsing continues: one broken line is normal, not fatal, and must never
    lose the rest of the list. Never raises for bad content.

    The label is the URI fragment (``#name``), falling back to ``host:port``
    when the provider did not name the node. Only a line *starting* with
    ``#`` is a comment — a ``#`` inside a fragment is part of the label, and
    such lines start with ``vless://`` so they are never misclassified.
    """
    text, was_base64 = _maybe_base64_decode(body)
    nodes: list[SubNode] = []
    issues: list[ParseIssue] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            link = parse_vless_uri(line)
        except AppError as exc:
            issues.append(ParseIssue(line_number=number, reason=_safe_reason(exc)))
            continue
        except Exception as exc:  # parse_vless_uri promises AppError-only; belt and braces so one line can never abort the list.
            issues.append(
                ParseIssue(
                    line_number=number,
                    reason=f"Unparseable subscription line ({type(exc).__name__}).",
                )
            )
            continue
        label = link.get("name") or f"{link['server']}:{link['port']}"
        nodes.append(SubNode(label=label, link=link, line_number=number))
    return Subscription(nodes=tuple(nodes), issues=tuple(issues), was_base64=was_base64)


def parse_subscription(body: str) -> list[SubNode]:
    """Parse a subscription body, returning just the good nodes.

    Thin wrapper over :func:`parse` for callers that do not need the issues
    or the base64 flag. Same contract: never raises for bad lines.
    """
    return list(parse(body).nodes)
