"""Tests for vlessp.subscriptions — fetch controls, parse rules, and secrecy.

Fetch tests never touch the network: httpx.Client is monkeypatched with a
fake that records how it was called and replays scripted responses.
"""
from __future__ import annotations

import base64
import unittest
from types import SimpleNamespace
from typing import Any
from unittest import mock

import httpx

from vlessp.errors import AppError
from vlessp.subscriptions import (
    MAX_SUBSCRIPTION_BYTES,
    fetch_subscription,
    parse,
    parse_subscription,
)

FAKE_SUB_URL = "https://subs.example.com/s/SECRET-SUB-TOKEN-9f8a7b6c"
FAKE_UUID = "11111111-2222-4333-8444-555555555555"
FAKE_UUID_2 = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _uri(
    uuid: str = FAKE_UUID,
    host: str = "example.com",
    port: int = 443,
    fragment: str | None = "node",
) -> str:
    base = f"vless://{uuid}@{host}:{port}?encryption=none&security=none&type=tcp"
    return base if fragment is None else f"{base}#{fragment}"


# --- Fake httpx plumbing -----------------------------------------------------

class _FakeResponse:
    """Mimics the slice of httpx.Response that fetch_subscription uses."""

    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        history: tuple[_FakeResponse, ...] = (),
        headers: dict[str, str] | None = None,
        scheme: str = "https",
    ) -> None:
        self._body = body
        self.status_code = status
        self.history = history
        self.headers = headers or {}
        self.request = SimpleNamespace(url=SimpleNamespace(scheme=scheme))

    def iter_bytes(self, chunk_size: int | None = None) -> Any:
        step = chunk_size or 65536
        for i in range(0, len(self._body), step):
            yield self._body[i : i + step]

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


class _FakeStreamContext:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    def __enter__(self) -> _FakeResponse:
        return self._response

    def __exit__(self, *args: Any) -> bool:
        return False


class _FakeClient:
    """Records construction kwargs and stream calls; replays one scripted outcome."""

    def __init__(self, outcome: Any, captured: dict[str, Any]) -> None:
        self._outcome = outcome
        self._captured = captured

    def __call__(self, *args: Any, **kwargs: Any) -> _FakeClient:
        self._captured["client_kwargs"] = kwargs
        return self

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *args: Any) -> bool:
        return False

    def stream(self, method: str, url: str, **kwargs: Any) -> _FakeStreamContext:
        self._captured.setdefault("stream_calls", []).append((method, url))
        if isinstance(self._outcome, BaseException):
            raise self._outcome
        return _FakeStreamContext(self._outcome)


def _run_fetch(outcome: Any, url: str = FAKE_SUB_URL) -> tuple[Any, dict[str, Any]]:
    """Run fetch_subscription with httpx.Client patched; return (result-or-exc, captured)."""
    captured: dict[str, Any] = {}
    with mock.patch("httpx.Client", _FakeClient(outcome, captured)):
        try:
            return fetch_subscription(url), captured
        except AppError as exc:
            return exc, captured


# --- Parse tests -------------------------------------------------------------

class TestParsePlain(unittest.TestCase):
    def test_multi_line_list_yields_count_labels_links(self) -> None:
        body = "\n".join([_uri(fragment="one"), _uri(uuid=FAKE_UUID_2, host="two.example.com", port=8443, fragment="two")])
        sub = parse(body)
        self.assertEqual(len(sub.nodes), 2)
        self.assertFalse(sub.was_base64)
        self.assertEqual(sub.nodes[0].label, "one")
        self.assertEqual(sub.nodes[1].label, "two")
        self.assertEqual(sub.nodes[0].link["uuid"], FAKE_UUID)
        self.assertEqual(sub.nodes[1].link["server"], "two.example.com")
        self.assertEqual(sub.nodes[1].link["port"], 8443)
        self.assertEqual(sub.issues, ())

    def test_wrapper_returns_just_nodes(self) -> None:
        nodes = parse_subscription(_uri(fragment="solo") + "\nnot-a-uri\n")
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].label, "solo")

    def test_single_malformed_line_skipped_rest_survive(self) -> None:
        body = "\n".join(
            [_uri(fragment="a"), "vless://not-a-uuid@example.com:443", _uri(uuid=FAKE_UUID_2, fragment="c")]
        )
        sub = parse(body)
        self.assertEqual([n.label for n in sub.nodes], ["a", "c"])
        self.assertEqual(len(sub.issues), 1)
        self.assertEqual(sub.issues[0].line_number, 2)

    def test_all_malformed_gives_empty_nodes_without_exception(self) -> None:
        sub = parse("garbage line one\nvless://bogus\n# only a comment\n\n   \n!!!")
        self.assertEqual(sub.nodes, ())
        # Two real lines attempted (comments and blanks are skipped silently).
        self.assertEqual(len(sub.issues), 3)
        self.assertEqual([i.line_number for i in sub.issues], [1, 2, 6])

    def test_comments_and_blanks_are_skipped(self) -> None:
        body = "# a comment\n\n   \n" + _uri(fragment="kept") + "\n  # indented comment\n"
        sub = parse(body)
        self.assertEqual(len(sub.nodes), 1)
        self.assertEqual(sub.issues, ())

    def test_label_falls_back_to_host_port(self) -> None:
        sub = parse(_uri(fragment=None, host="node.example.org", port=1234))
        self.assertEqual(sub.nodes[0].label, "node.example.org:1234")

    def test_hash_in_label_is_not_a_comment(self) -> None:
        sub = parse(_uri(fragment="my#node"))
        self.assertEqual(len(sub.nodes), 1)
        self.assertEqual(sub.nodes[0].label, "my#node")
        self.assertEqual(sub.issues, ())


class TestParseBase64(unittest.TestCase):
    def test_base64_wrapped_body_is_detected_and_decoded(self) -> None:
        plain = _uri(fragment="alpha") + "\n" + _uri(uuid=FAKE_UUID_2, fragment="beta") + "\n"
        wrapped = base64.b64encode(plain.encode()).decode()
        sub = parse(wrapped)
        self.assertTrue(sub.was_base64)
        self.assertEqual([n.label for n in sub.nodes], ["alpha", "beta"])
        self.assertEqual(sub.issues, ())

    def test_base64_decoding_to_garbage_does_not_raise(self) -> None:
        # Valid base64 whose payload holds no vless line: falls back to plain,
        # so the base64 text itself becomes one skippable line. No raise.
        wrapped = base64.b64encode(b"just some words, no links here").decode()
        sub = parse(wrapped)
        self.assertFalse(sub.was_base64)
        self.assertEqual(sub.nodes, ())
        self.assertEqual(len(sub.issues), 1)  # the base64 text itself, as one plain line

    def test_non_utf8_base64_payload_does_not_raise(self) -> None:
        wrapped = base64.b64encode(b"\xff\xfe\x00vless").decode()
        sub = parse(wrapped)
        self.assertFalse(sub.was_base64)
        self.assertEqual(sub.nodes, ())

    def test_invalid_base64_falls_back_to_plain(self) -> None:
        sub = parse("!!! not base64 at all !!!")
        self.assertFalse(sub.was_base64)
        self.assertEqual(sub.nodes, ())
        self.assertEqual(len(sub.issues), 1)


# --- Fetch tests -------------------------------------------------------------

class TestFetchValidation(unittest.TestCase):
    def test_rejects_http_without_touching_network(self) -> None:
        with mock.patch("httpx.Client") as client_cls:
            with self.assertRaises(AppError):
                fetch_subscription("http://subs.example.com/list")
            client_cls.assert_not_called()

    def test_rejects_non_url_scheme(self) -> None:
        with self.assertRaises(AppError):
            fetch_subscription("ftp://subs.example.com/list")

    def test_success_returns_text_and_uses_get_with_user_agent(self) -> None:
        body = (_uri(fragment="n") + "\n").encode()
        result, captured = _run_fetch(_FakeResponse(body))
        self.assertEqual(result, body.decode())
        self.assertEqual(captured["stream_calls"], [("GET", FAKE_SUB_URL)])
        headers = captured["client_kwargs"]["headers"]
        self.assertIn("User-Agent", headers)

    def test_size_cap_enforced_on_stream(self) -> None:
        big = b"vless://" + b"x" * MAX_SUBSCRIPTION_BYTES
        result, _ = _run_fetch(_FakeResponse(big))
        self.assertIsInstance(result, AppError)

    def test_declared_content_length_over_cap_refused_early(self) -> None:
        resp = _FakeResponse(b"tiny", headers={"content-length": str(MAX_SUBSCRIPTION_BYTES + 1)})
        result, _ = _run_fetch(resp)
        self.assertIsInstance(result, AppError)

    def test_timeout_becomes_apperror(self) -> None:
        exc = httpx.ConnectTimeout(f"timed out for {FAKE_SUB_URL}")
        result, _ = _run_fetch(exc)
        self.assertIsInstance(result, AppError)

    def test_non_https_redirect_hop_refused(self) -> None:
        first = _FakeResponse(b"", status=301, scheme="https")
        final = _FakeResponse(b"body", history=(first,), scheme="http")
        result, _ = _run_fetch(final)
        self.assertIsInstance(result, AppError)

    def test_non_200_status_is_apperror(self) -> None:
        result, _ = _run_fetch(_FakeResponse(b"nope", status=404))
        self.assertIsInstance(result, AppError)


# --- Credential-leak tests ---------------------------------------------------

class TestNoCredentialLeak(unittest.TestCase):
    def assertLeakFree(self, message: str) -> None:
        self.assertNotIn(FAKE_SUB_URL, message)
        self.assertNotIn("SECRET-SUB-TOKEN", message)
        self.assertNotIn("vless://", message)
        self.assertNotIn(FAKE_UUID, message)
        self.assertNotIn(FAKE_UUID_2, message)

    def test_fetch_failures_never_echo_url_or_body(self) -> None:
        link_body = (_uri(fragment="leaky") + "\n").encode() * 10
        big = b"vless://" + b"x" * MAX_SUBSCRIPTION_BYTES + link_body
        hop = _FakeResponse(b"", scheme="https")
        cases: list[tuple[str, Any]] = [
            ("http", None),  # url swapped below
            ("timeout", httpx.ConnectTimeout(f"timed out for {FAKE_SUB_URL}")),
            ("oversize", _FakeResponse(big)),
            ("redirect", _FakeResponse(b"body", history=(hop,), scheme="http")),
            ("status", _FakeResponse(b"nope", status=500)),
        ]
        for name, outcome in cases:
            with self.subTest(case=name):
                url = "http://subs.example.com/s/SECRET-SUB-TOKEN-9f8a7b6c" if name == "http" else FAKE_SUB_URL
                result, _ = _run_fetch(outcome, url=url) if outcome is not None else (None, None)
                if outcome is None:  # http-rejection path builds no fake
                    with mock.patch("httpx.Client"):
                        with self.assertRaises(AppError) as ctx:
                            fetch_subscription(url)
                        self.assertLeakFree(str(ctx.exception))
                else:
                    assert isinstance(result, AppError), name
                    self.assertLeakFree(str(result))

    def test_parse_issue_reasons_contain_no_link_or_uuid(self) -> None:
        body = "\n".join(
            [
                f"vless://{FAKE_UUID}@example.com:notaport#x",
                f"vless://{FAKE_UUID_2}@bad host:443",
                FAKE_UUID,  # a bare UUID as a line
                "vless://missing-everything-else",
            ]
        )
        sub = parse(body)
        self.assertEqual(sub.nodes, ())
        self.assertTrue(sub.issues)
        for issue in sub.issues:
            with self.subTest(line=issue.line_number):
                self.assertLeakFree(issue.reason)


if __name__ == "__main__":
    unittest.main()
