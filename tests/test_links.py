"""Unit tests for vlessp.links — the pure parser and config generator.

These complement tests/test_vless_proxy.py rather than replace it: that file
guards the pre-refactor behaviour through the old entry point and must stay
unmodified, while this one drives vlessp.links directly, covers the rejection
paths end to end, and pins the security invariants (loopback-only listeners, TLS
verification on by default, no URI in any error message).

Everything here is pure-function testing: no socket, no subprocess, no file.
"""
import json
import unittest

from vlessp.errors import AppError
from vlessp.links import (
    MAX_URI_BYTES,
    build_xray_config,
    is_valid_hostname,
    parse_vless_uri,
    query_params,
)

UUID = "01234567-89ab-cdef-0123-456789abcdef"
PIN = "d4cb869694ad29d03b4edccf73835ec56d31e2c3eef031b72b97f54487a248b3"
REALITY_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

WS_TLS_PIN = (
    f"vless://{UUID}@203.0.113.10:2083?"
    "sni=google.com&path=%2F&type=ws&"
    "encryption=none&security=tls&"
    "allowInsecure=0&insecure=0&fp=chrome&alpn=http%2F1.1&"
    f"pcs={PIN}&host=s7r.example.com#test"
)

REALITY = (
    f"vless://{UUID}@example.com:443?security=reality&type=tcp"
    f"&sni=example.com&fp=chrome&pbk={REALITY_KEY}&sid=abcd#reality"
)

XHTTP_EXTRA = (
    f"vless://{UUID}@example.com:443?security=tls&type=xhttp&sni=e.com&fp=chrome"
    "&path=%2Fdl&host=cdn.example.com&mode=auto&extra=%7B%22scMaxEachBufferBytes%22%3A1048576%7D"
)


class HostnameTests(unittest.TestCase):
    def test_accepts_names_and_ip_literals(self):
        for host in ("google.com", "s7r.example.com", "203.0.113.10", "::1", "xn--bcher-kva.example"):
            self.assertTrue(is_valid_hostname(host), host)

    def test_rejects_malformed_hosts(self):
        for host in ("", "-bad.com", "bad-.com", "a..b", "example.com.", "host_name", "1.2.3.4/32"):
            self.assertFalse(is_valid_hostname(host), host)

    def test_rejects_over_long_labels_and_names(self):
        self.assertFalse(is_valid_hostname("a" * 64 + ".com"))
        self.assertTrue(is_valid_hostname("a" * 63 + ".com"))
        self.assertFalse(is_valid_hostname(".".join(["a" * 63] * 5)))


class QueryParamTests(unittest.TestCase):
    def test_pairs_are_returned_verbatim(self):
        self.assertEqual(query_params("type=ws&security=tls"), {"type": "ws", "security": "tls"})

    def test_blank_values_are_kept(self):
        self.assertEqual(query_params("path="), {"path": ""})

    def test_duplicate_key_is_refused(self):
        with self.assertRaises(AppError):
            query_params("sni=a.example&sni=b.example")

    def test_malformed_query_is_refused(self):
        # A field with no "=" is malformed under strict parsing. "=====" is not:
        # it is a valid empty key, so only genuinely broken shapes belong here.
        for query in ("broken", "&&&", "&", "a=1&&b=2"):
            with self.subTest(query=query):
                with self.assertRaises(AppError):
                    query_params(query)

    def test_oversized_key_or_value_is_refused(self):
        with self.assertRaises(AppError):
            query_params("k" * 65 + "=1")
        with self.assertRaises(AppError):
            query_params("k=" + "v" * 4097)
        self.assertEqual(len(query_params("k=" + "v" * 4096)["k"]), 4096)

    def test_every_alias_pair_conflict_is_detected(self):
        # Both spellings of each setting are accepted when they agree, and a
        # disagreement is an error rather than a silent precedence rule.
        aliases = [
            ("type", "network"),
            ("sni", "serverName"),
            ("fp", "fingerprint"),
            ("pcs", "pinnedPeerCertSha256"),
            ("pbk", "publicKey"),
            ("sid", "shortId"),
        ]
        for first, second in aliases:
            with self.subTest(alias=first):
                self.assertEqual(query_params(f"{first}=x&{second}=x")[first], "x")
                with self.assertRaises(AppError):
                    query_params(f"{first}=x&{second}=y")

    def test_insecure_alias_must_agree_and_be_boolean(self):
        self.assertEqual(query_params("insecure=1&allowInsecure=1")["insecure"], "1")
        self.assertEqual(query_params("insecure=yes&allowInsecure=true")["insecure"], "yes")
        for query in ("insecure=1&allowInsecure=0", "insecure=0&allowInsecure=yes", "insecure=x&allowInsecure=y"):
            with self.subTest(query=query):
                with self.assertRaises(AppError):
                    query_params(query)

    def test_single_insecure_spelling_is_left_alone(self):
        # The alias check only fires when both spellings are present; one on its
        # own is the normal case and must not be treated as a conflict.
        self.assertEqual(query_params("allowInsecure=1"), {"allowInsecure": "1"})
        self.assertEqual(query_params("insecure=1"), {"insecure": "1"})


class ParseTests(unittest.TestCase):
    def test_ws_tls_with_pin(self):
        result = parse_vless_uri(WS_TLS_PIN)
        self.assertEqual(result["server"], "203.0.113.10")
        self.assertEqual(result["port"], 2083)
        self.assertEqual(result["uuid"], UUID)
        self.assertEqual(result["security"], "tls")
        self.assertEqual(result["network"], "ws")
        self.assertEqual(result["sni"], "google.com")
        self.assertEqual(result["host_header"], "s7r.example.com")
        self.assertEqual(result["path"], "/")
        self.assertEqual(result["encryption"], "none")
        self.assertEqual(result["pins"], PIN)
        self.assertEqual(result["alpn"], ["http/1.1"])
        self.assertEqual(result["fingerprint"], "chrome")
        self.assertEqual(result["name"], "test")
        self.assertFalse(result["allow_insecure"])
        self.assertEqual(result["headers"], {"Host": "s7r.example.com"})
        self.assertNotIn("reality", result)

    def test_reality_link(self):
        result = parse_vless_uri(REALITY)
        self.assertTrue(result["reality"])
        self.assertEqual(result["security"], "reality")
        self.assertEqual(result["reality_public_key"], REALITY_KEY)
        self.assertEqual(result["reality_short_id"], "abcd")
        self.assertEqual(result["sni"], "example.com")
        self.assertEqual(result["fingerprint"], "chrome")
        self.assertEqual(result["name"], "reality")
        self.assertEqual(result["reality_spider_x"], "")

    def test_reality_aliases_and_spider_path(self):
        # Parameters belong in the query, so anything appended after "#reality"
        # would be part of the display name rather than the link.
        link = (
            REALITY.replace("&pbk=", "&publicKey=")
            .replace("&sid=", "&shortId=")
            .replace("#reality", "&spiderX=%2Fsp#reality")
        )
        result = parse_vless_uri(link)
        self.assertEqual(result["reality_public_key"], REALITY_KEY)
        self.assertEqual(result["reality_short_id"], "abcd")
        self.assertEqual(result["reality_spider_x"], "/sp")

    def test_reality_requires_sni_fp_and_key(self):
        for drop in ("sni=example.com&", "fp=chrome&", f"pbk={REALITY_KEY}&"):
            with self.subTest(drop=drop):
                with self.assertRaises(AppError):
                    parse_vless_uri(REALITY.replace(drop, ""))

    def test_xhttp_with_extra_json(self):
        result = parse_vless_uri(XHTTP_EXTRA)
        self.assertEqual(result["network"], "xhttp")
        self.assertEqual(result["xhttp_path"], "/dl")
        self.assertEqual(result["xhttp_host"], "cdn.example.com")
        self.assertEqual(result["xhttp_mode"], "auto")
        self.assertEqual(result["xhttp_extra"], {"scMaxEachBufferBytes": 1048576})

    def test_xhttp_extra_must_be_json_object(self):
        base = f"vless://{UUID}@example.com:443?security=tls&type=xhttp&sni=e.com"
        for extra, in (("%7Bnotjson",), ("%5B1%2C2%5D",), ("%22text%22",)):
            with self.subTest(extra=extra):
                with self.assertRaises(AppError):
                    parse_vless_uri(f"{base}&extra={extra}")
        # No extra at all is the normal case and must not add the key.
        self.assertNotIn("xhttp_extra", parse_vless_uri(base))

    def test_grpc_service_name_agrees_with_path(self):
        agree = parse_vless_uri(f"vless://{UUID}@example.com:443?security=tls&type=grpc&serviceName=svc&path=%2Fsvc")
        self.assertEqual(agree["grpc_service"], "svc")
        from_path = parse_vless_uri(f"vless://{UUID}@example.com:443?security=tls&type=grpc&path=%2Fonlypath")
        self.assertEqual(from_path["grpc_service"], "onlypath")
        authority = parse_vless_uri(
            f"vless://{UUID}@example.com:443?security=tls&type=grpc&serviceName=svc&host=h.example.com"
        )
        self.assertEqual(authority["grpc_authority"], "h.example.com")

    def test_grpc_service_name_conflicts_with_path(self):
        link = f"vless://{UUID}@example.com:443?security=tls&type=grpc&serviceName=svc&path=%2Fother"
        with self.assertRaises(AppError):
            parse_vless_uri(link)

    def test_grpc_multi_mode(self):
        self.assertTrue(parse_vless_uri(f"vless://{UUID}@e.com:443?security=tls&type=grpc&multiMode=1")["grpc_multi_mode"])
        self.assertFalse(parse_vless_uri(f"vless://{UUID}@e.com:443?security=tls&type=grpc")["grpc_multi_mode"])

    def test_ws_headers_and_host_precedence(self):
        link = (
            f"vless://{UUID}@example.com:443?security=tls&type=ws"
            "&headers=%7B%22X-Key%22%3A%22v%22%2C%22host%22%3A%22loser.example%22%7D&host=winner.example"
        )
        headers = parse_vless_uri(link)["headers"]
        self.assertEqual(headers, {"X-Key": "v", "Host": "winner.example"})
        self.assertEqual([k for k in headers if k.lower() == "host"], ["Host"])

    def test_ws_headers_must_be_string_object(self):
        base = f"vless://{UUID}@example.com:443?security=tls&type=ws&headers="
        for headers in ("notjson", "%5B1%5D", "%7B%22k%22%3A1%7D"):
            with self.subTest(headers=headers):
                with self.assertRaises(AppError):
                    parse_vless_uri(base + headers)

    def test_httpupgrade_fields(self):
        result = parse_vless_uri(f"vless://{UUID}@e.com:443?security=tls&type=httpupgrade&path=%2Fu&host=h.example.com")
        self.assertEqual(result["httpupgrade_path"], "/u")
        self.assertEqual(result["httpupgrade_host"], "h.example.com")

    def test_vision_flow_is_accepted_on_tcp(self):
        result = parse_vless_uri(f"vless://{UUID}@e.com:443?security=tls&type=tcp&flow=xtls-rprx-vision")
        self.assertEqual(result["flow"], "xtls-rprx-vision")

    def test_uuid_and_pin_are_normalised(self):
        upper = WS_TLS_PIN.replace(UUID, UUID.upper()).replace(PIN, PIN.upper())
        result = parse_vless_uri(upper)
        self.assertEqual(result["uuid"], UUID)
        self.assertEqual(result["pins"], PIN)

    def test_colon_separated_pin_is_normalised(self):
        colonised = ":".join(PIN[i:i + 2] for i in range(0, 64, 2))
        result = parse_vless_uri(WS_TLS_PIN.replace(PIN, colonised))
        self.assertEqual(result["pins"], PIN)

    def test_multiple_pins_are_kept(self):
        second = "b" * 64
        result = parse_vless_uri(WS_TLS_PIN.replace(PIN, f"{PIN},{second}"))
        self.assertEqual(result["pins"], f"{PIN},{second}")

    def test_fragment_is_truncated(self):
        result = parse_vless_uri(f"vless://{UUID}@e.com:443?type=tcp#{'n' * 300}")
        self.assertEqual(len(result["name"]), 128)

    def test_encryption_defaults_to_none_but_may_not_be_empty(self):
        self.assertEqual(parse_vless_uri(f"vless://{UUID}@e.com:443?type=tcp")["encryption"], "none")
        self.assertEqual(
            parse_vless_uri(f"vless://{UUID}@e.com:443?type=tcp&encryption=mlkem768x25519plus.native.0rtt")["encryption"],
            "mlkem768x25519plus.native.0rtt",
        )
        with self.assertRaises(AppError):
            parse_vless_uri(f"vless://{UUID}@e.com:443?type=tcp&encryption=")

    def test_surrounding_whitespace_is_tolerated(self):
        self.assertEqual(parse_vless_uri("  \n" + WS_TLS_PIN + " \t ")["uuid"], UUID)


class RejectionTests(unittest.TestCase):
    """Every way a link can be wrong must fail as an AppError, not a traceback."""

    def assert_rejected(self, link, *, allow_insecure=False):
        with self.assertRaises(AppError):
            parse_vless_uri(link, allow_insecure=allow_insecure)

    def test_bad_uuid(self):
        for uuid in ("not-a-uuid", "0123456789abcdef0123456789abcdef", f"{UUID}-x", "01234567-89ab-cdef-0123-456789abcde"):
            with self.subTest(uuid=uuid):
                self.assert_rejected(f"vless://{uuid}@e.com:443?type=tcp")

    def test_bad_port(self):
        self.assert_rejected(f"vless://{UUID}@e.com:70000?type=tcp")
        self.assert_rejected(f"vless://{UUID}@e.com:0?type=tcp")
        self.assert_rejected(f"vless://{UUID}@e.com?type=tcp")

    def test_bad_host(self):
        self.assert_rejected(f"vless://{UUID}@bad_host..com:443?type=tcp")
        self.assert_rejected(f"vless://{UUID}@-nope.example:443?type=tcp")

    def test_bad_pin(self):
        self.assert_rejected(WS_TLS_PIN.replace(PIN, "abc"))
        self.assert_rejected(WS_TLS_PIN.replace(PIN, "z" * 64))

    def test_duplicate_parameter(self):
        raw, fragment = WS_TLS_PIN.split("#", 1)
        self.assert_rejected(raw + "&sni=other.example#" + fragment)

    def test_conflicting_aliases(self):
        self.assert_rejected(f"vless://{UUID}@e.com:443?type=ws&network=tcp&security=tls")
        self.assert_rejected(f"vless://{UUID}@e.com:443?security=tls&sni=a.example&serverName=b.example")

    def test_unsupported_transport(self):
        for transport in ("quic", "kcp", "http", "websocket", ""):
            with self.subTest(transport=transport):
                self.assert_rejected(f"vless://{UUID}@e.com:443?security=tls&type={transport}")

    def test_unsupported_security(self):
        for security in ("xtls", "ss", "tls1.3", ""):
            with self.subTest(security=security):
                self.assert_rejected(f"vless://{UUID}@e.com:443?security={security}&type=tcp")

    def test_bad_flow(self):
        # Only the exact Vision flow is supported. A trailing-space variant is
        # trimmed by the URI-level strip() before parsing, so it is accepted.
        for flow in ("xtls-rprx-origin", "xtls-rprx-vision-2", "xtls-rprx-visionX", "vision", "XTLS-RPRX-VISION"):
            with self.subTest(flow=flow):
                self.assert_rejected(f"vless://{UUID}@e.com:443?security=tls&type=tcp&flow={flow}")

    def test_flow_requires_tcp(self):
        for transport in ("ws", "grpc", "xhttp", "httpupgrade"):
            with self.subTest(transport=transport):
                self.assert_rejected(f"vless://{UUID}@e.com:443?security=tls&type={transport}&flow=xtls-rprx-vision")

    def test_oversized_link(self):
        self.assert_rejected("vless://" + UUID + "@e.com:443?type=tcp&pad=" + "x" * MAX_URI_BYTES)
        self.assert_rejected("")

    def test_control_characters(self):
        for raw in ("vless://\n" + UUID + "@e.com:443", UUID + "\x00" + UUID, "vless://a\tb"):
            with self.subTest(raw=repr(raw)):
                self.assert_rejected(raw)

    def test_wrong_scheme_or_missing_credentials(self):
        self.assert_rejected(f"https://{UUID}@e.com:443?type=tcp")
        self.assert_rejected("vless://@e.com:443?type=tcp")
        self.assert_rejected(f"vless://{UUID}:password@e.com:443?type=tcp")

    def test_invalid_insecure_value(self):
        self.assert_rejected(f"vless://{UUID}@e.com:443?security=tls&allowInsecure=maybe", allow_insecure=True)

    def test_invalid_sni(self):
        self.assert_rejected(f"vless://{UUID}@e.com:443?security=tls&sni=-bad-.com")


class TlsPolicyTests(unittest.TestCase):
    def test_insecure_is_refused_without_explicit_opt_in(self):
        link = WS_TLS_PIN.replace("allowInsecure=0&insecure=0&", "allowInsecure=1&insecure=1&").replace(f"&pcs={PIN}", "")
        with self.assertRaises(AppError):
            parse_vless_uri(link)
        self.assertTrue(parse_vless_uri(link, allow_insecure=True)["allow_insecure"])

    def test_insecure_single_spelling_also_needs_opt_in(self):
        link = f"vless://{UUID}@e.com:443?security=tls&allowInsecure=1"
        with self.assertRaises(AppError):
            parse_vless_uri(link)
        self.assertTrue(parse_vless_uri(link, allow_insecure=True)["allow_insecure"])

    def test_insecure_cannot_be_combined_with_a_pin(self):
        link = WS_TLS_PIN.replace("allowInsecure=0&insecure=0&", "allowInsecure=1&insecure=1&")
        with self.assertRaises(AppError):
            parse_vless_uri(link, allow_insecure=True)

    def test_pin_requires_tls(self):
        for security in ("none", "reality"):
            with self.subTest(security=security):
                link = f"vless://{UUID}@e.com:443?security={security}&type=tcp&pcs={PIN}"
                with self.assertRaises(AppError):
                    parse_vless_uri(link)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.link = parse_vless_uri(WS_TLS_PIN)

    def test_listeners_are_loopback_only(self):
        for address in ("0.0.0.0:10808", "192.168.1.5:10808", "example.com:10808", "[2001:db8::1]:10808"):
            with self.subTest(address=address):
                with self.assertRaises(AppError):
                    build_xray_config(self.link, address, None)

    def test_malformed_listener_address(self):
        for address in ("127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:abc", ":10808"):
            with self.subTest(address=address):
                with self.assertRaises(AppError):
                    build_xray_config(self.link, address, None)

    def test_ipv6_loopback_is_accepted_and_normalised(self):
        config = build_xray_config(self.link, "[::1]:10808", None)
        self.assertEqual(config["inbounds"][0]["listen"], "::1")
        self.assertEqual(config["inbounds"][0]["port"], 10808)

    def test_two_listeners_get_distinct_ports(self):
        config = build_xray_config(self.link, "127.0.0.1:10808", "127.0.0.1:10809")
        self.assertEqual([i["tag"] for i in config["inbounds"]], ["socks-in", "http-in"])
        self.assertEqual([i["port"] for i in config["inbounds"]], [10808, 10809])
        self.assertEqual([i["listen"] for i in config["inbounds"]], ["127.0.0.1", "127.0.0.1"])
        self.assertEqual([i["protocol"] for i in config["inbounds"]], ["socks", "http"])
        self.assertEqual(config["routing"]["rules"][0]["inboundTag"], ["socks-in", "http-in"])

    def test_http_listener_is_optional(self):
        for http_addr in (None, ""):
            with self.subTest(http_addr=http_addr):
                config = build_xray_config(self.link, "127.0.0.1:10808", http_addr)
                self.assertEqual(len(config["inbounds"]), 1)
                self.assertEqual(config["routing"]["rules"][0]["inboundTag"], ["socks-in"])

    def test_socks_inbound_settings(self):
        inbound = build_xray_config(self.link, "127.0.0.1:10808", None)["inbounds"][0]
        self.assertEqual(inbound["settings"], {"auth": "noauth", "udp": True, "userLevel": 0})
        self.assertEqual(inbound["sniffing"], {"enabled": True, "destOverride": ["http", "tls"]})

    def test_outbound_shape(self):
        config = build_xray_config(self.link, "127.0.0.1:10808", None)
        self.assertEqual([o["tag"] for o in config["outbounds"]], ["proxy", "direct", "block"])
        vnext = config["outbounds"][0]["settings"]["vnext"][0]
        self.assertEqual(vnext["address"], "203.0.113.10")
        self.assertEqual(vnext["port"], 2083)
        self.assertEqual(vnext["users"], [{"id": UUID, "encryption": "none"}])
        self.assertEqual(config["log"], {"loglevel": "warning"})

    def test_flow_is_passed_through_to_the_user(self):
        link = parse_vless_uri(f"vless://{UUID}@e.com:443?security=tls&type=tcp&flow=xtls-rprx-vision")
        users = build_xray_config(link, "127.0.0.1:10808", None)["outbounds"][0]["settings"]["vnext"][0]["users"]
        self.assertEqual(users[0]["flow"], "xtls-rprx-vision")
        without_flow = parse_vless_uri(f"vless://{UUID}@e.com:443?security=tls&type=tcp")
        users = build_xray_config(without_flow, "127.0.0.1:10808", None)["outbounds"][0]["settings"]["vnext"][0]["users"]
        self.assertNotIn("flow", users[0])

    def test_tls_stream_settings(self):
        stream = build_xray_config(self.link, "127.0.0.1:10808", None)["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["network"], "ws")
        self.assertEqual(stream["security"], "tls")
        self.assertEqual(
            stream["tlsSettings"],
            {
                "allowInsecure": False,
                "serverName": "google.com",
                "fingerprint": "chrome",
                "alpn": ["http/1.1"],
                "pinnedPeerCertSha256": PIN,
            },
        )
        self.assertEqual(stream["wsSettings"], {"path": "/", "headers": {"Host": "s7r.example.com"}})

    def test_tls_settings_omit_empty_optional_fields(self):
        link = parse_vless_uri(f"vless://{UUID}@e.com:443?security=tls&type=tcp")
        stream = build_xray_config(link, "127.0.0.1:10808", None)["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["tlsSettings"], {"allowInsecure": False})

    def test_reality_stream_settings(self):
        link = parse_vless_uri(REALITY)
        stream = build_xray_config(link, "127.0.0.1:10808", None)["outbounds"][0]["streamSettings"]
        self.assertNotIn("tlsSettings", stream)
        self.assertEqual(
            stream["realitySettings"],
            {
                "serverName": "example.com",
                "fingerprint": "chrome",
                "publicKey": REALITY_KEY,
                "shortId": "abcd",
            },
        )
        with_spider = parse_vless_uri(REALITY.replace("#reality", "&spiderX=%2Fspider#reality"))
        self.assertEqual(
            build_xray_config(with_spider, "127.0.0.1:10808", None)["outbounds"][0]["streamSettings"]["realitySettings"]["spiderX"],
            "/spider",
        )

    def test_pins_are_not_applied_when_security_is_not_tls(self):
        # The parser already refuses this combination; the config generator must
        # not emit a pin on a stream that has no TLS settings to hold it.
        link = dict(self.link, security="none")
        config = build_xray_config(link, "127.0.0.1:10808", None)
        stream = config["outbounds"][0]["streamSettings"]
        self.assertNotIn("tlsSettings", stream)
        self.assertNotIn("realitySettings", stream)
        self.assertNotIn(PIN, json.dumps(config))

    def test_security_none_emits_no_tls_block(self):
        link = parse_vless_uri(f"vless://{UUID}@e.com:443?security=none&type=tcp")
        stream = build_xray_config(link, "127.0.0.1:10808", None)["outbounds"][0]["streamSettings"]
        self.assertEqual(stream, {"network": "tcp", "security": "none"})

    def test_transport_specific_stream_settings(self):
        grpc = parse_vless_uri(f"vless://{UUID}@e.com:443?security=tls&type=grpc&serviceName=svc&authority=a.example")
        stream = build_xray_config(grpc, "127.0.0.1:10808", None)["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["grpcSettings"], {"serviceName": "svc", "multiMode": False, "authority": "a.example"})

        upgrade = parse_vless_uri(f"vless://{UUID}@e.com:443?security=tls&type=httpupgrade&path=%2Fu&host=h.example")
        stream = build_xray_config(upgrade, "127.0.0.1:10808", None)["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["httpupgradeSettings"], {"path": "/u", "host": "h.example"})

        stream = build_xray_config(parse_vless_uri(XHTTP_EXTRA), "127.0.0.1:10808", None)["outbounds"][0]["streamSettings"]
        self.assertEqual(
            stream["xhttpSettings"],
            {"path": "/dl", "host": "cdn.example.com", "mode": "auto", "extra": {"scMaxEachBufferBytes": 1048576}},
        )

    def test_config_is_pure_and_deterministic(self):
        before = json.dumps(self.link, sort_keys=True)
        first = build_xray_config(self.link, "127.0.0.1:10808", "127.0.0.1:10809")
        second = build_xray_config(self.link, "127.0.0.1:10808", "127.0.0.1:10809")
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(self.link, sort_keys=True), before)


class MessageSafetyTests(unittest.TestCase):
    """The project's core invariant: an AppError never carries any part of a URI."""

    BAD_LINKS = [
        "vless://not-a-uuid@example.com:443?type=quic",
        f"vless://{UUID}@example.com:70000?type=tcp",
        f"vless://{UUID}@example.com:443?type=quic&security=xtls",
        f"vless://{UUID}@example.com:443?security=tls&type=tcp&flow=xtls-rprx-origin&name=secret-name",
        f"vless://{UUID}@example.com:443?security=tls&type=ws&pcs=not-a-pin&host=secret.example",
        f"vless://{UUID}@example.com:443?security=tls&type=tcp&sni=a&serverName=b",
        "vless://" + "x" * (MAX_URI_BYTES + 10),
        f"vless://{UUID}@example.com:443\n?type=tcp",
    ]

    def test_no_failure_message_discloses_the_link(self):
        for raw in self.BAD_LINKS:
            for allow_insecure in (False, True):
                with self.subTest(raw=raw[:40]):
                    try:
                        parse_vless_uri(raw, allow_insecure=allow_insecure)
                    except AppError as exc:
                        message = str(exc)
                        self.assertNotIn(UUID, message)
                        self.assertNotIn("vless://", message)
                        self.assertNotIn("secret.example", message)
                        self.assertNotIn("secret-name", message)
                        self.assertNotIn(UUID.split("-")[0], message)

    def test_no_failure_message_discloses_the_link_from_config_generation(self):
        parsed = parse_vless_uri(WS_TLS_PIN)
        for socks, http in (("0.0.0.0:10808", None), ("127.0.0.1", None), ("example.com:10808", "8.8.8.8:10809")):
            with self.subTest(socks=socks):
                try:
                    build_xray_config(parsed, socks, http)
                except AppError as exc:
                    self.assertNotIn(UUID, str(exc))
                    self.assertNotIn(PIN, str(exc))


if __name__ == "__main__":
    unittest.main()