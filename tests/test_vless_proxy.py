import unittest

from vless_proxy import AppError, build_xray_config, parse_vless_uri

UUID = "01234567-89ab-cdef-0123-456789abcdef"
PIN = "d4cb869694ad29d03b4edccf73835ec56d31e2c3eef031b72b97f54487a248b3"
LINK = (
    f"vless://{UUID}@203.0.113.10:2083?"
    "sni=google.com&path=%2F&type=ws&"
    "encryption=mlkem768x25519plus.native.0rtt.EXAMPLE&security=tls&"
    "allowInsecure=0&insecure=0&fp=chrome&alpn=http%2F1.1&"
    f"pcs={PIN}&host=s7r.example.com#test"
)


class ParseTests(unittest.TestCase):
    def test_sample_preserves_security_and_ws_fields(self):
        result = parse_vless_uri(LINK)
        self.assertEqual(result["server"], "203.0.113.10")
        self.assertEqual(result["port"], 2083)
        self.assertEqual(result["sni"], "google.com")
        self.assertEqual(result["host_header"], "s7r.example.com")
        self.assertEqual(result["path"], "/")
        self.assertEqual(result["encryption"], "mlkem768x25519plus.native.0rtt.EXAMPLE")
        self.assertEqual(result["pins"], PIN)
        self.assertEqual(result["alpn"], ["http/1.1"])
        self.assertFalse(result["allow_insecure"])

    def test_config_uses_two_loopback_listeners_and_proxy_rule(self):
        parsed = parse_vless_uri(LINK)
        config = build_xray_config(parsed, "127.0.0.1:10808", "127.0.0.1:10809")
        user = config["outbounds"][0]["settings"]["vnext"][0]["users"][0]
        stream = config["outbounds"][0]["streamSettings"]
        self.assertEqual(user["encryption"], parsed["encryption"])
        self.assertEqual(stream["tlsSettings"]["pinnedPeerCertSha256"], PIN)
        self.assertEqual(stream["wsSettings"]["headers"]["Host"], "s7r.example.com")
        self.assertEqual(config["routing"]["rules"][0]["outboundTag"], "proxy")
        self.assertEqual([x["listen"] for x in config["inbounds"]], ["127.0.0.1", "127.0.0.1"])

    def test_insecure_requires_explicit_opt_in(self):
        link = LINK.replace("allowInsecure=0&insecure=0&", "allowInsecure=1&insecure=1&").replace(f"&pcs={PIN}", "")
        with self.assertRaises(AppError):
            parse_vless_uri(link)
        self.assertTrue(parse_vless_uri(link, allow_insecure=True)["allow_insecure"])

    def test_duplicate_query_fails(self):
        raw, fragment = LINK.split("#", 1)
        with self.assertRaises(AppError):
            parse_vless_uri(raw + "&sni=other.example#" + fragment)

    def test_bad_port_fails(self):
        with self.assertRaises(AppError):
            parse_vless_uri(LINK.replace(":2083?", ":70000?"))

    def test_bad_pin_fails(self):
        with self.assertRaises(AppError):
            parse_vless_uri(LINK.replace(PIN, "abc"))

    def test_conflicting_insecure_aliases_fail(self):
        link = LINK.replace("allowInsecure=0&insecure=0", "allowInsecure=1&insecure=0")
        with self.assertRaises(AppError):
            parse_vless_uri(link, allow_insecure=True)

    def test_wildcard_listener_is_accepted(self):
        # Binding beyond loopback is a deliberate opt-in (the proxy is
        # unauthenticated, so the UI warns), not an error.
        parsed = parse_vless_uri(LINK)
        config = build_xray_config(parsed, "0.0.0.0:10808", None)
        self.assertEqual(config["inbounds"][0]["listen"], "0.0.0.0")

    def test_hostname_listener_is_rejected(self):
        parsed = parse_vless_uri(LINK)
        with self.assertRaises(AppError):
            build_xray_config(parsed, "example.com:10808", None)

    def test_reality_fields(self):
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        reality = f"vless://{UUID}@example.com:443?security=reality&type=tcp&sni=example.com&fp=chrome&pbk={key}&sid=abcd"
        result = parse_vless_uri(reality)
        config = build_xray_config(result, "127.0.0.1:10808", None)
        self.assertEqual(config["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"], key)


if __name__ == "__main__":
    unittest.main()
