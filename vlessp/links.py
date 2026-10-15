"""VLESS URI parsing and Xray config generation. Pure functions, no I/O.

This module is deliberately the dumbest part of the package: given a string it
returns a dict, given a dict it returns another dict. It opens no socket, reads
no file, touches no environment variable, and logs nothing. That is what lets the
profile layer call it from a Textual worker thread, lets it be tested without a
network, and lets the pre-refactor ``vless_proxy.py`` tests keep passing
unmodified.

Everything here was extracted from ``vless_proxy.py`` with behaviour unchanged.
If you are changing a rule (which transports are accepted, whether a pin is
allowed with ``security=none``), you are changing product behaviour, not doing a
refactor — update ``tests/test_vless_proxy.py`` expectations deliberately.

INVARIANT inherited from ``errors.AppError`` and enforced by every message below:
no error raised from this module may contain any part of a VLESS URI. Messages
are written from the *shape* of the problem ("unsupported transport", "invalid
port"), never interpolated from the input.
"""
from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
from typing import Any

from .errors import AppError

# A VLESS link is a handful of short parameters. Anything approaching a web page
# is either a mistake or an attempt to make the parser allocate unboundedly, and
# both are refused before any other parsing happens.
MAX_URI_BYTES = 16 * 1024

UUID_RE = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"(?i)^[0-9a-f]{64}$")

# Two spellings of the same parameter appear in links produced by different
# clients. Both are accepted; disagreeing values are refused rather than silently
# resolved, because guessing which one wins would make the tunnel wrong in a way
# the user cannot see.
_ALIASES: tuple[tuple[str, str], ...] = (
    ("type", "network"),
    ("sni", "serverName"),
    ("fp", "fingerprint"),
    ("pcs", "pinnedPeerCertSha256"),
    ("pbk", "publicKey"),
    ("sid", "shortId"),
)

__all__ = [
    "MAX_URI_BYTES",
    "SHA256_RE",
    "UUID_RE",
    "build_xray_config",
    "is_valid_hostname",
    "parse_vless_uri",
    "query_params",
]


def is_valid_hostname(host: str) -> bool:
    """Return True for a syntactically valid hostname or IP literal.

    Accepts bracketed-free IPv4/IPv6 literals so a bare address can be used as a
    server name. Rejects anything with an empty label, an over-long label, or
    leading/trailing hyphens, because those are the shapes that turn into a
    confusing TLS or DNS failure later instead of an obvious error here.
    """
    if not host or len(host) > 253 or host.endswith("."):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return all(1 <= len(label) <= 63 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) for label in labels)


def query_params(query: str) -> dict[str, str]:
    """Parse a VLESS query string into a validated, alias-checked mapping.

    Rejects duplicate keys, oversized keys/values, and disagreeing aliases. This
    is the choke point where an ambiguous link is caught, so a link that reaches
    Xray has exactly one possible meaning for every setting it names.
    """
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=128)
    except (ValueError, UnicodeError):
        raise AppError("Malformed VLESS query parameters.") from None
    result: dict[str, str] = {}
    for key, value in pairs:
        if key in result:
            raise AppError(f"Duplicate VLESS parameter {key!r} is ambiguous.")
        if len(key) > 64 or len(value.encode("utf-8")) > 4096:
            raise AppError(f"VLESS parameter {key!r} is too long.")
        result[key] = value
    for first, second in _ALIASES:
        if first in result and second in result and result[first] != result[second]:
            raise AppError(f"Conflicting aliases for {first!r} and {second!r}.")
    if "insecure" in result and "allowInsecure" in result:
        truthy = {"1", "true", "yes"}
        falsy = {"0", "false", "no"}
        a, b = result["insecure"].lower(), result["allowInsecure"].lower()
        if a not in truthy | falsy or b not in truthy | falsy or (a in truthy) != (b in truthy):
            raise AppError("Conflicting or invalid insecure/allowInsecure parameters.")
    return result


def parse_vless_uri(raw: str, *, allow_insecure: bool = False) -> dict[str, Any]:
    """Parse one VLESS URI into the normalized link dict used everywhere else.

    The returned dict is the storage format: it is JSON-serializable by
    construction, so the profile layer can persist it verbatim. Its keys and
    their order are part of this project's contract — ``profiles.json`` written
    by one version is read by the next. Do not add, rename, or drop a key
    without updating the contract.

    ``allow_insecure`` is the only way to accept a link that disables TLS
    certificate verification. It is a deliberate, explicit acknowledgement of a
    security risk, never a default.
    """
    raw = raw.strip()
    if not raw or len(raw.encode("utf-8")) > MAX_URI_BYTES:
        raise AppError("VLESS link is empty or exceeds the 16 KiB input limit.")
    if any(ord(c) < 0x20 for c in raw):
        raise AppError("VLESS link contains control characters.")
    try:
        url = urllib.parse.urlsplit(raw)
    except ValueError:
        raise AppError("Invalid VLESS URI syntax.") from None
    if url.scheme.lower() != "vless" or not url.username or url.password is not None:
        raise AppError("Expected vless://UUID@host:port.")
    uuid = urllib.parse.unquote(url.username)
    if not UUID_RE.fullmatch(uuid):
        raise AppError("Invalid VLESS UUID; expected canonical UUID format.")
    try:
        host = url.hostname or ""
        port = url.port
    except ValueError:
        raise AppError("Invalid VLESS host or port.") from None
    if not is_valid_hostname(host):
        raise AppError("VLESS server host is not a valid hostname or IP address.")
    if port is None or not 1 <= port <= 65535:
        raise AppError("VLESS server port must be between 1 and 65535.")
    q = query_params(url.query)

    def get(*keys: str, default: str = "") -> str:
        # A named local function rather than a lambda so it carries the type of
        # what it returns; behaviour is the same first-match-wins lookup.
        return next((q[k] for k in keys if k in q), default)

    security = get("security", default="none").lower()
    network = get("type", "network", default="tcp").lower()
    if security not in {"none", "tls", "reality"}:
        raise AppError(f"Unsupported security mode {security!r}; supported modes are none, tls, and reality.")
    if network not in {"tcp", "ws", "grpc", "httpupgrade", "xhttp"}:
        raise AppError(f"Unsupported transport {network!r}.")
    insecure_raw = get("allowInsecure", "insecure", default="0").lower()
    if insecure_raw not in {"0", "1", "false", "true", "no", "yes"}:
        raise AppError("The insecure/allowInsecure parameter must be a boolean.")
    insecure = insecure_raw in {"1", "true", "yes"}
    if insecure and not allow_insecure:
        raise AppError("The link disables TLS certificate verification. Use --allow-insecure only if you accept the security risk.")
    encryption = get("encryption", default="none")
    if not encryption:
        raise AppError("VLESS encryption parameter is empty.")
    sni = get("sni", "serverName")
    fingerprint = get("fp", "fingerprint")
    alpn = [item.strip() for item in get("alpn").split(",") if item.strip()]
    if sni and not is_valid_hostname(sni):
        raise AppError("Invalid SNI/serverName.")
    if security == "reality":
        if not sni or not fingerprint or not get("pbk", "publicKey"):
            raise AppError("Reality links require sni, fp, and pbk/publicKey parameters.")
    pin = get("pcs", "pinnedPeerCertSha256")
    if pin:
        for item in pin.split(","):
            if not SHA256_RE.fullmatch(item.replace(":", "").strip()):
                raise AppError("Certificate pin must be a 64-character SHA-256 hex digest.")
        if security != "tls":
            raise AppError("Certificate pinning in pcs is supported only with security=tls in this launcher.")
        if insecure:
            # A pin combined with verification disabled would still be checked by
            # some Xray versions and silently ignored by others. Refuse instead.
            raise AppError("Do not combine disabled TLS verification with certificate pinning.")

    out: dict[str, Any] = {
        "server": host,
        "port": port,
        "uuid": uuid.lower(),
        "security": security,
        "network": network,
        "name": urllib.parse.unquote(url.fragment)[:128],
        "encryption": encryption,
        "sni": sni,
        "fingerprint": fingerprint,
        "alpn": alpn,
        "allow_insecure": insecure,
        "pins": ",".join(item.replace(":", "").strip().lower() for item in pin.split(",") if item.strip()) if pin else "",
        "flow": get("flow"),
        "path": get("path", default="/"),
        "host_header": get("host"),
        "headers": {},
        "grpc_service": get("serviceName", "service_name"),
        "grpc_authority": get("authority"),
        "grpc_multi_mode": get("multiMode").lower() in {"1", "true"},
        "httpupgrade_path": get("path", default="/"),
        "httpupgrade_host": get("host"),
        "xhttp_path": get("path", default="/"),
        "xhttp_host": get("host"),
        "xhttp_mode": get("mode"),
        "reality_public_key": get("pbk", "publicKey"),
        "reality_short_id": get("sid", "shortId"),
        "reality_spider_x": get("spx", "spiderX"),
    }
    if out["flow"] and out["flow"] != "xtls-rprx-vision":
        raise AppError("Unsupported VLESS flow; only xtls-rprx-vision is supported.")
    if out["flow"] and network != "tcp":
        raise AppError("VLESS Vision flow is only supported with TCP transport.")
    if network == "grpc":
        # gRPC clients spell the service name either as serviceName or as the
        # request path. Agreement is fine; disagreement means the link is lying
        # about which one it means, so refuse.
        path_service = get("path").lstrip("/")
        if out["grpc_service"] and path_service and out["grpc_service"] != path_service:
            raise AppError("Conflicting gRPC serviceName and path values.")
        out["grpc_service"] = out["grpc_service"] or path_service
        out["grpc_authority"] = out["grpc_authority"] or out["host_header"]
    if network == "ws":
        headers_text = get("headers")
        if headers_text:
            try:
                headers = json.loads(headers_text)
            except json.JSONDecodeError:
                raise AppError("WebSocket headers must be valid JSON.") from None
            if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
                raise AppError("WebSocket headers must be a JSON object with string keys and values.")
            out["headers"] = headers
        if out["host_header"]:
            # An explicit host= wins over any Host buried in the headers JSON, and
            # any case variant of it is removed first so the map has one Host key.
            for existing in list(out["headers"]):
                if existing.lower() == "host":
                    del out["headers"][existing]
            out["headers"]["Host"] = out["host_header"]
    if network == "xhttp" and get("extra"):
        try:
            extra = json.loads(get("extra"))
        except json.JSONDecodeError:
            raise AppError("XHTTP extra parameter must be valid JSON.") from None
        if not isinstance(extra, dict):
            raise AppError("XHTTP extra parameter must be a JSON object.")
        out["xhttp_extra"] = extra
    if security == "reality":
        out["reality"] = True
    return out


def build_xray_config(link: dict[str, Any], socks_addr: str, http_addr: str | None) -> dict[str, Any]:
    """Turn a parsed link plus local listener addresses into an Xray config.

    Pure: no filesystem, no network, no environment. The only thing that can
    fail is a bad listener address, and that failure is a security decision —
    a local proxy exposed beyond loopback hands an open relay to the network the
    machine is attached to, so a non-loopback address is refused outright rather
    than honoured with a warning.

    ``http_addr`` of ``None`` (or empty) means "no HTTP listener"; the caller
    decides, not this function.
    """
    inbounds: list[dict[str, Any]] = []
    tags: list[str] = []
    for tag, address, protocol in (("socks-in", socks_addr, "socks"), ("http-in", http_addr, "http")):
        if not address:
            continue
        host, sep, port_s = address.rpartition(":")
        if not sep or not host or not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
            raise AppError(f"Invalid local listener address for {tag}.")
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            # Not an IP literal, so it cannot be proven loopback. A hostname is
            # not accepted here: it could resolve to anything at spawn time.
            raise AppError("Proxy listeners must bind to loopback only (127.0.0.1 or ::1).") from None
        if not ip.is_loopback:
            raise AppError("Proxy listeners must bind to loopback only (127.0.0.1 or ::1).")
        inbound: dict[str, Any] = {
            "tag": tag, "listen": str(ip), "port": int(port_s), "protocol": protocol,
            "settings": {"auth": "noauth", "udp": True, "userLevel": 0} if protocol == "socks" else {},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }
        inbounds.append(inbound)
        tags.append(tag)

    user: dict[str, Any] = {"id": link["uuid"], "encryption": link["encryption"] or "none"}
    if link["flow"]:
        user["flow"] = link["flow"]
    stream: dict[str, Any] = {"network": link["network"], "security": link["security"]}
    if link["security"] == "tls":
        tls: dict[str, Any] = {"allowInsecure": link["allow_insecure"]}
        if link["sni"]: tls["serverName"] = link["sni"]
        if link["fingerprint"]: tls["fingerprint"] = link["fingerprint"]
        if link["alpn"]: tls["alpn"] = link["alpn"]
        if link["pins"]: tls["pinnedPeerCertSha256"] = link["pins"]
        stream["tlsSettings"] = tls
    elif link["security"] == "reality":
        reality = {"serverName": link["sni"], "fingerprint": link["fingerprint"], "publicKey": link["reality_public_key"], "shortId": link["reality_short_id"]}
        if link["reality_spider_x"]: reality["spiderX"] = link["reality_spider_x"]
        stream["realitySettings"] = reality
    if link["network"] == "ws":
        ws: dict[str, Any] = {"path": link["path"] or "/"}
        if link["headers"]: ws["headers"] = link["headers"]
        stream["wsSettings"] = ws
    elif link["network"] == "grpc":
        grpc: dict[str, Any] = {"serviceName": link["grpc_service"], "multiMode": link["grpc_multi_mode"]}
        if link["grpc_authority"]: grpc["authority"] = link["grpc_authority"]
        stream["grpcSettings"] = grpc
    elif link["network"] == "httpupgrade":
        upgrade: dict[str, Any] = {"path": link["httpupgrade_path"] or "/"}
        if link["httpupgrade_host"]: upgrade["host"] = link["httpupgrade_host"]
        stream["httpupgradeSettings"] = upgrade
    elif link["network"] == "xhttp":
        xhttp: dict[str, Any] = {"path": link["xhttp_path"] or "/"}
        if link["xhttp_host"]: xhttp["host"] = link["xhttp_host"]
        if link["xhttp_mode"]: xhttp["mode"] = link["xhttp_mode"]
        if link.get("xhttp_extra") is not None: xhttp["extra"] = link["xhttp_extra"]
        stream["xhttpSettings"] = xhttp

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": link["server"], "port": link["port"], "users": [user]}]}, "streamSettings": stream},
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": tags, "outboundTag": "proxy"}]},
    }