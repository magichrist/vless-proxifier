"""TCP reachability probe for saved profiles.

Why this exists: the profile table shows a latency column so the user can tell
a dead node from a slow one *before* switching to it. The cheapest signal that
answers that question is a bare TCP connect to the server — no TLS handshake,
no tunnel, no proxy process involved.

Honest limitation: this measures reachability and TCP handshake latency to the
*server*, NOT end-to-end throughput through the tunnel. A fast connect says the
host is up and accepting connections; it says nothing about Reality/TLS
handshake success, bandwidth, or how the node behaves under load.
"""
from __future__ import annotations

import socket
import time

__all__ = ["probe_server"]


def probe_server(host: str, port: int, *, timeout: float = 3.0) -> int | None:
    """Return TCP connect latency to ``host:port`` in whole milliseconds.

    Returns ``None`` instead of raising when the host is unreachable, refuses
    the connection, does not resolve, or does not answer within ``timeout`` —
    callers (``ProxyService.probe_all``) probe many profiles in a thread pool
    and a single dead node must not abort the sweep.

    This measures reachability and TCP latency to the *server*, NOT end-to-end
    throughput through the tunnel: no TLS handshake is performed, no proxy is
    started, and no credentials are used.
    """
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except (OSError, ValueError, TypeError, OverflowError):
        # OSError covers refused/unreachable/timeout plus DNS failures
        # (socket.gaierror is an OSError subclass). The ValueError family
        # covers malformed inputs (bad port range, undecodable hostname);
        # a profile that cannot even be dialled counts as unreachable.
        return None
    elapsed_ms = (time.monotonic() - start) * 1000.0
    return max(0, int(elapsed_ms))
