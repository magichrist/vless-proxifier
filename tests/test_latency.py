"""Tests for vlessp.latency — bare TCP connect timing, no proxy involved."""
from __future__ import annotations

import socket
import threading
import unittest

from vlessp.latency import probe_server


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


class TestProbeServer(unittest.TestCase):
    def test_closed_port_returns_none(self) -> None:
        # A freshly-freed loopback port refuses connections: unreachable.
        self.assertIsNone(probe_server("127.0.0.1", _free_port(), timeout=2.0))

    def test_listening_socket_returns_nonnegative_int(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            port = int(server.getsockname()[1])
            stop = threading.Event()

            def _accept_forever() -> None:
                server.settimeout(0.2)
                while not stop.is_set():
                    try:
                        conn, _ = server.accept()
                    except OSError:
                        continue
                    try:
                        conn.close()
                    except OSError:
                        pass

            worker = threading.Thread(target=_accept_forever, daemon=True)
            worker.start()
            try:
                result = probe_server("127.0.0.1", port, timeout=2.0)
            finally:
                stop.set()
                worker.join(timeout=5.0)
            self.assertIsInstance(result, int)
            assert result is not None  # for the type checker; implied by above
            self.assertGreaterEqual(result, 0)
        finally:
            server.close()

    def test_hostname_and_ip_forms_agree(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            port = int(server.getsockname()[1])
            by_ip = probe_server("127.0.0.1", port, timeout=2.0)
            by_name = probe_server("localhost", port, timeout=2.0)
            self.assertIsInstance(by_ip, int)
            self.assertIsInstance(by_name, int)
        finally:
            server.close()

    def test_unresolvable_host_returns_none_without_raising(self) -> None:
        # .invalid is reserved by RFC 2606 and never resolves.
        self.assertIsNone(probe_server("nonexistent.invalid", 443, timeout=2.0))

    def test_invalid_port_returns_none_without_raising(self) -> None:
        # Port 0 is never connectable; an out-of-range port cannot even be
        # dialled. Both are "unreachable" rather than errors.
        # (A routed-timeout case is intentionally absent: this sandbox answers
        # unroutable TEST-NET addresses via an egress proxy, so no address
        # reliably times out here. The closed-port test above covers OSError.)
        self.assertIsNone(probe_server("127.0.0.1", 0, timeout=2.0))
        self.assertIsNone(probe_server("127.0.0.1", 99999, timeout=2.0))


if __name__ == "__main__":
    unittest.main()
