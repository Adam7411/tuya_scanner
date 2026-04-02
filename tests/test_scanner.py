"""Unit tests for tuya_scanner."""

import json
import struct
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from tuya_scanner.device import TuyaDevice
from tuya_scanner.scanner import (
    TuyaScanner,
    _parse_tuya_udp,
    _probe_tcp,
    UDP_PORT_CLEAR,
    UDP_PORT_ENCRYPTED,
    TCP_PORT,
    TUYA_UDP_PREFIX,
)


# ---------------------------------------------------------------------------
# Helper: build a raw Tuya UDP packet from a dict payload
# ---------------------------------------------------------------------------

def _make_tuya_udp(payload: dict, with_header: bool = True) -> bytes:
    """Produce a minimal Tuya UDP packet wrapping *payload*.

    Header layout: prefix(4) + seq(4) + cmd(4) + data_len(4)
    data_len = len(json_payload) + 4 (the trailing CRC)
    """
    body = json.dumps(payload).encode()
    if not with_header:
        return body
    # data_len = body length + 4 (CRC suffix)
    data_len = len(body) + 4
    header = (
        TUYA_UDP_PREFIX
        + struct.pack(">I", 1)          # seq
        + struct.pack(">I", 0x12)       # cmd
        + struct.pack(">I", data_len)   # data_len
    )
    crc = struct.pack(">I", 0)          # CRC placeholder
    return header + body + crc


SAMPLE_PAYLOAD = {
    "ip": "192.168.1.42",
    "gwId": "abc123",
    "active": 2,
    "ability": 0,
    "mode": 0,
    "encrypt": True,
    "productKey": "key001",
    "version": "3.3",
    "token": False,
    "wf_cfg": True,
}


class TestTuyaDevice(unittest.TestCase):
    def test_str_representation(self):
        dev = TuyaDevice(ip="10.0.0.1", gwId="id1", productKey="pk", version="3.1")
        s = str(dev)
        self.assertIn("10.0.0.1", s)
        self.assertIn("id1", s)
        self.assertIn("pk", s)
        self.assertIn("3.1", s)

    def test_to_dict_keys(self):
        dev = TuyaDevice(ip="10.0.0.2")
        d = dev.to_dict()
        for key in ("ip", "gwId", "encrypt", "productKey", "version", "source"):
            self.assertIn(key, d)

    def test_defaults(self):
        dev = TuyaDevice(ip="10.0.0.3")
        self.assertEqual(dev.port, TCP_PORT)
        self.assertEqual(dev.source, "broadcast")
        self.assertFalse(dev.encrypt)


class TestParseTuyaUdp(unittest.TestCase):
    def test_plain_json(self):
        data = json.dumps(SAMPLE_PAYLOAD).encode()
        device = _parse_tuya_udp(data, ("192.168.1.42", 6666))
        self.assertIsNotNone(device)
        self.assertEqual(device.ip, "192.168.1.42")
        self.assertEqual(device.gwId, "abc123")
        self.assertTrue(device.encrypt)
        self.assertEqual(device.productKey, "key001")
        self.assertEqual(device.version, "3.3")

    def test_tuya_header_packet(self):
        data = _make_tuya_udp(SAMPLE_PAYLOAD, with_header=True)
        device = _parse_tuya_udp(data, ("0.0.0.0", 6666))
        self.assertIsNotNone(device)
        self.assertEqual(device.ip, "192.168.1.42")
        self.assertEqual(device.gwId, "abc123")

    def test_invalid_data_returns_none(self):
        device = _parse_tuya_udp(b"not json at all!!!", ("10.0.0.1", 6666))
        self.assertIsNone(device)

    def test_ip_fallback_to_addr(self):
        payload = {"gwId": "xyz"}
        data = json.dumps(payload).encode()
        device = _parse_tuya_udp(data, ("192.168.5.5", 6666))
        self.assertIsNotNone(device)
        self.assertEqual(device.ip, "192.168.5.5")

    def test_extra_fields_stored(self):
        payload = {**SAMPLE_PAYLOAD, "customField": "hello"}
        data = json.dumps(payload).encode()
        device = _parse_tuya_udp(data, ("192.168.1.42", 6666))
        self.assertIsNotNone(device)
        self.assertIn("customField", device.extra)
        self.assertEqual(device.extra["customField"], "hello")


class TestProbeTcp(unittest.TestCase):
    def _start_server(self):
        """Start a minimal TCP server; return (server_socket, port)."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _accept():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=_accept, daemon=True)
        t.start()
        return srv, port

    def test_open_port_returns_true(self):
        srv, port = self._start_server()
        try:
            self.assertTrue(_probe_tcp("127.0.0.1", port, timeout=2.0))
        finally:
            srv.close()

    def test_closed_port_returns_false(self):
        # Pick a port that is unlikely to be in use
        self.assertFalse(_probe_tcp("127.0.0.1", 19876, timeout=0.5))


class TestTuyaScanner(unittest.TestCase):
    """Tests for TuyaScanner that mock the network layer."""

    def _mock_udp_socket(self, packets, port):
        """Return a mock socket.socket that yields *packets* then times out."""
        mock_sock = MagicMock()
        side_effects = list(packets) + [socket.timeout()]
        mock_sock.recvfrom.side_effect = side_effects
        return mock_sock

    @patch("tuya_scanner.scanner.socket.socket")
    def test_scan_discovers_device_from_udp(self, mock_socket_cls):
        data = json.dumps(SAMPLE_PAYLOAD).encode()
        addr = ("192.168.1.42", 6666)

        # Both UDP sockets: one returns a packet, the other immediately times out
        call_count = [0]

        def socket_factory(*args, **kwargs):
            sock = MagicMock()
            if call_count[0] == 0:
                sock.recvfrom.side_effect = [(data, addr), socket.timeout()]
            else:
                sock.recvfrom.side_effect = [socket.timeout()]
            call_count[0] += 1
            return sock

        mock_socket_cls.side_effect = socket_factory

        scanner = TuyaScanner(timeout=0.1)
        devices = scanner.scan()

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].ip, "192.168.1.42")
        self.assertEqual(devices[0].gwId, "abc123")

    def test_on_device_callback(self):
        data = json.dumps(SAMPLE_PAYLOAD).encode()
        addr = ("192.168.1.42", 6666)
        call_count = [0]

        with patch("tuya_scanner.scanner.socket.socket") as mock_socket_cls:
            def socket_factory(*args, **kwargs):
                sock = MagicMock()
                if call_count[0] == 0:
                    sock.recvfrom.side_effect = [(data, addr), socket.timeout()]
                else:
                    sock.recvfrom.side_effect = [socket.timeout()]
                call_count[0] += 1
                return sock

            mock_socket_cls.side_effect = socket_factory

            seen = []
            scanner = TuyaScanner(timeout=0.1, on_device=seen.append)
            scanner.scan()

        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].ip, "192.168.1.42")

    def test_duplicate_devices_merged(self):
        """The same device discovered twice should only appear once."""
        data = json.dumps(SAMPLE_PAYLOAD).encode()
        addr = ("192.168.1.42", 6666)
        call_count = [0]

        with patch("tuya_scanner.scanner.socket.socket") as mock_socket_cls:
            def socket_factory(*args, **kwargs):
                sock = MagicMock()
                if call_count[0] == 0:
                    sock.recvfrom.side_effect = [
                        (data, addr), (data, addr), socket.timeout()
                    ]
                else:
                    sock.recvfrom.side_effect = [socket.timeout()]
                call_count[0] += 1
                return sock

            mock_socket_cls.side_effect = socket_factory

            scanner = TuyaScanner(timeout=0.1)
            devices = scanner.scan()

        self.assertEqual(len(devices), 1)

    @patch("tuya_scanner.scanner._probe_tcp", return_value=True)
    @patch("tuya_scanner.scanner.socket.socket")
    def test_tcp_scan_discovers_device(self, mock_socket_cls, mock_probe):
        # No UDP packets – each socket call gets its own mock
        def socket_factory(*args, **kwargs):
            sock = MagicMock()
            sock.recvfrom.side_effect = [socket.timeout()]
            return sock

        mock_socket_cls.side_effect = socket_factory

        scanner = TuyaScanner(timeout=0.1, network="192.168.1.1/30")
        devices = scanner.scan()

        # /30 has 2 usable hosts
        ips = {d.ip for d in devices}
        self.assertIn("192.168.1.1", ips)
        self.assertIn("192.168.1.2", ips)
        for d in devices:
            self.assertEqual(d.source, "tcp_scan")

    def test_invalid_network_does_not_crash(self):
        def socket_factory(*args, **kwargs):
            sock = MagicMock()
            sock.recvfrom.side_effect = [socket.timeout()]
            return sock

        with patch("tuya_scanner.scanner.socket.socket") as mock_socket_cls:
            mock_socket_cls.side_effect = socket_factory
            scanner = TuyaScanner(timeout=0.1, network="not_a_cidr")
            devices = scanner.scan()
        self.assertEqual(devices, [])


class TestCLI(unittest.TestCase):
    def test_help_exits_zero(self):
        from tuya_scanner.cli import _build_parser
        parser = _build_parser()
        with self.assertRaises(SystemExit) as cm:
            parser.parse_args(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_version_exits_zero(self):
        from tuya_scanner.cli import _build_parser
        parser = _build_parser()
        with self.assertRaises(SystemExit) as cm:
            parser.parse_args(["--version"])
        self.assertEqual(cm.exception.code, 0)

    @patch("tuya_scanner.scanner.socket.socket")
    def test_main_json_output(self, mock_socket_cls):
        def socket_factory(*args, **kwargs):
            sock = MagicMock()
            sock.recvfrom.side_effect = [socket.timeout()]
            return sock

        mock_socket_cls.side_effect = socket_factory

        import io
        import sys
        from tuya_scanner.cli import main

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            ret = main(["--timeout", "0.1", "--json"])
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout

        self.assertEqual(ret, 0)
        # Should be valid JSON array
        parsed = json.loads(output.split("\n", 1)[1])  # skip the "Scanning..." line
        self.assertIsInstance(parsed, list)


if __name__ == "__main__":
    unittest.main()
