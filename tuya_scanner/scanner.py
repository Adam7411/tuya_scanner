"""Core Tuya scanner: discovers devices via UDP broadcast and TCP port scan."""

import ipaddress
import json
import logging
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

from .device import TuyaDevice

logger = logging.getLogger(__name__)

# Tuya UDP broadcast ports
UDP_PORT_CLEAR = 6666   # unencrypted broadcasts
UDP_PORT_ENCRYPTED = 6667  # encrypted broadcasts

# Tuya TCP control port
TCP_PORT = 6668

# Tuya UDP message prefix (4-byte magic header)
TUYA_UDP_PREFIX = b"\x00\x00\x55\xaa"

# Maximum concurrent TCP probe workers during network scan
TCP_SCAN_MAX_WORKERS = 256

# Default scan timeout in seconds
DEFAULT_TIMEOUT = 5.0

# Maximum UDP packet size
UDP_BUFFER_SIZE = 4096


def _parse_tuya_udp(data: bytes, addr: tuple) -> Optional[TuyaDevice]:
    """Parse a raw UDP packet from a Tuya device.

    Tuya UDP packets may have a 16-byte header (magic + seq + cmd + data_len)
    followed by a JSON payload and a 4-byte CRC suffix, or may be plain JSON.

    Header layout: prefix(4) + seq(4) + cmd(4) + data_len(4)
    data_len = len(json_payload) + 4 (the trailing CRC)
    """
    payload = data
    # Strip the 16-byte Tuya UDP header when present
    if data[:4] == TUYA_UDP_PREFIX and len(data) >= 16:
        # data_len includes the JSON payload + 4-byte CRC suffix
        data_len = struct.unpack(">I", data[12:16])[0]
        # JSON payload sits between byte 16 and (16 + data_len - 4)
        payload = data[16:16 + data_len - 4] if data_len >= 4 else data[16:]

    try:
        obj = json.loads(payload.decode("utf-8", errors="replace").strip("\x00"))
    except (json.JSONDecodeError, ValueError):
        logger.debug("Non-JSON UDP packet from %s: %r", addr[0], data[:64])
        return None

    ip = obj.get("ip") or addr[0]
    device = TuyaDevice(
        ip=ip,
        gwId=obj.get("gwId", ""),
        active=int(obj.get("active", 0)),
        ability=int(obj.get("ability", 0)),
        mode=int(obj.get("mode", 0)),
        encrypt=bool(obj.get("encrypt", False)),
        productKey=obj.get("productKey", ""),
        version=str(obj.get("version", "")),
        token=bool(obj.get("token", False)),
        wf_cfg=bool(obj.get("wf_cfg", False)),
        port=TCP_PORT,
        source="broadcast",
        extra={k: v for k, v in obj.items() if k not in {
            "ip", "gwId", "active", "ability", "mode",
            "encrypt", "productKey", "version", "token", "wf_cfg",
        }},
    )
    return device


def _probe_tcp(ip: str, port: int = TCP_PORT, timeout: float = 1.0) -> bool:
    """Return True if a TCP connection to *ip*:*port* succeeds."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


class TuyaScanner:
    """Discovers Tuya devices on the local network.

    Two discovery methods are available:

    * **Broadcast listener** – passive: binds a UDP socket and collects the
      periodic beacon packets that Tuya devices send on ports 6666 / 6667.
    * **Network scan** – active: iterates every host in a CIDR range and
      probes TCP port 6668 (the Tuya control port).

    Both methods can be combined by calling :meth:`scan`.

    Parameters
    ----------
    timeout:
        How long (in seconds) to listen for UDP broadcasts.  Also used as
        the per-host TCP probe timeout when ``network`` is provided.
    network:
        Optional CIDR string (e.g. ``"192.168.1.0/24"``) to scan for Tuya
        devices via TCP in addition to UDP broadcast listening.
    bind_address:
        IP address to bind the UDP sockets to.  Defaults to ``""`` (all
        interfaces), which is necessary to receive LAN broadcast packets.
        Restrict to a specific interface address (e.g. ``"192.168.1.5"``)
        when you want to limit capture to a single network interface.
    on_device:
        Optional callback called with each :class:`~tuya_scanner.TuyaDevice`
        as soon as it is discovered.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        network: Optional[str] = None,
        bind_address: str = "",
        on_device: Optional[Callable[[TuyaDevice], None]] = None,
    ) -> None:
        self.timeout = timeout
        self.network = network
        self.bind_address = bind_address
        self.on_device = on_device
        self._devices: Dict[str, TuyaDevice] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> List[TuyaDevice]:
        """Run a full scan and return discovered devices.

        Listens for UDP broadcasts on ports 6666/6667 for :attr:`timeout`
        seconds.  If :attr:`network` was provided, also probes every host in
        that CIDR block on TCP port 6668.
        """
        threads = []

        # Start UDP listeners in background threads
        for port in (UDP_PORT_CLEAR, UDP_PORT_ENCRYPTED):
            t = threading.Thread(
                target=self._listen_udp,
                args=(port,),
                daemon=True,
            )
            t.start()
            threads.append(t)

        # TCP network scan (optional)
        if self.network:
            tcp_thread = threading.Thread(
                target=self._scan_network_tcp,
                daemon=True,
            )
            tcp_thread.start()
            threads.append(tcp_thread)

        for t in threads:
            t.join()

        return list(self._devices.values())

    def listen(self) -> List[TuyaDevice]:
        """Listen for UDP broadcast beacons only (no active TCP scan)."""
        threads = []
        for port in (UDP_PORT_CLEAR, UDP_PORT_ENCRYPTED):
            t = threading.Thread(
                target=self._listen_udp,
                args=(port,),
                daemon=True,
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return list(self._devices.values())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _register(self, device: TuyaDevice) -> None:
        """Thread-safe device registration; calls :attr:`on_device` once."""
        with self._lock:
            if device.ip not in self._devices:
                self._devices[device.ip] = device
                if self.on_device:
                    self.on_device(device)
            else:
                # Merge new data into existing record
                existing = self._devices[device.ip]
                for attr in ("gwId", "productKey", "version", "encrypt"):
                    new_val = getattr(device, attr)
                    if new_val and not getattr(existing, attr):
                        setattr(existing, attr, new_val)

    def _listen_udp(self, port: int) -> None:
        """Bind a UDP socket and collect Tuya broadcast packets."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass  # SO_REUSEPORT not available on all platforms
            sock.settimeout(self.timeout)
            # Bind to the specified address (default "" = all interfaces).
            # All-interfaces binding is intentional: broadcast packets arrive
            # on whatever interface the device is connected to, and we do not
            # always know which one that will be in advance.
            sock.bind((self.bind_address, port))
        except OSError as exc:
            logger.warning("Cannot bind UDP port %d: %s", port, exc)
            return

        logger.debug("Listening on UDP port %d for %.1fs", port, self.timeout)
        try:
            while True:
                try:
                    data, addr = sock.recvfrom(UDP_BUFFER_SIZE)
                except socket.timeout:
                    break
                except OSError as exc:
                    logger.debug("UDP recv error on port %d: %s", port, exc)
                    break
                device = _parse_tuya_udp(data, addr)
                if device:
                    logger.info("UDP(%d): discovered %s", port, device)
                    self._register(device)
        finally:
            sock.close()

    def _scan_network_tcp(self) -> None:
        """Probe every host in :attr:`network` on TCP port 6668."""
        try:
            net = ipaddress.ip_network(self.network, strict=False)
        except ValueError as exc:
            logger.error("Invalid network %r: %s", self.network, exc)
            return

        hosts = [str(h) for h in net.hosts()]
        logger.debug("TCP scan of %s (%d hosts, port %d)", net, len(hosts), TCP_PORT)
        max_workers = min(TCP_SCAN_MAX_WORKERS, len(hosts)) if hosts else 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._probe_and_register, ip): ip for ip in hosts}
            for future in as_completed(futures):
                # Propagate unexpected exceptions to the log
                exc = future.exception()
                if exc:
                    logger.debug("TCP probe error for %s: %s", futures[future], exc)

    def _probe_and_register(self, ip: str) -> None:
        if _probe_tcp(ip, TCP_PORT, timeout=self.timeout):
            device = TuyaDevice(ip=ip, port=TCP_PORT, source="tcp_scan")
            logger.info("TCP scan: discovered %s", device)
            self._register(device)
