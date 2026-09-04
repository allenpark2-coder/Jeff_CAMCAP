"""Windows-only: WinDivert packet redirector (via pydivert).

Two rewrite rules, mirroring what mitmproxy's old platform/windows.py did:

 1. client → camera        (outbound, ip.DstAddr == CAM, not from relay's src ports)
        remember NAT[client_src_port] = (CAM, orig_dst_port)
        rewrite dst  → (LOCAL_IP, RELAY_PORT)
 2. relay → client         (outbound, ip.SrcAddr == LOCAL_IP, tcp.SrcPort == RELAY_PORT)
        rewrite src  → (CAM, orig_dst_port)  so the client sees the camera replying

Checksums are recalculated by pydivert on send(). We rewrite to the interface
IP, never to 127.0.0.1 — WinDivert cannot inject to loopback (error 1214,
basil00/WinDivert#82), which is also why the relay binds 0.0.0.0.

A second SNIFF-only handle watches UDP 3702 (WS-Discovery) so the "scan" a
client performs is logged too; those packets are never touched.

Requires Administrator. Everything here is 待實機驗證 — this module cannot run
on Linux.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from typing import Callable, Optional, Tuple

from .decoders import wsd_action
from .model import PROTO_WSD, Event, LogStore
from .relay import NatTable


def is_windows() -> bool:
    return sys.platform.startswith("win")


def pydivert_available() -> Tuple[bool, str]:
    if not is_windows():
        return False, "not Windows"
    try:
        import pydivert  # noqa: F401
    except ImportError as e:
        return False, f"pydivert not installed: {e}"
    return True, ""


def local_ip_for(target_ip: str) -> str:
    """IP of the interface Windows would use to reach target_ip."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 9))
        return s.getsockname()[0]
    finally:
        s.close()


class Redirector(threading.Thread):
    def __init__(self, cam_ip: str, local_ip: str, relay_port: int, nat: NatTable,
                 src_port_range: Tuple[int, int] = (40000, 41000),
                 on_error: Optional[Callable[[str], None]] = None):
        super().__init__(name="camcap-redirector", daemon=True)
        self.cam_ip = cam_ip
        self.local_ip = local_ip
        self.relay_port = relay_port
        self.nat = nat
        self.lo, self.hi = src_port_range
        self.on_error = on_error or (lambda m: None)
        self._stop = threading.Event()
        self.packets_redirected = 0
        self.packets_restored = 0

    @property
    def filter(self) -> str:
        return (
            "outbound and ip and tcp and ("
            f"(ip.DstAddr == {self.cam_ip} and not (tcp.SrcPort >= {self.lo} and tcp.SrcPort < {self.hi}))"
            f" or (ip.SrcAddr == {self.local_ip} and tcp.SrcPort == {self.relay_port})"
            ")"
        )

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        import pydivert
        try:
            with pydivert.WinDivert(self.filter) as w:
                for pkt in w:
                    if self._stop.is_set():
                        w.send(pkt)
                        break
                    try:
                        self._rewrite(pkt)
                    except Exception as e:  # never drop the packet silently
                        self.on_error(f"rewrite failed: {e}")
                    w.send(pkt)
        except Exception as e:
            self.on_error(f"WinDivert failed: {e}")

    def _rewrite(self, pkt) -> None:
        if pkt.dst_addr == self.cam_ip and not (self.lo <= pkt.src_port < self.hi):
            # rule 1: client → camera
            self.nat.set(pkt.src_port, (self.cam_ip, pkt.dst_port))
            pkt.dst_addr = self.local_ip
            pkt.dst_port = self.relay_port
            self.packets_redirected += 1
        elif pkt.src_addr == self.local_ip and pkt.src_port == self.relay_port:
            # rule 2: relay → client
            orig = self.nat.get(pkt.dst_port)
            if orig:
                pkt.src_addr, pkt.src_port = orig
                self.packets_restored += 1


class WsDiscoverySniffer(threading.Thread):
    """SNIFF-only handle on UDP 3702; logs Probe / ProbeMatches as Events."""

    def __init__(self, store: LogStore, cam_ip: Optional[str] = None,
                 on_error: Optional[Callable[[str], None]] = None):
        super().__init__(name="camcap-wsd", daemon=True)
        self.store = store
        self.cam_ip = cam_ip
        self.on_error = on_error or (lambda m: None)
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        import pydivert
        flt = "udp and (udp.DstPort == 3702 or udp.SrcPort == 3702)"
        try:
            with pydivert.WinDivert(flt, flags=pydivert.Flag.SNIFF) as w:
                for pkt in w:
                    if self._stop.is_set():
                        break
                    if self.cam_ip and pkt.src_addr != self.cam_ip and pkt.dst_addr != self.cam_ip \
                            and not pkt.dst_addr.startswith("239."):
                        continue
                    text = bytes(pkt.payload).decode("utf-8", "replace")
                    ev = Event(id=self.store.new_id(), ts=time.time(), stream=0, proto=PROTO_WSD,
                               dst_ip=pkt.dst_addr, dst_port=pkt.dst_port, src_port=pkt.src_port,
                               method="UDP", url=f"udp://{pkt.dst_addr}:{pkt.dst_port}",
                               soap_action=wsd_action(text), req_body=text[:BODY_CAP_WSD],
                               note="WS-Discovery (sniffed, not relayed)")
                    self.store.add(ev)
        except Exception as e:
            self.on_error(f"WS-Discovery sniff failed: {e}")


BODY_CAP_WSD = 16 * 1024
