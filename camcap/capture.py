"""Orchestrates one capture session for a camera IP.

On Windows with pydivert: Redirector + Relay (+ WS-Discovery sniffer).
On Linux: iptables REDIRECT (needs root / cached sudo) + Relay using SO_ORIGINAL_DST;
with external_rules=True the iptables rules are assumed to be applied by hand.
Elsewhere (or with test_mode=True): Relay only, every connection to the relay
port goes to (cam_ip, test_port) — useful for pointing curl / ODM at
http://<pc>:<relay_port>/ to exercise decoding and replay without a driver.
"""
from __future__ import annotations

import threading
from typing import Optional

from .model import LogStore
from .relay import NatTable, Relay, RelayThread

SRC_PORT_RANGE = (40000, 41000)


class CaptureSession:
    def __init__(self, cam_ip: str, store: Optional[LogStore] = None, *, relay_port: int = 0,
                 test_mode: bool = False, test_port: int = 80, wsd: bool = True,
                 external_rules: bool = False):
        self.cam_ip = cam_ip
        self.store = store if store is not None else LogStore()
        self.nat = NatTable()
        self.test_mode = test_mode
        self.test_port = test_port
        self.wsd = wsd
        self.external_rules = external_rules
        self.errors: list[str] = []
        self._lock = threading.Lock()
        self.relay_thread: Optional[RelayThread] = None
        self.redirector = None
        self.wsd_sniffer = None
        self.mode = "idle"
        self._relay_port_req = relay_port

    def _err(self, msg: str) -> None:
        with self._lock:
            self.errors.append(msg)
            del self.errors[:-200]

    def start(self) -> None:
        from . import redirector as rd
        from . import redirector_linux as rl
        default_target = (self.cam_ip, self.test_port) if self.test_mode else None
        relay = Relay(self.store, self.nat, listen_port=self._relay_port_req,
                      default_target=default_target, src_port_range=SRC_PORT_RANGE, on_error=self._err)
        self.relay_thread = RelayThread(relay).start()
        if self.test_mode:
            self.mode = "test (relay only)"
            return
        if rl.is_linux():
            self.redirector = rl.LinuxRedirector(self.cam_ip, self.relay_thread.port, SRC_PORT_RANGE)
            if self.external_rules:
                self.mode = (f"intercepting {self.cam_ip} (Linux, external iptables rules → "
                             f"relay :{self.relay_thread.port})")
                self.redirector = None
                return
            ok, why = self.redirector.can_apply()
            if not ok:
                self.stop()
                raise RuntimeError(why)
            self.redirector.apply()
            self.mode = f"intercepting {self.cam_ip} via iptables REDIRECT → :{self.relay_thread.port}"
            return
        ok, why = rd.pydivert_available()
        if not ok:
            self.stop()
            raise RuntimeError(f"cannot intercept on this machine: {why}. Use test_mode.")
        local_ip = rd.local_ip_for(self.cam_ip)
        self.redirector = rd.Redirector(self.cam_ip, local_ip, self.relay_thread.port, self.nat,
                                        SRC_PORT_RANGE, on_error=self._err)
        self.redirector.start()
        if self.wsd:
            self.wsd_sniffer = rd.WsDiscoverySniffer(self.store, self.cam_ip, on_error=self._err)
            self.wsd_sniffer.start()
        self.mode = f"intercepting {self.cam_ip} via {local_ip}:{self.relay_thread.port}"

    def stop(self) -> None:
        if self.redirector:
            if hasattr(self.redirector, "remove"):
                self.redirector.remove(quiet=True)
            else:
                self.redirector.stop()
        if self.wsd_sniffer:
            self.wsd_sniffer.stop()
        if self.relay_thread:
            self.relay_thread.stop()
        self.mode = "stopped"

    @property
    def relay_port(self) -> int:
        return self.relay_thread.port if self.relay_thread else 0

    def status(self) -> dict:
        return {
            "cam_ip": self.cam_ip,
            "mode": self.mode,
            "relay_port": self.relay_port,
            "events": len(self.store),
            "nat_entries": len(self.nat),
            "redirected": getattr(self.redirector, "packets_redirected", None),
            "rules": self.redirector.shell_text(self.redirector.add_commands())
                     if hasattr(self.redirector, "add_commands") else "",
            "errors": list(self.errors[-5:]),
        }
