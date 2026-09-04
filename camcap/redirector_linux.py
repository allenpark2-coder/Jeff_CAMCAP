"""Linux counterpart of the WinDivert redirector: iptables REDIRECT.

    iptables -t nat -N CAMCAP
    iptables -t nat -A CAMCAP -d <CAM> -p tcp -m multiport ! --sports 40000:40999 -j REDIRECT --to-ports <RELAY>
    iptables -t nat -A OUTPUT -j CAMCAP

Locally generated TCP to the camera lands on the relay; the relay recovers the
original (ip, port) with SO_ORIGINAL_DST, so no NAT table is needed here. Our
own upstream sockets use source ports 40000-40999 and are excluded, exactly as
on Windows. Needs root (or a cached sudo).

This exists so the whole pipeline (relay → decoders → log → replay) can be
exercised against a real camera from a Linux box before the Windows driver
path is verified.
"""
from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
from typing import Optional, Tuple

SO_ORIGINAL_DST = 80  # linux/netfilter_ipv4.h
CHAIN = "CAMCAP"


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def original_dst(sock: socket.socket) -> Optional[Tuple[str, int]]:
    """(ip, port) the client actually connected to, before REDIRECT."""
    if not is_linux():
        return None
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    except OSError:
        return None
    port = struct.unpack("!H", raw[2:4])[0]
    ip = socket.inet_ntoa(raw[4:8])
    return ip, port


class LinuxRedirector:
    def __init__(self, cam_ip: str, relay_port: int, src_port_range=(40000, 41000), use_sudo: Optional[bool] = None):
        self.cam_ip = cam_ip
        self.relay_port = relay_port
        self.lo, self.hi = src_port_range
        self.use_sudo = (os.geteuid() != 0) if use_sudo is None else use_sudo
        self.applied = False

    # -- rule text -----------------------------------------------------------
    def add_commands(self) -> list[list[str]]:
        return [
            ["iptables", "-t", "nat", "-N", CHAIN],
            ["iptables", "-t", "nat", "-A", CHAIN, "-d", self.cam_ip, "-p", "tcp",
             "-m", "multiport", "!", "--sports", f"{self.lo}:{self.hi - 1}",
             "-j", "REDIRECT", "--to-ports", str(self.relay_port)],
            ["iptables", "-t", "nat", "-A", "OUTPUT", "-j", CHAIN],
        ]

    def del_commands(self) -> list[list[str]]:
        return [
            ["iptables", "-t", "nat", "-D", "OUTPUT", "-j", CHAIN],
            ["iptables", "-t", "nat", "-F", CHAIN],
            ["iptables", "-t", "nat", "-X", CHAIN],
        ]

    def shell_text(self, cmds) -> str:
        pre = "sudo " if self.use_sudo else ""
        return "\n".join(pre + " ".join(c) for c in cmds)

    # -- apply ---------------------------------------------------------------
    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        full = (["sudo", "-n"] if self.use_sudo else []) + cmd
        return subprocess.run(full, capture_output=True, text=True)

    def can_apply(self) -> Tuple[bool, str]:
        if not is_linux():
            return False, "not Linux"
        if not shutil.which("iptables"):
            return False, "iptables not found"
        if os.geteuid() == 0:
            return True, ""
        r = subprocess.run(["sudo", "-n", "true"], capture_output=True)
        if r.returncode != 0:
            return False, "not root and sudo needs a password; run these yourself:\n" + self.shell_text(self.add_commands())
        return True, ""

    def apply(self) -> None:
        self.remove(quiet=True)  # leftovers from a crashed run
        for c in self.add_commands():
            r = self._run(c)
            if r.returncode != 0:
                self.remove(quiet=True)
                raise RuntimeError(f"{' '.join(c)}: {r.stderr.strip()}")
        self.applied = True

    def remove(self, quiet: bool = False) -> None:
        for c in self.del_commands():
            r = self._run(c)
            if r.returncode != 0 and not quiet:
                print(f"[camcap] {' '.join(c)}: {r.stderr.strip()}", file=sys.stderr)
        self.applied = False
