"""Replay a captured log against a camera (the same one or another IP).

Auth strategy per request (auth_mode="auto"):
  1. raw     — send exactly what was captured. Works on cameras without
               nonce caching / replay protection.
  2. re-auth — on 401/403 or an ONVIF NotAuthorized fault, and only if
               credentials were given:
               * CGI  : drop Authorization, let requests do Digest/Basic.
               * ONVIF: strip <Security>, re-sign with fresh nonce/Created
                        (Created adjusted by the camera's clock offset), and
                        also allow HTTP Digest (Hikvision wants both).
A result is "ok" when the replayed status equals the captured one.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from . import wsse
from .model import PROTO_CGI, PROTO_ONVIF, Event

HOP_BY_HOP = {"host", "content-length", "transfer-encoding", "connection", "keep-alive",
              "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade",
              "accept-encoding"}

_NOT_AUTH = re.compile(r"NotAuthorized|FailedAuthentication|not\s+authorized", re.I)


@dataclass
class ReplayResult:
    event_id: int
    label: str
    orig_status: Optional[int]
    status: Optional[int]
    ok: bool
    auth_used: str = ""
    error: str = ""
    elapsed_ms: float = 0.0
    skipped: bool = False
    resp_body: str = ""


@dataclass
class ReplayOptions:
    target_ip: Optional[str] = None           # None = same camera as captured
    port_map: dict = field(default_factory=dict)  # orig_port → new_port
    username: Optional[str] = None
    password: Optional[str] = None
    speed: float = 1.0                        # 0 = as fast as possible
    auth_mode: str = "auto"                   # auto | raw | reauth
    stop_on_error: bool = False
    timeout: float = 10.0
    verify_tls: bool = False


class Replayer:
    def __init__(self, events: list[Event], opts: ReplayOptions):
        self.events = [e for e in sorted(events, key=lambda e: (e.ts, e.id))]
        self.opts = opts
        self.cancel = threading.Event()
        self.session = requests.Session()
        self.session.verify = opts.verify_tls
        self._clock_offset: Optional[float] = None
        self.results: list[ReplayResult] = []

    # -- helpers -------------------------------------------------------------
    def _rewrite_url(self, ev: Event) -> str:
        parts = urlsplit(ev.url or "")
        host = parts.hostname or ev.dst_ip
        port = parts.port or ev.dst_port
        if self.opts.target_ip:
            host = self.opts.target_ip
        port = self.opts.port_map.get(port, port)
        default = 443 if parts.scheme == "https" else 80
        netloc = host if port == default else f"{host}:{port}"
        return urlunsplit((parts.scheme or "http", netloc, parts.path or "/", parts.query, ""))

    def _headers(self, ev: Event, keep_auth: bool) -> dict:
        out = {}
        for k, v in ev.req_headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP:
                continue
            if lk == "authorization" and not keep_auth:
                continue
            out[k] = v
        return out

    def _clock_offset_for(self, url: str) -> float:
        if self._clock_offset is None:
            parts = urlsplit(url)
            dev = urlunsplit((parts.scheme, parts.netloc, "/onvif/device_service", "", ""))
            self._clock_offset = wsse.camera_clock_offset(dev, session=self.session)
        return self._clock_offset

    @staticmethod
    def _needs_reauth(status: int, body: str, proto: str) -> bool:
        if status in (401, 403):
            return True
        return proto == PROTO_ONVIF and status >= 400 and bool(_NOT_AUTH.search(body or ""))

    def _send(self, ev: Event, url: str, headers: dict, body: Optional[bytes], auth=None):
        t = time.perf_counter()
        r = self.session.request(ev.method or "GET", url, headers=headers, data=body, auth=auth,
                                 timeout=self.opts.timeout, allow_redirects=False)
        return r, (time.perf_counter() - t) * 1000

    # -- main ----------------------------------------------------------------
    def run(self) -> Iterator[ReplayResult]:
        prev_ts: Optional[float] = None
        for ev in self.events:
            if self.cancel.is_set():
                break
            if prev_ts is not None and self.opts.speed > 0:
                delay = (ev.ts - prev_ts) / self.opts.speed
                if delay > 0 and self.cancel.wait(min(delay, 3600)):
                    break
            prev_ts = ev.ts
            res = self._replay_one(ev)
            self.results.append(res)
            yield res
            if self.opts.stop_on_error and not res.ok and not res.skipped:
                break

    def _replay_one(self, ev: Event) -> ReplayResult:
        label = ev.summary()
        if ev.proto not in (PROTO_CGI, PROTO_ONVIF):
            return ReplayResult(ev.id, label, ev.resp_status, None, True, skipped=True,
                                error=f"{ev.proto} not replayable")
        if ev.req_body.startswith("<") and "bytes binary" in ev.req_body[:40]:
            return ReplayResult(ev.id, label, ev.resp_status, None, True, skipped=True,
                                error="binary request body not captured")
        url = self._rewrite_url(ev)
        body = ev.req_body.encode("utf-8") if ev.req_body else None
        o = self.opts
        try:
            # 1) raw
            if o.auth_mode in ("auto", "raw"):
                r, ms = self._send(ev, url, self._headers(ev, keep_auth=True), body)
                if r.status_code == ev.resp_status or o.auth_mode == "raw" \
                        or not self._needs_reauth(r.status_code, r.text, ev.proto) \
                        or not (o.username and o.password):
                    return ReplayResult(ev.id, label, ev.resp_status, r.status_code,
                                        r.status_code == ev.resp_status, "raw", "", ms,
                                        resp_body=r.text[:4096])
            # 2) re-auth
            if not (o.username and o.password):
                return ReplayResult(ev.id, label, ev.resp_status, None, False, "",
                                    "re-auth needed but no credentials")
            headers = self._headers(ev, keep_auth=False)
            auth = HTTPDigestAuth(o.username, o.password)
            if ev.auth == "basic":
                auth = HTTPBasicAuth(o.username, o.password)
            send_body = body
            if ev.proto == PROTO_ONVIF and body:
                off = self._clock_offset_for(url)
                send_body = wsse.resign(ev.req_body, o.username, o.password, off).encode("utf-8")
            r, ms = self._send(ev, url, headers, send_body, auth=auth)
            if r.status_code == 401 and isinstance(auth, HTTPDigestAuth):
                # camera wanted Basic after all
                r, ms = self._send(ev, url, headers, send_body, auth=HTTPBasicAuth(o.username, o.password))
            used = "wsse+digest" if ev.proto == PROTO_ONVIF else ("basic" if isinstance(auth, HTTPBasicAuth) else "digest")
            return ReplayResult(ev.id, label, ev.resp_status, r.status_code,
                                r.status_code == ev.resp_status, used, "", ms, resp_body=r.text[:4096])
        except requests.RequestException as e:
            return ReplayResult(ev.id, label, ev.resp_status, None, False, "", str(e))
