"""Passive protocol decoders.

A StreamDecoder receives the raw bytes of ONE TCP connection in both directions
(as tee'd by the relay) and turns them into Events. It never produces bytes; the
relay forwards the original bytes untouched.

HTTP/1.x is decoded with two mirrored h11 state machines: the SERVER-role
connection parses what the client sends, the CLIENT-role connection parses what
the camera answers. Every parsed event is "sent" into the opposite machine so
both stay in sync (this is the standard h11 proxy pattern) — the serialised
bytes h11 returns are discarded.
"""
from __future__ import annotations

import re
import time
from collections import deque
from typing import Callable, Optional

import h11

from .model import (BODY_CAP, PROTO_CGI, PROTO_ONVIF, PROTO_RAW, PROTO_RTSP, Event,
                    LogStore)

_HTTP_REQ = re.compile(rb"^[A-Z]{3,10} \S+ HTTP/1\.[01]\r\n")
_RTSP_REQ = re.compile(rb"^[A-Z_]{3,20} \S+ RTSP/1\.0\r\n")
_SOAP_ACTION = re.compile(r"<(?:[\w.-]+:)?Body\b[^>]*>\s*<(?:([\w.-]+):)?([\w.-]+)", re.S)
_WSD_ACTION = re.compile(r"<(?:[\w.-]+:)?Action\b[^>]*>\s*([^<\s]+)", re.S)

# path prefix → vendor guess; only cosmetic, helps the eye in the UI
VENDOR_PREFIXES = (
    ("/ISAPI/", "hikvision"),
    ("/SDK/", "hikvision"),
    ("/axis-cgi/", "axis"),
    ("/stw-cgi/", "hanwha"),
    ("/cgi-bin/", "dahua/amcrest/generic"),
    ("/RPC2", "dahua"),
    ("/web/cgi-bin/hi3510/", "hi3510"),
    ("/onvif/", "onvif"),
)

_TEXT_TYPES = ("text/", "application/xml", "application/soap+xml", "application/json",
               "application/x-www-form-urlencoded", "application/xhtml")


def classify_http(url: str, headers: dict, body: str):
    """Return (proto, soap_action, vendor) for a decoded HTTP request."""
    ctype = headers.get("content-type", "").lower()
    path = url.split("://", 1)[-1]
    path = "/" + path.split("/", 1)[1] if "/" in path else "/"
    is_soap = "/onvif/" in path.lower() or "soap+xml" in ctype or "<s:Envelope" in body[:500] or ":Envelope" in body[:500]
    action = None
    if is_soap:
        m = _SOAP_ACTION.search(body)
        if m:
            action = m.group(2)
        return PROTO_ONVIF, action, "onvif"
    vendor = None
    for prefix, name in VENDOR_PREFIXES:
        if path.startswith(prefix):
            vendor = name
            break
    return PROTO_CGI, None, vendor


def detect_auth(headers: dict, body: str) -> str:
    a = headers.get("authorization", "")
    if a.lower().startswith("digest "):
        return "digest"
    if a.lower().startswith("basic "):
        return "basic"
    if "PasswordDigest" in body:
        return "wsse-digest"
    if "PasswordText" in body:
        return "wsse-text"
    return "none"


def body_to_text(headers: dict, data: bytes) -> str:
    ctype = headers.get("content-type", "").lower()
    if data and ctype and not any(ctype.startswith(t) for t in _TEXT_TYPES):
        return f"<{len(data)} bytes binary {ctype}>"
    if len(data) > BODY_CAP:
        return data[:BODY_CAP].decode("utf-8", "replace") + f"\n<truncated, {len(data)} bytes total>"
    return data.decode("utf-8", "replace")


def _hdict(headers) -> dict:
    """h11 headers (list of (bytes, bytes)) → lower-cased str dict (last wins)."""
    out = {}
    for k, v in headers:
        out[k.decode("latin-1").lower()] = v.decode("latin-1")
    return out


class _Pending:
    __slots__ = ("event", "req_body", "resp_body", "t_req_done", "t_resp_first")

    def __init__(self, event: Event):
        self.event = event
        self.req_body = bytearray()
        self.resp_body = bytearray()
        self.t_req_done: Optional[float] = None
        self.t_resp_first: Optional[float] = None


class StreamDecoder:
    """Decode one TCP connection. Thread-agnostic: call feed_* from one thread."""

    def __init__(self, store: LogStore, stream: int, dst_ip: str, dst_port: int, src_port: int,
                 now: Callable[[], float] = time.time):
        self.store = store
        self.stream = stream
        self.dst_ip, self.dst_port, self.src_port = dst_ip, dst_port, src_port
        self.now = now
        self.kind: Optional[str] = None      # None (undecided) | http | rtsp | raw
        self._sniff = bytearray()
        self._early_s2c = bytearray()
        self.bytes_c2s = 0
        self.bytes_s2c = 0
        # http
        self._cconn: Optional[h11.Connection] = None
        self._sconn: Optional[h11.Connection] = None
        self._building: Optional[_Pending] = None
        self._awaiting: deque[_Pending] = deque()
        self._responding: Optional[_Pending] = None
        # rtsp
        self._rtsp_c = bytearray()
        self._rtsp_s = bytearray()
        self._rtsp_await: deque[_Pending] = deque()
        # raw
        self._raw_event: Optional[Event] = None

    # -- public --------------------------------------------------------------
    def feed_c2s(self, data: bytes) -> None:
        self.bytes_c2s += len(data)
        if self.kind is None:
            self._sniff += data
            if len(self._sniff) < 8 and b"\r\n" not in self._sniff:
                return
            self._decide()
            data = bytes(self._sniff)
            self._sniff.clear()
        if self.kind == "http":
            self._http_feed(self._cconn, data, client=True)
        elif self.kind == "rtsp":
            self._rtsp_c += data
            self._rtsp_parse()
        else:
            self._raw_touch()

    def feed_s2c(self, data: bytes) -> None:
        self.bytes_s2c += len(data)
        if self.kind is None:
            # server talked first (banner) — not HTTP/RTSP as we know it
            self._early_s2c += data
            if self._sniff:
                return
            self.kind = "raw"
            self._raw_touch()
            return
        if self.kind == "http":
            self._http_feed(self._sconn, data, client=False)
        elif self.kind == "rtsp":
            self._rtsp_s += data
            self._rtsp_parse()
        else:
            self._raw_touch()

    def close(self) -> None:
        if self.kind is None and self._sniff:
            self._decide()
            data = bytes(self._sniff)
            self._sniff.clear()
            if self.kind == "http":
                self._http_feed(self._cconn, data, client=True)
            elif self.kind == "rtsp":
                self._rtsp_c += data
                self._rtsp_parse()
            else:
                self._raw_touch()
        if self._raw_event is not None:
            self._raw_event.bytes_c2s = self.bytes_c2s
            self._raw_event.bytes_s2c = self.bytes_s2c
        # requests that never got a response
        for p in list(self._awaiting) + ([self._responding] if self._responding else []):
            if p.event.resp_status is None and not p.event.note:
                p.event.note = "connection closed before response"

    # -- decision ------------------------------------------------------------
    def _decide(self) -> None:
        head = bytes(self._sniff[:64])
        if _HTTP_REQ.match(head):
            self.kind = "http"
            self._cconn = h11.Connection(our_role=h11.SERVER)
            self._sconn = h11.Connection(our_role=h11.CLIENT)
        elif _RTSP_REQ.match(head):
            self.kind = "rtsp"
        else:
            self.kind = "raw"

    def _new_event(self, proto: str) -> Event:
        return Event(id=self.store.new_id(), ts=self.now(), stream=self.stream, proto=proto,
                     dst_ip=self.dst_ip, dst_port=self.dst_port, src_port=self.src_port)

    # -- raw -----------------------------------------------------------------
    def _raw_touch(self) -> None:
        if self._raw_event is None:
            ev = self._new_event(PROTO_RAW)
            ev.note = "non-HTTP TCP payload (vendor SDK protocol?)"
            self._raw_event = self.store.add(ev)
        self._raw_event.bytes_c2s = self.bytes_c2s
        self._raw_event.bytes_s2c = self.bytes_s2c

    def _degrade_to_raw(self, why: str) -> None:
        self.kind = "raw"
        self._raw_touch()
        self._raw_event.note = f"HTTP decode failed: {why}"

    # -- http ----------------------------------------------------------------
    def _http_feed(self, conn: h11.Connection, data: bytes, client: bool) -> None:
        try:
            conn.receive_data(data)
            while True:
                ev = conn.next_event()
                if ev is h11.NEED_DATA or ev is h11.PAUSED:
                    break
                if client:
                    self._on_client_event(ev)
                else:
                    self._on_server_event(ev)
                if ev is h11.ConnectionClosed or isinstance(ev, h11.ConnectionClosed):
                    break
        except (h11.RemoteProtocolError, h11.LocalProtocolError) as e:
            self._degrade_to_raw(str(e))

    def _on_client_event(self, ev) -> None:
        if isinstance(ev, h11.Request):
            hdrs = _hdict(ev.headers)
            host = hdrs.get("host", f"{self.dst_ip}:{self.dst_port}")
            url = f"http://{host}{ev.target.decode('latin-1')}"
            e = self._new_event(PROTO_CGI)
            e.method = ev.method.decode()
            e.url = url
            e.req_headers = hdrs
            self._building = _Pending(e)
            self._sconn.send(ev)
        elif isinstance(ev, h11.Data):
            if self._building:
                self._building.req_body += ev.data
            self._sconn.send(ev)
        elif isinstance(ev, h11.EndOfMessage):
            p = self._building
            self._building = None
            if p:
                e = p.event
                e.req_body = body_to_text(e.req_headers, bytes(p.req_body))
                e.proto, e.soap_action, e.vendor = classify_http(e.url, e.req_headers, e.req_body)
                e.auth = detect_auth(e.req_headers, e.req_body)
                e.ts = self.now()
                p.t_req_done = e.ts
                self._awaiting.append(p)
                self.store.add(e)
            self._sconn.send(ev)
            self._maybe_next_cycle()

    def _on_server_event(self, ev) -> None:
        if isinstance(ev, h11.InformationalResponse):
            return  # 100-continue etc.; nothing to record
        if isinstance(ev, h11.Response):
            p = self._awaiting.popleft() if self._awaiting else None
            if p is None:
                # response without a parsed request (e.g. we joined mid-stream)
                p = _Pending(self._new_event(PROTO_CGI))
                p.event.note = "response without captured request"
                self.store.add(p.event)
            p.t_resp_first = self.now()
            p.event.resp_status = ev.status_code
            p.event.resp_headers = _hdict(ev.headers)
            if p.t_req_done is not None:
                p.event.latency_ms = round((p.t_resp_first - p.t_req_done) * 1000, 1)
            self._responding = p
            self._cconn.send(ev)
        elif isinstance(ev, h11.Data):
            if self._responding:
                self._responding.resp_body += ev.data
            self._cconn.send(ev)
        elif isinstance(ev, h11.EndOfMessage):
            p = self._responding
            self._responding = None
            if p:
                p.event.resp_body = body_to_text(p.event.resp_headers, bytes(p.resp_body))
            self._cconn.send(ev)
            self._maybe_next_cycle()

    def _maybe_next_cycle(self) -> None:
        c, s = self._cconn, self._sconn
        if c.our_state is h11.DONE and c.their_state is h11.DONE:
            c.start_next_cycle()
        if s.our_state is h11.DONE and s.their_state is h11.DONE:
            s.start_next_cycle()

    # -- rtsp ----------------------------------------------------------------
    @staticmethod
    def _split_msg(buf: bytearray):
        """Return (head_lines, body, consumed) for one RTSP message or None."""
        idx = buf.find(b"\r\n\r\n")
        if idx < 0:
            return None
        head = bytes(buf[:idx]).decode("latin-1")
        lines = head.split("\r\n")
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        clen = int(hdrs.get("content-length", "0") or 0)
        total = idx + 4 + clen
        if len(buf) < total:
            return None
        body = bytes(buf[idx + 4: total])
        return lines[0], hdrs, body, total

    def _rtsp_parse(self) -> None:
        while True:
            m = self._split_msg(self._rtsp_c)
            if not m:
                break
            first, hdrs, body, used = m
            del self._rtsp_c[:used]
            parts = first.split(" ")
            e = self._new_event(PROTO_RTSP)
            e.method = parts[0]
            e.url = parts[1] if len(parts) > 1 else None
            e.req_headers = hdrs
            e.req_body = body.decode("utf-8", "replace")
            e.auth = detect_auth(hdrs, "")
            p = _Pending(e)
            p.t_req_done = e.ts
            self._rtsp_await.append(p)
            self.store.add(e)
        while True:
            m = self._split_msg(self._rtsp_s)
            if not m:
                break
            first, hdrs, body, used = m
            del self._rtsp_s[:used]
            parts = first.split(" ")
            p = self._rtsp_await.popleft() if self._rtsp_await else None
            if p is None:
                continue  # interleaved RTP or unmatched response
            try:
                p.event.resp_status = int(parts[1])
            except (IndexError, ValueError):
                p.event.resp_status = None
            p.event.resp_headers = hdrs
            p.event.resp_body = body.decode("utf-8", "replace")
            p.event.latency_ms = round((self.now() - p.t_req_done) * 1000, 1)


def wsd_action(xml_text: str) -> Optional[str]:
    """Extract the WS-Addressing Action (Probe / ProbeMatches / Hello / Bye)."""
    m = _WSD_ACTION.search(xml_text)
    if m:
        return m.group(1).rsplit("/", 1)[-1]
    m = _SOAP_ACTION.search(xml_text)
    return m.group(2) if m else None
