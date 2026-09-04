"""Replay a captured log against a camera (the same one or another IP).

Cookie sessions (e.g. `POST /api/v1/auth/login` + `Cookie: opsis_session=...`):
the replayer keeps its own cookie jar. When credentials are given, JSON /
form login bodies get the supplied username/password substituted (so a
redacted log with `"password":"<redacted>"` is still replayable), and captured
`Cookie` headers are dropped once the jar holds a cookie for the target — the
freshly issued session is used instead of the stale captured one.

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

import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from . import wsse
from .model import PROTO_CGI, PROTO_ONVIF, Event, _is_secret_key

HOP_BY_HOP = {"host", "content-length", "transfer-encoding", "connection", "keep-alive",
              "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade",
              "accept-encoding"}

_NOT_AUTH = re.compile(r"NotAuthorized|FailedAuthentication|not\s+authorized", re.I)
_USER_KEYS = ("username", "user", "login", "account", "name")
_PW_PARTS = ("password", "passwd", "pwd")
_RE_FORM_USER = re.compile(r"(\b(?:username|user|login|account)=)[^&\s]*", re.I)
_RE_FORM_PW = re.compile(r"(\b(?:password|passwd|pwd|pass)=)[^&\s]*", re.I)


def substitute_credentials(body: str, username: str, password: str) -> str:
    """Put the operator's credentials into a login body (JSON or form-encoded).
    Only keys that look like user / password are touched; anything else is kept."""
    stripped = body.strip()
    if stripped[:1] == "{":
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            changed = False
            for k in list(obj):
                lk = k.replace("-", "").replace("_", "").lower()
                if any(p in lk for p in _PW_PARTS) and isinstance(obj[k], str):
                    obj[k] = password
                    changed = True
                elif lk in _USER_KEYS and isinstance(obj[k], str):
                    obj[k] = username
                    changed = True
            return json.dumps(obj, ensure_ascii=False, separators=(",", ":")) if changed else body
    if "=" in body and "\n" not in body and _RE_FORM_PW.search(body):
        body = _RE_FORM_PW.sub(lambda m: m.group(1) + password, body)
        body = _RE_FORM_USER.sub(lambda m: m.group(1) + username, body)
    return body


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
        self.session = requests.Session()          # carries cookies obtained during replay
        self.session.verify = opts.verify_tls
        self.bare = requests.Session()             # for requests that were captured without any cookie
        self.bare.verify = opts.verify_tls
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
        have_jar = len(self.session.cookies) > 0
        for k, v in ev.req_headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP:
                continue
            if lk == "authorization" and not keep_auth:
                continue
            if lk == "cookie" and have_jar:
                continue  # use the session we obtained during this replay, not the stale capture
            out[k] = v
        return out

    def _body_for(self, ev: Event) -> Optional[bytes]:
        if not ev.req_body:
            return None
        body = ev.req_body
        o = self.opts
        if o.username and o.password and ev.proto == PROTO_CGI and (ev.method or "").upper() in ("POST", "PUT"):
            body = substitute_credentials(body, o.username, o.password)
        return body.encode("utf-8")

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

    def _client(self, ev: Event) -> requests.Session:
        """Requests captured with a Cookie, or whose response set one (login), go
        through the cookie-carrying session; everything else is sent bare so an
        originally unauthenticated request stays unauthenticated on replay."""
        req_has = any(k.lower() == "cookie" for k in ev.req_headers)
        resp_sets = any(k.lower() == "set-cookie" for k in ev.resp_headers)
        return self.session if (req_has or resp_sets) else self.bare

    def _send(self, ev: Event, url: str, headers: dict, body: Optional[bytes], auth=None):
        client = self._client(ev)
        t = time.perf_counter()
        r = client.request(ev.method or "GET", url, headers=headers, data=body, auth=auth,
                           timeout=self.opts.timeout, allow_redirects=False)
        if client is self.bare:
            self.bare.cookies.clear()
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
        body = self._body_for(ev)
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
