"""Event record, thread-safe store, JSONL / HAR export and redaction."""
from __future__ import annotations

import json
import re
import threading
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Iterable, Optional

BODY_CAP = 256 * 1024  # bytes kept per body; larger bodies are truncated with a note

# Protocol tags used in Event.proto
PROTO_ONVIF = "onvif"
PROTO_CGI = "cgi"
PROTO_RTSP = "rtsp"
PROTO_RAW = "raw"
PROTO_WSD = "wsd"  # WS-Discovery over UDP 3702


@dataclass
class Event:
    id: int
    ts: float                 # epoch seconds when the request was complete
    stream: int               # TCP connection number within the session
    proto: str                # onvif | cgi | rtsp | raw | wsd
    dst_ip: str
    dst_port: int
    src_port: int
    method: Optional[str] = None
    url: Optional[str] = None
    soap_action: Optional[str] = None
    vendor: Optional[str] = None
    auth: Optional[str] = None            # digest | basic | wsse-digest | wsse-text | none
    req_headers: dict = field(default_factory=dict)
    req_body: str = ""
    resp_status: Optional[int] = None
    resp_headers: dict = field(default_factory=dict)
    resp_body: str = ""
    latency_ms: Optional[float] = None
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    note: str = ""

    # -- serialisation -------------------------------------------------------
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})

    @property
    def is_http(self) -> bool:
        return self.proto in (PROTO_ONVIF, PROTO_CGI)

    @property
    def iso_ts(self) -> str:
        return datetime.fromtimestamp(self.ts, tz=timezone.utc).astimezone().isoformat(timespec="milliseconds")

    def summary(self) -> str:
        """One-line label used by the UI table."""
        if self.proto == PROTO_ONVIF:
            return self.soap_action or self.url or "?"
        if self.proto == PROTO_CGI:
            return self.url or "?"
        if self.proto == PROTO_RTSP:
            return self.url or "?"
        if self.proto == PROTO_WSD:
            return self.soap_action or "WS-Discovery"
        return f"tcp/{self.dst_port} {self.bytes_c2s}B→ ←{self.bytes_s2c}B"


class LogStore:
    """Thread-safe, append-only list of Events. Events are mutable: decoders
    append on request-complete and fill in the response later."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[Event] = []
        self._next_id = 1
        self._next_stream = 1

    def new_id(self) -> int:
        with self._lock:
            i = self._next_id
            self._next_id += 1
            return i

    def new_stream(self) -> int:
        with self._lock:
            s = self._next_stream
            self._next_stream += 1
            return s

    def add(self, ev: Event) -> Event:
        with self._lock:
            self._events.append(ev)
        return ev

    def all(self) -> list[Event]:
        with self._lock:
            return list(self._events)

    def since(self, last_id: int) -> list[Event]:
        with self._lock:
            return [e for e in self._events if e.id > last_id]

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._next_id = 1
            self._next_stream = 1

    # -- export / import -----------------------------------------------------
    def to_jsonl(self, redact: bool = False) -> str:
        evs = self.all()
        if redact:
            evs = [redact_event(e) for e in evs]
        return "".join(json.dumps(e.to_dict(), ensure_ascii=False) + "\n" for e in evs)

    @classmethod
    def from_jsonl(cls, text: str) -> "LogStore":
        store = cls()
        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            ev = Event.from_dict(json.loads(line))
            store.add(ev)
            store._next_id = max(store._next_id, ev.id + 1)
            store._next_stream = max(store._next_stream, ev.stream + 1)
        return store

    def to_har(self, redact: bool = False) -> str:
        evs = [e for e in self.all() if e.is_http]
        if redact:
            evs = [redact_event(e) for e in evs]
        return json.dumps(to_har_dict(evs), ensure_ascii=False, indent=1)


# ---------------------------------------------------------------------------
# HAR 1.2 export (HTTP events only; RTSP/RAW have no HAR representation)
# ---------------------------------------------------------------------------

def _hdrs(d: dict) -> list[dict]:
    return [{"name": k, "value": v} for k, v in d.items()]


def to_har_dict(events: Iterable[Event]) -> dict:
    entries = []
    for e in events:
        started = datetime.fromtimestamp(e.ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        req_ct = e.req_headers.get("content-type", "")
        resp_ct = e.resp_headers.get("content-type", "")
        entry = {
            "startedDateTime": started,
            "time": e.latency_ms or 0,
            "request": {
                "method": e.method or "GET",
                "url": e.url or "",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": _hdrs(e.req_headers),
                "queryString": [],
                "headersSize": -1,
                "bodySize": len(e.req_body.encode("utf-8", "replace")),
            },
            "response": {
                "status": e.resp_status or 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": _hdrs(e.resp_headers),
                "content": {
                    "size": len(e.resp_body.encode("utf-8", "replace")),
                    "mimeType": resp_ct,
                    "text": e.resp_body,
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
            },
            "cache": {},
            "timings": {"send": 0, "wait": e.latency_ms or 0, "receive": 0},
            "comment": f"camcap proto={e.proto} action={e.soap_action or ''} stream={e.stream}",
        }
        if e.req_body:
            entry["request"]["postData"] = {"mimeType": req_ct, "text": e.req_body}
        entries.append(entry)
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "camcap", "version": "0.1.0"},
            "entries": entries,
        }
    }


# ---------------------------------------------------------------------------
# Redaction — applied before a log leaves the machine.
# Raw replay of a redacted log will fail by design; re-auth replay still works.
# ---------------------------------------------------------------------------

_RE_DIGEST_RESP = re.compile(r'(response=")[0-9a-fA-F]+(")')
_RE_WSSE_PW = re.compile(r'(<(?:[\w.-]+:)?Password\b[^>]*>)[^<]*(</(?:[\w.-]+:)?Password>)', re.S)
_RE_URL_PW = re.compile(r'([?&](?:password|pwd|pass|passwd)=)[^&#]*', re.I)
_RE_RTSP_URL_CRED = re.compile(r'(rtsp://[^:/@\s]+:)[^@\s]+@')

_RE_FORM_PW = re.compile(
    r"(\b(?:password|passwd|pwd|pass|secret|token|api_?key|auth)=)[^&\s]*", re.I)
# cookie-ish session tokens anywhere (Set-Cookie, Cookie, bodies): name contains session/sessid/sid/token
_RE_SESSION_TOKEN = re.compile(r'([A-Za-z0-9_.-]*(?:session|sessid|sid|token)[A-Za-z0-9_.-]*=)[^;,&\s"]+', re.I)

REDACTED = "<redacted>"

#: body / JSON key 只要「包含」這些片段就遮掉（大小寫不敏感）。
#: 覆蓋 password / passwd / pwd / new_password / oldPassword / token /
#: access_token / apiKey / client_secret / privateKey ...
SECRET_KEY_PARTS = ("password", "passwd", "pwd", "secret", "token", "apikey",
                    "api_key", "credential", "privatekey", "private_key")


def _is_secret_key(key: str) -> bool:
    k = key.replace("-", "").replace("_", "").lower()
    return any(part.replace("_", "") in k for part in SECRET_KEY_PARTS)


def redact_json(obj):
    """遞迴遮掉 JSON 結構裡的密碼類欄位，其餘原樣保留。"""
    if isinstance(obj, dict):
        return {k: (REDACTED if _is_secret_key(str(k)) and obj[k] is not None
                    else redact_json(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_json(v) for v in obj]
    return obj


def redact_text(s: str) -> str:
    s = _RE_DIGEST_RESP.sub(r"\1" + REDACTED + r"\2", s)
    s = _RE_WSSE_PW.sub(r"\1" + REDACTED + r"\2", s)
    s = _RE_URL_PW.sub(r"\1" + REDACTED, s)
    s = _RE_RTSP_URL_CRED.sub(r"\1" + REDACTED + "@", s)
    # 整包 JSON body（REST 登入最常見的形狀）：
    #   {"username": "admin", "password": "admin"} -> password 變 <redacted>
    # 只在整串解得開、而且是 dict / list 的時候才動，否則走下面的 regex。
    stripped = s.strip()
    if stripped[:1] in ("{", "["):
        try:
            parsed = json.loads(stripped)
        except (ValueError, TypeError):
            pass
        else:
            if isinstance(parsed, (dict, list)):
                s = json.dumps(redact_json(parsed), ensure_ascii=False, separators=(",", ":"))
                return _RE_SESSION_TOKEN.sub(r"\1" + REDACTED, s)
    # form-urlencoded body / query string: password=xxx&user=yyy
    s = _RE_FORM_PW.sub(r"\1" + REDACTED, s)
    s = _RE_SESSION_TOKEN.sub(r"\1" + REDACTED, s)
    return s


def redact_event(e: Event) -> Event:
    d = e.to_dict()
    hdrs = dict(d["req_headers"])
    for k in list(hdrs):
        if k.lower() == "authorization":
            v = hdrs[k]
            if v.lower().startswith("basic "):
                hdrs[k] = "Basic " + REDACTED
            else:
                hdrs[k] = redact_text(v)
        elif k.lower() in ("cookie", "x-auth-token", "proxy-authorization"):
            hdrs[k] = REDACTED
    d["req_headers"] = hdrs
    rh = dict(d["resp_headers"])
    for k in list(rh):
        if k.lower() in ("set-cookie", "x-auth-token", "authorization"):
            rh[k] = REDACTED
    d["resp_headers"] = rh
    d["req_body"] = redact_text(d["req_body"])
    d["resp_body"] = redact_text(d["resp_body"])
    if d["url"]:
        d["url"] = redact_text(d["url"])
    return Event.from_dict(d)
