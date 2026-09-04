"""A deliberately strict fake IP camera for tests.

* /cgi-bin/*            HTTP Digest (RFC 2617, qop=auth, MD5). Every nonce is
                        single-use → byte-for-byte replay gets 401 again.
* /cgi-bin/snapshot.cgi returns a fake JPEG (binary body path).
* /onvif/device_service SOAP. GetSystemDateAndTime needs no auth and reports
                        the camera clock (server clock + `clock_skew`).
                        Everything else needs a WS-UsernameToken whose Created
                        is within ±300 s of the CAMERA clock and whose nonce has
                        never been seen → replayed tokens get a NotAuthorized
                        fault (HTTP 400, as ONVIF specifies).
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 60 + b"\xff\xd9"


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _parse_kv(s: str) -> dict:
    out = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^,\s]*))', s):
        out[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


class FakeCamera:
    def __init__(self, username="admin", password="secret", clock_skew: float = 0.0):
        self.username, self.password = username, password
        self.clock_skew = clock_skew
        self.realm = "FakeCam"
        self.live_nonces: set[str] = set()
        self.used_nonces: set[str] = set()
        self.used_wsse_nonces: set[str] = set()
        self.requests: list[tuple] = []
        self._lock = threading.Lock()
        cam = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # silence
                pass

            def _send(self, code, body: bytes, ctype="text/plain", extra=None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _challenge(self, stale=False):
                nonce = base64.b64encode(os.urandom(12)).decode()
                with cam._lock:
                    cam.live_nonces.add(nonce)
                hdr = f'Digest realm="{cam.realm}", qop="auth", nonce="{nonce}", algorithm=MD5'
                if stale:
                    hdr += ", stale=true"
                self._send(401, b"Unauthorized", extra={"WWW-Authenticate": hdr})

            def _digest_ok(self) -> bool:
                a = self.headers.get("Authorization", "")
                if not a.lower().startswith("digest "):
                    return False
                kv = _parse_kv(a[7:])
                nonce = kv.get("nonce", "")
                with cam._lock:
                    if nonce in cam.used_nonces or nonce not in cam.live_nonces:
                        return False
                ha1 = _md5(f"{kv.get('username')}:{cam.realm}:{cam.password}")
                ha2 = _md5(f"{self.command}:{kv.get('uri')}")
                if kv.get("qop"):
                    exp = _md5(f"{ha1}:{nonce}:{kv.get('nc')}:{kv.get('cnonce')}:{kv.get('qop')}:{ha2}")
                else:
                    exp = _md5(f"{ha1}:{nonce}:{ha2}")
                ok = exp == kv.get("response") and kv.get("username") == cam.username
                if ok:
                    with cam._lock:
                        cam.used_nonces.add(nonce)  # single-use → replay protection
                return ok

            def do_GET(self):
                cam.requests.append(("GET", self.path, None))
                if self.path.startswith("/cgi-bin/"):
                    if not self._digest_ok():
                        return self._challenge()
                    if self.path.startswith("/cgi-bin/snapshot.cgi"):
                        return self._send(200, FAKE_JPEG, "image/jpeg")
                    return self._send(200, b"OK\r\n")
                return self._send(404, b"not found")

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(n).decode("utf-8", "replace")
                if self.path.startswith("/onvif/"):
                    return self._onvif(body)
                if self.path.startswith("/cgi-bin/"):
                    cam.requests.append(("POST", self.path, None))
                    if not self._digest_ok():
                        return self._challenge()
                    return self._send(200, b"OK\r\n")
                return self._send(404, b"not found")

            # -- onvif ----------------------------------------------------------
            def _onvif(self, body: str):
                m = re.search(r"<(?:[\w.-]+:)?Body\b[^>]*>\s*<(?:([\w.-]+):)?([\w.-]+)", body, re.S)
                action = m.group(2) if m else "?"
                cam.requests.append(("POST", self.path, action))
                cam_now = datetime.now(timezone.utc) + timedelta(seconds=cam.clock_skew)
                if action == "GetSystemDateAndTime":
                    return self._soap(200, f"""<tds:GetSystemDateAndTimeResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tds:SystemDateAndTime><tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings><tt:UTCDateTime><tt:Time><tt:Hour>{cam_now.hour}</tt:Hour><tt:Minute>{cam_now.minute}</tt:Minute><tt:Second>{cam_now.second}</tt:Second></tt:Time><tt:Date><tt:Year>{cam_now.year}</tt:Year><tt:Month>{cam_now.month}</tt:Month><tt:Day>{cam_now.day}</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>""")
                if not self._wsse_ok(body, cam_now):
                    return self._soap(400, '<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value xmlns:ter="http://www.onvif.org/ver10/error">ter:NotAuthorized</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="en">Sender not Authorized</s:Text></s:Reason></s:Fault>')
                if action == "GetDeviceInformation":
                    return self._soap(200, '<tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Manufacturer>FakeCam</tds:Manufacturer><tds:Model>T-1000</tds:Model><tds:FirmwareVersion>1.0</tds:FirmwareVersion><tds:SerialNumber>0001</tds:SerialNumber><tds:HardwareId>hw</tds:HardwareId></tds:GetDeviceInformationResponse>')
                return self._soap(200, f'<x:{action}Response xmlns:x="urn:fake"/>')

            def _wsse_ok(self, body: str, cam_now: datetime) -> bool:
                def grab(tag):
                    mm = re.search(rf"<(?:[\w.-]+:)?{tag}\b[^>]*>([^<]*)<", body)
                    return mm.group(1).strip() if mm else None
                user, pw, nonce, created = grab("Username"), grab("Password"), grab("Nonce"), grab("Created")
                if not all([user, pw, nonce, created]) or user != cam.username:
                    return False
                try:
                    c = datetime.strptime(created.replace("Z", "+0000").split(".")[0] + "+0000" if "." in created else created.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z")
                except ValueError:
                    return False
                if abs((cam_now - c).total_seconds()) > 300:
                    return False
                with cam._lock:
                    if nonce in cam.used_wsse_nonces:
                        return False
                exp = base64.b64encode(hashlib.sha1(base64.b64decode(nonce) + created.encode() + cam.password.encode()).digest()).decode()
                if exp != pw:
                    return False
                with cam._lock:
                    cam.used_wsse_nonces.add(nonce)
                return True

            def _soap(self, code: int, inner: str):
                env = f'<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>{inner}</s:Body></s:Envelope>'
                self._send(code, env.encode(), "application/soap+xml; charset=utf-8")

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self._srv.daemon_threads = True
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._srv.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "FakeCamera":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
