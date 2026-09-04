"""End-to-end on Linux: fake camera ← relay(tee → decoders) ← real clients,
then replay the captured log (same target, other target, skewed clock)."""
from __future__ import annotations

import socket
import time

import pytest
import requests
from requests.auth import HTTPDigestAuth

from camcap import wsse
from camcap.capture import CaptureSession
from camcap.model import LogStore, redact_event, redact_text
from camcap.replay import ReplayOptions, Replayer

from fake_camera import FakeCamera

ONVIF_GETINFO = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Header>{sec}</s:Header>'
    '<s:Body><tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/></s:Body>'
    '</s:Envelope>'
)


@pytest.fixture
def cam():
    c = FakeCamera().start()
    yield c
    c.stop()


@pytest.fixture
def capture(cam):
    store = LogStore()
    sess = CaptureSession("127.0.0.1", store, test_mode=True, test_port=cam.port)
    sess.start()
    yield sess, store, f"http://127.0.0.1:{sess.relay_port}"
    sess.stop()


def _wait(store, n, timeout=5.0):
    t = time.time()
    while time.time() - t < timeout:
        evs = store.all()
        if len(evs) >= n and all(e.resp_status is not None or e.proto == "raw" for e in evs):
            return evs
        time.sleep(0.02)
    return store.all()


def _drive_clients(relay_url: str, cam: FakeCamera):
    """Simulate a vendor tool + an ONVIF client talking through the relay."""
    # CGI with digest: 401 then 200 on the same keep-alive connection
    r = requests.get(relay_url + "/cgi-bin/ptz.cgi?action=start&code=Up", auth=HTTPDigestAuth("admin", "secret"))
    assert r.status_code == 200
    # binary body
    r = requests.get(relay_url + "/cgi-bin/snapshot.cgi", auth=HTTPDigestAuth("admin", "secret"))
    assert r.headers["content-type"] == "image/jpeg"
    # ONVIF with WSSE
    body = ONVIF_GETINFO.format(sec=wsse.security_header("admin", "secret"))
    r = requests.post(relay_url + "/onvif/device_service", data=body.encode(),
                      headers={"Content-Type": "application/soap+xml; charset=utf-8"})
    assert r.status_code == 200 and "FakeCam" in r.text
    # something that is not HTTP at all (vendor SDK-ish)
    s = socket.create_connection(("127.0.0.1", int(relay_url.rsplit(":", 1)[1])))
    s.sendall(b"\x00\x00\x00\x10\x01\x02\x03\x04HELLO-SDK")
    time.sleep(0.2)
    s.close()


def test_capture_decodes_cgi_onvif_and_raw(capture, cam):
    sess, store, relay_url = capture
    _drive_clients(relay_url, cam)
    evs = _wait(store, 6)
    by = {}
    for e in evs:
        by.setdefault(e.proto, []).append(e)
    cgi = by["cgi"]
    assert [e.resp_status for e in cgi] == [401, 200, 401, 200]
    assert cgi[0].auth == "none" and cgi[1].auth == "digest"
    assert cgi[1].url.endswith("/cgi-bin/ptz.cgi?action=start&code=Up")
    assert cgi[1].vendor == "dahua/amcrest/generic"
    assert cgi[3].resp_body.startswith("<") and "binary image/jpeg" in cgi[3].resp_body
    assert cgi[1].latency_ms is not None and cgi[1].latency_ms >= 0
    onv = by["onvif"]
    assert len(onv) == 1 and onv[0].soap_action == "GetDeviceInformation" and onv[0].auth == "wsse-digest"
    assert onv[0].resp_status == 200 and "FakeCam" in onv[0].resp_body
    raw = by["raw"]
    assert len(raw) == 1 and raw[0].bytes_c2s == 17 and "non-HTTP" in raw[0].note
    # keep-alive: the two CGI requests of one connection share a stream id
    assert cgi[0].stream == cgi[1].stream
    assert sess.status()["events"] == len(evs)


def test_jsonl_har_roundtrip_and_redaction(capture, cam):
    sess, store, relay_url = capture
    _drive_clients(relay_url, cam)
    evs = _wait(store, 6)
    text = store.to_jsonl()
    back = LogStore.from_jsonl(text)
    assert [e.id for e in back.all()] == [e.id for e in evs]
    assert back.all()[1].req_headers["authorization"].startswith("Digest ")
    har = store.to_har(redact=True)
    assert '"version": "1.2"' in har and "GetDeviceInformation" in har and "snapshot.cgi" in har
    # redaction
    red = redact_event(evs[1])
    assert 'response="<redacted>"' in red.req_headers["authorization"]
    red_onvif = redact_event([e for e in evs if e.proto == "onvif"][0])
    assert "<redacted></wsse:Password>" in red_onvif.req_body
    assert "PasswordDigest" in red_onvif.req_body  # structure preserved


def test_replay_same_camera_reauths_when_nonces_are_single_use(capture, cam):
    sess, store, relay_url = capture
    _drive_clients(relay_url, cam)
    evs = _wait(store, 6)
    # replay straight at the fake camera (bypassing the relay)
    opts = ReplayOptions(target_ip="127.0.0.1", port_map={sess.relay_port: cam.port},
                         username="admin", password="secret", speed=0)
    results = list(Replayer(evs, opts).run())
    http = [r for r in results if not r.skipped]
    assert len(http) == 5 and all(r.ok for r in http), [(r.label, r.orig_status, r.status, r.error) for r in http]
    # the 401s replay as 401 via raw; the authenticated ones had to be re-signed
    assert [r.auth_used for r in http] == ["raw", "digest", "raw", "digest", "wsse+digest"]
    raw = [r for r in results if r.skipped]
    assert len(raw) == 1 and "raw" in raw[0].error


def test_replay_raw_only_fails_on_replay_protected_camera(capture, cam):
    sess, store, relay_url = capture
    _drive_clients(relay_url, cam)
    evs = _wait(store, 6)
    opts = ReplayOptions(target_ip="127.0.0.1", port_map={sess.relay_port: cam.port}, speed=0, auth_mode="raw")
    results = [r for r in Replayer(evs, opts).run() if not r.skipped]
    # unauthenticated requests still match (401 == 401); authenticated ones don't
    assert [r.ok for r in results] == [True, False, True, False, False]


def test_replay_to_other_camera_with_skewed_clock(capture, cam):
    sess, store, relay_url = capture
    _drive_clients(relay_url, cam)
    evs = _wait(store, 6)
    other = FakeCamera(clock_skew=+900).start()  # 15 min ahead → naive Created is rejected
    try:
        opts = ReplayOptions(target_ip="127.0.0.1", port_map={sess.relay_port: other.port},
                             username="admin", password="secret", speed=0)
        rp = Replayer(evs, opts)
        results = [r for r in rp.run() if not r.skipped]
        assert all(r.ok for r in results), [(r.label, r.status, r.error) for r in results]
        assert 880 < rp._clock_offset < 920
        assert any(a == "GetDeviceInformation" for _, _, a in other.requests)
    finally:
        other.stop()


def test_wsse_resign_preserves_envelope_and_verifies():
    body = ONVIF_GETINFO.format(sec=wsse.security_header("admin", "old"))
    new = wsse.resign(body, "admin", "secret")
    assert new.count("<wsse:Security") == 1 and "GetDeviceInformation" in new
    # without a Header element a Header is created
    no_hdr = ONVIF_GETINFO.format(sec="").replace("<s:Header></s:Header>", "")
    new2 = wsse.resign(no_hdr, "admin", "secret")
    assert "<s:Header><wsse:Security" in new2
    # digest formula against a hand-computed vector
    import base64, hashlib
    nonce = base64.b64encode(b"0123456789abcdef").decode()
    created = "2026-09-04T00:00:00.000Z"
    exp = base64.b64encode(hashlib.sha1(b"0123456789abcdef" + created.encode() + b"pw").digest()).decode()
    assert wsse.password_digest(nonce, created, "pw") == exp


def test_replay_timing_respects_speed(cam):
    store = LogStore.from_jsonl(
        '{"id":1,"ts":100.0,"stream":1,"proto":"cgi","dst_ip":"127.0.0.1","dst_port":%d,"src_port":1,"method":"GET","url":"http://127.0.0.1:%d/nope","resp_status":404}\n'
        '{"id":2,"ts":100.6,"stream":1,"proto":"cgi","dst_ip":"127.0.0.1","dst_port":%d,"src_port":1,"method":"GET","url":"http://127.0.0.1:%d/nope","resp_status":404}\n'
        % (cam.port, cam.port, cam.port, cam.port))
    t = time.perf_counter()
    res = list(Replayer(store.all(), ReplayOptions(speed=2.0)).run())
    dt = time.perf_counter() - t
    assert all(r.ok for r in res) and 0.25 < dt < 1.0


def test_jsonl_roundtrip_survives_unicode_line_separators():
    """str.splitlines() also splits on U+2028/U+0085 which appear in real HTML/SDP bodies."""
    from camcap.model import Event
    st = LogStore()
    e = Event(id=1, ts=1.0, stream=1, proto="cgi", dst_ip="1.2.3.4", dst_port=80, src_port=5,
              method="GET", url="http://1.2.3.4/", resp_status=200, resp_body="a\u2028b\x85c\x1ed")
    st.add(e)
    back = LogStore.from_jsonl(st.to_jsonl())
    assert len(back) == 1 and back.all()[0].resp_body == e.resp_body


def test_windivert_filter_avoids_unsupported_not_over_parens():
    """WinDivert 的 filter 語言只允許 `not` 套在單一 test 上，不能套在括號子
    運算式；`not (a and b)` 會讓 WinDivertOpen 回 ERROR_INVALID_PARAMETER (87)。
    這條測試釘住 De Morgan 展開後的形式，避免回歸。"""
    from camcap.redirector import Redirector

    r = Redirector("10.253.58.186", "10.253.58.14", 10222, None, (40000, 41000))
    flt = r.filter
    assert "not" not in flt
    assert "!" not in flt
    assert "tcp.SrcPort < 40000 or tcp.SrcPort >= 41000" in flt
    assert "ip.DstAddr == 10.253.58.186" in flt
    assert "ip.SrcAddr == 10.253.58.14 and tcp.SrcPort == 10222" in flt


def test_redaction_covers_json_and_form_login_bodies():
    """CV75 devkit 的 Web UI 走 `POST /api/v1/auth/login` + cookie session，
    密碼在 JSON body 裡；舊版 redact_text 只認 Digest / WSSE / URL，會把明文密碼
    留在 --redact 之後的輸出裡（DQA 會到處貼 log）。"""
    from camcap.model import redact_text

    j = redact_text('{"username":"admin","password":"admin"}')
    assert '"password":"<redacted>"' in j
    assert '"username":"admin"' in j  # 帳號留著，不然 log 沒有辨識度

    nested = redact_text(
        '{"a":{"newPassword":"NEWPW1","apiKey":"KEY2"},"list":[{"token":"TOK3"}]}')
    for leaked in ("NEWPW1", "KEY2", "TOK3"):
        assert leaked not in nested, leaked
    assert nested.count("<redacted>") == 3

    form = redact_text("user=admin&password=hunter2&remember=1")
    assert "hunter2" not in form and "user=admin" in form and "remember=1" in form

    # 不是 JSON 的東西不能被吃掉
    assert redact_text("plain body, no creds") == "plain body, no creds"
    assert redact_text("") == ""


def test_redaction_still_covers_digest_wsse_and_rtsp_url():
    from camcap.model import redact_text

    assert 'response="<redacted>"' in redact_text('Digest username="a", response="deadbeef01"')
    assert "<redacted></wsse:Password>" in redact_text("<wsse:Password Type='x'>secret</wsse:Password>")
    assert redact_text("rtsp://admin:hunter2@10.0.0.1/live") == "rtsp://admin:<redacted>@10.0.0.1/live"


def test_redaction_covers_cookies_and_response_headers():
    """Merged from the Linux-side fix: Cookie / Set-Cookie / session tokens must go too."""
    from camcap.model import Event
    e = Event(id=1, ts=1.0, stream=1, proto="cgi", dst_ip="1.2.3.4", dst_port=80, src_port=5,
              method="POST", url="http://1.2.3.4/api/v1/auth/login?password=x",
              req_headers={"cookie": "opsis_session=abc123; theme=dark"},
              req_body='{"username":"admin","password":"admin","remember":true}',
              resp_status=200,
              resp_headers={"set-cookie": "opsis_session=f78591ad00; Path=/; HttpOnly", "content-type": "application/json"},
              resp_body='{"status":"ok","token":"eyJhbGciOi","user":"admin"}')
    r = redact_event(e)
    assert r.req_headers["cookie"] == "<redacted>"
    assert r.resp_headers["set-cookie"] == "<redacted>" and r.resp_headers["content-type"] == "application/json"
    assert '"token":"<redacted>"' in r.resp_body and '"user":"admin"' in r.resp_body
    assert "password=<redacted>" in r.url
    assert redact_text("ok opsis_session=deadbeef; x=1") == "ok opsis_session=<redacted>; x=1"


def test_tls_client_hello_is_labelled_not_mistaken_for_vendor_protocol():
    """Windows debug-log open issue 9: HTTPS/RTSPS fell into `raw` with a
    'vendor SDK protocol?' note. Now it is tagged tls with version + SNI."""
    import ssl
    from camcap.decoders import StreamDecoder, tls_client_hello_sni
    # build a real ClientHello with SNI using the ssl module (no network)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inb, outb, server_side=False, server_hostname="cam.example.local")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outb.read()
    assert hello[:2] == b"\x16\x03"
    ver, sni = tls_client_hello_sni(hello)
    assert sni == "cam.example.local" and ver.startswith("TLS")
    st = LogStore()
    d = StreamDecoder(st, 1, "1.2.3.4", 443, 5)
    # feed in two fragments to exercise the "need more bytes" path
    d.feed_c2s(hello[:40])
    d.feed_c2s(hello[40:])
    d.feed_s2c(b"\x16\x03\x03\x00\x05hello")
    d.close()
    evs = st.all()
    assert len(evs) == 1 and evs[0].proto == "tls"
    assert "SNI=cam.example.local" in evs[0].note and "vendor" not in evs[0].note
    assert evs[0].url == "https://cam.example.local:443"
    assert evs[0].bytes_c2s == len(hello) and evs[0].bytes_s2c == 10


def test_replay_cookie_session_login_flow_even_from_redacted_log(capture, cam):
    """CV75 devkit Web UI: POST /api/v1/auth/login (JSON) → Set-Cookie → API calls with Cookie.
    A redacted log has "<redacted>" as password and a stale cookie; with --user/--password
    the replayer must log in again and carry the new cookie."""
    from camcap.replay import substitute_credentials
    sess, store, relay_url = capture
    s = requests.Session()
    r = s.post(relay_url + "/api/v1/auth/login", json={"username": "admin", "password": "secret"})
    assert r.status_code == 200 and "fc_session" in r.headers.get("set-cookie", "")
    assert s.get(relay_url + "/api/v1/auth/whoami").status_code == 200
    assert requests.get(relay_url + "/api/v1/auth/whoami").status_code == 401  # no cookie → 401
    evs = _wait(store, 3)
    assert [e.resp_status for e in evs] == [200, 200, 401]
    redacted = [redact_event(e) for e in evs]
    assert '"password":"<redacted>"' in redacted[0].req_body
    assert redacted[1].req_headers["cookie"] == "<redacted>"
    opts = ReplayOptions(target_ip="127.0.0.1", port_map={sess.relay_port: cam.port},
                         username="admin", password="secret", speed=0)
    res = list(Replayer(redacted, opts).run())
    assert [(r.orig_status, r.status, r.ok) for r in res] == [(200, 200, True), (200, 200, True), (401, 401, True)]
    # without credentials the redacted login fails and the stale cookie is rejected
    res2 = list(Replayer(redacted, ReplayOptions(target_ip="127.0.0.1", port_map={sess.relay_port: cam.port}, speed=0)).run())
    assert [r.ok for r in res2] == [False, False, True]
    assert substitute_credentials("user=x&password=y", "admin", "pw") == "user=admin&password=pw"
    assert substitute_credentials('{"a":1}', "admin", "pw") == '{"a":1}'
