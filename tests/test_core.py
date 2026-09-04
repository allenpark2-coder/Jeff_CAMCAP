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
from camcap.model import LogStore, redact_event
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
