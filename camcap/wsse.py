"""WS-Security UsernameToken (PasswordDigest) helpers for ONVIF replay.

    PasswordDigest = Base64( SHA-1( B64DECODE(Nonce) + Created + Password ) )
    (OASIS WSS UsernameToken Profile 1.1 §3.1; ONVIF Core §5.9.5 requires both
    Nonce and Created, and devices typically reject Created outside ±5 min.)

Because a captured token is bound to its nonce/created it cannot be replayed
against a compliant device; we strip the captured <Security> header and sign
the SOAP body again with the user's credentials. Everything else in the
envelope is preserved byte-for-byte (string surgery, no re-serialisation).
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
DIGEST_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
NONCE_ENC = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

_SECURITY = re.compile(
    r"<([\w.-]+:)Security\b[^>]*>.*?</\1Security\s*>|<Security\b[^>]*>.*?</Security\s*>", re.S)
_HEADER_OPEN = re.compile(r"<(?:[\w.-]+:)?Header\b[^>]*>")
_ENVELOPE_OPEN = re.compile(r"<(?:([\w.-]+):)?Envelope\b")
_BODY_OPEN = re.compile(r"<(?:[\w.-]+:)?Body\b")


def password_digest(nonce_b64: str, created: str, password: str) -> str:
    raw = base64.b64decode(nonce_b64) + created.encode("utf-8") + password.encode("utf-8")
    return base64.b64encode(hashlib.sha1(raw).digest()).decode("ascii")


def format_created(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def security_header(username: str, password: str, created: Optional[datetime] = None,
                    nonce: Optional[bytes] = None) -> str:
    created = created or datetime.now(timezone.utc)
    nonce = nonce or os.urandom(16)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    created_s = format_created(created)
    digest = password_digest(nonce_b64, created_s, password)
    return (
        f'<wsse:Security s:mustUnderstand="1" xmlns:wsse="{WSSE_NS}" xmlns:wsu="{WSU_NS}">'
        f'<wsse:UsernameToken><wsse:Username>{_esc(username)}</wsse:Username>'
        f'<wsse:Password Type="{DIGEST_TYPE}">{digest}</wsse:Password>'
        f'<wsse:Nonce EncodingType="{NONCE_ENC}">{nonce_b64}</wsse:Nonce>'
        f'<wsu:Created>{created_s}</wsu:Created>'
        f'</wsse:UsernameToken></wsse:Security>'
    )


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def strip_security(envelope: str) -> str:
    return _SECURITY.sub("", envelope, count=1)


def resign(envelope: str, username: str, password: str, clock_offset_s: float = 0.0) -> str:
    """Remove any existing <Security> header and insert a fresh UsernameToken.
    `clock_offset_s` = camera_clock - our_clock, so Created lands inside the
    camera's acceptance window even when its clock is wrong."""
    env = strip_security(envelope)
    created = datetime.now(timezone.utc) + timedelta(seconds=clock_offset_s)
    hdr = security_header(username, password, created)
    # the header we build uses prefix "s" for mustUnderstand; make sure it resolves
    m_env = _ENVELOPE_OPEN.search(env)
    env_prefix = (m_env.group(1) or "") if m_env else ""
    if env_prefix != "s":
        hdr = hdr.replace('s:mustUnderstand="1"',
                          f'{env_prefix + ":" if env_prefix else ""}mustUnderstand="1"')
    m = _HEADER_OPEN.search(env)
    if m:
        return env[:m.end()] + hdr + env[m.end():]
    m = _BODY_OPEN.search(env)
    if not m:
        raise ValueError("not a SOAP envelope (no Body)")
    tag = f"{env_prefix}:Header" if env_prefix else "Header"
    return env[:m.start()] + f"<{tag}>{hdr}</{tag}>" + env[m.start():]


GET_SYSTEM_DATE_AND_TIME = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Body><tds:GetSystemDateAndTime xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/></s:Body>'
    '</s:Envelope>'
)

_UTC = re.compile(
    r"<(?:[\w.-]+:)?UTCDateTime>.*?<(?:[\w.-]+:)?Time>.*?<(?:[\w.-]+:)?Hour>(\d+)</.*?<(?:[\w.-]+:)?Minute>(\d+)</.*?"
    r"<(?:[\w.-]+:)?Second>(\d+)</.*?<(?:[\w.-]+:)?Date>.*?<(?:[\w.-]+:)?Year>(\d+)</.*?<(?:[\w.-]+:)?Month>(\d+)</.*?"
    r"<(?:[\w.-]+:)?Day>(\d+)</", re.S)


def camera_clock_offset(device_service_url: str, timeout: float = 5.0,
                        session: Optional[requests.Session] = None) -> float:
    """Ask the camera for its UTC time via GetSystemDateAndTime (ONVIF: no auth
    required) and return camera_clock - local_clock in seconds. 0.0 on failure."""
    sess = session or requests.Session()
    try:
        t0 = datetime.now(timezone.utc)
        r = sess.post(device_service_url, data=GET_SYSTEM_DATE_AND_TIME.encode(),
                      headers={"Content-Type": "application/soap+xml; charset=utf-8"}, timeout=timeout)
        m = _UTC.search(r.text)
        if not m:
            return 0.0
        hh, mm, ss, yy, mo, dd = (int(x) for x in m.groups())
        cam = datetime(yy, mo, dd, hh, mm, ss, tzinfo=timezone.utc)
        return (cam - t0).total_seconds()
    except Exception:
        return 0.0
