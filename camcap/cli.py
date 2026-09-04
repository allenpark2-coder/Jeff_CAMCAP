"""Command line entry point.

  camcap                          launch the UI (pywebview)
  camcap capture IP [--test-mode] headless capture, prints events as they come
  camcap replay LOG.jsonl [--target IP] [--user U --password P] [--speed N]
"""
from __future__ import annotations

import argparse
import signal
import sys
import time

from .model import LogStore
from .replay import ReplayOptions, Replayer


def _cmd_capture(a) -> int:
    from .capture import CaptureSession
    store = LogStore()
    sess = CaptureSession(a.ip, store, relay_port=a.relay_port, test_mode=a.test_mode, test_port=a.test_port,
                          external_rules=a.external_rules)
    try:
        sess.start()
    except RuntimeError as e:
        print(f"[camcap] {e}", file=sys.stderr, flush=True)
        return 2

    def _term(*_):  # SIGTERM from a supervising script → same clean shutdown as Ctrl-C
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _term)
    print(f"[camcap] {sess.mode}", file=sys.stderr, flush=True)
    if a.test_mode:
        print(f"[camcap] point your client at http://<this-pc>:{sess.relay_port}/ ; Ctrl-C to stop", file=sys.stderr, flush=True)
    last = 0
    try:
        while True:
            for ev in store.since(last):
                last = ev.id
                print(f"{ev.iso_ts}  {ev.proto:5s} {ev.method or '':6s} {ev.summary():60s} {ev.resp_status or ''}", flush=True)
            for err in sess.errors:
                print(f"[err] {err}", file=sys.stderr, flush=True)
            sess.errors.clear()
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        sess.stop()
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(store.to_jsonl(redact=a.redact))
            print(f"[camcap] wrote {len(store)} events to {a.out}", file=sys.stderr)
    return 0


def _cmd_replay(a) -> int:
    with open(a.log, encoding="utf-8") as f:
        store = LogStore.from_jsonl(f.read())
    opts = ReplayOptions(target_ip=a.target, username=a.user, password=a.password, speed=a.speed,
                         auth_mode=a.auth, stop_on_error=a.stop_on_error)
    if a.port_map:
        for kv in a.port_map.split(","):
            k, v = kv.split(":")
            opts.port_map[int(k)] = int(v)
    rp = Replayer(store.all(), opts)
    bad = 0
    for r in rp.run():
        flag = "skip" if r.skipped else ("ok  " if r.ok else "FAIL")
        bad += (not r.ok and not r.skipped)
        print(f"{flag} #{r.event_id:<4} {r.label:60s} {r.orig_status or '-':>4} -> {r.status or '-':<4} "
              f"{r.auth_used:12s} {r.elapsed_ms:7.1f}ms {r.error}")
    print(f"[camcap] {len(rp.results)} replayed, {bad} mismatched", file=sys.stderr)
    return 1 if bad else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="camcap", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    c = sub.add_parser("capture", help="headless capture")
    c.add_argument("ip")
    c.add_argument("--relay-port", type=int, default=0)
    c.add_argument("--test-mode", action="store_true", help="no WinDivert; relay only")
    c.add_argument("--test-port", type=int, default=80, help="camera port used in test mode")
    c.add_argument("--external-rules", action="store_true",
                   help="Linux: iptables REDIRECT rules are applied by hand; just run the relay")
    c.add_argument("--out", help="write JSONL log on exit")
    c.add_argument("--redact", action="store_true")
    c.set_defaults(fn=_cmd_capture)
    r = sub.add_parser("replay", help="replay a JSONL log")
    r.add_argument("log")
    r.add_argument("--target", help="replay to this IP instead of the captured one")
    r.add_argument("--port-map", help="orig:new[,orig:new] e.g. 80:8080")
    r.add_argument("--user")
    r.add_argument("--password")
    r.add_argument("--speed", type=float, default=1.0, help="1=original timing, 0=max speed")
    r.add_argument("--auth", choices=["auto", "raw", "reauth"], default="auto")
    r.add_argument("--stop-on-error", action="store_true")
    r.set_defaults(fn=_cmd_replay)
    a = p.parse_args(argv)
    if a.cmd is None:
        from .app import run_ui
        return run_ui()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
