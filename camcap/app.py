"""pywebview desktop UI. The HTML lives in ui/index.html and talks to `Api`
through `window.pywebview.api.*`. Everything heavy runs in threads so the
webview stays responsive.
"""
from __future__ import annotations

import os
import sys
import threading
from datetime import datetime
from typing import Optional

from .capture import CaptureSession
from .model import LogStore
from .replay import ReplayOptions, Replayer

UI_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui", "index.html")


class Api:
    def __init__(self) -> None:
        self.store = LogStore()
        self.session: Optional[CaptureSession] = None
        self.replayer: Optional[Replayer] = None
        self._replay_thread: Optional[threading.Thread] = None
        self._replay_done = False
        self.window = None  # set by run_ui

    # -- capture -------------------------------------------------------------
    def start(self, ip: str, test_mode: bool = False, test_port: int = 80) -> dict:
        if self.session:
            return {"ok": False, "error": "already running"}
        try:
            self.session = CaptureSession(ip.strip(), self.store, test_mode=bool(test_mode), test_port=int(test_port or 80))
            self.session.start()
        except Exception as e:  # noqa: BLE001
            self.session = None
            return {"ok": False, "error": str(e)}
        return {"ok": True, "status": self.session.status()}

    def stop(self) -> dict:
        if self.session:
            self.session.stop()
            self.session = None
        return {"ok": True}

    def clear(self) -> dict:
        self.store.clear()
        return {"ok": True}

    def status(self) -> dict:
        if self.session:
            return self.session.status()
        return {"mode": "idle", "events": len(self.store), "errors": []}

    def poll(self, last_id: int = 0) -> list:
        # return new events AND re-send events whose response arrived later
        out = []
        for e in self.store.all():
            d = e.to_dict()
            d["label"] = e.summary()
            d["iso_ts"] = e.iso_ts
            out.append(d)
        return [d for d in out if d["id"] > int(last_id)] if last_id else out

    def all_events(self) -> list:
        return self.poll(0)

    # -- download ------------------------------------------------------------
    def download(self, fmt: str = "jsonl", redact: bool = True) -> dict:
        import webview
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        cam = (self.session.cam_ip if self.session else "camera").replace(":", "_")
        name = f"camcap-{cam}-{stamp}.{fmt}"
        path = self.window.create_file_dialog(webview.SAVE_DIALOG, save_filename=name) if self.window else None
        if isinstance(path, (list, tuple)):
            path = path[0] if path else None
        if not path:
            return {"ok": False, "error": "cancelled"}
        data = self.store.to_har(redact=redact) if fmt == "har" else self.store.to_jsonl(redact=redact)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        return {"ok": True, "path": path, "events": len(self.store)}

    def load(self) -> dict:
        import webview
        path = self.window.create_file_dialog(webview.OPEN_DIALOG, file_types=("JSONL log (*.jsonl)", "All files (*.*)"))
        if isinstance(path, (list, tuple)):
            path = path[0] if path else None
        if not path:
            return {"ok": False, "error": "cancelled"}
        with open(path, encoding="utf-8") as f:
            self.store = LogStore.from_jsonl(f.read())
        return {"ok": True, "events": len(self.store)}

    # -- replay --------------------------------------------------------------
    def replay(self, opts: dict) -> dict:
        if self._replay_thread and self._replay_thread.is_alive():
            return {"ok": False, "error": "replay already running"}
        ro = ReplayOptions(
            target_ip=(opts.get("target_ip") or None),
            username=(opts.get("username") or None),
            password=(opts.get("password") or None),
            speed=float(opts.get("speed", 1.0)),
            auth_mode=opts.get("auth_mode", "auto"),
            stop_on_error=bool(opts.get("stop_on_error", False)),
        )
        pm = opts.get("port_map") or ""
        for kv in filter(None, pm.split(",")):
            k, v = kv.split(":")
            ro.port_map[int(k)] = int(v)
        ids = set(opts.get("event_ids") or [])
        events = [e for e in self.store.all() if not ids or e.id in ids]
        self.replayer = Replayer(events, ro)
        self._replay_done = False

        def run():
            try:
                for _ in self.replayer.run():
                    pass
            finally:
                self._replay_done = True

        self._replay_thread = threading.Thread(target=run, name="camcap-replay", daemon=True)
        self._replay_thread.start()
        return {"ok": True, "total": len(events)}

    def replay_poll(self) -> dict:
        if not self.replayer:
            return {"running": False, "results": []}
        return {
            "running": not self._replay_done,
            "total": len(self.replayer.events),
            "results": [r.__dict__ for r in self.replayer.results],
        }

    def replay_cancel(self) -> dict:
        if self.replayer:
            self.replayer.cancel.set()
        return {"ok": True}


def run_ui() -> int:
    try:
        import webview
    except ImportError:
        print("pywebview is not installed. Install with: pip install camcap[windows]", file=sys.stderr)
        return 2
    api = Api()
    api.window = webview.create_window("camcap — camera command interceptor", UI_HTML, js_api=api,
                                       width=1200, height=800, min_size=(900, 600))
    webview.start(debug="--debug" in sys.argv)
    api.stop()
    return 0
