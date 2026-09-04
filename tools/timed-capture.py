"""跑 `camcap capture` N 秒後自動送出 KeyboardInterrupt，讓 JSONL 正常寫出。

存在的理由：`camcap capture` 平常靠 Ctrl-C 收工，但在腳本裡按不了 Ctrl-C，
而 Stop-Process 會跳過 finally、log 就不會寫檔。`_thread.interrupt_main()`
在 Windows 上會讓主執行緒收到 KeyboardInterrupt，走的是跟 Ctrl-C 完全一樣的
收工路徑。

    python tools\\timed-capture.py <cam-ip> <seconds> <out.jsonl>
"""
from __future__ import annotations

import _thread
import sys
import threading
import time

from camcap.cli import main


def run() -> int:
    ip = sys.argv[1]
    secs = float(sys.argv[2])
    out = sys.argv[3]

    def killer() -> None:
        time.sleep(secs)
        print(f"[timed-capture] {secs:.0f}s 到，送出 KeyboardInterrupt", file=sys.stderr, flush=True)
        _thread.interrupt_main()

    threading.Thread(target=killer, daemon=True).start()
    return main(["capture", ip, "--out", out])


if __name__ == "__main__":
    raise SystemExit(run())
