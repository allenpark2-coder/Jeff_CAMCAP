"""WinDivert 診斷：把 [WinError 87] 攤開成「哪一段 filter、第幾個字元、錯在哪」。

用法（Windows，專案 venv 裡）：

    python tools\\diag-windivert.py                    # 只做 filter 語法檢查，不需 Administrator
    python tools\\diag-windivert.py --open             # 另外真的 WinDivertOpen（SNIFF），需 Administrator
    python tools\\diag-windivert.py --cam 10.253.58.186 --relay-port 10222

check_filter 走的是 WinDivertHelperCompileFilter，純 user-mode，不載 driver、不需權限；
--open 才會碰 driver，用 Flag.SNIFF 以免真的把封包攔下來。
"""
from __future__ import annotations

import argparse
import os
import platform
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cam", default="10.253.58.186")
    ap.add_argument("--relay-port", type=int, default=10222)
    ap.add_argument("--local-ip", default=None, help="預設用 route 到 --cam 的網卡 IP")
    ap.add_argument("--open", action="store_true", help="真的開 handle（SNIFF），需 Administrator")
    args = ap.parse_args()

    print(f"python      : {sys.version.split()[0]} {platform.architecture()[0]} ({sys.executable})")
    try:
        import pydivert
    except Exception as e:
        print(f"pydivert    : IMPORT FAILED: {e}")
        return 2
    print(f"pydivert    : {pydivert.__version__}")

    from pydivert import windivert_dll

    dll = windivert_dll.DLL_PATH
    sys_path = os.path.join(os.path.dirname(dll), "WinDivert64.sys")
    for label, path in (("WinDivert64.dll", dll), ("WinDivert64.sys", sys_path)):
        ok = os.path.exists(path)
        size = os.path.getsize(path) if ok else 0
        print(f"{label:<12}: {'OK ' if ok else 'MISSING '}{path} ({size} bytes)")

    from camcap.redirector import Redirector, local_ip_for

    local_ip = args.local_ip or local_ip_for(args.cam)
    print(f"local ip    : {local_ip}  (route to {args.cam})")

    lo, hi = 40000, 41000
    broken = (
        "outbound and ip and tcp and ("
        f"(ip.DstAddr == {args.cam} and not (tcp.SrcPort >= {lo} and tcp.SrcPort < {hi}))"
        f" or (ip.SrcAddr == {local_ip} and tcp.SrcPort == {args.relay_port})"
        ")"
    )
    current = Redirector(args.cam, local_ip, args.relay_port, None, (lo, hi)).filter
    wsd = "udp and (udp.DstPort == 3702 or udp.SrcPort == 3702)"

    ladder = [
        ("true", "true"),
        ("outbound and tcp", "outbound and tcp"),
        ("bare ip", "ip"),
        ("dst addr", f"ip.DstAddr == {args.cam}"),
        (">= only", f"tcp.SrcPort >= {lo}"),
        ("not <test>", f"not tcp.SrcPort >= {lo}"),
        ("not (a and b)  <-- 舊寫法的可疑點", f"not (tcp.SrcPort >= {lo} and tcp.SrcPort < {hi})"),
        ("!(a and b)", f"!(tcp.SrcPort >= {lo} and tcp.SrcPort < {hi})"),
        ("De Morgan 展開", f"tcp.SrcPort < {lo} or tcp.SrcPort >= {hi}"),
        ("WSD sniffer filter", wsd),
        ("OLD 完整 filter", broken),
        ("NEW 完整 filter", current),
    ]

    print("\n--- WinDivertHelperCompileFilter (no driver, no admin) ---")
    failures = 0
    blocking = 0  # 只有「NEW 完整 filter」/ WSD filter 掛掉才算真的壞掉
    for label, flt in ladder:
        ok, pos, msg = pydivert.WinDivert.check_filter(flt)
        if ok:
            print(f"[ OK ] {label}")
        else:
            failures += 1
            if flt in (current, wsd):
                blocking += 1
            pos = int(pos or 0)
            print(f"[FAIL] {label}: offset {pos}: {msg or 'syntax error'}")
            print(f"       {flt}")
            print(f"       {' ' * pos}^")

    if args.open:
        print("\n--- WinDivertOpen (SNIFF, 需 Administrator) ---")
        for label, flt in (("WSD sniffer filter", wsd), ("NEW 完整 filter", current)):
            try:
                with pydivert.WinDivert(flt, flags=pydivert.Flag.SNIFF):
                    print(f"[ OK ] open: {label}")
            except Exception as e:
                failures += 1
                blocking += 1
                print(f"[FAIL] open: {label}: {e!r}")

    print(f"\n{failures} failure(s) total, {blocking} of them on filters camcap actually uses.")
    print("（ladder 中間那幾條本來就是拿來確認語法邊界的，FAIL 是預期內的資訊。）")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
