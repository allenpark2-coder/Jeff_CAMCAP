# 交接：在 Windows 上把 camcap 的 WinDivert 攔截段跑起來

> 給 Windows 端 Claude Code 的任務單。Linux 端（VirtualBox VM）已把其餘部分驗證完，
> 只剩這一段沒在實機跑過。請以**繁體中文**回報，技術名詞保留英文。

## 背景（30 秒版）

camcap 是一個「輸入 camera IP → 攔截本機所有送往該 IP 的 CGI/ONVIF/RTSP 指令 → 記錄 → 重播」的工具。
設計：WinDivert（pydivert）把送往 camera 的封包改 dst 到本機的透明 TCP relay，relay 原樣轉送並把 bytes 複製給解碼器。
細節見 `docs/design/camera-command-interceptor-proposal.md` §3.1，Windows 段的程式在 `camcap/redirector.py`，
啟動流程在 `camcap/capture.py`。

已驗證（不用再測）：
- 8 個單元測試在這台 Windows 上全過（fake camera + relay + 解碼 + 重播）。
- Linux 上用 iptables REDIRECT 取代 WinDivert，對真板 `10.253.58.186` 攔截 Web API 與 RTSP、重播全部正確。
  所以 relay / decoders / replay 不是嫌疑犯，**問題只會在 `redirector.py` 與 pydivert 的互動**。

## 目前卡住的點

以系統管理員執行：

```powershell
cd $env:USERPROFILE\camcap
.\.venv\Scripts\Activate.ps1
camcap capture 10.253.58.186 --out first.jsonl
```

輸出：

```
[camcap] intercepting 10.253.58.186 via 10.253.58.14:10222
[err] WinDivert failed: [WinError 87] 參數錯誤。
```

`WinDivertOpen` 回 ERROR_INVALID_PARAMETER。依 WinDivert 2.2 文件，這代表 filter 字串、layer、priority 或 flags 其中之一無效。
當時送進去的 filter 是 `Redirector.filter` 產生的：

```
outbound and ip and tcp and ((ip.DstAddr == 10.253.58.186 and not (tcp.SrcPort >= 40000 and tcp.SrcPort < 41000)) or (ip.SrcAddr == 10.253.58.14 and tcp.SrcPort == 10222))
```

## 假設（依可能性排序）

1. **filter 語法**：`not (...)` 或 `>=` / `<` 在這版 WinDivert 不被接受，或 pydivert 3.x 在開 handle 前另有檢查。
   可改寫成等價的 `!(...)`、或拆成 `tcp.SrcPort < 40000 or tcp.SrcPort > 40999`。
2. **pydivert 3.x API 與程式假設不同**：`redirector.py` 是照 pydivert 2.x 的介面寫的
   （`pydivert.WinDivert(filter)`、`for pkt in w`、`w.send(pkt)`、`pkt.src_addr/dst_addr/src_port/dst_port` 可寫、
   `pydivert.Flag.SNIFF`）。3.1.3 綑 WinDivert 2.2.2，建構子簽名或 enum 名可能變了。**先讀 `.venv\Lib\site-packages\pydivert\` 的原始碼**，
   不要猜。
3. driver 載入問題通常是別的錯誤碼（5 拒絕存取、1275 driver blocked），87 比較不像；但若 1、2 都排除，檢查 `WinDivert64.sys` 是否隨 wheel 裝到位。

## 建議步驟

1. 讀 `.venv\Lib\site-packages\pydivert\windivert.py`、`packet.py`、`consts.py`（或對應檔），對照 `camcap/redirector.py` 逐一確認：
   建構子參數、iteration、`send`、Packet 屬性 setter、Flag/Layer enum。
2. 用最小腳本逐步縮小 filter（在**系統管理員** PowerShell）：
   ```python
   import pydivert
   for f in ["true", "outbound and tcp", "ip.DstAddr == 10.253.58.186",
             "tcp.SrcPort >= 40000", "not (tcp.SrcPort >= 40000 and tcp.SrcPort < 41000)",
             "!(tcp.SrcPort >= 40000 and tcp.SrcPort < 41000)", "<完整 filter>"]:
       try:
           with pydivert.WinDivert(f, flags=pydivert.Flag.SNIFF): print("OK  ", f)
       except Exception as e: print("FAIL", f, e)
   ```
   （用 SNIFF 是為了不真的攔下封包。）若 pydivert 有 `check_filter` 類的 helper 就用它拿錯誤位置。
3. 修 `camcap/redirector.py`（filter 字串或 API 對接）。`WsDiscoverySniffer` 的 `Flag.SNIFF` 也一併對齊。
4. 重跑 `camcap capture 10.253.58.186 --out first.jsonl`，在瀏覽器直接開 `http://10.253.58.186/` 登入（admin / admin）點兩頁。
   成功判準：終端逐筆出現 `cgi GET http://10.253.58.186/api/v1/... 401/200`，Ctrl-C 後 `first.jsonl` 有內容。
5. 若 filter 過了但**瀏覽器連不上或轉圈**，嫌疑改為第二條改寫規則（relay → client 的回程把 src 改回 camera:port）或
   「注入到網卡 IP」這件事本身；請記錄 `status()` 裡的 `redirected` 計數、`ss`/`netstat -ano | findstr 10222`，以及瀏覽器的錯誤。
   參考：mitmproxy 舊版 `mitmproxy/platform/windows.py` 的做法（GitHub 上可查），它是同樣的兩條規則。
6. 過了之後跑 `camcap`（UI）與 `.\tools\build.ps1`，各自記錄結果。

## 規則

- 對板子 `10.253.58.186` **只讀**：瀏覽 Web UI、GET API 可以；不要改設定、不要 OTA、不要重開。
- 改動限縮在 `camcap/redirector.py`、`camcap/capture.py`、必要時 `camcap/app.py`；relay/decoders/replay 已驗證，非必要不動。
- 每次改完跑 `python -m pytest -q`，必須維持 8 個全過。
- 這份 tree 是從共享資料夾 robocopy 過來的、**不是 git repo**。改完把有變動的檔案複製回 `D:\SharedFolder\camcap\`（同路徑覆蓋），
  Linux 端會把它們接回 git。
- 結束時把過程與結論寫到 `D:\SharedFolder\camcap\docs\windows-debug-log.md`：實際錯因、改了哪些檔案與為什麼、每一步的終端輸出摘要、
  還沒解的問題。Linux 端會讀這個檔接手。
