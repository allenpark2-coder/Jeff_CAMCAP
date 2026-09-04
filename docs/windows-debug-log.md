# Windows 端 WinDivert 攔截 debug log

> 回覆 `docs/handoff-windows-debug.md`。日期 2026-09-04，機器 `desktop-o4nanbm`（Windows，
> Python 3.12.10 64-bit，pydivert 3.1.3 / WinDivert 2.2.2），板子 CV75 devkit `10.253.58.186`。
> 板子全程只讀：瀏覽 Web UI + GET，沒有改設定 / OTA / 重開。

## 結論

`WinError 87` 是**filter 字串語法錯誤**，不是 pydivert API、不是 driver。改掉 filter 之後
WinDivert 攔截整條打通：瀏覽器直連 `http://10.253.58.186/` 的流量 90 秒內抓到 **140 筆 event**，
全部正確解出 URL / status / headers，`first.jsonl` 正常寫出。

假設 1 命中，假設 2、3 排除。

## 根因

WinDivert 的 filter 語言裡，`not` **只能套在單一 test 上**，不能套在括號子運算式上。
`windivert_helper.c` 的 `WinDivertParseTest()` 吃掉 `TOKEN_NOT` 之後直接要求一個 field
（否定是靠反轉該 test 的比較運算子實作的）；括號是 `WinDivertParseAndOrArg()` 的 `TOKEN_OPEN`
分支在處理，兩條路不相通。所以

```
not (tcp.SrcPort >= 40000 and tcp.SrcPort < 41000)
```

是 parse error → `WinDivertHelperCompileFilter` 失敗 → `WinDivertOpen` 回
`ERROR_INVALID_PARAMETER (87)`。

WinDivert 自己給的證據（`tools\diag-windivert.py`，走
`WinDivertHelperCompileFilter`，純 user-mode、不載 driver、不需 Administrator）：

```
[ OK ] not <test>                       not tcp.SrcPort >= 40000
[FAIL] not (a and b): offset 4: Filter expression parse error
       not (tcp.SrcPort >= 40000 and tcp.SrcPort < 41000)
           ^
[FAIL] !(a and b): offset 1: Filter expression parse error
       !(tcp.SrcPort >= 40000 and tcp.SrcPort < 41000)
        ^
[ OK ] De Morgan 展開                    tcp.SrcPort < 40000 or tcp.SrcPort >= 41000
[FAIL] OLD 完整 filter: offset 66: Filter expression parse error
       outbound and ip and tcp and ((ip.DstAddr == 10.253.58.186 and not (tcp.SrcPort >= 40000 ...
                                                                         ^
[ OK ] NEW 完整 filter
```

`not <test>` 過、`not (` 掛在第 4 個字元 —— 所以不是「`not` 這個關鍵字不支援」，
是「`not` 後面不能接括號」。舊 filter 的錯誤位置 offset 66 正好指在 `not ` 後面那個左括號。

旁證：同時啟動的 `WsDiscoverySniffer`（filter 簡單、沒有 `not`）當初沒報錯，只有
`Redirector` 掛掉 —— 如果是 driver 載入問題兩個都會死。

### 假設 2（pydivert 3.x API 變了）排除

讀了 `.venv\Lib\site-packages\pydivert\` 的 `windivert.py`、`packet\__init__.py`、
`consts.py`、`windivert_dll\__init__.py`，`redirector.py` 照 2.x 寫的介面在 3.1.3 全部還在：

| 程式假設 | pydivert 3.1.3 實際 | 結果 |
|---|---|---|
| `pydivert.WinDivert(filter)` | `__init__(self, filter="true", layer=Layer.NETWORK, priority=0, flags=Flag.DEFAULT)` | 位置參數就是 filter，OK |
| `for pkt in w` | `__iter__` → `__next__` → `recv()` | OK |
| `w.send(pkt)` | `send(packet, recalculate_checksum=True)`，預設自動重算 checksum | OK |
| `pkt.src_addr / dst_addr / src_port / dst_port` 可寫 | 四個 property 都有 setter | OK |
| `pydivert.Flag.SNIFF` | `Flag.SNIFF = 1`（IntFlag） | OK |

### 假設 3（driver 沒載到）排除

`WinDivert64.dll` (47,616 B) 與 `WinDivert64.sys` (94,144 B) 都隨 wheel 裝在
`.venv\Lib\site-packages\pydivert\windivert_dll\`；實測 `WinDivertOpen` 成功、
`sc query WinDivert` 顯示 `STATE : 4 RUNNING`。

## 改了哪些檔案

### `camcap/redirector.py`（本次唯一的行為修改）

1. `Redirector.filter` 用 De Morgan 展開，`not (A and B)` → `(¬A or ¬B)`，語意完全相同：

   ```
   outbound and ip and tcp and (
     (ip.DstAddr == 10.253.58.186 and (tcp.SrcPort < 40000 or tcp.SrcPort >= 41000))
     or (ip.SrcAddr == 10.253.58.14 and tcp.SrcPort == 10607)
   )
   ```

   踩坑原因寫進 docstring，免得之後有人「順手改回比較好讀的寫法」。

2. 新增 module-level `check_filter(flt)`，在 `WinDivertOpen` 之前先跑
   `pydivert.WinDivert.check_filter()`（= `WinDivertHelperCompileFilter`，user-mode，
   不載 driver、不需 Administrator）。失敗就 raise 出「錯在第幾個字元 + WinDivert 自己的
   錯誤訊息 + caret 指位」，而不是一句 `[WinError 87] 參數錯誤`。
   `Redirector.run()` 和 `WsDiscoverySniffer.run()` 都接上了。

   > 這是本次最花時間的地方：原本的 87 完全不告訴你錯在哪，只能靠猜。以後任何人改 filter，
   > 第一時間就會看到 WinDivert 自己的抱怨。

`capture.py`、`app.py`、relay / decoders / replay **都沒動**。

### `tests/test_core.py`

加一條 `test_windivert_filter_avoids_unsupported_not_over_parens`，釘住新的 filter 形狀
（不得出現 `not` / `!`，且要有 De Morgan 展開後的 port range 條件）。
原本 8 條照舊，現在 **9 passed**。

### 新增的工具（不影響 camcap 行為）

| 檔案 | 用途 |
|---|---|
| `tools\diag-windivert.py` | filter ladder + `check_filter`；`--open` 才真的開 handle（SNIFF，需 admin） |
| `tools\timed-capture.py` | 跑 N 秒後用 `_thread.interrupt_main()` 送 KeyboardInterrupt，走跟 Ctrl-C 一樣的收工路徑（`Stop-Process` 會跳過 `finally`，log 就不會寫檔） |
| `tools\verify-windows.ps1` | 把驗證包成兩行指令，輸出寫成 `docs\windows-verify-{1,2}.txt` |

### 新增的樣本

`docs\samples\cv75-devkit-windivert-2026-09-04.jsonl` —— 本次 140 筆的遮罩版，
命名沿用既有慣例。**注意**：除了 `--redact` 之外我另外手動遮了登入 body，原因見下面「未解問題」。

## 終端輸出摘要

### part 1（不需 Administrator）

```
--- python -m pytest -q ---
.........                                                                [100%]
9 passed in 4.45s

--- tools\diag-windivert.py ---
python      : 3.12.10 64bit
pydivert    : 3.1.3
WinDivert64.dll: OK (47616 bytes)
WinDivert64.sys: OK (94144 bytes)
local ip    : 10.253.58.14  (route to 10.253.58.186)
3 failure(s) total, 0 of them on filters camcap actually uses.
```

（那 3 個 FAIL 是 ladder 裡故意拿來確認語法邊界的，見上面「根因」。）

### part 2（Administrator）

```
--- WinDivertOpen (SNIFF) ---
[ OK ] open: WSD sniffer filter
[ OK ] open: NEW 完整 filter

--- timed capture ---
[camcap] intercepting 10.253.58.186 via 10.253.58.14:10607
2026-09-04T16:32:31.934+08:00  cgi   GET  http://10.253.58.186/                          200
2026-09-04T16:32:32.003+08:00  cgi   GET  http://10.253.58.186/css/style.css             200
...
2026-09-04T16:32:45.707+08:00  cgi   GET  http://10.253.58.186/api/v1/config/rtsp        200
[timed-capture] 90s 到，送出 KeyboardInterrupt
[camcap] wrote 140 events to first.jsonl

--- sc query WinDivert ---
STATE : 4 RUNNING
```

`[camcap] intercepting ...` 之後**沒有**再出現任何 `[err]` —— 這是跟修改前最直接的差別，
修改前那行後面立刻跟著 `[err] WinDivert failed: [WinError 87]`。

> PowerShell 會把 native command 的 stderr 包成紅色 `NativeCommandError` ErrorRecord，
> 那是 `2>&1` 的顯示行為，不是錯誤，pipeline 有繼續跑完。

### first.jsonl 統計

| 項目 | 值 |
|---|---|
| events | 140（cgi 140，proto 全部正確辨識） |
| status | 200 × 130、502 × 2、null × 8 |
| method | GET 139、POST 1 |
| `/api/v1/*` | 26 筆（`auth/login`、`auth/whoami`、`config/platform`、`config/video`、`config/rtsp`、`system/info`、`storage/status` …） |
| latency | 1–5 ms |

502 × 2 都是 `GET /api/v1/storage/status` —— 板子自己回的（devkit 沒插卡），不是攔截問題。

## 順帶發現

1. **這塊板子的 Web UI 走 cookie session，不是 HTTP Digest。**
   `POST /api/v1/auth/login` 之後帶 `Cookie: opsis_session=<64 hex>`，140 筆的 `auth` 欄位
   全部是 `none`。跟 Linux 端 09-04 那次用 curl 打 Digest 的路徑完全不同 ——
   **replay engine 的 Digest / WSSE re-auth 路徑這次一次都沒被用到**，
   browser-flow 的 log 要重播需要處理 cookie（見「未解問題」1）。

2. **板上 httpd 對每個 request 都回 `Connection: close`**，即使 client 送
   `Connection: keep-alive`（132 筆全部如此）。結果是首頁一次載入就開了 140 條 TCP 連線
   （`stream` 數 = event 數 = 140，1:1）。這對 camcap 沒影響，但對 firmware 是效能議題，
   跟 09-04 記到的「Digest nonce 可重用」放在一起看，建議一併提。

3. `bytes_c2s` / `bytes_s2c` 在 cgi event 上都是 0。查了 `decoders.py`：這兩個欄位只寫在
   `_raw_event`（無法解析的 raw stream）上，**是設計如此，不是 bug**。

## 未解問題 / 交回 Linux 端

1. **`redact_event()` 不會遮 JSON 登入 body。**
   `redact_text()` 只處理 Digest `response=`、WSSE `Password`、URL 密碼、RTSP URL credential。
   `POST /api/v1/auth/login` 的 `{"username":"admin","password":"admin"}` 原封留在
   `--redact` 之後的輸出裡。docs/samples 是要進 git 的，這個洞得補。
   我這次是手動把那一筆 body 遮掉才放進 `docs\samples\`。
   `model.py` 不在這次允許改動的範圍，交給 Linux 端決定怎麼修
   （建議：body 是 JSON 就遞迴遮 `password` / `passwd` / `pwd` / `token` / `secret` 類 key）。

2. **WebSocket 沒解。** 8 筆 `resp_status: null` 都是 `GET /ws/events` 帶
   `Connection: Upgrade`。h11 decoder 到 101 就停了，之後的 ws frame 沒解析、也沒計數。
   要不要支援請 Linux 端決定。

3. **cookie session 的重播沒驗過。** 見「順帶發現」1。

4. **ONVIF 還是沒驗。** 板上 `/onvif/device_service` 依舊 404，這次一樣沒碰到。

5. **WS-Discovery sniffer 只驗到 handle 開得起來**（`[ OK ] open: WSD sniffer filter`），
   90 秒內沒有裝置在發 Probe，所以沒有實際 event。

6. **handoff 步驟 6（`camcap` UI 與 `tools\build.ps1`）還沒跑**，
   也就是 README「尚未實機驗證」的第 3、4 項（PyInstaller 打包 WinDivert `.sys`、
   WebView2 runtime）仍然未驗。

## 怎麼重跑

```powershell
cd $env:USERPROFILE\camcap

# 語法 / 單元測試，不需要 Administrator
powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1

# 實機攔截 90 秒，需要「以系統管理員身分執行」的 PowerShell
powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Live
```

輸出：`docs\windows-verify-1.txt`、`docs\windows-verify-2.txt`、`first.jsonl`。

### 給下一個人的兩個 Windows 坑（跟 camcap 無關，但會擋住你）

- `.ps1` 存成**無 BOM 的 UTF-8** 時，Windows PowerShell 5.1 會用 ANSI (cp950) 讀，
  中文變亂碼、引號括號跟著爆掉。存成 **UTF-8 with BOM**。
- PS 5.1 的 `Tee-Object` **沒有 `-Encoding` 參數**（PS 6 才有）。用
  `Tee-Object -Variable x` 再 `$x | Out-File -Encoding utf8`。
- Python 吐 UTF-8 但主控台是 cp950 時，連 Tee 出來的檔案都是亂碼；
  腳本裡設 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`。
