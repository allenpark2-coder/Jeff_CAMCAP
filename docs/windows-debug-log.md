# Windows 端 WinDivert 攔截 debug log

> 回覆 `docs/handoff-windows-debug.md`。日期 2026-09-04，機器 `desktop-o4nanbm`（Windows，
> Python 3.12.10 64-bit，pydivert 3.1.3 / WinDivert 2.2.2），板子 CV75 devkit `10.253.58.186`。
> 板子全程只讀：瀏覽 Web UI + GET，沒有改設定 / OTA / 重開。

## 結論

`WinError 87` 是**filter 字串語法錯誤**，不是 pydivert API、不是 driver。改掉 filter 之後
WinDivert 攔截整條打通：瀏覽器直連 `http://10.253.58.186/` 的流量 90 秒內抓到 **140 筆 event**，
全部正確解出 URL / status / headers，`first.jsonl` 正常寫出。

假設 1 命中，假設 2、3 排除。

handoff 步驟 1–6 全部做完。之後為了出貨給 DQA 多做了一輪：補揉碼的洞、修 `build.ps1`
（它從來沒被執行過，有兩個 bug）、打包成 zip、UI 實機確認。狀態一覽：

| 項目 | 狀態 |
|---|---|
| WinDivert 攔截（`.py`） | ✅ 140 events / 90s |
| WinDivert 攔截（打包後的 exe） | ✅ 51 events / 30s |
| 單元測試 | ✅ 11 passed（原 8 + 3） |
| PyInstaller onedir + zip | ✅ 16.7 MB |
| UI（pywebview / WebView2） | ✅ |
| 揉碼（JSON 登入 body） | ✅ 已修 |
| ONVIF | ❌ 板上 404，仍只有 fake camera |
| HTTPS / RTSPS | ❌ 只有 raw 計數，見「未解問題」9 |
| cookie session 重播 | ❌ 未驗 |
| DQA 機器試裝 | ❌ 未做 |

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
（`model.py` 在第二輪為了出貨動了 —— 見下面「`camcap/model.py`」。）

### `tests/test_core.py`

加一條 `test_windivert_filter_avoids_unsupported_not_over_parens`，釘住新的 filter 形狀
（不得出現 `not` / `!`，且要有 De Morgan 展開後的 port range 條件）。
第二輪再加兩條揉碼測試。原本 8 條照舊，現在 **11 passed**。

### 新增的工具（不影響 camcap 行為）

| 檔案 | 用途 |
|---|---|
| `tools\diag-windivert.py` | filter ladder + `check_filter`；`--open` 才真的開 handle（SNIFF，需 admin） |
| `tools\timed-capture.py` | 跑 N 秒後用 `_thread.interrupt_main()` 送 KeyboardInterrupt，走跟 Ctrl-C 一樣的收工路徑（`Stop-Process` 會跳過 `finally`，log 就不會寫檔） |
| `tools\verify-windows.ps1` | 把驗證包成四段，輸出寫成 `docs\windows-verify-{1..4}.txt` |
| `tools\camcap-entry.py` | PyInstaller 的進入點（PyInstaller 沒有 python 的 `-m <module>` 語意） |
| `docs\DQA-README.md` | 給 DQA 的使用說明，會被 `-Build` 一起壓進 zip |

### `camcap/model.py`（第二輪，出貨前追加 —— 超出 handoff 允許範圍，小張同意才動的）

原本 `redact_text()` 只認 Digest `response=`、WSSE `Password`、URL 密碼、RTSP URL credential，
**JSON body 裡的密碼原封不動**。這塊板子的 Web UI 正好就是
`POST /api/v1/auth/login` + `{"username":"admin","password":"admin"}`，
所以 `--redact` 之後的 log 還是有明文密碼。DQA 會把 log 貼進 ticket、轉給客戶，這個洞得在出貨前補。

改動：`redact_text()` 多兩條路徑 ——

- 整串解得開且是 dict / list 的 JSON body → `redact_json()` 遞迴遮 key
  （`SECRET_KEY_PARTS`：password / passwd / pwd / secret / token / apikey / credential / privatekey，
  比對前先拿掉 `-` `_` 並轉小寫，所以 `newPassword`、`client_secret`、`api-key` 都吃得到）。
- form-urlencoded body / query string → `_RE_FORM_PW`。

帳號、URL、其他欄位保留 —— 全遮掉 log 就沒有辨識度了。
新增兩條測試 `test_redaction_covers_json_and_form_login_bodies`、
`test_redaction_still_covers_digest_wsse_and_rtsp_url`（後者釘住原有行為不被我改壞）。

### 打包（`tools\build.ps1`）

原本的 build.ps1 **從來沒被執行過**，一跑就發現兩個 bug：

1. **裸的 `pyinstaller` 抓到 PATH 上的系統 Python**（實測跑成 3.13.7 +
   `C:\Users\allen\AppData\Local\Programs\Python\Python313`），用系統的 site-packages 打包，
   `camcap` / `pydivert` 根本不在裡面。原流程靠先 `Activate.ps1` 遮掉這件事。
   改成明確用 `.venv\Scripts\python.exe -m PyInstaller`。
2. **`-m camcap` 不是「跑模組」。** PyInstaller 6.22.2 `building/makespec.py:518`：
   `"-m", dest="shorthand_manifest", help="Deprecated shorthand for --manifest."`
   —— `camcap` 被當成 manifest 檔名吃掉，於是沒有 positional scriptname，
   報 `ERROR: Script file '-' does not exist.`。
   改成給它真的進入點 `tools\camcap-entry.py`（內含 `multiprocessing.freeze_support()`），
   並加 `--collect-submodules camcap`，因為 `redirector` / `app` 都是在函式裡才 import。

另外把 `--windowed` 改成 opt-in 的 `-Windowed`，**預設帶主控台**：
DQA 的包如果啟動就掛，`--windowed` 會讓畫面上什麼都不出現，他們連錯誤訊息都回報不了。
UI (pywebview) 在 console build 一樣開得起來。
build.ps1 收尾會自己確認 `WinDivert64.dll` / `.sys` 有沒有真的進 `dist\`。

### 新增的樣本

`docs\samples\cv75-devkit-windivert-2026-09-04.jsonl` —— 本次 140 筆，直接用修好的
`--redact` 產生（`{"username":"admin","password":"<redacted>"}`），命名沿用既有慣例。

## 終端輸出摘要

### part 1（不需 Administrator）

```
--- python -m pytest -q ---
.........                                                                [100%]
9 passed in 4.45s        （第二輪補了兩條揉碼測試後為 11 passed）

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

### part 3 / part 4（打包與打包後的 exe）

```
--- tools\build.ps1 (onedir, console) ---
  dist\camcap\_internal\pydivert\windivert_dll\WinDivert64.dll  (47616 bytes)
  dist\camcap\_internal\pydivert\windivert_dll\WinDivert64.sys  (94144 bytes)
camcap.exe OK, dist 總大小 30.4 MB
zip: camcap-windows-20260904.zip  (16.7 MB)

--- part 4：用打包後的 exe 攔 30 秒 ---
[camcap] intercepting 10.253.58.186 via 10.253.58.14:10935
2026-09-04T16:53:12.099+08:00  cgi GET http://10.253.58.186/api/v1/system/info      200
...
--- 共 51 行 event ---
sc query WinDivert -> STATE : 4 RUNNING
```

**凍結後的 exe 從 `_internal\` 載入 WinDivert driver 沒問題**，30 秒 51 筆，沒有任何 `[err]`。
zip 內容：根目錄 `camcap.exe` (8.5 MB) + `DQA-README.md`，
`_internal\camcap\ui\index.html` 與 WinDivert payload 都在。

> 這是 README 原本列為「尚未實機驗證」第 3 項的答案 —— 但只對 **onedir** 成立。
> onefile（`.sys` 先解到 `%TEMP%` 再載入）**刻意沒試**，那才是原本標記為風險的路徑；
> onedir 既然通了就沒有理由去冒那個險。

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

1. ~~`redact_event()` 不會遮 JSON 登入 body~~ → **已修**，見上面「`camcap/model.py`」。
   這是唯一一處超出 handoff 允許範圍的改動，因為要出貨給 DQA、而 DQA 會到處貼 log。
   Linux 端接回 git 時請特別 review 這一段。

2. **WebSocket 沒解。** 8 筆 `resp_status: null` 都是 `GET /ws/events` 帶
   `Connection: Upgrade`。h11 decoder 到 101 就停了，之後的 ws frame 沒解析、也沒計數。
   要不要支援請 Linux 端決定。

3. **cookie session 的重播沒驗過。** 見「順帶發現」1。

4. **ONVIF 還是沒驗。** 板上 `/onvif/device_service` 依舊 404，這次一樣沒碰到。

5. **WS-Discovery sniffer 只驗到 handle 開得起來**（`[ OK ] open: WSD sniffer filter`），
   90 秒內沒有裝置在發 Probe，所以沒有實際 event。

6. ~~UI 一次都沒被開過~~ → **已驗**（2026-09-04 17:00，打包後的 exe）。
   WebView2 正常不是白畫面，事件列表 / request-response 明細 / Replay 區都在，
   「下載前遮罩密碼」預設是勾的。畫面上 `⚠` 與 `…` 是
   `index.html:93` 的 `resp_status ?? (note ? '⚠' : '…')` —— 有 note vs 尚未結束，不是 bug。
   唯一的瑕疵是 Replay 的 target IP input 太窄、placeholder「（空＝原 camera）」視覺上被切掉，
   純 CSS，沒動。

7. **onefile 沒試。** 見 part 4 的註。onedir 夠用就不去碰 `.sys` 從 `%TEMP%` 載入那條路。

8. **還沒在任何一台 DQA 的機器上試裝。** 在開發機上測不出來的兩件事：
   防毒 / EDR 對封包攔截工具的誤判，以及 HVCI / driver blocklist 擋 WinDivert。
   建議先發一台，不要一次發全組。

9. **HTTPS / RTSPS 完全看不到內容 —— 這對市面機器比 ONVIF 重要得多，但這次沒動。**
   `decoders.py:_decide()` 只比對前 64 bytes 是不是 HTTP / RTSP request line；
   TLS ClientHello（`0x16 0x03`）兩個都不 match，掉進 `kind = "raw"`，
   只剩一筆事件加 byte 計數。camcap 不做 MITM，所以加密流量就是看不穿。

   **有一個會誤導人的地方**：這種情況下 note 寫的是
   `non-HTTP TCP payload (vendor SDK protocol?)` —— HTTPS 會被 DQA 讀成私有協定。
   最小的修法是解 TLS ClientHello（SNI / 版本 / ALPN）把 note 改成「TLS，內容加密」並附 SNI，
   不解密、不碰信任鏈，大約半小時。**這次沒做**，因為會動到 `decoders.py`。

   真要解密就是 MITM：relay 本來就是 asyncio TCP proxy 又已經從 NAT table 知道原始目的地，
   client 側 `start_tls` 配動態簽的 leaf cert（`ssl.SSLContext.sni_callback` 按 SNI 發）、
   camera 側 `ssl` 不驗證（camera 幾乎都自簽），`_pump` 和 decoder 一行都不用改。
   技術上一到兩天 + `cryptography` 依賴。**但成本不在程式**：
   要在每台機器裝自簽 CA（公司機器上是資安流程，比防毒白名單更難談），
   或讓操作者每次點掉憑證警告；有 certificate pinning 的 vendor app 會斷，
   而且斷的樣子很像 camera 壞掉，會製造假 bug。
   一個能看穿 HTTPS 的工具在公司裡的定位也跟現在不同，發給 DQA 前應該先過資安。

   另有一條不用 CA 的路：client 若吃 `SSLKEYLOGFILE`（Chrome 等），
   記下 TLS secret 用 Wireshark 解密；對原生 SDK 工具無效，而且是另一套流程不是 camcap 的功能。

   小張的傾向：短期先做「標示清楚」那半小時的版本 + 測試時把 DUT 切回 HTTP 當標準流程，
   MITM 等真的出現「只在 HTTPS 下重現」的案子再談。**尚未決定，交回 Linux 端一起議。**

## 怎麼重跑

```powershell
cd $env:USERPROFILE\camcap

# 1 語法 / 單元測試          不需 admin  -> docs\windows-verify-1.txt
powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1

# 2 實機攔截 90 秒           需要 admin  -> docs\windows-verify-2.txt + first.jsonl
powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Live

# 3 PyInstaller onedir + zip 不需 admin  -> docs\windows-verify-3.txt + camcap-windows-<date>.zip
#   （PyInstaller 6.x 在提權 shell 只是警告，7.0 會直接擋，所以這段刻意不提權）
powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Build

# 4 測打包後的 exe 30 秒     需要 admin  -> docs\windows-verify-4.txt
powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Smoke
```

### 給下一個人的兩個 Windows 坑（跟 camcap 無關，但會擋住你）

- `.ps1` 存成**無 BOM 的 UTF-8** 時，Windows PowerShell 5.1 會用 ANSI (cp950) 讀，
  中文變亂碼、引號括號跟著爆掉。存成 **UTF-8 with BOM**。
- PS 5.1 的 `Tee-Object` **沒有 `-Encoding` 參數**（PS 6 才有）。用
  `Tee-Object -Variable x` 再 `$x | Out-File -Encoding utf8`。
- Python 吐 UTF-8 但主控台是 cp950 時，連 Tee 出來的檔案都是亂碼；
  腳本裡設 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`。
