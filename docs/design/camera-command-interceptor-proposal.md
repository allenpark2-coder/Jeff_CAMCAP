# Camera Command Interceptor — 架構提案與我的想法

> 對應需求（2026-09-04）：Windows 端輸入 camera IP → 攔截所有送到該 IP 的 CGI / ONVIF command → UI 顯示指令與時間 → 可下載 log → 一鍵重播 log 行為。
> 網路資源的一手來源整理見 [`../research/camera-command-interceptor.md`](../research/camera-command-interceptor.md)；本文只放判斷與設計。

---

## 0. 先講結論

> **2026-09-04 拍板**：工具要發給同事／客戶 → 走 **WinDivert 轉導**路線，不用 Npcap／Wireshark。其餘由我決定：(a) UDP 3702 也用 WinDivert SNIFF flag 抓，全程一支 driver；(b) 重播的 **target override（打到 dev board）進 MVP**，ProfileToken 等值的映射延後；(c) HTTP 解析不掛 mitmproxy，改用「透明 TCP relay + h11 被動解碼」，理由見 §3.1。

| 項目 | 建議 |
|---|---|
| 抓包方式（只裝在自己機器） | **被動 sniff**：Npcap + BPF `host <camIP>`，用 `tshark` 子行程做 TCP 重組與 HTTP 解析，Python 讀 stdout 進 UI。最快能動、零干擾 |
| 抓包方式（要發給同事／客戶） | **WinDivert 轉導**：pydivert 依 `ip.DstAddr == camIP` 精準攔，改 dst 丟給本機 proxy（mitmproxy reverse mode 或自寫 relay）。原因：Npcap free license 只准 5 台且禁止 redistribution，WinDivert 是 LGPL |
| HTTPS / 改封包 | 只有 WinDivert 路線做得到，需 client 信任我們的 CA |
| 重播 | **不做 byte-for-byte 重送**。用獨立 HTTP client 重建請求，Digest / WS-UsernameToken 依 UI 輸入的帳密**重新產生**，時間間隔可選「原速 / 全速 / N 倍」 |
| Log 格式 | 內部 JSONL（一行一 request/response 對）；下載提供 JSONL + HAR（HAR 可直接丟進 Chrome DevTools、mitmproxy、Fiddler） |
| UI 技術 | Python + pywebview（HTML 前端、體積小、你正在學 Python），PyInstaller 打包並加 `--uac-admin` |
| 最大的隱藏風險 | 廠商工具（iVMS-4200、SmartPSS）常走**私有二進位協定**（Hikvision 8000、Dahua 37777），根本不是 CGI/ONVIF；工具要能標出「有非 HTTP 流量」，否則會誤以為 client 沒動作 |

---

## 1. 需求拆解：字面之外要注意的事

1. **「任何連線到此 IP 的 cgi/onvif」＝ HTTP 層的東西**，但同一台 camera 還會收到：
   - RTSP（554）：`DESCRIBE/SETUP/PLAY`，和 ONVIF `GetStreamUri` 是一組的，值得一起記（純文字，好解）。
   - 私有 SDK 協定（Hikvision 8000/TCP、Dahua 37777/TCP）：二進位，不解，只記「哪個 port、幾個 bytes、何時」。
   - WS-Discovery（UDP 3702 multicast）：Probe 的目的地是 239.255.255.250 不是 camera IP，`host <ip>` 會漏掉 Probe 只抓到 ProbeMatch；filter 要多加 `or udp port 3702`。
2. **HTTPS**：被動 sniff 完全看不到內容。LAN 上 camera 幾乎都開 HTTP，但若客戶只開 HTTPS，就要走 Phase 3 的 MITM 路線（且 client 得吃我們的 CA，或根本不驗證）。
3. **「模擬 log 的行為」不能只是重送封包**：
   - HTTP Digest（CGI 主流）：`nonce/nc/cnonce` 綁在當時的 401 challenge 上；RFC 7616 允許 server 拒絕重用的 nonce，Hikvision 甚至有「replay attack protection」開關。
   - ONVIF WS-UsernameToken：`PasswordDigest = B64(SHA1(nonce + created + password))`，spec 要求 device 拒絕沒有 nonce/created 的 token，並建議 cache 用過的 nonce、5 分鐘以外的 created 直接丟。
   - 所以重播引擎**一定需要帳密**，UI 要有帳密欄（或允許「先試原封重送、失敗再重簽」）。
4. **有狀態的 session**：Hikvision ISAPI 有 `sessionLogin`＋cookie、Dahua 有 RPC2 session id。這類 log 重播前要先重建 session，屬於 Phase 2 的「vendor-aware replay」，MVP 先標出「此 log 含 session 依賴，重播可能失敗」。

---

## 2. 四種抓法比較

| 方法 | 原理 | 需 admin | 看得到 body | HTTPS | client 忽略系統 proxy 仍可抓 | 會改動流量 | 依 IP 篩選 |
|---|---|---|---|---|---|---|---|
| A. 被動 sniff（Npcap） | 網卡層複製封包 | 安裝時可選；若勾「Administrators only」則執行也要 | ✅（自己/由 tshark 重組 TCP） | ❌ | ✅ | ❌（零風險） | ✅ BPF 原生 |
| B. WinDivert 轉導 → 本機 proxy | driver 攔下 outbound 封包改 dst 到 127.0.0.1:port | ✅ 永遠要 | ✅ | ✅（需 MITM CA） | ✅ | ✅（client 連線是被改過的） | ✅ filter `ip.DstAddr == x` |
| C. 系統 proxy（Fiddler/HTTP Toolkit） | WinINET proxy 設定 | ❌ | ✅ | ✅ | ❌ 多數 camera 工具、VMS 直接開 socket | — | ❌（是全機） |
| D. `mitmproxy --mode local` | mitmproxy 自帶的 WinDivert redirector | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ 只能依 **process 名稱/PID**，不能依目的 IP；全機或整個 process 的流量都會走 proxy，只能靠 `allow_hosts` 在 proxy 層再篩 |

**授權（research 挖出來、會影響路線的事）：** Npcap free license 明文「may be used (but not externally redistributed) on up to 5 systems」，要包進自家安裝檔得買 OEM license；WinDivert 是 LGPLv3/GPLv2。所以 A 方案適合「自己機器用」，一旦要發 exe 給別人就該走 B。

**B 方案其實沒有想像中難（修正 research 文件 open question #4 的說法）：** 「自己寫要做 TCP reassembly」只在 *sniff* 模式成立。轉導模式是把封包的 dst 改成本機後**重新注入 Windows 網路堆疊**，TCP 重組由 kernel 做，我們的 proxy 只是 `accept()` 一個普通 socket。pydivert 部分約 150 行：filter `outbound and ip.DstAddr == CAM and tcp`，記 `(src port) → 原始 dst port` 的表，回程封包反向改回。兩個實作細節：(1) 注入到 127.0.0.1 會 error 1214，proxy 要 bind 0.0.0.0 並把 dst 改成本機網卡 IP；(2) HTTP 解析直接交給 `mitmdump --mode reverse:http://CAM:PORT`（每個看到的 port 開一個），flow file / HAR / addon hook 全部現成。

**為什麼「自己機器用」先選 A：**
- 目標是「記錄」不是「篡改」，被動最安全，不會因 proxy 出錯讓客戶端工具連不上 camera，這在你要重現客戶問題時很重要（觀測不能改變被觀測物）。
- `host <ip>` 一條 BPF 就把所有 port 全收，不必猜 ONVIF 在 80/8080/8899/2020 哪個 port；RTSP、私有協定也同時進來。
- 不用自己維護 NAT 表（B 方案要記 `(src port) → 原始 dst`，回程再改回來；還有 WinDivert 注入到 127.0.0.1 會噴 error 1214，proxy 得 bind 0.0.0.0）。

**為什麼不直接用現成 D（mitmproxy local mode）：**
- 它的選擇器是 process，不是目的地。要抓「所有 client 對這台 camera」就得 `--mode local` 全機攔，其他 HTTPS 流量全被 MITM，pinned 的 app 會壞。
- 它自己文件寫著「doesn't (yet) support replay of HTTP Digest authentication」，重播這塊還是得自己寫。
- 但它是 Phase 3（HTTPS）最省力的底：可以只把 camera IP 加進 `allow_hosts`，其餘 `ignore_hosts` 直通。

---

## 3. 推薦架構（MVP）

```
┌──────────────────────── UI (pywebview, HTML) ────────────────────────┐
│ [Camera IP] [ports: auto] [user/pass]  (Start)(Stop)  (Download)(Replay)│
│ ┌ time ─┬ proto ┬ method ┬ URL / SOAP action ┬ status ┬ latency ┐     │
│ │ ...   │ ONVIF │ POST   │ GetProfiles       │ 200    │ 35ms    │     │
│ │ ...   │ CGI   │ GET    │ /ISAPI/System/... │ 401→200│ 12ms    │     │
│ │ ...   │ RTSP  │ DESCRIBE │ rtsp://.../ch1  │ 200    │         │     │
│ │ ...   │ RAW   │ —      │ tcp/8000 4.2 KB   │        │         │     │
│ └───────┴───────┴────────┴───────────────────┴────────┴─────────┘     │
│ detail pane: request headers / body / response body                   │
└───────────────────────────────────────────────────────────────────────┘
         ▲ events (JSON)                                  │ replay job
┌────────┴────────┐                          ┌────────────▼────────────┐
│ capture.py      │                          │ replay.py               │
│ tshark -l -T ek │  ← Npcap, BPF            │ requests + HTTPDigestAuth│
│ parse → classify│    "host IP or udp 3702" │ ONVIF: 重簽 wsse header │
│ → JSONL store   │                          │ timing: 原速/全速/N×     │
└─────────────────┘                          └─────────────────────────┘
```

### 3.1 Capture 層（定案：WinDivert 轉導 + 透明 TCP relay）
- **redirector（pydivert）**：filter `outbound and ip.DstAddr == CAM and tcp and not (tcp.SrcPort in relay 保留範圍)`，把 dst 改成 `本機網卡IP:relayPort`，NAT 表記 `client src port → 原始 dst port`；反向 filter `outbound and ip.SrcAddr == 本機IP and tcp.SrcPort == relayPort` 把 src 改回 `CAM:原始port`。重算 checksum 後注入。不能注入到 127.0.0.1（error 1214），所以 relay bind 0.0.0.0、dst 用網卡 IP。
- **relay 出去的連線要避開自己的 filter**：relay 對 camera 的 outbound socket 綁在保留 source port 範圍（預設 40000–40999），filter 排除該範圍即可，不必像 mitmproxy 用 GetExtendedTcpTable 查 PID。
- **relay 本身不解析、不改 bytes**：純 tee。client↔camera 的位元組原樣轉送，另一份餵給 decoder。這樣就算是 RTSP、私有 SDK 二進位協定，也不會被我們弄壞（觀測不改變被觀測物）。
- **decoder 被動解碼**：用 `h11` 的兩個 state machine（SERVER role 吃 client bytes、CLIENT role 吃 server bytes）配對 request/response，處理 keep-alive、chunked、Content-Length；RTSP 用簡單文字解析；其他歸 RAW 只記 port/bytes。
- 為什麼不掛 mitmproxy：reverse mode 要每個 port 開一個、`--mode local` 不能依 IP、onefile 打包還多一支它自己的 redirector 與 driver；h11 是純 Python 幾百 KB。HTTPS 要做時再評估把 TLS 終結加進 relay。
- 分類規則：
  1. URL 含 `/onvif/` 或 `Content-Type: application/soap+xml` → **ONVIF**，SOAP action 取 `Body` 第一個子元素 local-name（`GetProfiles`、`ContinuousMove`…）。
  2. 其他 HTTP → **CGI**（再依 path 前綴標 vendor：`/ISAPI/`=Hik、`/cgi-bin/`=Dahua/Amcrest、`/axis-cgi/`=Axis、`/stw-cgi/`=Hanwha）。
  3. `RTSP/1.0` → RTSP。
  4. 其餘 TCP 有 payload → RAW，只記 port/bytes/時間。
- 一併記錄 **401 challenge**：從 `WWW-Authenticate` 就能知道 camera 要 Digest 還是 Basic、realm、qop，重播時直接沿用。

### 3.2 Log schema（JSONL，一行一筆）
```json
{"ts":"2026-09-04T11:30:12.345+08:00","stream":17,"proto":"onvif","dst_port":80,
 "method":"POST","url":"http://192.168.1.64/onvif/media_service","soap_action":"GetProfiles",
 "auth":"wsse-digest","req_headers":{...},"req_body":"<s:Envelope ...>",
 "resp_status":200,"resp_body":"...","latency_ms":35}
```
- 下載時另產 HAR（timings 用 `latency_ms`），並提供「遮罩敏感欄位」勾選：Basic auth 是明文 base64、WS-Security 有 PasswordText 變體，會把密碼寫進 log。

### 3.3 Replay 引擎
- 逐筆依 `ts` 差值排程；選項：原速 / 全速 / N 倍速 / 逐步（手動下一筆）。
- 認證策略（可選、預設順序）：
  1. **raw**：原 header 原樣送，測試 camera 是否吃 nonce 重用（很多老 firmware 會吃）。
  2. **re-auth Digest**：拿掉 `Authorization`，交給 `requests.auth.HTTPDigestAuth` 走 401→重送。
  3. **re-sign WSSE**：解析 SOAP，刪 `wsse:Security`，用 UI 帳密重算 nonce/created/digest。
     - 我的加分想法：先對 camera 打一發 `GetSystemDateAndTime`（ONVIF 規定免認證），算出 camera 時鐘偏移，`Created` 用 **camera 時間**而非 PC 時間，就不會被 5 分鐘窗口打回來。
- 每筆顯示「原 status vs 重播 status」，狀態不同或 SOAP Fault 就標紅；可設 stop-on-error。
- **Replay target override**：允許把目的 IP 換成另一台（例如 CV75 dev board）。這是這工具對你們最有價值的地方：把客戶 VMS 對量產機的行為錄下來，在實驗室對開發板重播，不用裝客戶的軟體。

### 3.4 權限與打包
- Npcap：安裝時若勾「Restrict to Administrators only」，我們的 exe 就得以 admin 跑；不勾則一般權限可抓。
- WinDivert（Phase 3）：無條件要 admin。
- PyInstaller `--uac-admin` 在 manifest 寫 `requireAdministrator`，一開就跳 UAC，省得使用者忘記右鍵。

---

## 4. 我額外想加的功能（依價值排序）

1. **Replay 打到別台**（3.3 已述）：錄客戶環境 → 重播到 dev board。
2. **行為指紋 / 兩份 log diff**：把 ONVIF 序列壓成 `GetCapabilities → GetProfiles → GetStreamUri…`，比較 VMS A 和 VMS B 對同一台 camera 的差異，找「為什麼 A 可以 B 不行」。
3. **Server replay（假 camera）**：log 裡有 response，就能反過來起一個假 camera（mitmproxy `server_replay` 概念），讓 client 端團隊沒硬體也能測。
4. **RAW 流量提示**：看到 8000/37777 就在 UI 提示「client 正在用 Hikvision/Dahua 私有 SDK，CGI/ONVIF log 不完整」。
5. **敏感資料遮罩**後才允許下載（預設開）。

---

## 5. 風險與待決

| # | 風險 / 問題 | 影響 | 對策 |
|---|---|---|---|
| R1 | client 走私有二進位協定 | 抓不到「command」 | RAW 提示；不打算 reverse 私有協定 |
| R2 | camera 只開 HTTPS | 被動法全盲 | Phase 3 WinDivert/mitmproxy + 匯入 CA |
| R3 | camera 有 nonce cache / replay protection | raw replay 失敗 | 預設 fallback 到 re-auth |
| R4 | camera 時鐘偏差 > 5 min | WSSE 重簽被拒 | 先讀 GetSystemDateAndTime 校正 |
| R5 | session 型 API（ISAPI sessionLogin、Dahua RPC2） | 重播 401/403 | Phase 2 vendor plugin；MVP 標記 |
| R6 | Npcap 授權：free license 限 5 台、禁止 redistribution（已確認，見 research §1a） | 發 exe 給同事就違約 | 自用 → A；要散佈 → B（WinDivert LGPL） |
| R8 | PyInstaller onefile 內含 WinDivert `.sys` driver，從 temp 目錄載入是否會被 Windows 擋 | B 路線成立與否 | 第一個要做的 spike（research open question #1） |
| R9 | WS-Discovery Probe 走 UDP 3702 multicast，不會經過任何 proxy | B 路線抓不到「掃描」動作 | 另開一條 UDP sniff（WinDivert SNIFF flag 即可，不必 Npcap） |
| R7 | tshark 依賴 Wireshark 安裝 | 部署多一步 | 內部工具可接受；之後可換 scapy/WinDivert-sniff |

**已拍板（2026-09-04）：**
0. 發給同事／客戶 → **B（WinDivert）**。
1. 不依賴 Wireshark；WS-Discovery 也用 WinDivert SNIFF 抓。
2. 重播 target override 進 MVP；token 映射延後到 Phase 2 後段。

---

## 6. 分階段計畫

| Phase | 內容 | 狀態（2026-09-04） |
|---|---|---|
| 1 | relay + decoders（HTTP/RTSP/RAW）+ LogStore + JSONL/HAR + 遮罩 + UI + CLI | **Linux 上完成並有測試**（`tests/`，7 個全過；fake camera 模擬 Digest 單次 nonce 與 WSSE 重播保護） |
| 2 | replay：原速/N 倍/全速、raw→Digest→WSSE 重簽、camera 時鐘校正、target override + port map、逐筆比對 | **完成並有測試**（含打到時鐘快 15 分鐘的另一台） |
| W | Windows 端：pydivert redirector、WS-Discovery sniff、pywebview、PyInstaller `--uac-admin` | **程式寫好但未實機驗證**；spike 清單見 README「尚未實機驗證」 |
| 3 | HTTPS（relay 內做 TLS 終結 + 匯入 CA）、server replay 假 camera、session-aware vendor plugin、兩份 log diff | 未開始 |

Windows 實機第一步（以系統管理員 PowerShell）：
```powershell
py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -e .[windows,dev]
camcap capture 192.168.1.64 --out first.jsonl     # 開著它，用廠商工具或 ODM 操作 camera
camcap replay first.jsonl --user admin --password xxx --speed 1
```
若 redirector 有問題，先退到 `camcap capture <ip> --test-mode`（純 relay，把 client 指向 relay port）確認其餘鏈路正常，再單獨 debug WinDivert 那段。
