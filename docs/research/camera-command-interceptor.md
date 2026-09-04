# IP Camera 指令攔截器（Windows 桌面工具）一次來源調查

> 調查日期：2026-09-04
> 需求：Windows 上輸入一台 IP camera 的 IP，攔截本機任何軟體對該 IP 發出的 HTTP CGI（`/cgi-bin/...`、`/ISAPI/...`、`/stw-cgi/...`）與 ONVIF（SOAP over HTTP）指令，附時間戳顯示在 UI、可下載 log、可 replay。
> 原則：只引用 primary source（官方文件、GitHub 原始碼／README、RFC／spec）。無法從一手來源證實的一律標「待驗證」。

---

## Summary（結論先講）

1. **核心架構建議：WinDivert 轉導 + mitmproxy 當解析／記錄／replay 引擎。**
   - WinDivert 是 user-mode 的 WFP callout driver，filter 語法可以**直接依目的 IP 過濾**（`ip.DstAddr == 192.168.1.1`），並且可以改寫封包後重新注入 → 把去 camera 的 TCP 轉到本機 proxy port。這正好對上「使用者輸入一個 camera IP」這個需求。
     來源：<https://reqrypt.org/windivert-doc.html>
   - mitmproxy 的 `--mode local`（Local Capture）**在 Windows 底層就是用 WinDivert** 實作的 redirector，官方支援 Windows／Linux／macOS，mitmproxy 10.2+ 可用。
     來源：<https://www.mitmproxy.org/posts/local-capture/windows/>、<https://docs.mitmproxy.org/stable/concepts/modes/>
   - **但 `--mode local` 的 spec 只能挑 process name / PID，不能挑目的 IP。** 要「只看某台 camera」得改用 `allow_hosts` 選項（regex，會 match ip 或 hostname）來過濾。
     來源：<https://docs.mitmproxy.org/stable/concepts/modes/>、<https://docs.mitmproxy.org/stable/concepts/options/>
2. **mitmproxy 的 `--mode transparent` 在 Windows 上不可用**（官方標示 _Availability: Linux, macOS_），所以「透明代理」這條路在 Windows 只有 local mode 或自幹 WinDivert。
   來源：<https://docs.mitmproxy.org/stable/concepts/modes/>
3. **系統 proxy（Fiddler 式）這條路對 camera client 不可靠**：WinINET 的 proxy 設定是 `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings` 的 `ProxyEnable`/`ProxyServer`，**只有呼叫 WinINET 且用 `INTERNET_OPEN_TYPE_PRECONFIG` 的程式才會讀**；用 WinHTTP 或裸 Winsock 的程式預設完全不理它。
   來源：<https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality>、<https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-autoproxy-api>
4. **Replay 的最大風險是認證，不是傳輸。** ONVIF 的 WS-UsernameToken digest 綁 nonce + created timestamp，OASIS spec 明文建議 server 拒絕 stale timestamp（建議 5 分鐘）與重複 nonce；HTTP Digest（RFC 7616）也綁 server nonce 與 nonce-count。**照字面 replay 已錄的 Authorization / Security header 大概率會被相機拒絕**，正確做法是「replay 語意（method + URI + body）＋重新產生認證」。
   來源：<https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0.pdf>、<https://www.rfc-editor.org/rfc/rfc7616.txt>
5. **HTTPS 只有走 MITM 才看得到明文**，且 camera client 必須信任 mitmproxy 的 CA；被動 sniffing（Npcap）永遠只看得到密文。
   來源：<https://docs.mitmproxy.org/stable/concepts/certificates/>
6. **Npcap 授權會擋商業散佈**：free license 明講「may be used (but not externally redistributed) on up to 5 systems」，要塞進自家安裝檔要買 OEM redistribution license。這對「做成一個給同事裝的 exe」是實際的法務阻礙；WinDivert 是 LGPLv3 / GPLv2 雙授權，相對單純。
   來源：<https://npcap.com/#download>、<https://github.com/basil00/WinDivert>

---

## 1. Windows 上的攔截方式與取捨

### 1a. 被動封包側錄（Npcap / pyshark+tshark / scapy）

- Npcap 是「an architecture for packet capture and network analysis for Windows operating systems, consisting of a software library and a network driver」，並且是 **WinPcap 的 drop-in replacement**（"Npcap is a drop-in replacement for WinPcap in most applications"）。
  來源：<https://npcap.com/guide/>
- **Loopback**：Npcap 提供 `NPF_Loopback` 介面（description "Adapter for loopback capture"），可以像一般網卡一樣抓 loopback 流量，也支援注入。對「攔截送到 127.0.0.1 的本機 proxy」有用，但對 camera 這種 LAN IP 不必要。
  來源：<https://npcap.com/guide/>
- **權限**：Npcap 有 Admin-only Mode，安裝時勾「Restrict Npcap driver's access to Administrators only」後「only Built-in Administrators may access its features via user software」。實務上要當系統管理員跑。
  來源：<https://npcap.com/guide/>
- **授權（重要）**：「The free version of Npcap may be used (but not externally redistributed) on up to 5 systems」、「The Npcap free license only allows five installs (with a few exceptions) and does not allow for any redistribution.」商業散佈需買 Npcap OEM Redistribution License。
  來源：<https://npcap.com/#download>
- **scapy on Windows**：官方安裝文件寫「You need to install Npcap in order to install Scapy on Windows (should also work with Winpcap, but unsupported nowadays)」，並且建議安裝 Npcap 時**關掉** `Winpcap compatibility mode`。
  來源：<https://scapy.readthedocs.io/en/latest/installation.html>
- **pyshark**：它自己不解析封包 —「it doesn't actually parse any packets, it simply uses tshark's (wireshark command-line utility) ability to export XMLs to use its parsing」，所以 HTTP 的 TCP reassembly 完全來自 tshark/Wireshark 的 dissector，前提是機器上要裝 Wireshark/tshark。
  來源：<https://github.com/KimiNewt/pyshark>
- **HTTP over TCP 能不能可靠重組？** Wireshark 有 "Allow subdissector to reassemble TCP streams"（預設開），可以「collect a contiguous sequence of TCP segments and hand them over to the higher-level protocol」；但官方也明講「if the packet capture drops packets, then Wireshark will not be able to reconstruct the TCP stream」。也就是：**能重組，但取決於抓不抓得完整**，高流量（camera 同時在推 RTSP/影像）掉包風險真實存在。
  來源：<https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html>
- **HTTPS 限制**：被動側錄看到的是 TLS record，沒有 key 就沒有明文。這條路對 HTTPS camera（越來越多）等於失效。（推論；佐證見 §1b mitmproxy CA 段落）

**小結**：被動側錄最不侵入、不會改變 client 行為（適合「純觀察 vendor tool 到底送了什麼」），但 (i) HTTPS 無解、(ii) 重組不保證、(iii) Npcap 授權擋散佈、(iv) 沒辦法直接接到 replay 引擎。

### 1b. 透明轉導 / redirect 攔截（WinDivert + mitmproxy）— 本案主力

#### WinDivert

- 定位：「user-mode capture/sniffing/modification/blocking/re-injection package for Windows」，實作為 **WFP callout driver**，不需要自己寫 kernel code。
  來源：<https://reqrypt.org/windivert-doc.html>
- **Filter 語法**（本案關鍵）：
  - 依目的 IP：`outbound and ip.DstAddr == 192.168.1.1`（IPv6 用 `ipv6.DstAddr`）
  - 依 port：`tcp.DstPort == 80 or tcp.DstPort == 443`
  - 文件中的範例字串：`"outbound and tcp.DstPort == 80"`
  - 支援 `and` / `or` / `not`（也可用 `&&` / `||` / `!`），以及 `outbound`、`inbound`、`loopback`、`tcp`/`udp`/`icmp` 等欄位。
  - 所以「使用者輸入 camera IP」→ 直接組成 `outbound and ip.DstAddr == <IP> and tcp` 這種 filter，是 WinDivert 的原生能力。
  來源：<https://reqrypt.org/windivert-doc.html>
- **改寫與重新注入**：流程是 `WinDivertRecv()` 收 → 改 → `WinDivertHelperCalcChecksums()` 重算 checksum → `WinDivertSend()` 注入。文件說注入的封包「may be one received from WinDivertRecv(), or a modified version, or a completely new packet」。
  來源：<https://reqrypt.org/windivert-doc.html>
- **導到本機 proxy port**：官方範例 `streamdump.exe` 就是「divert outbound TCP connections to a local proxy server which can capture or manipulate the stream」。做法即改 `ip.DstAddr` / `tcp.DstPort` 後重算 checksum 再注入；inbound 方向要處理 `Network.IfIdx`。
  來源：<https://reqrypt.org/windivert-doc.html>
- **權限**：必須 Administrator。文件列出 `ERROR_ACCESS_DENIED` (5) 的成因是「the calling application does not have Administrator privileges」。
  來源：<https://reqrypt.org/windivert-doc.html>
- **Driver signing**：官方 release 的 binary「already digitally signed」；自己 build 的 `WinDivert32.sys`/`WinDivert64.sys` 沒有有效簽章會拿到 `ERROR_INVALID_IMAGE_HASH` (577)。→ **用官方預編 binary，不要自己 build driver。**
  來源：<https://reqrypt.org/windivert-doc.html>
- **Layers**：`WINDIVERT_LAYER_NETWORK`（本機封包，可 block + inject）、`WINDIVERT_LAYER_NETWORK_FORWARD`（轉送封包）、`WINDIVERT_LAYER_FLOW`（flow 事件，不可注入）、`WINDIVERT_LAYER_SOCKET`（socket 操作，只能 block）、`WINDIVERT_LAYER_REFLECT`（唯讀）。
  - 註：`FLOW` / `SOCKET` layer 可拿到「哪個 process 開了到哪個 IP 的連線」，適合在 UI 顯示「是哪支軟體在跟 camera 講話」。（用途為推論；layer 存在與能力為文件所載。）
  來源：<https://reqrypt.org/windivert-doc.html>
- **授權**：「WinDivert is dual-licensed under your choice of the GNU Lesser General Public License (LGPL) Version 3 or the GNU General Public License (GPL) Version 2.」
  來源：<https://github.com/basil00/WinDivert>
- **支援版本**：README 提到 Windows 7 / 8 / 10；最新為 2.2 系列。（對 Windows 11 的官方明文支援：待驗證，但 mitmproxy 在 Windows 11 上就是用它。）
  來源：<https://github.com/basil00/WinDivert>

#### pydivert（Python binding）

- Python 綁定，`with pydivert.Divert("tcp.DstPort == 80") as diverter:` 這種用法；bundle 了 WinDivert DLL 與 driver，不用另外裝。
- PyPI 上列 Python `>=3.10`，OS classifier 為 `Microsoft :: Windows :: Windows 11`（64-bit），並明列「Administrator/Root Privileges (required to interact with network drivers)」。
- **版本號待驗證**：GitHub 頁面摘要說「4.0.0 起 bundle WinDivert 2.2.2」，PyPI 頁面顯示最新為 3.1.3（2026-05-15）。實作前請直接 `pip index versions pydivert` 確認。
  來源：<https://github.com/ffalcinelli/pydivert>、<https://pypi.org/project/pydivert/>

#### mitmproxy on Windows

**模式支援（官方 Proxy Modes 頁）**：

| Mode | CLI | 平台 | 需要 client 設定？ |
|---|---|---|---|
| Regular | `mitmproxy`（預設，port 8080） | 全平台 | 要（設 HTTP proxy） |
| **Local capture** | `--mode local` / `--mode local:curl` / `--mode local:42` | **Windows / Linux / macOS** | 不用 |
| WireGuard | `--mode wireguard` / `--mode wireguard@51821` | 全平台 | 要（匯入 WireGuard config） |
| Reverse | `--mode reverse:https://example.com` | 全平台 | 要（client 改連 proxy） |
| **Transparent** | `--mode transparent` | **Linux / macOS only** | 不用 |
| TUN | `--mode tun` | Linux only | 不用 |
| Upstream | `--mode upstream:http://example.com:8081` | 全平台 | 要 |
| SOCKS5 | `--mode socks5` | 全平台 | 要 |
| DNS | `--mode dns` | 全平台 | 要 |

來源：<https://docs.mitmproxy.org/stable/concepts/modes/>

- **Local Capture 在 Windows 的實作**：mitmproxy 會「spawn a privileged redirector process that makes use of WinDivert, a user-mode packet capture library, via the ... windivert-rust crate, which allows targeting specific PIDs while avoiding memory-unsafe code」；封包經 **named pipe** 交給 `mitmproxy_rs`，後者用 user-space TCP/IP stack 把封包還原成 stream。Windows 的 local redirect mode 從 **mitmproxy 10.2** 起可用。
  來源：<https://www.mitmproxy.org/posts/local-capture/windows/>
- `mitmproxy-windows` PyPI 套件「contains the Windows traffic redirector based on WinDivert」。
  來源：<https://github.com/mitmproxy/mitmproxy_rs>
- **spec 語法（只認 process，不認 IP）**：
  - `mitmproxy --mode local` — 攔全機
  - `mitmproxy --mode local:curl` — 只攔 process name
  - `mitmproxy --mode local:42` — 只攔 PID
  - `mitmproxy --mode local:curl,wget` — 逗號多選
  - `mitmproxy --mode local:!curl` — `!` 反向排除
  - Linux 上 process name 只比對前 16 字元（kernel `TASK_COMM_LEN`）
  來源：<https://docs.mitmproxy.org/stable/concepts/modes/>
- **→ 因此「只看某台 camera IP」要靠 options，不是靠 mode spec**：
  - `allow_hosts` — 「Opposite of --ignore-hosts」，而 `ignore_hosts` 的說明是「The supplied value is interpreted as a regular expression and matched on the ip or the hostname」。所以 `--allow-hosts '^192\.168\.1\.64(:|$)'` 這種寫法是官方支援的過濾點。
  - `tcp_hosts` / `udp_hosts` — 對非 HTTP 的 TCP/UDP 做通用攔截（RTSP 若要記錄可考慮）。
  來源：<https://docs.mitmproxy.org/stable/concepts/options/>
- **Windows local mode 需要 elevation**：官方稱其為 "privileged redirector process"，而 WinDivert 本身明文要求 Administrator（見上）。→ 我們的 exe 要走 UAC 提權。
  來源：<https://www.mitmproxy.org/posts/local-capture/windows/> + <https://reqrypt.org/windivert-doc.html>
- **Local capture 目前的官方限制**：「limited to CLI invocations for now」，且 automated certificate installation 與 mitmweb UI 整合「remain planned but not yet implemented」。→ 我們自己做 UI 是合理的，但要自己處理 CA 安裝。
  來源：<https://www.mitmproxy.org/posts/local-capture/windows/>

**Python addon API（我們記 log 的掛點）**：

```python
def requestheaders(flow: mitmproxy.http.HTTPFlow)  # request header 讀完，body 還是空的
def request(flow: mitmproxy.http.HTTPFlow)         # 完整 request 讀完
def responseheaders(flow: mitmproxy.http.HTTPFlow) # response header 讀完
def response(flow: mitmproxy.http.HTTPFlow)        # 完整 response 讀完
def error(flow: mitmproxy.http.HTTPFlow)           # HTTP 錯誤 / 連線中斷
```
以及生命週期 `load(loader)` / `configure(updated: set[str])` / `running()` / `done()`，
還有 `tcp_start` / `tcp_message` / `tcp_end` / `tcp_error` 與對應的 `udp_*`。
來源：<https://docs.mitmproxy.org/stable/api/events.html>

Addon 以 `-s` 載入，最小骨架（官方範例）：

```python
import logging

class Counter:
    def __init__(self):
        self.num = 0
    def request(self, flow):
        self.num = self.num + 1
        logging.info("We've seen %d flows" % self.num)

addons = [Counter()]
```
執行：`mitmdump -s ./anatomy.py`
來源：<https://docs.mitmproxy.org/stable/addons/overview/>

**存檔與 replay 相關 options**：
- `save_stream_file`（`-w`）：「Stream flows to file as they arrive. Prefix path with + to append. The full path can use python strftime() formating, missing directories are created as needed.」
- `save_stream_filter`：「Filter which flows are written to file.」
- `hardump`：「Save a HAR file with all flows on exit.」← **UI 的「下載 log」可以直接產 HAR，通用格式**
- `client_replay`（`-C`）：「Replay client requests from a saved file.」
- `server_replay`（`-S`）：「Replay server responses from a saved file.」
- `rfile`：「Read flows from file.」
來源：<https://docs.mitmproxy.org/stable/concepts/options/>

官方 client replay 教學的指令：錄 `mitmdump -w wireless-login`，放 `mitmdump -C wireless-login`。
來源：<https://docs.mitmproxy.org/stable/tutorials/client-replay/>

Features 頁對兩種 replay 的定義：
- Client-side replay：「you provide a previously saved HTTP conversation, and mitmproxy replays the client requests one by one」
- Server-side replay：「The `server_replay` option lets us replay server responses from saved HTTP conversations. To do this, we use a set of heuristics to match incoming requests with saved responses.」
來源：<https://docs.mitmproxy.org/stable/overview/features/>

**憑證（HTTPS 必經）**：mitmproxy 首次啟動會在 `~/.mitmproxy` 產生 CA；「Since your browser won't trust the mitmproxy CA out of the box, you will either need to click through a TLS certificate warning on every domain, or install the CA certificate once so that it is trusted.」也可用 `--certs [domain=]path_to_certificate` 帶自己的憑證，用 `--set confdir=DIRECTORY` 換 CA 目錄。
來源：<https://docs.mitmproxy.org/stable/concepts/certificates/>
> 對 camera 場景的實務含意：VMS / vendor tool 常常自帶憑證驗證邏輯或直接 pin，安裝 mitmproxy CA 到 Windows 憑證存放區**不保證**它們就會信任。→ HTTPS 攔截成功率需實測（待驗證）。

### 1c. 系統 proxy 路線（Fiddler / WinINET）

- Fiddler Classic 官方定位：「A Windows-only tool that logs HTTP(s) network traffic」，可「inspect HTTP/HTTPS traffic to and from browsers and desktop apps」。
  來源：<https://www.telerik.com/fiddler/fiddler-classic>
  > 「Fiddler 會把自己註冊成系統 proxy（Act as system proxy on startup，port 8888）」這點我在 Telerik 官方文件頁面上**沒有抓到明文段落** → 標「待驗證」（需要翻 Configure Fiddler Classic 子頁）。
- **為什麼很多 camera client 不理系統 proxy（有一手佐證）**：
  - WinINET 的 `InternetOpen` 有三種 access type，其中 `INTERNET_OPEN_TYPE_PRECONFIG`「instruct your application to retrieve the configuration from the registry」，而它讀的是「the registry values **ProxyEnable**, **ProxyServer**, and **ProxyOverride** ... located under "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings"」。**程式若選 `INTERNET_OPEN_TYPE_DIRECT` 就完全不走 proxy。**
    來源：<https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality>
  - 同頁明講「WinINet does not support server implementations. In addition, it should not be used from a service. For server implementations or services use Microsoft Windows HTTP Services (WinHTTP).」→ VMS 這種以 Windows service 形式跑的軟體，**照微軟指引就不該用 WinINET**，自然也就不吃 IE/系統 proxy 設定。
    來源：<https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality>
  - WinHTTP 這邊：「AutoProxy support is not fully integrated into the HTTP stack in WinHTTP. Before sending a request, the application must call `WinHttpGetProxyForUrl` ...」，而範例中 `WinHttpOpen` 用的是 `WINHTTP_ACCESS_TYPE_NO_PROXY`「to indicate that requests are sent directly to the target server by default」。另外 `WinHttpGetIEProxyConfigForCurrentUser`「returns the current user Internet Explorer proxy settings ... without calling into "WinInet.dll"」—— 也就是**要程式自己明確去撈 IE 設定才會有 proxy**。
    來源：<https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-autoproxy-api>
  - 再加上大量 camera SDK 是直接用 Winsock / libcurl / 自寫 HTTP client 打 raw IP，根本沒有 proxy 概念。（推論）
- 另外 WinINET **預設就會 bypass** `localhost` / `loopback` / `127.0.0.1` / `[::1]`（IE9 起可用 `<-loopback>` macro 取消）。若我們的 proxy 掛在 localhost，這一條會反咬。
  來源：<https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality>

**小結**：系統 proxy 路線「零 driver、零提權」很誘人，但對本案的目標客群（vendor tool、VMS、ONVIF Device Manager）覆蓋率不可靠。可以做成「fallback / 額外模式」，不能當主力。

### 1d. Hosts 檔 / DNS 路線 —— 不適用

- 需求本身就是「使用者輸入 IP address」，client 是拿 raw IP 連線。WinINET 文件也印證 client 可以直接吃 IP：「The server name can contain either the host name (for example, "www.servername.com") or IP number of the site in ASCII dotted-decimal format (for example, "10.0.1.45")」。
  來源：<https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality>
- 走 IP 就不會發 DNS query，改 `hosts` 檔沒有任何攔截點。ONVIF 的 device discovery 也不是 DNS，是 WS-Discovery multicast（見 §2）。
- **結論：這條路直接排除。**

---

## 2. ONVIF 相關細節

（以下引自 ONVIF Core Specification，抓到的檔頁尾標示為 `ONVIF Core Spec – Ver. 26.06`）

- **傳輸**：ONVIF 建構在「XML, SOAP 1.2 [Part 1] and WSDL1.1 over an IP network」之上；且「This implies that the WSDL SOAP 1.2 bindings shall be used」（引 WS-I BP 2.0）。fault 也要照 SOAP 1.2 fault 走。
  來源：<https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf>（§5 概述、§5 服務需求段）
- **固定進入點**：「The entry point for the device management service is fixed to: `/onvif/device_service`」，而 device management service「is the entry point for all other services of the device」。
  規格中的實際請求長相：
  ```
  POST /onvif/device_service HTTP/1.1
  Host: 10.XX.XX.XX
  Content-Type: application/soap+xml; charset=utf-8
  Content-Length: 299
  ```
  Capabilities 回應中的 XAddr 範例：`<tds:XAddr>http://192.168.0.10/onvif/device_service</tds:XAddr>`
  來源：<https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf>（§5.1.1）
  > 含意：**其他 service（media / ptz / imaging / events）的 URL 是裝置自報的 XAddr，不是固定路徑**。所以 log 要記完整 path，replay 也不能假設路徑。
- **認證（§5.9）**：
  - §5.9.1：「The services defined in this standard, whenever consumed overt HTTP and HTTPS, shall be protected using digest authentication according to [RFC 2617]」，例外是 legacy 的 WS-UsernameToken 裝置、TLS client 授權、以及只在 HTTPS 上的 JWT（RFC 6750）。
  - 同節：若 device 同時支援兩者，「a web service request can be authenticated on the HTTP level via digest authentication [RFC 2617] or on the web service level via the WS-Security (WSS) framework」；client 沒帶憑證時 server 假設要用 HTTP digest，回 401。只支援 username token profile 的裝置則是回 HTTP 400 + `SOAP:Fault env:Sender ter:NotAuthorized`。
  - 「A client should not simultaneously supply authentication credentials on both the HTTP level and the WS level.」
  - §5.9.3：SHA-256 可用於 HTTP 與 RTSP digest；且「There is no ONVIF API to get the current hashing algorithm of a device, ONVIF clients should depend on HTTP or RTSP digest challenge response.」規格中的 challenge 範例：
    ```
    WWW-Authenticate: Digest algorithm=SHA-256, realm="Silvan_http_digest", qop="auth",
    nonce="62d82aa9ca59e3a04cd1", opaque="5b6ea228"
    ```
  - **§5.9.5 Username token profile（replay 的關鍵）**：「A client shall use both nonce and timestamps as defined in [WS-UsernameToken]. **The server shall reject any Username Token not using both nonce and creation timestamps.**」
  來源：<https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf>
- **WS-Security UsernameToken / PasswordDigest 的算法（OASIS 一手）**：
  - 「Passwords of type PasswordDigest are defined as being the Base64 [XML-Schema] encoded, SHA-1 hash value, of the UTF8 encoded password (or equivalent).」
  - 「Two optional elements are introduced in the `<wsse:UsernameToken>` element to provide a countermeasure for replay attacks: `<wsse:Nonce>` and `<wsu:Created>`.」
  - 公式：**`Password_Digest = Base64 ( SHA-1 ( nonce + created + password ) )`**
  - 「Note that the nonce is hashed using the octet sequence of its decoded value while the timestamp is hashed using the octet sequence of its UTF8 encoding」
  - **三條 RECOMMENDED 反 replay 措施**：
    1. 「reject any UsernameToken not using both nonce and creation timestamps」
    2. 「provide a timestamp "freshness" limitation, and that any UsernameToken with "stale" timestamps be rejected. As a guideline, **a value of five minutes** can be used as a minimum to detect, and thus reject, replays.」
    3. 「used nonces be cached for a period at least as long as the timestamp freshness limitation period ... and that UsernameToken with nonces that have already been used (and are thus in the cache) be rejected.」
  - 「Each message including a `<wsse:Nonce>` element MUST use a new nonce value in order for web service producers to detect replay attacks.」
  - 規格範例 header：
    ```xml
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>NNK</wsse:Username>
        <wsse:Password Type="...#PasswordDigest">weYI3nXd8LjMNVksCKFV8t3rgHh3Rw==</wsse:Password>
        <wsse:Nonce>WScqanjCEAC4mQoBE07sAQ==</wsse:Nonce>
        <wsu:Created>2003-07-16T01:24:32Z</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
    ```
  來源：<https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0.pdf>（ONVIF Core Spec 的 normative reference 也列了 "OASIS Web Services Security UsernameToken Profile 1.0"）
  相關版本：<https://docs.oasis-open.org/wss/v1.1/wss-v1.1-spec-os-UsernameTokenProfile.pdf>

  > **對 replay 功能的直接結論**：
  > 1. 原樣重送錄下來的 `<wsse:Security>` header，只要超過相機的 freshness 窗（規格建議 ≥5 分鐘）就會被拒；相機若有 nonce cache，即使在窗內也會被拒。
  > 2. 正確做法：replay 時**丟掉舊的 Security header，用使用者提供的帳密重新產生 nonce + created + digest**。
  > 3. 這也代表 UI 需要一個「replay 用的憑證」輸入欄位 —— 因為錄到的是 digest，**逆推不出原始密碼**（"PasswordDigest can only be used if the plain text password ... is available to both the requestor and the recipient"）。

- **WS-Discovery 不是 HTTP**：
  - ONVIF §7.1：「A client may search for available devices using the dynamic Web Services discovery protocol [WS-Discovery]」，device 要實作 Target Service role。§7.2 描述 discoverable 模式會送 multicast Hello、監聽 Probe / Resolve。
    來源：<https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf>
  - WS-Discovery spec §2.4 Protocol Assignments 明列：
    ```
    • DISCOVERY_PORT: port 3702 [IANA]
    • IPv4 multicast address: 239.255.255.250
    • IPv6 multicast address: FF02::C (link-local scope)
    ```
    且「Messages sent over UDP MUST be sent using SOAP over UDP [SOAP/UDP]」。
    來源：<http://specs.xmlsoap.org/ws/2005/04/discovery/ws-discovery.pdf>（ONVIF Core Spec normative reference 指向此 URL）
  - **含意**：ONVIF Device Manager 按「掃描」時的探測封包**不會經過任何 HTTP proxy**。若要在 UI 上呈現「device discovery」也得抓，就必須另外用 WinDivert/Npcap 監聽 UDP 3702 multicast，這是一條獨立的資料路徑。

---

## 3. CGI 相關細節

### HTTP Digest（RFC 7616）與 replay

- 參數（§3.3 challenge）：`realm`、`nonce`（「A server-specified string which should be uniquely generated each time a 401 response is made」）、`qop`（「This parameter MUST be used by all implementations」，值 `auth` / `auth-int`）、`opaque`（「a string of data, specified by the server, that SHOULD be returned by the client unchanged」）、`algorithm`（SHA-256 為必備，SHA-512/256 備援，MD5 僅為相容）、`stale`（表示「the previous request from the client was rejected because the nonce value was stale」）。
- 回應計算（§3.4.1）：
  ```
  response = KD ( H(A1), unq(nonce) ":" nc ":" unq(cnonce) ":" unq(qop) ":" H(A2) )
  A1 = unq(username) ":" unq(realm) ":" passwd            (§3.4.2)
  A2 = Method ":" request-uri                              (qop=auth, §3.4.3)
  ```
- `nc` 是「the hexadecimal count of the number of requests ... that the client has sent with the nonce value」（§3.4）。
- 反 replay（§3.3 / §5.5）：server「MAY choose not to accept a previously used nonce or previously used digest, in order to protect against a replay attack」；並且「An implementation must give special attention to the possibility of replay attacks with POST and PUT requests」。
  來源：<https://www.rfc-editor.org/rfc/rfc7616.txt>

> **對 replay 功能的直接結論**：跟 ONVIF 一樣 —— 錄到的 `Authorization: Digest ...` 幾乎必然無法重用（nonce 過期、nc 重複、opaque 不符）。Replay 引擎必須**重跑 401 challenge → 重算 response**。Python 端用 `requests.auth.HTTPDigestAuth` 就自動處理這個流程：
> ```python
> from requests.auth import HTTPDigestAuth
> requests.get(url, auth=HTTPDigestAuth('user', 'pass'))
> ```
> 來源：<https://requests.readthedocs.io/en/latest/user/authentication/>

### Vendor CGI URL 形狀（只需知道長相）

- **Axis VAPIX**：「an open application programming interface (API) developed by Axis that uses standard protocols to provide direct access and control of Axis devices」。Param API 讀寫 `/axis-cgi/param.cgi`（「enables users to read, export, and import /axis-cgi/param.cgi parameters」）。認證：文件有 Authentication 專章，說明 digest access authentication 比 basic 安全；`Network.HTTP.AuthenticationPolicy` 參數控制 HTTP/HTTPS/RTSP 的認證能力（`Basic` / `Digest` / `Basic_Digest` / `Recommended`，AXIS OS 5.70+）。
  來源：<https://developer.axis.com/vapix/>、<https://developer.axis.com/vapix/device-configuration/param-api/>、<https://developer.axis.com/vapix/authentication/>
- **Hikvision ISAPI**：官方文件在 Technology Partner Program 入口 <https://tpp.hikvision.com/download/ISAPI_OTAP>，**需要簽 Materials License Agreement 才能下載**（＝一手文件受管制，我沒辦法在此引用內文）。ISAPI 是 HTTP 之上、REST 風格的應用層協定，URL 形如 `/ISAPI/System/TwoWayAudio/channels/<ID>`。
  來源：<https://tpp.hikvision.com/download/ISAPI_OTAP>、<https://tpp.hikvision.com/tpp/IntegrationCenter>
  > 標「待驗證」：具體端點清單無法從公開一手來源取得，實作時以實測抓到的封包為準（這也正好是本工具的價值）。
- **Dahua HTTP API**：URL 形如 `http://<ip>/cgi-bin/magicBox.cgi?action=getProductDefinition&name=...`、`http://<ip>/cgi-bin/configManager.cgi?action=getConfig` / `action=setConfig`。
  **待驗證**：我沒有找到 dahuasecurity.com 官方公開託管的 HTTP API 文件 URL；流通的 PDF（v1.40 / v2.0 / v2.63）都掛在第三方站點，不算 primary source。實作前建議向 Dahua 索取官方版本。
- **`/stw-cgi/`**：這是 Hanwha（Samsung）Wisenet 的 SUNAPI 路徑前綴。**待驗證**：未取得 Hanwha 官方公開文件 URL。

### RTSP（port 554）要不要記？

- RTSP 是獨立的 application-layer protocol，不是 HTTP。RFC 7826（RTSP 2.0）：「For the scheme 'rtsp', if no port number is provided in the authority part of the URI, the port number 554 MUST be used」；且「RTSP 2.0 requires clients and servers to implement TCP and TLS over TCP as mandatory transports for RTSP messages」，並支援 §14 "Embedded (Interleaved) Binary Data"（RTP over TCP 交錯）。
  來源：<https://www.rfc-editor.org/rfc/rfc7826.txt>
  （多數相機實作的是 RTSP 1.0 / RFC 2326，port 同為 554 —— 待驗證，本次未取 RFC 2326 原文。）

**建議**：
- **v1 不做 RTSP payload 解析**。RTSP 的 DESCRIBE/SETUP/PLAY 訊息文法雖然像 HTTP，但 mitmproxy 的 HTTP 層不會解它，而且一旦 PLAY 之後就是 interleaved binary RTP，量大且對「指令 log」沒有價值。
- **但值得記一筆「有 RTSP 連線發生」**：可用 mitmproxy 的 `tcp_hosts` 把 554 當 generic TCP 攔下只記 metadata，或用 WinDivert 的 FLOW layer 記「哪支 process 在 t 時刻開了到 camera:554 的連線」。這對「模擬錄下來的行為」很有用（知道何時該起串流）。
  來源（能力佐證）：<https://docs.mitmproxy.org/stable/concepts/options/>、<https://reqrypt.org/windivert-doc.html>

---

## 4. Replay 工具

| 工具 | 能做什麼 | 對本案的適配 |
|---|---|---|
| **mitmproxy client replay** | 「you provide a previously saved HTTP conversation, and mitmproxy replays the client requests one by one」；`mitmdump -w <file>` 錄、`mitmdump -C <file>` 放。也可 `-C` 多次指定。<br>來源：<https://docs.mitmproxy.org/stable/overview/features/>、<https://docs.mitmproxy.org/stable/tutorials/client-replay/>、<https://docs.mitmproxy.org/stable/concepts/options/> | ✅ 天然搭配（我們本來就用 mitmproxy 錄）。❌ 但它是**原樣重送**，認證 header 會過期 → 必須配一個 addon 在 `request` hook 裡重寫認證。 |
| **mitmproxy addon 自寫 replay** | 讀 flow file / HAR，用 `request` hook 改寫 header 後送出 | ✅ 最可控。建議主力。 |
| **goreplay** | 「an open-source tool for capturing and replaying live HTTP traffic」；`--input-raw :8000`（像 tcpdump）、`--output-http http://staging.env`、`--input-file`。<br>來源：<https://github.com/buger/goreplay> | ⚠️ Windows 是次等公民：官方 Windows 頁明說「Pcap on Windows is not Unix」、「Install Npcap for local/loopback traffic」，並指向已知問題 issue #440。<br>來源：<https://goreplay.org/docs/windows/> ｜ 而且它是 HTTP-only 的 raw 重放，同樣不處理 digest/nonce。**不建議。** |
| **Python `requests` + `HTTPDigestAuth`** | `requests.get(url, auth=HTTPDigestAuth('user','pass'))` 自動走 401 challenge → 重算 response。<br>來源：<https://requests.readthedocs.io/en/latest/user/authentication/> | ✅ CGI replay 的正解。 |
| **python-onvif-zeep** | `ONVIFCamera('192.168.0.2', 80, 'user', 'passwd', '/etc/onvif/wsdl/')`。<br>來源：<https://github.com/FalkTannhaeuser/python-onvif-zeep> | ✅ 若要「重新產生合法 WS-Security token」，走底層 zeep 即可。 |
| **zeep `UsernameToken`** | 「The UsernameToken supports both the passwordText and passwordDigest methods」，「To use the passwordDigest method you need to supply `use_digest=True`」；另有 `timestamp_token` 參數。<br>來源：<https://docs.python-zeep.org/en/master/wsse.html> | ✅ 這就是重新產生 nonce/created/digest 的機制。<br>⚠️ 待驗證：zeep 內部 nonce 產生與 `created` 時區處理細節文件沒寫，需讀 `zeep/wsse/username.py` 原始碼確認。 |

**建議的 replay 語意**（設計決策，非引用）：
- 儲存的是「**指令意圖**」：timestamp、method、完整 URI、headers（標記哪些是認證用、replay 時要重生）、body。
- Replay 時：
  1. 剝掉 `Authorization` / `<wsse:Security>`；
  2. 用使用者在 UI 輸入的帳密重建；
  3. 依錄製時的相對時間差重播（或使用者選「全速」）；
  4. 記錄每筆的實際 response code 做 diff。

---

## 5. UI 技術選型（Python 為前提）

- **pywebview**：「a lightweight native webview wrapper that allows to display HTML content in its own native GUI window」；「It uses native GUI for creating a web component window: WinForms on Windows, Cocoa on macOS and QT or GTK on Linux」。Windows 上可用 renderer：Edge/Chromium（WebView2）、CEF、QT；需要 `pythonnet`（.NET 4.0+），CEF 需 `cefpython`，WebView2 Runtime 要另外安裝，散佈 WebView2 需遵守微軟的 distribution guidelines。
  來源：<https://pywebview.flowrl.com/guide/>、<https://pywebview.flowrl.com/guide/installation.html>
  > 適合本案：log 表格 + 篩選 + 下載按鈕，用 HTML/JS 做最快；Python 端專心處理 WinDivert/mitmproxy。
  > 待驗證：pywebview 在 Windows 的**預設** renderer 為何，文件未明說。
- **PySide6 / Qt for Python**：官方文件站 <https://doc.qt.io/qtforpython-6/>。
  **待驗證**：我這次沒抓到 PySide6 授權條款的一手明文段落（LGPLv3 / GPLv3 / commercial 三選一是常識但需查 <https://www.qt.io/licensing/> 確認），若產品要商業散佈務必先確認。
- **Tauri / Electron**：需改用 Rust / Node 生態，與 Python 的 mitmproxy addon、pydivert 就得跨語言 IPC。若最終決定用 mitmproxy 當引擎，Python UI 明顯較省事。（本次未做一手調查 → 待驗證）
- **打包（PyInstaller）**：
  - `-F, --onefile`：「Create a one-file bundled executable.」
  - `-i, --icon <FILE.ico ...>`：「FILE.ico: apply the icon to a Windows executable.」
  - **`--uac-admin`：「Using this option creates a Manifest that will request elevation upon application start.」← 這就是 WinDivert/Npcap 需要的提權開關**
  - `--uac-uiaccess`：「allows an elevated application to work with Remote Desktop」
  來源：<https://pyinstaller.org/en/stable/usage.html>
  > 待驗證：把 mitmproxy（含 `mitmproxy-windows` 的 `windows-redirector.exe` 與 WinDivert driver 檔）一起 PyInstaller 打包是否可行、driver 檔能否從 onefile 的 temp 目錄載入。**這是最需要早期做 spike 的技術風險。**

---

## 6. 已存在的開源／現成工具（先確認要不要自己造）

| 工具 | 一手來源 | 它已經做到什麼 | 缺什麼（＝我們的空間） |
|---|---|---|---|
| **mitmproxy / mitmweb** | <https://docs.mitmproxy.org/stable/overview/features/> | 攔截、修改、client/server replay、flow 存檔、HAR dump、addon scripting、Windows local capture | 沒有「輸入一個 camera IP」的一鍵 UI；local mode 只能挑 process；Windows local capture「limited to CLI invocations for now」、憑證自動安裝與 mitmweb UI 整合尚未實作（<https://www.mitmproxy.org/posts/local-capture/windows/>）；不懂 ONVIF 語意 |
| **Fiddler Classic** | <https://www.telerik.com/fiddler/fiddler-classic> | Windows-only、記錄 HTTP(S)、可 inspect/compose/mock/modify | 走系統 proxy → 不理 proxy 的 client 抓不到（見 §1c）；ONVIF SOAP 只當一般 body |
| **HTTP Toolkit** | <https://httptoolkit.com/docs/getting-started/intercepting/> | Chrome 攔截、Fresh Terminal（「Terminal interception should be available on all machines」）、多語言 client 自動攔截、手動 proxy | 攔截點是「啟動一個被設定好的 process」，對**已經在跑的 vendor tool / Windows service** 無效；不懂 ONVIF |
| **Wireshark / tshark** | <https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html> | 完整 dissector、TCP reassembly、ONVIF SOAP 也看得到 XML | 被動、HTTPS 無解、掉包就重組失敗、**完全不能 replay** |
| **Proxyman / Charles** | （本次未做一手調查） | — | 待驗證：Windows 支援與攔截機制 |
| **onvif-cli**（quatanium/python-onvif） | <https://github.com/quatanium/python-onvif> | CLI + 互動式 shell：`onvif-cli devicemgmt GetHostname --user 'admin' --password '12345' --host '192.168.0.112' --port 80`，支援 batch pipe | 是**主動發送**工具，不是攔截／記錄工具 |
| **python-onvif-zeep** | <https://github.com/FalkTannhaeuser/python-onvif-zeep> | `ONVIFCamera(ip, port, user, pass, wsdl_dir)`，zeep 當 SOAP client | 同上，且 README 未著墨認證細節 |
| **Happytime ONVIF Client / Server** | <https://happytimesoft.com/product.html>、<https://www.happytimesoft.com/products/onvif-client/index.html>、<https://www.happytimesoft.com/products/multi-onvif-server/index.html> | ONVIF client（Profile S/G/C/T/M/A）、ONVIF Server 模擬器、Multi ONVIF Server 可模擬多達 400 台虛擬裝置 | 商業軟體；是 client / 模擬 device，不是「攔截本機其他軟體」 |
| **ONVIF Device Manager** | （開源，常見於 ONVIF 生態） | ONVIF 裝置管理 GUI | 待驗證：它是否有內建 SOAP log 匯出功能；本次未取得一手 repo/文件 URL |
| **ONVIF Explorer**（dev-sunghwan） | <https://github.com/dev-sunghwan/onvif_explorer/> | 瀏覽器版 ONVIF SOAP 指令測試器，可看 parsed JSON 與 raw SOAP XML | 主動測試工具，非攔截器 |

**結論**：沒有現成工具同時滿足「依 IP 攔截本機所有軟體 + ONVIF/CGI 語意化顯示 + 一鍵 replay」。但**mitmproxy 已經提供了 80% 的引擎**，本案的價值在於那層「camera 語意 + 單一 IP 的一鍵操作 UI + 認證重生的 replay」。

---

## 7. 攔截方式比較表

| 方式 | 需要 admin？ | 看得到 HTTP body？ | 看得到 HTTPS 明文？ | client 不理 proxy 也抓得到？ | 需要裝 Windows driver？ | 授權風險 |
|---|---|---|---|---|---|---|
| **Npcap 被動側錄**（Wireshark / pyshark / scapy） | 是（Admin-only Mode 時必然）<sup>[1]</sup> | 是，但依賴 TCP reassembly，掉包即失敗<sup>[2]</sup> | **否** | 是（完全被動） | **是**（Npcap driver）<sup>[1]</sup> | **高**：free license 禁止 redistribution，限 5 台<sup>[3]</sup> |
| **WinDivert 自寫轉導 → 本機 proxy** | **是**（`ERROR_ACCESS_DENIED` 明載）<sup>[4]</sup> | 是（proxy 端完整 stream） | 是（需自建 MITM + client 信任 CA） | **是**（在 network layer 改封包，不管 client 設定）<sup>[4]</sup> | **是**（官方預編已簽章）<sup>[4]</sup> | 低：LGPLv3 / GPLv2 雙授權<sup>[5]</sup> |
| **mitmproxy `--mode local`**（Windows = WinDivert redirector） | **是**（privileged redirector）<sup>[6]</sup> | 是 | 是（需安裝 mitmproxy CA）<sup>[7]</sup> | **是** | **是**（隨 `mitmproxy-windows` 帶的 WinDivert）<sup>[8]</sup> | 低 |
| **mitmproxy `--mode transparent`** | — | — | — | — | — | **Windows 不支援**（_Availability: Linux, macOS_）<sup>[9]</sup> |
| **mitmproxy `--mode regular` / Fiddler（系統 proxy）** | 否 | 是 | 是（需信任 CA） | **否**（WinHTTP 預設 `WINHTTP_ACCESS_TYPE_NO_PROXY`；WinINET 需 `INTERNET_OPEN_TYPE_PRECONFIG`）<sup>[10][11]</sup> | 否 | 低 |
| **mitmproxy `--mode reverse:`** | 否 | 是 | 是 | 否（需要把 client 指到 proxy，等於改設定） | 否 | 低 |
| **mitmproxy `--mode wireguard`** | 否（「Runs in userspace; no admin privileges needed for server」）<sup>[9]</sup> | 是 | 是 | 只對「能匯入 WireGuard config 的裝置」有效，不適合同機 Windows app | 否（需 WireGuard client） | 低 |
| **goreplay `--input-raw`** | 是（pcap） | 是（HTTP-only） | 否 | 是 | 是（Npcap）<sup>[12]</sup> | 同 Npcap |

<sup>[1]</sup> <https://npcap.com/guide/> ｜ <sup>[2]</sup> <https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html> ｜ <sup>[3]</sup> <https://npcap.com/#download> ｜ <sup>[4]</sup> <https://reqrypt.org/windivert-doc.html> ｜ <sup>[5]</sup> <https://github.com/basil00/WinDivert> ｜ <sup>[6]</sup> <https://www.mitmproxy.org/posts/local-capture/windows/> ｜ <sup>[7]</sup> <https://docs.mitmproxy.org/stable/concepts/certificates/> ｜ <sup>[8]</sup> <https://github.com/mitmproxy/mitmproxy_rs> ｜ <sup>[9]</sup> <https://docs.mitmproxy.org/stable/concepts/modes/> ｜ <sup>[10]</sup> <https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality> ｜ <sup>[11]</sup> <https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-autoproxy-api> ｜ <sup>[12]</sup> <https://goreplay.org/docs/windows/>

---

## 8. 建議架構（一句話版）

```
[使用者輸入 camera IP]
        │
        ▼
[mitmproxy --mode local  (Windows = WinDivert redirector, 需 UAC 提權)]
        │  --allow-hosts '^<camera-ip>(:\d+)?$'
        ▼
[自寫 addon: request/response hook]
        ├─→ 分類：ONVIF (POST + application/soap+xml, path 含 /onvif/) vs CGI (/cgi-bin/, /ISAPI/, /stw-cgi/)
        ├─→ ONVIF 再解 SOAP Body 第一個子元素 = 指令名 (GetDeviceInformation…)
        ├─→ 存成內部 log（timestamp + method + URI + headers + body + status）
        └─→ 推到 UI (pywebview / WebSocket)
                │
                ├─→ [下載 log] : mitmproxy flow file (-w) 或 HAR (hardump)
                └─→ [Replay]   : 讀回 flow → 剝除認證 header → requests/HTTPDigestAuth 或 zeep UsernameToken(use_digest=True) 重生 → 重送
```

---

## 9. Open questions（待驗證 / 待拍板）

**技術風險（建議先做 spike）**
1. **PyInstaller 打包 mitmproxy + `mitmproxy-windows` 的 WinDivert driver 是否可行？** onefile 模式下 `.sys` driver 檔從 temp 目錄載入會不會被 Windows 拒絕？→ **最高優先，這決定整個架構可不可行。**
2. **`--mode local` + `allow_hosts` 的組合實際行為**：redirector 已經把全機（或指定 process）的封包轉進來了，`allow_hosts` 是在 proxy 層過濾還是會 passthrough？非 allow 的流量會不會被劣化（延遲、斷線）？→ 需實測，這關係到「開著我們的工具時，機器上其他網路活動會不會受影響」。
3. **HTTPS camera 的 MITM 成功率**：vendor tool / VMS 是否接受安裝到 Windows Root Store 的 mitmproxy CA？有沒有 certificate pinning？→ 需拿實機測。
4. **是否乾脆繞過 mitmproxy 自己用 pydivert + 自寫 HTTP parser？** 好處是 filter 直接就是 `ip.DstAddr == <IP>`（原生依 IP，不必繞 `allow_hosts`）、依賴少、打包簡單；壞處是要自己做 TCP reassembly、TLS MITM、replay。→ 建議先試 mitmproxy，2 卡住再退這條。
5. **pydivert 版本**：GitHub 說 4.0.0 bundle WinDivert 2.2.2，PyPI 顯示 3.1.3（2026-05-15）—— 兩者不一致，安裝前確認。

**需求面待拍板**
6. **RTSP（554）要不要記？** 建議 v1 只記「連線發生」的 metadata，不解 payload。需使用者確認是否夠用。
7. **WS-Discovery（UDP 3702 multicast）要不要記？** 這是完全獨立的資料路徑（不經 HTTP proxy），做了會增加一個 WinDivert UDP filter。需確認「攔截 ONVIF 指令」是否包含 discovery。
8. **Replay 的憑證從哪來？** 錄下的 digest 逆推不出密碼（OASIS 明載），所以 UI 必須讓使用者另外輸入帳密。這是否可接受？
9. **Replay 的時序語意**：照原始時間間隔重播 vs 全速連發 vs 單筆手動觸發？（會影響相機的 nonce cache 行為）
10. **只攔一台 camera，還是允許多台／整個網段？** 影響 filter 設計與 UI。
11. **散佈方式**：若最終仍需 Npcap（例如做 WS-Discovery 監聽），free license 禁止 redistribution 且限 5 台 —— 是內部自用（可接受）還是要外部交付（需買 OEM license）？

**文件缺口（一手來源沒拿到）**
12. Hikvision ISAPI 官方文件受 TPP NDA 管制，無法引用內文。
13. Dahua HTTP API 沒有找到官方公開託管的文件 URL（流通版本皆為第三方鏡像）。
14. `/stw-cgi/`（Hanwha SUNAPI）官方文件 URL 未取得。
15. Fiddler Classic「註冊為系統 proxy / port 8888」的官方明文段落未抓到。
16. PySide6 授權條款一手明文未抓到（需查 <https://www.qt.io/licensing/>）。
17. pywebview 在 Windows 的預設 renderer 未在文件中明說。
18. Proxyman / Charles 在 Windows 的攔截機制未做一手調查。
19. ONVIF Device Manager 是否內建 SOAP log 匯出，未做一手調查。
20. RTSP 1.0（RFC 2326）原文未取，本文 RTSP 段落引用的是 RFC 7826（RTSP 2.0）。

---

## 附錄：本文引用的一手來源清單

**攔截 / 驅動**
- WinDivert 文件：<https://reqrypt.org/windivert-doc.html>
- WinDivert repo（授權、版本）：<https://github.com/basil00/WinDivert>
- pydivert：<https://github.com/ffalcinelli/pydivert>、<https://pypi.org/project/pydivert/>
- Npcap Guide：<https://npcap.com/guide/>
- Npcap 下載／授權：<https://npcap.com/#download>
- scapy 安裝（Windows）：<https://scapy.readthedocs.io/en/latest/installation.html>
- pyshark：<https://github.com/KimiNewt/pyshark>
- Wireshark 重組：<https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html>

**mitmproxy**
- Proxy Modes：<https://docs.mitmproxy.org/stable/concepts/modes/>
- Options：<https://docs.mitmproxy.org/stable/concepts/options/>
- Event Hooks API：<https://docs.mitmproxy.org/stable/api/events.html>
- Anatomy of an addon：<https://docs.mitmproxy.org/stable/addons/overview/>
- Certificates：<https://docs.mitmproxy.org/stable/concepts/certificates/>
- Features（client/server replay 定義）：<https://docs.mitmproxy.org/stable/overview/features/>
- Client replay tutorial：<https://docs.mitmproxy.org/stable/tutorials/client-replay/>
- Intercepting Windows Applications（local capture 實作）：<https://www.mitmproxy.org/posts/local-capture/windows/>
- mitmproxy_rs：<https://github.com/mitmproxy/mitmproxy_rs>
- mitmproxy_rs.local API：<https://mitmproxy.github.io/mitmproxy_rs/mitmproxy_rs/local.html>

**Windows proxy 機制**
- WinINET Enabling Internet Functionality：<https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality>
- WinHTTP AutoProxy：<https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-autoproxy-api>

**協定規格**
- ONVIF 規格總覽：<https://www.onvif.org/profiles/specifications/>
- ONVIF Core Specification（Ver. 26.06）：<https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf>
- WS-Discovery（2005/04）：<http://specs.xmlsoap.org/ws/2005/04/discovery/ws-discovery.pdf>
- OASIS WSS UsernameToken Profile 1.0：<https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0.pdf>
- OASIS WSS UsernameToken Profile 1.1：<https://docs.oasis-open.org/wss/v1.1/wss-v1.1-spec-os-UsernameTokenProfile.pdf>
- RFC 7616（HTTP Digest）：<https://www.rfc-editor.org/rfc/rfc7616.txt>
- RFC 7826（RTSP 2.0）：<https://www.rfc-editor.org/rfc/rfc7826.txt>

**Vendor API**
- Axis VAPIX：<https://developer.axis.com/vapix/>、<https://developer.axis.com/vapix/device-configuration/param-api/>、<https://developer.axis.com/vapix/authentication/>
- Hikvision ISAPI（需簽約）：<https://tpp.hikvision.com/download/ISAPI_OTAP>

**Replay / client 函式庫**
- requests Authentication：<https://requests.readthedocs.io/en/latest/user/authentication/>
- zeep WSSE：<https://docs.python-zeep.org/en/master/wsse.html>
- python-onvif-zeep：<https://github.com/FalkTannhaeuser/python-onvif-zeep>
- python-onvif / onvif-cli：<https://github.com/quatanium/python-onvif>
- goreplay：<https://github.com/buger/goreplay>、<https://goreplay.org/docs/windows/>

**UI / 打包**
- pywebview：<https://pywebview.flowrl.com/guide/>、<https://pywebview.flowrl.com/guide/installation.html>
- PyInstaller usage：<https://pyinstaller.org/en/stable/usage.html>

**既有工具**
- Fiddler Classic：<https://www.telerik.com/fiddler/fiddler-classic>
- HTTP Toolkit 攔截說明：<https://httptoolkit.com/docs/getting-started/intercepting/>
- Happytimesoft：<https://happytimesoft.com/product.html>
- ONVIF Explorer：<https://github.com/dev-sunghwan/onvif_explorer/>
