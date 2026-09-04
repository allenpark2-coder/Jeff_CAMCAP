# camcap — camera command interceptor

輸入 camera IP → 攔截這台 Windows 上所有送往該 IP 的 CGI / ONVIF（順帶 RTSP、私有協定計數、WS-Discovery）→ UI 顯示指令與時間 → 下載 JSONL / HAR → 一鍵重播到同一台或另一台 camera。

- 研究：`docs/research/camera-command-interceptor.md`
- 設計與決策：`docs/design/camera-command-interceptor-proposal.md`

## 架構一句話

WinDivert（pydivert）把送往 camera 的封包改道到本機的透明 TCP relay；relay 原樣轉送、把 bytes 複製給 h11 被動解碑器；重播引擎重新產生 Digest / WS-UsernameToken 認證後送出。

```
client app ──► WinDivert 改 dst ──► Relay(0.0.0.0:N) ──► camera
                                      │ tee
                                      ▼
                                 decoders → LogStore → UI / JSONL / HAR → Replayer
```

## 開發（Linux / macOS，不需 driver）

```bash
uv venv --python 3.12 .venv && source .venv/bin/activate
uv pip install -e '.[dev]'
pytest -q
# 手動玩：relay only，把 client 指向 relay port
camcap capture 192.168.1.64 --test-mode --test-port 80 --out log.jsonl
camcap replay log.jsonl --target 192.168.1.99 --user admin --password xxx --speed 0
```

## Linux 真正攔截（iptables REDIRECT，需 root）

```bash
# 三行規則（camcap capture 若能 sudo -n 會自己下；不能就手動）
sudo iptables -t nat -N CAMCAP
sudo iptables -t nat -A CAMCAP -d <camIP> -p tcp -m multiport ! --sports 40000:40999 -j REDIRECT --to-ports 38080
sudo iptables -t nat -A OUTPUT -j CAMCAP
camcap capture <camIP> --relay-port 38080 --external-rules      # 之後本機任何程式連 camIP 都會被記錄
# 收工
sudo iptables -t nat -D OUTPUT -j CAMCAP; sudo iptables -t nat -F CAMCAP; sudo iptables -t nat -X CAMCAP
```

## 2026-09-04 真機結果（CV75 devkit 10.253.58.186，test-mode relay，不需 root）

- Web API（HTTP Digest，`/api/v1/*`）12 筆：401/200 配對、錯密碼 401/401、首頁 200 全部正確解出；重播 12/12 status 一致。
- RTSP：OPTIONS / DESCRIBE（含 392 B SDP）正確配對。
- **發現：板上 httpd 接受 Digest nonce 重用**——原封重送抓到的 `Authorization` 直接 200，re-auth 路徑根本沒被用到。對本工具是好消息（raw replay 可行），對 firmware 是安全面待議事項。
- ONVIF 板上沒有（`/onvif/device_service` 404），ONVIF 路徑目前只有 fake camera 驗證。
- **透明攔截（iptables REDIRECT + `--external-rules`）也通了**：curl、ffprobe 直接連板子，10 筆全部進 log，含完整 RTSP 會話 OPTIONS→DESCRIBE→SETUP×2→PLAY→TEARDOWN（ffprobe 走 TCP interleaved，RTP 資料沒干擾解碼）。踩到的坑：手動貼規則時 `--to-ports` 被吃掉會產生一條「導到同 port」的規則而且先匹配，症狀是 0 ms connection refused；用 `iptables -t nat -S | grep CAMCAP` 核對。
- 遮罩後的樣本 log：`docs/samples/`。

## Windows（真正攔截）

VirtualBox 開發時：Linux 端 `git archive` 到共享資料夾，Windows 端以**系統管理員** PowerShell 執行
`tools\setup-windows.ps1`（會複製到 `%USERPROFILE%\camcap`、建 venv、裝套件、跑測試、印出下一步）。手動則：

```powershell
py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e .[windows,dev]
# 以系統管理員開 PowerShell
camcap capture 192.168.1.64            # headless
camcap                                 # UI
.\tools\build.ps1                      # PyInstaller onedir
```

## 2026-09-04 Windows 真機結果（同一塊 CV75 devkit，WinDivert 真攔截）

- **`WinError 87` 的病因是 filter 語法**：WinDivert 的 `not` 只能套在單一 test 上，
  不能套括號子運算式。`not (A and B)` 改成 De Morgan 展開的 `(¬A or ¬B)` 就通了。
  細節與證據見 `docs/windows-debug-log.md`。
- 瀏覽器直連 `http://<cam>/` 的流量 90 秒抓到 **140 筆**，全部正確解出；
  `sc query WinDivert` = RUNNING。遮罩後樣本：`docs/samples/cv75-devkit-windivert-2026-09-04.jsonl`。
- 這塊板子的 Web UI 走 **cookie session（`POST /api/v1/auth/login`）不是 Digest**，
  所以 replay 的 re-auth 路徑這次沒被用到；cookie 重播尚未驗證。
- httpd 對每個 request 都回 `Connection: close`（即使 client 要 keep-alive），
  首頁一次載入開了 140 條 TCP 連線 —— firmware 面的效能議題，跟「Digest nonce 可重用」一起議。

驗證腳本（輸出寫成 `docs/windows-verify-{1,2}.txt`）：

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1          # 不需 admin
powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Live    # 需系統管理員
```

### 尚未實機驗證（Windows 端）
1. ~~pydivert 3.x 的 Packet 屬性與 `Flag.SNIFF` 名稱~~ → 3.1.3 與 2.x 介面一致，已驗。
2. ~~改寫 dst 到網卡 IP 再注入，client 是否正確收到回應~~ → 已驗，瀏覽器正常收到回應。
3. PyInstaller onefile 內含 WinDivert `.sys` 從 temp 目錄載入是否被擋；不行就用 onedir。
4. pywebview 在 Windows 使用 EdgeChromium (WebView2) runtime，目標機需已安裝。
5. ~~`redact_event()` 不會遮 JSON 登入 body~~ → 已補：JSON/form 的 password/token 類 key、Cookie/Set-Cookie、session token 一律遮（`test_redaction_covers_json_login_form_and_cookies`）。
6. WebSocket（`/ws/events`）升級後的 frame 沒解析。
