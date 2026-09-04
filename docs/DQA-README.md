# camcap — 給 DQA 的使用說明

抓「這台電腦送給某台 camera 的所有指令」，看得到、存得下來、可以重播到另一台 camera。
攔的是 CGI / Web API / ONVIF / RTSP，不用改 camera、不用裝憑證、不用設 proxy。

版本：0.1.0（2026-09-04 first drop）

---

## 需要什麼

| 項目 | 說明 |
|---|---|
| Windows 10 / 11 **64-bit** | 32-bit 不支援 |
| **系統管理員權限** | 攔截靠 WinDivert kernel driver，第一次跑會裝一個 service。沒有管理員權限**完全不能用** |
| WebView2 Runtime | UI 需要。Win11 和有 Edge 的 Win10 通常已內建；沒有的話裝 Microsoft Edge WebView2 Runtime |
| 跟 camera 同網段 | 不用同網段也行，能 route 到就好 |

不需要裝 Python。

## 怎麼跑

1. 解壓縮 zip 到任何資料夾（**不要**放在 `C:\Program Files`，權限會卡）。
2. 在 `camcap.exe` 上按右鍵 →「以系統管理員身分執行」。
   （它自己會跳 UAC，按「是」。）
3. UI 開起來後輸入 camera IP，按開始。
4. 接著就照平常的方式操作 —— 用瀏覽器開 camera 的 Web UI、用 ODM 工具、用你自己的測試程式，
   **只要這台電腦連到那個 IP，指令就會被記下來**，不用把工具指向 camcap。
5. 要交件時按下載，會得到 `.jsonl`（給工程師看）或 `.har`（可以丟進 Chrome DevTools）。

### 命令列（不開 UI）

在**系統管理員** PowerShell / CMD：

```
camcap.exe capture 192.168.1.64 --out log.jsonl --redact
```

指令會一筆一筆印在畫面上，按 Ctrl-C 收工並寫檔。

重播到另一台 camera：

```
camcap.exe replay log.jsonl --target 192.168.1.99 --user admin --password xxxx --speed 0
```

`--speed 0` = 用最快速度重播，`--speed 1` = 照原本的時間間隔。

---

## 重要：交件前請加 `--redact`

log 裡會有帳號密碼、session cookie、Authorization header。
**要把 log 給客戶或貼進 ticket 之前，請用 `--redact`**（UI 下載時勾「遮罩」）。
遮罩後密碼類欄位會變成 `<redacted>`，帳號和 URL 保留。

> 遮罩過的 log 沒辦法用「原封重送」的方式重播（設計如此），但帶 `--user` / `--password`
> 的重新認證重播還是可以。

## 幾個可能會遇到的狀況

| 症狀 | 原因 / 處理 |
|---|---|
| 沒跳 UAC、按了沒反應 | 沒有用「以系統管理員身分執行」。攔截一定要管理員 |
| 防毒 / EDR 把它擋掉或直接刪掉 | 這是封包攔截工具，被誤判很正常。請找 IT 加白名單，**不要**自己關防毒 |
| 開起來但一筆都沒抓到 | 確認輸入的 IP 就是你實際在連的那個 IP；如果流量是別台機器發的，這台電腦攔不到 |
| `WinDivert` 相關錯誤、或裝不起 driver | 機器開了 HVCI / driver blocklist。請把畫面上的錯誤整段回報 |
| UI 開起來是白的 | 缺 WebView2 Runtime，裝一下 |

## 已知限制（這版還沒做/沒驗）

1. **ONVIF 沒有在真機驗過** —— 手上的 CV75 devkit 沒有 `/onvif/device_service`。
   ONVIF 解碼與 WS-UsernameToken 重新簽章目前只在 fake camera 上驗過。
2. **WebSocket 只記到升級那一筆**，之後的 frame 不解析（例如 `/ws/events`）。
3. **cookie session 的重播沒驗過。** 走 HTTP Digest 的 camera 重播已驗；
   走 `POST /api/v1/auth/login` + cookie 的（例如 CV75 devkit 的新 Web UI）還沒。
4. 只攔 **IPv4**。
5. 只攔**這台電腦自己發出去的**流量，不是整個網段的。

## 回報問題

請一起附上：

1. `--redact` 過的 `.jsonl`
2. 畫面上的錯誤訊息（整段，不要只截一行）
3. camera 型號 / 韌體版本、你當時在做什麼操作

---

聯絡：小張（韌體）
