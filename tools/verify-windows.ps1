<#
.SYNOPSIS
  camcap Windows 端驗證，輸出寫成檔案讓 Linux 端 / Claude 直接讀。

  powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1           # 1 語法+單元測試   不需 admin
  powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Live     # 2 實機攔截 90s    需要 admin
  powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Build    # 3 PyInstaller+zip 不需 admin
  powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Smoke    # 4 測打包後的 exe  需要 admin

  第 3 段刻意不要提權：PyInstaller 6.x 在 admin 下會警告，7.0 會直接擋。
#>
param(
  [switch]$Live,
  [switch]$Build,
  [switch]$Smoke,
  [string]$Cam = "10.253.58.186",
  [int]$Seconds = 90
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
Set-Location $root

if (-not (Test-Path $py)) {
  Write-Host "找不到 $py — 先跑 tools\setup-windows.ps1 建 venv" -ForegroundColor Red
  exit 2
}

$stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$env:PYTHONUNBUFFERED = "1"
$env:PYTHONIOENCODING = "utf-8"
# python 用 utf-8 吐出來，主控台預設是 cp950；不對齊的話連 Tee 出來的檔案都是亂碼
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

function Test-Elevated {
  ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Save-Log($captured, $path) {
  $captured | Out-File -FilePath $path -Encoding utf8
  Write-Host "`n>>> 寫到 $path" -ForegroundColor Green
}

$exe = Join-Path $root "dist\camcap\camcap.exe"

if ($Build) {
  $out = Join-Path $root "docs\windows-verify-3.txt"
  if (Test-Elevated) {
    Write-Host "注意：這一段最好用**非**系統管理員的 PowerShell 跑（PyInstaller 7.0 會擋提權執行）。" -ForegroundColor Yellow
  }
  $zip = Join-Path $root ("camcap-windows-" + (Get-Date -Format "yyyyMMdd") + ".zip")
  & {
    "=== camcap Windows verify part 3 (build) $stamp ==="
    "root: $root   elevated: $(Test-Elevated)"
    ""
    "--- tools\build.ps1 (onedir, console) ---"
    & (Join-Path $root "tools\build.ps1")
    ""
    "--- dist 內容 ---"
    if (Test-Path $exe) {
      $sz = (Get-ChildItem (Join-Path $root "dist\camcap") -Recurse -File | Measure-Object -Property Length -Sum).Sum
      "camcap.exe OK, dist 總大小 {0:N1} MB" -f ($sz / 1MB)
      "--- 打包成 zip ---"
      Copy-Item (Join-Path $root "docs\DQA-README.md") (Join-Path $root "dist\camcap\") -Force -ErrorAction SilentlyContinue
      Remove-Item $zip -ErrorAction SilentlyContinue
      Compress-Archive -Path (Join-Path $root "dist\camcap\*") -DestinationPath $zip
      "zip: $zip  ({0:N1} MB)" -f ((Get-Item $zip).Length / 1MB)
      ""
      "下一步（系統管理員 PowerShell）："
      "  powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Smoke"
    } else {
      "camcap.exe 不存在 — 打包失敗，上面的 pyinstaller 輸出就是原因"
    }
  } | Tee-Object -Variable captured
  Save-Log $captured $out
}
elseif ($Smoke) {
  $out = Join-Path $root "docs\windows-verify-4.txt"
  if (-not (Test-Elevated)) {
    Write-Host "這一段需要「以系統管理員身分執行」的 PowerShell（exe 帶 --uac-admin，" -ForegroundColor Red
    Write-Host "非提權 shell 每次啟動它都會跳 UAC，腳本會卡住）。" -ForegroundColor Red
    exit 3
  }
  if (-not (Test-Path $exe)) {
    Write-Host "還沒有 $exe — 先跑 -Build" -ForegroundColor Red
    exit 4
  }
  $so = Join-Path $env:TEMP "camcap-smoke-out.txt"
  $se = Join-Path $env:TEMP "camcap-smoke-err.txt"
  Write-Host ""
  Write-Host "接下來 30 秒用**打包後的 exe** 攔截 $Cam。" -ForegroundColor Yellow
  Write-Host "請在這段時間內用瀏覽器開 http://$Cam/ 點一兩頁（只瀏覽、只 GET）。" -ForegroundColor Yellow
  Write-Host ""
  & {
    "=== camcap Windows verify part 4 (packaged exe smoke, admin) $stamp ==="
    "exe: $exe   cam: $Cam"
    ""
    Remove-Item $so, $se -ErrorAction SilentlyContinue
    $proc = Start-Process -FilePath $exe -ArgumentList "capture", $Cam `
      -NoNewWindow -PassThru -RedirectStandardOutput $so -RedirectStandardError $se
    Start-Sleep -Seconds 30
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    Start-Sleep -Seconds 1
    "--- stderr（banner / 錯誤在這）---"
    Get-Content $se -ErrorAction SilentlyContinue
    "--- stdout 前 20 筆 event ---"
    Get-Content $so -TotalCount 20 -ErrorAction SilentlyContinue
    $n = (Get-Content $so -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
    "--- 共 $n 行 event ---"
    ""
    "--- sc query WinDivert ---"
    sc.exe query WinDivert 2>&1
  } | Tee-Object -Variable captured
  Save-Log $captured $out
}
elseif (-not $Live) {
  $out = Join-Path $root "docs\windows-verify-1.txt"
  & {
    "=== camcap Windows verify part 1 (no admin) $stamp ==="
    "root: $root"
    ""
    "--- python -m pytest -q ---"
    & $py -m pytest -q 2>&1
    ""
    "--- python tools\diag-windivert.py --cam $Cam ---"
    & $py tools\diag-windivert.py --cam $Cam 2>&1
  } | Tee-Object -Variable captured
  Save-Log $captured $out
}
else {
  $out = Join-Path $root "docs\windows-verify-2.txt"
  if (-not (Test-Elevated)) {
    Write-Host "這一段需要「以系統管理員身分執行」的 PowerShell。" -ForegroundColor Red
    exit 3
  }
  Write-Host ""
  Write-Host "接下來 $Seconds 秒會開始攔截 $Cam。" -ForegroundColor Yellow
  Write-Host "請在這段時間內用瀏覽器開 http://$Cam/ 登入 (admin/admin) 並點兩頁。" -ForegroundColor Yellow
  Write-Host "只要瀏覽和 GET，不要改設定 / OTA / 重開。" -ForegroundColor Yellow
  Write-Host ""
  & {
    "=== camcap Windows verify part 2 (live, admin) $stamp ==="
    "root: $root  cam: $Cam  seconds: $Seconds"
    ""
    "--- WinDivertOpen 實測 (diag --open) ---"
    & $py tools\diag-windivert.py --cam $Cam --open 2>&1
    ""
    "--- timed capture ---"
    & $py tools\timed-capture.py $Cam $Seconds first.jsonl 2>&1
    ""
    "--- first.jsonl ---"
    if (Test-Path "first.jsonl") {
      "lines: " + ((Get-Content first.jsonl | Measure-Object -Line).Lines)
      Get-Content first.jsonl -TotalCount 3
    } else { "first.jsonl 不存在" }
    ""
    "--- netstat / $Cam ---"
    netstat -ano | Select-String $Cam
    ""
    "--- sc query WinDivert ---"
    sc.exe query WinDivert 2>&1
  } | Tee-Object -Variable captured
  Save-Log $captured $out
}
