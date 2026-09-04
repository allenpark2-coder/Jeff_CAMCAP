<#
.SYNOPSIS
  camcap Windows 端驗證，輸出寫成檔案讓 Linux 端 / Claude 直接讀。

.EXAMPLE
  # 第一段：不需要系統管理員
  powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1

.EXAMPLE
  # 第二段：需要「以系統管理員身分執行」的 PowerShell
  powershell -ExecutionPolicy Bypass -File tools\verify-windows.ps1 -Live
#>
param(
  [switch]$Live,
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

if (-not $Live) {
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
  $captured | Out-File -FilePath $out -Encoding utf8
  Write-Host "`n>>> 寫到 $out" -ForegroundColor Green
}
else {
  $out = Join-Path $root "docs\windows-verify-2.txt"
  $elevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $elevated) {
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
  $captured | Out-File -FilePath $out -Encoding utf8
  Write-Host "`n>>> 寫到 $out" -ForegroundColor Green
}
