# Build a Windows executable. 用專案 venv 的 python，**不要**在提權的 shell 裡跑
# （PyInstaller 6.x 會警告，7.0 會直接擋）。
#
#   powershell -ExecutionPolicy Bypass -File tools\build.ps1              # onedir + console（給 DQA 的）
#   powershell -ExecutionPolicy Bypass -File tools\build.ps1 -Windowed    # 不要主控台視窗
#   powershell -ExecutionPolicy Bypass -File tools\build.ps1 -OneFile     # spike: WinDivert 從 temp 解壓目錄載得起來嗎
#
# 打包出來的 exe 帶 --uac-admin，執行時自己會要求系統管理員（WinDivert 需要）。
param([switch]$OneFile, [switch]$Windowed)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$pyexe = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $pyexe)) {
  Write-Host "找不到 $pyexe — 先跑 tools\setup-windows.ps1 建 venv" -ForegroundColor Red
  exit 2
}

# 一定要用 venv 的 python 去跑 PyInstaller。裸的 `pyinstaller` 會抓到 PATH 上
# 系統那份，於是拿系統 Python 的 site-packages 去打包，camcap / pydivert 全都不在裡面。
$pyiArgs = @(if ($OneFile) { "--onefile" } else { "--onedir" })
# 預設帶主控台：DQA 用的包如果啟動就掛掉，--windowed 會讓畫面上什麼都不出現，
# 完全沒東西可以回報。UI (pywebview) 在 console build 一樣開得起來，
# 而且 `camcap.exe capture <ip>` 這個 headless 模式本來就要有 stdout 才有用。
$pyiArgs += if ($Windowed) { "--windowed" } else { "--console" }
$pyiArgs += "--noconfirm", "--clean", "--name", "camcap", "--uac-admin"
$pyiArgs += "--collect-submodules", "camcap"   # redirector / app 是在函式裡才 import 的
$pyiArgs += "--collect-all", "pydivert"        # 連 WinDivert64.dll / .sys 一起收
$pyiArgs += "--collect-all", "webview"
$pyiArgs += "--add-data", "camcap/ui/index.html;camcap/ui"
$pyiArgs += (Join-Path $root "tools\camcap-entry.py")

Write-Host "pyinstaller $($pyiArgs -join ' ')" -ForegroundColor DarkGray
& $pyexe -m PyInstaller @pyiArgs
if ($LASTEXITCODE -ne 0) {
  Write-Host "pyinstaller failed ($LASTEXITCODE)" -ForegroundColor Red
  exit $LASTEXITCODE
}

# WinDivert 的 .dll / .sys 一定要跟著進 dist，否則到了 DQA 機器上才會發現載不起來
$hit = Get-ChildItem -Path (Join-Path $root "dist") -Recurse -Filter "WinDivert64.*" -ErrorAction SilentlyContinue
if ($hit) {
  Write-Host "`nWinDivert payload in dist:" -ForegroundColor Green
  $hit | ForEach-Object { "  {0}  ({1} bytes)" -f $_.FullName, $_.Length }
} else {
  Write-Host "`nWinDivert64.dll / .sys NOT in dist — --collect-all pydivert 沒收到，別發出去" -ForegroundColor Red
}

Write-Host ""
Write-Host "Smoke test (elevated):"
Write-Host "  dist\camcap\camcap.exe capture <camera-ip>          # UI-less, prints events"
Write-Host "  dist\camcap\camcap.exe                              # UI"
