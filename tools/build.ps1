# Build a Windows executable. Run in an elevated PowerShell on the Windows box.
#
#   py -3.12 -m venv .venv ; .\.venv\Scripts\Activate.ps1
#   pip install -e .[windows,dev]
#   .\tools\build.ps1            # onedir (recommended until the onefile spike passes)
#   .\tools\build.ps1 -OneFile   # spike: does WinDivert load from the temp extraction dir?
#
# The exe requests Administrator (WinDivert needs it) via --uac-admin.
param([switch]$OneFile)

$mode = if ($OneFile) { "--onefile" } else { "--onedir" }
pyinstaller $mode --noconfirm --clean --name camcap `
  --uac-admin `
  --windowed `
  --collect-all pydivert `
  --collect-all webview `
  --add-data "camcap/ui/index.html;camcap/ui" `
  -m camcap

Write-Host ""
Write-Host "Smoke test (elevated):"
Write-Host "  dist\camcap\camcap.exe capture <camera-ip>          # UI-less, prints events"
Write-Host "  dist\camcap\camcap.exe                              # UI"
