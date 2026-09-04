# One-shot setup on the Windows host. Run in an ELEVATED PowerShell:
#
#   powershell -ExecutionPolicy Bypass -File \\vboxsvr\SharedFolder\camcap\tools\setup-windows.ps1
#   (or from the mapped drive, e.g. E:\camcap\tools\setup-windows.ps1)
#
# It copies the tree to %USERPROFILE%\camcap (VirtualBox shared folders and
# editable installs / venvs do not mix well), creates a venv, installs, runs the
# test-suite, and prints the spike commands. Re-run after the Linux side changes
# the code: robocopy /MIR keeps the copy in sync.
$ErrorActionPreference = "Stop"
$src  = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$dest = Join-Path $env:USERPROFILE "camcap"

Write-Host "== copy $src -> $dest"
robocopy $src $dest /MIR /XD .venv .git __pycache__ build dist /XF *.pyc /NFL /NDL /NJH /NJS | Out-Null
Set-Location $dest

$py = Get-Command py -ErrorAction SilentlyContinue
if (-not $py) { throw "Python launcher 'py' not found. Install Python 3.12 from python.org (tick 'py launcher')." }

if (-not (Test-Path .venv)) {
    Write-Host "== create venv (3.12)"
    py -3.12 -m venv .venv
}
& .\.venv\Scripts\python.exe -m pip install -q --upgrade pip
Write-Host "== install camcap[windows,dev]"
& .\.venv\Scripts\python.exe -m pip install -q -e ".[windows,dev]"

Write-Host "== unit tests (fake camera, no driver)"
& .\.venv\Scripts\python.exe -m pytest -q
if ($LASTEXITCODE -ne 0) { Write-Warning "tests failed - stop here and report the output" }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ""
Write-Host "== next (board = 10.253.58.186), in THIS shell:" -ForegroundColor Cyan
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  camcap capture 10.253.58.186 --test-mode         # step A: relay only, then browse http://localhost:<relay_port>/"
Write-Host "  camcap capture 10.253.58.186 --out first.jsonl   # step B: WinDivert; then browse http://10.253.58.186/ normally"
Write-Host "  camcap                                           # step C: UI"
Write-Host "  .\tools\build.ps1                                # step D: PyInstaller onedir"
if (-not $isAdmin) { Write-Warning "not elevated: step B/C/D need an Administrator PowerShell" }
