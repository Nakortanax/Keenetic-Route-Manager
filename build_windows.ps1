# Local Windows builder ONLY. No GitHub Actions or deployment.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path .venv\Scripts\python.exe)) { py -3 -m venv .venv }
$py = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
& $py -m pip install --disable-pip-version-check -r requirements.txt 'pyinstaller>=6.11,<7'
if ($LASTEXITCODE -ne 0) { throw 'Dependency install failed' }
& $py -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
& $py -m PyInstaller --noconfirm --clean --onefile --windowed --name KeeneticRouteManager --collect-all PySide6 main.py
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed' }
$exe = Join-Path $PSScriptRoot 'dist\KeeneticRouteManager.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'EXE not found' }
$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $exe
$hash.Hash.ToLower() + '  KeeneticRouteManager.exe' | Set-Content -Encoding ascii (Join-Path $PSScriptRoot 'dist\KeeneticRouteManager.exe.sha256')
Write-Host "EXE: $exe"
Write-Host "SHA-256: $($hash.Hash)"
