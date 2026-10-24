# Standalone Windows x64 release build; run only on trusted local Windows builder.
# GitHub Actions is intentionally not used.
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Root
if (-not [Environment]::Is64BitOperatingSystem -or [Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Windows x64 is required' }
$py = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
  & py -3 -m venv (Join-Path $Root '.venv')
  if ($LASTEXITCODE -ne 0) { throw 'Creating .venv failed' }
}
& $py -m pip install --disable-pip-version-check -r requirements.txt 'pyinstaller>=6.11,<7'
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
& $py -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Unit or PySide6 smoke test failed' }
& $py -m PyInstaller --noconfirm --clean --onefile --windowed --noupx --name KeeneticRouteManager --collect-all PySide6 main.py
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }
$exe = Join-Path $Root 'dist\KeeneticRouteManager.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'Missing Windows EXE' }
$fs=[IO.File]::OpenRead($exe)
try {
  $r=[IO.BinaryReader]::new($fs)
  if ($r.ReadUInt16() -ne 0x5A4D) { throw 'Missing MZ header' }
  [void]$fs.Seek(0x3c,[IO.SeekOrigin]::Begin)
  $pos=$r.ReadInt32()
  [void]$fs.Seek($pos,[IO.SeekOrigin]::Begin)
  if ($r.ReadUInt32() -ne 0x4550 -or $r.ReadUInt16() -ne 0x8664) { throw 'Not Windows AMD64 PE' }
} finally { $fs.Dispose() }
$dest=Join-Path $Root 'release\KeeneticRouteManager-0.2.4-Windows-x64'
New-Item -Type Directory -Force -Path $dest | Out-Null
Copy-Item $exe (Join-Path $dest 'KeeneticRouteManager.exe') -Force
Copy-Item (Join-Path $Root 'LICENSE') (Join-Path $dest 'LICENSE.txt') -Force
$sha=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $dest 'SHA256SUMS.txt') -Encoding ASCII -Value ($sha+'  KeeneticRouteManager.exe')
$zip=Join-Path $Root 'release\KeeneticRouteManager-0.2.4-Windows-x64.zip'
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $dest '*') -DestinationPath $zip -CompressionLevel Optimal
$zipsha=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath ($zip+'.sha256') -Encoding ASCII -Value ($zipsha+'  KeeneticRouteManager-0.2.4-Windows-x64.zip')
Write-Host ('EXE: '+$exe)
Write-Host ('EXE SHA256: '+$sha)
Write-Host ('ZIP: '+$zip)
Write-Host ('ZIP SHA256: '+$zipsha)
