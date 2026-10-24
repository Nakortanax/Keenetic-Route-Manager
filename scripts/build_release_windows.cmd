@echo off
cd /d "%~dp0.."
where pwsh >nul 2>&1
if %errorlevel%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_release_windows.ps1"
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_release_windows.ps1"
)
if errorlevel 1 (
  echo BUILD FAILED.
  pause
  exit /b 1
)
echo Build complete. See release directory.
pause
