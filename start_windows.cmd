@echo off
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 (echo Install Python 3.11+ from python.org & pause & exit /b 1)
if not exist .venv\Scripts\python.exe (
  py -3 -m venv .venv
  .venv\Scripts\python.exe -m pip install -r requirements.txt
  if errorlevel 1 (echo Installation failed & pause & exit /b 1)
)
.venv\Scripts\python.exe main.py
if errorlevel 1 pause
