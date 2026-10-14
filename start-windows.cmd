@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  call install-windows.cmd
  if errorlevel 1 exit /b 1
)
.venv\Scripts\python.exe -c "import fastapi, uvicorn, dns, reportlab" 2>nul
if errorlevel 1 (
  call install-windows.cmd
  if errorlevel 1 exit /b 1
)
echo Starting External Surface Auditor. Keep this window open.
.venv\Scripts\python.exe -m app.launcher
if errorlevel 1 pause
