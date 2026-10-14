@echo off
setlocal
cd /d "%~dp0"
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"
if errorlevel 1 goto python_missing
py -3 -m venv .venv
if errorlevel 1 goto failed
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo Installation complete. Double-click start-windows.cmd to launch.
pause
exit /b 0
:python_missing
echo Install Python 3.11 or newer from https://www.python.org/downloads/windows/
echo Include the Python launcher during installation.
:failed
echo Installation could not complete. Review the error above.
pause
exit /b 1
