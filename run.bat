@echo off
title DFIR Web Application — Volatility 3 Forensic Workbench
cd /d "%~dp0"

echo ======================================================================
echo    Volatility 3 DFIR Web Application — Standalone Forensic Workbench
echo ======================================================================
echo.

:: 1. Activate virtual environment if present
if exist "venv\Scripts\activate.bat" (
    echo [*] Activating Python virtual environment (venv)...
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    echo [*] Activating Python virtual environment (.venv)...
    call .venv\Scripts\activate.bat
)

:: 2. Non-destructive port check
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo [!] Notice: Port 8000 is currently occupied by PID %%a.
)

echo Starting backend server on http://127.0.0.1:8000 ...
echo The web interface will open automatically once the server is ready.
echo.

python app.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] The application terminated with error code %ERRORLEVEL%.
    pause
)
