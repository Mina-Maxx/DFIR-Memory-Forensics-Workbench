@echo off
title DFIR Web Application — Volatility 3 Forensic Workbench
cd /d "%~dp0"

echo ======================================================================
echo    Volatility 3 DFIR Web Application — Standalone Forensic Workbench
echo ======================================================================
echo.

:: Ensure port 8000 is free by terminating any lingering background process
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo [!] Releasing port 8000 occupied by previous PID %%a ...
    taskkill /F /PID %%a >nul 2>&1
)

echo Starting backend server on http://127.0.0.1:8000 ...
echo The web interface will open automatically once the server is ready.
echo.

python app.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] The application terminated unexpectedly with error code %ERRORLEVEL%.
    pause
)
