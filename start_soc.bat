@echo off
title MiniSOC Launcher
echo ================================================================
echo   MiniSOC Enterprise - Launching Dashboard & Public Tunnel
echo ================================================================
echo.

cd /d "%~dp0"

REM 1. Start Flask Dashboard in the background
echo [*] Starting Flask SOC Server on port 5000...
start "MiniSOC Dashboard" /B venv\Scripts\python.exe dashboard\app.py

REM Wait 2 seconds for Flask to bind
timeout /t 2 /nobreak >nul

REM 2. Start Ngrok Static Tunnel
if exist ngrok.exe (
    echo [*] Starting Ngrok Tunnel to underfoot-such-italics.ngrok-free.dev...
    start "MiniSOC Ngrok" /B ngrok.exe http --url=underfoot-such-italics.ngrok-free.dev 5000
) else (
    echo [!] ngrok.exe not found in root directory.
)

echo.
echo ================================================================
echo   MiniSOC is now LIVE!
echo   Local Web Console : http://127.0.0.1:5000
echo   Public Domain     : https://underfoot-such-italics.ngrok-free.dev
echo ================================================================
echo.
