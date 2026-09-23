@echo off
title MiniSOC Endpoint Agent - Background Service Installer
echo ================================================================
echo   MiniSOC v2.2 Enterprise - Automated Agent Persistence Installer
echo ================================================================
echo.

:: 1. Self-elevation check for Administrator rights (required to control Windows Firewall)
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Administrator privileges required to manage Windows Firewall policies.
    echo [*] Requesting UAC elevation...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\" %*\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

:: 2. Target SOC server URL (default to live public domain if none provided)
set TARGET_URL=%1
if "%TARGET_URL%"=="" (
    set TARGET_URL=https://trishula-soc.onrender.com/api/v1/telemetry
)

:: 3. Select Security Policy Profile
set PROFILE_CHOICE=%2
if "%PROFILE_CHOICE%"=="" (
    echo Choose Security Policy Profile for this endpoint:
    echo   [1] Standard Workstation  (Normal 15s Heartbeat, Analyst Containment) [Default]
    echo   [2] High-Security Server  (Fast 5s Heartbeat, Strict Auto-Block)
    echo   [3] Friend's PC / Safe    (Non-Disruptive Audit Mode - No Automatic Lockouts)
    echo.
    set /p P_SEL="Select option [1-3, default 1]: "
    if "%P_SEL%"=="2" (
        set PROFILE_CHOICE=high_security_server
    ) else if "%P_SEL%"=="3" (
        set PROFILE_CHOICE=audit_friend
    ) else (
        set PROFILE_CHOICE=standard_workstation
    )
)

echo.
echo [*] Target SOC Server: %TARGET_URL%
echo [*] Policy Profile:   %PROFILE_CHOICE%
echo [*] Enrolling endpoint with Administrator privileges...
echo.

:: 4. Execute installation with python or virtual environment
where python >nul 2>&1
if %errorLevel% equ 0 (
    python endpoint_agent.py --install "%TARGET_URL%" --profile "%PROFILE_CHOICE%"
) else (
    if exist "..\venv\Scripts\python.exe" (
        "..\venv\Scripts\python.exe" endpoint_agent.py --install "%TARGET_URL%" --profile "%PROFILE_CHOICE%"
    ) else (
        echo [!] Error: Python was not found in PATH or ..\venv\
        echo     Please install Python 3.11+ and check 'Add python.exe to PATH'.
        pause
        exit /b 1
    )
)

echo.
echo ================================================================
echo   Installation completed with HIGHEST Administrator Privileges!
echo   Active Profile: %PROFILE_CHOICE%
echo   The agent is now active and will automatically start on boot.
echo ================================================================
echo.
pause
