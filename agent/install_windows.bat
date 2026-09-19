@echo off
title MiniSOC Endpoint Agent - Background Service Installer
echo ================================================================
echo   MiniSOC v2.2 Enterprise - Automated Agent Persistence Installer
echo ================================================================
echo.
cd /d "%~dp0"

REM If python is in PATH or venv
python endpoint_agent.py --install %1

echo.
echo ================================================================
echo   Installation completed! The agent will auto-start on boot.
echo ================================================================
echo.
pause
