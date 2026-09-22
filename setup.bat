@echo off
:: ============================================================
:: MiniSOC Enterprise - One-Click Setup Script (Windows)
:: Run this ONCE after cloning the repo.
:: Double-click setup.bat OR run from a normal (non-admin) cmd.
:: ============================================================
setlocal EnableDelayedExpansion
title MiniSOC Setup

echo.
echo  ============================================================
echo    MiniSOC Enterprise - Prerequisite Setup
echo    Setting up Python venv, dependencies, and database...
echo  ============================================================
echo.

:: ── 1. Check Python ──────────────────────────────────────────
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in PATH.
    echo         Download Python 3.10+ from https://python.org/downloads/
    echo         Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%V in ('python --version 2^>^&1') do set PYVER=%%V
echo [+] Found Python %PYVER%

:: ── 2. Create virtual environment ────────────────────────────
if exist venv\Scripts\python.exe (
    echo [*] Virtual environment already exists, skipping creation.
) else (
    echo [*] Creating Python virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [+] Virtual environment created: .\venv\
)

:: ── 3. Install dependencies ───────────────────────────────────
echo [*] Installing Python dependencies from requirements.txt...
venv\Scripts\pip.exe install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo [+] All dependencies installed successfully.

:: ── 4. Initialize database ───────────────────────────────────
echo [*] Initializing SQLite database and running migrations...
venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'D:/cyber/mini-soc'); from database.models import init_db; init_db()" 2>nul
:: Fallback: use relative path
venv\Scripts\python.exe -c "import sys, os; sys.path.insert(0, os.getcwd()); from database.models import init_db; init_db()"
if %errorlevel% neq 0 (
    echo [ERROR] Database initialization failed.
    pause
    exit /b 1
)
echo [+] Database initialized at .\minisoc.db

:: ── 5. Summary ────────────────────────────────────────────────
echo.
echo  ============================================================
echo    Setup Complete!
echo  ============================================================
echo.
echo  HOW TO START THE SOC DASHBOARD:
echo    venv\Scripts\python.exe dashboard\app.py
echo.
echo  HOW TO ENROLL AN ENDPOINT (run on each monitored machine):
echo    install_windows.bat       (friend's machine / remote endpoint)
echo.
echo  DEFAULT LOGIN CREDENTIALS:
echo    admin    / minisoc@admin      (SOC Administrator)
echo    analyst  / minisoc@analyst    (Tier 1/2 Analyst)
echo    rites    / password123        (Lead SecOps)
echo.
echo  Dashboard URL: http://localhost:5000
echo.
pause
