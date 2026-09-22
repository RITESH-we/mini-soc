#!/usr/bin/env bash
# ============================================================
# MiniSOC Enterprise - One-Click Setup Script (Linux / macOS)
# Run:  chmod +x setup.sh && ./setup.sh
# ============================================================
set -e

BOLD="\033[1m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; RESET="\033[0m"

echo ""
echo -e "${BOLD} ============================================================"
echo "   MiniSOC Enterprise - Prerequisite Setup"
echo -e " ============================================================${RESET}"
echo ""

# ── 1. Check Python ──────────────────────────────────────────
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}[ERROR] Python 3.10+ is required but not found.${RESET}"
    echo "        Install via: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi
PYVER=$($PYTHON --version 2>&1)
echo -e "${GREEN}[+] Found ${PYVER}${RESET}"

# ── 2. Create virtual environment ────────────────────────────
if [ -f "venv/bin/python" ]; then
    echo "[*] Virtual environment already exists, skipping creation."
else
    echo "[*] Creating Python virtual environment..."
    $PYTHON -m venv venv
    echo -e "${GREEN}[+] Virtual environment created: ./venv/${RESET}"
fi

# ── 3. Install dependencies ───────────────────────────────────
echo "[*] Installing Python dependencies from requirements.txt..."
venv/bin/pip install -r requirements.txt --quiet
echo -e "${GREEN}[+] All dependencies installed.${RESET}"

# ── 4. Initialize database ───────────────────────────────────
echo "[*] Initializing SQLite database and running migrations..."
venv/bin/python -c "import sys, os; sys.path.insert(0, os.getcwd()); from database.models import init_db; init_db()"
echo -e "${GREEN}[+] Database initialized at ./minisoc.db${RESET}"

# ── 5. Summary ────────────────────────────────────────────────
echo ""
echo -e "${BOLD} ============================================================"
echo "   Setup Complete!"
echo -e " ============================================================${RESET}"
echo ""
echo "  HOW TO START:"
echo "    venv/bin/python dashboard/app.py"
echo ""
echo "  ENROLL AN ENDPOINT:"
echo "    venv/bin/python agent/endpoint_agent.py http://<SOC-IP>:5000/api/v1/telemetry"
echo ""
echo "  DEFAULT LOGIN:"
echo "    admin    / minisoc@admin"
echo "    analyst  / minisoc@analyst"
echo "    rites    / password123"
echo ""
echo "  Dashboard URL: http://localhost:5000"
echo ""
