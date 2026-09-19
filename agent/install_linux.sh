#!/usr/bin/env bash
# MiniSOC Endpoint Agent - Linux Systemd Service Installer
set -e

echo "================================================================"
echo "  MiniSOC v2.2 Enterprise - Linux Service Installer"
echo "================================================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SERVER="${1:-https://underfoot-such-italics.ngrok-free.dev/api/v1/telemetry}"

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root: sudo bash install_linux.sh"
  exit 1
fi

python3 "${SCRIPT_DIR}/endpoint_agent.py" --install "${TARGET_SERVER}"
echo ""
echo "[+] MiniSOC service active and enabled on boot."
