#!/usr/bin/env bash
# ==============================================================================
# DFIR Memory Forensics Workbench — Linux & macOS Startup Script
# ==============================================================================

set -e

# Change directory to the script root directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$ROOT_DIR"

echo "================================================================="
echo "  DFIR Memory Forensics Workbench — Linux / Unix Environment"
echo "================================================================="

# 1. Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[!] Error: python3 is not installed or not in PATH."
    echo "    Install with: sudo apt install python3 python3-pip python3-venv (Debian/Ubuntu/Kali)"
    exit 1
fi

# 2. Activate virtual environment if present, or create one
if [ -d "venv" ]; then
    echo "[*] Activating virtual environment (venv)..."
    source venv/bin/activate
elif [ -d ".venv" ]; then
    echo "[*] Activating virtual environment (.venv)..."
    source .venv/bin/activate
else
    echo "[*] No virtual environment found. Creating one at ./venv ..."
    python3 -m venv venv
    source venv/bin/activate
    echo "[*] Installing dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
fi

# 3. Environment configuration
export HOST="${HOST:-127.0.0.1}"
export PORT="${PORT:-8000}"

echo "[*] Launching server on http://${HOST}:${PORT} ..."
echo "[*] Press Ctrl+C to terminate."
echo "================================================================="

# 4. Run application
python3 app.py
