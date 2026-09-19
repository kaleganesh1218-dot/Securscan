#!/bin/bash

echo "================================"
echo "       SecureScan Installer"
echo "================================"

echo "[+] Checking Nmap..."

if command -v nmap >/dev/null 2>&1; then
    echo "[+] Nmap is already installed."
else
    echo "[+] Installing Nmap..."
    sudo apt update
    sudo apt install -y nmap
fi

echo "[+] Checking Python3..."

if command -v python3 >/dev/null 2>&1; then
    echo "[+] Python3 is available."
else
    echo "[-] Python3 is required."
    exit 1
fi

chmod +x securscan.py

mkdir -p scans reports evidence

echo ""
echo "[+] SecureScan installation completed."
echo "[+] Run with: python3 securscan.py"
