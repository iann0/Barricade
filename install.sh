#!/bin/bash

echo "Installing Barricade..."

# Detect Termux or Linux
if [["$PREFIX" == *"com.termux"* ]]; then
    echo "Detected Termux environment."
    BIN_PATH="$HOME/.barricade"
    PYTHON_CMD="python"
else
    echo "Detected full Linux environment."
    BIN_PATH="/usr/local/bin/barricade"
    PYTHON_CMD="python3"
    if [[$EUID -ne 0 ]]; then
        echo "Please run this installer as root (sudo ./install.sh)"
        exit 1
    fi
fi

# Install dependencies
echo "Installing Python and Scapy..."
if command -v pkg >/dev/null 2>&1; then
    pkg install -y python
else
    apt update && apt install -y python3 python3-pip
fi

$PYTHON_CMD -m pip install --upgrade pip
$PYTHON_CMD -m pip install scapy

# Symlink CLI command
echo "Linking Barricade to: $BIN_PATH"
chmod +x firewall.py
ln -sf \"$PWD/firewall.py\" \"$BIN_PATH\"

echo -e \"\\nBarricade installation complete!\"
echo \"Usage:\"
echo \"  $BIN_PATH --start\"
echo \"  $BIN_PATH --add blocked_ips '192.168.1.1'\"
echo \"  $BIN_PATH --list\"
