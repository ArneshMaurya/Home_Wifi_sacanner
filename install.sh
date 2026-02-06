#!/bin/bash
# Installation script for Network Scanner

echo "=========================================="
echo "Network Scanner - Installation"
echo "=========================================="
echo ""

# Check Python installation
echo "[*] Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
    echo "[+] Python 3 found: $(python3 --version)"
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
    PYTHON_VERSION=$(python --version 2>&1)
    if [[ $PYTHON_VERSION == *"Python 3"* ]]; then
        echo "[+] Python 3 found: $PYTHON_VERSION"
    else
        echo "[!] Python 3 is required. Please install Python 3.6 or higher."
        exit 1
    fi
else
    echo "[!] Python not found. Please install Python 3.6 or higher."
    echo "    Download from: https://www.python.org/downloads/"
    exit 1
fi

echo ""

# Check pip installation
echo "[*] Checking pip installation..."
if command -v pip3 &> /dev/null; then
    PIP_CMD=pip3
    echo "[+] pip3 found"
elif command -v pip &> /dev/null; then
    PIP_CMD=pip
    echo "[+] pip found"
else
    echo "[!] pip not found. Installing pip..."
    $PYTHON_CMD -m ensurepip --default-pip
    PIP_CMD="$PYTHON_CMD -m pip"
fi

echo ""

# Install dependencies
echo "[*] Installing required packages..."
echo ""
$PIP_CMD install requests
echo ""

# Verify installation
echo "[*] Verifying installation..."
$PYTHON_CMD -c "import requests; print('[+] requests library installed successfully')" 2>&1

if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "Installation Complete!"
    echo "=========================================="
    echo ""
    echo "You can now run the scanner with:"
    echo "  $PYTHON_CMD network_scanner.py"
    echo ""
    echo "For best results, run with elevated privileges:"
    echo "  sudo $PYTHON_CMD network_scanner.py"
    echo ""
else
    echo ""
    echo "[!] Installation failed. Please install requests manually:"
    echo "  $PIP_CMD install requests"
    exit 1
fi
