@echo off
REM Installation script for Network Scanner (Windows)

echo ==========================================
echo Network Scanner - Installation
echo ==========================================
echo.

REM Check Python installation
echo [*] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Python found
    python --version
) else (
    echo [!] Python not found. Please install Python 3.6 or higher.
    echo     Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.

REM Check pip installation
echo [*] Checking pip installation...
pip --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] pip found
) else (
    echo [!] pip not found. Installing pip...
    python -m ensurepip --default-pip
)

echo.

REM Install dependencies
echo [*] Installing required packages...
echo.
pip install requests
echo.

REM Verify installation
echo [*] Verifying installation...
python -c "import requests; print('[+] requests library installed successfully')" 2>&1

if %errorlevel% equ 0 (
    echo.
    echo ==========================================
    echo Installation Complete!
    echo ==========================================
    echo.
    echo You can now run the scanner with:
    echo   python network_scanner.py
    echo.
    echo For best results, run as Administrator:
    echo   Right-click Command Prompt -^> Run as Administrator
    echo   Then run: python network_scanner.py
    echo.
) else (
    echo.
    echo [!] Installation failed. Please install requests manually:
    echo   pip install requests
    pause
    exit /b 1
)

pause
