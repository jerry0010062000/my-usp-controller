@echo off
REM ========================================
REM USP Controller One-Click Launcher
REM Auto-start: Mini-Broker + Daemon + GUI
REM ========================================

echo.
echo ========================================
echo   USP Controller Development Environment
echo ========================================
echo.

REM Check virtual environment
if exist ".venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment...
    call .venv\Scripts\activate.bat
) else (
    echo [!] Virtual environment not found, using system Python
)

REM Start full environment
echo [*] Starting services (Mini-Broker + Daemon + GUI)...
echo.
python start_dev.py %*

pause
