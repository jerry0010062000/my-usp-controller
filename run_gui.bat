@echo off
setlocal
cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH. Please install Python 3.8+ first.
    pause
    exit /b 1
)

if exist requirements.txt (
    echo [INFO] Checking/installing dependencies from requirements.txt...
    python -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install required dependencies.
        pause
        exit /b 1
    )
)

echo [INFO] Starting USP Controller GUI...
python usp_gui_v3.py
set EXIT_CODE=%ERRORLEVEL%

if not "%EXIT_CODE%"=="0" (
    echo [ERROR] GUI exited with code %EXIT_CODE%.
)

pause
exit /b %EXIT_CODE%
