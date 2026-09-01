@echo off
@chcp 65001 >nul
setlocal
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8

echo ===================================================
echo   USP Controller - Python Environment Setup
echo ===================================================
echo.

python --version >nul 2>&1
if errorlevel 1 goto :no_python

if exist ".venv\Scripts\python.exe" goto :venv_exists

echo [INFO] Creating Python virtual environment in .venv ...
python -m venv .venv
if errorlevel 1 goto :venv_failed
echo [OK] Virtual environment created successfully.
goto :install_deps

:venv_exists
echo [INFO] Virtual environment .venv already exists.

:install_deps
echo [INFO] Upgrading pip and installing dependencies from requirements.txt ...
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto :deps_warning

echo [OK] All dependencies installed successfully!
goto :finished

:deps_warning
echo [WARNING] Dependency installation had issues. Please check your network connection.
goto :finished

:no_python
echo [ERROR] Python not found in system PATH.
echo Please install Python 3.8+ from https://www.python.org/ and check "Add Python to PATH".
goto :end

:venv_failed
echo [ERROR] Failed to create virtual environment.
goto :end

:finished
echo.
echo ===================================================
echo   Setup completed successfully!
echo   You can now launch:
echo     1. run_daemon.bat (Start background Daemon window)
echo     2. run_gui.bat    (Start GUI Control Deck)
echo     3. run_cli.bat    (Start Interactive CLI)
echo ===================================================

:end
echo.
pause
