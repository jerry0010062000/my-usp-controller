@echo off
@chcp 65001 >nul
title STOMP Message Broker (Port 61614)
setlocal
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8

set PY_EXE=python
if exist ".venv\Scripts\python.exe" set PY_EXE=.venv\Scripts\python.exe
if not exist ".venv\Scripts\python.exe" if exist "venv\Scripts\python.exe" set PY_EXE=venv\Scripts\python.exe

%PY_EXE% --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8+ or run setup_env.bat.
    pause
    exit /b 1
)

echo [INFO] Starting Standalone STOMP Broker on port 61614 with %PY_EXE%...
%PY_EXE% tools\embedded_broker.py --port 61614
set EXIT_CODE=%ERRORLEVEL%

if %EXIT_CODE% neq 0 (
    echo.
    echo [ERROR] Broker exited with code %EXIT_CODE%
    pause
)
exit /b %EXIT_CODE%
