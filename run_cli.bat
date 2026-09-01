@echo off
@chcp 65001 >nul
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

echo [INFO] Starting USP Controller Interactive CLI with %PY_EXE%...
%PY_EXE% usp_main.py %*
set EXIT_CODE=%ERRORLEVEL%

if not "%EXIT_CODE%"=="0" (
    echo [ERROR] CLI exited with code %EXIT_CODE%.
    pause
)

exit /b %EXIT_CODE%
