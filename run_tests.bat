@echo off
REM Run all tests with pytest
REM 運行所有測試

echo ========================================
echo Running USP Controller Test Suite
echo 運行 USP 控制器測試套件
echo ========================================
echo.

REM Activate virtual environment
echo Activating virtual environment...
echo 正在激活虛擬環境...
call D:\usp\.venv\Scripts\activate.bat

REM Check if pytest is installed
pytest --version >nul 2>&1
if errorlevel 1 (
    echo pytest is not installed!
    echo pytest 未安裝!
    echo.
    echo Installing test dependencies...
    echo 正在安裝測試依賴...
    pip install pytest pytest-cov pytest-timeout pytest-mock
    echo.
)

REM Run tests
echo.
echo Running tests...
echo 正在運行測試...
echo.

pytest tests/ -v --tb=short

echo.
echo ========================================
echo Test run completed
echo 測試運行完成
echo ========================================
echo.

pause
