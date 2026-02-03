@echo off
echo Starting USP Controller Daemon + GUI...
echo.
echo [1/2] Starting daemon in new window...
start "USP Controller Daemon" python usp_controller.py --daemon --force
timeout /t 2 >nul
echo [2/2] Starting GUI...
start "USP Controller GUI" pythonw usp_gui.py
echo.
echo Done! Both windows should now be visible.
timeout /t 1 >nul
