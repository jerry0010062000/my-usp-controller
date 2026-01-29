@echo off
echo Starting USP Controller Daemon + GUI...
start /B python usp_controller.py --daemon
timeout /t 2 >nul
start python usp_gui.py
