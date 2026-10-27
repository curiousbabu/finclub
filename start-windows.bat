@echo off
cd /d "%~dp0"
python server.py
if errorlevel 9009 py server.py
pause
