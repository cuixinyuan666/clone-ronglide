@echo off
rem K-Line viewer launcher (double-click me)
rem Starts a local server, then open http://127.0.0.1:8765 in your browser.
cd /d "%~dp0"
set PYEXE=C:\Users\Administrator\Documents\a_conda\python.exe
if not exist "%PYEXE%" set PYEXE=python
echo Starting K-Line viewer on http://127.0.0.1:8765 ...
echo Press Ctrl+C to stop.
"%PYEXE%" kline.py --serve
pause
