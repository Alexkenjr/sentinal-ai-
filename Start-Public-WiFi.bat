@echo off
cd /d "%~dp0"
if exist "SentinelAI.pyz" (
  python SentinelAI.pyz wifi --gui
) else (
  python -m sentinelai wifi --gui
)
if errorlevel 1 (
  echo Could not start. Python 3.10+ with Tcl/Tk and Windows Wi-Fi support are required.
  pause
)
