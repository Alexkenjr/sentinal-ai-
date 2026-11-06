@echo off
cd /d "%~dp0"
if exist "SentinelAI.pyz" (
  python SentinelAI.pyz investigation-demo --gui
) else (
  python -m sentinelai investigation-demo --gui
)
if errorlevel 1 (
  echo Could not start. Python 3.10+ with Tcl/Tk is required.
  pause
)
