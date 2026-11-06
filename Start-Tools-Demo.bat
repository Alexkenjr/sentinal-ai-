@echo off
cd /d "%~dp0"
if exist "SentinelAI.pyz" (
  python SentinelAI.pyz tools-demo --gui
) else (
  python -m sentinelai tools-demo --gui
)
if errorlevel 1 (
  echo Demo could not start. Python 3.10+ with Tcl/Tk is required.
  pause
)
