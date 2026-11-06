@echo off
cd /d "%~dp0"
if exist "SentinelAI.pyz" (
  python SentinelAI.pyz gui
) else (
  python -m sentinelai gui
)
if errorlevel 1 (
  echo SentinelAI could not start. Install Python 3.10 or later with Tcl/Tk support.
  pause
)
