@echo off
cd /d "%~dp0"
if exist "SentinelAI.pyz" (
  python SentinelAI.pyz simulate --gui --hosts 50
) else (
  python -m sentinelai simulate --gui --hosts 50
)
if errorlevel 1 (
  echo Demo could not start. Python 3.10 or later with Tcl/Tk is required.
  pause
)
