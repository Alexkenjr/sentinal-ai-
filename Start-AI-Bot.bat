@echo off
cd /d "%~dp0"
set "SENTINELAI_BOT_MODEL=qwen3:1.7b"
python -m sentinelai gui
if errorlevel 1 pause
