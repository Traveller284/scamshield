@echo off
cd /d "%~dp0"
findstr /R /C:"^[ ]*TELEGRAM_TOKEN=.[^ ]" .env >nul 2>nul
if %errorlevel%==0 start "ScamShield Telegram Bot" cmd /k python bot.py
python server.py
pause
