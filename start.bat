@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo   OTP Authenticator (offline mode)
echo   Open: http://127.0.0.1:8765/
echo   Keep this window open while using the app.
echo.
start "" "http://127.0.0.1:8765/"
python -m http.server 8765 --bind 127.0.0.1
if errorlevel 1 py -m http.server 8765 --bind 127.0.0.1
pause
