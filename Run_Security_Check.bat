@echo off
title Security Toolkit - Full Scan
cd /d "%~dp0"

:: Request admin rights for full scan (Event Log, etc.)
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ========================================
echo    Running Full Security Scan...
echo ========================================
echo.

python main.py
if errorlevel 1 py main.py

echo.
echo Press any key to close...
pause >nul
