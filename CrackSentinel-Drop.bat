@echo off
setlocal enabledelayedexpansion
title CrackSentinel - Drag and Drop Scanner
cd /d "%~dp0"
if "%~1"=="" (
    echo ========================================================
    echo   CrackSentinel - Drag ^& Drop Game Malware Scanner
    echo ========================================================
    echo.
    echo   Cara pakai:
    echo   1. Drag ^& Drop 1 file, 1 folder game, atau BANYAK
    echo      folder/file sekaligus ke atas file .bat ini!
    echo   2. Atau double-click CrackSentinel-UI.bat untuk
    echo      tampilan Web UI Drag ^& Drop + Real-Time Guard.
    echo.
    pause
    exit /b 0
)
if not exist "%~dp0tmp" mkdir "%~dp0tmp"
if not exist "%~dp0reports" mkdir "%~dp0reports"
for /f %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "TS=%%I"
set "REP=%~dp0reports\scan-%TS%.html"
echo Scanning target(s)... Temp: %~dp0tmp
"%~dp0scanner.exe" -tmp-dir "%~dp0tmp" -html "%REP%" %*
echo.
echo Laporan HTML: %REP%
if exist "%REP%" start "" "%REP%"
echo.
pause
