@echo off
title CrackSentinel - Game Malware Guard UI
cd /d "%~dp0"
if not exist "%~dp0tmp" mkdir "%~dp0tmp"
"%~dp0scanner.exe" ui -addr 127.0.0.1:8787 -tmp-dir "%~dp0tmp" %*
if errorlevel 1 pause
