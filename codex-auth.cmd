@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0codex-auth.ps1" "%~1" "%~2"
exit /b %ERRORLEVEL%
