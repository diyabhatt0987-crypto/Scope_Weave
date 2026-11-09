@echo off
setlocal
title ScopeWeave - Update Groq key
set "PSModulePath="
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-groq.ps1" -ReplaceGroqKey
set "SENTINEL_EXIT=%errorlevel%"
if not "%SENTINEL_EXIT%"=="0" pause
exit /b %SENTINEL_EXIT%
