@echo off
setlocal
title ScopeWeave - Keep this window open
set "PSModulePath="
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-groq.ps1" -SkipGroqPrompt
set "SENTINEL_EXIT=%errorlevel%"
if not "%SENTINEL_EXIT%"=="0" pause
exit /b %SENTINEL_EXIT%
