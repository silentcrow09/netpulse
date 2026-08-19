@echo off
chcp 65001 >nul 2>&1
title NetPulse - 构建脚本
REM 调用 PowerShell 构建脚本 (进度条 + 静默 PyInstaller, 详细输出走日志)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_exe.ps1"
exit /b %ERRORLEVEL%
