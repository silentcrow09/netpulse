@echo off
chcp 65001 >nul 2>&1
title NetPulse - 构建脚本

echo ============================================
echo   NetPulse 单文件 EXE 构建脚本
echo ============================================
echo.

REM 检查 Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 Python，请先安装 Python 3.10+
    pause
    exit /b 1
)

REM 安装依赖
echo [1/3] 安装依赖...
pip install scapy speedtest-cli reportlab pyinstaller -q
if errorlevel 1 (
    echo [警告] 部分依赖安装失败，继续构建...
)
echo.

REM 构建
echo [2/3] 开始构建单文件 EXE...
pyinstaller --onefile --console ^
    --name "NetPulse" ^
    --add-data "netpulse.py;." ^
    --hidden-import "tkinter" ^
    --hidden-import "scapy.all" ^
    --collect-all "scapy" ^
    --hidden-import "reportlab" ^
    --collect-all "reportlab" ^
    netpulse.py

if errorlevel 1 (
    echo.
    echo [错误] 构建失败!
    pause
    exit /b 1
)

echo.
echo [3/3] 构建完成!
echo.
echo 单文件 EXE 位于: dist\NetPulse.exe
echo.
echo 注意:
echo   - 如果需要 DHCP 完整检测功能，请在目标机器上安装 Npcap
echo   - 如果需要 iperf3 测速，请将 iperf3.exe 放在 EXE 同目录
echo.
pause
