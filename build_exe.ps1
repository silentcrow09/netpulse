# NetPulse 单文件 EXE 构建脚本 (PowerShell 版)
# 输出分阶段 + 旋转动画, PyInstaller 静默到日志, 失败时回显
# 用法: 双击 build_exe.bat, 或在 PowerShell 里 .\build_exe.ps1

# 用 'Continue' (默认) 而不是 'Stop', 避免单点错误直接终止脚本闪退
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 全局 try/catch 兑底: 任何未捕获异常都写出原因, 不闪退
trap {
    Write-Host ""
    Write-Host "  [未捕获异常] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  调用栈: $($_.ScriptStackTrace)" -ForegroundColor Gray
    Read-Host "`n  按 Enter 退出"
    exit 1
}

$logFile = Join-Path $PSScriptRoot 'build_last.log'

function Step-Start($n, $total, $msg) {
    Write-Host ("  [{0}/{1}] {2}... " -f $n, $total, $msg) -NoNewline -ForegroundColor Gray
}

function Step-Ok($extra = '') {
    if ($extra) { Write-Host "OK $extra" -ForegroundColor Green }
    else { Write-Host "OK" -ForegroundColor Green }
}

function Step-Fail($msg) {
    Write-Host "[失败]" -ForegroundColor Red
    if ($msg) { Write-Host "  $msg" -ForegroundColor Yellow }
}

# 探测 Python 解释器 (用 try/catch 包装, 任何错误都不闪退)
# 优先用 'py' 启动器 (Windows 官方推荐, 稳定指向已注册 Python, 不依赖 PATH)
function Find-Python {
    $candidates = @('py', 'python', 'python3')
    foreach ($c in $candidates) {
        try {
            $ver = & $c --version 2>&1
            if ($LASTEXITCODE -eq 0) { return @{ Cmd = $c; Ver = ($ver -join '') } }
        } catch {}
    }
    return $null
}

# 探测 pip 命令 (返回 hashtable: Cmd + ExtraArgs, 让调用方用 splat 展开)
# 重要: PowerShell 不能把 "python -m pip" 当一个命令名调用, 必须分开传参
function Find-Pip($pyCmd) {
    # 优先用 python -m pip (最稳, 不依赖 PATH 里的 pip)
    try {
        $ver = & $pyCmd -m pip --version 2>&1
        if ($LASTEXITCODE -eq 0) { return @{ Cmd = $pyCmd; ExtraArgs = @('-m', 'pip') } }
    } catch {}
    # 备选: PATH 里的 pip / pip3
    foreach ($p in @('pip', 'pip3')) {
        try {
            $ver = & $p --version 2>&1
            if ($LASTEXITCODE -eq 0) { return @{ Cmd = $p; ExtraArgs = @() } }
        } catch {}
    }
    return $null
}

# 用 import 测试代替 pip show (更稳, 不依赖 pip 状态)
function Test-Module($pyCmd, $modName) {
    try {
        $null = & $pyCmd -c "import $modName" 2>&1
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

Clear-Host
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  NetPulse 单文件 EXE 构建脚本" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ---- 1/6: 查找 Python ----
Step-Start 1 6 "查找 Python"
$py = Find-Python
if (-not $py) {
    Step-Fail "未找到 python.exe, 请先安装 Python 3.10+ 并勾选 'Add Python to PATH'"
    Read-Host "`n  按 Enter 退出"; exit 1
}
Step-Ok "($($py.Ver)  via: $($py.Cmd))"

# ---- 2/6: 检查/安装依赖 ----
Step-Start 2 6 "检查依赖"
$pip = Find-Pip $py.Cmd
if (-not $pip) {
    Step-Fail "未找到 pip. 请运行: $($py.Cmd) -m ensurepip --upgrade"
    Read-Host "`n  按 Enter 退出"; exit 1
}
# pip 探测成功但路径不展示, 静默即可 (失败时再显示手动修复命令)
$pipDisplay = if ($pip.ExtraArgs.Count -gt 0) { "$($pip.Cmd) $($pip.ExtraArgs -join ' ')" } else { $pip.Cmd }

# 用 import 测试代替 pip show
# key = pip 安装名, value = import 测试名 (两者不同的: speedtest-cli 的 import 名是
# speedtest; pyinstaller 的 import 名是 PyInstaller)。注意 PyPI 上的 'speedtest'
# 是 2020 年的 1.3 kB 占位空包, 绝不能直接 pip install speedtest
$required = @{
    'scapy'         = 'scapy'
    'cryptography'  = 'cryptography'
    'speedtest-cli' = 'speedtest'
    'reportlab'     = 'reportlab'
    'pyinstaller'   = 'PyInstaller'
}
$missing = @()
foreach ($entry in $required.GetEnumerator()) {
    $installed = Test-Module $py.Cmd $entry.Value
    if (-not $installed) { $missing += $entry.Key }
}

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "      缺失: $($missing -join ', ')" -ForegroundColor Yellow
    Write-Host "      正在自动安装 (cryptography 修 scapy.modules.krack ImportError)..." -NoNewline -ForegroundColor Yellow
    try {
        # splat 必须用独立变量, PowerShell 5.1 不支持 @pip.ExtraArgs 这种属性访问形式
        $pipExtra = $pip.ExtraArgs
        & $pip.Cmd @pipExtra install --quiet --disable-pip-version-check $missing 2>&1 | Out-Null
    } catch {
        Write-Host " [失败]" -ForegroundColor Red
        Write-Host "      $_" -ForegroundColor Yellow
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host " [失败]" -ForegroundColor Red
        Write-Host "      pip install 退出码 $LASTEXITCODE" -ForegroundColor Yellow
        Write-Host "      可手动: $pipDisplay install $($missing -join ' ')" -ForegroundColor Yellow
        Read-Host "`n  按 Enter 退出"; exit 1
    }
    Write-Host " 完成" -ForegroundColor Green
} else {
    Step-Ok "(scapy, cryptography, speedtest-cli, reportlab, pyinstaller 全部就位)"
}

# ---- 3/6: 清理旧构建 ----
Step-Start 3 6 "清理旧构建"
try {
    if (Test-Path build) { Remove-Item -Recurse -Force build }
    if (Test-Path dist)  { Remove-Item -Recurse -Force dist }
    if (Test-Path $logFile) { Remove-Item $logFile -Force }
    Step-Ok
} catch {
    Step-Fail "清理失败: $_"
    Read-Host "`n  按 Enter 退出"; exit 1
}

# ---- 4/6: 打包 EXE ----
Step-Start 4 6 "打包 EXE (单文件, 通常 30-90 秒)"

# 关键: --log-level WARN 把 INFO 压到日志, 详细输出走 build_last.log, 失败时回显
# --noconfirm 避免覆盖 dist 时询问
$piArgs = @(
    '--onefile', '--console', '--noconfirm',
    '--name', 'NetPulse',
    '--add-data', 'netpulse.py;.',
    '--hidden-import', 'tkinter',
    '--hidden-import', 'scapy.all',
    '--collect-all', 'scapy',
    '--hidden-import', 'reportlab',
    '--collect-all', 'reportlab',
    '--log-level', 'WARN',
    'netpulse.py'
)

# 后台跑 pyinstaller, 同时显示旋转动画
# 不用 Start-Job (splat 在 job scriptblock 里行为不稳定), 改用 Start-Process
# --noconfirm 避免覆盖 dist 时询问
# 日志走 stderr, RedirectStandardError 捕获到 stderrLog
$stdoutLog = "$logFile.stdout"
$stderrLog = "$logFile.stderr"
if (Test-Path $stdoutLog) { Remove-Item $stdoutLog -Force }
if (Test-Path $stderrLog) { Remove-Item $stderrLog -Force }

# 找 pyinstaller.exe (优先 Scripts 目录, 然后 PATH)
# py 启动器 ('py') 没有父路径概念, 用 python -c "import sys; print(sys.executable)" 拿真实解释器位置
$pyinstallerCmd = $null
try {
    $realPython = & $py.Cmd -c "import sys; print(sys.executable)" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $pyScripts = Join-Path (Split-Path $realPython.Trim() -Parent) 'Scripts\pyinstaller.exe'
        if (Test-Path $pyScripts) { $pyinstallerCmd = $pyScripts }
    }
} catch {}
if (-not $pyinstallerCmd) {
    $pi = Get-Command pyinstaller -ErrorAction SilentlyContinue
    if ($pi) { $pyinstallerCmd = $pi.Source }
}
if (-not $pyinstallerCmd) {
    Step-Fail "找不到 pyinstaller.exe. 请运行: $pipDisplay install pyinstaller"
    Read-Host "`n  按 Enter 退出"; exit 1
}

try {
    $piProcess = Start-Process -FilePath $pyinstallerCmd `
        -ArgumentList $piArgs `
        -NoNewWindow -PassThru `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog `
        -WorkingDirectory $PSScriptRoot
} catch {
    Step-Fail "启动 pyinstaller 失败: $_"
    Read-Host "`n  按 Enter 退出"; exit 1
}

# 旋转动画, 实时显示已用秒数
$spin = @('|', '/', '-', '\')
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$i = 0
while (-not $piProcess.HasExited) {
    $c = $spin[$i % 4]
    $sec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    Write-Host ("`r  [4/6] 打包 EXE (单文件, 已用 {0}s)... {1}  " -f $sec, $c) -NoNewline -ForegroundColor Gray
    $i++
    Start-Sleep -Milliseconds 200
}
$sw.Stop()
$piProcess.WaitForExit()

# Start-Process 的 ExitCode 在某些情况下返回 $null (尤其进程已退出但 handle 未释放时),
# 用 HasExited + 文件存在双保险判断
$piExit = $piProcess.ExitCode
$piExit = if ($null -eq $piExit) { 0 } else { [int]$piExit }

# 合并 stdout + stderr 到 build_last.log 供失败时查看
if ((Test-Path $stdoutLog) -or (Test-Path $stderrLog)) {
    Get-Content $stdoutLog, $stderrLog -ErrorAction SilentlyContinue | Out-File $logFile -Encoding UTF8
}

if ($piExit -ne 0) {
    Step-Fail
    Write-Host ""
    Write-Host "  PyInstaller 日志 (前 50 行, 来自 $logFile):" -ForegroundColor Yellow
    if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt 0) {
        Get-Content $logFile -TotalCount 50 -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "    $_" -ForegroundColor Gray
        }
    } else {
        Write-Host "    (--log-file 写出来 0 字节, 可能是 pyinstaller 启动前就崩了)" -ForegroundColor DarkGray
        Write-Host "    补充检查 stderr:" -ForegroundColor DarkGray
        if ((Test-Path $stderrLog) -and (Get-Item $stderrLog).Length -gt 0) {
            Get-Content $stderrLog -TotalCount 30 -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Host "      $_" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "      (stderr 也为空)" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    Write-Host "  手动复现命令 (用于排查):" -ForegroundColor Yellow
    Write-Host "    pyinstaller $piArgs" -ForegroundColor Gray
    Read-Host "`n  按 Enter 退出"; exit 1
}
Step-Ok

# ---- 5/6: 验证 EXE ----
Step-Start 5 6 "验证 EXE"
$exePath = Join-Path $PSScriptRoot 'dist\NetPulse.exe'
if (-not (Test-Path $exePath)) {
    Step-Fail "EXE 未生成"
    Read-Host "`n  按 Enter 退出"; exit 1
}
$sizeMB = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
Step-Ok "($sizeMB MB)"

# ---- 6/6: 清理临时文件 (build 工作区 + 合并日志, 保留 dist/NetPulse.exe) ----
Step-Start 6 6 "清理临时文件"
$cleanedSize = 0
$cleanedItems = @()
# 1. build/ 目录 (PyInstaller 工作区, 通常 40-60 MB)
if (Test-Path build) {
    $buildSize = (Get-ChildItem build -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    Remove-Item -Recurse -Force build
    $cleanedSize += $buildSize
    $cleanedItems += "build/ ($([math]::Round($buildSize/1MB, 1)) MB)"
}
# 2. build_last.log* (合并日志 + stdout/stderr 备份, 失败时已回显, 成功时不需要)
foreach ($f in @($logFile, $stdoutLog, $stderrLog)) {
    if (Test-Path $f) {
        Remove-Item -Force $f
        $cleanedItems += (Split-Path $f -Leaf)
    }
}
if ($cleanedItems.Count -gt 0) {
    $totalMB = [math]::Round($cleanedSize / 1MB, 1)
    Step-Ok "(释放 $totalMB MB: $($cleanedItems -join ', '))"
} else {
    Step-Ok "(无临时文件)"
}

# ---- 完成 ----
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  [完成] dist\NetPulse.exe 已就绪" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  部署注意:" -ForegroundColor Yellow
Write-Host "    - DHCP 完整检测: 首次跑需管理员权限 (会触发 UAC 自动装 Npcap)" -ForegroundColor Yellow
Write-Host "      无管理员时自动降级 ipconfig 简化检测, 仍可用" -ForegroundColor Yellow
Write-Host "    - iperf3 测速: 首次跑会询问是否自动下载 (默认 Y, ~2MB)" -ForegroundColor Yellow
Write-Host "      也可手动下载 https://iperf.fr/iperf-download.php 放 EXE 同目录" -ForegroundColor Yellow
Write-Host ""
Read-Host "  按 Enter 退出"
