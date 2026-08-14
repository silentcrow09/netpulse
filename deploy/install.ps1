# =============================================================================
# NetPulse Bootstrap Installer
# -----------------------------------------------------------------------------
# 用法 (PowerShell, Windows 10/11 默认支持):
#   irm https://<your-oss>/netpulse/v1/install.ps1 | iex
#
# 也可手动运行:
#   iwr -useb https://<your-oss>/netpulse/v1/install.ps1 | Out-File install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# 行为:
#   1. 拉 index.json 拿当前版本号和 SHA256
#   2. 检测本机是否有 Python 3.x
#      - 有 -> 下载 netpulse.py (300KB, 快)
#      - 没 -> 下载 netpulse.exe (PyInstaller 打包, 15-30MB)
#   3. 校验 SHA256, 不一致立即中止
#   4. 透传所有 netpulse 命令行参数 (e.g. `... | iex -- all --json`)
# =============================================================================

[CmdletBinding()]
param(
    # OSS 公共读根地址 (末尾不要带 /)
    [string]$BaseUrl = 'https://netpulse-dist.oss-cn-hangzhou.aliyuncs.com/netpulse',

    # 版本通道 (v1 / v2 / stable ...), 改这个切到不同主版本
    [string]$Channel = 'v1',

    # 强制使用 EXE 模式 (跳过 Python 检测)
    [switch]$ForceExe,

    # 强制使用 Python 模式 (没有 Python 就退出报错)
    [switch]$ForcePython,

    # 只下载不执行 (调试用)
    [switch]$DownloadOnly,

    # 跳过 SHA256 校验 (不推荐)
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

# -----------------------------------------------------------------------------
# 颜色输出
# -----------------------------------------------------------------------------
function Write-Banner {
    Write-Host ''
    Write-Host '  ============================================' -ForegroundColor Cyan
    Write-Host '         NetPulse Bootstrap Installer' -ForegroundColor Cyan
    Write-Host '  ============================================' -ForegroundColor Cyan
    Write-Host ''
}

function Write-Step($msg)  { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "[X] $msg" -ForegroundColor Red }

# -----------------------------------------------------------------------------
# 1. 拉 index.json
# -----------------------------------------------------------------------------
function Get-Index {
    $url = "$BaseUrl/$Channel/index.json"
    Write-Step "Fetching metadata: $url"
    try {
        # 加时间戳避免 CDN 缓存
        $resp = Invoke-WebRequest -Uri "$url`?t=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" `
                                  -UseBasicParsing -TimeoutSec 15
        $json = $resp.Content | ConvertFrom-Json
        return $json
    } catch {
        Write-Err "无法拉取 index.json: $($_.Exception.Message)"
        Write-Host "  请检查 BaseUrl ($BaseUrl) 和 Channel ($Channel) 是否正确" -ForegroundColor Gray
        Write-Host "  或者 OSS bucket 是否开了公共读" -ForegroundColor Gray
        throw
    }
}

# -----------------------------------------------------------------------------
# 2. 检测 Python 3
# -----------------------------------------------------------------------------
function Get-Python {
    $candidates = @('python', 'python3', 'py')
    foreach ($cmd in $candidates) {
        $exe = Get-Command $cmd -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        try {
            $ver = & $cmd -c 'import sys; print("%d.%d" % (sys.version_info.major, sys.version_info.minor))' 2>$null
            if ($ver -and $ver -match '^3\.(\d+)') {
                $minor = [int]$Matches[1]
                if ($minor -ge 8) {
                    return @{ Command = $cmd; Version = $ver; Path = $exe.Source }
                }
            }
        } catch { }
    }
    return $null
}

# -----------------------------------------------------------------------------
# 3. 下载文件 (带进度)
# -----------------------------------------------------------------------------
function Get-NetPulseFile {
    param(
        [string]$RemoteName,
        [string]$LocalPath
    )
    $url = "$BaseUrl/$Channel/$RemoteName"
    Write-Step "Downloading $RemoteName ..."
    Write-Host "    from: $url" -ForegroundColor Gray
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $LocalPath -UseBasicParsing -TimeoutSec 120
    } catch {
        Write-Err "下载失败: $($_.Exception.Message)"
        throw
    }
    $size = (Get-Item $LocalPath).Length
    Write-Ok "Downloaded ($([math]::Round($size/1KB, 1)) KB)"
    return $size
}

# -----------------------------------------------------------------------------
# 4. SHA256 校验
# -----------------------------------------------------------------------------
function Test-Sha256 {
    param(
        [string]$FilePath,
        [string]$Expected
    )
    if ($SkipVerify) {
        Write-Warn "跳过 SHA256 校验 (--SkipVerify)"
        return
    }
    Write-Step "Verifying SHA256 ..."
    $actual = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    $expected = $Expected.ToLower()
    if ($actual -ne $expected) {
        Write-Err "SHA256 不匹配!"
        Write-Host "    Expected: $expected" -ForegroundColor Gray
        Write-Host "    Actual:   $actual"   -ForegroundColor Gray
        throw "Checksum mismatch - file may be corrupted or tampered with."
    }
    Write-Ok "SHA256 verified"
}

# =============================================================================
# Main
# =============================================================================
Write-Banner

# 收 netpulse 自己的参数 (从 iex 管道进来时, 位置参数在 $args 里)
$netpulseArgs = @()
if ($args) {
    # iex 时 $args 包含传给脚本的所有位置参数
    $netpulseArgs = $args
}

# 1) 拉 index
$index = Get-Index
Write-Ok "Channel: $Channel, Version: $($index.version), Released: $($index.released_at)"
Write-Host ''

# 2) 决定模式
$useExe = $false
if ($ForceExe) {
    $useExe = $true
    Write-Step "Mode: EXE (forced via --ForceExe)"
} elseif ($ForcePython) {
    $useExe = $false
    Write-Step "Mode: Python (forced via --ForcePython)"
} else {
    $py = Get-Python
    if ($py) {
        $useExe = $false
        Write-Ok "Found Python: $($py.Version) at $($py.Path)"
    } else {
        $useExe = $true
        Write-Warn "Python 3.8+ not found, falling back to EXE mode"
    }
}
Write-Host ''

# 3) 准备临时目录
$tempDir = Join-Path $env:TEMP "netpulse-$($index.version)-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
Write-Step "Workspace: $tempDir"

# 4) 下载
if ($useExe) {
    if (-not $index.exe) {
        Write-Err "index.json 中没有 exe 字段, 无法用 EXE 模式"
        Write-Host "  请先在管理端打包并上传 netpulse.exe" -ForegroundColor Gray
        exit 1
    }
    $localFile = Join-Path $tempDir $index.exe.file
    Get-NetPulseFile -RemoteName $index.exe.file -LocalPath $localFile
    Test-Sha256 -FilePath $localFile -Expected $index.exe.sha256
    $runCmd = "& `"$localFile`""
} else {
    if (-not $index.python) {
        Write-Err "index.json 中没有 python 字段"
        exit 1
    }
    $localFile = Join-Path $tempDir $index.python.file
    Get-NetPulseFile -RemoteName $index.python.file -LocalPath $localFile
    Test-Sha256 -FilePath $localFile -Expected $index.python.sha256
    # 用哪个 python 命令
    $py = Get-Python
    $pyCmd = if ($py) { $py.Command } else { 'python' }
    $runCmd = "& $pyCmd `"$localFile`""
}

Write-Host ''

# 5) 执行
if ($DownloadOnly) {
    Write-Ok "DownloadOnly 模式, 文件已保存到: $localFile"
    Write-Host "  手动运行: $runCmd" -ForegroundColor Gray
    exit 0
}

Write-Step "Running NetPulse $($index.version) ..."
Write-Host ('-' * 60) -ForegroundColor DarkGray

try {
    if ($netpulseArgs.Count -gt 0) {
        # 透传参数
        $argList = @($netpulseArgs | ForEach-Object { [string]$_ })
        & $runCmd.Substring(2).Trim() @argList
    } else {
        Invoke-Expression $runCmd
    }
} catch {
    Write-Host ''
    Write-Err "NetPulse 执行失败: $($_.Exception.Message)"
    exit 1
}
