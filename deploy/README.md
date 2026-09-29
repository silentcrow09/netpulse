## 🚀 一键分发部署 (开发者读)

**适用人群**：发版者 / 运维者。客户只读 [主 README § 一键分发部署](../README.md#%F0%9F%9A%80-%E4%B8%80%E9%94%AE%E5%88%86%E5%8F%91%E9%83%A8%E7%BD%B2-%E9%98%BF%E9%87%8C%E4%BA%91-oss)
一段说明。**本文件是发版者于 OSS/aliyun CLI/PowerShell 部署流示例**。

将 NetPulse 部署到阿里云 OSS 后，客户机**一行命令**即可拉取并执行。

### 客户端体验

```powershell
# Windows 10/11 PowerShell (无需预装 Python)
irm https://<bucket>.oss-cn-hangzhou.aliyuncs.com/netpulse/v1/install.ps1 | iex

# 带参数 (透传给 netpulse)
irm https://.../v1/install.ps1 | iex -- all --export report.html
```

引导脚本 `install.ps1` 自动完成：
1. 拉 `index.json` 拿版本号 + SHA256
2. 检测 Python 3.8+ → 有则用 `.py` (300KB)，无则用 `.exe` (25MB)
3. SHA256 校验，不一致立即中止
4. 透传参数并执行

### 5 步上线

| # | 步骤 | 操作 |
|---|------|------|
| 1 | 阿里云 OSS 控制台建 bucket `netpulse-dist`，**读写权限 = 公共读** | （控制台操作）|
| 2 | 装阿里云 CLI 并配置 AccessKey | `winget install Alibaba.AliyunCLI` → `aliyun configure` |
| 3 | 打包 EXE（首次或改了 .py 后） | `build_exe.bat` |
| 4 | 上传文件到 OSS（手动） | 详见下方 |
| 5 | 自测 | `irm https://<bucket>.oss-cn-hangzhou.aliyuncs.com/netpulse/v1/install.ps1 \| iex -- --list` |

### 手动上传一个版本

每次发版需要往 OSS 放 4 个文件（首次还要加 `install.ps1`）：

```
oss://<bucket>/netpulse/v1/
├── install.ps1        ← 首次部署上传一次, 之后不变 (v1.14.4 起按 OS 位数自动选包)
├── netpulse.py        ← 每次发版覆盖
├── netpulse.exe       ← 每次发版覆盖 (64 位)
├── netpulse_x86.exe   ← 每次发版覆盖 (32 位; GitHub Release 的 NetPulse_x86.exe 重命名即可)
└── index.json         ← 每次发版覆盖 (含 SHA256, 见下方生成)
```

**生成 `index.json`**（PowerShell 一行搞定）：

```powershell
$pySha = (Get-FileHash netpulse.py -Algorithm SHA256).Hash.ToLower()
$pySize = (Get-Item netpulse.py).Length
$exePath = ".\dist\NetPulse.exe"
$exeX86Path = ".\dist\NetPulse_x86.exe"     # 从 GitHub Release 下载 NetPulse_x86.exe 放这里
$hasExe = Test-Path $exePath
$index = [ordered]@{
  version = "v1.0.0"   # ← 改这里
  released_at = (Get-Date).ToUniversalTime().ToString("o")
  python = @{ file = "netpulse.py"; sha256 = $pySha; size = $pySize }
}
if ($hasExe) {
  $index.exe = @{ file = "netpulse.exe"; sha256 = (Get-FileHash $exePath -Algorithm SHA256).Hash.ToLower(); size = (Get-Item $exePath).Length }
}
if (Test-Path $exeX86Path) {
  $index.exe_x86 = @{ file = "netpulse_x86.exe"; sha256 = (Get-FileHash $exeX86Path -Algorithm SHA256).Hash.ToLower(); size = (Get-Item $exeX86Path).Length }
}
$index | ConvertTo-Json -Depth 5 | Set-Content index.json -Encoding UTF8
```

**上传到 OSS**（任选一种）：

```powershell
# 方式 A: aliyun CLI (推荐)
aliyun oss cp netpulse.py      oss://<bucket>/netpulse/v1/netpulse.py --force
aliyun oss cp dist\NetPulse.exe oss://<bucket>/netpulse/v1/netpulse.exe --force  # 有 EXE 才传
aliyun oss cp dist\NetPulse_x86.exe oss://<bucket>/netpulse/v1/netpulse_x86.exe --force  # 有 32 位 EXE 才传
aliyun oss cp index.json       oss://<bucket>/netpulse/v1/index.json --force

# 方式 B: OSS 控制台拖拽
# 把上面 4 个文件拖到 bucket 的 netpulse/v1/ 目录下, 设置 ACL = 公共读
```

### 灰度发布

把文件上传到 `netpulse/v1-beta/` 子目录，测试组用：

```powershell
irm https://<bucket>.oss-cn-hangzhou.aliyuncs.com/netpulse/v1-beta/install.ps1 | iex
```

### 日常发版流程

```
1. 改 netpulse.py
2. 跑 build_exe.bat (可选, 重新生成 EXE)
3. 跑上面那段 PowerShell 生成新的 index.json (改 version 字段)
4. 上传 3 个文件覆盖 OSS 上的旧版本
```

