# NetPulse

> 单文件 Windows 网络诊断命令行工具 · 内置 18 项诊断模块 · v1.0.0

NetPulse 是一个面向 Windows 平台的便携网络诊断工具。**单个 `netpulse.py` 文件即可运行**（核心功能仅依赖 Python 标准库），覆盖局域网、网关、DNS、外网、WiFi、测速、TCP、路由等常见排障场景，并可将结果导出为 HTML / PDF / TXT 报告。

## ✨ 特性

- **零依赖即可运行**：核心诊断只用 Python 标准库，无需安装任何第三方包。
- **18 个诊断模块**：从局域网设备扫描到 TCP 传输质量，覆盖端到端排障链路。
- **原生 UDP DNS 探测**：自构造 DNS 报文，并行查询多家国内 DNS，速度快、无需 `nslookup` 进程。
- **双运行模式**：交互式菜单（适合新手）+ 命令行参数（适合脚本/自动化）。
- **专业报告**：导出 HTML（工程风可视化）/ PDF / TXT，按日期自动归档到 `reports/YYYY-MM-DD/`。
- **国内网络优化**：默认检测国内 DNS（AliDNS / DNSPod / 114）与公网 IP 服务，不探测国外站点。
- **优雅降级**：可选依赖（scapy / speedtest-cli）缺失时自动降级，不会报错退出。

## 🚀 快速开始

```bash
# 可选：安装增强依赖 (不装也能跑, 对应功能自动降级)
pip install scapy speedtest-cli

# 进入交互式菜单 (可直接回车运行全部模块)
python netpulse.py
```

## 🛠 命令行用法

```bash
# 列出全部可用模块
python netpulse.py --list

# 运行全部模块
python netpulse.py all

# 指定模块运行 (支持 key 或序号, 空格分隔)
python netpulse.py gateway dns external
python netpulse.py 2 10 4

# 以 JSON 输出完整结果 (便于脚本解析)
python netpulse.py all --json

# 导出报告 (支持 txt / html / pdf, 逗号分隔多种格式)
python netpulse.py all --export report.pdf,report.html,report.txt

# 端口探测: 指定目标与协议
python netpulse.py port --port-target 223.5.5.5:53,119.29.29.29:53 --port-proto both --port-count 4

# 端口探测: 范围扫描 (host:port1-port2)
python netpulse.py port --port-target 10.0.0.1:1-1024

# 端口探测: 混合 (离散 + 范围)
python netpulse.py port --port-target "8.8.8.8:80,443,8000-8100"

# 端口探测: 多个目标主机
python netpulse.py port --port-target a.com:80 --port-target b.com:443

# 端口探测: 超过 1000 目标数, 加 --port-force
python netpulse.py port --port-target "10.0.0.0/24:80" --port-force

# 禁用 scapy 二层抓包 (Npcap 不稳定导致崩溃时使用, DHCP 降级)
python netpulse.py dhcp --no-scapy

# 自动安装缺失依赖 (scapy / Npcap), 无需交互确认
python netpulse.py --install
```

常用参数说明：

| 参数 | 说明 |
|------|------|
| `modules` | 要运行的模块 key 或序号；`all` 表示全部；省略则进入交互菜单 |
| `--list` | 列出所有可用模块后退出 |
| `--json` | 以 JSON 格式输出每个模块的完整结果 |
| `--verbose` | 完整输出，不截断长字段 |
| `--no-color` | 禁用彩色输出（兼容老旧终端） |
| `--install` | 自动安装缺失依赖 |
| `--no-scapy` | 禁用 scapy 二层抓包，DHCP 检测降级 |
| `--port-target` | 端口探测目标，支持单端口/范围/混合，详见下方 |
| `--port-proto` | 端口探测协议：`tcp`（默认）/ `udp` / `both` |
| `--port-count` | 每个目标采样次数（默认 4） |
| `--port-force` | 强制执行端口探测（即使展开后目标数超过 1000 上限） |
| `--export` | 诊断后导出报告，逗号分隔多格式（`report.pdf,report.html`） |

## 📋 诊断模块（18 项）

| # | key | 模块 | 说明 |
|---|-----|------|------|
| 1 | `dhcp` | DHCP 检测 | 发送 DHCP Discover 捕获 Offer，识别多服务器干扰（需 scapy / Npcap） |
| 2 | `gateway` | 网关检测 | Ping 默认网关，统计延迟、丢包率、抖动 |
| 3 | `loop` | 环路检测 | ARP 表 / TTL / 丢包模式分析内网环路 |
| 4 | `external` | 外网检测 | 多目标 Ping + Traceroute，逐跳延迟、丢包与路径可视化 |
| 5 | `linkspeed` | 链路速率 | 适配器协商速率、双工模式、WiFi 信号强度 |
| 6 | `wifi` | WiFi 分析 | 扫描周边 WiFi，信道重叠分析，推荐最佳信道 |
| 7 | `tcp` | TCP 连接 | 按状态 / 进程统计 TCP 连接，检测连接数超限 |
| 8 | `port` | 端口探测 | TCP / UDP 端口可达性与响应时延 |
| 9 | `egress` | 多出口 | 多默认路由、VPN 出口、公网 IP 一致性检测 |
| 10 | `dns` | DNS 诊断 | 多 DNS 服务器原生 UDP 对比，延迟 / 异常 / **DNS 劫持检测** |
| 11 | `mtu` | MTU 检测 | 二分法发现路径 MTU，识别分片风险 |
| 12 | `arp` | ARP 分析 | ARP 冲突检测、网关 MAC 验证、ARP 欺骗排查 |
| 13 | `bufferbloat` | Bufferbloat | 负载下延迟测试，评级 A–F |
| 14 | `ipv6` | IPv6 检测 | IPv6 地址 / 路由 / 连通性 / DNS 全面检测 |
| 15 | `route` | 路由表 | 路由环路检测、异常路由、网关子网验证 |
| 16 | `speedtest` | 测速 | 国内镜像多连接下载测速（可选 iperf3 上下行 / Speedtest.net 参考） |
| 17 | `lan` | LAN 设备扫描 | `arp -a` 发现局域网设备，结合 MAC OUI 识别厂商 |
| 18 | `tcpstats` | TCP 传输质量 | 解析 `netstat -s` 重传率、错误段、连接失败数 |

## 🔌 端口探测 `--port-target` 语法

支持单端口、范围、混合，以及多目标主机：

```bash
# 单端口
--port-target 223.5.5.5:53

# 单主机多端口 (逗号分隔)
--port-target "223.5.5.5:80,443,8080"

# 端口范围 (短横线)
--port-target 10.0.0.1:1-1024
--port-target 8.8.8.8:8000-8100

# 混合 (离散 + 范围)
--port-target "8.8.8.8:22,80,443,8000-8100"

# 多个目标主机 (多次 --port-target)
--port-target a.com:80 --port-target b.com:443

# IPv6 主机
--port-target "[2400:3200::1]:443"
--port-target "[::1]:80-82"
```

**安全限流**：单次探测目标数（`host:port` 展开后）默认上限 **1000**。超过会拒绝并提示加 `--port-force`。例：
```bash
--port-target 10.0.0.1:1-1500      # 1500 目标, 被拦下
--port-target 10.0.0.1:1-1500 --port-force   # 强制执行
```

## 📄 报告导出

报告是给客户看的，技术细节放 JSON 单独存。**`reports/YYYY-MM-DD/`** 按日期归档。

- **`--export report.html`**：客户版 HTML，含健康分、待办问题清单、关键指标、可折叠技术细节。
- **`--export report.pdf`**：客户版 PDF，浅色主题、模块卡片化、适合打印/留档。
- **`--export report.json`**：技术员 / 脚本用。含完整 raw 原始数据（30 个 RTT 序列、ARP 表、路由表等）+ 阈值定义 + 健康分计算依据。
- 多个格式可同时导：`--export report.html,report.pdf,report.json`。
- 旧版拍平所有字段的 `.txt` 已废弃，导出 `.txt` 会提示改用 HTML/PDF/JSON。

示例：
```bash
# 客户版
python netpulse.py all --port-target 223.5.5.5:53 --export report.html

# 客户版 + 技术员 JSON
python netpulse.py all --port-target 223.5.5.5:53 --export report.html,report.json

# 三种都导 (HTML + PDF + JSON)
python netpulse.py all --port-target 223.5.5.5:53 --export report.html,report.pdf,report.json --install
```

### 报告设计要点

- **健康分（0-100）**：异常 -20 / 错误 -30 / 警告 -5 / 未检测 -2。等级 A/B/C/D/F。
- **待办问题清单**：按严重度排序，每条带"影响 + 建议"（如"网关延迟高 → 检查网线/WiFi 信号/路由 CPU"）。
- **关键指标**：每个模块 3-5 个，颜色按阈值（绿/黄/红）。
- **技术细节**：HTML 默认折叠；PDF 弱化为浅灰小表；完整数据见 `.json`。

## 📦 打包为单文件 EXE

```bash
build_exe.bat
# 生成的 EXE 位于 dist\NetPulse.exe
```

> 若需 DHCP 完整检测，目标机需安装 [Npcap](https://npcap.com/)（勾选 WinPcap API 兼容模式）；
> 若需 iperf3 测速（可测上下行），用 `--iperf3-server HOST[:PORT]` 指定服务器，
> 缺少 `iperf3.exe` 时程序会询问是否自动下载（或手动放到 EXE 同目录）。
> 默认测速为国内镜像多连接下载（仅下行）；`--speedtest-net` 可开启 Speedtest.net
> 作参考（国内网络下常选中海外服务器，结果会严重偏低并给出提示）。

## 🚀 一键分发部署

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

每次发版需要往 OSS 放 3 个文件（首次还要加 `install.ps1`）：

```
oss://<bucket>/netpulse/v1/
├── install.ps1       ← 首次部署上传一次, 之后不变
├── netpulse.py       ← 每次发版覆盖
├── netpulse.exe      ← 每次发版覆盖 (可选)
└── index.json        ← 每次发版覆盖 (含 SHA256, 见下方生成)
```

**生成 `index.json`**（PowerShell 一行搞定）：

```powershell
$pySha = (Get-FileHash netpulse.py -Algorithm SHA256).Hash.ToLower()
$pySize = (Get-Item netpulse.py).Length
$exePath = ".\dist\NetPulse.exe"
$hasExe = Test-Path $exePath
$index = [ordered]@{
  version = "v1.0.0"   # ← 改这里
  released_at = (Get-Date).ToUniversalTime().ToString("o")
  python = @{ file = "netpulse.py"; sha256 = $pySha; size = $pySize }
}
if ($hasExe) {
  $index.exe = @{ file = "netpulse.exe"; sha256 = (Get-FileHash $exePath -Algorithm SHA256).Hash.ToLower(); size = (Get-Item $exePath).Length }
}
$index | ConvertTo-Json -Depth 5 | Set-Content index.json -Encoding UTF8
```

**上传到 OSS**（任选一种）：

```powershell
# 方式 A: aliyun CLI (推荐)
aliyun oss cp netpulse.py      oss://<bucket>/netpulse/v1/netpulse.py --force
aliyun oss cp dist\NetPulse.exe oss://<bucket>/netpulse/v1/netpulse.exe --force  # 有 EXE 才传
aliyun oss cp index.json       oss://<bucket>/netpulse/v1/index.json --force

# 方式 B: OSS 控制台拖拽
# 把上面 3 个文件拖到 bucket 的 netpulse/v1/ 目录下, 设置 ACL = 公共读
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

## 🔧 可选依赖

| 依赖 | 用途 | 缺失时 |
|------|------|--------|
| `scapy` | DHCP 完整检测（发送 Discover） | DHCP 降级为仅读取当前 DHCP 服务器 |
| `speedtest-cli` | Speedtest.net 测速（可选，`--speedtest-net`） | 不启用；仅用国内镜像测速 |
| `pyinstaller` | 打包为单文件 EXE | 不影响直接运行 |

## 💻 系统要求

- Windows 10 / 11（64 位）
- Python 3.10+
- 部分功能需**管理员权限**（如 scapy 的 DHCP 二层检测）

## 📁 目录结构

```
netpulse.py         单文件主程序 (~4000 行)
build_exe.bat       PyInstaller 打包脚本
requirements.txt    依赖说明
deploy/
└── install.ps1     客户端引导脚本 (上传到 OSS, 客户用 irm | iex 拉取)
.gitignore          忽略缓存 / 打包产物 / 运行时报告
reports/            诊断报告输出 (运行时自动生成, 已被 .gitignore 忽略)
```

## 📜 许可证

内部使用，无限制。
