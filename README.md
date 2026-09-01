# NetPulse

> 单文件 Windows 网络诊断命令行工具 · 内置 23 项诊断模块 · v1.5.3

[![GitHub release](https://img.shields.io/github/v/release/silentcrow09/netpulse)](https://github.com/silentcrow09/netpulse/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)]()

## ⬇️ 下载

**最新稳定版见 [Releases 页面](https://github.com/silentcrow09/netpulse/releases/latest)**

直接下载 `NetPulse.exe`（约 25 MB，单文件可执行，免安装），双击即可运行。

> SHA256 见 [Releases 页面](https://github.com/silentcrow09/netpulse/releases/latest)，下载后可对照 `*.sha256.txt` 校验。

NetPulse 是一个面向 Windows 平台的便携网络诊断工具。**单个 `netpulse.py` 文件即可运行**（核心功能仅依赖 Python 标准库），覆盖局域网、网关、DNS、外网、WiFi、测速、TCP、路由等常见排障场景，并可将结果导出为 HTML / JSON 报告（HTML 支持浏览器打印/另存为 PDF）。

## ✨ 特性

- **零依赖即可运行**：核心诊断只用 Python 标准库，无需安装任何第三方包。
- **23 个诊断模块**：从局域网设备扫描、TCP 并发压测、网页分层体检到 NAT 类型与代理检测，覆盖端到端排障链路。
- **根因分析引擎**：6 条内置规则（DNS / WAN / WiFi / Bufferbloat / 网关丢包 / NAT）跨模块聚合证据，按严重度排序输出根因 + 置信度 + 建议；HTML 报告每条根因带「为什么这样判断 / 已基本排除」证据链和**一句话报障卡**（可直接复制发给客服）。
- **场景化诊断 Profile**：`--diagnose slow|disconnect|web|gaming|wifi` 按故障场景一键选模块组合，跑完直接给根因结论。
- **并行执行**：`--parallel` 多模块并发跑（`--max-workers N` 控制并发数），交互菜单多模块默认并发。
- **JSON Schema + 调试包**：结果文件遵循 `schema/netpulse-result-v1.1.json`（`--json-schema` 离线查询版本与字段，供 AI Agent / RMM introspect）；`--debug-bundle DIR` 一键导出脱敏调试包（system + diagnostic + log 的 zip）。
- **TCP 并发能力压测**：阶梯并发连接测试（累计保持），判定网络路径（光猫/路由器 NAT）最大可持续并发；同跑本机回环对照，自动区分「本机瓶颈 vs 网络/NAT 瓶颈」，零依赖、无需自建服务器。
- **盯障模式 `--monitor`**：分钟级持续监测网关/外网 ping + TCP + DNS，抓偶发掉线（普通模块全是快照抓不到）；自动事件检测 + 分段定位（内网侧/运营商侧/解析侧/内外同抖），含**抖动窗口**检测（60s 窗口内反复丢包但未达连续中断 → 抖动集中段，偶发掉线最典型形态），输出带时间轴的 HTML 报告 + Excel 直开的 CSV + 完整 JSON。
- **iperf3 UDP 模式**：`--iperf3-udp` 以 1 Mbps 发包率测点对点抖动/丢包 —— 语音/游戏质量的关键指标。
- **宽带测速 = 带宽体检**：上下行测速 + 预估宽带 + Bufferbloat 评级一体化；
  交互菜单默认叠加 **Ookla 官方测速**（`speedtest.exe`，支持指定国内服务器），
  未启用/失败时回退内置方案（国内镜像多连接下行 + 运营商上行节点），零第三方 Python 依赖。
- **iperf3 链路吞吐（独立模块）**：`iperf3` 模块测量到指定服务器的点对点上下行吞吐
  （需自建 iperf3 服务器），与互联网宽带测速完全分开，报告明确标注"链路吞吐非宽带"。
- **测速实时可视化**：单独测速时终端实时刷新速率/进度，结束自动生成独立测速报告。
- **原生 UDP DNS 探测**：自构造 DNS 报文，并行查询多家国内 DNS，速度快、无需 `nslookup` 进程。
- **双运行模式**：交互式菜单（适合新手）+ 命令行参数（适合脚本/自动化）。
- **专业报告**：导出 HTML（工程风可视化）/ JSON，按日期自动归档到 `reports/YYYY-MM-DD/`。
- **国内网络优化**：默认检测国内 DNS（AliDNS / DNSPod / 114）与公网 IP 服务，不探测国外站点。
- **优雅降级**：可选依赖（scapy / speedtest-cli）缺失时自动降级，不会报错退出。

## 🚀 快速开始

```bash
# 可选：安装增强依赖 (不装也能跑, 对应功能自动降级)
pip install scapy          # Ookla speedtest.exe 随发行版打包/自动下载, 无需 pip

# 进入交互式菜单 (可直接回车运行全部模块)
python netpulse.py
# 交互菜单内: 数字=单模块, 分类字母 a/b/c=按分类运行, 0/all=全部,
#             e=导出上次诊断报告 (回车返回菜单后无需重新测试即可导出)
```

## 🛠 命令行用法

```bash
# 列出全部可用模块
python netpulse.py --list

# 运行全部模块
python netpulse.py all

# 指定模块运行 (支持 key 或序号, 空格分隔; 序号以 --list 实时输出为准)
python netpulse.py gateway dns external
python netpulse.py dhcp gateway dns

# 按分类运行 (a=基础信息  b=宽带测速  c=故障诊断, 可组合)
python netpulse.py a
python netpulse.py a c --export report.html

# 以 JSON 输出完整结果 (便于脚本解析)
python netpulse.py all --json

# 导出报告 (支持 html / json, 逗号分隔多种格式)
python netpulse.py all --export report.html,report.json

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

# 指定测速服务器 (可选): Ookla 服务器数字 ID (配合 --speedtest-net) 或上行节点 host:port; 默认自动选择延迟最低的国内运营商节点
python netpulse.py speedtest --speedtest-node 112.25.80.50:8080

# 启用 Ookla 官方测速 (CLI 显式指定; 交互菜单默认已启用, 支持国内服务器选点)
python netpulse.py speedtest --speedtest-net

# iperf3 链路吞吐测试 (独立模块): 测到指定服务器的上下行吞吐, 非互联网宽带
python netpulse.py iperf3 --iperf3-server 192.168.1.10:5201
python netpulse.py iperf3 --iperf3-server 10.0.0.1 --iperf3-duration 15   # 单方向 15s
# 缺 iperf3.exe 时会询问自动下载; 服务器不可达时明确报"双向均失败"并给出排查提示

# TCP 并发能力压测: 阶梯 50→1600 累计保持连接, 找 NAT 并发上限 + 本机回环对照
python netpulse.py tcpcc
python netpulse.py tcpcc --tcpcc-max 3200                          # 提高阶梯上限
python netpulse.py tcpcc --tcpcc-target 192.168.1.10:5201          # 指向自建服务器复测

# 网页体检: DNS/TCP/TLS/TTFB 分段计时 + 证书 + 重定向 (默认 qq/baidu/aliyun)
python netpulse.py web
python netpulse.py web --web-target https://example.com            # 追加目标

# NAT 类型: STUN 双服务器对比判定锥形/对称型, 检测 UDP 出网受阻 (游戏/P2P 排障)
python netpulse.py nattype
python netpulse.py nattype --nattype-server stun.chat.bilibili.com  # 自定义服务器

# 代理检测: WinINET/WinHTTP/环境变量/VPN 网卡全清点 + 代理可用性探测
python netpulse.py proxy

# iperf3 UDP 模式: 测抖动/丢包 (语音/游戏质量口径, 1 Mbps 发包率)
python netpulse.py iperf3 --iperf3-server 192.168.1.10 --iperf3-udp

# 盯障模式 (独立运行, 不属于 23 个模块): 长时间监测找偶发掉线
python netpulse.py --monitor              # 默认 600 秒 (10 分钟)
python netpulse.py --monitor 1800         # 30 分钟
python netpulse.py --monitor 600 --monitor-target www.baidu.com
# 交互菜单里也有 m=盯障模式 入口; Ctrl+C 提前结束同样生成报告

# 禁用 scapy 二层抓包 (Npcap 不稳定导致崩溃时使用, DHCP 降级)
python netpulse.py dhcp --no-scapy

# 自动安装缺失依赖 (scapy / Npcap), 无需交互确认
python netpulse.py --install
```

常用参数说明：

| 参数 | 说明 |
|------|------|
| `modules` | 要运行的模块 key、序号或分类字母 `a/b/c`；`all` 表示全部；省略则进入交互菜单 |
| `--list` | 列出所有可用模块后退出 |
| `--json` | 以 JSON 格式输出每个模块的完整结果 |
| `--verbose` | 显示完整原始字段（默认仅显示结论 + 关键指标 + 问题清单，细节保存在 HTML/JSON 报告中） |
| `--no-color` | 禁用彩色输出（兼容老旧终端） |
| `--install` | 自动安装缺失依赖 |
| `--no-scapy` | 禁用 scapy 二层抓包，DHCP 检测降级 |
| `--port-target` | 端口探测目标，支持单端口/范围/混合，详见下方 |
| `--port-proto` | 端口探测协议：`tcp`（默认）/ `udp` / `both` |
| `--port-count` | 每个目标采样次数（默认 4） |
| `--port-force` | 强制执行端口探测（即使展开后目标数超过 1000 上限） |
| `--iperf3-server` | iperf3 服务器地址 (iperf3 独立模块必填): 测到该服务器的上下行吞吐 (iperf3.exe 缺失时会交互式询问自动下载)。例: `192.168.1.10` 或 `192.168.1.10:5201` |
| `--iperf3-duration` | iperf3 单方向测速时长秒数 (默认 10) |
| `--tcpcc-target` | TCP 并发测试自定义目标 `HOST:PORT` (可选): 默认自动挑公网 anycast DNS 的 TCP 53 端点 (预检并发友好度) |
| `--tcpcc-max` | TCP 并发阶梯上限 (默认 1600, 硬上限 8000)。高上限会短时建立大量连接, 勿短时间重复运行 |
| `--web-target` | 网页体检追加目标 URL (可选, 可多次; 追加到默认 3 个国内大站后, 总数上限 8) |
| `--nattype-server` | NAT 类型检测的 STUN 服务器 `HOST[:PORT]` (可选, 可指定两次提供两台; 缺省端口 3478); 默认内置国内服务器自动回退 |
| `--iperf3-udp` | iperf3 改用 UDP 模式测抖动/丢包 (1 Mbps 发包率, 语音/游戏质量口径); 默认 TCP 测吞吐 |
| `--monitor` | 盯障模式: 持续监测 `SEC` 秒找偶发掉线, 结束生成 CSV/HTML/JSON 报告 (不带值 = 600 秒; 范围 30-86400; Ctrl+C 提前结束同样生成报告); 与其他模块互斥 |
| `--monitor-target` | 盯障外网 ping 目标 (默认 223.5.5.5, 同时对该目标 TCP 53 建连; 可用域名) |
| `--speedtest-node` | 指定测速服务器 (可选): Ookla 服务器数字 ID (配合 `--speedtest-net`) 或上行节点 `host:port`; 默认自动选延迟最低的国内运营商节点 |
| `--speedtest-net` | 启用 Ookla 官方测速 (CLI 默认关闭, 交互菜单默认启用; 结论优先采用 Ookla 结果) |
| `--diagnose` | 按场景 Profile 诊断: `slow` / `disconnect` / `web` / `gaming` / `wifi`, 跑完输出根因分析; 也支持 `netpulse diagnose <profile>` 子命令形式 |
| `--parallel` | 多模块并行执行 (输出经线程锁同步, 详细结果仍按模块顺序排列); 交互菜单多模块默认并发 |
| `--max-workers` | 并行模式最大并发数 (默认 4) |
| `--port-timeout` | 端口探测总时长上限秒数 (默认 60), 超过跳过剩余目标并在报告 `timed_out_specs` 列出 |
| `--port-concurrency` | 端口探测并发数 (默认 8) |
| `--pip-mirror` | `--install` 自动装依赖时显式指定 pip 镜像 |
| `--json-schema` | 输出当前 JSON Schema 版本号与结构路径 (供 AI Agent / RMM / bot introspect), 不跑诊断 |
| `--debug-bundle` | 生成脱敏调试包 zip (system.json + diagnostic.json + netpulse.log, SSID/MAC/公网 IP/hostname 已脱敏), 用于上报 bug 或远端排障. 例: `--debug-bundle ./out` |
| `--export` | 诊断后导出报告，逗号分隔多格式（`report.html,report.json`） |

## 📋 诊断模块（23 项）

> 按装维工作流分三大类，序号与交互菜单 / `--list` 输出一致；菜单 / CLI 均可用分类字母快捷运行：**a=基础信息、b=宽带测速、c=故障诊断**。

| # | key | 模块 | 说明 |
|---|-----|------|------|
| 1 | `linkspeed` | 链路速率 | 适配器协商速率、双工模式、WiFi 信号强度 |
| 2 | `dhcp` | DHCP 检测 | 发送 DHCP Discover 捕获 Offer，识别多服务器干扰（需 scapy / Npcap） |
| 3 | `lan` | LAN 设备扫描 | `arp -a` 发现局域网设备，结合 MAC OUI 识别厂商 |
| 4 | `wifi` | WiFi 分析 | 扫描周边 WiFi，信道重叠分析，推荐最佳信道 |
| 5 | `ipv6` | IPv6 检测 | IPv6 地址 / 路由 / 连通性 / DNS 全面检测 |
| 6 | `egress` | 多出口 | 多默认路由、VPN 出口、公网 IP 一致性检测 |
| 7 | `speedtest` | 测速 | 带宽体检: 上下行测速 + 预估宽带 + Bufferbloat 评级 (上行用内置国内运营商节点, 零依赖) |
| 8 | `bufferbloat` | Bufferbloat | 负载下延迟测试，评级 A–F |
| 9 | `iperf3` | iperf3 吞吐 | 到指定 iperf3 服务器的点对点上下行吞吐 (链路吞吐非宽带, 需 `--iperf3-server`) |
| 10 | `tcpcc` | TCP 并发 | 阶梯并发连接压测, 判定最大可持续并发 (NAT 表上限), 本机回环对照区分瓶颈位置 |
| 11 | `gateway` | 网关检测 | Ping 默认网关，统计延迟、丢包率、抖动 |
| 12 | `external` | 外网检测 | 多目标 Ping + Traceroute，逐跳延迟、丢包与路径可视化 |
| 13 | `dns` | DNS 诊断 | 多 DNS 服务器原生 UDP 对比，延迟 / 异常 / **DNS 劫持检测** |
| 14 | `web` | 网页体检 | DNS/TCP/TLS/TTFB 分段计时, 证书检查, 重定向跟踪, 断层定位 |
| 15 | `arp` | ARP 分析 | ARP 冲突检测、网关 MAC 验证、ARP 欺骗排查 |
| 16 | `loop` | 环路检测 | ARP 表 / TTL / 丢包模式分析内网环路 |
| 17 | `tcp` | TCP 连接 | 按状态 / 进程统计 TCP 连接，检测连接数超限 |
| 18 | `port` | 端口探测 | TCP / UDP 端口可达性与响应时延 |
| 19 | `route` | 路由表 | 路由环路检测、异常路由、网关子网验证 |
| 20 | `tcpstats` | TCP 传输质量 | 解析 `netstat -s` 重传率、错误段、连接失败数 |
| 21 | `mtu` | MTU 检测 | 二分法发现路径 MTU，识别分片风险 |
| 22 | `proxy` | 代理检测 | WinINET/WinHTTP/环境变量/VPN 网卡代理清点 + 可用性探测 (疑似断网根因) |
| 23 | `nattype` | NAT 类型 | STUN 双服务器对比判定锥形/对称型, UDP 出网受阻检测 (游戏/P2P 排障) |

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
- **纸质留档**：PDF 直接导出已移除。用浏览器打开 HTML 后 `Ctrl+P` 打印或另存为 PDF（内置打印样式：技术细节全部展开、去阴影）。
- **`--export report.json`**：技术员 / 脚本用。含完整 raw 原始数据（30 个 RTT 序列、ARP 表、路由表等）+ 阈值定义 + 健康分计算依据。
- 多个格式可同时导：`--export report.html,report.json`。
- 旧版拍平所有字段的 `.txt` 已废弃，导出 `.txt` 会提示改用 HTML/JSON。

示例：
```bash
# 客户版
python netpulse.py all --port-target 223.5.5.5:53 --export report.html

# 客户版 + 技术员 JSON
python netpulse.py all --port-target 223.5.5.5:53 --export report.html,report.json

# 两种都导 (HTML + JSON)
python netpulse.py all --port-target 223.5.5.5:53 --export report.html,report.json --install
```

### 报告设计要点

- **健康分（0-100）**：异常 -20 / 错误 -30 / 超时 -10 / 警告 -2 / 未检测不扣分（环境缺测不记过）；iperf3 / ipv6 / proxy / nattype 四个环境相关模块评分豁免（不扣总分，异常仍展示）。等级 A/B/C/D/F。
- **待办问题清单**：按严重度排序，每条带"影响 + 建议"（如"网关延迟高 → 检查网线/WiFi 信号/路由 CPU"）。
- **根因摘要 + 证据链**：6 条内置规则跨模块聚合、按严重度排序；每条根因卡带「为什么这样判断 / 已基本排除」证据、影响模块、建议复测命令，并生成可直接复制发客服的**一句话报障卡**。
- **装维可读**：每个模块卡片带一句"这是测什么的、结果怎么看"的说明；行话指标（首字节/P95/并发/CPS、NAT 锥形对称等）附通俗解释；存在异常级问题时清单尾部出现**会诊指引**——现场处置无效的，提示保留 HTML+JSON 报告带回专家分析（.json 含逐跳路径、时序等完整原始数据）。
- **关键指标**：每个模块 3-5 个，颜色按阈值（绿/黄/红）。
- **技术细节**：HTML 默认折叠；完整数据见 `.json`。

### 盯障模式报告（偶发掉线取证单）

`--monitor N`（或交互菜单 `m`）持续监测 N 秒：网关/外网 ping（1s×2 路）+ 外网 TCP 53 + DNS 解析（各 5s），结束后自动保存 **`reports/YYYY-MM-DD/monitor_时间戳.{csv,html,json}`**：

- **事件检测 + 分段定位**：连续丢包 ≥3s 判中断；外网中断且网关正常 → **运营商侧**（带 HTML 报告报障，分钟级时间轴可对齐客服记录）；与网关中断同时 → 内外同断；网关单独中断 → 内网侧；DNS 连续失败而 ping 正常 → 解析侧；另有延迟突增段检测（10s 桶 p95 对比基线）和**抖动窗口**检测（60s 窗口内丢包 ≥3 次或丢包率 ≥10% → 抖动集中段，按段实际时长描述，网关同时丢包 ≥2 次判内外同抖）。
- **HTML 报告**：结论 banner（含处置建议，服务"现场解决不了带回落诊"流程）+ 事件表（时刻/持续/定位/是否已恢复）+ 延迟时序双线图（红色区带标中断时段）+ TCP/DNS 连通率图。
- **CSV 用 Excel 直接打开**（utf-8-sig），一列时间戳可精确对齐客户口述的掉线时刻；JSON 含全部原始样本。
- **Ctrl+C 随时可停**：提前结束同样生成报告；网关漂移（切 WiFi/换路由）自动切换监测目标。
- 提示：监测期间常驻两个 ping 进程 + 周期外联，部分杀软/EDR 可能告警，装维机建议加白。

### 独立测速报告（带宽体检单）

单独运行测速（或任何包含 `speedtest` 的运行）后，自动保存一份专业测速报告到 **`reports/YYYY-MM-DD/speedtest_时间戳.html`**（配套 `.json` 存原始速率/延迟时间序列）：

- **三大指标仪表盘**：下行 / 上行 / 预估宽带 + Bufferbloat 评级
- **速率曲线**：下行（蓝）+ 上行（橙）实时速率时间序列，canvas 绘制、完全离线可用
- **延迟变化曲线**：空闲 → 下行负载 → 上行负载 全程延迟采样，直观反映缓冲膨胀
- **测试详情**：测速方法、节点、延迟目标、空闲/负载延迟、膨胀增量
- 交互式终端运行且单独测速时，报告生成后自动在浏览器打开

## 📦 打包为单文件 EXE

```bash
build_exe.bat
# 生成的 EXE 位于 dist\NetPulse.exe
```

> 若需 DHCP 完整检测，目标机需安装 [Npcap](https://npcap.com/)（勾选 WinPcap API 兼容模式）；
> 默认测速 = 带宽体检：下行（国内镜像多连接）+ 上行（内置国内运营商节点）+ 预估宽带 +
> Bufferbloat 评级，全程零第三方依赖；交互菜单默认叠加 Ookla 官方测速
> （`speedtest.exe` 缺失时会询问自动下载，CLI 模式用 `--speedtest-net` 显式启用）。
> iperf3 是独立模块（`netpulse.py iperf3 --iperf3-server HOST[:PORT]`）：测到指定服务器的
> 链路吞吐（非互联网宽带），需自建 iperf3 服务器；缺少 `iperf3.exe` 时程序会询问是否自动下载
> （或手动放到 EXE 同目录）。

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
| `scapy` | DHCP 完整检测（发送 Discover，需 Npcap） | DHCP 降级为仅读取当前 DHCP 服务器 |
| `cryptography` | 修 scapy 可选模块的导入告警 | 不影响核心功能 |
| Ookla `speedtest.exe` | 官方测速（`--speedtest-net` / 交互菜单默认） | 询问自动下载，或回退内置国内节点测速 |
| `pyinstaller` | 打包为单文件 EXE | 不影响直接运行 |

## 💻 系统要求

- Windows 10 / 11（64 位）
- Python 3.10+
- 部分功能需**管理员权限**（如 scapy 的 DHCP 二层检测）

## 📁 目录结构

```
netpulse.py         单文件主程序 (~16000 行)
build_exe.bat       PyInstaller 打包脚本
requirements.txt    依赖说明
schema/
└── netpulse-result-v1.1.json   JSON 结果 Schema (--json-schema 查询)
deploy/
└── install.ps1     客户端引导脚本 (上传到 OSS, 客户用 irm | iex 拉取)
CHANGELOG.md        更新日志
AGENTS.md           开发/验证约定 (AI 协作者先读)
.gitignore          忽略缓存 / 打包产物 / 运行时报告
reports/            诊断报告输出 (运行时自动生成, 已被 .gitignore 忽略)
```

## 📜 许可证

内部使用，无限制。
