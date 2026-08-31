# 更新日志

本项目的所有重要变更都会记录在此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.0.0] - 2026-08-31

### 新增
- 单文件可执行版本 `NetPulse.exe`（PyInstaller 打包，约 25 MB）
- 23 项诊断模块：局域网扫描、网关、DNS、外网、WiFi、宽带测速、TCP 压测、路由、NAT 类型、代理检测等
- TCP 并发能力压测：阶梯并发连接，自动区分本机瓶颈与网络/NAT 瓶颈
- 盯障模式 `--monitor`：分钟级持续监测，自动事件检测 + 分段定位
- iperf3 UDP 模式：1 Mbps 发包率测抖动/丢包
- 宽带测速：上下行测速 + 预估宽带 + Bufferbloat 评级
- 原生 UDP DNS 探测：自构造 DNS 报文并行查询多家国内 DNS
- 双运行模式：交互式菜单 + 命令行参数
- HTML / JSON 报告导出，支持浏览器打印/另存为 PDF
- 国内网络优化：默认使用国内 DNS（AliDNS / DNSPod / 114）与公网 IP 服务

[Unreleased]: https://github.com/henu_09/netpulse/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/henu_09/netpulse/releases/tag/v1.0.0