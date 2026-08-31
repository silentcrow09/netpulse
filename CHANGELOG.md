# 更新日志

本项目的所有重要变更都会记录在此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.1.0] - 2026-08-31

### 变更（内部基建，**无对外行为变化**）
- V2 演进路线图（A 线路）阶段 A 完成——为后续根因引擎 / Profiles / JSON Schema 铺路
- 新增 `Status` / `Severity` / `RiskLevel` 枚举（替代散落字符串 `完成/警告/异常/错误/超时/未检测`）
- 新增 `DiagnosticResult` / `Evidence` / `Issue` / `DiagnosticError` / `ModuleMeta` dataclass
- 新增 `STATUS_ZH_KEY` / `STATUS_KEY_TO_STATUS` 兼容桥接映射
- `_smoke_report.py` 断言 25 → 60 项（覆盖新模型序列化往返 + 旧 `STATUS_KEY` / `STATUS_COLORS` 完整性）
- 现有 `STATUS_KEY` / `STATUS_COLORS` / `STATUS_BAR_ORDER` / `PROBLEM_STATUSES` 完全保留
- HTML 报告 / CLI 输出 / JSON 字段保持完全一致（`_verify_latest.html` 长度 56505 字节零差异）
- 不引入任何新依赖（`dataclasses` + `enum` 标准库）

[1.1.0]: https://github.com/silentcrow09/netpulse/compare/v1.0.0...v1.1.0

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