# 更新日志

本项目的所有重要变更都会记录在此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.3.0] - 2026-08-31

### 新增
- **根因引擎 (SECTION 1f)**：从"23 项独立检测"升级为"故障定位"
  - `RootCause` / `DiagnosisReport` dataclass（id/category/severity/title/description/confidence/evidence_ids/affected_modules/recommendations）
  - **6 条内置规则**：
    - `dns_failure` — DNS 解析失败率 > 50% 且网关可达
    - `wan_interruption` — 网关可达但外网目标全失败
    - `wifi_weak` — WiFi 干扰等级 ≥ 较高
    - `bufferbloat` — 加载延迟比空闲延迟高得多（grade D/F）
    - `gateway_loss` — 网关丢包 ≥ 5%
    - `nat_restricted` — STUN 测得 Symmetric NAT
  - `diagnose(results_dict) -> DiagnosisReport`：主入口，跨模块证据聚合
  - `_module_status_confidence` + `_rule_confidence`：基于模块 status + 证据数量的置信度算法
  - **整体置信度加权**：`overall_confidence` 按 severity 权重 (CRITICAL=3, HIGH=2, MEDIUM=1) 计算
- **5 个 Profile**（用户场景驱动的模块组合）：
  - `slow`：网关 + WiFi + 测速 + Bufferbloat + TCP + DNS
  - `disconnect`：网关 + 外网 + DNS + TCP + 环路
  - `web`：DNS + TCP + Web + TCP 质量 + MTU + 路由
  - `gaming`：网关 + TCP + NAT + Bufferbloat + MTU + TCP 质量
  - `wifi`：WiFi + 网关 + LAN
- **CLI `--diagnose PROFILE`** 子命令：按场景诊断并输出根因分析
- **HTML 报告根因摘要区块**：第一屏（hero 之后）显示主要问题卡（severity 配色 + 置信度% + 影响模块 + 可折叠建议）
- **JSON 报告 schema_version 1.1.0** + `diagnosis` 顶层字段

### 测试
- `tests/test_diagnosis.py` **32 项** unittest（覆盖 6 条规则 + 5 profile + diagnose 主入口 + confidence 加权 + Profile 模块注册验证）
- `_smoke_report.py` 109 → **126 项**（17 项新增 diagnose 集成）
- HTML 报告长度 56505 → 60643 字节（CSS + diagnosis section）
- 用户视觉体验：第一屏直接看到「主要问题 + 置信度 + 建议」，再下拉看 evidence 详情

### 不变更（向后兼容）
- CLI `--help` / `--list` 输出不变（仅新增 `--diagnose` 选项）
- `netpulse <modules>` 旧调用方式完全不变
- JSON 报告新增 `schema_version` + `diagnosis` 字段，旧解析器忽略未知字段即可兼容
- HTML 报告布局变化：hero 之后**插入** diagnosis section（原有 todo / stats / mod 区块不变）

[1.3.0]: https://github.com/silentcrow09/netpulse/compare/v1.2.0...v1.3.0

## [1.2.0] - 2026-08-31

### 新增
- **Parsers 区块** (SECTION 1d)：集中 Windows 命令文本解析
  - `parse_ipconfig(raw)` → `list[NetworkAdapter]`（中英文 Windows 都支持）
  - `parse_route_print(raw)` → `list[RouteEntry]`（含 On-link 判定）
  - `parse_arp_a(raw)` → `list[ArpEntry]`（含 interface 段落归属）
  - `parse_netsh_wlan_interfaces(raw)` → `list[WifiInterface]`（行尾归一化）
- **Probes 区块** (SECTION 1e)：5 模块迁移到 Probe 契约
  - `probe_gateway_v2` / `probe_dns_v2` / `probe_route_v2` / `probe_arp_v2` / `probe_wifi_v2`
  - 统一返回 `DiagnosticResult`，`.metrics` 字段保留旧 results dict 兼容
  - `_V2_PROBES` 注册表 + `_register_probe(key)` 装饰器
  - `_wrap_as_diagnostic_result()` helper（B8-B11 共享 dict→DR 包装）
- **`CONFIG` 顶层字典**：把散落的 `PORT_PROBE_CONFIG` / `SPEEDTEST_CONFIG` / `NATTYPE_CONFIG` / `WEB_CONFIG` / `TCPCC_CONFIG` 集中到 `CONFIG["port"]` / ...
- 旧 CONFIG 名字作为 alias 指向 CONFIG 子项（dict 引用同一对象，零侵入）

### 变更
- `_run_module_with_timeout` 双轨化：key 在 `_V2_PROBES` 走 probe 路径，否则走旧 Tester.detect()
- 5 个 Tester 类加 `@deprecated v1.2.0 (B7-B11)` 注释（仍被 probe 函数调 detect()，等 v1.3.0 用户无感知后再硬删除）

### 测试
- `_smoke_report.py` 60 → **109 项**（含 parser + probe + CONFIG 集中化 + 双轨分支）
- `tests/test_parsers.py` **23 项** unittest（覆盖 4 parser + dataclass + 边界场景）
- `tests/test_probes.py` **33 项** unittest（覆盖 5 probe + helper + status 推导）
- HTML 报告长度 56505 字节零差异（用户视觉零回归）

### 不变更（向后兼容）
- CLI / HTML / JSON 字段完全一致
- `--list` 仍列 23 项
- 用户感知：`netpulse gateway` / `dns` / `route` / `arp` / `wifi` 输出与 v1.1.0 逐字一致
- 旧 `STATUS_KEY` / `STATUS_COLORS` / `STATUS_BAR_ORDER` / `PROBLEM_STATUSES` 完全保留

[1.2.0]: https://github.com/silentcrow09/netpulse/compare/v1.1.0...v1.2.0

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