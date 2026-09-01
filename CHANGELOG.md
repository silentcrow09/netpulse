# 更新日志

本项目的所有重要变更都会记录在此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.5.3] - 2026-09-01

代码审查修复 10 项（审查范围 v1.5.0–v1.5.2 三次提交）：2 项新功能承诺被反转、3 项抖动检测判定缺陷、2 项截断误伤，另有性能、漏检、文案各 1 项。

### 修复

- **首要根因按 severity 排序**（`diagnose()`）：`root_causes[0]` 被 HTML 报告模块折叠策略当作「首要根因」，但原为注册表顺序 — WAN 中断（CRITICAL）叠加 DNS 故障（HIGH）时 DNS 排前，最严重问题的证据反被折叠到一次点击之后。现按严重度降序（同级保持注册表顺序），CLI 清单 / 报障工单 / HTML 卡片同步受益
- **检测范围去重**：`_parse_keys` 保序去重 + `selected_modules` 去重计数 — 重复 token（如 `a c c a` 分类字母重复展开）会使模块双跑、sel > tot，Hero 反而显示「23 项全覆盖」
- **抖动丢包率判据修正**（`_detect_jitter_segments`）：原「窗口样本 ≥ 窗口一半才算完整」与「丢包率 ≥10% 且丢包 <3 次」数学互斥（丢包 ≤2 且 ≥10% ⇒ 样本 ≤20 < 30），丢包率分支从未生效，检测退化为纯计数。现改为：窗口内丢包 ≥3 次，**或**丢包 ≥2 次且样本 ≥10 个且丢包率 ≥10%
- **抖动窗口改真滑动**：原固定 10s 网格步进使跨度 50-60s 的丢包束是否命中取决于与会话起点的相位对齐（同一形态可能报或不报）。窗口起点现锚定丢包时刻（含 ≥3 次丢包的任意窗口都可平移到窗口内最早丢包处而不丢样本），彻底消除网格缝隙漏检
- **抖动窗口计数 O(n²) → O(n·log n)**：每窗对 loss_times / all_times 的全量线性扫描改为 bisect 二分 — 24h 盯障（86400s 上限）汇总从两流 ~75s 降到毫秒级，Ctrl+C 后不再冻结约 1.5 分钟
- **网关单次丢包不再判 both_down**：抖动段分类原 `gw_loss_n >= 1` 与中断判据（网关连续 ≥3 丢包）口径不一致，网关一次孤立 WiFi 超时就把运营商侧抖动误定位为「链路/设备侧」。现需网关同时丢包 ≥2 次
- **跨流重叠去重修正**：抖动段与中断段的重叠抑制原把两流 outage 混在一个池且整段丢弃 — 另一条流 2-3s 的中断与抖动段相切 1s 就吞掉整段 40s+ 抖动。现只与本流中断段比对
- **抖动事件 detail 按段实际跨度描述**：原硬编码「60s 窗口内反复丢包 N/M (P%)」，但相邻触发窗口合并后段可远超 60s、段口径丢包率可低于 10% 触发线（实测打出过「60s 窗口内 … 6/83 (7.2%)」的自相矛盾行）。现按段时长描述（「{N}s 内反复丢包 …」）
- **模块卡正文「结论」行不再截断**：v1.5.1 第三层 60 字兜底误伤本无空间约束的卡片正文 — 打印/PDF 不显示 title，Ookla 成功结论（常态 70-90 字，含上行速率与海外选点警示）与 NAT 对称型双映射地址被拦腰截断，纸质留档缺文。现只截折叠态摘要行（与「检测结果一览」同口径），正文渲染全文
- **测速顶层 error 结论截断**：`_verdict_speedtest` 兜底分支未走 `_err_short` — 执行器把异常 `str(exc)` 整包塞进 error 时可上百字符，原样进 CLI 结论。现统一截断 40 字

### 验证

`tests/` 119 → 120 项（新增 root_causes severity 排序断言）；`_smoke_report.py` 186 → 192 项（新增：丢包率判据生效、57s 跨度相位盲检、跨流不吞段、网关单次丢包不误判、测速 error 截断、正文结论不截断）。24h 盯障（86400s）抖动汇总实测 452ms/流（旧实现 ~37s/流）。

## [1.5.2] - 2026-09-01

盯障模式新增「抖动窗口」检测：偶发掉线最典型的形态不是连续中断，而是短窗口内反复丢包，原事件判定（连续丢包 ≥3 次才报中断、延迟 p95 > 200ms 才报突增）会漏掉这类现象。

背景：用户对 2026-09-01 10:45:33~10:55:33 盯障报告核对数据时发现——全部 14 次丢包（网关 4 次 + 外网 10 次）和 RTT 尖峰都集中在第 390~450s（10:52:03~10:52:59），外网该窗口丢包率 10/61 ≈ 16.4%，但报告结论「监测稳定 / 事件 0 起 / 最长中断 0s」完全没体现，易误导报障方向。

### 新增

- **`_detect_jitter_segments`**：60s 宽、10s 步进的滑动窗口扫描，窗口内丢包 ≥3 次**或**丢包率 ≥10%（窗口样本 ≥ 一半才算完整，防会话尾部 1/10=10% 边界误报）记为抖动窗口，相邻触发窗口合并成段，段界取段内最早/最晚丢包时刻，贴合实际抖动期
- **`jitter_burst` 事件**（`_detect_monitor_events`）：网关段定位 `internal`（内网段抖动）；外网段按窗口内网关状态分 `both_down`（内外同抖）/ `carrier`（运营商/上联侧）/ `unknown`；与 `outage` 中断段重叠时不重复报
- **结论矩阵**：`jitter_burst` 优先级高于 `latency_spike`（有实际丢包比纯延迟突增更重），verdict=`degraded`，conclusion 给出抖动时段与窗口内丢包数，advice 按定位给处置建议（光衰/LOS、路由器日志、与客户掉线记录对齐）
- **root_cause / summary / HTML**：抖动事件带根因标签；summary 追加「抖动集中 N 段」；事件表类型名「抖动集中」

### 验证

用下载目录真实盯障 JSON 重放：检出 2 段（网关 4/29=13.8% internal + 外网 10/38=26.3% both_down，时段 10:52:04~10:53:02），verdict=`degraded`。边界用例：均匀散布 10 次丢包不误报、连续 3 次丢包由中断事件覆盖、单路突发/短会话均正确。`_smoke_report.py` 178 → 185 项。

## [1.5.1] - 2026-09-01

修复测速模块结论信息泄露「代码噪声」问题（报告可信度回归）。

用户反馈：Ookla 测速失败时，报告结论串出 `Protocol error: Did not receive HELLO; input:/VJ+... result:... key:...` 这类 base64 协议握手日志，看起来像代码崩溃。

根因（三层链路每层都缺一道清洗）：

1. 源头（probe）：Ookla 失败时把 `speedtest.exe` 原始 stdout 前 200 字符塞进 error，base64 是协议握手日志
2. 拼装（`_verdict_speedtest`）：把完整 error 原样拼进一句话结论
3. 渲染：详细模块卡「结论」行无长度上限完整展示 verdict

修复（三层组合）：

- 源头清洗：不再塞 `out[:200]`，优先提取 Ookla CLI log 行的 message（error/warning 级优先，info 级流水日志跳过），退化固定文案「speedtest.exe 输出异常 (无有效 result 行)」
- verdict 截短：`_verdict_speedtest` 对失败原因统一截断 40 字 + `…`，模块级 error 分支同样防护
- 渲染兜底：详细模块卡结论统一截断 60 字（与「检测结果一览」同口径）+ `title` 悬停看全文，防任何模块未来塞长文本

同类排查：web / ipv6 / mtu / tcp 等模块 error 均已截断，测速是全仓唯一把原始命令输出塞进 error 的位置。

测试：`_smoke_report.py` 170 → 178 项（新增 base64 噪声回归、源头清洗断言、error 截断断言、渲染兜底 60 字截断 + title 悬停 + 一览行同步截断）。

## [1.5.0] - 2026-09-01

HTML 报告第二轮优化：从「诊断 Dashboard」走向「诊断报告」。依据专家评审 31 条逐条核对源码后落地 6 项（评审中 3 条与代码现状不符，未采纳；2 条与项目红线冲突，列为暂缓）。

### 安全
- **P0 HTML 属性转义**：`_html_esc` 使用 `quote=False` 却把结果拼进单引号 HTML 属性（`title=` / `data-hint=` / `href=` / `data-mod=` / `id=`），恶意 SSID / DNS 名 / hostname 可闭合属性注入标签。现在拆成两个函数：文本节点用 `_html_esc`（不转义引号），**属性值一律用 `_html_attr`**（`quote=True`）；7 处属性拼接点全部复核

### 新增
- **根因证据链**：根因卡新增「为什么这样判断 / 已基本排除」两块，把「事实」与「判断」分开写。注意 B 阶段的 `Evidence` 实体目前只在 gateway 模块构造，覆盖率极低，因此 `RootCause.evidence_ids` 无法直接渲染；新增"规则判定条件 → 证据项"生成层（`_RC_EVIDENCE_BUILDERS`，6 条规则各一个 builder），只读取规则本身验证过的字段，缺失即跳过该条，不伪造数字
- **Hero 增加检测耗时与检测范围**：只跑部分模块时健康分 100 容易被误读成「23 项全正常」，现在 Hero 显示「耗时 18.4 秒 · 检测范围 3/23 项」，部分检测时 chip 带 hover 说明未覆盖项数
- **一句话报障**：根因区底部生成可直接提交给运营商 / 技术支持的文本（时间 + 健康度 + 主要问题 + 实测 + 首条建议），带「复制报障描述」按钮
- **复测命令卡**：每张根因卡给出可复制的复测命令（如 `netpulse dns gateway`），复用已有的 `copyText` 复制能力

### 改进
- **模块折叠收窄**：此前所有问题模块都默认展开，23 个模块里若有 5 个异常会一次刷出 5 张巨型卡片。现在只自动展开首要根因涉及的模块；**无根因时退回旧行为**（规则没命中时不能把异常藏起来）
- **诊断标准归入技术附录**：判定阈值与评分规则原本直接铺在客户报告里（虽已折叠），容易引来「为什么异常就是扣 20 分」的疑问。现在统一收进「技术附录」区块，并明确健康分是用于排序问题优先级的规则分

### 测试
- `_smoke_report.py` 断言 90 → 120+ 项（+30：属性转义单元与 XSS 注入回归、证据链字段、耗时/范围、折叠策略、技术附录、报障卡与命令卡）

## [1.4.1] - 2026-08-31

v1.4.0 代码审查修复：v1.2.0–v1.4.0 有多项路线图标 [x] 但未真正交付的功能，本版本补齐。

### 修复（v1.4.0 未兑现的承诺）
- **Exit Code 真正接入 (D2)**：`compute_exit_code` 此前零调用点，CLI 恒 exit 0。现在 `modules` / `diagnose` 两条路径跑完诊断后按 D2 标准退出（0=OK / 1=警告 / 2=检测出问题）；参数错（无效模块名 / 缺 `--port-target` / 未知 profile）exit 4
- **report.json 对齐自带 Schema (D1)**：`render_report_json` 此前丢弃 `schema_version` 与 `diagnosis` 顶层字段。现在输出与 `schema/netpulse-result-v1.1.json` 必填字段完全一致（`meta` 兼容视图保留），`jq .diagnosis` / `jq .schema_version` 可用
- **`netpulse diagnose <profile>` 子命令 (C4/C8)**：文档记载的调用形式此前是静默空操作（实际只有 `--diagnose` 旗标）。现在两种形式等价；`--diagnose` 路径不再吞 `--export`
- **调试包脱敏补漏 (D3)**：新增公网 IPv6（`ipv6_public_ip` 及文本中的全球单播地址）、STUN 映射地址（`mapped_ip` / `mapped_addr` / `mapped_port` / `public_ip_tcp` / `servers[].mapped_addr`）、文案内嵌的公网 `ip:port` 打码；内网/回环/链路本地地址保留（排障刚需）；`netpulse.log` 由 4 行占位文本改为真实运行概要（模块状态 + 模块级 error）
- **`APP_VERSION` 修正**：常量停留在 1.0.0，报告/CLI 显示与 CHANGELOG 脱节，升至 1.4.1

### 修复（v1.3.0 根因引擎键名错位）
- 6 条根因规则中 3 条对真实数据永不触发或误触发（测试喂的是想象键名）：
  - `_rule_bufferbloat`：改读 `idle_rtt_ms`/`loaded_rtt_ms`/`bloat_ms`（原读不存在的 `idle_latency_ms`），grade 按前缀匹配（实际值为 `"D (较差)"` 等中文串），`load_warning` 时跳过 —— 此前健康网络每次都误报「Bufferbloat 严重」
  - `_rule_wan_interruption`：改读 `tcp_ok`/`tcp_total`（原读不存在的 `overall_status`/`detail`）—— 此前真断网漏报、模块超时反而误报 CRITICAL
  - `_rule_nat_restricted`：改读 `nat_behavior`（原读不存在的 `nat_type`）—— 此前永不触发
  - `_rule_dns_failure`：模块自身 error/超时不再被当成 100% 解析失败（纯工具故障被当网络根因）

### 修复（v1.2.0 B 阶段「输出零差异」回归）
- **网关无网关路径**：v2 probe 失败时错误文案被丢弃、状态从「错误」变「异常」（健康分虚高 10 分）。现在 `_run_module_with_timeout` 把 `.error` 回填到结果且状态恢复「错误」，与旧 `GatewayTester` 零差异
- **报告证据行消失**：`_issues_gateway` 现在同时认旧下划线（`gateway_packet_loss`）与新点分（`gateway.packet_loss`）issue id，「20 发 / 19 收 / 1 丢」证据行恢复
- **Parser 双语缺陷**：`parse_arp_a` 段落正则补中文「接口:」（原英文-only，中文系统返回空表）；`parse_netsh_wlan_interfaces` 补中文字段名（名称/状态/物理地址/信号/通道…），与 LinkSpeedDetector 口径一致；新增中文 fixture（此前 "zh" fixture 实为英文输出，测试从未覆盖中文）

### 修复（Monitor 模式）
- `target_unreachable` / `no_data` / `with_outage` 三类事件的 `root_cause` 不再落到「其他」

### 测试
- 新增 `tests/test_redaction.py`（12 项：IPv6 / STUN / 文案打码 / 内网保留 / 嵌套结构）
- `tests/test_diagnosis.py` 夹具改用生产者真实键名（原喂想象键名），32 → 39 项（+7 回归：模块 error 不触发 / load_warning / UDP 受阻等）
- `tests/test_probes.py` 30 → 39 项（+9：无网关错误语义 / wrap 型 error 保留 metrics / 点分 id 兼容）
- `tests/test_parsers.py` 23 → 29 项（+6：中文 arp / 中文 netsh fixture）

### 已知未完成（如实记录）
- SECTION 1d parser 仍未接入生产调用点（Tester 内部解析仍在用）；接线需先在真实中文 Windows 上做零差异验证（B13 门槛）
- `GatewayTester` 等 5 个旧 Tester 类为已标记 `@deprecated` 的死代码，待 B13 删除
- Monitor 模式 exit code 仍恒为 0（盯障是长驻交互模式，退出码语义待定义）

[1.4.1]: https://github.com/silentcrow09/netpulse/compare/v1.4.0...v1.4.1

## [1.4.0] - 2026-08-31

### 新增
- **Exit Code 标准化 (D2)**：让 PowerShell / BAT / RMM / CI / AI Agent 能稳定判定诊断结果
  - `compute_exit_code(statuses)` 函数
  - **0** = 全部 OK（无异常/警告/超时）
  - **1** = 有 WARNING（网络有可关注项，不阻塞）
  - **2** = 检测出问题（异常 / 错误 / 超时）
  - **3** = 工具执行失败
  - **4** = 参数错（argparse 已处理）
  - **5** = 权限不足
- **`--json-schema` 子命令 (D4)**：输出当前 schema_version + schema 路径，AI Agent / RMM / 飞书 bot introspect 用
- **`--debug-bundle <DIR>` 子命令 (D3)**：生成脱敏调试包
  - `system.json` + `diagnostic.json` + `netpulse.log` 打包成 zip
  - **默认脱敏** SSID / MAC 地址 / 公网 IP / hostname（用户隐私偏好）
  - 脱敏函数：`_redact_value(key, value)` + `_redact_dict(d)` 递归处理嵌套
- **Monitor 模式 root_cause 标签 (D5)**：每次事件附客户可读的根因描述
  - `internal` → LAN/WiFi 内网中断
  - `carrier` → 运营商 WAN 中断
  - `both_down` → 网关 + 外网同时中断
  - `dns` → DNS 解析故障
  - `policy` → 端口策略 / QoS（信息级）
  - `monitor_gap` → 采集间隙（系统睡眠?）
- **JSON Schema 文档 (D1)**：`schema/netpulse-result-v1.1.json`
  - 完整的 JSON Schema (draft 2020-12) 描述 `schema_version: "1.1.0"` 输出格式
  - 包含顶层 9 个字段定义（app/version/schema_version/system/health/diagnosis/modules/tech 等）

### 待执行（D6）
- **D6 · Exit Code 变更预告**：需在 GitHub Discussions 发预告帖（v1.4.0 之前一周）
  - 当前 v1.3.0 默认 exit 0（旧行为）
  - v1.4.0 起按 D2 标准 exit code 返回
  - 用户在 Discussions 发预告后完成 D6

### 测试
- `_smoke_report.py` 126 → **142 项**（+16 项 D 接口标准化 + 脱敏 + JSON Schema 文件存在）
- 脱敏单元测试覆盖：MAC / 公网 IP / SSID / hostname / 普通字段
- Exit Code 单元测试覆盖：全部 OK / 有警告 / 有异常 / 有超时

### 不变更（向后兼容）
- CLI `--help` / `--list` 输出不变（仅新增 `--json-schema` 和 `--debug-bundle` 选项）
- 现有 `--only / --diagnose / --export / --monitor` 完全不变
- HTML 报告布局完全不变
- v1.3.0 默认 exit 0（旧行为）—— D2 标准 exit code v1.4.0 生效，D6 预告

[1.4.0]: https://github.com/silentcrow09/netpulse/compare/v1.3.0...v1.4.0

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