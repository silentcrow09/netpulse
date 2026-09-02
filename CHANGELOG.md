# 更新日志

本项目的所有重要变更都会记录在此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.9.4] - 2026-09-02

系统性排查报告 HTML 中「标题行 + 下方留白 = 两行空白观感」类排版问题
（继 v1.9.3 修健康卡居中后，同类的其余容器一并收口）。

### 修复

- **健康卡 `.diagnosis.healthy` 仍偏空**：v1.9.3 已整句居中、去掉底部
  12px 空距，但 padding 14px + row-gap 6px 让卡片仍像「两行」。现收紧为
  padding 9px 20px、row-gap 4px、line-height 1.4、badge padding 5px 14px，
  呈紧凑按钮状，单行即满
- **`.hero .sub` 长文字被 gauge 挤换行成两行**：verdict + 生成时间戳一行
  超宽时被 132px 圆形 gauge + 36px gap 挤成两行。现 `white-space: nowrap`
  + `overflow: hidden` + `text-overflow: ellipsis` + `min-width: 0`，
  次要时间戳截断保留 verdict
- **「所有核心检测通过」分支 `.todo.ok .impact` 无背景样式**：该分支的
  impact 直接挂在 `.todo.ok` 内（不经 `.issue`），旧 `.issue .impact`
  规则匹配不到 → 绿勾标题下挂一行无样式的灰字，观感像第二行空白。
  现补 `.todo.ok .impact` 绿字 + 浅绿底（与 `.issue.ok .impact` 同风格）
- **回归保护**：问题诊断卡（`.diagnosis .dhead` 左对齐、margin-bottom
  12px）与 `.diagnosis .rcard` 基线未受健康卡紧凑化误伤

### 测试

- 新增 `tests/test_v194_layout.py`（6 项）：健康卡紧凑化 CSS、hero .sub
  nowrap/ellipsis、todo ok .impact 绿底样式、问题卡 dhead 基线未回退、
  全绿场景渲染 `.todo ok` 分支含 `.impact` 行、有问题场景走 `.diagnosis`
  （非 healthy）。套件累计 14 文件 / 330 用例全绿 + `_smoke_report.py`
  192 项断言通过

## [1.9.3] - 2026-09-02

现场实测反馈修复（场景模式易用性 + MTU 误报 + 报告展示口径，三处均来自
真实客户现场报告核对）。

### 修复

- **工程师模式没有返回场景模式的入口**：场景主菜单 [9] 进入的模块级菜单
  （工程师模式）此前只能 `q` 直接退出整个程序。现新增 `r` = 返回场景模式
  主菜单（`r` 不与分类字母 a/b/c、模块 key、命令 m/e 冲突；置于模块解析前）。
  菜单底部与快捷提示同步更新
- **MTU 误报「路径 1500 < 接口 4294967295」**：Windows 回环口
  （Loopback Pseudo-Interface 1）NlMtu=4294967295（0xFFFFFFFF，-1 无符号）
  被 `Get-NetIPInterface` 收进 `local_mtus`，规则 `max()` 把它当本机最大 MTU
  伪判 MTU 黑洞（现场报告：差 4294965795）。修复：
  - 探测/规则/证据三侧统一过滤（回环名 + MTU ∈ [68, 65535] 双保险，
    `_clean_local_mtus` 共用 helper）
  - 判定对比对象从「全列表极值」改为「默认路由出口接口」（探测时标记
    `egress`，与盯障模式 `_default_route_if_mtu()` 同口径）——未承载路由的
    VPN 虚拟口（如 ZeroTier 2800）不再污染判定
- **MTU 修复建议写占位符「接口名」**：netsh 命令本可直接内嵌真实接口名，
  却让用户自己去找。命中时建议现直接给出接口名（egress/最大有效项），
  无名字才回落占位符
- **网关延迟图「平均 0ms」误导**：Windows ping 对局域网（<1ms）一律输出
  整数 0，图表标题直写「平均 0ms」像测量失败。图表 cap / 模块 verdict /
  summary 有样本时统一显示「平均 <1ms」
- **网关折线图红点歧义**：峰值点无条件标红（局域网 1ms 峰值也像故障点，
  与「经常断网」场景叠加极易误读）。现仅峰值 ≥50ms 标红点（带 hover
  title），其余不画点；折线图底部补 0ms 刻度
- **无故障结论卡「两行、第二行空白」观感**：健康分支 `.diagnosis` 卡片
  内容左对齐且底部留 12px 空距。现 healthy 卡整句水平居中、去底部空距、
  窄屏允许换行仍居中

### 变更

- 版本 1.9.2 → 1.9.3
- 回归测试新增 `tests/test_mtu_loopback_regression.py`（13 项：回环过滤 /
  egress 优先 / 兜底带接口名 / 真命中仍报 / 证据链清洗 / 红点阈值 / <1ms 文案）

## [1.9.2] - 2026-09-02

代码审查第二批修复（逐行扫描 + 移除行为审计两个角度交叉确认）。

### 修复

- **MTU 接口名键反转（更正 v1.8.3 的错误修复）**：生产者 `MTUDetector` 发的键一直是 `interface`（`InterfaceAlias`），v1.8.3 按测试 fixture 误改为读 `name`——真实运行里证据链接口名自 v1.8.2 起一直是空。现消费端（`_evidence_mtu` + builder 回落）统一读 `interface`，测试 fixture 全部对齐生产者真实键形
- **丢包误判修复补全到生产者侧**：P0-05 只修了展示层 `_issues_external`，`ExternalNetworkTester.detect()` 自产的 `external_high_loss` issue 仍无条件 critical（徽章/健康分路径继续误判）——现同样按 TCP 劣化门控，TCP 全通降 warning
- **空 results 状态逃逸**：wrapper 对空 results 给 `UNKNOWN("未知")`，不在 schema 状态枚举且不计入健康分；旧路径映射为「未检测」——现改回 IDLE，覆盖 v1.8.2 新迁的 6 个模块
- **`--json`/`--verbose` 泄漏 `_evidence` 过渡键**：模块打印发生在 LAST_RUN 装配摘键之前，机器可读输出含 schema 外的私有键——`_cli_print_result` 现过滤
- **`_ev_mtu_blackhole` 排除项漏传 `evd`**（v1.9.1 修了 dns_failure 的同款，漏了这对孪生）
- **Schema v1.2 枚举过期**：根因 id 枚举只有 6 条（缺 mtu_blackhole/tcp_loss_burst）、category 缺 "MTU"、rules 计数 maximum=6——用 8 规则引擎的合法报告会被自家 schema 拒绝；已全部对齐
- **`_classify_module_error`：「无法获取网关地址」误归类** UNAVAILABLE/dependency/retryable=False——这是链路状态错误（插回网线重测即恢复），改 NETWORK_ERROR/retryable=True
- **`_issues_external` TCP 证据缺失时伪造「TCP 建连正常」表述**：tcp_total=0 分支现如实写「TCP 佐证缺失」

### 变更

- `SCHEMA_VERSION` 常量收编三处散落的 "1.2.0" 字面量（build_report / --json-schema / debug-bundle）
- 健康报告分支残留的「整体置信度 100%」改分档显示（P1-04 漏网点）
- 版本 1.9.1 → 1.9.2

## [1.9.1] - 2026-09-02

代码审查修复（对 v1.8.1–v1.9.0 五个提交的复查）。

### 修复

- **`_ev_dns_failure` 排除项漏传证据映射**：共享排除项 helper 的循环调用 `fn(results)` 没透传 `evd`，该规则的排除项一直走旧口径——与 v1.8.4「排除项同源」目标相悖。修复后 raw 与证据不一致时以证据为准（附判别性回归测试）
- **抓包置信度分档尺度错误**：`--capture` 结论徽标把 0-100 百分数（92/85）直接喂给 0-1 阈值的 `_conf_band`——今天碰巧落「高」，但 1-74 区间会全部误判「高置信度」。现先除以 100 归一（74% → 中置信度，附回归测试）

### 变更

- `probe_web_v2` / `probe_nattype_v2` 的 detect 参数改走 `**_module_detect_kwargs(key)`——不再手工拷贝配置映射，杜绝双轨参数漂移（审查发现）
- 版本 1.9.0 → 1.9.1

## [1.9.0] - 2026-09-02

V2 模型收口收官（审计 P0-03）：JSON Schema v1.2——**evidence 升为一等结构**，`_evidence` 过渡键移除。

### 新增

- **`LAST_RUN["evidence"]` 独立映射**：`{module: [Evidence...]}`，v2 分支夹带在模块 res 里的过渡键 `_evidence` 由 `_extract_evidence_map` 在 LAST_RUN 装配时摘出——模块 results 恢复纯净，证据不再混进模块数据落盘
- **Schema v1.2**（`schema/netpulse-result-v1.2.json`，v1.1 留档）：`schema_version` 固定 `1.2.0`；`tech.evidence` 定义为一等结构（module → Evidence 列表，字段 id/source/metric/value/unit/timestamp/confidence/metadata）；`--json-schema` 输出同步
- **调试包**：zip 新增脱敏 `evidence.json`（system + diagnostic + evidence + log）
- 证据链 builder 以 `evd` 参数接收证据映射（`_enrich_diagnosis_evidence` / `_build_diagnosis_with_evidence` 透传，build_report 与场景路径均接入）；模块无证据/映射损坏时回落旧口径，文案不变

### 变更

- build_report：`schema_version` 1.1.0 → 1.2.0，`tech.evidence` 进入 JSON 导出（与 `tech.raw_results` 平级）
- 版本 1.8.4 → 1.9.0（导出结构演进，minor）

### 验证

- 端到端：LAST_RUN（独立 evidence 映射）→ build_report → `tech.evidence` 含两模块证据 + `raw_results` 无 `_evidence` 残留 + HTML/JSON 证据链文本同源
- 测试：全套件 12 文件全绿（diagnosis 68 / probes 67），新增 `_extract_evidence_map` 摘键/空证据/纯净 results 断言

## [1.8.4] - 2026-09-02

V2 模型收口第三步（审计 P0-03）：8 条根因规则的证据链（支持项 + 排除项）全部与模块自证 Evidence 同源。

### 新增

- **bufferbloat / nattype 补证据**：`_evidence_bufferbloat`（bloat_ms + idle/loaded metadata + grade + load_warning）与 `_evidence_nattype`（nat_behavior + cone_type）；`probe_bufferbloat_v2` / `probe_nattype_v2` 注册（nattype 的 `servers` 与旧路径 `_module_detect_kwargs` 同源），`_V2_PROBES` 达 11
- **排除项同源**：`_ev_gateway_reachable` / `_ev_external_reachable` 两个共享排除项 helper 优先读 gateway/external 自证 Evidence；`_ev_wan_interruption`（网关无丢包）、`_ev_gateway_loss`（DNS 全正常）、`_ev_tcp_loss_burst`（MTU 相符）、`_ev_bufferbloat`（网关空闲延迟）的 builder 级排除项同步迁移——全部带旧口径回落

### 测试

- `test_probes.py` +5（66 用例）：两个新 probe 冒烟 + 新证据源键断言 + 注册表 11 个
- `test_diagnosis.py` +3（68 用例）：排除项同源断言（注入 `_evidence` 与旧口径文本逐字一致）+ bufferbloat/nattype 支持项同源
- 版本 1.8.3 → 1.8.4

## [1.8.3] - 2026-09-02

V2 模型收口第二步（审计 P0-03）：报告层证据链开始**消费**模块自证 Evidence，不再只从原始 dict 二次解析。

### 变更

- **证据链与模块证据同源**：`_ev_dns_failure / _ev_wan_interruption / _ev_wifi_weak / _ev_gateway_loss / _ev_mtu_blackhole / _ev_tcp_loss_burst` 六个 builder 的**支持项**优先取模块 `_evidence`（v1.8.2 probe 认证数值），缺证据/结构损坏时回落旧口径（原地取值），文案逐字不变；**排除项**本批仍读原始 dict（跨模块上下文，下一批迁移）
- `probe_gateway_v2` 的丢包 Evidence 补 `sent/received` metadata（证据路径可生成「N 发 M 收」后缀）
- **修复**：`_ev_mtu_blackhole` 旧口径读 `local_mtus[].interface`（字段实为 `name`），接口名一直显示 `None`；两条路径统一读 `name`
- 版本 1.8.2 → 1.8.3

### 测试

- `test_diagnosis.py` +8（65 用例）：`TestEvidenceChainConsumption` 断言同一数据「注入 _evidence」与「旧口径」两条路径产出的证据项文本**逐字一致**（同源证明），覆盖 6 规则 + 无证据回落 + `_evidence` 结构损坏不崩
- 端到端合成验证：失败 DNS + 健康 gateway → `dns_failure` 根因支持项来自证据路径，HTML 报告证据链同步

## [1.8.2] - 2026-09-02

V2 模型收口第一批（审计 P0-03）：`external` / `dns` / `wifi` / `tcpstats` / `mtu` / `web` 六个模块进入 V2 双轨并产出结构化 Evidence（`gateway` 此前已原生）。状态/指标口径与旧 Tester 路径零差异（同一 `determine_status`，metrics 全保留）。

### 新增

- **Evidence builders**：`_evidence_external / _evidence_dns / _evidence_wifi / _evidence_tcpstats / _evidence_mtu / _evidence_web`——只记录根因规则实际读取的字段（与 `_rule_*` 同源），模块 error/数据缺失 → 空列表（证据缺失 ≠ 证据为 0）
- **4 个新 v2 probe**：`probe_external_v2 / probe_tcpstats_v2 / probe_mtu_v2 / probe_web_v2`（web 的 `extra_targets` 与旧路径 `_module_detect_kwargs` 同源）；`_V2_PROBES` 达 9 个
- `_wrap_as_diagnostic_result(evidence_fn=...)`：迁移期旧 results → Evidence 的统一通道，生成失败不阻断主结果

### 变更

- **Evidence 持久化（过渡）**：v2 分支成功路径把 `result.evidence` 以保留键 `_evidence` 随 res 进入 `LAST_RUN.results`，JSON 导出 `tech.raw_results` 可见（实测 `tcpstats --json` 含完整证据块）；报告层直接消费 Evidence 后移除该过渡键
- 版本 1.8.1 → 1.8.2

## [1.8.1] - 2026-09-02

质量收口批次：专家审计整改——判定口径/隐私文案/压测分级修正 + 测试入仓。不新增任何 Probe。

### 修复

- **外网丢包误判（审计 P0-05）**：`_issues_external` 曾用 `if loss >= 5` 无视 TCP 状态直接报「异常/问题在运营商侧」，与自身注释口径（只在 TCP 同步劣化时升级）矛盾——ICMP 限速场景被误报为真丢包。现仅 TCP 有目标建连失败时升级异常；TCP 全通降级为「ICMP 限速」警告；TCP 证据缺失（tcp_total=0）同样不给故障级结论。附 6 条回归测试
- **抓包隐私文案校准（审计 P0-06）**：HTML 报告/首次确认/README 的「不含任何应用内容/只存包头」改为如实描述——DNS 查询域名 (QNAME)、HTTP Host、TLS SNI 可能被记录，不保存普通 TCP/HTTP 应用载荷；四处同步补充「抓包分析当前仅覆盖 IPv4」

### 变更

- **压力级模块不随 `all` 执行（审计 §12）**：`tcpcc`（1600 并发压测）从 `--modules all`、交互菜单 `0/all/*`、debug-bundle 全诊断中排除，运行时打印提示；展开口径统一走新增的 `all_module_keys()`
- **置信度分档显示（审计 P1-04）**：CLI 根因输出/HTML 报告/一句话报障/盯障置信度徽标不再显示伪精确百分比，改「高/中/低置信度」三档（`_conf_band`，≥0.75/≥0.5）；JSON 保留原始数值
- **模块错误语义化（审计 P1-01）**：`_wrap_as_diagnostic_result` 不再把所有模块错误统一为 `MODULE_ERROR/retryable=True`，按错误文案特征映射 TIMEOUT / PERMISSION_DENIED / UNAVAILABLE / NETWORK_ERROR（兜底 COMMAND_FAILED），retryable/severity/exception_type 随之设置
- **旧 Issue 不再伪造置信度（审计 P1-02）**：旧结果包装的 `Issue.confidence=None`（此前统一 0.85）；`Issue.confidence` 类型放宽为 `float | None`
- `render_report_html` 标记 DEPRECATED（零调用点死代码，稳定版后删除）
- 版本 1.8.0 → 1.8.1；README 同步（版本/隐私边界/置信度描述/目录结构）

### 新增

- **测试入仓（审计 P0-01）**：`tests/`（12 个文件 / 276 用例）移出 `.gitignore`；fixtures 全面脱敏——真实设备 MAC/GUID/hostname/ZeroTier 网络 ID/全球 IPv6 前缀 → 02/06 本地管理 MAC、RFC 3849 文档前缀 (`2001:db8::/32`)、假 hostname；`tests/fixtures/private/` 本地忽略。clone 后即可逐文件跑 `python tests/test_xxx.py`
- **诊断回归矩阵**（审计 P1-05）：`tests/test_diagnosis_matrix.py` 覆盖审计 §5 组合场景（全 OK/全 FAIL→LAN、网关 OK 其余 FAIL→WAN、仅 DNS→DNS、仅 TCP→传输层、高负载→Bufferbloat）+ 模块自身超时不得当网络证据的边界
- **XSS 回归**（审计 §9）：`tests/test_html_escape.py` 恶意 SSID/hostname/DNS 名/URL 四类样本全链路（LAST_RUN → build_report → customer 渲染），断言无标签注入 + 属性通道（data-copy）引号转义
- `CLAUDE.md`（AI 协作入口，指向 AGENTS.md + 收口硬规则）

## [1.8.0] - 2026-09-01

盯障抓包取证层（阶段 F 第二步 / PR-F1~F5）：统计层说「有病」，抓包层给「证据」。`--capture` 显式开启（默认关闭，需 Npcap + 管理员），事件触发自动落盘切片 pcap + 离线三信号分析，结论联动置信度。隐私红线：**只存包头，不存任何应用内容**。

### 新增

- **抓包核心（PR-F1）**：`_PcapCaptureSession`（AsyncSniffer + BPF `ip and (icmp or udp port 53 or tcp or udp port 443)`，显式 v4）；`_capture_strip_packet` 隐私剥离——80/443/8080 每流**前 2 包**保留头部 +384B（提取 Host/SNI 用），QUIC 头 +16B，DNS/ICMP 整包，其余 TCP 剥到头部；`_PcapRingBuffer` **字节记账**环形缓冲（默认 64MB，`--capture-mb` 8 下限），超限挤最旧并如实报告挤出数；prn 回调零工作原则（只截断入队，分析全部后置）。检查链四级降级（--no-scapy / scapy 缺失 / Npcap 缺失含 npcap.com 安装指引 / 非管理员），任一失败给客户语言原因、统计层照跑、退出码不变
- **事件触发切片（PR-F2）**：outage / jitter_burst / tcp_fail / tcp_retrans_burst 事件结束后 30s 落盘**前后各 30s** 窗口切片（`monitor_时间戳_slice_类型.pcap`，Wireshark 直开；mtu_mismatch 是持续态不触发）；盯障主循环 5s 增量跑事件检测（复用 `_detect_monitor_events` + 抽取的 `MonitorSession._tcpstat_quality`）；报告事件表挂切片链接；`_cleanup_old_captures` 超 7 天或超 10 个，下次运行时自动清理（措辞如实）；`--capture full` 全程单文件模式
- **离线证据分析（PR-F3）**：`PcapAnalyzer` + `CaptureDiagnostic`——按 (src,sport,dst,dport) 方向流重组：同 (seq,len) 间隔 ≤1s 计重传（>1s 视为应用层重发不计）、连续重复 ack ≥3 计 dup-ack、SYN 反复无应答单独计数（不算数据重传）、RST/零窗口、full-size(>1200B) 同序号 ≥3 次判**停滞**；DNS query→resp 配对计时（>1s 慢查询）；SNI/Host 从 384B 窗口解析（越界记 `sni_truncated` 不误报）。**三信号 PMTUD 判定**：A=ICMP 3/4（含下一跳 MTU）、B=握手 MSS≥1400 + full-size 停滞 + 小包正常流动、C=SYN MSS>路径 MTU−40（由统计层提供）——A 或 B∧C 判黑洞，仅 B 或重传率 ≥8%（≥50 段）判链路丢包；MSS<1460 本身不是判据（PPPoE 1452 正常）
- **结论联动（PR-F4）**：`_apply_capture_evidence` 对全部切片离线分析合并——suspected_* 追加进盯障结论/建议/摘要（不推翻统计层判定，抓包永远不是规则前置）、verdict stable→degraded、对应事件根因标注 `🔬 抓包分析` 徽标、**置信度**：黑洞确认 92% / 链路丢包·DNS 佐证 85%（无证据不出该字段）；报告 banner 置信度徽标 + 抓包面板「证据分析」行（重传/dup-ack/RST/零窗口/ICMP/SNI 提取/DNS 汇总）+ JSON `capture.analysis` 块
- **首次使用确认（PR-F5）**：`--capture` 首次运行弹隐私说明（只存包头/不存账号密码内容/域名会出现/自动清理策略）需确认，`reports/captures/.capture_ack` 记住选择只问一次；非交互环境不阻塞（--capture 即显式授权）；拒绝则降级仅统计层盯障照常

### 变更

- 版本 1.7.0 → 1.8.0；README 同步（特性/用法示例/参数表/盯障报告节/可选依赖表/目录结构）；captures 目录在 `reports/` 下，已被现有 .gitignore 规则覆盖无需新增
- **实机修复：默认路由接口取错索引**——scapy 2.7 的 `route()` 返回 3 元组 `(iface, gw, dst)`，原取 `[2]` 把网关 IP 当接口名传给 AsyncSniffer，嗅探线程静默死亡而主流程仍报「已启动」（实测 0 包）。现 `_capture_default_iface()` 取 `[0]` 并校验在 `get_if_list()` 清单内（不符回退 `conf.iface`）；`start()` 加 1s 线程验活，死了按启动失败降级并给原因，杜绝「已启动 + 0 包」假成功

### 验证

`tests/` 190 → 256 项：新增 `tests/test_pcap_capture.py` 36 项（RingBuffer 字节记账/剥离矩阵数值验证/切片窗口与命名 rdpcap 回读/清理年龄+个数双策略/检查链降级/finish 挂链/首次确认 5 态/接口解析 4 态 + precheck 挂接/嗅探线程验活死活两态）、`tests/test_pcap_analyzer.py` 20 项（方案 §9.1 场景 1-8：三信号各分支/PPPoE 不误报/拥塞 vs 黑洞/SYN 重传口径/边界（>1s 不计、dup-ack<3 不计）/SNI 截断/DNS 慢查询/pcap 文件输入与 JSON 序列化）、`tests/test_pcap_evidence.py` 10 项（联动结论/verdict 升级/置信度 92·85/事件标注/C 信号来自统计层/坏文件缺文件兜底/无证据不改结论/HTML 徽标与证据行）。`_smoke_report.py` +9 项 v1.8.0 断言（真实调用验证：三信号判黑洞、RingBuffer 挤出、剥离矩阵、临时 pcap 走 `_apply_capture_evidence` 全链路、确认标记免问）、共 244 项全绿。**实机双轮走查**（Windows 11 + Npcap）：①非管理员 60s——检查链第 4 级拦截、客户语言降级、统计层照常出报告、无残留 capture 块；②管理员 240s `--monitor --capture full --monitor-load`——接口解析正确（NPF 设备名）、40,796 包入环形缓冲仅 2.5MB（隐私剥离实效，均值 ~62B/包）、full pcap 3.1MB 落盘、分析块提取真实 SNI（`sg.tgalileo.com`）与 HTTP Host（`szextshort.weixin.qq.com`，即负载下载流量）、128 次 DNS 查询配对 0 慢查询、466 条方向流重传率 0.018%、MSS 全 1460、健康网络三 suspicion 全 False 不出置信度字段、HTML 抓包面板/证据分析行/全程 pcap 链接齐全。

## [1.7.0] - 2026-09-01

盯障模式统计层（阶段 F 第一步 / PR-F0）：给盯障装上 L4 眼睛——主动探测路径 MTU + TCP 重传差分采样，MTU 不匹配（PMTUD 黑洞）类故障从「盯障发现不了」变为自动出事件 + 给改法。零新依赖，无需 Npcap（抓包证据层是阶段 F 后续 PR-F1~F5，目标 v1.8.0）。

### 新增

- **盯障 MTU 探测**：MonitorSession 后台线程对网关/外网目标各跑一轮 `ping -f -l` 二分（576..1472，三态判读：太大/放行/无信号；连续 ≥4 次无信号如实报探测失败，不再把 ICMP 被滤当成假 MTU）；本机侧取默认路由出口接口 MTU（`Get-NetRoute` 最优 metric → `Get-NetIPInterface`，避免 VPN/环回口污染）。接口 − 路径差 ≥100 → `mtu_mismatch` 事件（PPPoE 的 1492 不误报），结论直接给管理员命令 `netsh interface ipv4 set subinterface "接口名" mtu=NNNN store=persistent`
- **盯障 TCP 重传差分**：30s 周期采样系统 TCP 计数器（`Get-NetTCPStatistics` 主路 → `netstat -s` 中英文回退），差分出**会话口径**重传率（区别于 diagnose 的开机累计口径）；发送增量 ≥5000 才判率（分母保护），≥5% → `tcp_retrans_burst` 事件；与 MTU 事件同时出现时提示「大概率同源，先改 MTU 复测」
- **主动负载 `--monitor-load` / `--load-url`**：盯障开始 60s 后流式读取 15s（默认微信安装包 CDN 大文件，可换地址），制造 full-size 下载流量——空闲网络没有大包可丢，重传统计需要真实负载才有分母；读即丢弃不落盘，报告记录实际读取量
- **diagnose 新规则 ×2**：`mtu_blackhole`（路径 MTU 显著小于接口 MTU，HIGH；tcpstats 重传率 ≥5% 佐证时置信度 0.75 → 0.92）、`tcp_loss_burst`（开机累计重传率 ≥5%，MEDIUM，描述带口径警示并建议盯障复测确认）；PROFILE_RULES 的 web/gaming/slow 纳入，slow 场景补采 tcpstats 模块
- **报告**：盯障 HTML 新增「MTU 与传输质量」面板（路径/接口 MTU 表 + 重传率时序图）与 TCP 重传率指标卡；CSV 新增逐区间 `tcp_retrans` 行；JSON 含完整 `mtu` / `tcp_quality` 块

### 变更

- `_probe_path_mtu` / `_tcp_stats_snapshot` 分别从 MTUDetector / TCPStatsTester 提取为模块级函数：diagnose 单次采样与盯障周期采样共用同一探测/解析逻辑（提取前已 grep 核对全部消费者）
- `_monitor_conclusion` 改追加式：MTU/重传结论与任何 verdict 并存——stable 升级 degraded，carrier/internal/dns 定位保持不变（统计层不覆盖中断定位）

### 验证

`tests/` 141 → 190 项：新增 `tests/test_monitor_stats.py` 31 项（MTU 探测中英文输出二分收敛/三态判读/无信号放弃、快照双路采集与假零修正、`_default_route_if_mtu`、事件判据、结论矩阵、常量契约）；`tests/test_diagnosis.py` +18 项（新规则口径/置信度/不误报、场景过滤纳入）；规则数 6 → 8 的既有断言同步修正 16 处（三个测试/smoke 文件）。`_smoke_report.py` +20 项 v1.7.0 断言、共 234 项全绿。实机 90s `--monitor --monitor-load` 走查：MTU 双目标探测 1500/1500（正确不报事件）、会话重传率 0.14%（分母 12583、护栏生效）、负载 15s 读取 117.4 MB 未落盘、CSV/HTML/JSON 产物齐全。

## [1.6.1] - 2026-09-01

代码审查修复 10 项（审查范围 v1.6.0 场景菜单提交）：2 项经真实构造数据实证的功能失效（导出报告绕过规则过滤、web 场景恒零根因），其余为交互兜底、健壮性与性能。

### 修复

- **场景/CLI 导出报告绕过规则过滤**（首要）：完成屏按场景过滤了根因，但 `export_report → build_report` 链路仍跑全规则 — gaming 完成屏隐藏了「WiFi 信号弱」，存桌面的 HTML 报告却照列（实测复现）。现 `rule_filter` 全链路透传（`export_report` / `build_report` / `_export_reports` / `_export_scene_report`），CLI `--diagnose <profile> --export` 同步
- **web 场景恒零根因**：`DIAGNOSE_PROFILES["web"]` 不采集 gateway/external，而 web 的 3 条规则（dns_failure / wan_interruption / gateway_loss）全依赖这两个模块的数据 — DNS 全断也报「无根因」（实测复现）。现补采 gateway + external（6 → 8 模块）
- **场景完成屏无回车暂停**：`_run_scene` 返回后菜单循环立即清屏，健康分/根因结论/报告路径瞬间被擦（错误路径同样）。新增 `_pause_enter()` 通用暂停；盯障路径的同款 input 拷贝一并收敛
- **Ctrl+C 穿透场景错误兜底**：KeyboardInterrupt 是 BaseException，`except Exception` 拦不住 — 场景中断直接裸抛回溯，`_format_error_for_user` 的「已中断本次检测」成死分支。场景/盯障两处包装改为 `except (Exception, KeyboardInterrupt)`
- **场景报告同日复测静默覆盖**：文件名只到日期（`YYYY-MM-DD_场景名.html`），下午复测覆盖上午记录且无警告。现含时分秒（`YYYY-MM-DD_HHMMSS_场景名.html`）
- **中文 OneDrive 桌面漏判**：原只探测 `OneDrive\Desktop`，中文 Windows 的 OneDrive 重定向桌面是 `OneDrive\桌面`，报告会落进用户看不到的目录。现优先 `SHGetKnownFolderPath(FOLDERID_Desktop)` 一次系统调用解析真实桌面（覆盖一切重定向/本地化），候选探测兜底并补充 `桌面` 变体
- **菜单清屏回退死代码**：`_menu_clear` 先写转义再探返回值，而 `_clear_screen` 只要写入不抛异常就返回 True — VT 未启用的旧 conhost 会打出字面转义乱码，且 cls/clear 子进程回退永不可达；同款块还在 `_module_menu` 逐字重复。现 `_cli_enable_vt()` 返回是否确认启用，`_menu_clear` 先确认再写转义（回退真正可达），`_module_menu` 收敛为调用 `_menu_clear()`

### 变更

- **场景诊断只评一次**：原一次场景运行完整构建报告 2-3 次（完成屏健康分、导出各一次），同一批规则最多被评估 4 遍。现 `_run_scene` 构建一份诊断 + 报告（`build_report` 接受预构建 `diagnosis`），完成屏/导出复用同一份 — 屏幕与文件必然一致，也省掉重复的全量规则评估
- **diagnose 兜底不重复评估**：过滤无命中退回全规则时，原整轮重评（含首轮刚跑过的场景规则，慢速场景 10 次规则执行 vs 6 次足够）。现只补评首轮未跑过的规则，`rules_evaluated` 始终按实际评估条数累计；排除集在兜底路径的拦截不再依赖脆弱的身份比较
- **规则注册表单一来源**：`ALL_RULES` / `_RULE_BY_ID` / `_RULE_ID_OF` 收敛为由 `_RULE_REGISTRY` 单张有序表派生 — 新增规则只加一行，杜绝手工同步漂移导致规则静默退出场景评估（且无测试能发现）

### 验证

`tests/` 136 → 142 项（新增 `TestV161` 6 项：注册表同源、web 规则依赖采集、兜底不重复评估、Ctrl+C 兜底、文件名时分秒、SHGetKnownFolderPath 优先）；`_smoke_report.py` 新增 4 项断言（注册表单一来源、兜底计数、web 补采、文件名时分秒）并随行为更新 2 项（web 模块数 8、版本号 1.6.1），全绿。审查中 2 项实证发现（gaming 报告夹带 wifi_weak、web 零根因）已用构造数据回归确认。

## [1.6.0] - 2026-09-01

装维场景入口（阶段 E 收窄版：PR-A 场景菜单 + PR-B 规则过滤 + PR-C 完成屏/桌面报告/错误兜底）。

### 新增

- **场景菜单（双击即用）**：无参数启动 exe 进入「场景模式」主菜单 — `[1] 网络很慢 / [2] 经常断网 / [3] 网页打不开 / [4] 游戏卡顿 / [5] WiFi 信号差 / [7] 持续盯障（可输分钟数）/ [9] 高级选项 / [0] 退出`。场景选项自动映射 `DIAGNOSE_PROFILES` 跑对应模块组合；`[9]` 高级选项 = 原模块清单菜单（工程师用，行为与 v1.5.x 一致）
- **profile 规则过滤**：`diagnose(results, rule_filter=profile)` 只评估该场景相关规则 — 修复 gaming 场景误报「WiFi 信号弱」等无关根因（gaming 显式排除 wifi_weak，兜底退回全规则时也禁止评估）；CLI `--diagnose` 同步启用
- **场景完成屏**：健康分（复用 `compute_health_score`）+ 一句话根因结论（复用 `_print_diagnosis`）
- **报告存桌面**：场景路径导出到 `桌面\NetPulse\YYYY-MM-DD_场景名.html`（OneDrive 桌面重定向优先探测，不可写退化 `reports/`），完成屏明示绝对路径
- **错误兜底客户语言**：`_format_error_for_user()` — DNS 解析失败 / 权限不足 / 网络超时等常见异常给「中文一句话 + 工程师细节」两段（仅场景路径生效，CLI 输出不变）

### 变更

- `--diagnose` 输出按场景规则集评估（v1.5.3 为全规则），`rules_evaluated` 反映实际评估条数；无命中时退回全规则（排除场景明确排除项），不把异常藏起来
- 无参数启动行为：模块清单菜单 → 场景模式主菜单（原模块清单移至 `[9]` 高级选项）

### 验证

`tests/` 120 → 136 项（新增 `test_v160_scene.py` 16 项：gaming 排除 wifi_weak、兜底退回、OneDrive 桌面路径、错误文案、菜单交互、场景集成）；`_smoke_report.py` 192 → 208 项（+16 项 v1.6.0 断言）。

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