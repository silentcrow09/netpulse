# NetPulse 项目约定

## Git 环境

**当前工作区在 `D:\Work\Projects\NetPulse`，git 读写全部正常**，可直接 `add` / `commit` / `push`。

历史遗留：早期在 UNC 共享路径 `\\172.168.1.1\...` 上出现过 `fatal: unable to write new index file`。该路径目前不使用；若将来回到 UNC 路径，已知两个坑：

1. 提交类操作（写 `.git/index`）可能失败 → 只读操作可用，提交交给用户手动执行
2. `git push` 能成功推到远程，但本地 `origin/master` 跟踪引用可能不刷新（`packed-refs` 写入失败），
   导致 `git status -sb` 误报 `ahead N`。核对用 `git ls-remote origin master`，
   必要时手动写 loose ref：`printf '<sha>\n' > .git/refs/remotes/origin/master`

## 评分口径（改这里前务必看）

`compute_health_score(counts, text_counts=None)`：

- **扣分**：异常 -20 / 错误 -30 / 警告 -2 / **超时 -10** / 未检测 0
- 超时必须扣分：超时模块会被 `_issues_*` 登记成 `severity="异常"` 的 issue，
  若不扣分就会出现「23 个模块全超时 → 100 分 A 级"网络良好"」而报告其它位置说有问题的矛盾

## 两种计数口径并存（易踩坑）

| 口径 | 来源 | 数量 | 用途 |
|---|---|---|---|
| 扣分口径 | `report["counts"]` | 19 | 统计卡、健康分、信息条「扣分项」 |
| 全口径 | `report["summary"]` | 23 | 状态分布条、检测结果一览徽章 |

差值是 4 个评分豁免模块：`iperf3` / `ipv6` / `proxy` / `nattype`。
两者并排展示时界面上必须说明差异，否则看起来像算错。

## 状态与配色

状态语义键与配色的**唯一来源**是 `STATUS_KEY` / `STATUS_COLORS` / `STATUS_BAR_ORDER`，
不要在各渲染函数里另立映射（曾因三份映射并存出现过两种「警告橙」）。
`PROBLEM_STATUSES` 决定哪些状态会被标红 + 默认展开。

**v1.15.2 补充（色值审查结论，勿回退）**：

- **按语义轴分层**。全仓约 550 处 hex，但它们分属**不同语义轴**，不能一锅端塞进
  `STATUS_COLORS`：
  - **状态语义轴**（完成/警告/异常/错误/超时/未检测）→ 归 `STATUS_COLORS`。
    客户版 CSS 里那 11 处 `.dot.*` / `.stat-card.*` 已改为引用（拆成
    `_CSS_DOT_COLORS` / `_CSS_STAT_COUNT_COLORS` 片段 + `%` 格式化 ——
    **不要**把整块 CSS 改成 f-string，里面全是 `{{ }}` 双花括号，逐个转义风险高）
  - **数据轴身份轴**（测速/iperf3 的下行蓝 `#0a84ff` / 上行橙 `#ff9500` /
    延迟绿 `#34c759`）→ **不进 `STATUS_COLORS`**。这两族报告页脚自己写着
    「仅为客观测速数据, 不包含达标判定」—— 把「延迟轴」标成 `ok`（正常绿）
    是语义错配（把「测的是哪条曲线」偷换成「好不好」）
  - **等级轴**（A–F）→ `GRADE_COLORS` / `GRADE_BADGE`
  - **严重度轴**（critical/high/medium/low）→ `_DIAGNOSIS_CSS`
- **已修真 bug**：`_DIAGNOSIS_CSS` 的 `.dbadge.warn` 曾是红底红字 `#fee2e2/#991b1b`，
  与客户版 `.badge.err` **逐字节相同** —— 同一份报告里「警告」和「错误」渲染出来
  一模一样。现已与 `.badge.warn` 同口径（橙底棕字）。
- **仍待排期**：盯障族（`#0e8a4f`/`#b26a00`/`#b42318`）与 brief v1
  （`#0e8a4f`/`#d92d20`/`#b26a00`）归位到 `STATUS_COLORS`。这两族是**纯状态语义轴**，
  归位正确但会**改变用户可见颜色**（盯障报告是运维长时间盯的产物，色变影响判读习惯），
  且 6 处引用里有 3 处在含大量 `{{}}` 转义的 f-string/CSS/JS 里 → 需人工视觉确认后单独做。

## 报告渲染

- `export_report` 只调用 `render_report_html_customer`（客户视图）
- `render_report_html`（技术视图）和 `render_report_text`（纯文本）曾长期零调用，
  **v1.14.14 已删除这两个入口函数**（报告输出逐行 diff 验证零回归）。
  **v1.15.0 更正（本文件早前写"连同其专属 helper 一并删除"是错的）**：那两个入口删掉时，
  它们的专属 helper（`_fmt_value` / `_fmt_record_table` / `_flatten_kv` / `DETAIL_KEYS`
  / `_try_unjson`）**漏删**，一直零引用地留在文件里，直到 v1.15.0 审查 P2 才真正清掉。
  需要技术视图请重新实现并补测试
- 报告须**可离线打开**：全部用系统字体，不引入任何在线资源，图表用纯 SVG 手绘
- **HTML 属性转义**（v1.5.0 P0）：文本节点用 `_html_esc(s)`（`quote=False`），
  **属性值一律用 `_html_attr(s)`**（`quote=True`）—— `_html_esc` 不能进属性拼接。
  评审发现旧版 `_html_esc` 在 `title=` / `data-hint=` / `href=` / `data-mod=` / `id=` 里裸拼，
  恶意 SSID / DNS 名 / hostname 可闭合属性注入标签
- **根因证据链**（v1.5.0）：`RootCause.evidence_ids` 不直接渲染（B 阶段 `Evidence` 实体
  全仓只在 gateway 模块构造 4 处，覆盖率极低）。改为按"规则判定条件 → 证据项"生成——
  `_RC_EVIDENCE_BUILDERS` 里 8 条规则各对应一个 builder（v1.14.14 更正：本文早前写"6 条"，
  实际注册 8 条，与 8 条诊断规则一一对应），只读规则验证过的字段，缺失即跳过，
  不伪造数字
- **模块折叠**（v1.5.0）：有根因时**只展开首要根因**涉及的模块（首要根因 = severity 最高，v1.5.3 起 `diagnose()` 按严重度降序保证）；**无根因时退回旧行为**
  （规则没命中时不能把异常藏起来）
- **渲染器结构**（v1.14.14）：`render_report_html_customer` 曾是 927 行单体函数
  （289 个调用点 / 529 个字符串块）。现拆为 **268 行编排层 + 7 个章节 helper**：
  `_band_counts_band`（状态分布条）/ `_todo_issues_section`（待办清单）/
  `_stats_overview_sections`（统计卡 + 指标一览）/ `_chart_section`（图表）/
  `_module_cards_section`（模块卡，178 行）/ `_host_info_section`（本机信息）/
  `_tech_appendix_section`（技术附录）。191 行 CSS 提成模块常量
  `CSS_CUSTOMER_REPORT`（与 `CSS_BRIEF_V2` 同一惯例）。
  **拆分零回归验证方式**（改渲染代码后照做）：用固定 LAST_RUN fixture 渲染
  customer/brief/brief_v2 三份 HTML 落盘，改前改后 `Compare-Object` 逐行比对，
  必须完全一致。

## JSON Schema 必须与导出一致 (v1.14.14)

`schema/netpulse-result-v1.2.json` 漂移了两年没人发现——schema 声明了
`duration_ms` / `selected_modules` / `total_modules` 但 `render_report_json`
从不导出（技术员拿不到耗时与覆盖范围），而导出里的 `site_check` / `site_note` /
`meta_manual` / `meta` schema 一个都没声明；schema 又没设
`additionalProperties: false`，拿标准校验器去验也不会报错。

- 现根级设了 `additionalProperties: false`，`render_report_json` 补齐那 3 个字段。
- **`tests/test_schema_export_consistency.py` 双向锁住**（6 用例，不依赖
  `jsonschema` 包）。增删导出字段时必须同步 schema，否则该测试红。
- `schema/` 下的 v1.1 是留档，不要改。
- **诊断标准**（v1.5.0）已归入统一「技术附录」折叠区块，原章节文案移除

## 收口阶段规则（v1.8.1 起，源自 2026-09 专家审计）

- **冻结新增大 Probe**：除非同时满足 解决真实用户场景 + 有诊断价值 + 有测试 +
  有报告展示 + 有退出/降级策略。优先修现有能力，不再用新 Probe 证明能力。
- **停止新增 `LAST_RUN` 依赖**：数据流向 `runner → report → renderer`；
  新代码（报告/Debug Bundle/Monitor）不得直接读写全局 `LAST_RUN`，存量引用只减不增。
- **新 Probe 直接产出原生 `DiagnosticResult`**（Evidence/Issue），不走
  `_wrap_as_diagnostic_result` 旧包装；旧 Probe 逐个迁移。
  **进度 (v1.8.3)**：第一批完成——external/dns/wifi/tcpstats/mtu/web 已走
  `@_register_probe` + wrap helper + 模块专属 `_evidence_*` builder（字段与
  `_rule_*` 同源，error → 空列表），gateway 原生。Evidence 以保留键
  `_evidence` 随 res 进入 LAST_RUN（JSON tech.raw_results 可见）。
  **报告层已消费并转正 (v1.8.3–v1.9.0)**：8 条规则的证据链 builder 支持**与
  排除项**全部优先读模块自证 Evidence（缺证据/损坏回落旧口径，文案逐字不变）。
  v1.9.0 起 evidence 为一等结构：`LAST_RUN["evidence"]` 独立映射
  （`_extract_evidence_map` 在装配时摘除过渡键），导出 JSON 的
  `tech.evidence`（Schema v1.2）与 debug-bundle 的 evidence.json 为正式出口。
  builder 一律以 `evd` 参数接证据映射，不要再往模块 results 里塞保留键。
  P0-03 收尾余项（低优）：剩余非根因模块 (proxy/loop/route/arp/dhcp) 补证据。
- **压力级模块**（`STRESS_MODULE_KEYS`，现为 tcpcc）的口径 (v1.10.0 收窄)：
  仅 debug-bundle 自动全诊断排除（静默场景不压测，走 `all_module_keys()`）；
  **菜单 0 / CLI `--modules all` 包含**压力级（走 `full_module_keys()`，
  用户显式点名的"全部"= 支持的功能全测一遍），单独选中始终允许。
  tcpcc 默认上限 4000，预检通过的候选目标全部入池 round-robin 轮转
  （防单 IP 高频建连被限流/拉黑），`--tcpcc-target` 指定后保持单目标。
- **带宽敏感模块独占**（`EXCLUSIVE_NET_MODULE_KEYS`，v1.12.2）：并行模式
  下 speedtest/bufferbloat/iperf3/tcpcc 不参与并发——普通模块并发结束后
  逐个串行跑（否则测速被网页下载/LAN 扫描等并行流量压低，全量报告与
  单独测速口径不一致）。新增对网络吞吐/并发有影响的模块时评估是否入集。
- **置信度显示走 `_conf_band()` 三档**（高/中/低）：内部 0-1 数值是规则设计值不是统计
  概率，UI 不做伪精确百分比；JSON 保留原始数值。旧结果包装的 `Issue.confidence=None`
  （无依据不显示），不要回填统一数字。

## 抓包分析必须走生产管线 (v1.14.14 · 教训)

**剥载荷发生在 sniffer 回调里**（`_PcapCaptureSession.start` 的 `_prn`），环形缓冲、
事件切片、`PcapAnalyzer` 全都只见过"剥掉载荷的包"。任何"拿 payload 字节数当段长"
的分析逻辑在生产上恒为 0：

- v1.14.14 之前 `PcapAnalyzer` 用 `bytes(tcp.payload)` 判段长 → 数据段被当成纯 ACK，
  **信号 B（full-size 段同序号停滞）永不触发**，对外主推的「A 或 B∧C 判 PMTU 黑洞」
  实际只剩 A；重传统计恒 0；`LOSS_MIN_SEGS` 门槛不可达；被剥载荷的数据段还会喂进
  `_dup_ack` 把正常传输**伪报成 dup-ack 突发**。
- 之所以长期没被发现：`test_pcap_analyzer.py` 用**未剥离**的合成包直接喂分析器，
  从不经过 `_capture_strip_packet` —— 测的是错误的对象。

**规矩**：

1. 段长一律走 `_tcp_payload_len(ip, tcp)`（IP 总长 − 头长），**不要**用 `bytes(payload)`。
   剥除保留原始总长正是为了这个。
2. 任何分析逻辑的测试必须走 `剥载荷 → 环形缓冲 → _write_pcap → 读回分析` 全链路，
   见 `tests/test_pcap_pipeline_e2e.py`。直接构造包喂 `analyze()` 的单测只验证了
   分析器的一半输入形态。
3. 隐私白名单 `CAPTURE_WEB_PORTS = (80, 443, 8080)`，用户可见文案（抓包确认弹窗 /
   盯障报告隐私声明 / `--capture` 帮助）必须**从常量生成**，不要写死端口串——
   v1.14.14 前三处都写 "80/443" 而白名单含 8080。

## 控制台编码 (v1.14.14)

面向中文 Windows 装维机，默认代码页 cp936 编不了 ✓ ✗ ⚠ 🔴 等符号。模块加载时
`_ensure_console_safe()` 把 stdout/stderr 的 **errors 降级为 replace**（只改 errors
不改 encoding，`--json` 字节与管道语义不受影响）。新增终端符号前不必再担心崩溃；
`tests/test_console_encoding.py` 锁住该行为。**注意：不要用 `PYTHONIOENCODING=utf-8`
"解决"本地测试失败**——那正是真实用户会遇到的那个 bug。

## 现场检测模式 (v1.13.0)

- **入口**：场景菜单 `[6]` / CLI `--site`（`--customer` 预填客户名）。
  独立顶层模式，与其他模块互斥；需交互终端（非 TTY 直接报错）。
- **口径**：诊断走 `all_module_keys()`（排除 tcpcc 压测）且剔除 port/iperf3
  （无配置自动跳过）—— 不在客户网络里制造压测负载。
- **手输三处**：客户名称（必填）/ 检测时间（默认当前）/ 签约带宽（可空，
  有值才渲染一页版「达标」格，按实测/签约 ≥90% 判达标）。
- **机房 6 项**：`SITE_CHECK_ITEMS` 常量（建议文案 ≤24 字，破坏会折行破坏
  一页高度锁）；`_normalize_site_check` 白名单校验，清单外 key/值按「未检查」。
- **四件套**：同一 report 出 一页客户报告 / 完整版 / .json / **PDF**。
  - **v1.14.10 起**：一页客户报告走模板D 极简报风
    (`render_report_html_brief_v2`，与 `design_ref/report_templates/模板D_现代仪表盘风.html` 同源),
    `export_report(layout='brief_v2')` 路由, 现场模式主页走该路径; 旧
    `layout='brief'` / `render_report_html_brief` 保留作为兑底 (未动)。
    A4 双页: 第 1 页 = 报头/标题/评分/KPI/主要发现/机房6 项;
    第 2 页 = 检测明细 21 行全表 + 页脚。详情字段 `_fmt_kpi_for_detail` 抽取。
  - **PDF**（v1.14.0，v1.14.1 起 `_find_pdf_browser()` 按 Chrome → **Edge** 探测链兜底——
    Edge 系统必装且同为 Chromium 内核，PDF 能力=Windows 自带；
    `_html_to_pdf()` 无头打印 A4；
    profile 复用 `%TEMP%\np_pdf_profile` + 禁首跑/组件联网 —— 冷启动
    45s → ~3s；Chrome/Edge 都没有才静默跳过，Ctrl+P 兜底），文件名
    `reports/现场检测_客户名_时间戳.*`。
- **数据流**：`build_report(site_check=, meta_manual=, site_note=)` 显式
  传参进 report dict —— 不新增 LAST_RUN 依赖（守收口规则）。
- **截断锁高**：一页版问题卡 标题≤26/现象≤41/建议≤36 字（恒 3 行）、
  机房建议≤24 字（恒单行）—— 字号改动必须重推 `_BRIEF_CLIP`。

## 发版流程（GitHub Actions 自动出包）

**推 tag 即自动发布 Release，不需要手工上传 exe、不需要手工算 SHA256。**
`.github/workflows/release.yml` 在推 `v[0-9]+.[0-9]+.[0-9]+` 形式的 tag 时自动触发
（`on.push.tags`），跑 `windows-latest`：

| 步骤 | 说明 |
|---|---|
| x64 构建 | Python **3.13**（`actions/setup-python`）→ `pyinstaller NetPulse.spec` → `dist/NetPulse.exe` |
| Ookla 依赖 | `speedtest/` 被 gitignore，仓库里没有 `speedtest.exe`；Actions 自己从 Ookla 官方下载放进去（仅 x64，Ookla 无 win32 版） |
| x86 构建 | Python **3.8 x86** + 环境变量 `NETPULSE_ARCH=x86` → `dist/NetPulse_x86.exe`。**必须 3.8**：3.9+ 打的 exe 在 Win7 启动报缺 `api-ms-win-core-path-l1-1-0.dll`（该 API Set 是 Win8+ 才有） |
| 校验 | 两个 exe 都存在才继续；构建日志无论成败都上传成 artifact |
| SHA256 | 对两个 exe 各算一次，写进 Release 正文 |
| Release | `softprops/action-gh-release@v2` + `generate_release_notes: true` 自动建 Release、上传 **6 个资源**：`NetPulse.exe` / `NetPulse.zip` / `NetPulse.exe.sha256.txt` ×（x64、x86 各一套） |

- **改完 `netpulse.py` 不必本地重打 exe**。正式发布只做：版本号三处同步
  （`APP_VERSION` + `version.json` + README 头部）→ 写 CHANGELOG → commit →
  打带注释 tag → **把 tag 推给 `github` remote**。只有推 tag 才触发（推 master 不触发）；
  tag 推到内网 Gitea（`origin`）不会触发。
- **本地重打 exe 只用于自测**（`build_exe.ps1` / `build_exe.bat` → `dist/NetPulse.exe`），
  或 Actions 构建失败时人工兜底。打包完清掉 `build/` 工作区。
- ⚠️ **本地 exe 与线上 exe 字节数不同，不要互相核对**。构建环境不同（Python 小版本、
  PyInstaller 版本、是否内嵌 Ookla exe）→ 同一份代码两次构建可差几十万字节。
  实测 v1.15.1：本地 19,229,389 B vs Actions 19,487,819 B。
  **Release 正文里的 SHA256 只对应 Actions 那份产物**，拿本地 exe 去校验必然对不上。
- 发完确认：`https://github.com/silentcrow09/netpulse/actions` 看 build job 是否绿；
  `https://github.com/silentcrow09/netpulse/releases` 看 Release 与 6 个资源是否齐。
- **tag 发布后不可改**。Actions 失败可在 Actions 页面「Re-run failed jobs」重跑同一个
  tag；彻底失败才追加版本号（如 v1.15.2）重发。
- Release 正文里 `[CHANGELOG.md](./CHANGELOG.md)` 的相对链接，GitHub 会自动重写成
  `/{owner}/{repo}/blob/{tag}/CHANGELOG.md`，可用（已实测 v1.15.1 渲染结果）。

## 隐私开关与环境变量 (v1.15.2 起)

项目对外**有第三方查询**（公网 IP / 出口位置 / LAN 厂商补查），每个都有开关：

| 变量 | 作用 | 覆盖的调用点 |
|---|---|---|
| `NP_OFFLINE=1` | 完全关闭公网 IP / IPv6 / 地理 / ASN 查询 | `get_public_ip` / `get_public_ipv6` / `get_ip_geo` / egress 模块自带的 IP 服务池 —— **四个入口都要各自判**，只在 `run_diagnostics` 层判断会漏掉 nattype 与 egress |
| `NP_NO_ONLINE_OUI=1` | 关闭 LAN 厂商在线补查（不把 MAC 发给第三方） | `_oui_vendor_online` |

- 两个开关**默认都不设置**（行为与以前一致）；`NETWORK_CONFIG["offline"]` / `_OUI_ONLINE_ENABLED`
  是**模块级常量**（环境变量在 import 时读一次），测试里要 mock 常量而不是改环境变量。
- `_env_flag(name)` 统一判定：值非空且不为 `0/false/no/off` 即为真。
- **披露必须从常量生成**（AGENTS.md 既有硬规则）：第三方服务清单是
  `PUBLIC_IP_SERVICES` / `_IPV6_SERVICES` / `_EGRESS_IP_SERVICES` / `IP_GEO_SERVICE` /
  `OUI_ONLINE_SERVICE`，披露文案里的域名一律用 `_public_ip_service_domains()` 取，
  **不要在文案里另写一份域名**（改了一处漏一处 = 新的文案漂移）。
- geo 查询**必须走 HTTPS**：旧版用明文 HTTP 的 ip-api.com，把公网 IP 躺在 URL path 里，
  路径上任何一跳都能读到。ip-api 免费版不支持 HTTPS（实测 403），已换 ipwho.is
  （`?lang=zh-CN` 中文返回，字段与旧服务对齐）。

## 抓包授权标记 (v1.15.2)

`.capture_ack` 写 `{"ts": ISO时间, "fp": 白名单指纹}`，判读时校验三件事：
时间戳可解析 / 未超 `CAPTURE_ACK_VALID_DAYS`（30 天）/ 白名单指纹仍一致
（指纹 = `CAPTURE_WEB_PORTS` + `CAPTURE_PAYLOAD_PORTS` + `CAPTURE_PAYLOAD_KEEP` +
`CAPTURE_FIRST_PKTS` + `CAPTURE_RETENTION_DAYS` + `CAPTURE_MAX_FILES` 的哈希）。
任一不满足 → 重新征求授权。**旧格式（只有一行时间戳）判无效** —— 否则老用户永远
不会被新白名单约束。读文件失败（权限/只读目录）保持「不拦路」语义。

## 验证

```bash
for f in tests/test_*.py; do python "$f"; done
#   单元/回归套件 (v1.15.2: 41 文件): diagnosis/诊断矩阵/丢包口径/
#   XSS 转义 (含测速报告族 href 属性注入回归)/抓包离线分析/pcap 分析与取证/
#   **抓包生产管线端到端 (v1.14.14 新增, 最重要的一条)**/控制台编码兜底 (v1.14.14)/
#   **JSON Schema ↔ 导出一致性 (v1.14.14 新增)**/probes/redaction/场景菜单/
#   盯障统计/scapy 懒加载 (v1.9.7 PR-2)/自提权重启/管理员修复命令一键执行/
#   全量口径与 tcpcc 多目标轮转 (v1.10.0)/自动检查更新 (v1.12.0)/
#   现场检测模式 (v1.13.0)/一页版问题区回退 (v1.13.1)/现场模式自动 PDF (v1.14.0)
#   v1.14.14 已删 tests/test_parsers.py: 那 29 个用例测的 4 个解析器
#   (parse_ipconfig / parse_route_print / parse_arp_a / parse_netsh_wlan_interfaces)
#   **生产代码一次都没调用** —— ARPAnalyzer/RouteAnalyzer/WifiAnalyzer 都是各自
#   内联解析。测试绿着但测的是不运行的代码, 属假覆盖, 已连同解析器一并删除。
#   注意: 壳环境 `python` 可能指向未装 scapy 的解释器; 且 `test_pcap_capture.py`
#   的 TestPcapRingBuffer 2 个用例需要本机装有 Npcap (无 Npcap 时 scapy 解析不出
#   \Device\NPF_Loopback → ValueError), 这是环境依赖不是代码缺陷。
# 抓包取证 (v1.14.14 改了长度口径): 剥载荷时**不再改写 IP/UDP 长度字段**,
# 改为保留原始总长 + 给包挂 .wirelen, 落盘写出 caplen < wirelen 的标准 snaplen
# 截断记录 (等价 tcpdump -s)。Wireshark 读作"线上更长、被截断", 既不误报
# ACKed lost segment, 又保住段长供离线分析器还原。旧文件用 _migrate_pcap.py 修。
```

> ⚠️ `_smoke_report.py` 不在版本库里（被 gitignore），新克隆者跑不了上面那条
> 262 项断言命令。v1.14.14 已从本文移除该引用；如需恢复请把它纳入版本控制。

`tests/fixtures/windows/` 为**脱敏** fixture（MAC 用 02/06 本地管理前缀、IPv6 用
RFC 3849 文档前缀、假 hostname/GUID）；真实抓包或含隐私的本地 fixture 放
`tests/fixtures/private/`（gitignore）。新判定口径改动必须带回归测试
（参考 `test_report_issues.py` / `test_diagnosis_matrix.py` / `test_html_escape.py`）。

产物 `reports/_verify_latest.html` 用于人工核对（`reports/` 已 gitignore）。

## 盯障模式 (v1.5.2)

- **抖动窗口** `_detect_jitter_segments`（v1.5.3 重写判据）：60s 宽**真滑动窗口**（起点锚定丢包时刻，无固定网格的相位漏检；bisect 计数，24h 盯障汇总毫秒级），窗口内丢包 ≥3 次**或**丢包率 ≥10%（需丢包 ≥2 次且窗口样本 ≥10 个，防单次丢包/稀疏窗口误报）→ `jitter_burst` 事件；事件 detail 按段实际跨度描述（合并段可超 60s，不硬编码窗口宽度）
- 事件定位：网关段 `internal`；外网段按段窗口内网关状态分 `both_down`（网关同时丢包 ≥2 次）/ `carrier` / `unknown`；与本**流** `outage` 段重叠不重复报（跨流是独立证据，不互相吞段）
- 结论矩阵：`jitter_burst` 优先级高于 `latency_spike`，verdict=`degraded`
- 阈值常量在 `MonitorSession`：`JITTER_WINDOW_S=60 / JITTER_STEP_S=10（触发窗口合并间隔）/ MIN_JITTER_LOSS=3 / MIN_JITTER_PCT=10.0 / MIN_JITTER_SAMPLES=10`
- **网卡错误采样 (v1.11.0)**：`_nic_err_snapshot()` 30s 采
  Get-NetAdapterStatistics 收发错误/丢弃（开机累计，`_nic_quality()` 差分）。
  判据：会话错误增量 ≥ `NIC_ERR_BURST_MIN_DELTA=20` 出 `nic_error_burst`
  事件（错误集中区间另需单区间 ≥ `NIC_ERR_BURST_WINDOW_MIN=10`），与丢包
  症状同现 → 结论追加链路层根因 + 强制百兆一键命令（建议格式
  `powershell ... (管理员)`，提取器 `_extract_admin_fix_commands` 已支持
  netsh/powershell 双前缀，返回 `[(kind, cmd)]`）。相邻采样计数下降 =
  回绕/重置，本会话不判。CRC 错帧在驱动层被丢弃，**抓包看不到这一层**，
  NIC 计数器是唯一链路层硬证据

## scapy 懒加载契约 (v1.9.7 PR-2)

- 顶层 `import scapy` 已移除：模块级只有占位符（`Ether/TCP/conf/... = None`），
  实际导入走 `_load_scapy()`（main() 开 daemon 线程预加载）
- **任何直接引用 scapy 裸名的函数，入口必须先 `_ensure_scapy()`**，否则拿到
  占位符 None；`SCAPY_AVAILABLE` 判定也要放在 `_ensure_scapy()` 之后
- 测试里 mock `netpulse.conf` / `netpulse.get_if_list` 前必须先 `N._ensure_scapy()`
  （否则函数入口触发的 `_load_scapy()` 会把真实对象写回 globals 覆盖 mock，
  参考 `tests/test_pcap_capture.py` 头部注释）

## 其它

- **发版清单 (v1.12.0 起)**：版本号**三处同步**——`netpulse.py` 的
  `APP_VERSION` + 仓库根 `version.json`（jsDelivr 回落源读它，漏更会让
  国内用户永远检查不到新版本）+ README 头部；然后 tag + 双 remote 推送
  （**推 tag 到 `github` remote 会自动触发 Actions 出 Release**，见
  「发版流程（GitHub Actions 自动出包）」节）
- **自动检查更新 (v1.12.0)**：`_start_update_check()` 在 main() 参数解析
  后开 daemon 线程（**不阻塞启动**，失败静默）；双源
  `UPDATE_CHECK_API`(GitHub Releases) → `UPDATE_CHECK_FALLBACK`(jsDelivr
  version.json)；24h 频控缓存 `%LOCALAPPDATA%\NetPulse\update_check.json`，
  **主源成功或回落源报新版才写**（v1.14.2：jsDelivr @master 快照实测可滞后数周，
  回落源的“无新版”答案不写缓存，否则陈旧答案锁死提示一整天）；提示行走 `UPDATE_DL_PROXY`(gh-proxy.com) 加速前缀。菜单渲染
  经 `_update_notice_line()` 读 `_UPDATE_STATE`（锁保护）；`--json`/CLI
  单次运行不显示提示；测试改这几个函数时全部 mock 网络，不许真实联网。
  **v1.14.6**：启动路径改 `force=True` 每次启动真检查（24h 频控曾让检查
  “看起来没生效”，频控机制仅保留给 `force=False` 调用方）；
  `NP_UPDATE_DEBUG=1` 时 worker 向 stderr 打印源/耗时/结论
  （默认零输出，不污染 stdout/--json），排查“更新检测是否生效”用。
  **v1.14.8**：检查仅交互终端启动（`sys.stdout.isatty()`，CLI/--json 不再
  启动检查线程）；菜单首帧前 `_prime_update_state_from_cache()` 预填
  缓存 + `join(2.0)` 等首次检查结果（否则线程总输给首帧渲染，
  新版提示“永远下一屏才出现”）
- 打包（**仅本地自测用**）：`build_exe.bat` 或 `build_exe.ps1` → `dist/NetPulse.exe`
  （64 位默认；`-Arch x86` 出 32 位 `NetPulse_x86.exe`，需另装 32 位 Python，
  Ookla exe 不随包）。改了 `netpulse.py` 后本地 exe 会落后于代码，自测前要重打；
  **正式发布的 exe 由 GitHub Actions 自动构建，不需要本地打包上传**，
  见「发版流程（GitHub Actions 自动出包）」节
- 根目录 `nul` 是 Windows 保留设备名误产生的 54B 垃圾文件，
  常规删除方式（`rm` / PowerShell / Python）都会被解析成设备路径而失败，已在 `.gitignore` 忽略
- `_smoke_report.py`、`reports/`、`.codefree/`、`speedtest/` 均已 gitignore
