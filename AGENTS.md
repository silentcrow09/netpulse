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

## 报告渲染

- `export_report` 只调用 `render_report_html_customer`（客户视图）
- `render_report_html`（技术视图）和 `render_report_text`（纯文本）**当前零调用点**，
  属于死代码；修改后不会被线上路径覆盖，启用前需自行验证
- 报告须**可离线打开**：全部用系统字体，不引入任何在线资源，图表用纯 SVG 手绘
- **HTML 属性转义**（v1.5.0 P0）：文本节点用 `_html_esc(s)`（`quote=False`），
  **属性值一律用 `_html_attr(s)`**（`quote=True`）—— `_html_esc` 不能进属性拼接。
  评审发现旧版 `_html_esc` 在 `title=` / `data-hint=` / `href=` / `data-mod=` / `id=` 里裸拼，
  恶意 SSID / DNS 名 / hostname 可闭合属性注入标签
- **根因证据链**（v1.5.0）：`RootCause.evidence_ids` 不直接渲染（B 阶段 `Evidence` 实体
  全仓只在 gateway 模块构造 4 处，覆盖率极低）。改为按"规则判定条件 → 证据项"生成——
  `_RC_EVIDENCE_BUILDERS` 里 6 条规则各对应一个 builder，只读规则验证过的字段，缺失即跳过，
  不伪造数字
- **模块折叠**（v1.5.0）：有根因时**只展开首要根因**涉及的模块（首要根因 = severity 最高，v1.5.3 起 `diagnose()` 按严重度降序保证）；**无根因时退回旧行为**
  （规则没命中时不能把异常藏起来）
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
- **置信度显示走 `_conf_band()` 三档**（高/中/低）：内部 0-1 数值是规则设计值不是统计
  概率，UI 不做伪精确百分比；JSON 保留原始数值。旧结果包装的 `Issue.confidence=None`
  （无依据不显示），不要回填统一数字。

## 验证

```bash
for f in tests/test_*.py; do python "$f"; done
#   单元/回归套件 (20 文件 / 457 用例): parsers/diagnosis/诊断矩阵/丢包口径/
#   XSS 转义/pcap 分析与取证 (含 v1.9.9 截断长度字段修正)/probes/redaction/
#   场景菜单/盯障统计/scapy 懒加载 (v1.9.7 PR-2)/自提权重启 (v1.9.7 PR-3)/
#   管理员修复命令一键执行 (v1.9.8)/全量口径与 tcpcc 多目标轮转 (v1.10.0)/
#   自动检查更新 (v1.12.0)
#   注意: 壳环境 `python` 可能指向未装 scapy 的解释器 → test_pcap_capture
#   模块级 proto=TCP NameError; 用装了 scapy 的系统 Python 跑
python _smoke_report.py          # 250 项断言: 图表/导航/折叠/打印/复制/超时扣分 + v1.5.0 转义/证据链/折叠策略/技术附录/报障卡 + v1.5.2 盯障抖动窗口 + v1.5.3 判据修正 6 项 + v1.10.0 全量口径/多目标轮转 6 项 + v1.11.0 网卡错误暴增 2 项 + v1.12.0 更新检查 4 项
# 抓包取证: 截断存储会剥载荷 — v1.9.9 起截断时同步修正 IP/UDP 长度字段,
# 避免 Wireshark 专家误报 (ACKed lost 满屏)。旧文件用根目录 _migrate_pcap.py 修正
```

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
- **自动检查更新 (v1.12.0)**：`_start_update_check()` 在 main() 参数解析
  后开 daemon 线程（**不阻塞启动**，失败静默）；双源
  `UPDATE_CHECK_API`(GitHub Releases) → `UPDATE_CHECK_FALLBACK`(jsDelivr
  version.json)；24h 频控缓存 `%LOCALAPPDATA%\NetPulse\update_check.json`，
  仅成功才写；提示行走 `UPDATE_DL_PROXY`(gh-proxy.com) 加速前缀。菜单渲染
  经 `_update_notice_line()` 读 `_UPDATE_STATE`（锁保护）；`--json`/CLI
  单次运行不显示提示；测试改这几个函数时全部 mock 网络，不许真实联网
- 打包：`build_exe.bat` 或 `build_exe.ps1` → `dist/NetPulse.exe`。
  改了 `netpulse.py` 后需重新打包，否则 exe 落后于代码
- 根目录 `nul` 是 Windows 保留设备名误产生的 54B 垃圾文件，
  常规删除方式（`rm` / PowerShell / Python）都会被解析成设备路径而失败，已在 `.gitignore` 忽略
- `_smoke_report.py`、`reports/`、`.codefree/`、`speedtest/` 均已 gitignore
