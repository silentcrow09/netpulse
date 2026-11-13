# NetPulse 模块勾选高级面板 (v1.23.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** GUI 二期第 2 项——主页次级入口「高级模块组合 ›」进面板，按分类勾选任意模块组合（24 项，三分类同源）运行，复用既有进度/报告页；终端模块菜单零变化。

**Architecture:** `/api/run` 扩展 `{keys:[...]}` 形态（与 `{profile}` 互斥出现，服务端白名单校验 ⊆ 24 模块）；`_GuiSession.start` 接受 keys 形态（label=「模块组合 (N 项)」，rule_filter=None 落全规则评估——既有语义零改动）；`/api/scenarios` 载荷新增 `module_catalog`（MODULE_REGISTRY/MODULE_CATEGORIES 只读下发）；页面新增 `#view-modules` 面板（三分类勾选 + 组操作 + tcpcc 确认弹层 + port/iperf3 内联输入 + Ookla 开关）。

**Tech Stack / 视觉基准:** 同前两期；视觉基准 `design_ref/gui/modules_design_v1.html`（Simon 已确认：入口变体 A）。

## Global Constraints

- 终端 `_module_menu`/`parse_choice`/`_parse_keys`/`--list`/`_print_module_list`/`MODULE_REGISTRY`/`MODULE_CATEGORIES` **零修改**（GUI 只读消费）。
- `/api/run {profile}` 形态向后兼容（现有测试零改动）；`keys` 形态服务端白名单（非法/空/与 profile 同现 → 400），互斥沿用 `_GUI_ACT_LOCK`+`_gui_net_busy()`（409）。
- 新代码不碰 `LAST_RUN`；textContent/零外链/状态色红线沿用；全量 pytest 绿（当前 1124）；TDD + 每任务 commit。
- port 目标写 `PORT_PROBE_CONFIG`（格式校验失败 400 留面板）；iperf3 服务器写 `CONFIG["speedtest"]["iperf3_server"]`；Ookla 开关写 `SPEEDTEST_CONFIG["use_speedtest_net"]`——均为既有常量，启动前写入（组合运行结束不回滚：与 CLI 单次进程语义差异可接受，GUI 常驻进程内后续轮次以面板当前值为准，spec 已按「面板当前值」口径冻结）。
- 独占/压测调度不碰（内核既有）；组合的 diagnose(rule_filter=None) 全规则评估是口径不是承诺。
- commit 中文 `feat:`/`fix:`/`docs:` 前缀 `(v1.23.0)` 结尾。

## 背景事实速查（行号 @ v1.22.0 @ 4cb6b46，漂移用符号定位）

| 事实 | 位置 |
|---|---|
| `MODULE_REGISTRY` 24 项 (key,中文名,Tester) | :15543-15577 |
| `MODULE_CATEGORIES` 三分类 6/5/13 + 字母表 | :15609-15632 |
| `EXCLUSIVE_NET_MODULE_KEYS` / `STRESS_MODULE_KEYS`(tcpcc) | :15591/:15584 |
| `diagnose()` rule_filter 未知值 → 全规则 | :2583/:2599 |
| port 无目标 → 警告「未提供目标」 | :10919-10938 → determine_status 警告 :16167 |
| `CONFIG["port"|"speedtest"|...]` | :209-247（port targets/proto/count :211-213；speedtest iperf3_server/use_speedtest_net :225-229） |
| `_GuiSession.start(profile,...)` 只收 profile/full | :24778-24793；`_begin` :24756；`_run_diag` rf 逻辑 :24811 |
| `_GUI_LABELS`（未知 id 回落原串）| :24676-24684 |
| `_gui_meta()` scenarios/module_desc 组装 | :26720-26753 |
| `/api/run` profile 形态 | :26864-26874 |
| 主页次级行 `.g-fullrow`（btn-full + full-count）| :26510；`updateHomeState` :25826 |
| 页面闸测试 | tests/test_gui_page.py（innerHTML/零外链/占位符/createElementNS 白名单） |

---

### Task 1: 服务端——keys 形态 + module_catalog + 配置注入

**Files:** Modify `netpulse.py`（`_GuiSession.start`/`_GUI_LABELS`/`_gui_meta`/`/api/run`）；Test `tests/test_gui_server.py` + `tests/test_gui_monitor.py`（若互斥用例受影响）追加

**Interfaces:**
- `_GuiSession.start(profile=None, keys=None, install=True, pip_mirror=None) -> (ok, err|None)`：keys 优先；白名单（非空、⊆ MODULE_REGISTRY 全集、去重保序）；label=`模块组合 (N 项)`；`_run_diag` 内 rf=None（组合不在 DIAGNOSE_PROFILES 即 None，既有逻辑天然兼容，若需显式化则一行）。
- `/api/run` 请求体：`{keys:[...]}` 或 `{profile}` 二选一（同现 400）；非法 key/空 keys → 400 `{"ok":false,"err":...}`。
- `/api/scenarios` 载荷新增 `"module_catalog": [{"key","name","cat"}...]`（cat ∈ a/b/c）。
- port/iperf3/Ookla 配置写入：新 `POST /api/run` 请求体可选字段 `port_targets`（字符串，逗号分隔）/`iperf3_server`/`use_speedtest_net`（bool）——仅当对应模块在 keys 里才消费；port_targets 格式校验（逐段 `host:port` 或 `host:p1-p2`，正则）失败 → 400。

- [ ] Step 1 失败测试（追加 test_gui_server.py）：
  - P1 keys 组合启动 → progress label=「模块组合 (2 项)」（mock MonitorSession 风格沿用 test_gui_monitor 替身——注意替身需复制类常量的坑，这里 mock 的是 run_diagnostics 管线则用 test_gui_session.py 风格）
  - P2 keys 含非法 key / 空 / 与 profile 同现 → 400
  - P3 module_catalog：24 项、分组 6/5/13、与 MODULE_REGISTRY 中文名一致
  - P4 port_targets 非法 → 400 不启动；合法 → `PORT_PROBE_CONFIG["targets"]` 被写入
  - P5 `{profile:"slow"}` 旧形态回归（现有 P9 类断言继续绿）
- [ ] Step 2 红 → Step 3 实现 → Step 4 绿（四文件定向）→ Step 5 全量 → **Commit** `feat: /api/run keys 形态 + module_catalog + 配置注入 (v1.23.0)`

### Task 2: 页面——次级入口 + 面板视图

**Files:** Modify `netpulse.py`（`_GUI_PAGE_HTML`/`_GUI_CSS`/`_GUI_JS`）；Test `tests/test_gui_page.py` 追加

**要点（全部按设计稿定稿 + 入口变体 A）：**
- 主页 `.g-fullrow` 追加 `<button id="g-modpanel" class="g-link2">高级模块组合 ›</button>`（变体 A 文字入口；样式 g-link2 次级）→ 点击 `show("modules")`。
- `#view-modules`：顶部计数「已选 N / 24」+ 全选/清空/反选；三分类分组（module_catalog 按 cat 分组渲染，组头字母 chip + 分类名 + 副题——副题三句从 MODULE_CATEGORIES 第二元组一并下发）；行 = checkbox + 中文名（textContent）；`tcpcc` 行红字警示；`speedtest` 勾选 → 缩进 Ookla 开关；`iperf3` 勾选 → 缩进服务器输入；`port` 勾选 → 缩进目标输入。
- 「运行所选 (N)」：N=0 禁用；tcpcc 在所选 → confirm 弹层（设计稿第 3 节：遮罩+居中，DOM 实现非 alert）→ 确认后 POST；请求体 `{keys, port_targets?, iperf3_server?, use_speedtest_net?}`；400/409 错误就地显示。
- 运行成功 → 复用既有进度页（pollOnce 已存在，label 自动来自快照）；报告页复用 openMonReport 之外的既有 openReport（诊断管线 `/api/report`）。
- 面板运行中互斥的页面面：updateHomeState 的 diagRun 已覆盖（快照 phase=running），面板运行即 diag running——无需新状态。
- [ ] Step 1 失败测试（锚点：g-modpanel/view-modules/module_catalog 消费/tcpcc 警示文本/createElementNS 不涉及/innerHTML 闸/零外链）→ Step 2 红 → Step 3 实现 → Step 4 绿 → Step 5 全量 → **Commit** `feat: 模块勾选面板视图 + 次级入口 (设计稿定稿 1:1) (v1.23.0)`

### Task 3: 文档 + 版本 + 回归

- [ ] Step 1 全量 `py -m pytest -q` 绿 → Step 2：CHANGELOG [Unreleased] 新增条目；AGENTS.md GUI 层补一条（keys 形态白名单校验红线）；version.json + APP_VERSION → 1.23.0 → Step 3 **Commit** `docs: 模块勾选面板条目 + 版本升 1.23.0 (v1.23.0)`

### Task 4: 端到端自验（verify S1-S8）

- [ ] S1-S8 逐条（S2/S3/S4/S5 真机跑组合与两口径；S6 API 校验；S7 终端菜单对照 + 全量；S8 截图人眼核对留 Simon）；证据落 `.superpowers/sdd/modules-panel/evidence/`；汇总 ✅/❌/⚠️ 到交付说明；❌ 回修

## Self-Review 结论

1. **Spec 覆盖**：F1→T2 入口；F2→T1 catalog+T2 面板；F3→T1 keys+T2 复用进度/报告；F4→T1 白名单/互斥/token；不变量→T3 回归。无缺口。
2. **占位符**：测试为断言要点式（展开按既有风格，brief 流程已声明笔误自修惯例）。
3. **一致性**：`module_catalog` 键名 T1 定义/T2 消费；`keys`/`port_targets`/`iperf3_server`/`use_speedtest_net` 请求体字段 T1 校验/T2 发送一致；label「模块组合 (N 项)」T1 生成/T3 CHANGELOG 口径一致。
