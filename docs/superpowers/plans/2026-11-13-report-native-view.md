# 报告/结果页原生重构（v1.25.0）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 诊断与盯障报告在 GUI 内改为原生 DOM 渲染（JSON 数据通道），消灭 iframe 嵌套；导出链逐字节不变；发 v1.25.0。

**Architecture:** 服务端新增报告投影（`_gui_report_view` / monitor 投影）把内存 report dict 以 JSON 下发；前端在 `_GUI_JS` 内新增渲染器（textContent + createElementNS，零 innerHTML）；`/api/report` 与 `/api/monitor/report` 改返回 JSON；`session.report_html()` / `_GuiMonitor.report_html()` 与两个 iframe 退役。导出渲染器（`render_report_html_customer` 及其 helper、`_render_monitor_html`）零改动，用 golden 逐字节锁。

**Tech Stack:** Python 3.8+ 单文件（netpulse.py，x86 打包兼容：f-string 表达式内不得有反斜杠/换行）、内嵌 vanilla JS、unittest（`for f in tests/test_*.py` 套件）。

## Global Constraints

- 唯一依据：`docs/spec.md`（2026-11-13 Simon 确认：盯障一并改、屏幕原生重设计、改完发 v1.25.0；设计稿选型 **方案 A 单列流**，已回写）+ `docs/verify.md`。
- HTML 转义铁律：导出链文本 `_html_esc` / 属性 `_html_attr`（本计划不改导出链，仅守回归）。
- 页面动态渲染：textContent / createElementNS，禁 innerHTML（P5 闸 `_html_guard_violations`）；`insertAdjacentHTML` 只准全大写常量。
- 状态色唯一来源：页面 `COLORS`/`GRADES` 由 `/api/scenarios` 下发，JS 不内嵌色表。
- 屏幕版数字零自算：分数/计数/待办全部来自投影 JSON；JS 只画不算。
- 双口径并排必须写「实检 N/M 项 · K 项参与计分」。
- 判级口径：无根因时不得写「无故障 / 高置信度」。
- 不新增 `LAST_RUN` 依赖（投影只读 `session._report` / 入参 report dict）。
- 报告数据端点按需拉取，不进轮询；只读端点不持 `_GUI_ACT_LOCK`。
- 导出链 golden 逐字节一致（Task 1 基线，改后每 Task 复跑）。
- x86 兼容：f-string 表达式内无反斜杠/换行；Py3.8 语法（不用 `match`、不用 3.9+ 泛型下标）。
- 发版三处同步：`APP_VERSION`(netpulse.py:3726) + `version.json` + README 头部 = 1.25.0。

---

### Task 1: golden 基线（改任何代码之前）

**Files:**
- Create: `tests/test_report_golden.py`
- Create: `tests/fixtures/golden/report_customer.html` / `report_brief.html` / `report_brief_v2.html`（生成后入库）

**Interfaces:**
- Produces: `tests/fixtures/golden/*.html` 三份基线；`tests/test_report_golden.py::TestReportGolden`（后续每个 Task 结束必跑）。

- [ ] **Step 1: 写 golden 测试** —— fixture 沿用 `test_gui_report_partial.py` 的 `_run()` 模式扩展：KEYS 含 gateway/dns/wifi/speedtest/mtu/ipv6/port/loopback，gateway raw 带 `ping.rtts`（>0 样本）、speedtest raw 带下载/上传 Mbps、dns/wifi 带 issue（警告），部分 key 未测（未检测）。渲染 `render_report_html_customer` / `render_report_html_brief` / `render_report_html_brief_v2` 三份，与 `tests/fixtures/golden/` 下基线逐字节比对；基线缺失时跳过并提示先跑生成命令（`python tests/test_report_golden.py --bless` 支持 `--bless` 写基线）。
- [ ] **Step 2: 生成基线并跑测试** —— `python tests/test_report_golden.py --bless` → `python tests/test_report_golden.py` PASS；`git add` 基线三份 + 测试。
- [ ] **Step 3: 提交** `test: 报告渲染 golden 基线（改前快照）`

### Task 2: 待办聚合抽纯数据函数（零 HTML 变化）

**Files:**
- Modify: `netpulse.py:20879-21011`（`_todo_issues_section`）

**Interfaces:**
- Produces: `_todo_issues_data(modules) -> dict`，键：`todo_issues`（全量聚合后列表，元素含 severity/text/action/impact/raw_summary/_module/_modules/_dup）、`need_attention`、`top_issues`(≤10)、`info_cnt`、`involved_cnt`、`critical_cnt`。`_todo_issues_section(modules)` 改为调它后只做 HTML 拼装。

- [ ] **Step 1: 提取**：把 20885-20990 的聚合/去重/合并/计数逻辑原样搬进 `_todo_issues_data`（返回上述 dict，不动任何文案与顺序）；`_todo_issues_section` 消费它拼 HTML（会诊卡/溢出提示/文案逐字节保留）。
- [ ] **Step 2: 验证**：`python tests/test_report_golden.py` PASS（逐字节一致）+ `python tests/test_v1150_timeout_todo.py` PASS。
- [ ] **Step 3: 提交** `refactor: 待办聚合抽 _todo_issues_data 纯数据函数（golden 锁零变化）`

### Task 3: 诊断报告投影 + /api/report JSON 化

**Files:**
- Modify: `netpulse.py`（`_gui_report_view` 新函数，放 `session.report_html` 附近；`session.report_html` 25263 改 `report_view`；路由 28197-28202）

**Interfaces:**
- Produces: `_gui_report_view(report) -> dict`（None 进 None 出），键：
  `meta{app,version,generated_at,duration_ms,selected_modules,total_modules,ran,note,label场景?不需要}`、
  `health{score,grade,label,verdict,formula}`、`counts`、`summary_counts`（按 STATUS_BAR_ORDER 序）、`exempt_count`、`scope{ran,sel,tot,coverage_text,scope_note}`（Hero 检测范围 chip 同口径：ran<sel → "ran/sel"+提前结束 note；sel<tot → "sel/tot"；否则 "tot 项全覆盖"）、
  `todo{need_cnt,involved_suffix,cards:[{severity,text,impact,action,module,modules,dup,raw_summary}],info_cnt,hidden_cnt,critical_cnt}`（`_todo_issues_data` 直出）、
  `charts{ping{rtts,avg_ms,loss_pct,cap_bits[]},speed{data,method},status{counts按序,exempt_note}}`（ping cap_bits 复刻 _chart_section 21093-21105 口径：平均 <1ms 表达/峰值/丢包）、
  `modules:[{key,name,status,badge_text,verdict,key_metrics:[{label,value,level,hint}](过滤空值同 21166 口径),issues:[{severity,text,action}](按 (severity,text) 去重同 21203 口径),expanded}]`（expanded：有根因 → key∈primary affected；无根因 → status∈PROBLEM_STATUSES）、
  `diagnosis{root_causes:[{severity,title,desc,suggestion}],conf_band}`（`_conf_band(overall_confidence)`）、
  `host{pairs:[[lab,val]...],disclosure}`（对齐 `_host_info_section` 的 sys_pairs 逻辑）、
  `site{site_check?,site_note?,meta_manual?}`（有才给）。
- `/api/report`：`view = self.session.report_view()`；None → 404 `{"error":"尚无报告"}`；否则 200 `application/json`。
- `session.report_view()`：锁内 `self._report` → `_gui_report_view`。

- [ ] **Step 1: 写失败测试** `tests/test_gui_report_view.py`：fixture report（复用 Task 1 fixture 经 build_report）→ 断言投影键齐全、`health.formula == np._score_formula(rep)`、todo.cards 与 `np._todo_issues_data(rep["modules"])` 同源同序、modules[].expanded 符合规则（有根因→首要根因集合；构造无根因 run → PROBLEM_STATUSES 集合）、载荷**不含** `raw_results`/`raw` 键。
- [ ] **Step 2: 跑测试确认 FAIL**（函数不存在）。
- [ ] **Step 3: 实现投影 + 路由**（如上；`generated_at` strftime 同导出；hero chips 数据 host/meta 由 JS 从投影拼）。
- [ ] **Step 4: 跑测试 PASS + golden PASS**（本 Task 尚未动前端，路由契约测试旧断言会红 —— `tests/test_gui_server.py` 的 /api/report HTML 断言在 Task 6 一并更新；本 Task 完成判据 = 新测试绿 + golden 绿 + 其余 GUI 测试不涉 /api/report 的仍绿）。
- [ ] **Step 5: 提交** `feat: 诊断报告投影 _gui_report_view + /api/report JSON 化`

### Task 4: 盯障报告投影 + 路由 JSON 化

**Files:**
- Modify: `netpulse.py`（`_GuiMonitor.report_view()` 26131 旁；路由 28209-28214）

**Interfaces:**
- Produces: `_GuiMonitor.report_view() -> dict|None`：读 `_paths["json"]`（落盘 JSON 已含 stats/events/targets/samples/summary/duration/tcp/nic 全量）→ 投影：`{summary, verdict, conclusion?, targets, duration{actual_s,planned_s,early}, stats{gw{...},ext{...},dns{...}}, events:[{type,time,duration_s,stream,detail}...], series{gw:[[dt,ms]...],ext:[...]}(服务端按 240 点桶降采样,丢包点 ms=null), tcp{retrans_rate_pct}, nic{err_delta}|None, files[文件名]}`。复用 `_GuiMonitor._downsample` 口径（桶降采样，含丢包桶保留丢包点）但独立小函数 `_monitor_series_downsample(pts, cap)`（实例方法依赖会话，落盘回放场景无 session）。
- 路由：`view = self.monitor.report_view()`；None → 404；否则 JSON。

- [ ] **Step 1: 失败测试**（tests/test_gui_report_view.py 追加）：写 `save_monitor_report` 的固定 res 到 tmp reports dir（monkeypatch `_report_dir`）→ `report_view()` 键齐全、series 点数 ≤240、丢包点为 None、events 透传。
- [ ] **Step 2: FAIL 确认 → 实现 → PASS**；golden PASS（盯障导出未动）。
- [ ] **Step 3: 提交** `feat: 盯障报告投影 report_view + /api/monitor/report JSON 化`

### Task 5: 前端原生渲染（方案 A）

**Files:**
- Modify: `netpulse.py` `_GUI_CSS`（26341 iframe 样式替换为 `.g-rpt` 报告样式族）、`_gui_page()`（27860 iframe → `<div id="g-frame" class="g-rpt"></div>`；27992 监控 iframe → `<div id="mon-frame" class="g-rpt"></div>`）、`_GUI_JS`（openReport 27167 / openMonReport 27520 重写 + 渲染器函数群）

**Interfaces:**
- Consumes: Task 3/4 投影 JSON；`el(tag, cls, text)`、`COLORS`/`GRADES`（/api/scenarios）、`fmtMs`、`$()`。
- Produces: `renderReport(d)`（诊断）与 `renderMonReport(d)`（盯障）——全部 textContent/createElementNS；`openReport()` 改为 `get(API.report).then(renderReport).then(show("report"))`，404 → 既有错误提示；`openMonReport()` 同构（保留结论条/文件行/提前终止标逻辑，`#mon-frame` 填充改为渲染）。

渲染器结构（方案 A，组件与 design_ref/gui/report_native_design_v1.html 一致）：
- `svgEl(tag, attrs)`（createElementNS 封装）+ `ringSvg(score, gradeColor)`（120px 环形，dasharray 按 score/100 × 周长）+ `pingLineSvg(rtts)`（折线 + 峰值红点，绿 #34c759 数据轴色硬编码允许：数据轴身份色不属 STATUS_COLORS 轴，与导出报告同口径）+ `speedBars(d)`（div 条形，下行 #0a84ff/上行 #ff9500）+ `statusBar(counts)`（分段条 + 图例）。
- `renderReport(d)`：`#g-frame` 内清空后依次：Hero（环 + score/grade + label + formula + chips[检测范围/实检/待办/生成时间] + scope 双口径条）→ 待办（need_cnt 标 + cards，来源/扣分 chip：豁免模块状态色灰豁免）→ 关键指标（3 卡：ping/speed/status，无数据卡隐藏）→ 模块明细（折叠行列表 + 展开/收起，`expanded` 初始态，其余 N 项正常行）→ 诊断结论（根因卡 + conf_band）→ 本机信息（pairs 网格 + disclosure 小字）→ 技术附录折叠条（含 site 三件时加现场信息卡）。
- `renderMonReport(d)`：banner（沿用现有 `#mon-conclusion` 条）→ 5 统计卡（网关丢包/外网丢包/中断/抖动段/DNS 失败，缺数据不伪 0：无该键不画卡）→ 延迟双线 SVG（蓝/紫双折线 + 红点 + 抖动色带）→ 事件表。
- 双口径说明：Hero 下 scope 条「计分口径：实检 sel 项 · K 项参与计分 · 豁免 E 项（名单）」。
- 状态徽章/圆点颜色一律 `COLORS[st]`/`GRADES[g]`。

- [ ] **Step 1: CSS**（设计稿样式移植进 `_GUI_CSS`，白卡/圆角/间距按稿）。
- [ ] **Step 2: 渲染器 JS**（如上；每段用 `el()`/`svgEl()`，不出现 innerHTML）。
- [ ] **Step 3: openReport/openMonReport 改造**（fetch JSON → 渲染；错误分支 404/异常 → 既有 toast/g-err 风格提示，页面不白屏）。
- [ ] **Step 4: 页面壳**（两处 iframe → div；CSS id 保留 g-frame/mon-frame 以少动引用）。
- [ ] **Step 5: 机械闸**：`python tests/test_gui_page.py`（P5 闸 + 新断言：页面无 `<iframe`）PASS。
- [ ] **Step 6: 提交** `feat: GUI 报告/盯障报告原生渲染（iframe 退役，方案 A）`

### Task 6: session.report_html / monitor.report_html 退役 + 服务器/页面测试更新

**Files:**
- Modify: `netpulse.py`（删 `session.report_html` 25263-25269、`_GuiMonitor.report_html` 26131-26144；确认零引用后删）
- Modify: `tests/test_gui_server.py`（/api/report：无报告 404 + 有报告 JSON 契约；/api/monitor/report 同理）、`tests/test_gui_page.py`（P4 断言更新：`/api/report` 经 fetch 消费 + 页面无 `<iframe` + 渲染器函数锚点）

- [ ] **Step 1: grep 确认 `report_html(` 零引用**（前端已改 fetch JSON）→ 删两函数。
- [ ] **Step 2: 更新两测试文件**（契约照 verify S6：200 application/json、键齐全、404）。
- [ ] **Step 3: 全 GUI 测试绿**：test_gui_server / test_gui_page / test_gui_session / test_gui_report_partial / test_gui_monitor 全 PASS。
- [ ] **Step 4: 提交** `refactor: report_html 现渲路径退役 + GUI 测试契约更新`

### Task 7: 全量回归 + 真机 E2E（verify S1–S5）

- [ ] **Step 1: 全套件** `for f in tests/test_*.py; do python "$f"; done` 全绿（Npcap 2 例环境依赖除外）。
- [ ] **Step 2: E2E harness**（reports/ 下临时脚本，不入库）：真起 GUI server（token + 随机端口）→ POST /api/run 小组合（gateway,dns,mtu）→ 轮询至 done → 无头 Chrome 打开页面 dump DOM：断言无 `<iframe>`、报告视图含 Hero 分数与 formula 文本、数字与 /api/report JSON 一致 → POST /api/run + /api/run/stop 部分报告路径 → 主页「查看报告」入口 → 30s 盯障 start/stop → 盯障报告视图断言（统计卡/事件表/无 mon-frame iframe）。收集结果回填 verify 执行状态（交付说明）。
- [ ] **Step 3: 人眼核对（M8）**：设计稿 vs 实现——由 Simon 打开实机确认（交付四要素标注 ⚠️ 待他过目）；我方以 E2E DOM 断言 + 截图存档 reports/_e2e_*.png 佐证。

### Task 8: 文档 / 版本 / 发版

- [ ] **Step 1: AGENTS.md**：「本地 GUI 层」节补 v1.25.0 四条约定（报告 JSON 投影唯一通道、屏幕版零自算、iframe 退役、golden 测试名）；「报告渲染」节：三份比对自动化指向 `tests/test_report_golden.py`；「验证」清单补新测试文件名。
- [ ] **Step 2: 版本三处**：`APP_VERSION = "1.25.0"` + `version.json` + README 头部。
- [ ] **Step 3: CHANGELOG** `## [1.25.0] - 2026-11-13`（新增/修复/说明分组，Keep a Changelog 中文格式同前条目）。
- [ ] **Step 4: spec 回写**：选型结论已回写（方案 A）；本步核对 spec「待用户决策」清空。
- [ ] **Step 5: commit + tag + push**：master 提交 → `git tag -a v1.25.0 -m ...` → 推 master + tag 到 `github` remote（origin 同步 master）→ Actions 出包确认（交付阶段核对 Release 页）。
- [ ] **Step 6: 独立验证（verifier 子代理，干净 context）**：输入 = docs/spec.md + docs/verify.md + git diff + 测试输出 + golden 结果；输出结构化意见；逐条核实后修复再交付。
