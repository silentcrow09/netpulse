# 报告/结果页原生重构（v1.25.0）· 需求规格

> 本文件是**需求的唯一来源**。验收标准见 `docs/verify.md`。前一特性（诊断中途取消/
> 续跑 v1.24.0）的 spec/verify 见 git 历史 `0a04b9c`。
>
> 2026-11-13 方向确认（Simon），三个口径已拍板：
>
> 1. **盯障报告一并改造** —— 诊断报告与盯障报告用同一套原生视图机制，一次消灭全部
>    iframe 嵌套；
> 2. **屏幕原生重设计** —— GUI 里的报告页信息层级按屏幕阅读优化，共享主界面顶栏与
>    视觉语言；**导出用的 HTML/PDF/JSON 报告完全不动**；
> 3. **改完即发 v1.25.0** —— 走完整发版清单（三处版本号同步 + CHANGELOG + 推 tag）。
>
> 设计稿选型（同日方案确认）：**方案 A「结论前置 · 单列流」**——与进度页同一阅读节奏，
> 自上而下：标题工具条 → Hero+口径条 → 待办 → 指标图 → 模块明细 → 诊断结论 →
> 本机信息 → 附录折叠。设计稿见 `design_ref/gui/report_native_design_v1.html`。

## 目标

诊断或盯障跑完后，用户在 GUI 里看到的报告页不再是「嵌在 iframe 里的独立 HTML 文档」
（双顶栏、双导航、双滚动条、报告自带浮动导航悬浮在半屏里），而是与主界面同一个页面、
同一套视觉语言的原生视图。导出交付物（给客户的 HTML/PDF/JSON 文件）保持现状逐字节
同口径。本次同时为将来 Windows 客户端打基础：报告从「服务端渲 HTML」改为「JSON 数据
+ 前端渲染」分层，客户端壳可直接复用同一套数据通道与前端渲染。

**怎样看到生效**：打开 NetPulse GUI → 跑一次诊断 → 跑完自动进入报告视图，该视图在
主界面页面内渲染（DOM 中不再出现 `<iframe>`），顶栏/导航与主页一致；盯障停止后同样。

## 现状（为什么要改）

- GUI 报告视图是一个 `<iframe id="g-frame">` 直指 `/api/report`（netpulse.py:27168、
  27860）；`/api/report`（28197-28202）每次请求调 `session.report_html()`
  （25263-25269）→ `render_report_html_customer(self._report)` **现渲一份完整独立
  HTML 文档**（自带左侧浮动导航 236px、自己的 hero 卡与页脚），塞进 iframe。
- 盯障报告同理：`/api/monitor/report` → `_GuiMonitor.report_html()`（26131），
  iframe `#mon-frame`（27992）。
- 完整报告数据只在内存 `self._report`，页面拿不到 JSON（`/api/progress` 只有
  `verdict` 摘要），这是 iframe 方案被迫存在的根因。

## 范围

1. **报告数据通道**：把内存 report dict 以 JSON 形式下发给页面（覆盖渲染屏幕版所需
   全部要素：健康分/counts/summary/待办清单/模块卡数据/诊断结论/本机信息/元信息）；
   盯障报告有对应的数据通道（事件/结论/统计）。报告数据按需拉取，不进轮询。
2. **诊断报告视图原生重设计**：GUI 内以原生 DOM 渲染报告（替换 `iframe#g-frame`），
   信息层级按屏幕阅读优化（具体视觉与层级以设计稿选型为准，定稿后回写本节）：
   - 与主界面共享顶栏与视觉语言，不再有报告自带的浮动左侧导航；
   - 结论前置：健康分/等级/两口径说明/待办清单优先可见；
   - 模块明细即点即展（默认只展开有问题的模块，沿用 `PROBLEM_STATUSES` +
     首要根因展开口径）；
   - 技术附录弱化（折叠，不占首屏）。
3. **盯障报告视图原生改造**：替换 `iframe#mon-frame`，与诊断报告同一套视觉语言
   （内容结构按盯障报告自身要素组织，不强行套诊断报告结构）。
4. **四个报告入口全部切换**：诊断 done 自动进入、「查看报告」（部分报告）、主页
   「查看上次报告」、现场检测提交成功——全部走新原生视图，行为不变。
5. **现场检测**：GUI 内展示同步走新视图（落盘四件套不变）。
6. **旧 HTML 现渲通道退役**：`/api/report` 改为数据通道后，iframe 现渲路径不再被
   GUI 使用；`session.report_html()` / `_GuiMonitor.report_html()` 按「零引用即删」
   处理（删前确认无其他调用方）。
7. **测试**：GUI 页面资产闸（iframe 断言、渲染规则闸）与服务器路由契约测试同步更新；
   新增「屏幕版与导出版口径一致」的保障测试（同一 report fixture 下关键数字一致）；
   AGENTS.md:233-235 的三份 HTML 渲染比对流程自动化为脚本/测试（导出链回归安全网）。
8. **发版 v1.25.0**：`APP_VERSION` + `version.json` + README 头部三处同步、
   CHANGELOG 条目、AGENTS.md 相关章节更新（GUI 层约定 + 报告渲染节）、tag 推
   `github` remote 触发 Actions。

## 不做什么

- **导出链完全不动**：`render_report_html_customer` 及 7 个章节 helper、
  `CSS_CUSTOMER_REPORT`、`export_report`、`render_report_json`、`_html_to_pdf`、
  现场检测四件套（brief_v2 + 完整版 + json + pdf）与 A4 截断锁——离线可打开、
  系统字体、零外链等既有约束原样保留。
- **终端侧不动**：`--cli` / `--json` / 非 TTY / 交互菜单全不变。
- **数据口径不动**：健康评分、`_score_scope_counts` 双口径、诊断规则、判级口径、
  豁免逻辑零变化。屏幕版只是换渲染载体，不是重算。
- **不新增 `LAST_RUN` 依赖**（收口规则）：报告数据通道从 `session._report` /
  `build_report(run=...)` 显式取数。
- **不做 Windows 客户端壳本身**：只做数据/视图分层打底，不写壳工程。
- **屏幕版不做打印排版**：纸质输出一律走导出（HTML 打开打印或 PDF），屏幕视图不
  适配 A4/分页。
- **不改导出文件的打开方式**：GUI 导出按钮、落盘目录规则、文件名规则维持现状。

## 硬约束

- **安全 · 渲染闸**：屏幕版动态渲染一律 `textContent` / 元素属性赋值，禁
  `innerHTML` 插值（`insertAdjacentHTML` 只准全大写零插值常量，P5 闸延续）；
  HTML 转义铁律（`_html_esc` / `_html_attr`）对导出链继续生效。
- **安全 · 数据**：屏幕版展示的一切字符串值来自 report dict / 盯障报告数据，
  JS 不得拼装服务端不可信内容；SVG 图形以既有方式安全生成。
- **状态色唯一来源**：页面 JS 不内嵌色表，继续经 `/api/scenarios` 下发
  （`STATUS_COLORS` / `GRADE_COLORS`）；报告视图用同一来源，不另立映射。
- **屏幕版数字零自算**：屏幕版所有分数/计数/徽章直接取自报告数据通道下发的值，
  JS 不重算计分、不重判状态（与 `_gui_verdict`「GUI 不自算」同一纪律）。
- **双口径并排必须说明**：屏幕版同时呈现扣分口径与全口径时，必须写明
  「实检 N/M 项 · K 项参与计分」（沿用 AGENTS.md 诊断汇总口径）。
- **判级口径**：无根因时不得写「✓ 无故障 / 高置信度」（AGENTS.md 判级四条硬规矩
  延续到屏幕版文案）。
- **节流红线**：报告数据按需拉取不轮询；不加重现有 `/api/progress` 等轮询成本。
- **互斥锁边界**：报告数据端点是只读端点，不持 `_GUI_ACT_LOCK`，不改变三类网络
  活动的互斥语义。
- **离线**：GUI 页面保持零外链（资产闸延续）。
- **兼容契约**：`--cli` / `--json` / 非 TTY 永不进 GUI 的既有判定不变；token 鉴权
  不变；`/api/shutdown` beacon 语义不变。
- **发版纪律**：版本号三处同步 + CHANGELOG + 双 remote（tag 只推 `github`）。

## 交付物

- `netpulse.py`：GUI 资产（`_GUI_CSS` / `_GUI_JS` / `_gui_page`）、报告数据端点、
  `session`/`monitor` 数据出口、iframe 与现渲路径退役
- `tests/`：更新的 GUI 闸测试 + 新增口径一致性测试 + 导出链渲染比对自动化
- `design_ref/gui/report_native_design_v1.html`：屏幕版报告设计稿（多套方案选型）
- `docs/spec.md` + `docs/verify.md`（本文件与验收）
- `CHANGELOG.md` + `APP_VERSION` + `version.json` + `README.md` + `AGENTS.md` 更新
- tag `v1.25.0` → GitHub Actions Release

## 待用户决策

- 无（设计稿选型已定：方案 A，见文首确认记录）。

## 术语

- **屏幕版报告（结果页）**：GUI 内以原生 DOM 呈现的报告视图，本次新增的 JS 渲染路径。
- **导出版报告**：`render_report_html_customer` 等产出的独立完整 HTML 文档（现状
  不动），用于落盘导出与 PDF 打印。
- **报告数据通道**：把 `build_report` 产出的 report dict 以 JSON 下发给页面的 HTTP
  端点；盯障报告有对应的数据通道。
- **双口径**：`counts`（扣分口径，豁免 5 模块后 19 项）与 `summary`（全口径 24 项），
  唯一来源 `_score_scope_counts`。
- **首要根因展开**：有根因时只展开首要根因涉及的模块，无根因时退回
  `PROBLEM_STATUSES` 默认展开（AGENTS.md 模块折叠口径，屏幕版沿用）。
