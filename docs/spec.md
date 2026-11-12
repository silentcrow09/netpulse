# 本地 GUI 壳：双击即用的窗口版 NetPulse（v1.21.0）· 需求规格

> 本文件是**需求的唯一来源**。验收标准见 `docs/verify.md`。前一特性（报告判级纠偏 v1.20.0）
> 的 spec/verify 见 git 历史 `41637ef`。
>
> 2026-11-12 方向确认（Simon）：
> ① 技术方向 **A —— 本地 Web 服务 + Chromium `--app` 应用窗口**（零新增第三方依赖）；
> ② **双击默认进 GUI**，终端菜单退为 `--cli` 参数入口；
> ③ 首版范围 = **场景诊断闭环 + 现场检测**；盯障实时窗口与模块勾选高级面板留二期。
> 界面设计稿：`design_ref/gui/gui_design_v1.html`（壳层视觉的唯一参考）。

## 目标

装维人员双击 NetPulse.exe，弹出一个普通应用程序窗口：点场景卡片开始诊断，窗口内看进度、
看报告、一键导出——全程不打字、不面对黑底终端。终端模式完整保留给脚本化场景。

**完成后能做什么、怎样看到生效**：双击 exe（或 `py netpulse.py`）→ 应用窗口弹出
（无地址栏无标签页）→ 主页见场景卡 → 点「网络很慢」→ 窗口内进度逐模块推进 → 完成后窗口内
直接呈现客户版报告 → 点「导出 PDF」在 `桌面\NetPulse\` 生成文件。同时：
`--cli` 仍进旧终端菜单；`--json` 仍输出纯 JSON；所有现有参数行为不变。

## 技术形态

- **壳**：Python 标准库 `http.server`（ThreadingHTTPServer）绑 `127.0.0.1` 随机端口 +
  按 Chrome→Edge 探测链（复用 `_find_pdf_browser()`，netpulse.py:23405）取 Chromium 路径，
  以 `--app=<url>` 拉起独立窗口。**零新增第三方依赖**，PyInstaller 打包体积几乎不变。
- **UI**：单页 HTML/CSS/JS，作为模块常量字符串进 netpulse.py（与 `CSS_CUSTOMER_REPORT`
  同惯例）；进度用 ~1s 轮询本地 JSON API，不用 WebSocket/SSE（装维机环境复杂，轮询最皮实）。
- **诊断内核零改动**：GUI 直接调用既有管线 `run_diagnostics`（16473）→ `diagnose()` →
  `build_report`（19665）→ 渲染/导出，与终端 `_run_scene`（23935）同一条数据管线，
  评分/判级/报告口径天然一致。
- **绕开全屏终端层**：GUI 不进备用屏幕缓冲区（`_console_fullscreen` 包裹的 3 个入口
  interactive_menu / `--diagnose` / modules 路径均不经由）。

## 范围

### F1 · 入口与窗口生命周期

- **入口**：无参数 + TTY → GUI（新默认）；新增 `--cli` → 旧 `interactive_menu()`；
  新增 `--gui` → 显式指定 GUI；**其余全部现有参数（--json/--diagnose/--site/--monitor/
  --list/模块位置参数等）行为逐字节不变**。
- **非 TTY 守卫**：无参数且 stdout 非 TTY（管道/重定向）→ 不启 GUI，维持现状
  （自动化场景没有窗口可看）；`--json` 在任何情况下都不进 GUI。
- **启动链**：生成一次性 token → 绑 `127.0.0.1` 随机端口 → HTTP 服务进守护线程 →
  `--app=http://127.0.0.1:<port>/?t=<token>` 拉起窗口 → 探测失败回落 `webbrowser.open()`
  （普通标签页）→ 再失败（无任何浏览器）→ 终端打印带 token 的 URL 与使用说明，进程驻留等连接。
- **token**：启动时生成（`secrets`），页面与全部 API 请求校验；缺失/不符一律拒绝。
  目的：防本机其他进程借回环端口窥探报告内容。
- **退出**：页面 unload 时 `navigator.sendBeacon` 通知服务端退出进程；诊断进行中时
  页面先弹确认（「诊断仍在进行，关闭窗口将终止本次诊断」），确认后进程直接退出
  （诊断为 daemon 线程，随之终止，不提供中途取消——无取消机制是现状，不为此新增）。
  另有 `atexit` 兜底。
- **宿主控制台**：GUI 窗口拉起成功后，若当前控制台为本进程独占（`GetConsoleProcessList`
  仅返回本进程，即双击 exe 场景）→ 隐藏宿主控制台窗口；若控制台还挂着其他进程
  （用户从已有终端手动启动）→ **保持不动**（不藏用户自己的终端）。降级路径（打印 URL）
  控制台始终可见。
- **HTTP 常驻 vs 终端**：GUI 模式下主线程只等待退出事件，不向 stdout 打印任何诊断内容；
  终端窗口仅承载降级路径的 URL 提示。

### F2 · 主页（场景选择）

- 顶栏：品牌徽标（文字）+ 版本号 + 本机主机名 chip（插值过 `_html_attr`）。
- **6 张场景卡**：`SCENE_MENU_KEYS`（2682）的 slow / disconnect / web / gaming / wifi
  五张 + 现场检测一张（视觉区分）。文案与终端场景菜单**同源**（`SCENE_LABELS` 2674 /
  `SCENE_MENU_DESC` 24192），GUI 不另写一套口径。
- 次级操作：**完整诊断**单按钮，口径 = `full_module_keys()`（与终端菜单「全部」同义，
  含 tcpcc 压测）；按钮说明文案带「含压测，客户网络慎用」。数量文案取
  `len(full_module_keys())` 动态生成，不写死。
- **单轮互斥**：同一时刻只允许一轮诊断（并行两轮会互相污染测速——带宽敏感模块独占
  的同一精神）。进行中：场景卡禁用 + 顶部状态条显示进行中并可点击回到进度页。
- 主页保留「查看上次报告」入口（本次进程内最后一次成功诊断）。

### F3 · 诊断执行与进度

- 后台单线程调用 `run_diagnostics(keys, parallel=True, max_workers=4, banner=False,
  print_modules=False)`（与 `_run_scene` 同参同模块集：`DIAGNOSE_PROFILES` 2633），
  随后 `diagnose(results, rule_filter=profile)`（`PROFILE_RULES` 2656 同源）→
  `build_report(rule_filter=...)`——**评分/判级与终端场景完全同一条管线**。
- **进度通道（新增，不碰 `LAST_RUN`）**：一个线程安全快照对象（模块开始/结束事件 +
  当前阶段 + 起始时间戳 + 每模块状态）。实现挂点：`run_diagnostics` 并行路径现有的
  per-module callback 注入位（当前传 `lambda msg: None`，16990）。HTTP 层只读快照，
  **新代码不得直接读写全局 `LAST_RUN`**（收口规则 2）。
- 进度页展示：完成计数（如 `12/24`）+ 进度条 + 已耗时（**不做 ETA**，不报伪精确预估）+
  当前模块一句话人话说明（复用既有模块呈现文案，缺省回落模块名）+ 模块亮灯列表。
- 亮灯状态色**唯一来源 `STATUS_COLORS` / `STATUS_KEY`**（20122-20136）：
  完成绿 / 警告橙 / 异常红 / 错误深红 / **超时中性灰（不是红）** / 等待灰。

### F4 · 报告页与导出

- 诊断完成 → 自动跳报告页：顶部结论条（健康分 + 等级 + 一句话，读 `report["health"]` /
  `report["summary"]`，口径不动）+ 导出按钮条 + **整页内嵌** `render_report_html_customer`
  （21578）产物——内存直出（HTTP 响应体），不经过临时文件，样式与导出的 HTML 报告完全一致。
- 导出四件：
  - **存 HTML**：`export_report(path, report=..., layout="full")`（23293），落盘
    `桌面\NetPulse\` + 时间戳命名（`_desktop_netpulse_dir()` 23733，与场景报告同规则）；
  - **导出 PDF**：`_find_pdf_browser()` + `_html_to_pdf()`（23451）；无 Chromium 时按钮
    禁用并注明原因（不弹窗报错）；
  - **存 JSON**：`render_report_json`（21874）按扩展名导出；
  - **打开报告文件夹**：`os.startfile`。
- 导出成功就地给文件路径反馈；一次诊断可反复查看，重跑生成新一轮。

### F5 · 现场检测（GUI 版）

- 分步表单（步骤条：填信息 → 自动诊断 → 机房核对 → 产出）：
  1. **填写**：客户名称（必填，空则禁用开始按钮）/ 检测时间（默认当前，可改）/
     签约带宽（可空，填了报告才有达标格——与终端口径一致）；
  2. **诊断**：`[k for k in all_module_keys() if k not in ("port", "iperf3")]`、
     parallel=True——**与终端 `run_site_visit`（23513）完全同口径**（不在客户网络制造压测）；
  3. **机房核对**：`SITE_CHECK_ITEMS`（19570）六项逐项**按 options 单选**
     （每项 3-4 个真实选项，默认「未检查」= 不提交该 key，与终端「直接回车=跳过」
     语义一致；白名单校验沿用 build_report 内置的 `_normalize_site_check`，
     GUI 不另立判级）+ 现场备注；
  4. **产出**：`build_report(site_check=, meta_manual=, site_note=)` 显式传参
     （守收口规则）→ 四件套与终端 `--site` **同构**：文件命名走 `_site_report_base`
     （23483，消毒 + MAX_PATH 预算截断），一页版 brief_v2 / 完整版 full / JSON / PDF；
     无 Chromium 时打开一页 HTML 走 Ctrl+P 兜底（与终端行为一致）。
- 终端 `--site` 入口保持原样不动（GUI 版是新增入口，不是替换）。

### F6 · 视觉与安全红线

- 壳层设计语言继承模板 D（藏蓝 `#0a3b6e` 主色、hairline 分隔、tabular-nums、
  严重度色克制），以 `design_ref/gui/gui_design_v1.html` 为准；
  **状态语义色不进壳层映射**，只从 `STATUS_COLORS` 取（超时=灰不是红）。
- HTML 转义铁律沿用：文本节点 `_html_esc`（19996）/ 属性值 `_html_attr`（20009）；
  主机名、客户名、模块名等一切插值必过转义。
- 页面资产零在线资源（系统字体、纯 CSS/SVG 图形），与现有报告同规。
- 中文界面文案用大白话（面向装维），按钮字短；界面不出现「端点/协议/回调」类 IT 黑话。

### 二期明确不做（本期拒绝实现）

盯障实时窗口、模块勾选高级面板、诊断中途取消/续跑、历史报告浏览（跨进程）、
多语言、GUI 内自动更新。

## 不变量（回归红线）

- `--cli` / `--json` / `--diagnose` / `--site` / `--monitor` / `--list` / 模块位置参数 /
  配置注入参数行为与现状**逐字节一致**；非 TTY 无参数行为不变。
- 终端渲染、评分、判级、报告渲染、导出规则全部不动——GUI 是纯新增层。
- 全量 pytest 套件保持绿；`tests/` 现有用例零改动通过。
- 新增代码不得直接读写全局 `LAST_RUN`（收口规则 2，存量引用只减不增）。
- 冻结新增大 Probe 规则不受影响（本特性不新增任何 Probe）。
