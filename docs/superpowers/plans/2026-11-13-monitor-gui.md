# NetPulse 盯障实时窗口 (v1.22.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** GUI 二期第一项——主页第 7 张卡「持续盯障」进配置页 → 实时盯障页（四路状态 + 延迟双曲线 + 事件预览）→ 停止或到时自动结束 → 窗口内嵌盯障报告，三件套照旧落盘；终端 `--monitor` 全参数零变化。

**Architecture:** 盯障内核零改动——GUI 新增 `_GuiMonitor` 会话层直接组装既有公共件（`MonitorSession.start/snapshot/stop/build_result` + `save_monitor_report`），daemon 线程编排「等时长或停止 → 收尾出报告」；`/api/monitor/*` 路由带 token 闸与服务端节流（进度 ≥2s、曲线 ≥5s、事件预览 ≥5s，全历史精确判定只在结束时跑一次）；页面沿用单页状态机新增 mon-config / mon-live / mon-report 三视图与第 7 张卡。

**Tech Stack:** 同 v1.21.0（标准库 + 模块常量单页 + 1s 轮询）；测试 `py -m pytest`。

**视觉基准:** `design_ref/gui/monitor_design_v1.html`（Simon 已确认定稿）——配置页 / 实时页（大数字+四路状态+840×240 双曲线+事件计数+停止钮）/ 报告页（verdict 结论条+统计卡+图表占位）。

## Global Constraints

- `run_monitor_mode` 与 `MonitorSession` **零修改**；GUI 只读复用其公共方法（start/snapshot/stop/build_result/stream_since/losses_since/_stream_stats 均公共或既有）。
- 新代码不直接读写全局 `LAST_RUN`；`save_monitor_report` 内部机制照旧沿用（注意它会 `res.pop("_csv_rows")` 并可能返回 None——GUI 必须处理 None = 报告落盘失败）。
- 全部新路由过 token 闸（`?t=` / `X-NetPulse-Token`，`hmac.compare_digest` bytes 路径）。
- 动态渲染一律 `textContent`/DOM API，禁 `.innerHTML =`（既有测试闸）；零外链；状态色唯一来源 `STATUS_COLORS`/载荷下发。
- 服务端节流：进度类计算 ≥2s 一次、曲线类 ≥5s 一次、事件预览 ≥5s 一次；页面 1s 轮询只读缓存；节流计数器可观测（验收 S2.4/S6 硬闸）。
- 单轮互斥扩展到盯障：同一时段只允许一个网络活动（诊断/现场检测/盯障），服务端 409 + 页面禁用双保险；检查与置位必须在同一把锁内原子完成。
- 终端行为逐字节不变；全量 pytest 保持绿（当前 1094 passed）；每任务 TDD + commit。
- 单文件不变：新代码进 netpulse.py GUI 区段；页面常量同惯例。
- commit message 中文、`feat:`/`fix:` 前缀、`(v1.22.0)` 结尾。

## 背景事实速查（行号为 v1.21.0 @ 2b0bf50，可能漂移，用符号定位）

| 事实 | 位置/签名 |
|---|---|
| MonitorSession 常量 | `PROBE_INTERVAL=5.0`/`GAP_S=10.0`/`MIN_LOSS_BURST=3`/`MIN_DNS_FAIL=2` :13263-13272 |
| 构造 | `MonitorSession(duration_s, ext_target=None, load_url=None)` :13288；`MONITOR_LOAD_URL` :13284 |
| 公共件 | `start()` :13315 / `snapshot()` :13496（返回 gw_stream/ext_stream/tcp/dns，流条目 (status,t,ms)）/ `progress_line(elapsed)` :13508（口径参照）/ `stop()` 幂等 :13538 / `build_result(early_terminated=False)` :13645 / `_stream_stats` :13623 |
| 事件预览 | `_merge_runs(_strip_gaps(stream, GAP_S)[0], MIN_LOSS_BURST, now)` :13526（中断段数口径）；`_detect_monitor_events(snap, t0, ended_at)` :12875（8 类完整判定，可喂窗口快照做预览） |
| 结束产物 | `build_result` → result["verdict"(stable/degraded/mixed)/conclusion/advice/stats/events/summary/samples...]（13687→13724）；`save_monitor_report(res)` :13822 → `(html_path, json_path)` 或 None，**会 pop `_csv_rows`**，落 `_report_dir()/monitor_ stamp.*` |
| 报告渲染 | `_render_monitor_html(res)` :13848（canvas 图表，离线） |
| stream 窗口 | `LatencyMonitor.stream_since(since=None)` :4180（bisect 支持窗口） |
| GUI 会话层 | `_GuiSession`（`_begin`/`start`/`snapshot`/`is_running`/`on_progress`）:24632 起；`_GUI_RESET_FOR_TEST` :24622；`_GUI_SHUTDOWN` 区段头 |
| HTTP 层 | `_GuiHandler`（`_authorized`/`_send`/`_body`/do_GET/do_POST if-链）:25690 起；`_start_gui_server` :25616（注入 session/token/shutdown_evt 类属性） |
| 页面 | `_GUI_PAGE_HTML = _gui_page()` :25625；JS 状态机 `state.view` + `Q()` 路由表 :25145 起；`updateHomeState(d)` 主页三态 :25196；pollOnce 1s 轮询 |
| 既有互斥 | `_GuiSession._begin` 只查自身 phase；跨类型互斥本计划新增（锁内 check-then-start） |
| 测试模式 | `sys.path.insert + import netpulse as np` + unittest.mock；GUI 测试 6 文件（progress/session/page/server/site/launch/cli） |

---

### Task 1: `_GuiMonitor` 会话层 + 共享互斥

**Files:**
- Modify: `netpulse.py`（GUI 区段：`_GuiMonitor` 类、`_gui_net_busy()`、`_GUI_ACT_LOCK`、`_GuiSession._begin` 接入共享互斥、`_GUI_RESET_FOR_TEST` 扩展）
- Test: `tests/test_gui_monitor.py`（新建）

**Interfaces:**
- Produces（后续任务依赖）:
  - `class _GuiMonitor`: `start(duration_s, ext_target=None, load=False) -> (ok, err|None, effective_s)`（phase: idle→running→done/error）；`stop()`（置停止事件 + `session.stop()`，幂等）；`snapshot() -> dict`；`progress_payload() -> dict`（≥2s 节流）；`curve_payload() -> dict`（≥5s 节流，≤200 点/流）；`report_html() -> bytes|None`（读 html_path 文件）；`is_running() -> bool`
  - `snapshot()` 键：`phase/effective_s/elapsed_s/stop_requested/early/has_report/report_paths/site`（无 verdict——报告页数据走 /api/monitor/report 内嵌）
  - `progress_payload()` 键：`phase/elapsed_s/duration_s/connect{gw:{ok,loss10},ext:{ok,loss10},dns_ok,tcp_ok}/loss_pct{gw,ext}/events_preview{outage,dns_fail,jitter_burst,latency_spike}/load/counters{polls,progress_computes,curve_computes,event_computes}`
  - 模块级 `_gui_net_busy() -> bool`（diag/site/monitor 任一 running）与 `_GUI_ACT_LOCK`
- 互斥语义：三类活动的 start 路径必须在 `_GUI_ACT_LOCK` 内完成「查忙 + 置 running」；`_GuiSession._begin` 增查 `_gui_net_busy()`（排除自身），保持既有单类行为不变。

- [ ] **Step 1: 写失败测试**（要点，完整代码按既有测试风格展开）：

```python
# tests/test_gui_monitor.py 关键用例骨架
class TestGuiMonitor(unittest.TestCase):
    def setUp(self):
        np._GUI_RESET_FOR_TEST()

    def _fake_session(self, dur=60):
        """stub MonitorSession: 可控 snapshot/stop/build_result。"""
        s = mock.Mock()
        s.duration_s = dur
        s.snapshot.return_value = {"gw_stream": [], "ext_stream": [],
                                   "tcp": [], "dns": []}
        s.build_result.return_value = {"verdict": "stable"}
        return s

    # P1 时长钳位: start(0)→effective 30; start(2000*60)→86400; 合法值原样
    # P2 编排: fake MonitorSession → start → 立即 stop() → 线程 join →
    #        phase=done, early=True, build_result(early_terminated=True) 被调,
    #        save_monitor_report 被调且 None(失败) 时 phase=error
    # P3 progress_payload 节流: 1s 内两次调用 progress_computes 只 +1,
    #        counters 键齐全; curve_payload 同理 ≥5s
    # P4 曲线: 注入带 (status,t,ms) 的流 → 窗口过滤(只留最近 600s) +
    #        降采样 ≤200/流 + 丢包点 ms=None 保留
    # P5 事件预览: 注入含连续 3 丢包的 gw 流 → events_preview.outage ≥1,
    #        且 5s 内第二次读取不重算 (event_computes 不变)
    # P6 互斥: handler.session.phase="running" 时 monitor.start 拒绝;
    #        monitor running 时 (patch _gui_net_busy 场景) diag._begin 拒绝
    # P7 report_html: 文件存在返回 bytes, 不存在返回 None
```

- [ ] **Step 2: 跑测试确认失败**：`py -m pytest tests/test_gui_monitor.py -q` → ERROR（`_GuiMonitor` 不存在）

- [ ] **Step 3: 实现**（GUI 区段内，`_GuiSession` 之后插入；要点）：

```python
_GUI_ACT_LOCK = threading.Lock()


def _gui_net_busy():
    """任一网络活动 (诊断/现场检测/盯障) 进行中。"""
    h = _GuiHandler
    s = h.session
    m = h.monitor
    if s is not None and s.is_running():
        return True
    if m is not None and m.is_running():
        return True
    return False
```

`_GuiSession._begin` 开头改为（保持原逻辑，只加共享互斥）：

```python
    def _begin(self, profile, keys):
        with self._lock:
            if self._phase == "running":
                return False, "已有诊断在进行中"
            if _gui_net_busy():          # v1.22.0: 跨类型互斥 (盯障等)
                return False, "已有网络活动在进行中"
            ...原置位逻辑不动...
```

`_GuiMonitor` 核心（完整字段/编排按 Interfaces 实现）：

```python
class _GuiMonitor:
    """盯障 GUI 会话: MonitorSession 只读复用 + 节流快照 + 编排线程。

    phase: idle → running → done / error
    编排: daemon 线程内 (等 duration 或 stop_evt, 1s 粒度) → session.stop()
    → build_result(early_terminated=stop_requested) → save_monitor_report
    (返回 None = 落盘失败 → phase=error)。
    """

    CURVE_WINDOW_S = 600
    CURVE_MAX_POINTS = 200

    def __init__(self):
        import threading  # 顶部已导入, 此处仅为可读性; 直接用模块级 threading
        ...
```

实现要点（全部要落到代码）：
- `start()` 全程持 `_GUI_ACT_LOCK`：查 `_gui_net_busy()` → 置 `self._phase="running"` → 构造 `MonitorSession(effective, ext_target or None, MONITOR_LOAD_URL if load else None)` → `start()` 失败（返回 False 语义, :15432 的判据是 truthiness）→ 回滚 phase 并报错 → 起 daemon 编排线程 → 返回 (True, None, effective)。
- 编排线程：`stop_evt.wait(1.0)` 循环直到超时或停止 → `session.stop()` → `build_result(early_terminated=self._stop_requested)` → `save_monitor_report(res)` → None 则 error、否则存 `self._paths`（含 csv/json）+ `self._phase="done"`；全程异常 → phase=error + error 文本。
- `stop()`：`_stop_requested=True` + `session.stop()`（幂等，直接调即可——编排线程在 wait 中 1s 内感知并收尾）。
- `progress_payload()`/`curve_payload()`/事件预览：实例属性 `_ts_prog/_ts_curve/_ts_evt + 缓存 + 计数器`；`snapshot()` 每次都便宜（只读字段），重算型载荷按节流窗刷新。
- 事件预览：窗口快照（把流条目 t 过滤到最近 600s）喂 `_detect_monitor_events(win_snap, now-600, now)`，按 `type` 计数（outage/jitter_burst/latency_spike/dns_fail/tcp_fail）；异常吞掉置空计数。
- `_GUI_RESET_FOR_TEST` 追加：`_GuiHandler.monitor = None`、`_GUI_ACT_LOCK` 无状态无需清。

- [ ] **Step 4: 跑测试确认通过** → `py -m pytest tests/test_gui_monitor.py -q` 全绿
- [ ] **Step 5: 全量回归** → `py -m pytest -q` 全绿（既有 GUI 测试零改动）
- [ ] **Step 6: Commit**：`feat: _GuiMonitor 会话层 (节流快照/编排/跨类型互斥) (v1.22.0)`

---

### Task 2: `/api/monitor/*` 路由

**Files:**
- Modify: `netpulse.py`（`_GuiHandler` 类属性 `monitor`、do_GET/do_POST 路由、`_start_gui_server` 注入、`_run_gui` 创建 monitor 实例并注入）
- Test: `tests/test_gui_server.py`（追加用例）

**Interfaces:**
- Consumes: Task 1 全部。
- Produces:
  - `GET /api/monitor/progress` → progress_payload（含 counters）
  - `GET /api/monitor/curve` → curve_payload
  - `GET /api/monitor/report` → 整页 HTML（读 html_path；无 → 404）
  - `POST /api/monitor/start` `{minutes, target, load}` → `{ok, err, effective_s}`；忙 → 409 `{ok:false, reason:"busy"}`
  - `POST /api/monitor/stop` → `{ok: true}`（幂等）；未在跑 → 400
- `_start_gui_server(session=None, shutdown_evt=None, monitor=None)`：monitor 缺省自建并注入 `_GuiHandler.monitor`。

- [ ] **Step 1: 写失败测试**（追加到 test_gui_server.py）：
  - P1 token 闸覆盖全部新路由（无 token → 403）
  - P2 start→progress→（fake 编排完成）→report→stop 全链（MonitorSession/诊断全 mock；report 用 tmp 文件）
  - P3 忙时 409：`_GuiHandler.session._phase="running"` 时 POST monitor/start → 409；`_GuiHandler.monitor._phase="running"` 时 POST /api/run → 409
  - P4 minutes 钳位回显：`{"minutes": 0}` → effective_s=30
- [ ] **Step 2: 确认失败** → Step 3: 实现（if-链追加 + `_run_gui` 注入）→ Step 4: 通过 → Step 5: 全量回归 → **Commit**：`feat: /api/monitor/* 路由 (节流+互斥 409+报告内嵌) (v1.22.0)`

---

### Task 3: 页面资产（第 7 卡 + 三视图）

**Files:**
- Modify: `netpulse.py`（`_GUI_PAGE_HTML`/`_GUI_CSS`/`_GUI_JS`）
- Test: `tests/test_gui_page.py`（追加）

**Interfaces:**
- Consumes: Task 1/2 载荷契约。
- 产出（按设计稿 `design_ref/gui/monitor_design_v1.html` 三节 1:1）：
  - 主页第 7 张卡 `[data-p="monitor"]`「持续盯障」（描述与终端语义一致）；`updateHomeState` 扩展：monitor running → 其余卡禁用 + runbar 文案「盯障进行中 · 点击查看」→ 点击 `show("mon-live")`；diag/site running → monitor 卡禁用
  - `#view-mon-config`：预设片（10/30/60 分钟，可点选高亮）+ 自定义分钟输入 + 目标输入 + 负载开关 + 「开始盯障」+ 返回
  - `#view-mon-live`：大数字区（elapsed/duration + 连通率 + 监测中徽章）+ 四路状态行 + SVG 双曲线（840×240 观感，折线由 JS 按 curve_payload 绘制，丢包点 ms=null 画红点）+ 事件计数四卡 + 注记 + 负载提示条 + 「停止盯障」（confirm 后 POST stop）
  - `#view-mon-report`：verdict 徽章（stable/degraded/mixed → 绿/琥珀/红）+ 结论/建议行 + 「提前终止」标（early）+ iframe `/api/monitor/report` + 打开文件夹/返回主页
  - JS：`monFlow` 状态处理（config→live→report）、`monPoll` 1s（live 可见时）、曲线 SVG 用 `document.createElementNS` 逐点绘制（**禁 innerHTML**）、数据全部 textContent
- [ ] Step 1 失败测试（P4 机制断言补 `/api/monitor/*`；新视图锚点；既有闸仍绿）→ Step 2 红 → Step 3 实现（CSS 从设计稿提取，曲线 SVG 用 createElementNS）→ Step 4 绿 → **Commit**：`feat: 盯障页三视图 + 主页第 7 卡 (设计稿定稿 1:1) (v1.22.0)`

---

### Task 4: 文档 + 全量回归

**Files:** `CHANGELOG.md`（[Unreleased] 新增小节：盯障实时窗口条目）、`AGENTS.md`（GUI 层小节追加盯障两条约定：节流红线、互斥锁）、`docs/verify.md` 无需改
- [ ] Step 1: 全量 `py -m pytest -q` 绿 → Step 2: 文档三处 → **Commit**：`docs: 盯障实时窗口条目 + GUI 约定补充 (v1.22.0)`

### Task 5: 端到端自验（verify S1-S8）

**Files:** 只产证据（`.superpowers/sdd/monitor-gui/evidence/`）
- [ ] S1 入口/钳位回显；S2 实时页五条（曲线载荷 ≤200 点/流 + 节流计数）；S3 停止→提前终止报告；S4 到时结束（1 分钟档）+ JSON 数值同源比对；S5 双向互斥 409；S6 10 分钟实跑（内存/曲线窗口/计数达标）；S7 终端 `--monitor 45` 与 v1.21.0 行为对照 + `--monitor --capture` 确认 GUI 无抓包痕迹（有 Npcap 环境则实跑，否则标注待人工）；S8 三页截图人眼核对（截图落 evidence，人眼由 Simon 把关）
- [ ] 汇总 ✅/❌/⚠️ 逐条到交付说明；❌ 回修

---

## Self-Review 结论

1. **Spec 覆盖**：F1→T1(互斥)+T2(409)+T3(卡片/禁用)、F2→T2 start+T3 配置视图、F3→T1 节流载荷+T2 路由+T3 实时视图、F4→T1 编排+T2 report 路由+T3 报告视图、F5→T1/T2 节流计数器+token 闸、F6/不变量→T4 回归+T5 S7。无缺口。
2. **占位符**：测试骨架为要点式（标注「按既有测试风格展开完整断言」），实现代码给出结构与全部关键逻辑；Python 侧无 TBD。
3. **类型一致性**：progress/curve 载荷键名在 T1 定义、T2 透传、T3 JS 消费一致；`effective_s` 在 T1 返回、T2 转发、T3 回显一致；`_gui_net_busy`/`_GUI_ACT_LOCK` 在 T1 定义、T2 使用。
