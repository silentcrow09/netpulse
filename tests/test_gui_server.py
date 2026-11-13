# -*- coding: utf-8 -*-
"""GUI HTTP 服务 (v1.21.0): token 闸 / API 契约 / 关停。

全部本机回环 + 随机端口, 管线全 mock, 不跑真实诊断。
验证点:
  P1 无 token → 403; 带 token → 200 (页面与 API)
  P2 /api/scenarios 场景集与 DIAGNOSE_PROFILES 一致, status_colors 来自 STATUS_COLORS
  P3 POST /api/run 启动成功; busy 时 409
  P4 GET /api/report 无报告 404, 有报告返回 HTML
  P5 POST /api/shutdown 触发事件
  P6 GET /api/netstatus → {"ok": ...} (顶栏联网状态数据源, 锁内读 _GUI_NET)
  P7 _gui_conn_check 三态 (通/不通/OSError→False) + _gui_net_watch 单轮写状态

v1.22.0 盯障路由 (Task 2):
  P8 五条 /api/monitor/* 新路由全部过 token 闸 (无 token → 403)
  P9 start→progress→curve→report→stop 全链: minutes×60 回显 / 载荷键 /
     无报告 404 / 重复 stop 幂等 200 / 收尾后 stop 400 / 报告内嵌 bytes
  P10 双向互斥 409: 诊断 running → 盯障 start 409; 盯障 running →
      /api/run 409 (同类 running 也走同一忙闸)
  P11 minutes 钳位与非法输入: 0 → effective_s=30; 非法值 400 且不构造
      MonitorSession; int(∞) OverflowError 同样 400
  P12 Task 1 审查 4 条 Minor 回归: ①提交窗口内 stop 不丢 ②编排线程
      start 失败回滚 idle+清孤儿 ③int OverflowError 并入时长不合法
      ④curve_payload 返回缓存副本

v1.22.0 页面资产 (Task 3):
  P13 /api/shutdown 守卫: 盯障 running + 非 force → 409 (防丢当轮报告);
      force 放行且先尽力 monitor.stop(); 诊断 running 的既有 409 保持
"""
import json
import os
import socket
import sys
import http.client
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


def _req(port, method, path, token=None, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = dict(headers or {})
    if token:
        h["X-NetPulse-Token"] = token
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        h["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=h)
    r = conn.getresponse()
    raw = r.read()
    conn.close()
    return r.status, raw


def _fake_monitor_session(dur=600):
    """MonitorSession 实例替身 (与 tests/test_gui_monitor.py 同款契约):
    可控 snapshot/stop/build_result; start 显式声明成功语义。"""
    s = mock.Mock()
    s.duration_s = dur
    s.snapshot.return_value = {"gw_stream": [], "ext_stream": [],
                               "tcp": [], "dns": []}
    s.build_result.return_value = {"verdict": "stable"}
    s.start.return_value = True
    return s


def _patch_monitor_session(fake, save_result=None):
    """MonitorSession 类替身三件套 (沿用 test_gui_monitor.py::_patch_ms)。

    关键坑: 类替身必须复制真实 MonitorSession 全部大写常量 ——
    _detect_monitor_events 以模块级 MonitorSession.GAP_S 引用, 缺常量的
    Mock 替身会让事件预览静默吞成空计数。save_result 传可调用对象时
    按 side_effect 生效 (P9 的落盘替身要真写 tmp 文件)。
    """
    rec = {}
    real = np.MonitorSession

    def _factory(*args, **kw):
        rec["args"] = args
        rec["kw"] = kw
        return fake

    for attr in dir(real):
        if attr.isupper():
            setattr(_factory, attr, getattr(real, attr))
    p_ms = mock.patch.object(np, "MonitorSession", _factory)
    save_mock = mock.Mock()
    if callable(save_result):
        save_mock.side_effect = save_result
    else:
        save_mock.return_value = save_result
    p_save = mock.patch.object(np, "save_monitor_report", save_mock)
    return rec, p_ms, p_save


class TestGuiServer(unittest.TestCase):

    def setUp(self):
        np._GUI_RESET_FOR_TEST()
        self.session = np._GuiSession()
        self.evt = threading.Event()
        self.srv, self.port, self.token = np._start_gui_server(
            self.session, self.evt)
        self.addCleanup(lambda: (self.evt.set(), self.srv.shutdown(),
                                 self.srv.server_close()))

    def test_token_gate(self):
        st, _ = _req(self.port, "GET", "/", token=None)
        self.assertEqual(st, 403)
        st, body = _req(self.port, "GET", "/", token=self.token)
        self.assertEqual(st, 200)
        self.assertIn(b"<!DOCTYPE html>", body)
        st, _ = _req(self.port, "GET", "/api/progress", token="wrong")
        self.assertEqual(st, 403)

    def test_token_non_ascii_403(self):
        # I1 (审查): hmac.compare_digest 的 str 路径遇非 ASCII 抛 TypeError,
        # 被外层 except 兜成 500 并泄漏内部报错文本。契约要求未认证一律
        # 403 forbidden。header 与 ?t= 两个取值通道都要锁:
        #   header: latin-1 字符 'ÿ' (服务端按 latin-1 解码 → 非 ASCII str)
        #   query : %FF (parse_qs unquote errors='replace' → U+FFFD 非 ASCII str)
        st, raw = _req(self.port, "GET", "/api/progress",
                       headers={"X-NetPulse-Token": "ÿ"})
        self.assertEqual(st, 403)
        self.assertIn(b"forbidden", raw)
        st, raw = _req(self.port, "GET", "/api/progress?t=%FF")
        self.assertEqual(st, 403)
        self.assertIn(b"forbidden", raw)

    def test_scenarios_payload(self):
        st, raw = _req(self.port, "GET", "/api/scenarios?t=" + self.token)
        self.assertEqual(st, 200)
        meta = json.loads(raw)
        ids = {s["id"] for s in meta["scenarios"]}
        self.assertEqual(ids - {"site", "monitor"}, set(np.DIAGNOSE_PROFILES))
        self.assertIn("site", ids)
        # v1.22.0 第 7 卡「持续盯障」必须在场景载荷中 (页面按 payload 渲染)
        mon = [s for s in meta["scenarios"] if s["id"] == "monitor"]
        self.assertEqual(len(mon), 1)
        self.assertEqual(mon[0]["label"], "持续盯障")
        self.assertIn("偶发掉线", mon[0]["desc"])   # 与终端菜单同语义
        for st_cn, color in meta["status_colors"].items():
            self.assertEqual(np.STATUS_COLORS.get(np.STATUS_KEY.get(st_cn)),
                             color, "状态色必须来自 STATUS_COLORS")
        self.assertEqual(meta["full_count"], len(np.full_module_keys()))
        labels = {s["label"] for s in meta["scenarios"]}
        self.assertTrue(set(np.SCENE_LABELS.values()) <= labels,
                        "场景卡文案必须与终端菜单同源")

    def test_run_and_progress(self):
        run = {"status": {"gateway": "完成"}, "results": {"gateway": {"x": 1}},
               "evidence": {}, "keys": ["gateway"], "system": {},
               "duration_ms": 1, "total_modules": 1}
        report = {"health": {"score": 90}}
        def _rd(keys, **kw):
            # brief 笔误修正: LAST_RUN 初值为 None, 直接 .clear() 会 AttributeError
            # (与 tests/test_gui_session.py::_seed_last_run 同一修正)。
            if np.LAST_RUN is None:
                np.LAST_RUN = dict(run)
            else:
                np.LAST_RUN.clear(); np.LAST_RUN.update(run)
            return run
        s = self.session
        with mock.patch.object(np, "run_diagnostics", side_effect=_rd), \
             mock.patch.object(np, "diagnose", side_effect=lambda r, rule_filter=None: type("D", (), {"to_dict": lambda self: {}})()), \
             mock.patch.object(np, "_enrich_diagnosis_evidence", side_effect=lambda d, r, e: d), \
             mock.patch.object(np, "build_report", side_effect=lambda **kw: report):
            st, raw = _req(self.port, "POST", "/api/run?t=" + self.token,
                           body={"profile": "disconnect"})
            self.assertEqual(st, 200)
            self.assertTrue(json.loads(raw)["ok"])
            for _ in range(100):        # 等 daemon 线程跑完 (最多 10s)
                if s.snapshot()["phase"] in ("done", "error"):
                    break
                import time; time.sleep(0.1)
            self.assertEqual(s.snapshot()["phase"], "done")
            st, raw = _req(self.port, "GET", "/api/progress?t=" + self.token)
            self.assertEqual(json.loads(raw)["phase"], "done")

    def test_report_gate(self):
        st, _ = _req(self.port, "GET", "/api/report?t=" + self.token)
        self.assertEqual(st, 404)
        with mock.patch.object(np, "render_report_html_customer",
                               return_value="<html>fake</html>"):
            self.session._report = {"fake": True}
            st, raw = _req(self.port, "GET", "/api/report?t=" + self.token)
        self.assertEqual(st, 200)
        self.assertIn(b"fake", raw)

    def test_shutdown_event(self):
        st, raw = _req(self.port, "POST", "/api/shutdown?t=" + self.token,
                       body={"force": False})
        self.assertEqual(st, 200)
        self.assertTrue(self.evt.is_set())

    def test_shutdown_guard_monitor_running(self):
        # P13 (Task 3 生命周期必收项): 盯障 running 时非 force 关停必须
        # 409 (防丢当轮报告 + 孤儿 ping -t); force 放行且先尽力 monitor.stop()。
        tok = "?t=" + self.token
        mon = np._GuiHandler.monitor      # setUp 缺省自建的实例
        mon._phase = "running"            # 直摆忙 (同 P10 手法)
        st, raw = _req(self.port, "POST", "/api/shutdown" + tok,
                       body={"force": False})
        self.assertEqual(st, 409)
        self.assertFalse(self.evt.is_set())       # 未放行退出
        st, raw = _req(self.port, "POST", "/api/shutdown" + tok,
                       body={"force": True})
        self.assertEqual(st, 200)
        self.assertTrue(self.evt.is_set())        # force 放行
        self.assertTrue(mon._stop_requested)      # 放行前已尽力停止盯障
        # 诊断 running 的既有 409 口径保持不变 (回归锁)
        self.evt.clear()
        mon._phase = "idle"
        self.session._phase = "running"
        st, _ = _req(self.port, "POST", "/api/shutdown" + tok,
                     body={"force": False})
        self.assertEqual(st, 409)

    def test_run_conflict_409(self):
        self.session._phase = "running"     # 直接摆成忙
        st, raw = _req(self.port, "POST", "/api/run?t=" + self.token,
                       body={"profile": "slow"})
        self.assertEqual(st, 409)

    # -- v1.22.0 盯障路由 (P8–P12) --

    def test_monitor_routes_token_gate(self):
        # P8: 五条新路由全部过 token 闸 (无 token → 403)
        for method, path in (("GET", "/api/monitor/progress"),
                             ("GET", "/api/monitor/curve"),
                             ("GET", "/api/monitor/report"),
                             ("POST", "/api/monitor/start"),
                             ("POST", "/api/monitor/stop")):
            st, _ = _req(self.port, method, path, token=None)
            self.assertEqual(st, 403, path)

    def test_monitor_full_chain(self):
        # P9: start→progress→curve→report→stop 全链。minutes×60 回显;
        # build_result 用事件闸拦住编排收尾, 依次验证「无报告 404 →
        # 重复 stop 幂等 200 → 放行落盘 → 报告 200 → 结束后 stop 400」。
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        html_path = os.path.join(tmp, "mon.html")
        json_path = os.path.join(tmp, "mon.json")
        fake = _fake_monitor_session()
        gate = threading.Event()
        fake.build_result.side_effect = lambda **kw: (
            gate.wait(5), {"verdict": "stable"})[1]

        def _fake_save(res):
            with open(html_path, "wb") as f:
                f.write("<html><body>盯障报告OK</body></html>".encode("utf-8"))
            return (html_path, json_path)

        rec, p_ms, p_save = _patch_monitor_session(fake,
                                                    save_result=_fake_save)
        mon = np._GuiHandler.monitor        # setUp 注入的同一实例
        tok = "?t=" + self.token
        with p_ms, p_save:
            st, _ = _req(self.port, "GET", "/api/monitor/report" + tok)
            self.assertEqual(st, 404)               # 起步无报告
            st, raw = _req(self.port, "POST",
                           "/api/monitor/start" + tok,
                           body={"minutes": 10, "target": "1.2.3.4",
                                 "load": False})
            self.assertEqual(st, 200)
            d = json.loads(raw)
            self.assertTrue(d["ok"])
            self.assertEqual(d["effective_s"], 600)      # minutes×60
            self.assertEqual(rec["args"], (600, "1.2.3.4"))
            self.assertEqual(rec["kw"], {"load_url": None})
            st, raw = _req(self.port, "GET", "/api/monitor/progress" + tok)
            self.assertEqual(st, 200)
            d = json.loads(raw)
            self.assertEqual(d["phase"], "running")
            self.assertEqual(d["duration_s"], 600)
            for k in ("elapsed_s", "connect", "loss_pct", "events_preview",
                      "load", "counters"):
                self.assertIn(k, d)
            for k in ("polls", "progress_computes", "curve_computes",
                      "event_computes"):
                self.assertIn(k, d["counters"])
            st, raw = _req(self.port, "GET", "/api/monitor/curve" + tok)
            self.assertEqual(st, 200)
            d = json.loads(raw)
            self.assertEqual(d["window_s"], 600)
            self.assertIn("gw", d)
            self.assertIn("ext", d)
            st, _ = _req(self.port, "GET", "/api/monitor/report" + tok)
            self.assertEqual(st, 404)               # 编排被闸住, 未落盘
            st, raw = _req(self.port, "POST", "/api/monitor/stop" + tok)
            self.assertEqual(st, 200)
            self.assertTrue(json.loads(raw)["ok"])
            st, raw = _req(self.port, "POST", "/api/monitor/stop" + tok)
            # 幂等: build_result 仍被闸着, phase 还是 running → 再 stop 也 200
            self.assertEqual(st, 200)
            gate.set()
            for _ in range(100):
                if mon.snapshot()["phase"] in ("done", "error"):
                    break
                time.sleep(0.1)
            self.assertEqual(mon.snapshot()["phase"], "done")
            fake.build_result.assert_called_once_with(early_terminated=True)
            st, raw = _req(self.port, "GET", "/api/monitor/report" + tok)
            self.assertEqual(st, 200)
            self.assertIn("盯障报告OK".encode("utf-8"), raw)
            st, raw = _req(self.port, "POST", "/api/monitor/stop" + tok)
            self.assertEqual(st, 400)               # 已结束 → 未在跑
            self.assertFalse(json.loads(raw)["ok"])

    def test_monitor_busy_409_both_ways(self):
        # P10: 双向互斥 409 (忙检在 _GUI_ACT_LOCK 内查)
        tok = "?t=" + self.token
        self.session._phase = "running"     # 直接摆忙 (同 test_run_conflict_409)
        st, raw = _req(self.port, "POST", "/api/monitor/start" + tok,
                       body={"minutes": 10})
        self.assertEqual(st, 409)
        self.assertEqual(json.loads(raw), {"ok": False, "reason": "busy"})
        self.session._phase = "idle"
        np._GuiHandler.monitor._phase = "running"
        st, raw = _req(self.port, "POST", "/api/monitor/start" + tok,
                       body={"minutes": 10})
        self.assertEqual(st, 409)           # 同类 running → 同一忙闸
        st, raw = _req(self.port, "POST", "/api/run" + tok,
                       body={"profile": "slow"})
        self.assertEqual(st, 409)
        self.assertEqual(json.loads(raw)["reason"], "busy")

    def test_monitor_minutes_clamp_and_invalid(self):
        # P11: 非法输入 400 且不构造 MonitorSession; minutes=0 钳到下限
        # 30 并回显; int(∞) OverflowError 同样 400 (审查 Minor ③ 路由侧)。
        mon = np._GuiHandler.monitor
        fake = _fake_monitor_session()
        rec, p_ms, p_save = _patch_monitor_session(fake,
                                                   save_result=("x", "y"))
        tok = "?t=" + self.token
        with p_ms, p_save:
            st, raw = _req(self.port, "POST", "/api/monitor/start" + tok,
                           body={"minutes": "abc"})
            self.assertEqual(st, 400)
            self.assertIn("err", json.loads(raw))
            self.assertNotIn("args", rec)           # 未构造 MonitorSession
            st, _ = _req(self.port, "POST", "/api/monitor/start" + tok,
                         body={"minutes": float("inf")})   # JSON Infinity
            self.assertEqual(st, 400)
            st, raw = _req(self.port, "POST", "/api/monitor/start" + tok,
                           body={"minutes": 0})
            self.assertEqual(st, 200)
            d = json.loads(raw)
            self.assertTrue(d["ok"])
            self.assertEqual(d["effective_s"], 30)  # 钳位回显
            self.assertEqual(rec["args"][0], 30)
            mon.stop()
            mon._thread.join(timeout=5)

    def test_minor_stop_before_commit_kept(self):
        # P12a (审查 Minor ①): phase 置位到 _session 提交之间到达的 stop
        # 曾被提交块 clear 抹掉 → 用户点了停止却跑满全程。修复后窗口起点
        # 清上一轮残留、提交块甄别保留: 编排线程首个 wait 即返回。
        m = np._GuiMonitor()
        fake = _fake_monitor_session()
        # 落盘替身须返回真值路径 (None = 落盘失败 → phase=error, 既有语义)
        rec, p_ms, p_save = _patch_monitor_session(fake,
                                                   save_result=("x", "y"))
        in_window = threading.Event()
        release = threading.Event()

        def _blocking_start():
            in_window.set()
            release.wait(5)
            return True

        fake.start.side_effect = _blocking_start
        box = {}

        def _do_start():
            box["res"] = m.start(600)

        with p_ms, p_save:
            w = threading.Thread(target=_do_start, daemon=True)
            w.start()
            self.assertTrue(in_window.wait(5), "未进入 session.start 窗口")
            self.assertEqual(m.snapshot()["phase"], "running")  # 已置位未提交
            m.stop()                    # 窗口内到达的 stop
            release.set()
            w.join(timeout=5)
            ok, err, _ = box["res"]
            self.assertTrue(ok, err)
            m._thread.join(timeout=5)   # 若 stop 被抹, 这里会白等满 600s
        snap = m.snapshot()
        self.assertEqual(snap["phase"], "done")
        self.assertTrue(snap["early"])
        self.assertTrue(snap["stop_requested"])
        fake.build_result.assert_called_once_with(early_terminated=True)

    def test_minor_thread_start_failure_rollback(self):
        # P12b (审查 Minor ②): 编排线程起不来 (线程耗尽 RuntimeError) 时
        # phase 必须回滚 idle (否则永久卡 running 挡死后续盯障), 且补
        # stop() 清已在跑的采集 (孤儿 ping)。
        m = np._GuiMonitor()
        fake = _fake_monitor_session()
        rec, p_ms, p_save = _patch_monitor_session(fake)

        def _boom_thread(*args, **kw):
            t = mock.Mock()
            t.start.side_effect = RuntimeError("cannot start new thread")
            return t

        with p_ms, p_save, mock.patch.object(np.threading, "Thread",
                                             _boom_thread):
            ok, err, eff = m.start(600)
        self.assertFalse(ok)
        self.assertIn("盯障启动失败", err)
        self.assertIn("RuntimeError", err)
        self.assertIsNone(eff)
        self.assertEqual(m.snapshot()["phase"], "idle")   # 回滚, 不卡 running
        self.assertTrue(fake.stop.called)                 # 孤儿采集清理
        self.assertFalse(fake.build_result.called)        # 无编排收尾

    def test_minor_duration_overflow(self):
        # P12c (审查 Minor ③): int(∞) 抛 OverflowError, 与类型/取值错误
        # 同按「时长不合法」拒, 不再炸穿 start()。
        m = np._GuiMonitor()
        fake = _fake_monitor_session()
        rec, p_ms, p_save = _patch_monitor_session(fake)
        with p_ms, p_save:
            ok, err, eff = m.start(float("inf"))
        self.assertFalse(ok)
        self.assertIn("不合法", err)
        self.assertIsNone(eff)
        self.assertEqual(m.snapshot()["phase"], "idle")
        self.assertNotIn("args", rec)

    def test_minor_curve_payload_copy(self):
        # P12d (审查 Minor ④): curve_payload 返回缓存副本, 消费方改写
        # (append/换值) 不污染节流缓存 (第二次调用走缓存命中路径)。
        m = np._GuiMonitor()
        fake = _fake_monitor_session()
        rec, p_ms, p_save = _patch_monitor_session(fake)
        with p_ms, p_save:
            m.start(600)
            c1 = m.curve_payload()
            c1["gw"].append([999, 1.0])     # 消费方改写「副本」
            c1["window_s"] = 0
            c2 = m.curve_payload()          # 5s 内 → 缓存命中
            m.stop()
            m._thread.join(timeout=5)
        self.assertEqual(c2["window_s"], 600)
        self.assertNotIn([999, 1.0], c2["gw"])

    def test_netstatus_api(self):
        # P6: 探测线程之外, 测试直接在锁内摆状态 → API 原样透传
        self.addCleanup(np._GUI_RESET_FOR_TEST)
        with np._GUI_NET_LOCK:
            np._GUI_NET["ok"] = True
        st, raw = _req(self.port, "GET", "/api/netstatus?t=" + self.token)
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(raw), {"ok": True})
        with np._GUI_NET_LOCK:
            np._GUI_NET["ok"] = False
        st, raw = _req(self.port, "GET", "/api/netstatus?t=" + self.token)
        self.assertEqual(json.loads(raw), {"ok": False})

    def test_gui_conn_check_three_states(self):
        # P7a: 探测函数就近 `import socket as _s` → 与顶层 socket 同一模块
        # 对象, mock `socket.create_connection` 本身即可命中。
        with mock.patch("socket.create_connection") as m:
            self.assertTrue(np._gui_conn_check())
            args, kwargs = m.call_args
            self.assertEqual(args[0], np._GUI_NET_HOSTPORT)   # 默认目标
            self.assertEqual(kwargs["timeout"], 2.0)
            m.reset_mock()
            self.assertTrue(np._gui_conn_check(host="127.0.0.1", port=1))
            self.assertEqual(m.call_args[0][0], ("127.0.0.1", 1))
        with mock.patch("socket.create_connection", side_effect=OSError("no")):
            self.assertFalse(np._gui_conn_check())
        # socket.timeout 是 OSError 子类 (超时 = 不通, 不冒泡)
        with mock.patch("socket.create_connection",
                        side_effect=socket.timeout("t/o")):
            self.assertFalse(np._gui_conn_check())

    def test_gui_net_watch_single_cycle(self):
        # P7b: 一次性循环 —— 先置位的 evt 会让循环体一次都不跑 (条件在顶上),
        # 所以在首次探测的 mock 里置位: 探测→写状态→wait 立即返回→退出, 恰一轮。
        self.addCleanup(np._GUI_RESET_FOR_TEST)
        evt = threading.Event()

        def _probe():
            evt.set()
            return True

        with mock.patch.object(np, "_gui_conn_check", side_effect=_probe):
            np._gui_net_watch(evt)
        self.assertIs(np._GUI_NET["ok"], True)
        self.assertGreater(np._GUI_NET["ts"], 0.0)


if __name__ == "__main__":
    unittest.main()
