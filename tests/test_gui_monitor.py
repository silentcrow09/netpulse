# -*- coding: utf-8 -*-
"""GUI 盯障会话 (v1.22.0): _GuiMonitor 会话层 / 节流载荷 / 编排 / 跨类型互斥。

全 mock (MonitorSession 工厂替身 + save_monitor_report 落盘替身), 不跑真实
ping, 不写真实报告目录。
验证点:
  P1 时长钳位: 0→30 / 2000*60→86400 / 合法值原样; 构造参数透传 (load URL)
  P2 编排: start→stop→join → phase=done, early=True,
     build_result(early_terminated=True) 被调; 落盘 None → phase=error;
     session.start 失败 → 回滚 idle + 补 stop 清孤儿
  P3 progress ≥2s / curve ≥5s 节流; counters 键齐全且可观测
  P4 曲线: 窗口过滤 (只留最近 600s) + 降采样 ≤200/流 + 丢包点 ms=None 保留
  P5 事件预览: 连续 3 丢包 → outage ≥1; 独立 ≥5s 节流 (progress 重算不带重算)
  P6 互斥: session running → monitor.start 拒; monitor running → session 拒;
     同类 running → 二次 start 拒
  P7 report_html: 文件存在 → bytes; 文件被删/无报告 → None
  P8 编排落盘后 progress_payload 带报告页结论块 (verdict/conclusion/advice/
     early/files + targets/error 元信息); running 期不含 verdict
"""
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np

SAVE_PATHS = ("/tmp/np_test/monitor_x.html", "/tmp/np_test/monitor_x.json")


class TestGuiMonitor(unittest.TestCase):

    def setUp(self):
        np._GUI_RESET_FOR_TEST()      # 测试隔离: 清模块级单例/事件

    # -- 替身 --

    def _fake_session(self, dur=60):
        """MonitorSession 实例替身: 可控 snapshot/stop/build_result。

        brief 骨架笔误修正: 补 start.return_value=True 显式声明成功语义
        (骨架靠 Mock 默认真值侥幸通过), 失败用例单独覆写为 False。
        """
        s = mock.Mock()
        s.duration_s = dur
        s.snapshot.return_value = {"gw_stream": [], "ext_stream": [],
                                   "tcp": [], "dns": []}
        s.build_result.return_value = {"verdict": "stable"}
        s.start.return_value = True
        return s

    def _patch_ms(self, fake, save_result=SAVE_PATHS):
        """替身三件套: (构造参数记录器, MonitorSession patcher, save patcher)。

        brief 骨架笔误修正 (两处):
        1. MonitorSession 类替身必须带真实类常量 — _detect_monitor_events
           等共用件按 MonitorSession.GAP_S 引用, 若替身缺常量, 事件预览
           会静默异常置空计数; 工厂函数复制真实类全部大写属性。
        2. 骨架的 mock.patch.object(..., return_value=fake) 做不到上面这点
           (MagicMock 属性是自动生成的假值), 也无法断言 load_url 透传。
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
        p_save = mock.patch.object(np, "save_monitor_report",
                                   mock.Mock(return_value=save_result))
        return rec, p_ms, p_save

    # -- P1 时长钳位 --

    def test_duration_clamp(self):
        for req, expect in ((0, 30), (2000 * 60, 86400), (600, 600), (45, 45)):
            m = np._GuiMonitor()
            fake = self._fake_session()
            rec, p_ms, p_save = self._patch_ms(fake)
            with p_ms, p_save:
                ok, err, eff = m.start(req)
                self.assertTrue(ok, err)
                self.assertIsNone(err)
                self.assertEqual(eff, expect)
                self.assertEqual(rec["args"][0], expect)   # 构造收到钳位值
                m.stop()
                m._thread.join(timeout=5)

    def test_ctor_args_passthrough(self):
        m = np._GuiMonitor()
        fake = self._fake_session()
        rec, p_ms, p_save = self._patch_ms(fake)
        with p_ms, p_save:
            ok, err, _ = m.start(600, ext_target="1.2.3.4", load=True)
            self.assertTrue(ok, err)
            self.assertEqual(rec["args"], (600, "1.2.3.4"))
            self.assertEqual(rec["kw"], {"load_url":
                                         np.MonitorSession.MONITOR_LOAD_URL})
            m.stop()
            m._thread.join(timeout=5)
        m2 = np._GuiMonitor()
        rec2, p_ms2, p_save2 = self._patch_ms(self._fake_session())
        with p_ms2, p_save2:
            ok2, _, _ = m2.start(600)          # 默认: 无外网目标 / 无负载
            self.assertTrue(ok2)
            self.assertEqual(rec2["args"], (600, None))
            self.assertEqual(rec2["kw"], {"load_url": None})
            m2.stop()
            m2._thread.join(timeout=5)

    def test_duration_invalid(self):
        m = np._GuiMonitor()
        fake = self._fake_session()
        rec, p_ms, p_save = self._patch_ms(fake)
        with p_ms, p_save:
            ok, err, eff = m.start("abc")
        self.assertFalse(ok)
        self.assertTrue(err)
        self.assertIsNone(eff)
        self.assertNotIn("args", rec)          # MonitorSession 未构造

    # -- P2 编排 --

    def test_orchestration_early_stop_done(self):
        m = np._GuiMonitor()
        fake = self._fake_session()
        rec, p_ms, p_save = self._patch_ms(fake)
        with p_ms, p_save:
            ok, err, eff = m.start(600)
            self.assertEqual((ok, err, eff), (True, None, 600))
            self.assertTrue(m.is_running())
            self.assertEqual(m.snapshot()["phase"], "running")
            m.stop()
            m.stop()               # 幂等: 二次 stop 不炸
            m._thread.join(timeout=5)
        self.assertFalse(m.is_running())
        fake.build_result.assert_called_once_with(early_terminated=True)
        self.assertTrue(fake.stop.called)          # 采集已停
        snap = m.snapshot()
        for k in ("phase", "effective_s", "elapsed_s", "stop_requested",
                  "early", "has_report", "report_paths", "site"):
            self.assertIn(k, snap)
        self.assertEqual(snap["phase"], "done")
        self.assertTrue(snap["early"])
        self.assertTrue(snap["stop_requested"])
        self.assertTrue(snap["has_report"])
        self.assertEqual(snap["report_paths"],
                         {"html": SAVE_PATHS[0], "json": SAVE_PATHS[1]})
        self.assertEqual(snap["effective_s"], 600)

    def test_save_failure_to_error(self):
        m = np._GuiMonitor()
        fake = self._fake_session()
        rec, p_ms, p_save = self._patch_ms(fake, save_result=None)
        with p_ms, p_save:
            m.start(600)
            m.stop()
            m._thread.join(timeout=5)
        snap = m.snapshot()
        self.assertEqual(snap["phase"], "error")
        self.assertTrue(snap["error"])
        self.assertIsNone(snap["report_paths"])
        self.assertIsNone(m.report_html())         # 无报告 → None

    def test_session_start_failure_rollback(self):
        m = np._GuiMonitor()
        fake = self._fake_session()
        fake.start.return_value = False
        save_mock = mock.Mock(return_value=SAVE_PATHS)
        rec, p_ms, _ = self._patch_ms(fake)
        with p_ms, mock.patch.object(np, "save_monitor_report", save_mock):
            ok, err, eff = m.start(600)
        self.assertFalse(ok)
        self.assertIn("ping", err)
        self.assertIsNone(eff)
        self.assertFalse(m.is_running())
        self.assertEqual(m.snapshot()["phase"], "idle")   # 回滚
        self.assertTrue(fake.stop.called)                 # 孤儿 ping 清理
        self.assertFalse(save_mock.called)                # 不会走到落盘

    # -- P3 节流 --

    def test_progress_and_curve_throttle(self):
        m = np._GuiMonitor()
        fake = self._fake_session()
        rec, p_ms, p_save = self._patch_ms(fake)
        with p_ms, p_save:
            m.start(600)
            p1 = m.progress_payload()
            p2 = m.progress_payload()          # 1s 内 → 缓存命中
            self.assertEqual(p2["counters"]["polls"], 2)
            self.assertEqual(p2["counters"]["progress_computes"], 1)
            for k in ("polls", "progress_computes", "curve_computes",
                      "event_computes"):
                self.assertIn(k, p1["counters"])
            for k in ("phase", "elapsed_s", "duration_s", "connect",
                      "loss_pct", "events_preview", "load"):
                self.assertIn(k, p1)
            for k in ("gw", "ext"):
                self.assertIn(k, p1["connect"])
                self.assertIn(k, p1["loss_pct"])
                self.assertEqual(sorted(p1["connect"][k]), ["loss10", "ok"])
            self.assertIn("dns_ok", p1["connect"])
            self.assertIn("tcp_ok", p1["connect"])
            # 终审 #4: 无样本 → None (前端显示等待灰), 不再 False 误判红
            self.assertIsNone(p1["connect"]["dns_ok"])
            self.assertIsNone(p1["connect"]["tcp_ok"])
            for k in ("outage", "dns_fail", "jitter_burst", "latency_spike"):
                self.assertIn(k, p1["events_preview"])
            self.assertFalse(p1["load"])
            # curve ≥5s 节流: 两次调用只重算一次 (counters 每次
            # progress 调用都取现值, 经它观测)
            m.curve_payload()
            m.curve_payload()
            p3 = m.progress_payload()          # 2s 内 → progress 缓存命中
            self.assertEqual(p3["counters"]["curve_computes"], 1)
            self.assertEqual(p3["counters"]["progress_computes"], 1)
            m.stop()
            m._thread.join(timeout=5)

    # -- P4 曲线 --

    def test_curve_window_and_downsample(self):
        now = time.time()
        gw = [("ok", now - i * 2, 10.0) for i in range(320)]      # 跨 638s
        gw += [("loss", now - 100 + j, None) for j in range(5)]   # 窗口内丢包
        gw.sort(key=lambda s: s[1])
        ext = [("ok", now - i, 20.0) for i in range(250)]
        m = np._GuiMonitor()
        fake = self._fake_session()
        fake.snapshot.return_value = {"gw_stream": gw, "ext_stream": ext,
                                      "tcp": [], "dns": []}
        rec, p_ms, p_save = self._patch_ms(fake)
        with p_ms, p_save:
            m.start(600)
            cu = m.curve_payload()
            m.stop()
            m._thread.join(timeout=5)
        self.assertEqual(cu["window_s"], 600)
        self.assertLessEqual(len(cu["gw"]), 200)
        self.assertLessEqual(len(cu["ext"]), 200)
        # 窗口过滤: 只留最近 600s (横轴为窗口内相对位置 0..600)
        for key in ("gw", "ext"):
            for x, _v in cu[key]:
                self.assertGreaterEqual(x, 0)
                self.assertLessEqual(x, 600)
        # 降采样不得抹平丢包: 丢包点以 ms=None 保留 (前端画红点)
        self.assertTrue(any(v is None for _x, v in cu["gw"]))
        # 纯 ok 桶取均值: 全 20ms 的流降采样后数值不变
        self.assertTrue(all(v == 20.0 for _x, v in cu["ext"]))

    # -- P5 事件预览 --

    def test_events_preview_and_throttle(self):
        now = time.time()
        gw = [("ok", now - 40 + i, 5.0) for i in range(30)]    # -40..-11s
        gw += [("loss", now - 10, None), ("loss", now - 9, None),
               ("loss", now - 8, None)]                        # 连续 3 丢包
        gw += [("ok", now - 7 + i, 5.0) for i in range(8)]     # -7..0s
        ext = [("ok", now - 30 + i, 12.0) for i in range(31)]
        m = np._GuiMonitor()
        fake = self._fake_session()
        fake.snapshot.return_value = {"gw_stream": gw, "ext_stream": ext,
                                      "tcp": [], "dns": []}
        rec, p_ms, p_save = self._patch_ms(fake)
        with p_ms, p_save:
            m.start(600)
            p1 = m.progress_payload()
            self.assertGreaterEqual(p1["events_preview"]["outage"], 1)
            first_evt = p1["counters"]["event_computes"]
            self.assertEqual(first_evt, 1)
            # 强制 progress 过期 (回拨其时间戳), event 缓存保持新鲜:
            # progress 重算而事件预览不重算 → 独立节流通道
            with m._lock:
                m._ts_prog = 0.0
            p2 = m.progress_payload()
            m.stop()
            m._thread.join(timeout=5)
        self.assertEqual(p2["counters"]["progress_computes"],
                         first_evt + 1)            # progress 确实重算了
        self.assertEqual(p2["counters"]["event_computes"], first_evt)
        self.assertGreaterEqual(p2["events_preview"]["outage"], 1)

    # -- P6 互斥 --

    def test_busy_session_rejects_monitor(self):
        s = np._GuiSession()
        ok, err = s._begin("slow", ["dns"])    # 不起线程, 只置 running
        self.assertTrue(ok, err)
        np._GuiHandler.session = s
        self.assertTrue(np._gui_net_busy())
        m = np._GuiMonitor()
        np._GuiHandler.monitor = m
        fake = self._fake_session()
        rec, p_ms, p_save = self._patch_ms(fake)
        with p_ms, p_save:
            ok2, err2, eff2 = m.start(600)
        self.assertFalse(ok2)
        self.assertIn("网络活动", err2)
        self.assertIsNone(eff2)
        self.assertNotIn("args", rec)          # MonitorSession 未构造
        self.assertEqual(m.snapshot()["phase"], "idle")

    def test_busy_monitor_rejects_session(self):
        m = np._GuiMonitor()
        np._GuiHandler.monitor = m
        fake = self._fake_session()
        rec, p_ms, p_save = self._patch_ms(fake)
        s = np._GuiSession()
        # 互斥防线万一失效, 诊断也不能真跑: guard 替身直接炸
        guard = mock.Mock(side_effect=RuntimeError("互斥失效: 诊断真的跑起来了"))
        with p_ms, p_save, \
                mock.patch.object(np, "run_diagnostics", guard):
            ok, err, _ = m.start(600)
            self.assertTrue(ok, err)
            self.assertTrue(np._gui_net_busy())
            ok2, err2 = s.start("slow")
        self.assertFalse(ok2)
        self.assertIn("网络活动", err2)
        self.assertEqual(s.snapshot()["phase"], "idle")
        self.assertFalse(guard.called)
        m.stop()
        m._thread.join(timeout=5)
        self.assertFalse(np._gui_net_busy())

    def test_monitor_single_running_mutex(self):
        m = np._GuiMonitor()
        fake = self._fake_session()
        rec, p_ms, p_save = self._patch_ms(fake)
        with p_ms, p_save:
            ok, _, _ = m.start(600)
            ok2, err2, eff2 = m.start(600)     # 同类 running → 拒
            m.stop()
            m._thread.join(timeout=5)
        self.assertTrue(ok)
        self.assertFalse(ok2)
        self.assertIn("盯障", err2)
        self.assertIsNone(eff2)

    # -- P7 report_html --

    def test_report_html_bytes(self):
        tmp = tempfile.mkdtemp()
        try:
            hp = os.path.join(tmp, "monitor_x.html")
            with open(hp, "wb") as f:
                f.write("<html><body>盯障报告</body></html>".encode("utf-8"))
            m = np._GuiMonitor()
            with m._lock:
                m._paths = {"html": hp, "json": hp}   # 直填私有态 (落盘路径已在 P2 验证)
            data = m.report_html()
            self.assertIsInstance(data, bytes)
            self.assertIn("盯障报告".encode("utf-8"), data)
            os.remove(hp)
            self.assertIsNone(m.report_html())        # 文件被删 → None
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertIsNone(np._GuiMonitor().report_html())   # 无报告 → None

    # -- P8 编排落盘后的结论块 (Task 3 报告页数据源) --

    def test_progress_payload_outcome_after_done(self):
        # 落盘完成后 progress_payload 必须带报告页结论条所需字段:
        # verdict/conclusion/advice/early/files; running 期不下发 verdict
        # (报告尚未生成, 前端不得提前渲染结论)。
        m = np._GuiMonitor()
        fake = self._fake_session()
        fake.build_result.return_value = {
            "verdict": "degraded", "conclusion_text": "外网抖动两段",
            "advice": "查光猫光衰"}
        rec, p_ms, p_save = self._patch_ms(fake)
        with p_ms, p_save:
            ok, err, _ = m.start(600, ext_target="1.2.3.4")
            self.assertTrue(ok, err)
            running_payload = m.progress_payload()
            self.assertNotIn("verdict", running_payload)
            m.stop()
            m._thread.join(timeout=5)
        self.assertEqual(m.snapshot()["phase"], "done")
        # 载荷 ≥2s 节流: 回拨时间戳强制重算 (同 P5 手法), 立即读到 done 态
        with m._lock:
            m._ts_prog = 0.0
        d = m.progress_payload()
        self.assertEqual(d["phase"], "done")
        self.assertEqual(d["verdict"], "degraded")
        self.assertEqual(d["conclusion"], "外网抖动两段")
        self.assertEqual(d["advice"], "查光猫光衰")
        self.assertTrue(d["early"])
        self.assertTrue(d["error"] is None)
        # targets 元信息: 外网目标透传, 网关键存在 (替身会话未置 _gw_ip → None)
        self.assertEqual(d["targets"]["ext"], "1.2.3.4")
        self.assertIn("gw", d["targets"])
        # files: 由 html 落盘名推三件套同名清单 (csv/json/html)
        self.assertEqual(d["files"],
                         ["monitor_x.csv", "monitor_x.json",
                          "monitor_x.html"])


if __name__ == "__main__":
    unittest.main()
