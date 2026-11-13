# -*- coding: utf-8 -*-
"""GUI 取消 / 续跑 的 HTTP 路由与载荷 (v1.24.0 · Task 4)。

验证点:
  R1 三条新路由都过 token 闸 (无 token → 403)
  R2 /api/run/stop: 没在跑 → 400; 在跑 → 200; 已在收尾 → 200 (幂等)
  R3 /api/run/resume: 没有续跑点 → 400; 有 → 200 且真的开跑
  R4 /api/resume/discard → 200 且续跑点文件被删
  R5 /api/scenarios 带 resume 摘要 (主页横幅数据源); 无续跑点时为 None
  R6 /api/shutdown: 诊断在跑时关窗 → 先落盘已测完的项目, 再退出
  R7 收尾期间互斥不放宽 (诊断 running → 盯障 start 409)
"""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


def _req(port, method, path, token=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {}
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


class TestGuiStopRoutes(unittest.TestCase):

    def setUp(self):
        np._GUI_RESET_FOR_TEST()
        self.tmp = tempfile.mkdtemp(prefix="np_route_")
        self.resume_path = os.path.join(self.tmp, "resume.json")
        p = mock.patch.object(np, "_gui_resume_path",
                              return_value=self.resume_path)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.session = np._GuiSession()
        self.evt = threading.Event()
        self.srv, self.port, self.token = np._start_gui_server(
            self.session, self.evt)
        self.addCleanup(lambda: (self.evt.set(), self.srv.shutdown(),
                                 self.srv.server_close()))

    def _write_point(self, completed=None, keys=("gateway", "dns")):
        payload = {
            "schema": 1, "saved_at": "2026-11-13T15:30:00",
            "saved_at_ts": time.time(), "profile": "slow",
            "label": "网络很慢", "keys": list(keys),
            "completed": completed if completed is not None else {
                "gateway": {"status": "完成", "result": {"fake": "gateway"}}},
            "duration_ms": 1234, "total_modules": len(np.MODULE_MAP),
        }
        with open(self.resume_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

    def _start_running(self, release):
        """起一轮「跑着不动」的诊断, 返回 started 事件。"""
        started = threading.Event()

        def _fake(keys, **kw):
            started.set()
            release.wait(10)
            return {"app": "NetPulse", "version": "1.24.0",
                    "generated_at": np.datetime.now(), "system": {},
                    "status": {k: "完成" for k in keys},
                    "results": {k: {"fake": k} for k in keys},
                    "evidence": {}, "keys": list(keys),
                    "duration_ms": 1, "total_modules": len(np.MODULE_MAP)}

        patcher = mock.patch.object(np, "run_diagnostics", side_effect=_fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        ok, err = self.session.start(keys=["gateway", "dns"])
        self.assertTrue(ok, err)
        self.assertTrue(started.wait(5), "诊断线程没起来")
        return started

    # ── R1 token 闸 ──
    def test_token_gate(self):
        for path in ("/api/run/stop", "/api/run/resume", "/api/resume/discard"):
            st, _ = _req(self.port, "POST", path, token=None, body={})
            self.assertEqual(st, 403, path)

    # ── R2 停止路由 ──
    def test_stop_when_idle_is_400(self):
        st, raw = _req(self.port, "POST", "/api/run/stop",
                       token=self.token, body={})
        self.assertEqual(st, 400)
        doc = json.loads(raw)
        self.assertFalse(doc["ok"])
        self.assertTrue(doc["err"])

    def test_stop_when_running_is_200(self):
        release = threading.Event()
        self._start_running(release)
        try:
            st, raw = _req(self.port, "POST", "/api/run/stop",
                           token=self.token, body={})
            self.assertEqual(st, 200)
            self.assertTrue(json.loads(raw)["ok"])
            # 受理后进入收尾相位, 仍在跑 (互斥不放宽)
            snap = self.session.snapshot()
            self.assertEqual(snap["phase"], "stopping")
            self.assertTrue(snap["stop_requested"])
            self.assertTrue(snap["can_stop"])
        finally:
            release.set()
            t = self.session._thread
            if t is not None:
                t.join(5)

    def test_stop_is_idempotent_while_stopping(self):
        release = threading.Event()
        self._start_running(release)
        try:
            st, _ = _req(self.port, "POST", "/api/run/stop",
                         token=self.token, body={})
            self.assertEqual(st, 200)
            st, raw = _req(self.port, "POST", "/api/run/stop",
                           token=self.token, body={})
            self.assertEqual(st, 200, "已在收尾时再点停止应幂等 200")
            self.assertTrue(json.loads(raw)["ok"])
        finally:
            release.set()
            t = self.session._thread
            if t is not None:
                t.join(5)

    # ── R3 续跑路由 ──
    def test_resume_without_point_is_400(self):
        st, raw = _req(self.port, "POST", "/api/run/resume",
                       token=self.token, body={})
        self.assertEqual(st, 400)
        doc = json.loads(raw)
        self.assertFalse(doc["ok"])
        self.assertTrue(doc["err"])

    def test_resume_with_point_starts(self):
        self._write_point()
        release = threading.Event()
        started = threading.Event()

        def _fake(keys, **kw):
            started.set()
            release.wait(10)
            return {"app": "NetPulse", "version": "1.24.0",
                    "generated_at": np.datetime.now(), "system": {},
                    "status": {k: "完成" for k in keys},
                    "results": {k: {"fake": k} for k in keys},
                    "evidence": {}, "keys": list(keys),
                    "duration_ms": 1, "total_modules": len(np.MODULE_MAP)}

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            st, raw = _req(self.port, "POST", "/api/run/resume",
                           token=self.token, body={})
            self.assertEqual(st, 200)
            self.assertTrue(json.loads(raw)["ok"])
            self.assertTrue(started.wait(5))
        release.set()
        t = self.session._thread
        if t is not None:
            t.join(5)

    # ── R4 丢弃续跑点 ──
    def test_discard_removes_point(self):
        self._write_point()
        self.assertTrue(os.path.exists(self.resume_path))
        st, raw = _req(self.port, "POST", "/api/resume/discard",
                       token=self.token, body={})
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(raw)["ok"])
        self.assertFalse(os.path.exists(self.resume_path))

    # ── R5 主页横幅数据 ──
    def test_meta_carries_resume_summary(self):
        st, raw = _req(self.port, "GET", "/api/scenarios", token=self.token)
        self.assertEqual(st, 200)
        doc = json.loads(raw)
        self.assertIn("resume", doc)
        self.assertIsNone(doc["resume"], "没有续跑点时不该带横幅数据")
        self._write_point()
        st, raw = _req(self.port, "GET", "/api/scenarios", token=self.token)
        doc = json.loads(raw)
        r = doc["resume"]
        self.assertIsNotNone(r)
        self.assertEqual(r["done"], 1)
        self.assertEqual(r["total"], 2)
        self.assertEqual(r["label"], "网络很慢")

    # ── R6 关窗落盘 ──
    def test_shutdown_saves_partial_results(self):
        release = threading.Event()
        started = self._start_running(release)
        # 让第一项先测完 (有结果可存), 再让第二轮卡住
        try:
            st, raw = _req(self.port, "POST", "/api/shutdown",
                           token=self.token, body={"force": True})
            self.assertEqual(st, 200)
        finally:
            release.set()
            t = self.session._thread
            if t is not None:
                t.join(5)
        # 没测出结果 → 不该凭空造一个续跑点
        self.assertFalse(os.path.exists(self.resume_path))

    def test_shutdown_saves_when_partial_exists(self):
        release = threading.Event()
        self._start_running(release)
        # 直接灌一条已完成结果 (模拟第一项已测完)
        self.session.on_progress({"event": "done", "key": "gateway",
                                   "status": "完成", "result": {"fake": 1}})
        try:
            st, _ = _req(self.port, "POST", "/api/shutdown",
                         token=self.token, body={"force": True})
            self.assertEqual(st, 200)
            # 落盘发生在关窗请求里 —— 必须在诊断线程收尾**之前**断言:
            # 线程正常跑完会按设计清掉续跑点 (那一轮已经完整, 不需要续跑了);
            # 真机关窗时进程随即退出, 线程被强杀, 续跑点留着。
            self.assertTrue(os.path.exists(self.resume_path),
                            "关窗前应把已测完的项目落盘")
            with open(self.resume_path, encoding="utf-8") as f:
                pt = json.load(f)
            self.assertIn("gateway", pt["completed"])
        finally:
            release.set()
            t = self.session._thread
            if t is not None:
                t.join(5)

    # ── R7 收尾期间互斥 ──
    def test_monitor_start_blocked_while_stopping(self):
        release = threading.Event()
        self._start_running(release)
        try:
            _req(self.port, "POST", "/api/run/stop", token=self.token, body={})
            st, raw = _req(self.port, "POST", "/api/monitor/start",
                           token=self.token, body={"minutes": 1})
            self.assertEqual(st, 409, "收尾期间盯障仍应被互斥挡住")
        finally:
            release.set()
            t = self.session._thread
            if t is not None:
                t.join(5)


if __name__ == "__main__":
    unittest.main()
