# -*- coding: utf-8 -*-
"""GUI HTTP 服务 (v1.21.0): token 闸 / API 契约 / 关停。

全部本机回环 + 随机端口, 管线全 mock, 不跑真实诊断。
验证点:
  P1 无 token → 403; 带 token → 200 (页面与 API)
  P2 /api/scenarios 场景集与 DIAGNOSE_PROFILES 一致, status_colors 来自 STATUS_COLORS
  P3 POST /api/run 启动成功; busy 时 409
  P4 GET /api/report 无报告 404, 有报告返回 HTML
  P5 POST /api/shutdown 触发事件
"""
import json
import os
import sys
import http.client
import threading
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

    def test_scenarios_payload(self):
        st, raw = _req(self.port, "GET", "/api/scenarios?t=" + self.token)
        self.assertEqual(st, 200)
        meta = json.loads(raw)
        ids = {s["id"] for s in meta["scenarios"]}
        self.assertEqual(ids - {"site"}, set(np.DIAGNOSE_PROFILES))
        self.assertIn("site", ids)
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

    def test_run_conflict_409(self):
        self.session._phase = "running"     # 直接摆成忙
        st, raw = _req(self.port, "POST", "/api/run?t=" + self.token,
                       body={"profile": "slow"})
        self.assertEqual(st, 409)


if __name__ == "__main__":
    unittest.main()
