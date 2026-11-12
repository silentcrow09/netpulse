# -*- coding: utf-8 -*-
"""GUI 会话核心 (v1.21.0): 状态快照 / 单轮互斥 / 报告编排 / 导出。

全 mock, 不跑真实诊断, 不写真实桌面 (导出目录 mock 到 tmp)。
验证点:
  P1 snapshot 阶段迁移 idle→running→done, 计数正确
  P2 单轮互斥: running 时 start 返回 (False, 原因)
  P3 报告编排与 _run_scene 同构: diagnose(rule_filter) → build_report(rule_filter)
  P4 full 场景 rule_filter=None
  P5 export html/json 落盘 mock 目录, pdf 经 _html_to_pdf
  P6 诊断异常 → phase=error, snapshot.error 非空
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


def _fake_run(keys):
    """最小 run dict: 与 run_diagnostics 返回结构同键。"""
    return {"status": {k: "完成" for k in keys},
            "results": {k: {"fake": 1} for k in keys},
            "evidence": {}, "keys": list(keys),
            "system": {}, "duration_ms": 1, "total_modules": len(keys)}


class _Diag:
    """diagnosis 哨兵: .to_dict() 可调。"""
    def to_dict(self):
        return {"fake": True}


def _seed_last_run(run):
    """模拟 run_diagnostics 的管线副作用 (build_report 内部读 LAST_RUN)。

    brief 笔误修正: LAST_RUN 初值为 None, 直接 .clear() 会 AttributeError。
    """
    if np.LAST_RUN is None:
        np.LAST_RUN = dict(run)
    else:
        np.LAST_RUN.clear()
        np.LAST_RUN.update(run)


class TestGuiSession(unittest.TestCase):

    def setUp(self):
        np._GUI_RESET_FOR_TEST()      # 测试隔离: 清模块级单例/事件

    def _patch_pipeline(self, profile="slow", fail=False):
        keys = list(np.DIAGNOSE_PROFILES[profile])
        run = _fake_run(keys)
        report = {"health": {"score": 92}, "fake": True}
        def _rd(keys_, **kw):
            _seed_last_run(run)
            # brief 笔误修正: 原 `kw.get("progress_cb") and None` 是恒 None 的
            # 死语句; 按真实管线契约逐模块发 start/done 事件 (顺带覆盖 on_progress)
            cb = kw.get("progress_cb")
            if cb:
                for k in keys_:
                    cb({"event": "start", "key": k})
                    cb({"event": "done", "key": k, "status": "完成"})
            return run
        p = mock.patch.object(np, "run_diagnostics", side_effect=_rd)
        pd = mock.patch.object(np, "diagnose", return_value=_Diag())
        pb = mock.patch.object(np, "build_report",
                               side_effect=RuntimeError("boom") if fail
                               else lambda **kw: report)
        return keys, run, report, p, pd, pb

    def test_phase_transition_and_counts(self):
        keys, run, report, p, pd, pb = self._patch_pipeline()
        s = np._GuiSession()
        with p, pd, pb, \
             mock.patch.object(np, "_enrich_diagnosis_evidence",
                               side_effect=lambda d, r, e: d):
            ok, err = s.start("slow")
            self.assertTrue(ok)
            s._thread.join(timeout=5)
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "done")
        self.assertEqual(snap["total"], len(keys))
        self.assertEqual(snap["done"], len(keys))
        self.assertTrue(snap["has_report"])

    def test_busy_reject(self):
        keys, run, report, p, pd, pb = self._patch_pipeline()
        s = np._GuiSession()
        def _slow_rd(keys_, **kw):
            import time as _t
            _t.sleep(0.4)
            return run
        p2 = mock.patch.object(np, "run_diagnostics", side_effect=_slow_rd)
        with p2, pd, pb:
            ok, _ = s.start("slow")
            self.assertTrue(ok)
            ok2, err2 = s.start("web")
            self.assertFalse(ok2)
            self.assertTrue(err2)
            s._thread.join(timeout=5)

    def test_report_pipeline_same_as_scene(self):
        captured = {}
        keys, run, report, p, pd, pb = self._patch_pipeline()
        def _cap_diag(results, rule_filter=None):
            captured["rule_filter"] = rule_filter
            return _Diag()
        def _cap_build(**kw):
            captured["build"] = kw
            return report
        s = np._GuiSession()
        with p, mock.patch.object(np, "diagnose", side_effect=_cap_diag), \
             mock.patch.object(np, "build_report", side_effect=_cap_build), \
             mock.patch.object(np, "_enrich_diagnosis_evidence",
                               side_effect=lambda d, r, e: d):
            s.start("gaming")
            s._thread.join(timeout=5)
        self.assertEqual(captured["rule_filter"], "gaming")
        self.assertEqual(captured["build"]["rule_filter"], "gaming")
        self.assertIn("diagnosis", captured["build"])

    def test_full_no_rule_filter(self):
        captured = {}
        run = _fake_run(list(np.full_module_keys()))
        report = {"health": {"score": 100}}
        def _rd(keys_, **kw):
            _seed_last_run(run)
            return run
        s = np._GuiSession()
        with mock.patch.object(np, "run_diagnostics", side_effect=_rd), \
             mock.patch.object(np, "diagnose", side_effect=lambda r, rule_filter=None: _Diag()), \
             mock.patch.object(np, "build_report", side_effect=lambda **kw: captured.update(kw) or report), \
             mock.patch.object(np, "_enrich_diagnosis_evidence", side_effect=lambda d, r, e: d):
            s.start("full")
            s._thread.join(timeout=5)
        self.assertIsNone(captured["rule_filter"])

    def test_export_files(self):
        keys, run, report, p, pd, pb = self._patch_pipeline()
        tmp = tempfile.mkdtemp()
        written = []
        def _fake_export(path, rule_filter=None, report=None, layout="full"):
            written.append(path)
            return None
        def _fake_pdf(chrome, html, pdf, timeout=90):
            written.append(pdf)
            return None
        s = np._GuiSession()
        with p, pd, pb, \
             mock.patch.object(np, "_enrich_diagnosis_evidence", side_effect=lambda d, r, e: d), \
             mock.patch.object(np, "_desktop_netpulse_dir", return_value=tmp), \
             mock.patch.object(np, "export_report", side_effect=_fake_export), \
             mock.patch.object(np, "_find_pdf_browser", return_value="C:/x/chrome.exe"), \
             mock.patch.object(np, "_html_to_pdf", side_effect=_fake_pdf):
            s.start("slow"); s._thread.join(timeout=5)
            p1, e1 = s.export("html")
            p2, e2 = s.export("json")
            p3, e3 = s.export("pdf")
            self.assertIsNone(e1); self.assertIsNone(e2); self.assertIsNone(e3)
        self.assertTrue(p1.startswith(tmp))
        self.assertTrue(p2.endswith(".json"))
        self.assertTrue(p3.endswith(".pdf"))
        # brief 笔误修正: 原断言要求 p1/p3 文件名全同, 但 export 每次调用各自
        # 取当前时间戳 (秒级), 跨秒边界必假失败; 改比「同名规则」= 标题段一致
        self.assertEqual(os.path.basename(p1).split("_", 2)[-1],
                         os.path.basename(p3).replace(".pdf", ".html").split("_", 2)[-1])

    def test_error_phase(self):
        keys, run, report, p, pd, pb = self._patch_pipeline(fail=True)
        s = np._GuiSession()
        with p, pd, pb, \
             mock.patch.object(np, "_enrich_diagnosis_evidence", side_effect=lambda d, r, e: d):
            s.start("slow"); s._thread.join(timeout=5)
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "error")
        self.assertTrue(snap["error"])


if __name__ == "__main__":
    unittest.main()
