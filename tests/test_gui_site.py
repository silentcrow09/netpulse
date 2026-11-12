# -*- coding: utf-8 -*-
"""GUI 现场检测 (v1.21.0): site start/finish 与终端 --site 同构。

验证点:
  P1 客户名必填 (空白 → False + 原因)
  P2 键集 = 全量 - port - iperf3, 且不含 tcpcc (与终端 --site 同口径)
  P3 诊断完成 → phase=site_ready (等机房勾选)
  P4 finalize: build_report 收到 site_check/meta_manual/site_note;
     四件套落盘 (brief_v2/full/json/pdf); PDF 走 _html_to_pdf
  P5 无 Chromium: 三件套照出, 无 PDF, 不报错
  P6 tested_at 空值 → 默认当前时间 (与终端「回车=默认当前」同口径)
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


def _seed_last_run(run):
    """模拟 run_diagnostics 的管线副作用。

    brief 笔误修正 (同 test_gui_session 约定): LAST_RUN 初值为 None,
    直接 .clear() 会 AttributeError。
    """
    if np.LAST_RUN is None:
        np.LAST_RUN = dict(run)
    else:
        np.LAST_RUN.clear()
        np.LAST_RUN.update(run)


class TestGuiSite(unittest.TestCase):

    # 记录最后一次 build_report kwargs (P4 断言用; 类级 dict, 在用例内
    # patch build_report 时直写, 不跨方法借用局部变量)
    _last_build = {}

    def setUp(self):
        np._GUI_RESET_FOR_TEST()
        type(self)._last_build.clear()

    def _run_site(self, s, customer="张伟·幸福小区3-502",
                  tested_at="2026-11-12 15:00"):
        captured = {}
        # 键集对齐 test_site_mode 种子 (P5 用例走真实 build_report, 需 app/
        # version/generated_at/system)
        run = {"app": "NetPulse", "version": "1.21.0",
               "generated_at": "2026-11-12 15:00",
               "status": {}, "results": {"gateway": {"x": 1}}, "evidence": {},
               "keys": ["gateway"], "system": {}, "duration_ms": 1,
               "total_modules": 1}
        def _rd(keys, **kw):
            captured["keys"] = list(keys)
            captured["install"] = kw.get("install")
            _seed_last_run(run)
            return run
        report = {"health": {"score": 95}}
        with mock.patch.object(np, "run_diagnostics", side_effect=_rd), \
             mock.patch.object(np, "_enrich_diagnosis_evidence",
                               side_effect=lambda d, r, e: d), \
             mock.patch.object(np, "diagnose",
                               side_effect=lambda r, rule_filter=None: type(
                                   "D", (), {"to_dict": lambda self: {}})()), \
             mock.patch.object(np, "build_report",
                               side_effect=lambda **kw: captured.update(kw)
                               or report):
            ok, err = s.start_site(customer, tested_at=tested_at,
                                   plan="300M")
            if ok:
                s._thread.join(timeout=5)
        return captured, report

    def test_customer_required(self):
        s = np._GuiSession()
        ok, err = s.start_site("   ")
        self.assertFalse(ok)
        self.assertTrue(err)

    def test_keys_match_terminal_site(self):
        s = np._GuiSession()
        captured, _ = self._run_site(s)
        expect = [k for k in np.all_module_keys()
                  if k not in ("port", "iperf3")]
        self.assertEqual(captured["keys"], expect)
        self.assertNotIn("tcpcc", captured["keys"])

    def test_site_ready_phase(self):
        s = np._GuiSession()
        self._run_site(s)
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "site_ready")
        self.assertEqual(snap["site"]["customer"], "张伟·幸福小区3-502")

    def test_tested_at_default_now(self):
        # 决议: 页面 datetime-local 可能为空, 空值默认当前时间 —
        # 与终端 run_site_visit 同口径 (回车 = %Y-%m-%d %H:%M)
        s = np._GuiSession()
        self._run_site(s, tested_at=None)
        ta = s.snapshot()["site"]["tested_at"]
        self.assertRegex(ta, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")

    def test_finalize_exports_four_files(self):
        s = np._GuiSession()
        tmp = tempfile.mkdtemp()
        written = []
        def _fake_export(path, rule_filter=None, report=None, layout="full"):
            written.append((os.path.basename(path), layout))
            return None
        def _fake_pdf(chrome, html, pdf, timeout=90):
            written.append((os.path.basename(pdf), "pdf"))
            return None
        _, report = self._run_site(s)
        with mock.patch.object(np, "_site_report_base",
                               return_value=os.path.join(tmp, "现场检测_测试")), \
             mock.patch.object(np, "export_report", side_effect=_fake_export), \
             mock.patch.object(np, "_find_pdf_browser",
                               return_value="C:/x/edge.exe"), \
             mock.patch.object(np, "_html_to_pdf", side_effect=_fake_pdf), \
             mock.patch.object(np, "build_report",
                               side_effect=lambda **kw:
                                   type(self)._last_build.update(kw)
                                   or report):
            ok, err = s.finalize_site(
                {"onu_led": "LOS 告警", "bogus_key": "x",
                 "power_ups": "不在选项里的值"},
                note="机房温度偏高")
            self.assertTrue(ok)
        names = [n for n, _ in written]
        self.assertIn("现场检测_测试.html", names)
        self.assertIn("现场检测_测试_完整版.html", names)
        self.assertIn("现场检测_测试.json", names)
        self.assertIn("现场检测_测试.pdf", names)
        layouts = dict(written)
        self.assertEqual(layouts["现场检测_测试.html"], "brief_v2")
        self.assertEqual(layouts["现场检测_测试_完整版.html"], "full")
        # 白名单: 脏 key / 脏值不进 site_check (build_report 内部 _normalize_site_check
        # 也会拦一层, 这里验证会话层不清洗但参数原样透传给它)
        self.assertIn("site_check", type(self)._last_build)
        self.assertEqual(type(self)._last_build["site_note"], "机房温度偏高")
        self.assertEqual(type(self)._last_build["meta_manual"]["customer"],
                         "张伟·幸福小区3-502")

    def test_finalize_without_chromium(self):
        s = np._GuiSession()
        tmp = tempfile.mkdtemp()
        self._run_site(s)
        with mock.patch.object(np, "_site_report_base",
                               return_value=os.path.join(tmp, "现场检测_测试")), \
             mock.patch.object(np, "export_report", return_value=None), \
             mock.patch.object(np, "_find_pdf_browser", return_value=None):
            ok, err = s.finalize_site({}, note="")
            self.assertTrue(ok)
            self.assertIsNone(err)
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "done")
        pdfs = [f for f in snap["files"] if f.endswith(".pdf")]
        self.assertEqual(pdfs, [])


if __name__ == "__main__":
    unittest.main()
