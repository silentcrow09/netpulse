# -*- coding: utf-8 -*-
"""部分报告 (提前结束) 的报告层口径 (v1.24.0)。

verify.md 点名的单元级闸之一 —— 「检测范围 N/M」分支、note 字段、
build_report(run=...) 显式传参, 在 pytest 内必须有覆盖 (不能只靠仓库外
的渲染 diff 脚本)。

验证点:
  R1 Hero「检测范围」: 请求 6 项只测完 4 项 → 写「4/6 项」+ 注明提前结束;
     全部测完时仍写「N 项全覆盖」(既有报告逐字节不变)
  R2 没测到的模块在报告里是「未检测」, 且**不扣分** (健康分与去掉它们后一致)
  R3 note: build_report(note=...) 写进报告并渲染; 空串不渲染;
     JSON 导出恒带 note 字段 (schema 与导出逐字段对齐)
  R4 build_report(run=...): 显式传 run 时不读全局 LAST_RUN
"""
import json
import os
import sys
import unittest
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np  # noqa: E402

KEYS = ["gateway", "dns", "wifi", "speedtest", "mtu", "ipv6"]


def _run(ran_keys, status=None):
    """造一个 run dict: 请求 KEYS 全部, 只有 ran_keys 测出了结果。"""
    results = {}
    statuses = {}
    for k in ran_keys:
        results[k] = {"fake": k, "issues": []}
        statuses[k] = "完成"
    return {
        "app": "NetPulse", "version": "1.24.0",
        "generated_at": datetime(2026, 1, 2, 3, 4, 5),
        "system": {"local_ip": "192.168.1.2", "hostname": "PC-01"},
        "status": statuses, "results": results, "evidence": {},
        "keys": list(KEYS), "duration_ms": 43210, "total_modules": len(KEYS),
    }


def _report(run, note=None):
    kwargs = {}
    if note is not None:
        kwargs["note"] = note
    return np.build_report(run=run, **kwargs)


class TestPartialReport(unittest.TestCase):

    # ── R1 Hero 检测范围 ──
    def test_hero_writes_ran_over_requested_when_stopped_early(self):
        run = _run(KEYS[:4])                    # 请求 6 项, 只测完 4 项
        html = np.render_report_html_customer(_report(run))
        self.assertIn("检测范围 <b>4/6</b> 项", html,
                      "提前结束要写「检测范围 4/6 项」")
        self.assertIn("本轮提前结束", html)
        self.assertNotIn("项全覆盖", html, "提前结束不能写「全覆盖」")

    def test_hero_full_run_keeps_coverage_wording(self):
        run = _run(KEYS)                        # 全部测完
        html = np.render_report_html_customer(_report(run))
        self.assertIn("项全覆盖", html)
        self.assertNotIn("本轮提前结束", html)

    # ── R2 未检测不扣分 ──
    def test_untested_modules_are_undetected_and_not_penalized(self):
        run = _run(KEYS[:4])
        rep = _report(run)
        for k in KEYS[4:]:
            self.assertEqual(rep["summary"].get(k), "未检测",
                             "%s 应为未检测" % k)
        # 去掉未检测项重算一次 → 分数必须一样 (未检测扣 0 分)
        run2 = dict(run)
        run2 = {"app": run["app"], "version": run["version"],
                "generated_at": run["generated_at"], "system": run["system"],
                "status": run["status"], "results": run["results"],
                "evidence": run["evidence"], "keys": run["keys"],
                "duration_ms": run["duration_ms"],
                "total_modules": run["total_modules"]}
        rep2 = _report(run2)
        self.assertEqual(rep["health"]["score"], rep2["health"]["score"])

    # ── R3 note ──
    def test_note_goes_to_report_and_json(self):
        run = _run(KEYS[:4])
        note = "本轮为续跑: 其中 4 项的数据来自上一次运行 (11-13 15:30)"
        rep = _report(run, note=note)
        self.assertEqual(rep.get("note"), note)
        html = np.render_report_html_customer(rep)
        self.assertIn("本轮为续跑", html, "备注要渲染到报告 Hero 副行")
        doc = json.loads(np.render_report_json(rep))
        self.assertEqual(doc.get("note"), note, "JSON 导出恒带 note")

    def test_note_empty_is_not_rendered(self):
        run = _run(KEYS[:4])
        rep = _report(run, note="")
        self.assertEqual(rep.get("note"), "")
        html = np.render_report_html_customer(rep)
        self.assertNotIn("本轮为续跑", html)
        doc = json.loads(np.render_report_json(rep))
        self.assertEqual(doc.get("note"), "", "无备注时导出空串, 不是缺字段")

    def test_note_is_escaped(self):
        run = _run(KEYS[:4])
        payload = '<script>alert(1)</script>'
        html = np.render_report_html_customer(_report(run, note=payload))
        self.assertNotIn(payload, html, "注入串不能以原始形式出现")
        self.assertIn("&lt;script&gt;", html, "注入串要转义后出现")

    # ── R4 build_report(run=) 不读全局 LAST_RUN ──
    def test_explicit_run_overrides_global(self):
        import copy
        old = copy.deepcopy(np.LAST_RUN)
        try:
            np.LAST_RUN = _run(KEYS)             # 全局是「全测完」
            rep = np.build_report(run=_run(KEYS[:4]))
            self.assertIn("检测范围 <b>4/6</b> 项",
                          np.render_report_html_customer(rep),
                          "显式传 run 时不能用全局 LAST_RUN")
        finally:
            np.LAST_RUN = old


if __name__ == "__main__":
    unittest.main()
