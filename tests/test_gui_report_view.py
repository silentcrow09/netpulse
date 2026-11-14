# -*- coding: utf-8 -*-
"""GUI 报告投影口径一致性 (v1.25.0 · verify S7/S6 数据侧)。

屏幕版报告的一切数字必须与导出 HTML 报告同源:
  - health.formula == _score_formula(report) (同一算式函数)
  - todo 与 _todo_issues_data(report["modules"]) 同源同值
  - 模块展开集合符合折叠口径 (有根因 → 首要根因模块; 无根因 → PROBLEM_STATUSES)
  - 载荷不含 tech.raw_results / 模块 raw 大对象 (屏幕视图不需要)
"""
import json
import os
import sys
import unittest
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netpulse as np  # noqa: E402
from test_report_golden import _fixture_run  # noqa: E402


def _rep(**kwargs):
    return np.build_report(run=_fixture_run(), **kwargs)


class TestGuiReportView(unittest.TestCase):

    def test_none_safe(self):
        self.assertIsNone(np._gui_report_view(None))
        self.assertIsNone(np._gui_report_view({}))

    def test_projection_keys_complete(self):
        view = np._gui_report_view(_rep())
        for k in ("meta", "health", "counts", "summary_counts", "exempt_count",
                  "exempt_names", "scope", "todo", "charts", "modules",
                  "diagnosis", "host", "thresholds"):
            self.assertIn(k, view, "投影缺键: %s" % k)
        for k in ("score", "grade", "label", "verdict", "formula"):
            self.assertIn(k, view["health"])
        # 算式行与导出报告 Hero 同一函数产出 (S7 口径一致)
        rep = _rep()
        view = np._gui_report_view(rep)
        self.assertEqual(view["health"]["formula"], np._score_formula(rep))
        self.assertEqual(view["health"]["score"], rep["health"]["score"])
        self.assertEqual(view["health"]["grade"], rep["health"]["grade"])
        # 双口径: counts 为扣分口径直传, summary_counts 覆盖全部模块
        self.assertEqual(view["counts"], rep["counts"])
        total_in_bar = sum(seg["n"] for seg in view["summary_counts"])
        self.assertEqual(total_in_bar, len(rep["modules"]),
                         "状态分布条 (全口径) 必须覆盖全部模块")

    def test_projection_excludes_raw_payload(self):
        view = np._gui_report_view(_rep())
        blob = json.dumps(view, ensure_ascii=False, default=str)
        self.assertNotIn("raw_results", blob,
                         "屏幕投影不得携带 tech.raw_results 大对象")
        self.assertNotIn("evidence", blob)
        for mv in view["modules"]:
            self.assertNotIn("raw", mv, "模块投影不得携带 raw 原始载荷")

    def test_todo_same_source_as_export(self):
        rep = _rep()
        t = np._todo_issues_data(rep["modules"])
        view = np._gui_report_view(rep)["todo"]
        self.assertEqual(view["need_cnt"], t["need_cnt"])
        self.assertEqual(view["involved_cnt"], t["involved_cnt"])
        self.assertEqual(view["info_cnt"], t["info_cnt"])
        self.assertEqual(view["hidden_cnt"], t["hidden_cnt"])
        self.assertEqual(len(view["cards"]), len(t["merged"]))
        for card, src in zip(view["cards"], t["merged"]):
            self.assertEqual(card["severity"], src.get("severity", "信息"))
            self.assertEqual("；".join(card["texts"]),
                             "；".join(x for x in src["_texts"] if x))
            self.assertEqual(card["module"], src.get("_module", ""))
            self.assertEqual(card["dup"], src.get("_dup", 1) or 1)
        # fixture 有 2 条警告 → 待办必须非空 (否则 fixture 退化)
        self.assertGreaterEqual(view["need_cnt"], 2)

    def test_module_views_dedup_and_expand_rules(self):
        view = np._gui_report_view(_rep())
        mods = {m["key"]: m for m in view["modules"]}
        self.assertIn("gateway", mods)
        self.assertIn("dns", mods)
        # 未跑的模块也在列表里 (状态 未检测), 屏幕版不隐藏
        self.assertEqual(mods["iperf3"]["status"], "未检测")
        # 问题去重: (severity, text) 同键不重复
        for m in view["modules"]:
            seen = set()
            for issue in m["issues"]:
                key = (issue["severity"], issue["text"])
                self.assertNotIn(key, seen)
                seen.add(key)
        # 模块级指标过滤空值 (与导出报告同一口径)
        for m in view["modules"]:
            for me in m["key_metrics"]:
                self.assertNotIn(str(me["value"]).strip(),
                                 ("—", "N/A", "无", ""))

    def test_expand_primary_root_cause_only(self):
        # 有根因 → 只展开首要根因涉及的模块 (wifi 也是问题模块但不展开)
        diag = {"root_causes": [{
            "id": "dns_failure", "category": "DNS", "severity": "high",
            "title": "DNS 解析异常", "description": "", "confidence": 0.6,
            "evidence_ids": [], "affected_modules": ["dns"],
            "recommendations": [], "supports": [], "excludes": [],
        }], "overall_confidence": 0.6, "rules_evaluated": 8, "rules_fired": 1}
        rep = _rep(diagnosis=diag)
        view = np._gui_report_view(rep)
        mods = {m["key"]: m for m in view["modules"]}
        self.assertTrue(mods["dns"]["expanded"])
        self.assertFalse(mods["wifi"]["expanded"],
                         "首要根因口径下非根因模块不得自动展开")
        self.assertFalse(mods["gateway"]["expanded"])
        self.assertEqual(view["diagnosis"]["mode"], "root_causes")
        self.assertEqual(view["diagnosis"]["root_causes"][0]["sev_label"], "高")
        self.assertEqual(view["diagnosis"]["root_causes"][0]["conf_band"],
                         np._conf_band(0.6))

    def test_expand_without_root_cause_uses_problem_statuses(self):
        rep = _rep()   # fixture 无根因命中 (合成结果不构成规则证据)
        view = np._gui_report_view(rep)
        if view["diagnosis"]["mode"] == "root_causes":
            self.skipTest("fixture 命中了根因规则, 本用例不适用")
        mods = {m["key"]: m for m in view["modules"]}
        self.assertTrue(mods["dns"]["expanded"], "警告模块应默认展开")
        self.assertTrue(mods["wifi"]["expanded"], "警告模块应默认展开")
        self.assertFalse(mods["gateway"]["expanded"], "完成模块默认折叠")

    def test_scope_partial_and_full(self):
        # 全量跑完 → 「N 项全覆盖」
        view = np._gui_report_view(_rep())
        self.assertIn("项全覆盖", view["scope"]["text"])
        # 提前结束 (ran < sel) → 「ran/sel 项」+ 提前结束说明 (部分报告口径)
        run = _fixture_run()
        for k in ("speedtest", "mtu", "tcpstats"):
            run["results"].pop(k, None)
            run["status"].pop(k, None)
        rep2 = np.build_report(run=run)
        view2 = np._gui_report_view(rep2)
        ran = len(rep2["tech"]["raw_results"])
        self.assertEqual(view2["scope"]["text"], "%d/%d 项" % (ran, 8))
        self.assertIn("本轮提前结束", view2["scope"]["note"])

    def test_host_pairs_and_disclosure(self):
        view = np._gui_report_view(_rep())
        labels = [p[0] for p in view["host"]["pairs"]]
        for lab in ("本机 IP", "默认网关", "DNS", "公网 IP"):
            self.assertIn(lab, labels)
        self.assertTrue(view["host"]["disclosure"],
                        "第三方披露文案必须随投影下发 (AGENTS.md 隐私口径)")

    def test_session_report_view(self):
        # session 侧: 有报告给投影, 无报告 None (路由据此 404)
        s = np._GuiSession()
        self.assertIsNone(s.report_view())
        s._report = _rep()
        view = s.report_view()
        self.assertIsNotNone(view)
        self.assertIn("health", view)


if __name__ == "__main__":
    unittest.main()
