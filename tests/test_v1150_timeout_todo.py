# -*- coding: utf-8 -*-
"""v1.15.0 审查 P1-15 回归测试: 超时/错误模块必须进待办清单。

缺陷基线 (修复前, HEAD 551d151):
  探测失败时 res 里只有 {"error": ...} 一个键, 而各模块的 issues_fn 大多只认
  issues/warnings 字段 —— 于是**失败模块一条 issue 都不产出**。
  实测 23 个模块全超时时同一份报告里有四处互相打架:
    1) 待办清单只有 1 条, 且是 gateway 的 issues_fn 碰巧认得 error 键那条
       → 顶部写「1 项需要您关注 / 来源: 网关检测」, 把「整机 23 个模块都没测
         出来」说成「网关有问题」, 装维会照着查错方向
    2) 根因摘要区写「✓ 无故障」, 而健康分是 0 分 F 级、verdict 写
       「23 个模块未完成检测」
    3) 会诊卡片写「1 项异常级问题」, 与「23 个问题模块已展开」打架
    4) WiFi 模块超时却显示「[提示] 当前未连接 Wi-Fi ... 这是正常现象, 而非故障」
       → 把「没测出来」说成「没连 WiFi」

修复后契约:
  1) 超时/错误模块各自产出一条 severity=异常 的 issue; 超时文案与模块无关
     (各模块超时阈值不同, 写进文案会让 23 条 issue 无法去重合并)
  2) 待办区标题与会诊计数按「涉及模块数」口径
  3) 有未完成模块时根因摘要区不写「✓ 无故障」
  4) WiFi 的「未连接」友好提示在超时/错误时不出现 (那是"没测出来", 不是"没连")

跑用: cd 到项目根目录, `py -3.13 tests/test_v1150_timeout_todo.py`
"""
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

TIMEOUT_ERR = "模块执行超时（超过 120 秒）"
SYNTH_TEXT = "未取得该模块检测结果"


def _mk_last_run(status=None, results=None, keys=None):
    """构造一份 LAST_RUN (结构同 run_diagnostics 装配结果)."""
    status = status or {}
    results = results if results is not None else {}
    keys = keys if keys is not None else list(status.keys())
    return {
        "app": "NetPulse", "version": N.APP_VERSION,
        "generated_at": datetime(2026, 10, 20, 12, 0, 0),
        "system": {"local_ip": "192.168.1.10", "gateway": "192.168.1.1",
                   "dns": "223.5.5.5", "public_ip": "1.2.3.4", "asn": "",
                   "geo": "", "ipv6_public_ip": ""},
        "status": dict(status),
        "results": dict(results),
        "evidence": {},
        "keys": list(keys),
        "duration_ms": 1000,
        "total_modules": len(N.MODULE_MAP),
    }


class _AllTimeoutBase(unittest.TestCase):
    """23 个模块全超时的公共夹具。"""

    def _report(self):
        old = N.LAST_RUN
        N.LAST_RUN = _mk_last_run(
            status={k: "超时" for k in N.MODULE_MAP},
            results={k: {"error": TIMEOUT_ERR} for k in N.MODULE_MAP},
            keys=list(N.MODULE_MAP),
        )
        try:
            return N.build_report()
        finally:
            N.LAST_RUN = old


class TestFailureIssueSynth(unittest.TestCase):
    """超时/错误模块自己产出一条异常级 issue。"""

    def test_timeout_module_produces_issue(self):
        m = N._present_module("gateway", {"error": TIMEOUT_ERR}, "超时")
        self.assertEqual(len(m["issues"]), 1)
        iss = m["issues"][0]
        self.assertEqual(iss["severity"], "异常")
        self.assertIn("超时", iss["text"])
        self.assertIn(SYNTH_TEXT, iss["text"])

    def test_timeout_text_is_module_independent(self):
        """超时文案必须与模块无关 ——
        各模块超时阈值不同 (120~180 秒), 写进文案会让 23 条 issue 无法去重,
        待办区直接刷屏 23 张卡。"""
        a = N._present_module("linkspeed", {"error": TIMEOUT_ERR}, "超时")
        b = N._present_module("speedtest", {"error": TIMEOUT_ERR}, "超时")
        self.assertEqual(a["issues"][0]["text"], b["issues"][0]["text"])

    def test_timeout_replaces_misleading_module_issue(self):
        """超时时模块自身的 issue 是「把 error 当空数据解读」的误判, 必须整份替换。

        基线: linkspeed 的 issues_fn 对 {"error": ...} 返回 0 条, 而其 verdict
        却会给「检测到 0 个适配器」这类与故障无关的结论。
        """
        m = N._present_module("linkspeed", {"error": TIMEOUT_ERR}, "超时")
        self.assertEqual(len(m["issues"]), 1)
        self.assertNotIn("适配器", m["issues"][0]["text"])

    def test_error_module_produces_issue_with_original_text(self):
        m = N._present_module("gateway", {"error": "探测异常: 拒绝访问"}, "错误")
        texts = [i.get("text", "") for i in m["issues"]]
        self.assertTrue(any("拒绝访问" in t for t in texts),
                        f"错误原文必须出现在 issue 里, 实际: {texts}")

    def test_error_module_keeps_partial_findings(self):
        """错误时 res 可能带部分实测数据 (wrap 型 probe 失败仍保留 metrics),
        模块自身的 issue 是真实发现 → 必须保留, 只额外登记失败本身。"""
        key = "gateway"
        old = N.MODULE_PRESENTATION[key]
        N.MODULE_PRESENTATION[key] = dict(
            old, issues_fn=lambda res: [{"severity": "警告",
                                          "text": "部分实测发现",
                                          "impact": "", "action": ""}])
        try:
            m = N._present_module(key, {"error": "boom", "partial": 1}, "错误")
        finally:
            N.MODULE_PRESENTATION[key] = old
        texts = [i.get("text", "") for i in m["issues"]]
        self.assertIn("部分实测发现", texts)
        self.assertTrue(any("boom" in t for t in texts))

    def test_ok_module_gets_no_synthetic_issue(self):
        m = N._present_module("gateway", {"ping": {"avg_ms": 1.0}}, "完成")
        for i in m["issues"]:
            self.assertNotIn(SYNTH_TEXT, i.get("text", ""))

    def test_not_detected_module_gets_no_synthetic_issue(self):
        """「未检测」= 环境缺测 (无 WiFi 网卡等), 不是故障, 不该进待办清单。"""
        m = N._present_module("wifi", {}, "未检测")
        for i in m["issues"]:
            self.assertNotIn(SYNTH_TEXT, i.get("text", ""))


class TestTodoSectionReflectsTimeouts(_AllTimeoutBase):
    """待办清单的口径必须覆盖全部超时模块。"""

    def test_todo_not_claiming_all_passed(self):
        rep = self._report()
        todo = N._todo_issues_section(rep["modules"])
        self.assertNotIn("所有核心检测通过", todo)
        self.assertNotIn("所有检测通过", todo)
        self.assertNotIn("网络状态良好", todo)

    def test_todo_heading_shows_involved_module_count(self):
        rep = self._report()
        todo = N._todo_issues_section(rep["modules"])
        self.assertIn("涉及 23 个模块", todo)

    def test_todo_card_shows_affected_modules(self):
        rep = self._report()
        todo = N._todo_issues_section(rep["modules"])
        self.assertIn("波及", todo)
        self.assertIn("23", todo)

    def test_consult_card_counts_by_module(self):
        """会诊卡片按「涉及模块数」计数, 不能把 23 个模块说成 1 项。"""
        rep = self._report()
        todo = N._todo_issues_section(rep["modules"])
        self.assertIn("23 项异常级问题", todo)

    def test_todo_issue_is_timeout_not_gateway_only(self):
        """基线: 待办卡来源写「网关检测」→ 装维以为只有网关有问题。"""
        rep = self._report()
        todo = N._todo_issues_section(rep["modules"])
        self.assertIn(SYNTH_TEXT, todo)

    def test_brief_v1_shows_involved_modules(self):
        """现网现场交付主文档 (选项 6) 同样不能把 23 个模块说成 1 项。"""
        rep = self._report()
        html = N.render_report_html_brief(rep)
        self.assertIn("涉及 23 个模块", html)


class TestDiagnosisSectionNotClaimNoFault(_AllTimeoutBase):
    """根因摘要区: 「无根因」≠「无故障」。"""

    def test_no_fault_badge_suppressed_when_modules_unfinished(self):
        rep = self._report()
        sec = N._render_diagnosis_section_html(rep["diagnosis"], report=rep)
        self.assertNotIn("无故障", sec)
        self.assertIn("未定位到根因", sec)

    def test_no_fault_badge_kept_when_all_ok(self):
        """正常报告仍写「✓ 无故障」, 别把闸门做成一刀切。"""
        keys = ["gateway"]
        old = N.LAST_RUN
        N.LAST_RUN = _mk_last_run(
            status={"gateway": "完成"},
            results={"gateway": {"ping": {"avg_ms": 1.0}}},
            keys=keys,
        )
        try:
            rep = N.build_report()
        finally:
            N.LAST_RUN = old
        sec = N._render_diagnosis_section_html(rep["diagnosis"], report=rep)
        self.assertIn("无故障", sec)


class TestWifiNoteNotMisleading(_AllTimeoutBase):
    """WiFi 友好提示不能出现在超时模块上。"""

    def test_wifi_timeout_has_no_not_connected_note(self):
        rep = self._report()
        html = N.render_report_html_customer(rep)
        self.assertNotIn("当前未连接 Wi-Fi", html)

    def test_wifi_timeout_still_shows_timeout_issue(self):
        rep = self._report()
        html = N.render_report_html_customer(rep)
        self.assertIn(SYNTH_TEXT, html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
