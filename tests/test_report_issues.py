# -*- coding: utf-8 -*-
"""报告层 issue 生成回归测试 (P0-05 · v1.8.1 引入)

覆盖: _issues_external 丢包告警口径 — 注释说"只在 TCP 同步劣化时升级",
实现曾用 if loss >= 5 无视 TCP 状态直接下"运营商侧故障"结论 (审计 P0-05)。
跑用: cd 到项目根目录, `python tests/test_report_issues.py`
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _ext_res(loss_pct, tcp_ok, tcp_total, unreachable=0, rtt_ms=30):
    """键名与 ExternalNetworkTester.results 完全一致."""
    return {"targets": [], "tcp_ok": tcp_ok, "tcp_total": tcp_total,
            "unreachable_count": unreachable, "avg_loss_pct": loss_pct,
            "avg_rtt_ms": rtt_ms, "issues": []}


class TestExternalLossGate(unittest.TestCase):
    """ICMP-only 丢包不得产生 WAN 故障级结论 (审计 P0-05 验收用例)."""

    def _severities(self, res):
        return [i["severity"] for i in N._issues_external(res)]

    def test_icmp10_tcp_ok_no_critical(self):
        """ICMP loss 10% + TCP 全部可达 → 无异常级结论 (ICMP 限速非真丢包)."""
        issues = N._issues_external(_ext_res(10, tcp_ok=4, tcp_total=4))
        self.assertNotIn("异常", [i["severity"] for i in issues])
        loss_issues = [i for i in issues if "丢包" in i["text"]]
        self.assertEqual(1, len(loss_issues))
        self.assertEqual("警告", loss_issues[0]["severity"])
        self.assertIn("ICMP", loss_issues[0]["text"])

    def test_icmp10_tcp_failed_is_candidate(self):
        """ICMP loss 10% + TCP 有失败 → 可进入 WAN 异常候选."""
        issues = N._issues_external(_ext_res(10, tcp_ok=2, tcp_total=4,
                                             unreachable=2))
        self.assertIn("异常", [i["severity"] for i in issues])
        critical = [i for i in issues if i["severity"] == "异常"
                    and "丢包" in i["text"]]
        self.assertEqual(1, len(critical))

    def test_icmp10_no_tcp_evidence_no_critical(self):
        """ICMP loss 10% + TCP 证据缺失 (tcp_total=0) → 不给故障级结论."""
        issues = N._issues_external(_ext_res(10, tcp_ok=0, tcp_total=0))
        self.assertNotIn("异常", [i["severity"] for i in issues])

    def test_mild_loss_warns(self):
        """1% ≤ loss < 5% → 警告级 (原有口径保留)."""
        issues = N._issues_external(_ext_res(2, tcp_ok=4, tcp_total=4))
        loss_issues = [i for i in issues if "丢包" in i["text"]]
        self.assertEqual(1, len(loss_issues))
        self.assertEqual("警告", loss_issues[0]["severity"])

    def test_no_loss_no_entry(self):
        """loss < 1% → 不产生丢包条目."""
        issues = N._issues_external(_ext_res(0, tcp_ok=4, tcp_total=4))
        self.assertEqual([], [i for i in issues if "丢包" in i["text"]])

    def test_error_result_empty(self):
        """模块 error → 不产出任何条目 (原有口径保留)."""
        self.assertEqual([], N._issues_external({"error": "超时"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
