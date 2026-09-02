# -*- coding: utf-8 -*-
"""诊断回归矩阵 (审计 P1-05 · v1.8.1 引入)

审计 §5 矩阵: 组合 Gateway/External/DNS/TCP 状态 → 期望归因类别。
单规则的触发/门控细节由 tests/test_diagnosis.py 覆盖; 本文件锁的是
"组合场景下的归因方向" — 多模块同报错时不得归错段。

跑用: cd 到项目根目录, `python tests/test_diagnosis_matrix.py`
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _ok_gateway():
    return {"ping": {"loss_pct": 0, "avg_ms": 5, "jitter_ms": 1}, "issues": []}


def _ok_external():
    return {"targets": [], "tcp_ok": 4, "tcp_total": 4,
            "unreachable_count": 0, "issues": []}


def _ok_dns():
    return {"success_count": 8, "total_count": 8, "issues": []}


def _ok_tcpstats():
    return {"segments_sent": 100000, "retransmitted": 120,
            "retrans_rate_pct": 0.12, "issues": []}


def _ok_bufferbloat():
    return {"idle_rtt_ms": 8, "loaded_rtt_ms": 12, "bloat_ms": 4.0,
            "grade": "A (优秀, 无 Bufferbloat)", "load_warning": False,
            "issues": []}


def _base():
    """全健康底座 (矩阵每一行的起点)."""
    return {"gateway": _ok_gateway(), "external": _ok_external(),
            "dns": _ok_dns(), "tcpstats": _ok_tcpstats(),
            "bufferbloat": _ok_bufferbloat()}


def _fail_external():
    return {"targets": [], "tcp_ok": 0, "tcp_total": 4,
            "unreachable_count": 4, "issues": [{"severity": "critical"}]}


def _fail_dns():
    return {"success_count": 2, "total_count": 10, "issues": []}


def _fail_tcpstats():
    return {"segments_sent": 100000, "retransmitted": 9000,
            "retrans_rate_pct": 9.0, "issues": []}


def _fail_gateway():
    return {"ping": {"loss_pct": 100, "avg_ms": 0, "jitter_ms": 0},
            "issues": []}


def _ids(report):
    return [rc.id for rc in report.root_causes]


class TestDiagnosisMatrix(unittest.TestCase):
    """审计 §5 矩阵: 组合状态 → 归因方向."""

    def test_all_ok_healthy(self):
        """| OK | OK | OK | OK | → HEALTHY (无根因)."""
        report = N.diagnose(_base())
        self.assertEqual([], report.root_causes)

    def test_all_fail_lan(self):
        """| FAIL | FAIL | FAIL | FAIL | → LAN/GATEWAY, 不得误归 WAN/DNS."""
        r = _base()
        r["gateway"] = _fail_gateway()
        r["external"] = _fail_external()
        r["dns"] = _fail_dns()
        r["tcpstats"] = _fail_tcpstats()
        report = N.diagnose(r)
        ids = _ids(report)
        self.assertIn("gateway_loss", ids)
        self.assertNotIn("wan_interruption", ids)   # 网关断 → 不是 WAN
        self.assertNotIn("dns_failure", ids)        # 网关断 → 不是 DNS

    def test_gw_ok_rest_fail_wan(self):
        """| OK | FAIL | FAIL | FAIL | → WAN 为主因 (CRITICAL), 非 LAN."""
        r = _base()
        r["external"] = _fail_external()
        r["dns"] = _fail_dns()
        r["tcpstats"] = _fail_tcpstats()
        report = N.diagnose(r)
        ids = _ids(report)
        self.assertIn("wan_interruption", ids)
        self.assertNotIn("gateway_loss", ids)
        wan = [rc for rc in report.root_causes if rc.id == "wan_interruption"][0]
        self.assertEqual(N.Severity.CRITICAL, wan.severity)
        self.assertEqual("wan_interruption", ids[0])   # 头条根因是 WAN

    def test_only_dns_fail(self):
        """| OK | OK | FAIL | OK | → DNS, 不升级为 WAN."""
        r = _base()
        r["dns"] = _fail_dns()
        report = N.diagnose(r)
        ids = _ids(report)
        self.assertIn("dns_failure", ids)
        self.assertNotIn("wan_interruption", ids)
        self.assertNotIn("gateway_loss", ids)

    def test_only_tcp_fail(self):
        """| OK | OK | OK | FAIL | → TCP 传输层, 不误归网关/解析."""
        r = _base()
        r["tcpstats"] = _fail_tcpstats()
        report = N.diagnose(r)
        ids = _ids(report)
        self.assertIn("tcp_loss_burst", ids)
        self.assertNotIn("gateway_loss", ids)
        self.assertNotIn("dns_failure", ids)
        self.assertNotIn("wan_interruption", ids)

    def test_high_latency_performance(self):
        """| OK | OK | 高延迟负载 | OK | → PERFORMANCE (Bufferbloat)."""
        r = _base()
        r["bufferbloat"] = {"idle_rtt_ms": 8, "loaded_rtt_ms": 208,
                            "bloat_ms": 200.0,
                            "grade": "F (严重 Bufferbloat)",
                            "load_warning": False, "issues": []}
        report = N.diagnose(r)
        ids = _ids(report)
        self.assertIn("bufferbloat", ids)
        self.assertNotIn("gateway_loss", ids)


class TestMatrixEdgeCases(unittest.TestCase):
    """边界: 模块自身故障不得当网络证据 (与单规则口径一致, 矩阵级兜底)."""

    def test_gateway_module_error_no_misattribution(self):
        """gateway 模块超时 → 不产生 LAN 根因, 也不得顺手归 WAN/DNS."""
        r = _base()
        r["gateway"] = {"error": "模块执行超时（超过 120 秒）"}
        r["external"] = _fail_external()     # 外网同时失败, 诱惑归因 WAN
        report = N.diagnose(r)
        ids = _ids(report)
        self.assertNotIn("gateway_loss", ids)
        self.assertNotIn("wan_interruption", ids)   # 网关未知 → WAN 不可判
        self.assertNotIn("dns_failure", ids)

    def test_dns_module_error_no_misattribution(self):
        """dns 模块超时 ≠ DNS 故障: 外网全断时归 WAN 而非 DNS."""
        r = _base()
        r["dns"] = {"error": "模块执行超时（超过 120 秒）"}
        r["external"] = _fail_external()
        report = N.diagnose(r)
        ids = _ids(report)
        self.assertIn("wan_interruption", ids)
        self.assertNotIn("dns_failure", ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
