# -*- coding: utf-8 -*-
"""v1.15.0 审查 P1-13 回归测试: 健康分 / verdict / 退出码必须同一口径。

缺陷基线 (修复前, HEAD 551d151):
  iperf3 未配置服务器 → 模块返回 error → 状态「错误」。
  但这层改写 (「未配置」→ 未检测) 只做在 build_report 的**客户视图**里,
  而且在状态计数**之后** —— 同一份数据出现三套口径:
    健康分 100 分 / A 级 (iperf3 是评分豁免模块, 不扣分)
    verdict「优秀 · 1 个模块需关注 (含 1 个异常)」(文案口径数到了「错误」)
    退出码 2 (按 LAST_RUN["status"] 里的「错误」)
  客户视角: 一边说 100 分优秀, 一边说含 1 个异常, 自动化脚本还收到退出码 2。

修复后契约: 状态改写前置到状态层, 报告计数 / verdict / 退出码共用同一份 summary。

跑用: cd 到项目根目录, `py -3.13 tests/test_v1150_health_verdict.py`
"""
import contextlib
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


IPERF3_ERR = ("未指定 iperf3 服务器。请在菜单中选择 iperf3 时输入服务器地址, "
              "或用 CLI: netpulse.py iperf3 --iperf3-server HOST[:PORT]")


def _mk_last_run(status=None, results=None, keys=None):
    """构造一份 LAST_RUN (结构同 run_diagnostics 装配结果)."""
    from datetime import datetime
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


class TestStatusNormalize(unittest.TestCase):
    """_normalize_module_statuses: 「未配置」不是故障。"""

    def test_iperf3_not_configured_becomes_not_detected(self):
        out = N._normalize_module_statuses(
            {"iperf3": "错误", "dns": "完成"},
            {"iperf3": {"error": IPERF3_ERR}, "dns": {"summary": "ok"}})
        self.assertEqual(out["iperf3"], "未检测")
        self.assertEqual(out["dns"], "完成")

    def test_real_error_untouched(self):
        out = N._normalize_module_statuses(
            {"iperf3": "错误"},
            {"iperf3": {"error": "iperf3 双向均失败 — 服务器不可达"}})
        self.assertEqual(out["iperf3"], "错误")

    def test_other_modules_untouched(self):
        out = N._normalize_module_statuses(
            {"gateway": "错误"}, {"gateway": {"error": "网关不可达"}})
        self.assertEqual(out["gateway"], "错误")

    def test_no_results_returns_copy(self):
        src = {"dns": "完成"}
        out = N._normalize_module_statuses(src, None)
        self.assertEqual(out, src)
        out["dns"] = "异常"
        self.assertEqual(src["dns"], "完成", "不得就地改传入的 dict")


class TestHealthVerdictConsistency(unittest.TestCase):
    """build_report: 健康分 / verdict / 计数 同一口径。"""

    def _report(self, status, results):
        old = N.LAST_RUN
        N.LAST_RUN = _mk_last_run(status, results)
        try:
            return N.build_report()
        finally:
            N.LAST_RUN = old

    def test_iperf3_unconfigured_no_false_alarm(self):
        """未配置 iperf3 → 100 分 A 级 + verdict 不提「异常」+ 退出码 0。"""
        status = {"dns": "完成", "gateway": "完成", "iperf3": "错误"}
        results = {"dns": {"summary": "ok"}, "gateway": {"summary": "ok"},
                   "iperf3": {"error": IPERF3_ERR}}
        rep = self._report(status, results)
        self.assertEqual(rep["health"]["score"], 100)
        self.assertEqual(rep["health"]["grade"], "A")
        self.assertNotIn("异常", rep["health"]["verdict"])
        self.assertNotIn("需关注", rep["health"]["verdict"])
        self.assertEqual(rep["summary"]["iperf3"], "未检测")
        # 退出码: 同一份 summary → 不该报「检测出问题」
        self.assertEqual(N.compute_exit_code(rep["summary"]), 0)

    def test_real_error_still_deducts_and_reports(self):
        """真异常仍然扣分 + verdict 点名 + 退出码 2。"""
        status = {"dns": "完成", "gateway": "异常"}
        results = {"dns": {"summary": "ok"},
                   "gateway": {"summary": "网关丢包 25%", "issues": []}}
        rep = self._report(status, results)
        self.assertLess(rep["health"]["score"], 100)
        self.assertIn("异常", rep["health"]["verdict"])
        self.assertEqual(N.compute_exit_code(rep["summary"]), 2)

    def test_verdict_error_count_matches_summary(self):
        """verdict 里的「含 N 个异常」必须等于 summary 里的异常+错误数。"""
        status = {"dns": "完成", "gateway": "异常", "wifi": "错误",
                  "iperf3": "错误", "tcp": "警告"}
        results = {"dns": {"summary": "ok"},
                   "gateway": {"summary": "x", "issues": []},
                   "wifi": {"summary": "y", "issues": []},
                   "iperf3": {"error": IPERF3_ERR},
                   "tcp": {"summary": "z", "issues": []}}
        rep = self._report(status, results)
        summary = rep["summary"]
        n_err = sum(1 for st in summary.values() if st in ("异常", "错误"))
        verdict = rep["health"]["verdict"]
        self.assertIn(f"含 {n_err} 个异常", verdict)
        # 豁免模块的状态是「未检测」→ 不计入异常数
        self.assertEqual(summary["iperf3"], "未检测")
        self.assertEqual(n_err, 2)

    def test_counts_and_summary_agree(self):
        """报告的 counts 与 summary 必须同源 (不再各数各的)。"""
        status = {"dns": "完成", "iperf3": "错误"}
        results = {"dns": {"summary": "ok"}, "iperf3": {"error": IPERF3_ERR}}
        rep = self._report(status, results)
        self.assertEqual(rep["counts"].get("错误", 0), 0)
        self.assertEqual(rep["counts"].get("未检测", 0), 0)   # 豁免不计入扣分口径


class TestRunnerNormalizesStatus(unittest.TestCase):
    """runner 层: 状态改写前置 → CLI 汇总 / LAST_RUN / 退出码一致。"""

    def test_run_diagnostics_normalizes_iperf3(self):
        out, err = io.StringIO(), io.StringIO()
        results = {"iperf3": "错误"}
        full = {"iperf3": {"error": IPERF3_ERR}}
        with contextlib.ExitStack() as st:
            for p in (mock.patch.object(N, "_run_diagnostics_sequential",
                                        return_value=(results, full)),
                      mock.patch.object(N, "get_local_ip", return_value="1.1.1.1"),
                      mock.patch.object(N, "get_default_gateway", return_value="1.1.1.2"),
                      mock.patch.object(N, "get_dns_servers", return_value=["1.1.1.3"]),
                      mock.patch.object(N, "get_public_ip", return_value="1.2.3.4"),
                      mock.patch.object(N, "get_ip_geo", return_value=None),
                      mock.patch.object(N, "get_public_ipv6", return_value="")):
                st.enter_context(p)
            st.enter_context(contextlib.redirect_stdout(out))
            st.enter_context(contextlib.redirect_stderr(err))
            N.run_diagnostics(["iperf3"])
        self.assertEqual(N.LAST_RUN["status"]["iperf3"], "未检测")
        self.assertEqual(N.compute_exit_code(N.LAST_RUN["status"]), 0)
        self.assertNotIn("[错误]", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
