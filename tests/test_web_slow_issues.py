# -*- coding: utf-8 -*-
"""web 模块"慢但通"issue 化回归测试

背景: 此前 WebPageTester 全部目标可达时再慢也不产生 issue —— 模块状态"完成",
健康分 0 扣分; avg ttfb ≥500ms 只给 assessment 文案"网页访问偏慢"。
修复: 慢升格进 issue 体系 ——
  - avg ttfb ≥ 2000ms → critical (异常 -20); ≥ 500ms → warning (警告 -2)
  - 分段慢: dns ≥200 / tcp ≥500 / tls ≥500 (ms) → warning
阈值与 THRESHOLDS["web"] / _metrics_web 客户视角配色同值, 三处须同步。
跑用: cd 到项目根目录, `python tests/test_web_slow_issues.py`
(全程 mock _probe_one / WebPageTester, 不联网)
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _issue_types(results, itype):
    return [i for i in results["issues"] if i.get("type") == itype]


class TestWebSlowIssues(unittest.TestCase):
    """WebPageTester.detect 模块级慢判定。"""

    def _detect(self, ttfb, dns=20.0, tcp=30.0, tls=60.0):
        tester = N.WebPageTester()

        def fake_probe_one(url):
            return {"url": url, "final_url": url, "redirects": 0,
                    "dns_ms": dns, "tcp_ms": tcp, "tls_ms": tls,
                    "ttfb_ms": ttfb, "status_code": 200, "total_ms": 100.0}

        with mock.patch.object(N.WebPageTester, "_probe_one",
                               side_effect=fake_probe_one):
            return tester.detect()

    def test_fast_no_slow_issues(self):
        res = self._detect(ttfb=120)
        self.assertEqual(res["assessment"], "网页访问正常")
        for t in ("web_slow", "dns_slow", "tcp_slow", "tls_slow"):
            self.assertEqual(_issue_types(res, t), [], t)

    def test_ttfb_warn_boundary(self):
        self.assertEqual(_issue_types(self._detect(ttfb=499.0), "web_slow"), [])
        res = self._detect(ttfb=500.0)
        slow = _issue_types(res, "web_slow")
        self.assertEqual(len(slow), 1)
        self.assertEqual(slow[0]["severity"], "warning")
        self.assertEqual(res["assessment"], "网页访问偏慢")

    def test_ttfb_critical_boundary(self):
        res = self._detect(ttfb=2000.0)
        slow = _issue_types(res, "web_slow")
        self.assertEqual(len(slow), 1)
        self.assertEqual(slow[0]["severity"], "critical")
        self.assertEqual(res["assessment"], "网页访问严重缓慢")
        self.assertEqual(_issue_types(self._detect(ttfb=1999.0),
                                      "web_slow")[0]["severity"], "warning")

    def test_segment_slow_warnings(self):
        res = self._detect(ttfb=120, dns=200.0, tcp=500.0, tls=500.0)
        for t in ("dns_slow", "tcp_slow", "tls_slow"):
            hit = _issue_types(res, t)
            self.assertEqual(len(hit), 1, t)
            self.assertEqual(hit[0]["severity"], "warning", t)
        res2 = self._detect(ttfb=120, dns=199.0, tcp=499.0, tls=499.0)
        for t in ("dns_slow", "tcp_slow", "tls_slow"):
            self.assertEqual(_issue_types(res2, t), [], t)

    def test_failures_unaffected(self):
        """失败断层 (fail_stage) 判定不受本次改动影响."""
        tester = N.WebPageTester()

        def fake_probe_one(url):
            return {"url": url, "redirects": 0, "fail_stage": "dns",
                    "error": "DNS 解析失败: x"}

        with mock.patch.object(N.WebPageTester, "_probe_one",
                               side_effect=fake_probe_one):
            res = tester.detect()
        self.assertEqual(res["assessment"], "网页访问异常")
        self.assertEqual(len(_issue_types(res, "dns_fail")), 3)


class TestWebSlowWrapChain(unittest.TestCase):
    """issue severity → DiagnosticResult.status 映射 (健康分扣分链路)."""

    def _probe_with_issues(self, issues):
        results = {
            "summary": "网页体检", "issues": issues, "assessment": "x",
            "ok_count": 3, "total_count": 3,
            "avg_dns_ms": 20.0, "avg_tcp_ms": 30.0, "avg_tls_ms": 60.0,
            "avg_ttfb_ms": 800.0, "min_cert_days": None,
            "fail_stages": {}, "targets": [],
            "timestamp": "2026-09-14T00:00:00",
        }
        stub = type("StubTester", (), {
            "__init__": lambda self: setattr(self, "results", {}),
            "detect": lambda self, callback=None, **kw:
                setattr(self, "results", results),
            "name": "stub",
        })
        with mock.patch.object(N, "WebPageTester", stub):
            return N.probe_web_v2(callback=lambda m: None)

    def test_web_slow_warning_maps_to_warning(self):
        result = self._probe_with_issues([
            {"type": "web_slow", "severity": "warning", "message": "偏慢",
             "detail": ""}])
        self.assertEqual(result.status, N.Status.WARNING)

    def test_web_slow_critical_maps_to_error(self):
        result = self._probe_with_issues([
            {"type": "web_slow", "severity": "critical", "message": "严重缓慢",
             "detail": ""}])
        self.assertEqual(result.status, N.Status.ERROR)

    def test_segment_slow_maps_to_warning(self):
        result = self._probe_with_issues([
            {"type": "dns_slow", "severity": "warning", "message": "DNS 段慢",
             "detail": ""}])
        self.assertEqual(result.status, N.Status.WARNING)


if __name__ == "__main__":
    unittest.main(verbosity=2)
