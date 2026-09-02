# -*- coding: utf-8 -*-
"""Probes 单元测试 (阶段 B · v1.2.0 引入 — B7 gateway 试点)

覆盖: probe_gateway_v2 在各场景下的状态推导 / issues 装配 / evidence 收集.
不依赖真实网络: monkey-patch ping_host + get_default_gateway 返回 mock 数据.

跑法: cd 到项目根目录, `python tests/test_probes.py`
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _stub_ping_ok(*args, **kwargs):
    """完美 ping: 0 丢包, 低延迟, 无 TTL (避免污染 evidence 计数)."""
    return {
        "sent": 1, "received": 1, "loss_pct": 0.0,
        "avg_ms": 2.0, "min_ms": 1.0, "max_ms": 3.0,
        "jitter_ms": 0.5, "ttl": None, "rtts": [2.0],
    }


def _stub_ping_high_latency(*args, **kwargs):
    return {
        "sent": 20, "received": 20, "loss_pct": 0.0,
        "avg_ms": 35.0, "min_ms": 30.0, "max_ms": 50.0,
        "jitter_ms": 5.0, "ttl": 64, "rtts": [35.0] * 20,
    }


def _stub_ping_packet_loss(*args, **kwargs):
    return {
        "sent": 20, "received": 18, "loss_pct": 10.0,
        "avg_ms": 50.0, "min_ms": 10.0, "max_ms": 200.0,
        "jitter_ms": 25.0, "ttl": 64, "rtts": [50.0] * 18,
    }


def _stub_ping_jitter_high(*args, **kwargs):
    return {
        "sent": 20, "received": 20, "loss_pct": 0.0,
        "avg_ms": 15.0, "min_ms": 5.0, "max_ms": 100.0,
        "jitter_ms": 60.0, "ttl": 64, "rtts": [15.0] * 20,
    }


class TestProbeGatewayV2(unittest.TestCase):

    def test_registered_in_v2_probes(self):
        self.assertIn("gateway", N._V2_PROBES)
        self.assertIs(N._V2_PROBES["gateway"], N.probe_gateway_v2)

    def test_returns_diagnostic_result(self):
        """正常路径返回 DiagnosticResult."""
        with patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             patch.object(N, "ping_host", side_effect=_stub_ping_ok):
            result = N.probe_gateway_v2(count=1)
        self.assertIsInstance(result, N.DiagnosticResult)
        self.assertEqual(result.module_id, "gateway")
        self.assertEqual(result.status, N.Status.OK)

    def test_no_gateway_returns_error(self):
        """get_default_gateway 返回 None/空 → Status.ERROR + DiagnosticError."""
        for empty_val in (None, ""):
            with patch.object(N, "get_default_gateway", return_value=empty_val), \
                 patch.object(N, "ping_host", side_effect=_stub_ping_ok):
                result = N.probe_gateway_v2(count=1)
            self.assertEqual(result.status, N.Status.ERROR,
                             f"empty_val={empty_val!r}")
            self.assertIsNotNone(result.error)
            self.assertEqual(result.error.code, "NO_GATEWAY")
            self.assertEqual(result.error.category, "network")
            # 不调 ping
            self.assertEqual(len(result.evidence), 0)

    def test_high_latency_triggers_critical_issue(self):
        """avg=35ms (>=30) → critical latency issue."""
        with patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             patch.object(N, "ping_host", side_effect=_stub_ping_high_latency):
            result = N.probe_gateway_v2(count=20)
        self.assertEqual(result.status, N.Status.ERROR)
        ids = [i.id for i in result.issues]
        self.assertIn("gateway.high_latency", ids)
        high = next(i for i in result.issues if i.id == "gateway.high_latency")
        self.assertEqual(high.severity, N.Severity.CRITICAL)
        self.assertEqual(len(high.recommendations), 4)

    def test_moderate_latency_triggers_warning(self):
        """avg=35 同时触发 high_latency critical — 改 avg=15 走 latency_high warning."""
        def _stub(*a, **k):
            r = _stub_ping_high_latency(*a, **k)
            r["avg_ms"] = 15.0   # 10-30 区间 → warning
            return r
        with patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             patch.object(N, "ping_host", side_effect=_stub):
            result = N.probe_gateway_v2(count=20)
        self.assertEqual(result.status, N.Status.WARNING)
        ids = [i.id for i in result.issues]
        self.assertIn("gateway.latency_high", ids)

    def test_packet_loss_10pct_critical(self):
        """loss=10% → critical packet_loss issue."""
        with patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             patch.object(N, "ping_host", side_effect=_stub_ping_packet_loss):
            result = N.probe_gateway_v2(count=20)
        self.assertEqual(result.status, N.Status.ERROR)
        ids = [i.id for i in result.issues]
        self.assertIn("gateway.packet_loss", ids)
        self.assertIn("gateway.high_latency", ids)
        self.assertIn("gateway.jitter", ids)   # 25ms >=20

    def test_jitter_60ms_critical(self):
        """jitter=60ms (>=50) → critical jitter issue."""
        with patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             patch.object(N, "ping_host", side_effect=_stub_ping_jitter_high):
            result = N.probe_gateway_v2(count=20)
        self.assertEqual(result.status, N.Status.ERROR)
        ids = [i.id for i in result.issues]
        self.assertIn("gateway.jitter", ids)

    def test_evidence_has_avg_loss_jitter(self):
        """正常路径 evidence 必须含 avg/loss/jitter 三个核心指标."""
        with patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             patch.object(N, "ping_host", side_effect=_stub_ping_high_latency):
            result = N.probe_gateway_v2(count=20)
        eids = {e.id for e in result.evidence}
        self.assertIn("gateway.ping.avg_ms", eids)
        self.assertIn("gateway.ping.loss_pct", eids)
        self.assertIn("gateway.ping.jitter_ms", eids)
        # ttl 也应在 (stub 返回 64)
        self.assertIn("gateway.ping.ttl", eids)

    def test_metrics_legacy_compat_keys(self):
        """result.metrics 必须含 GatewayTester.results 同款 key (兼容旧渲染)."""
        with patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             patch.object(N, "ping_host", side_effect=_stub_ping_ok):
            result = N.probe_gateway_v2(count=1)
        for k in ("gateway", "ping", "assessment", "issues", "timestamp", "summary"):
            self.assertIn(k, result.metrics, f"metrics 缺关键 key: {k}")
        # issues 必须是 dict 列表 (旧 _issues_gateway 期望 dict)
        for it in result.metrics["issues"]:
            self.assertIsInstance(it, dict)
            self.assertIn("severity", it)
            self.assertIn(it["severity"], ("critical", "warning"))

    def test_status_precedence_critical_beats_warning(self):
        """critical + warning 同时存在时, status = ERROR (不是 WARNING)."""
        with patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             patch.object(N, "ping_host", side_effect=_stub_ping_packet_loss):
            result = N.probe_gateway_v2(count=20)
        self.assertEqual(result.status, N.Status.ERROR)
        self.assertTrue(any(i.severity == N.Severity.CRITICAL for i in result.issues))

    def test_callback_invoked(self):
        """callback 参数在探测过程中被调用."""
        calls = []
        with patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             patch.object(N, "ping_host", side_effect=_stub_ping_ok), \
             patch.object(N, "ping_host", side_effect=_stub_ping_ok):
            result = N.probe_gateway_v2(count=1, callback=lambda msg: calls.append(msg))
        self.assertGreaterEqual(len(calls), 1, "callback 应被调用至少一次")


class TestRunModuleWithTimeoutV2Branch(unittest.TestCase):
    """_run_module_with_timeout 双轨分支覆盖."""

    def test_v2_path_used_when_registered(self):
        """_V2_PROBES 含 gateway 时, _run_module_with_timeout 走 v2 路径."""
        with patch.object(N, "_V2_PROBES", {"gateway": N.probe_gateway_v2}), \
             patch.object(N, "ping_host", side_effect=_stub_ping_ok), \
             patch.object(N, "get_default_gateway", return_value="192.168.1.1"):
            status, res = N._run_module_with_timeout("gateway", lambda msg: None)
        self.assertEqual(status, "完成")
        self.assertIn("ping", res)
        self.assertIn("summary", res)
        # GatewayTester 没被实例化 — 用 mock 检查
        self.assertFalse(hasattr(N, "_gateway_called"))

    def test_fallback_to_old_tester_when_not_in_v2_probes(self):
        """key 不在 _V2_PROBES 时走旧 Tester.detect() 路径."""
        # 清空 _V2_PROBES, 让 gateway 走旧路径
        with patch.object(N, "_V2_PROBES", {}):
            # 用 mock 替换 GatewayTester 防止真实 ping
            mock_inst = unittest.mock.MagicMock()
            mock_inst.results = {"summary": "test"}
            mock_inst.detect = unittest.mock.MagicMock(return_value=None)
            with patch.object(N, "MODULE_MAP", {"gateway": ("网关测试", lambda: mock_inst)}):
                with patch.object(N, "determine_status", return_value="完成"):
                    status, res = N._run_module_with_timeout("gateway", lambda msg: None)
            self.assertTrue(mock_inst.detect.called)

    def test_no_gateway_error_restores_legacy_semantics(self):
        """无网关时 v2 路径必须与旧 Tester 零差异:
        状态「错误」+ res 含错误文案 (不再是「异常」+ 空文案)."""
        with patch.object(N, "_V2_PROBES", {"gateway": N.probe_gateway_v2}), \
             patch.object(N, "get_default_gateway", return_value=None), \
             patch.object(N, "ping_host", side_effect=_stub_ping_ok):
            status, res = N._run_module_with_timeout("gateway", lambda msg: None)
        self.assertEqual(status, "错误")
        self.assertIn("error", res)
        self.assertIn("无法获取默认网关", res["error"])

    def test_probe_module_error_keeps_metrics(self):
        """wrap 型 probe (metrics 含 error) 走错误路径时, 完整 metrics 不丢."""
        def _fake_probe(callback=None):
            return N._wrap_as_diagnostic_result(
                {"error": "boom", "summary": "partial", "issues": []},
                "dns", "2026-08-31T00:00:00", 50)
        with patch.object(N, "_V2_PROBES", {"dns": _fake_probe}):
            status, res = N._run_module_with_timeout("dns", lambda msg: None)
        self.assertEqual(status, "错误")
        self.assertEqual(res["error"], "boom")
        self.assertEqual(res["summary"], "partial")   # 完整 metrics 保留


class TestIssuesGatewayDottedId(unittest.TestCase):
    """B7 迁移回归: _issues_gateway 必须兼容 v2 probe 的点分 issue id."""

    def _res(self, issue_type):
        return {
            "ping": {"sent": 20, "received": 19, "loss_pct": 5.0},
            "issues": [{"type": issue_type, "severity": "critical",
                        "message": "网关丢包 5%", "detail": "d", "action": "a"}],
        }

    def test_dotted_id_gets_raw_summary(self):
        items = N._issues_gateway(self._res("gateway.packet_loss"))
        self.assertEqual(items[0]["raw_summary"], "20 发 / 19 收 / 1 丢")

    def test_legacy_underscore_id_gets_raw_summary(self):
        items = N._issues_gateway(self._res("gateway_packet_loss"))
        self.assertEqual(items[0]["raw_summary"], "20 发 / 19 收 / 1 丢")

    def test_other_type_no_raw_summary(self):
        items = N._issues_gateway(self._res("gateway.high_latency"))
        self.assertIsNone(items[0]["raw_summary"])

    def test_error_res_renders_error_text(self):
        items = N._issues_gateway({"error": "无法获取默认网关"})
        self.assertEqual(len(items), 1)
        self.assertIn("无法获取默认网关", items[0]["text"])


# ────────────────────────────────────────────────────────────────────────────
# B8-B11: dns / route / arp / wifi probe 注册 + helper 通用包装测试
# ────────────────────────────────────────────────────────────────────────────


class TestWrapAsDiagnosticResultHelper(unittest.TestCase):
    """B8-B11 共享 helper: Tester.results dict → DiagnosticResult."""

    def test_empty_results_returns_unknown(self):
        r = N._wrap_as_diagnostic_result({}, "x", "2026-08-31T00:00:00", 0)
        self.assertEqual(r.status, N.Status.UNKNOWN)
        self.assertEqual(r.module_id, "x")
        self.assertEqual(r.duration_ms, 0)

    def test_error_results_returns_error_status(self):
        r = N._wrap_as_diagnostic_result(
            {"error": "boom"}, "x", "2026-08-31T00:00:00", 100)
        # determine_status("错误") -> Status.FATAL
        self.assertIn(r.status, (N.Status.ERROR, N.Status.FATAL))
        self.assertIsNotNone(r.error)
        # v1.8.1 (审计 P1-01): 错误码按文案语义分类, 无特征命中兜底 COMMAND_FAILED
        self.assertEqual(r.error.code, "COMMAND_FAILED")

    def test_error_code_classified_by_message(self):
        """v1.8.1: 超时/权限/依赖缺失 → 对应错误码与 retryable."""
        cases = [
            ({"error": "模块执行超时（超过 30 秒）"}, "TIMEOUT", True),
            ({"error": "权限不足 (需要管理员)"}, "PERMISSION_DENIED", False),
            ({"error": "iperf3.exe 未找到"}, "UNAVAILABLE", False),
            ({"error": "TCP 连接失败"}, "NETWORK_ERROR", True),
        ]
        for res, code, retryable in cases:
            r = N._wrap_as_diagnostic_result(
                res, "x", "2026-08-31T00:00:00", 100)
            self.assertEqual(code, r.error.code, msg=str(res))
            self.assertEqual(retryable, r.error.retryable, msg=str(res))

    def test_wrapped_issue_has_no_faked_confidence(self):
        """v1.8.1 (审计 P1-02): 旧结果包装的 Issue 不再统一填 0.85."""
        r = N._wrap_as_diagnostic_result(
            {"issues": [{"type": "latency", "severity": "warning",
                         "message": "延迟偏高"}],
             "summary": "test"},
            "x", "2026-08-31T00:00:00", 50)
        self.assertIsNone(r.issues[0].confidence)

    def test_critical_issue_elevates_to_error(self):
        r = N._wrap_as_diagnostic_result(
            {"issues": [{"type": "dns_hijack", "severity": "critical",
                         "message": "DNS 劫持", "action": "换 DNS"}],
             "summary": "test"},
            "x", "2026-08-31T00:00:00", 50)
        self.assertEqual(r.status, N.Status.ERROR)
        self.assertEqual(len(r.issues), 1)
        self.assertEqual(r.issues[0].severity, N.Severity.CRITICAL)
        self.assertEqual(r.issues[0].recommendations, ["换 DNS"])

    def test_warning_issue_yields_warning_status(self):
        r = N._wrap_as_diagnostic_result(
            {"issues": [{"type": "latency", "severity": "warning",
                         "message": "延迟偏高"}],
             "summary": "test"},
            "x", "2026-08-31T00:00:00", 50)
        self.assertEqual(r.status, N.Status.WARNING)
        self.assertEqual(r.issues[0].severity, N.Severity.MEDIUM)

    def test_info_issue_does_not_change_status(self):
        r = N._wrap_as_diagnostic_result(
            {"issues": [{"type": "x", "severity": "info", "message": "info"}],
             "summary": "test"},
            "x", "2026-08-31T00:00:00", 50)
        # info issue 不改变状态 -> OK
        self.assertEqual(r.status, N.Status.OK)

    def test_metrics_preserves_full_dict(self):
        """metrics 字段必须完整保留旧 results dict, 供 verdict_fn / 报告渲染."""
        results = {"summary": "x", "issues": [], "foo": "bar",
                   "per_server": [{"dns_server": "1.1.1.1"}]}
        r = N._wrap_as_diagnostic_result(results, "x", "t", 0)
        self.assertEqual(r.metrics["foo"], "bar")
        self.assertEqual(r.metrics["per_server"][0]["dns_server"], "1.1.1.1")


class TestProbesB8B11Registered(unittest.TestCase):
    """B8-B11 4 个 probe 全部注册到 _V2_PROBES."""

    def test_dns_registered(self):
        self.assertIn("dns", N._V2_PROBES)
        self.assertIs(N._V2_PROBES["dns"], N.probe_dns_v2)

    def test_route_registered(self):
        self.assertIn("route", N._V2_PROBES)
        self.assertIs(N._V2_PROBES["route"], N.probe_route_v2)

    def test_arp_registered(self):
        self.assertIn("arp", N._V2_PROBES)
        self.assertIs(N._V2_PROBES["arp"], N.probe_arp_v2)

    def test_wifi_registered(self):
        self.assertIn("wifi", N._V2_PROBES)
        self.assertIs(N._V2_PROBES["wifi"], N.probe_wifi_v2)

    def test_total_5_probes(self):
        """v1.8.4 (P0-03): 11 个 probe (B7-B11 + external/tcpstats/mtu/web/
        bufferbloat/nattype)."""
        self.assertEqual(set(N._V2_PROBES),
                         {"gateway", "dns", "route", "arp", "wifi",
                          "external", "tcpstats", "mtu", "web",
                          "bufferbloat", "nattype"})

    def test_dns_old_tester_still_exists(self):
        """DNSTester 保留 (双轨), 等 B13 删除."""
        self.assertTrue(hasattr(N, "DNSTester"))
        self.assertTrue(callable(N.DNSTester))

    def test_route_old_tester_still_exists(self):
        self.assertTrue(hasattr(N, "RouteTableAnalyzer"))

    def test_arp_old_tester_still_exists(self):
        self.assertTrue(hasattr(N, "ARPAnalyzer"))

    def test_wifi_old_tester_still_exists(self):
        self.assertTrue(hasattr(N, "WiFiAnalyzer"))


class TestProbesB8B11StubRun(unittest.TestCase):
    """用 stub Tester.detect() 验证 probe 路径 (避免真实网络探测)."""

    def _make_stub_tester(self, results):
        """构造一个 detect() 后 self.results = results 的 stub 测试器."""
        cls = type("StubTester", (), {
            "__init__": lambda self: setattr(self, "results", {}),
            "detect": lambda self, callback=None: setattr(self, "results", results),
            "name": "stub",
        })
        return cls

    def test_probe_dns_with_stub(self):
        """probe_dns_v2 调 DNSTester.detect() + wrap."""
        stub_results = {
            "summary": "DNS OK", "issues": [], "assessment": "正常",
            "success_count": 8, "total_count": 8,
            "per_server": [], "detail": [], "timestamp": "2026-08-31T17:00:00",
        }
        with patch.object(N, "DNSTester",
                          self._make_stub_tester(stub_results)):
            result = N.probe_dns_v2(callback=lambda m: None)
        self.assertIsInstance(result, N.DiagnosticResult)
        self.assertEqual(result.module_id, "dns")
        self.assertEqual(result.status, N.Status.OK)
        self.assertEqual(result.metrics["summary"], "DNS OK")

    def test_probe_route_with_stub(self):
        stub_results = {"summary": "路由 OK", "issues": [], "timestamp": "2026-08-31T17:00:00"}
        with patch.object(N, "RouteTableAnalyzer",
                          self._make_stub_tester(stub_results)):
            result = N.probe_route_v2(callback=lambda m: None)
        self.assertEqual(result.module_id, "route")
        self.assertEqual(result.status, N.Status.OK)

    def test_probe_arp_with_stub(self):
        stub_results = {"summary": "ARP OK", "issues": [], "timestamp": "2026-08-31T17:00:00"}
        with patch.object(N, "ARPAnalyzer",
                          self._make_stub_tester(stub_results)):
            result = N.probe_arp_v2(callback=lambda m: None)
        self.assertEqual(result.module_id, "arp")
        self.assertEqual(result.status, N.Status.OK)

    def test_probe_wifi_with_stub(self):
        stub_results = {"summary": "WiFi OK", "issues": [], "timestamp": "2026-08-31T17:00:00"}
        with patch.object(N, "WiFiAnalyzer",
                          self._make_stub_tester(stub_results)):
            result = N.probe_wifi_v2(callback=lambda m: None)
        self.assertEqual(result.module_id, "wifi")
        self.assertEqual(result.status, N.Status.OK)

    def test_probe_issue_propagation(self):
        """probe 把 Tester.results["issues"] 转 dataclass Issue (severity 正确)."""
        stub_results = {
            "summary": "bad", "issues": [{"type": "x", "severity": "critical",
                                          "message": "严重问题",
                                          "detail": "details",
                                          "action": "修复"}],
            "timestamp": "2026-08-31T17:00:00",
        }
        with patch.object(N, "ARPAnalyzer",
                          self._make_stub_tester(stub_results)):
            result = N.probe_arp_v2(callback=lambda m: None)
        self.assertEqual(result.status, N.Status.ERROR)
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.issues[0].id, "x")
        self.assertEqual(result.issues[0].severity, N.Severity.CRITICAL)
        self.assertEqual(result.issues[0].title, "严重问题")
        self.assertEqual(result.issues[0].recommendations, ["修复"])


class TestEvidenceBuilders(unittest.TestCase):
    """P0-03 第一批 Evidence builders (v1.8.2): 字段与 _rule_* 同源."""

    def test_external(self):
        res = {"tcp_ok": 4, "tcp_total": 4, "unreachable_count": 0,
               "avg_loss_pct": 0.0, "avg_rtt_ms": 23.5}
        eids = {e.id for e in N._evidence_external(res)}
        self.assertIn("external.tcp.tcp_ok", eids)
        self.assertIn("external.tcp.unreachable_count", eids)
        self.assertIn("external.ping.avg_loss_pct", eids)
        self.assertIn("external.ping.avg_rtt_ms", eids)
        ok = next(e for e in N._evidence_external(res)
                  if e.id == "external.tcp.tcp_ok")
        self.assertEqual(4, ok.metadata["tcp_total"])

    def test_external_no_tcp_data_skips_tcp_fields(self):
        res = {"tcp_ok": 0, "tcp_total": 0, "avg_loss_pct": 3.0}
        eids = {e.id for e in N._evidence_external(res)}
        self.assertNotIn("external.tcp.tcp_ok", eids)
        self.assertIn("external.ping.avg_loss_pct", eids)

    def test_dns(self):
        ev = N._evidence_dns({"success_count": 2, "total_count": 10})
        self.assertEqual(1, len(ev))
        self.assertEqual("dns.resolve.success_count", ev[0].id)
        self.assertEqual(10, ev[0].metadata["total_count"])
        self.assertEqual([], N._evidence_dns({"success_count": None,
                                              "total_count": 0}))

    def test_wifi_and_tcpstats(self):
        wf = N._evidence_wifi({"overall_interference": "干扰较高"})
        self.assertEqual("wifi.spectrum.overall_interference", wf[0].id)
        self.assertEqual([], N._evidence_wifi({"overall_interference": None}))
        ts = N._evidence_tcpstats({"retrans_rate_pct": 6.0,
                                   "segments_sent": 1000,
                                   "retransmitted": 60})
        self.assertEqual("tcpstats.retrans.retrans_rate_pct", ts[0].id)
        self.assertEqual(1000, ts[0].metadata["segments_sent"])
        self.assertEqual([], N._evidence_tcpstats({"retrans_rate_pct": None}))

    def test_mtu(self):
        res = {"path_mtus": [{"target": "223.5.5.5", "path_mtu": 1500},
                             {"target": "x", "error": "超时", "path_mtu": None}],
               "local_mtus": [{"name": "以太网", "mtu": 1500},
                              {"name": "bad", "mtu": 0}]}
        ev = N._evidence_mtu(res)
        paths = [e for e in ev if e.id == "mtu.probe.path_mtu"]
        ifaces = [e for e in ev if e.id == "mtu.iface.mtu"]
        self.assertEqual(1, len(paths))
        self.assertEqual("223.5.5.5", paths[0].metadata["target"])
        self.assertEqual(1, len(ifaces))
        self.assertEqual("以太网", ifaces[0].metadata["name"])

    def test_web_none_fields_skipped(self):
        ev = N._evidence_web({"ok_count": 3, "total_count": 4,
                              "avg_ttfb_ms": 120, "min_cert_days": None})
        eids = {e.id for e in ev}
        self.assertIn("web.http.ok_count", eids)
        self.assertIn("web.timing.avg_ttfb_ms", eids)
        self.assertNotIn("web.cert.min_cert_days", eids)

    def test_error_or_non_dict_returns_empty(self):
        for builder in (N._evidence_external, N._evidence_dns,
                        N._evidence_wifi, N._evidence_tcpstats,
                        N._evidence_mtu, N._evidence_web,
                        N._evidence_bufferbloat, N._evidence_nattype):
            self.assertEqual([], builder({"error": "超时"}), msg=builder.__name__)
            self.assertEqual([], builder(None), msg=builder.__name__)

    def test_bufferbloat_and_nattype(self):
        """v1.8.4 (P0-03 第二批): 两条新证据源的键与缺失跳过."""
        bb = N._evidence_bufferbloat({"idle_rtt_ms": 8, "loaded_rtt_ms": 208,
                                      "grade": "F (严重)", "issues": []})
        eids = {e.id for e in bb}
        self.assertIn("bufferbloat.load.bloat_ms", eids)     # 缺 bloat_ms → 推导 200
        self.assertIn("bufferbloat.grade.grade", eids)
        self.assertNotIn("bufferbloat.load.load_warning", eids)  # 键缺失跳过
        bloat = next(e for e in bb if e.id == "bufferbloat.load.bloat_ms")
        self.assertEqual(200, bloat.value)
        self.assertEqual(8, bloat.metadata["idle_rtt_ms"])

        nat = N._evidence_nattype({"nat_behavior": "对称型",
                                   "cone_type": "未细分"})
        self.assertEqual({"nattype.stun.nat_behavior", "nattype.stun.cone_type"},
                         {e.id for e in nat})


class TestWrapEvidenceFn(unittest.TestCase):
    """wrap helper 的 evidence_fn 参数 (v1.8.2)."""

    def test_evidence_attached(self):
        r = N._wrap_as_diagnostic_result(
            {"ok": 1}, "external", "2026-09-02T00:00:00", 10,
            evidence_fn=lambda res: [N._ev_item("external", "tcp", "tcp_ok", 4)])
        self.assertEqual(1, len(r.evidence))
        self.assertEqual("external.tcp.tcp_ok", r.evidence[0].id)

    def test_evidence_fn_exception_is_swallowed(self):
        def _boom(res):
            raise RuntimeError("证据生成失败")
        r = N._wrap_as_diagnostic_result(
            {"ok": 1}, "external", "2026-09-02T00:00:00", 10,
            evidence_fn=_boom)
        self.assertEqual([], r.evidence)   # 证据丢弃但主流程不受影响

    def test_non_evidence_items_filtered(self):
        r = N._wrap_as_diagnostic_result(
            {"ok": 1}, "dns", "2026-09-02T00:00:00", 5,
            evidence_fn=lambda res: ["not-evidence", None])
        self.assertEqual([], r.evidence)


class TestP0MigratedProbes(unittest.TestCase):
    """P0-03 第一批 (v1.8.2): external/tcpstats/mtu/web 注册进 V2 双轨."""

    def test_registry_contains_batch(self):
        for key in ("external", "tcpstats", "mtu", "web", "dns", "wifi",
                    "gateway"):
            self.assertIn(key, N._V2_PROBES, msg=key)

    @staticmethod
    def _patch_detect(cls, results):
        def _fake_detect(self, callback=None, **kwargs):
            self.results = results
        return patch.object(cls, "detect", _fake_detect)

    def test_probe_external_v2(self):
        canned = {"targets": [], "tcp_ok": 4, "tcp_total": 4,
                  "unreachable_count": 0, "avg_loss_pct": 0.0,
                  "avg_rtt_ms": 20.0, "issues": []}
        with self._patch_detect(N.ExternalNetworkTester, canned):
            result = N.probe_external_v2(callback=lambda m: None)
        self.assertIsInstance(result, N.DiagnosticResult)
        self.assertEqual("external", result.module_id)
        self.assertEqual(N.Status.OK, result.status)
        self.assertIn("external.tcp.tcp_ok", {e.id for e in result.evidence})
        # 旧口径兼容: metrics 原样保留
        self.assertEqual(4, result.metrics["tcp_ok"])

    def test_probe_tcpstats_v2(self):
        canned = {"segments_sent": 100000, "retransmitted": 9000,
                  "retrans_rate_pct": 9.0, "issues": []}
        with self._patch_detect(N.TCPStatsTester, canned):
            result = N.probe_tcpstats_v2(callback=lambda m: None)
        self.assertEqual("tcpstats", result.module_id)
        self.assertIn("tcpstats.retrans.retrans_rate_pct",
                      {e.id for e in result.evidence})

    def test_probe_mtu_v2(self):
        canned = {"path_mtus": [{"target": "223.5.5.5", "path_mtu": 1492}],
                  "local_mtus": [{"name": "以太网", "mtu": 1500}], "issues": []}
        with self._patch_detect(N.MTUDetector, canned):
            result = N.probe_mtu_v2(callback=lambda m: None)
        self.assertEqual("mtu", result.module_id)
        self.assertIn("mtu.probe.path_mtu", {e.id for e in result.evidence})

    def test_probe_web_v2(self):
        canned = {"ok_count": 3, "total_count": 4, "avg_ttfb_ms": 200,
                  "avg_dns_ms": 30, "avg_tls_ms": 80, "min_cert_days": 45,
                  "issues": []}
        with self._patch_detect(N.WebPageTester, canned), \
             patch.dict(N.WEB_CONFIG, {"targets": []}, deep=True):
            result = N.probe_web_v2(callback=lambda m: None)
        self.assertEqual("web", result.module_id)
        self.assertIn("web.http.ok_count", {e.id for e in result.evidence})

    def test_probe_bufferbloat_v2(self):
        canned = {"idle_rtt_ms": 8, "loaded_rtt_ms": 208, "bloat_ms": 200.0,
                  "grade": "F (严重 Bufferbloat)", "load_warning": False,
                  "issues": []}
        with self._patch_detect(N.BufferbloatTester, canned):
            result = N.probe_bufferbloat_v2(callback=lambda m: None)
        self.assertEqual("bufferbloat", result.module_id)
        self.assertIn("bufferbloat.load.bloat_ms",
                      {e.id for e in result.evidence})

    def test_probe_nattype_v2(self):
        canned = {"nat_behavior": "对称型", "cone_type": "未细分",
                  "issues": []}
        with self._patch_detect(N.NATTypeTester, canned), \
             patch.dict(N.NATTYPE_CONFIG, {"servers": []}, deep=True):
            result = N.probe_nattype_v2(callback=lambda m: None)
        self.assertEqual("nattype", result.module_id)
        self.assertIn("nattype.stun.nat_behavior",
                      {e.id for e in result.evidence})

    def test_probe_error_path_yields_error_result(self):
        """Tester.detect 抛异常 → probe 冒泡 (由 run 路径转「错误」)."""
        def _boom(self, callback=None, **kwargs):
            raise RuntimeError("netsh 失败")
        with patch.object(N.ExternalNetworkTester, "detect", _boom):
            with self.assertRaises(RuntimeError):
                N.probe_external_v2(callback=lambda m: None)

    def test_run_module_timeout_persists_evidence(self):
        """v2 分支: result.evidence → res["_evidence"] (夹带传递, LAST_RUN
        装配时由 _extract_evidence_map 摘出, 不随模块 results 落盘)."""
        fake = N.DiagnosticResult(
            module_id="external", status=N.Status.OK,
            evidence=[N.Evidence(id="external.ping.avg_loss_pct",
                                 source="external", metric="avg_loss_pct",
                                 value=0.0, unit="%")],
            metrics={"tcp_ok": 4, "tcp_total": 4})
        with patch.dict(N._V2_PROBES, {"external": lambda callback=None: fake}):
            status, res = N._run_module_with_timeout("external",
                                                     lambda m: None)
        self.assertEqual("完成", status)
        self.assertEqual(1, len(res["_evidence"]))
        self.assertEqual(4, res["tcp_ok"])   # metrics 不丢

    def test_run_module_timeout_no_evidence_no_key(self):
        fake = N.DiagnosticResult(module_id="mtu", status=N.Status.OK,
                                  metrics={"x": 1})
        with patch.dict(N._V2_PROBES, {"mtu": lambda callback=None: fake}):
            _, res = N._run_module_with_timeout("mtu", lambda m: None)
        self.assertNotIn("_evidence", res)

    def test_extract_evidence_map(self):
        """v1.9.0: LAST_RUN 装配摘键 — results 纯净, 证据走独立映射."""
        full = {
            "external": {"tcp_ok": 4, "_evidence": [{"id": "e1"}]},
            "mtu": {"x": 1},
            "dns": {"a": 1, "_evidence": []},   # 空证据 → 键移除且不进映射
        }
        results, evidence = N._extract_evidence_map(full)
        self.assertEqual({"tcp_ok": 4}, results["external"])
        self.assertEqual({"a": 1}, results["dns"])
        self.assertEqual({"e1"}, {e["id"] for e in evidence["external"]})
        self.assertNotIn("dns", evidence)
        self.assertNotIn("mtu", evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)