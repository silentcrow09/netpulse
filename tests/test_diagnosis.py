# -*- coding: utf-8 -*-
"""Diagnosis 根因引擎单元测试 (阶段 C · v1.3.0 引入)

覆盖: 8 条内置规则 (v1.7.0 +mtu_blackhole +tcp_loss_burst) +
confidence 加权 + Profile 定义
跑用: cd 到项目根目录, `python tests/test_diagnosis.py`
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _ok_gateway():
    return {"ping": {"loss_pct": 0, "avg_ms": 5, "jitter_ms": 1},
            "issues": []}


def _ok_dns():
    return {"success_count": 8, "total_count": 8, "issues": []}


def _ok_bufferbloat():
    """键名/取值与 BufferbloatTester.results 完全一致."""
    return {"idle_rtt_ms": 8, "loaded_rtt_ms": 12, "bloat_ms": 4.0,
            "grade": "A (优秀, 无 Bufferbloat)", "load_warning": False,
            "issues": []}


def _ok_external():
    """键名/取值与 ExternalNetworkTester.results 完全一致."""
    return {"targets": [], "tcp_ok": 4, "tcp_total": 4,
            "unreachable_count": 0, "issues": []}


def _ok_nattype():
    """键名/取值与 NATTypeTester.results 完全一致."""
    return {"nat_behavior": "EIM(锥形)", "cone_type": "未细分",
            "mapped_ip": "1.2.3.4", "mapped_port": 50000, "issues": []}


def _ok_mtu():
    """键名/取值与 MTUDetector.results 一致 (路径=接口 → 无不匹配)."""
    return {"path_mtus": [{"target": "223.5.5.5", "path_mtu": 1500}],
            "local_mtus": [{"name": "以太网", "mtu": 1500}],
            "issues": []}


def _ok_tcpstats():
    """键名/取值与 TCPStatsTester.results 一致 (重传率健康)."""
    return {"segments_sent": 100000, "retransmitted": 120,
            "retrans_rate_pct": 0.12, "issues": []}


def _healthy_full():
    """全健康: 所有规则都不应触发 (含 v1.7.0 统计层模块)."""
    return {
        "gateway": _ok_gateway(),
        "dns": _ok_dns(),
        "wifi": {"overall_interference": "正常", "issues": []},
        "bufferbloat": _ok_bufferbloat(),
        "external": _ok_external(),
        "nattype": _ok_nattype(),
        "mtu": _ok_mtu(),
        "tcpstats": _ok_tcpstats(),
    }


class TestDataclasses(unittest.TestCase):
    """RootCause / DiagnosisReport dataclass + to_dict."""

    def test_rootcause_to_dict_keys(self):
        rc = N.RootCause(id="x", category="DNS", severity=N.Severity.HIGH,
                          title="t", description="d", confidence=0.9,
                          evidence_ids=["e1"], affected_modules=["dns"],
                          recommendations=["r1"])
        d = rc.to_dict()
        for k in ("id", "category", "severity", "title", "description",
                  "confidence", "evidence_ids", "affected_modules",
                  "recommendations"):
            self.assertIn(k, d)
        self.assertEqual(d["severity"], "high")

    def test_diagnosisreport_to_dict(self):
        r = N.DiagnosisReport(root_causes=[], overall_confidence=0.95,
                               timestamp="2026-08-31T18:00:00",
                               rules_evaluated=6, rules_fired=0)
        d = r.to_dict()
        self.assertEqual(d["rules_evaluated"], 6)
        self.assertEqual(d["rules_fired"], 0)
        self.assertEqual(d["root_causes"], [])


class TestConfidenceHelpers(unittest.TestCase):
    """C2 confidence 加权算法."""

    def test_empty_results_zero_confidence(self):
        self.assertEqual(N._module_status_confidence({}), 0.0)

    def test_error_results_zero_confidence(self):
        self.assertEqual(N._module_status_confidence({"error": "x"}), 0.0)

    def test_critical_issues_high_confidence(self):
        r = {"issues": [{"severity": "critical"}]}
        self.assertEqual(N._module_status_confidence(r), 0.95)

    def test_warning_issues_medium_confidence(self):
        r = {"issues": [{"severity": "warning"}]}
        self.assertEqual(N._module_status_confidence(r), 0.7)

    def test_no_issues_low_confidence(self):
        r = {"issues": []}
        self.assertEqual(N._module_status_confidence(r), 0.4)

    def test_rule_confidence_clamp_to_base(self):
        """无证据时钳到 base (避免永远 0.4)."""
        c = N._rule_confidence([], base=0.7)
        self.assertEqual(c, 0.0)  # 实际无 modules 时返回 0
        # 有 modules 但全是 OK (低置信度), 应被 base 抬升
        c = N._rule_confidence([({}, 1.0)], base=0.7)
        self.assertGreaterEqual(c, 0.7)


class TestRuleDNSFailure(unittest.TestCase):
    """规则 1: DNS 故障 (gateway OK + DNS fail > 50%)."""

    def test_normal_dns_no_fire(self):
        report = N.diagnose(_healthy_full())
        self.assertNotIn("dns_failure", [rc.id for rc in report.root_causes])

    def test_high_dns_failure_rate_fires(self):
        r = _healthy_full()
        r["dns"] = {"success_count": 2, "total_count": 10, "issues": []}
        report = N.diagnose(r)
        ids = [rc.id for rc in report.root_causes]
        self.assertIn("dns_failure", ids)

    def test_dns_failure_requires_gateway_up(self):
        """网关不可达时不归 DNS (可能是 WAN 中断)."""
        r = _healthy_full()
        r["dns"] = {"success_count": 2, "total_count": 10, "issues": []}
        r["gateway"] = {"ping": {"loss_pct": 100, "avg_ms": 0}, "issues": []}
        report = N.diagnose(r)
        ids = [rc.id for rc in report.root_causes]
        # 应该归 WAN 而不是 DNS (因为 gateway down)
        self.assertNotIn("dns_failure", ids)

    def test_dns_module_error_no_fire(self):
        """模块自身超时/崩溃 (res={'error':…}) 不是 DNS 网络故障."""
        r = _healthy_full()
        r["dns"] = {"error": "模块执行超时 (120s)"}
        report = N.diagnose(r)
        self.assertNotIn("dns_failure", [rc.id for rc in report.root_causes])


class TestRuleWANInterruption(unittest.TestCase):
    """规则 2: WAN 中断."""

    def test_external_ok_no_fire(self):
        r = _healthy_full()
        r["external"] = _ok_external()
        report = N.diagnose(r)
        self.assertNotIn("wan_interruption", [rc.id for rc in report.root_causes])

    def test_external_all_failed_fires(self):
        """tcp_ok=0 且 tcp_total>0 → 全部外网目标 TCP 不可达."""
        r = _healthy_full()
        r["external"] = {"targets": [], "tcp_ok": 0, "tcp_total": 4,
                          "unreachable_count": 4,
                          "issues": [{"severity": "critical"}]}
        report = N.diagnose(r)
        ids = [rc.id for rc in report.root_causes]
        self.assertIn("wan_interruption", ids)

    def test_wan_requires_gateway_up(self):
        """网关断时不算 WAN (gateway 自己就有问题)."""
        r = _healthy_full()
        r["external"] = {"targets": [], "tcp_ok": 0, "tcp_total": 4,
                          "unreachable_count": 4, "issues": []}
        r["gateway"] = {"ping": {"loss_pct": 100, "avg_ms": 0}, "issues": []}
        report = N.diagnose(r)
        ids = [rc.id for rc in report.root_causes]
        self.assertNotIn("wan_interruption", ids)

    def test_wan_module_error_no_fire(self):
        """模块自身超时/崩溃 (res={'error':…}) 不能当 WAN 中断证据."""
        r = _healthy_full()
        r["external"] = {"error": "模块执行超时 (120s)"}
        report = N.diagnose(r)
        self.assertNotIn("wan_interruption", [rc.id for rc in report.root_causes])

    def test_wan_no_target_data_no_fire(self):
        """tcp_total=0 (无目标数据) 无法判定, 不触发."""
        r = _healthy_full()
        r["external"] = {"targets": [], "tcp_ok": 0, "tcp_total": 0, "issues": []}
        report = N.diagnose(r)
        self.assertNotIn("wan_interruption", [rc.id for rc in report.root_causes])


class TestRuleWifiWeak(unittest.TestCase):
    """规则 3: WiFi 干扰."""

    def test_normal_wifi_no_fire(self):
        report = N.diagnose(_healthy_full())
        self.assertNotIn("wifi_weak", [rc.id for rc in report.root_causes])

    def test_high_interference_fires(self):
        r = _healthy_full()
        r["wifi"] = {"overall_interference": "干扰较高", "issues": []}
        report = N.diagnose(r)
        ids = [rc.id for rc in report.root_causes]
        self.assertIn("wifi_weak", ids)

    def test_severe_interference_critical_severity(self):
        r = _healthy_full()
        r["wifi"] = {"overall_interference": "严重干扰",
                      "issues": [{"severity": "critical"}]}
        report = N.diagnose(r)
        wifi_rc = next((rc for rc in report.root_causes if rc.id == "wifi_weak"), None)
        self.assertIsNotNone(wifi_rc)
        self.assertEqual(wifi_rc.severity, N.Severity.CRITICAL)


class TestRuleBufferbloat(unittest.TestCase):
    """规则 4: Bufferbloat 严重."""

    def test_a_grade_no_fire(self):
        """健康网络 (真实键名+真实等级文案) 绝不能触发."""
        report = N.diagnose(_healthy_full())
        self.assertNotIn("bufferbloat", [rc.id for rc in report.root_causes])

    def test_f_grade_fires_critical(self):
        r = _healthy_full()
        r["bufferbloat"] = {"idle_rtt_ms": 8, "loaded_rtt_ms": 200,
                             "bloat_ms": 192.0, "grade": "F (很差)",
                             "load_warning": False, "issues": []}
        report = N.diagnose(r)
        bb_rc = next((rc for rc in report.root_causes if rc.id == "bufferbloat"), None)
        self.assertIsNotNone(bb_rc)
        self.assertEqual(bb_rc.severity, N.Severity.CRITICAL)

    def test_d_grade_fires_high(self):
        r = _healthy_full()
        r["bufferbloat"] = {"idle_rtt_ms": 8, "loaded_rtt_ms": 100,
                             "bloat_ms": 92.0, "grade": "D (较差)",
                             "load_warning": False, "issues": []}
        report = N.diagnose(r)
        bb_rc = next((rc for rc in report.root_causes if rc.id == "bufferbloat"), None)
        self.assertIsNotNone(bb_rc)
        self.assertEqual(bb_rc.severity, N.Severity.HIGH)

    def test_load_warning_no_fire(self):
        """负载未建立 (测速源不可用) 结果不可信, 不触发."""
        r = _healthy_full()
        r["bufferbloat"] = {"idle_rtt_ms": 8, "loaded_rtt_ms": 500,
                             "bloat_ms": 492.0,
                             "grade": "无法判定 (负载未建立, 测速源不可用)",
                             "load_warning": True, "issues": ["测速源不可用"]}
        report = N.diagnose(r)
        self.assertNotIn("bufferbloat", [rc.id for rc in report.root_causes])

    def test_module_error_no_fire(self):
        r = _healthy_full()
        r["bufferbloat"] = {"error": "模块执行超时 (120s)"}
        report = N.diagnose(r)
        self.assertNotIn("bufferbloat", [rc.id for rc in report.root_causes])


class TestRuleGatewayLoss(unittest.TestCase):
    """规则 5: 网关丢包."""

    def test_zero_loss_no_fire(self):
        report = N.diagnose(_healthy_full())
        self.assertNotIn("gateway_loss", [rc.id for rc in report.root_causes])

    def test_5pct_loss_fires(self):
        r = _healthy_full()
        r["gateway"] = {"ping": {"loss_pct": 5.0, "avg_ms": 8}, "issues": []}
        report = N.diagnose(r)
        ids = [rc.id for rc in report.root_causes]
        self.assertIn("gateway_loss", ids)

    def test_20pct_loss_critical(self):
        r = _healthy_full()
        r["gateway"] = {"ping": {"loss_pct": 25.0, "avg_ms": 20},
                         "issues": [{"severity": "critical"}]}
        report = N.diagnose(r)
        gl_rc = next((rc for rc in report.root_causes if rc.id == "gateway_loss"), None)
        self.assertIsNotNone(gl_rc)
        self.assertEqual(gl_rc.severity, N.Severity.CRITICAL)


class TestRuleNATRestricted(unittest.TestCase):
    """规则 6: NAT 受限."""

    def test_full_cone_no_fire(self):
        report = N.diagnose(_healthy_full())
        self.assertNotIn("nat_restricted", [rc.id for rc in report.root_causes])

    def test_symmetric_fires(self):
        """nat_behavior='对称型' (两台 STUN 映射不一致) → 触发."""
        r = _healthy_full()
        r["nattype"] = {"nat_behavior": "对称型", "cone_type": "—",
                         "mapped_ip": "1.2.3.4", "mapped_port": 50000,
                         "issues": []}
        report = N.diagnose(r)
        ids = [rc.id for rc in report.root_causes]
        self.assertIn("nat_restricted", ids)

    def test_udp_blocked_no_fire(self):
        """UDP 受阻只判 '未知', 不是对称型证据."""
        r = _healthy_full()
        r["nattype"] = {"nat_behavior": "未知(UDP受阻)", "cone_type": "—",
                         "issues": []}
        report = N.diagnose(r)
        self.assertNotIn("nat_restricted", [rc.id for rc in report.root_causes])

    def test_module_error_no_fire(self):
        r = _healthy_full()
        r["nattype"] = {"error": "模块执行超时 (120s)"}
        report = N.diagnose(r)
        self.assertNotIn("nat_restricted", [rc.id for rc in report.root_causes])


class TestRuleMtuBlackhole(unittest.TestCase):
    """规则 7 (v1.7.0): MTU 黑洞 — 路径 MTU 显著小于本机接口."""

    def _mtu(self, path, local=1500):
        return {"path_mtus": [{"target": "223.5.5.5", "path_mtu": path}],
                "local_mtus": [{"name": "以太网", "mtu": local}],
                "issues": []}

    def test_path_1280_fires_confidence_075(self):
        r = _healthy_full()
        r["mtu"] = self._mtu(1280)
        report = N.diagnose(r)
        rc = next((x for x in report.root_causes if x.id == "mtu_blackhole"), None)
        self.assertIsNotNone(rc)
        self.assertEqual(rc.severity, N.Severity.HIGH)
        self.assertAlmostEqual(rc.confidence, 0.75)
        self.assertIn("差 220", rc.title)

    def test_tcp_retrans_corroborates_to_092(self):
        r = _healthy_full()
        r["mtu"] = self._mtu(1280)
        r["tcpstats"] = {"segments_sent": 200000, "retransmitted": 16000,
                         "retrans_rate_pct": 8.0, "issues": []}
        report = N.diagnose(r)
        rc = next((x for x in report.root_causes if x.id == "mtu_blackhole"), None)
        self.assertIsNotNone(rc)
        self.assertAlmostEqual(rc.confidence, 0.92)

    def test_pppoe_1492_not_fired(self):
        """PPPoE 场景 1492 vs 1500 (差 8) 不误报."""
        r = _healthy_full()
        r["mtu"] = self._mtu(1492)
        report = N.diagnose(r)
        self.assertNotIn("mtu_blackhole", [x.id for x in report.root_causes])

    def test_module_error_not_fired(self):
        r = _healthy_full()
        r["mtu"] = {"error": "模块执行超时 (120s)"}
        report = N.diagnose(r)
        self.assertNotIn("mtu_blackhole", [x.id for x in report.root_causes])

    def test_no_valid_path_data_not_fired(self):
        """全部探测失败 (path_mtu=None) 时无从对比, 不触发."""
        r = _healthy_full()
        r["mtu"] = {"path_mtus": [{"target": "x", "error": "ICMP 被过滤",
                                   "path_mtu": None}],
                    "local_mtus": [{"name": "以太网", "mtu": 1500}],
                    "issues": []}
        report = N.diagnose(r)
        self.assertNotIn("mtu_blackhole", [x.id for x in report.root_causes])

    def test_evidence_builder_registered(self):
        self.assertIn("mtu_blackhole", N._RC_EVIDENCE_BUILDERS)


class TestRuleTcpLossBurst(unittest.TestCase):
    """规则 8 (v1.7.0): TCP 传输层丢包 — 开机累计重传率 ≥5%."""

    def test_6pct_fires_medium(self):
        r = _healthy_full()
        r["tcpstats"] = {"segments_sent": 200000, "retransmitted": 12000,
                         "retrans_rate_pct": 6.0, "issues": []}
        report = N.diagnose(r)
        rc = next((x for x in report.root_causes if x.id == "tcp_loss_burst"), None)
        self.assertIsNotNone(rc)
        self.assertEqual(rc.severity, N.Severity.MEDIUM)
        self.assertAlmostEqual(rc.confidence, 0.70)
        self.assertIn("开机累计", rc.description)   # 口径警示必须带上

    def test_3pct_not_fired(self):
        """1%~5% 留在模块 issues 提示, 不升级根因."""
        r = _healthy_full()
        r["tcpstats"] = {"segments_sent": 200000, "retransmitted": 6000,
                         "retrans_rate_pct": 3.0, "issues": []}
        report = N.diagnose(r)
        self.assertNotIn("tcp_loss_burst", [x.id for x in report.root_causes])

    def test_module_error_not_fired(self):
        r = _healthy_full()
        r["tcpstats"] = {"error": "模块执行超时 (120s)"}
        report = N.diagnose(r)
        self.assertNotIn("tcp_loss_burst", [x.id for x in report.root_causes])

    def test_evidence_builder_registered(self):
        self.assertIn("tcp_loss_burst", N._RC_EVIDENCE_BUILDERS)


class TestDiagnoseMain(unittest.TestCase):
    """diagnose() 主入口 + overall_confidence 加权."""

    def test_healthy_returns_zero_root_causes(self):
        report = N.diagnose(_healthy_full())
        self.assertEqual(len(report.root_causes), 0)
        self.assertEqual(report.overall_confidence, 1.0)
        self.assertEqual(report.rules_fired, 0)
        self.assertEqual(report.rules_evaluated, 8)

    def test_multiple_root_causes_weighted_confidence(self):
        r = _healthy_full()
        r["dns"] = {"success_count": 2, "total_count": 10, "issues": []}
        r["wifi"] = {"overall_interference": "严重干扰",
                      "issues": [{"severity": "critical"}]}
        report = N.diagnose(r)
        self.assertGreaterEqual(len(report.root_causes), 2)
        # overall_confidence 应在 0-1 之间
        self.assertGreater(report.overall_confidence, 0.0)
        self.assertLessEqual(report.overall_confidence, 1.0)
        self.assertGreater(report.rules_fired, 1)

    def test_root_causes_sorted_by_severity(self):
        """v1.5.3: root_causes 按严重度降序 — [0] 被 HTML 报告的模块折叠
        策略当作「首要根因」, 注册表顺序 (dns 在前) 会让 HIGH 的 dns_failure
        压住 CRITICAL 的 wan_interruption, 最严重问题的证据反被折叠。"""
        def _rc(rid, sev):
            return N.RootCause(id=rid, category="测试", severity=sev,
                               title=rid, description="")
        fake_rules = [
            lambda rd: _rc("dns_failure", N.Severity.HIGH),
            lambda rd: _rc("wan_interruption", N.Severity.CRITICAL),
            lambda rd: _rc("wifi_weak", N.Severity.MEDIUM),
            lambda rd: None,
            lambda rd: _rc("gateway_loss", N.Severity.HIGH),
            lambda rd: None,
        ]
        orig = N.ALL_RULES
        N.ALL_RULES = fake_rules
        try:
            report = N.diagnose({})
        finally:
            N.ALL_RULES = orig
        ids = [rc.id for rc in report.root_causes]
        # CRITICAL 最前; 两个 HIGH 先于 MEDIUM, 且同级保持注册表顺序
        # (dns_failure 在 gateway_loss 前)
        self.assertEqual(ids, ["wan_interruption", "dns_failure",
                               "gateway_loss", "wifi_weak"])

    def test_empty_input_zero_rules(self):
        report = N.diagnose({})
        self.assertEqual(len(report.root_causes), 0)
        self.assertEqual(report.rules_fired, 0)


class TestProfiles(unittest.TestCase):
    """C3: 5 个 Profile 定义."""

    def test_5_profiles_defined(self):
        self.assertEqual(len(N.DIAGNOSE_PROFILES), 5)
        for name in ("slow", "disconnect", "web", "gaming", "wifi"):
            self.assertIn(name, N.DIAGNOSE_PROFILES)

    def test_slow_profile_modules(self):
        mods = N.DIAGNOSE_PROFILES["slow"]
        # 期望: gateway / wifi / speedtest / bufferbloat / tcp / dns
        for m in ("gateway", "wifi", "speedtest", "bufferbloat", "tcp", "dns"):
            self.assertIn(m, mods)

    def test_disconnect_profile_modules(self):
        mods = N.DIAGNOSE_PROFILES["disconnect"]
        self.assertIn("gateway", mods)
        self.assertIn("external", mods)
        self.assertIn("dns", mods)

    def test_all_profile_modules_in_registry(self):
        """Profile 里的模块 key 都必须在 MODULE_REGISTRY 注册."""
        for name, mods in N.DIAGNOSE_PROFILES.items():
            for m in mods:
                self.assertIn(m, N.MODULE_MAP,
                              f"profile '{name}' 的模块 '{m}' 不在 MODULE_MAP")


class TestProfileRulesV17(unittest.TestCase):
    """v1.7.0: PROFILE_RULES 8 条注册 + 场景过滤纳入统计层新规则."""

    def test_registry_has_8_rules(self):
        self.assertEqual(len(N._RULE_BY_ID), 8)
        self.assertIn("mtu_blackhole", N._RULE_BY_ID)
        self.assertIn("tcp_loss_burst", N._RULE_BY_ID)

    def test_profile_rule_ids_all_exist(self):
        for scene, rules in N.PROFILE_RULES.items():
            for rid in rules:
                self.assertIn(rid, N._RULE_BY_ID,
                              f"PROFILE_RULES[{scene}] 的 {rid} 不在注册表")

    def test_web_gaming_include_new_rules(self):
        """网页/游戏场景是 MTU 黑洞典型受害面, 必须纳入."""
        for scene in ("web", "gaming"):
            self.assertIn("mtu_blackhole", N.PROFILE_RULES[scene])
            self.assertIn("tcp_loss_burst", N.PROFILE_RULES[scene])

    def test_slow_includes_tcp_loss_only(self):
        """网慢场景看传输层丢包; MTU 由 diagnose 补采模块覆盖, 不占场景过滤."""
        self.assertIn("tcp_loss_burst", N.PROFILE_RULES["slow"])
        self.assertNotIn("mtu_blackhole", N.PROFILE_RULES["slow"])

    def test_disconnect_excludes_new_rules(self):
        """掉线场景聚焦连通性, 不掺 MTU/重传."""
        self.assertNotIn("mtu_blackhole", N.PROFILE_RULES["disconnect"])
        self.assertNotIn("tcp_loss_burst", N.PROFILE_RULES["disconnect"])

    def test_slow_diagnose_evaluates_5_rules(self):
        """slow 场景命中过滤时 rules_evaluated = 过滤条数 (5)."""
        r = _healthy_full()
        r["wifi"] = {"overall_interference": "干扰较高", "issues": []}
        report = N.diagnose(r, rule_filter="slow")
        self.assertIn("wifi_weak", [x.id for x in report.root_causes])
        self.assertEqual(report.rules_evaluated, 5)

    def test_slow_profile_collects_tcpstats(self):
        """slow 场景补采 tcpstats 模块 (重传率判据的数据源)."""
        self.assertIn("tcpstats", N.DIAGNOSE_PROFILES["slow"])


if __name__ == "__main__":
    unittest.main(verbosity=2)