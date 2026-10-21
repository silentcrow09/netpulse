# -*- coding: utf-8 -*-
"""v1.15.2 审查 P1-15b · wan_interruption 分段归因 回归测试。

旧版实现 (审查前):
    tcp_total = ext_res.get("tcp_total", 0)
    tcp_ok    = ext_res.get("tcp_ok", 0)
    if tcp_total <= 0 or tcp_ok > 0:
        return None
    return RootCause(
        severity=Severity.CRITICAL,
        title="WAN 中断 (运营商链路故障)",
        description="网关可达但外网不可达, 故障点在『网关 ↔ 运营商』这一段; 需联系运营商.",
        ...)

缺陷: 「TCP 全不通」有两种成因, 旧版一律断言「运营商链路故障」:
  ① 目标真不可达 (reachability="unreachable", unreachable_count > 0)
  ② 目标主机 ping 得通、TCP 被拦 (reachability="tcp_blocked", unreachable_count == 0)
     —— 阻断点在本机/企业防火墙/代理, 让装维白跑一趟运营商。

注: 规则**从不读** unreachable_count (它读 tcp_ok/tcp_total + gateway.ping.loss_pct);
unreachable_count 是本次修复新引入的判据。字段缺失时必须回落旧行为。

跑用: cd 到项目根目录, `py -3.13 tests/test_v1152_wan_attribution.py`
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _results(unreachable_count=None, tcp_ok=0, tcp_total=4, gw_loss=0.0):
    ext = {"targets": [], "tcp_ok": tcp_ok, "tcp_total": tcp_total, "issues": []}
    if unreachable_count is not None:
        ext["unreachable_count"] = unreachable_count
    gw = {"ping": {"loss_pct": gw_loss, "avg_ms": 3, "jitter_ms": 1}, "issues": []}
    return {"external": ext, "gateway": gw}


class TestWanInterruptionAttribution(unittest.TestCase):
    """TCP 全不通时的归因必须分段。"""

    # ── 闸门 1: 目标可达但 TCP 被拦 → 不得断言运营商故障 ──
    def test_tcp_blocked_not_blamed_on_carrier(self):
        rc = N._rule_wan_interruption(_results(unreachable_count=0))
        self.assertIsNotNone(rc, "仍应出根因 (只是归因不同)")
        blob = f"{rc.title} {rc.description} " + " ".join(rc.recommendations)
        self.assertNotIn("运营商链路故障", rc.title,
                         "TCP 被拦时不得再断言运营商链路故障")
        self.assertNotIn("需联系运营商", rc.description,
                         "TCP 被拦时不得再让装维直接联系运营商")
        self.assertNotIn("联系运营商客服报修", " ".join(rc.recommendations),
                         "TCP 被拦时不得再让装维直接联系运营商")
        self.assertIn("拦截", rc.title + rc.description,
                      "应指向本机/出口侧拦截")

    def test_tcp_blocked_severity_not_critical(self):
        """拦截类问题不该抢占 root_causes[0] (CRITICAL 位)。"""
        rc = N._rule_wan_interruption(_results(unreachable_count=0))
        self.assertNotEqual(N.Severity.CRITICAL, rc.severity,
                            "疑似本机/出口侧拦截不应是 CRITICAL")

    def test_tcp_blocked_recommends_proxy_check(self):
        rc = N._rule_wan_interruption(_results(unreachable_count=0))
        joined = " ".join(rc.recommendations)
        self.assertIn("proxy", joined,
                      "应引导先查代理/防火墙 (与模块级 issue 同口径)")

    # ── 闸门 2: 目标真不可达 → 保持运营商归因 ──
    def test_genuinely_unreachable_still_blames_carrier(self):
        rc = N._rule_wan_interruption(_results(unreachable_count=4))
        self.assertIsNotNone(rc)
        self.assertIn("运营商", rc.title + rc.description,
                      "真不可达时仍应指向运营商")
        self.assertEqual(N.Severity.CRITICAL, rc.severity,
                         "真不可达仍是 CRITICAL")

    # ── 闸门 3: unreachable_count 缺失 → 回落旧行为 (不误伤旧数据) ──
    def test_missing_field_falls_back_to_legacy(self):
        rc = N._rule_wan_interruption(_results(unreachable_count=None))
        self.assertIsNotNone(rc, "字段缺失时应回落旧行为 (仍然出根因)")
        self.assertEqual(N.Severity.CRITICAL, rc.severity,
                         "字段缺失时不得改严重度 (回落旧行为)")
        self.assertIn("运营商", rc.title + rc.description)

    # ── 正向: 前提不满足时不出根因 ──
    def test_gateway_down_does_not_fire(self):
        self.assertIsNone(N._rule_wan_interruption(
            _results(unreachable_count=4, gw_loss=100.0)))

    def test_some_tcp_ok_does_not_fire(self):
        self.assertIsNone(N._rule_wan_interruption(
            _results(unreachable_count=0, tcp_ok=1)))

    def test_external_error_does_not_fire(self):
        r = _results(unreachable_count=4)
        r["external"]["error"] = "模块超时"
        self.assertIsNone(N._rule_wan_interruption(r))

    # ── 闸门 4: 证据链要能支撑新文案 (排除项必须指向「非运营商侧」) ──
    def test_evidence_excludes_carrier_side_when_tcp_blocked(self):
        supports, excludes = N._ev_wan_interruption(_results(unreachable_count=0))
        excl_text = " ".join(str(e.get("text", "")) for e in excludes)
        self.assertIn("非运营商上联", excl_text,
                      "证据链排除项必须有一条能排除运营商侧, 否则撑不住新文案")

    def test_evidence_no_carrier_exclusion_when_really_unreachable(self):
        supports, excludes = N._ev_wan_interruption(_results(unreachable_count=4))
        excl_text = " ".join(str(e.get("text", "")) for e in excludes)
        self.assertNotIn("非运营商上联", excl_text,
                         "真不可达时不得排除运营商侧")

    # ── 闸门 5: 报告层不得再出现「需联系运营商」这类误导表述 ──
    def test_rootcause_text_has_no_direct_carrier_instruction(self):
        rc = N._rule_wan_interruption(_results(unreachable_count=0))
        joined = " ".join([rc.title, rc.description] + list(rc.recommendations))
        self.assertNotIn("需联系运营商", joined)
        self.assertNotIn("联系运营商客服报修", joined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
