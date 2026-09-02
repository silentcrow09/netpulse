# -*- coding: utf-8 -*-
"""MTU 回环口误报回归测试 (v1.9.3)

背景: Windows 回环口 (Loopback Pseudo-Interface 1) 的 NlMtu=4294967295
(0xFFFFFFFF, -1 无符号) 被收进 local_mtus 后, 规则 max() 伪判出
"路径 1500 < 接口 4294967295, 差 4294965795" 的 MTU 黑洞, 且修复建议
写占位符 "接口名" 让用户自己去找接口。

覆盖: _clean_local_mtus 过滤 / _rule_mtu_blackhole 判定口径 (egress 优先)
/ 建议带真实接口名 / 证据链不含回环值 / _svg_ping_line 峰值红点阈值 /
网关 verdict "<1ms" 文案。

跑用: cd 到项目根目录, `python tests/test_mtu_loopback_regression.py`
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _mtu_ctx(local, path=1500):
    """拼一个诊断上下文: mtu + 低重传 tcpstats."""
    return {
        "mtu": {"path_mtus": [{"target": "223.5.5.5", "path_mtu": path}],
                "local_mtus": local},
        "tcpstats": {"retrans_rate_pct": 0.5},
    }


class TestCleanLocalMtus(unittest.TestCase):
    def test_loopback_and_invalid_removed(self):
        raw = [
            {"interface": "Loopback Pseudo-Interface 1", "mtu": 4294967295},
            {"interface": "以太网", "mtu": 1500, "egress": True},
            {"interface": "ZeroTier One [x]", "mtu": 2800},
            {"interface": "坏值", "mtu": 0},
            {"interface": "坏值2", "mtu": -1},
        ]
        clean = N._clean_local_mtus(raw)
        mtus = [x["mtu"] for x in clean]
        self.assertNotIn(4294967295, mtus)
        self.assertNotIn(0, mtus)
        self.assertEqual(sorted(mtus), [1500, 2800])
        # 保留原字段 (interface / mtu / egress)
        eg = [x for x in clean if x.get("egress")][0]
        self.assertEqual(eg["interface"], "以太网")

    def test_garbage_input_returns_empty(self):
        self.assertEqual(N._clean_local_mtus(None), [])
        self.assertEqual(N._clean_local_mtus([None, "x", {"mtu": None}]), [])


class TestRuleMtuBlackhole(unittest.TestCase):
    def test_loopback_does_not_trigger(self):
        """用户实测现场: 出口以太网 1500 + 回环口 4294967295 → 不得命中."""
        ctx = _mtu_ctx([
            {"interface": "以太网", "mtu": 1500, "egress": True},
            {"interface": "Loopback Pseudo-Interface 1", "mtu": 4294967295},
        ])
        self.assertIsNone(N._rule_mtu_blackhole(ctx))

    def test_egress_preferred_over_vpn_iface(self):
        """出口 1500 与路径 1500 相符 → 即使列表里有 VPN 2800 也不命中."""
        ctx = _mtu_ctx([
            {"interface": "ZeroTier One [x]", "mtu": 2800},
            {"interface": "以太网", "mtu": 1500, "egress": True},
        ])
        self.assertIsNone(N._rule_mtu_blackhole(ctx))

    def test_egress_missing_falls_back_to_max_with_name(self):
        """无 egress 标记 (老数据/异常): 退回有效最大值, 建议直接给接口名."""
        ctx = _mtu_ctx([
            {"interface": "ZeroTier One [x]", "mtu": 2800},
            {"interface": "以太网", "mtu": 1500},
        ])
        rc = N._rule_mtu_blackhole(ctx)
        self.assertIsNotNone(rc)
        self.assertIn("接口 2800", rc.title)
        rec0 = rc.recommendations[0]
        self.assertIn('subinterface "ZeroTier One [x]" mtu=1500', rec0)
        self.assertNotIn("接口名", rec0)

    def test_real_mismatch_still_fires(self):
        """真出口受限 (VPN 出口 2800 走 1500 通道): 该报还是要报, 且建议带 egress 名."""
        ctx = _mtu_ctx([
            {"interface": "ZeroTier One [x]", "mtu": 2800, "egress": True},
        ], path=1500)
        rc = N._rule_mtu_blackhole(ctx)
        self.assertIsNotNone(rc)
        self.assertIn("1500", rc.title)
        self.assertIn('subinterface "ZeroTier One [x]" mtu=1500',
                      rc.recommendations[0])


class TestEvidenceMtu(unittest.TestCase):
    def test_evidence_no_loopback_value(self):
        ctx = _mtu_ctx([
            {"interface": "Loopback Pseudo-Interface 1", "mtu": 4294967295},
            {"interface": "以太网", "mtu": 1500},
        ])
        supports, _ = N._ev_mtu_blackhole(ctx)
        self.assertTrue(supports)
        for s in supports:
            self.assertNotIn("4294967295", s["text"])
        self.assertTrue(any("接口 以太网 MTU = 1500" in s["text"]
                            for s in supports))

    def test_evidence_map_defensive_range(self):
        """老 exe 快照的 evidence map 残留回环值 → 转写时按有效区间过滤."""
        evd = {"mtu": [
            {"id": "mtu.probe.path_mtu", "value": 1500,
             "metadata": {"target": "223.5.5.5"}},
            {"id": "mtu.iface.mtu", "value": 4294967295,
             "metadata": {"interface": "Loopback Pseudo-Interface 1"}},
            {"id": "mtu.iface.mtu", "value": 1500,
             "metadata": {"interface": "以太网"}},
        ]}
        supports, _ = N._ev_mtu_blackhole({}, evd)
        for s in supports:
            self.assertNotIn("4294967295", s["text"])
        self.assertTrue(any("接口 以太网 MTU = 1500" in s["text"]
                            for s in supports))


class TestPingLinePeak(unittest.TestCase):
    def test_all_zero_no_red_dot_has_zero_scale(self):
        s = N._svg_ping_line([0] * 20)
        self.assertIn("0ms", s)
        self.assertNotIn("dc2626", s)

    def test_1ms_peak_no_red_dot(self):
        """局域网 1ms 峰值不得标红 (会被误读为故障点)."""
        s = N._svg_ping_line([0] * 7 + [1] + [0] * 12)
        self.assertNotIn("dc2626", s)

    def test_high_peak_red_with_title(self):
        s = N._svg_ping_line([2, 3, 80, 5, 4])
        self.assertIn("dc2626", s)
        self.assertIn("峰值 80ms", s)


class TestVerdictText(unittest.TestCase):
    def test_avg_zero_with_samples_shows_lt1ms(self):
        v = N._verdict_gateway({"gateway": "192.168.1.1",
                                "ping": {"avg_ms": 0, "loss_pct": 0,
                                         "jitter_ms": 0, "rtts": [0] * 5}})
        self.assertIn("平均 <1ms", v)

    def test_real_avg_unchanged(self):
        v = N._verdict_gateway({"gateway": "192.168.1.1",
                                "ping": {"avg_ms": 18, "loss_pct": 0,
                                         "jitter_ms": 3, "rtts": [18] * 5}})
        self.assertIn("平均 18ms", v)


if __name__ == "__main__":
    unittest.main(verbosity=2)
