# -*- coding: utf-8 -*-
"""预估宽带档位回归 (代码审查 P0-1 · v1.15.0 引入)

背景: `estimate_bandwidth` 此前写成 "实测 × 1.1 后取第一个 >= 修正值的档位",
1.1 修正与"向上取档"叠加 = 双重上偏 —— 实测 100 Mbps 报「约 200 兆」、
实测 1000 Mbps 报「约 2000 兆」。该字符串进客户报告的**绿色**指标
(「预估宽带」), 装维照着它跟客户说档位, 属信任级错误。

正确口径: 实测值应落在「签约档位 × 1.1」这个带内, 取**能容纳该实测值的
最小档位** (measured <= tier * 1.1)。

跑用: cd 到项目根目录, `python tests/test_v1150_bandwidth_tiers.py`
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


class TestBandwidthTierNoOverShoot(unittest.TestCase):
    """档位不得比实测高一整档。"""

    # (实测 Mbps, 期望档位 Mbps) —— 实测值恰好等于档位时必须报该档位本身
    CASES = [
        (30, 30), (50, 50), (100, 100), (200, 200),
        (300, 300), (500, 500), (1000, 1000), (2000, 2000),
    ]

    def test_exact_tier_not_bumped(self):
        for measured, expect in self.CASES:
            with self.subTest(measured=measured):
                est = N.estimate_bandwidth(measured)
                self.assertIsNotNone(est)
                self.assertEqual(est["tier_mbps"], expect,
                                 "实测 %s Mbps 应报 %s 兆, 不得上抬一档"
                                 % (measured, expect))
                self.assertEqual(est["text"], "约 %d 兆" % expect)

    def test_gigabit_not_reported_as_2g(self):
        """回归锚点: 1G 线路曾被报成「约 2000 兆」。"""
        est = N.estimate_bandwidth(1000)
        self.assertEqual(est["text"], "约 1000 兆")

    def test_100m_not_reported_as_200m(self):
        """回归锚点: 100M 线路曾被报成「约 200 兆」。"""
        est = N.estimate_bandwidth(100)
        self.assertEqual(est["text"], "约 100 兆")

    def test_tier_never_exceeds_next_tier(self):
        """通用不变式: 报出的档位不得是「下一个」档位。"""
        for measured, _ in self.CASES:
            est = N.estimate_bandwidth(measured)
            tier = est["tier_mbps"]
            i = N.BANDWIDTH_TIERS.index(tier)
            nxt = (N.BANDWIDTH_TIERS[i + 1]
                   if i + 1 < len(N.BANDWIDTH_TIERS) else None)
            if nxt is not None:
                self.assertLessEqual(measured, tier * 1.1 + 1e-6)


class TestBandwidthTierTolerance(unittest.TestCase):
    """1.1 容差带: 实测偏低仍应落到正确档位, 且不越档。"""

    def test_measured_below_tier_snaps_up_within_10pct(self):
        # 100M 线路实测 95 (协议开销) → 仍是 100 兆
        self.assertEqual(N.estimate_bandwidth(95)["tier_mbps"], 100)
        # 500M 线路实测 460 → 500 兆
        self.assertEqual(N.estimate_bandwidth(460)["tier_mbps"], 500)
        # 30M 线路实测 28 → 30 兆
        self.assertEqual(N.estimate_bandwidth(28)["tier_mbps"], 30)

    def test_measured_deep_below_tier_uses_next(self):
        # 45 Mbps 只能落在 50 兆档 (30 兆档解释不了)
        self.assertEqual(N.estimate_bandwidth(45)["tier_mbps"], 50)

    def test_transparency_fields_kept(self):
        est = N.estimate_bandwidth(95)
        self.assertEqual(est["basis_download_mbps"], 95.0)
        self.assertAlmostEqual(est["adjusted_mbps"], 104.5, places=1)

    def test_invalid_input(self):
        self.assertIsNone(N.estimate_bandwidth(0))
        self.assertIsNone(N.estimate_bandwidth(None))
        self.assertIsNone(N.estimate_bandwidth(-1))


class TestBandwidthUploadCrossCheck(unittest.TestCase):
    """上行交叉校验 (非对称提示) 不受档位修正影响。"""

    def test_asymmetric_ratio_note(self):
        est = N.estimate_bandwidth(100, upload_mbps=4)
        self.assertEqual(est["tier_mbps"], 100)
        self.assertIn("note", est)
        self.assertIn("悬殊", est["note"])

    def test_symmetric_ratio_note(self):
        est = N.estimate_bandwidth(100, upload_mbps=90)
        self.assertEqual(est["tier_mbps"], 100)
        self.assertIn("对称", est["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
