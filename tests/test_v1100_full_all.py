# -*- coding: utf-8 -*-
"""v1.10.0 全量口径 + tcpcc 多目标轮转压测回归 (mock 隔离, 不碰真实网络)。

验证点:
  F1  full_module_keys() = 全部 23 模块含压力级 tcpcc (菜单 0 / CLI all 口径)
  F2  all_module_keys() = 22 模块排除 tcpcc (debug-bundle 静默口径, 审计 §12)
  F3  parse_choice("0"/"all"/"*") 返回全量含 tcpcc, 不再打印"已排除"提示
  F4  _ladder(4000) = 50..4000 八级; _module_timeout("tcpcc") 随级数伸缩
  F5  _pick_targets custom: 非法端口/预检不可用 → 空池; 可用 → 单目标池
  F6  _pick_targets 默认候选: 预检通过者全部入池 (不再"首个即停")
  F7  _run_ladder round-robin: 连接轮转分配到目标池, 单 IP 压力 ≈ need/N
  F8  CONFIG/CLI 默认上限 4000
"""
import asyncio
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


class TestFullKeys(unittest.TestCase):
    """F1-F3: "全部"口径拆分 — 显式 all 含压力级, debug-bundle 静默仍排除。"""

    def test_full_contains_stress(self):
        full = np.full_module_keys()
        self.assertEqual(len(full), len(np.MODULE_REGISTRY))
        self.assertIn("tcpcc", full)

    def test_all_excludes_stress_for_debug_bundle(self):
        ak = np.all_module_keys()
        self.assertNotIn("tcpcc", ak)
        self.assertEqual(len(ak), len(np.MODULE_REGISTRY) - len(np.STRESS_MODULE_KEYS))

    def test_parse_choice_zero_is_full(self):
        with mock.patch("builtins.print"):
            for ch in ("0", "all", "*"):
                keys = np.parse_choice(ch)
                self.assertIn("tcpcc", keys, f"菜单 {ch} 应含压力级 tcpcc")
                self.assertEqual(len(keys), len(np.MODULE_REGISTRY))

    def test_stress_hint_gone(self):
        # "已排除"提示函数已删除 (all 现在含压力级, 旧提示会误导)
        self.assertFalse(hasattr(np, "_stress_excluded_hint"))


class TestLadderAndTimeout(unittest.TestCase):
    """F4: 阶梯与超时随默认 4000 伸缩。"""

    def test_ladder_4000(self):
        t = np.TCPConcurrencyTester()
        self.assertEqual(t._ladder(4000),
                         [50, 100, 200, 400, 800, 1600, 3200, 4000])

    def test_timeout_scales_with_levels(self):
        # 8 级 → 30 + 12*8 + 10 = 136s (旧 1600 是 6 级 → 112s)
        np.TCPCC_CONFIG["max"] = 4000
        try:
            self.assertEqual(np._module_timeout("tcpcc"), 136)
        finally:
            np.TCPCC_CONFIG["max"] = 4000

    def test_default_4000(self):
        self.assertEqual(np.CONFIG["tcpcc"]["max"], 4000)
        t = np.TCPConcurrencyTester()
        with mock.patch.object(t, "_pick_targets", return_value=([], "", [])):
            t.detect()          # 无可用目标 → 早退, 但可观察 mx 无异常即可
        # detect 早退路径不携带 max_concurrency; 参数默认由签名保证
        import inspect
        sig = inspect.signature(np.TCPConcurrencyTester.detect)
        self.assertEqual(sig.parameters["max_concurrency"].default, 4000)


class TestPickTargets(unittest.TestCase):
    """F5-F6: 目标池构建。"""

    def setUp(self):
        self.t = np.TCPConcurrencyTester()

    def test_custom_bad_port(self):
        addrs, label, recs = self.t._pick_targets("no-port-here")
        self.assertEqual(addrs, [])
        self.assertIn("目标需含端口", recs[0]["error"])

    def test_custom_unreachable(self):
        with mock.patch.object(np, "_tcping_ms", return_value=None):
            addrs, label, recs = self.t._pick_targets("223.5.5.5:53")
        self.assertEqual(addrs, [])
        self.assertEqual(label, "223.5.5.5:53")

    def test_custom_ok_single_pool(self):
        with mock.patch.object(np, "_tcping_ms", return_value=5.0):
            addrs, label, recs = self.t._pick_targets("192.168.1.10:5201")
        self.assertEqual(addrs, [("192.168.1.10", 5201)])
        self.assertEqual(label, "192.168.1.10:5201")

    def test_candidates_pool_all_pass(self):
        rec_ok = {"success_rate": 100.0}
        with mock.patch.object(self.t, "_concurrency_precheck",
                               return_value=dict(rec_ok)):
            addrs, label, recs = self.t._pick_targets(None)
        self.assertEqual(len(addrs), len(np.TCPConcurrencyTester.CANDIDATE_TARGETS))
        self.assertIn("目标轮转", label)
        self.assertEqual(len(recs), len(np.TCPConcurrencyTester.CANDIDATE_TARGETS))

    def test_candidates_pool_partial(self):
        """两个通过一个被限流 → 池只含通过的 2 个 (原版首个通过即停)。"""
        cands = np.TCPConcurrencyTester.CANDIDATE_TARGETS
        seq = [{"host": cands[0][0], "port": 53, "success_rate": 100.0},
               {"host": cands[1][0], "port": 53, "success_rate": 40.0},
               {"host": cands[2][0], "port": 53, "success_rate": 95.0}]
        with mock.patch.object(self.t, "_concurrency_precheck",
                               side_effect=[dict(r) for r in seq]):
            addrs, label, recs = self.t._pick_targets(None)
        self.assertEqual(len(addrs), 2)
        self.assertIn(f"{cands[0][0]}:{cands[0][1]}", label)
        self.assertIn(f"{cands[2][0]}:{cands[2][1]}", label)
        self.assertNotIn(f"{cands[1][0]}:", label)

    def test_candidates_none_pass(self):
        with mock.patch.object(self.t, "_concurrency_precheck",
                               return_value={"success_rate": 10.0}):
            addrs, label, recs = self.t._pick_targets(None)
        self.assertEqual(addrs, [])
        self.assertEqual(label, "")


class TestRunLadderRoundRobin(unittest.TestCase):
    """F7: 每级补建连接按 round-robin 分配到目标池。"""

    def test_round_robin_distribution(self):
        t = np.TCPConcurrencyTester()
        seen = []

        async def fake_connect(addr, held, stats):
            seen.append(addr)
            stats["ok"] += 1
            return True

        addrs = [("10.0.0.1", 53), ("10.0.0.2", 53)]
        with mock.patch.object(t, "_connect_one", side_effect=fake_connect):
            records = asyncio.run(t._run_ladder(addrs, 50, None))
        self.assertEqual(len(seen), 50)
        self.assertEqual(seen.count(addrs[0]), 25)
        self.assertEqual(seen.count(addrs[1]), 25)
        # 交错 (相邻连接不同目标), 不是前一半后一半
        self.assertNotEqual(seen[0], seen[1])
        self.assertEqual(records[-1]["level"], 50)

    def test_single_target_unchanged(self):
        """单目标 (custom) 行为与旧版一致: 全部打到同一 addr。"""
        t = np.TCPConcurrencyTester()
        seen = []

        async def fake_connect(addr, held, stats):
            seen.append(addr)
            stats["ok"] += 1
            return True

        with mock.patch.object(t, "_connect_one", side_effect=fake_connect):
            asyncio.run(t._run_ladder([("10.0.0.9", 53)], 50, None))
        self.assertEqual(set(seen), {("10.0.0.9", 53)})


if __name__ == "__main__":
    unittest.main(verbosity=1)
