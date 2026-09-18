"""v1.12.2 并行模式带宽敏感模块独占跑 回归测试。

背景: 菜单 0 / CLI --parallel 并发跑多模块时, 测速的下载/上传窗口里
网页体检下载、LAN 扫描等同时抢带宽 → 全量报告测速普遍偏低, 与单独
测速报告不一致。修复: 并行阶段只跑普通模块, speedtest/bufferbloat/
iperf3/tcpcc (EXCLUSIVE_NET_MODULE_KEYS) 在并发阶段结束后逐个独占跑。

测试全部 mock _run_module_with_timeout (无真实网络), 用时间戳区间
断言独占语义, 用 Barrier 断言普通模块确实并发。
"""
import threading
import time
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np

EXCLUSIVE = np.EXCLUSIVE_NET_MODULE_KEYS


class TestExclusiveNetModules(unittest.TestCase):
    """并行 runner: 普通模块先并发, 独占模块后串行。"""

    def _run(self, keys, max_workers=4):
        """跑 _run_diagnostics_parallel, 记录每个模块的执行区间。

        返回 (results, full, calls); calls 为 [(key, start, end)]，
        时间用 time.monotonic。
        """
        calls = []
        lock = threading.Lock()

        def fake_run(key, cb):
            start = time.monotonic()
            # 独占模块短睡, 普通模块长睡: 若独占模块混入并发阶段,
            # 区间断言会立刻暴露
            time.sleep(0.02 if key in EXCLUSIVE else 0.08)
            end = time.monotonic()
            with lock:
                calls.append((key, start, end))
            return "完成", {"key": key}

        with mock.patch.object(np, "_run_module_with_timeout",
                               side_effect=fake_run), \
             mock.patch.object(np, "_safe_print"):
            results, full = np._run_diagnostics_parallel(
                keys, max_workers=max_workers, total=len(keys))
        return results, full, calls

    def test_membership(self):
        # 独占集合 = 容量性能家族四模块 (写死, 防误改扩大/缩小范围)
        self.assertEqual(EXCLUSIVE,
                         ("speedtest", "bufferbloat", "iperf3", "tcpcc"))

    def test_solo_after_all_normal_finished(self):
        # 全量口径: 最后一个普通模块结束时间 <= 最早独占模块开始时间
        keys = [k for k, _, _ in np.MODULE_REGISTRY]
        _, _, calls = self._run(keys)
        normal = [c for c in calls if c[0] not in EXCLUSIVE]
        solo = [c for c in calls if c[0] in EXCLUSIVE]
        self.assertEqual(len(normal), len(keys) - 4)
        self.assertEqual(len(solo), 4)
        self.assertGreaterEqual(min(c[1] for c in solo),
                                max(c[2] for c in normal))

    def test_solo_modules_serial(self):
        # 独占模块彼此不重叠 (逐个跑)
        _, _, calls = self._run(list(EXCLUSIVE))
        ordered = sorted(calls, key=lambda c: c[1])
        self.assertEqual(len(ordered), 4)
        for (_, _, prev_end), (_, nxt_start, _) in zip(ordered, ordered[1:]):
            self.assertGreaterEqual(nxt_start, prev_end)

    def test_results_preserved(self):
        # 分阶段不影响结果归集: status/full 与 keys 一一对应
        keys = ["linkspeed", "speedtest", "dhcp", "tcpcc", "web"]
        results, full, calls = self._run(keys)
        self.assertEqual(set(results), set(keys))
        self.assertTrue(all(results[k] == "完成" for k in keys))
        self.assertEqual(set(full), set(keys))
        self.assertEqual({c[0] for c in calls}, set(keys))

    def test_normal_modules_still_concurrent(self):
        # 无独占模块时保持并发 (Barrier: 4 线程必须同时在跑, 否则超时炸)
        keys = ["linkspeed", "dhcp", "lan", "wifi"]
        barrier = threading.Barrier(4, timeout=5)

        def fake_run(key, cb):
            barrier.wait()
            return "完成", {"key": key}

        with mock.patch.object(np, "_run_module_with_timeout",
                               side_effect=fake_run), \
             mock.patch.object(np, "_safe_print"):
            results, _ = np._run_diagnostics_parallel(
                keys, max_workers=4, total=len(keys))
        self.assertEqual(set(results), set(keys))


if __name__ == "__main__":
    unittest.main()
