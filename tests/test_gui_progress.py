# -*- coding: utf-8 -*-
"""GUI 进度回调通道 (v1.21.0): run_diagnostics progress_cb 事件契约。

验证点:
  P1 并行路径: 每模块 start/done 各一条, done 带中文 status
  P2 顺序路径: 事件按 keys 顺序成对出现
  P3 progress_cb=None: 行为与旧版一致 (不抛异常, results 正确)
  P4 回调抛异常不中断诊断 (事件通知永不打断主流程)
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np

_KEYS = ["gateway", "dns", "wifi"]


def _fake_probe(key, cb=None):
    return "完成", {"fake": key}


class TestGuiProgress(unittest.TestCase):

    def _run(self, keys=_KEYS, parallel=True, **kw):
        """跑一次 run_diagnostics, 系统信息/探测全 mock (不碰真实网络)。"""
        def _s(*a, **k):
            return "192.168.1.2"
        with mock.patch.object(np, "_run_module_with_timeout",
                               side_effect=_fake_probe), \
             mock.patch.object(np, "get_local_ip", side_effect=_s), \
             mock.patch.object(np, "get_default_gateway", side_effect=_s), \
             mock.patch.object(np, "get_dns_servers", side_effect=lambda: ["223.5.5.5"]), \
             mock.patch.object(np, "get_public_ip", side_effect=_s), \
             mock.patch.object(np, "get_public_ipv6", side_effect=lambda: None), \
             mock.patch.object(np, "get_ip_geo", side_effect=lambda *a, **k: None):
            return np.run_diagnostics(keys, banner=False, parallel=parallel,
                                      max_workers=2, print_modules=False, **kw)

    def test_parallel_events_paired(self):
        events = []
        run = self._run(parallel=True, progress_cb=events.append)
        starts = sorted(e["key"] for e in events if e["event"] == "start")
        dones = sorted(e["key"] for e in events if e["event"] == "done")
        self.assertEqual(starts, sorted(_KEYS))
        self.assertEqual(dones, sorted(_KEYS))
        for e in events:
            if e["event"] == "done":
                self.assertEqual(e["status"], "完成")
        self.assertEqual(run["status"], {k: "完成" for k in _KEYS})

    def test_sequential_events_in_order(self):
        events = []
        self._run(parallel=False, progress_cb=events.append)
        seq = [(e["event"], e["key"]) for e in events]
        expect = []
        for k in _KEYS:
            expect += [("start", k), ("done", k)]
        self.assertEqual(seq, expect)

    def test_no_callback_unchanged(self):
        run = self._run()
        self.assertEqual(run["status"], {k: "完成" for k in _KEYS})

    def test_callback_exception_ignored(self):
        def _bad(ev):
            raise RuntimeError("gui down")
        run = self._run(progress_cb=_bad)
        self.assertEqual(run["status"], {k: "完成" for k in _KEYS})


if __name__ == "__main__":
    unittest.main()
