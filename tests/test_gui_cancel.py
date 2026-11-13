# -*- coding: utf-8 -*-
"""诊断中途取消 / 续跑 (v1.24.0): 调度层取消闸 + 进度事件的结果契约。

验证点:
  P1 取消闸存在: run_diagnostics 接受 cancel_evt 关键字, 默认 None
  P2 取消后**未启动**的模块不产生结果 (报告里走「未检测」, 不新增状态值)
  P3 已跑完的模块结果不受取消影响 (保住已完成的工作)
  P4 顺序路径: 取消后不再启动后续模块
  P5 并行路径: 取消后不再启动后续模块
  P6 cancel_evt=None: 行为与旧版一致 (全部模块都跑, 事件成对)
  P7 done 事件带该模块的完整结果 (关窗落盘 / 续跑点要用)
  P8 取消闸不改变 run dict 的结构 (keys 仍是请求全集)
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np

_KEYS = ["gateway", "dns", "wifi"]


def _fake_probe(key, cb=None):
    return "完成", {"fake": key}


class TestCancelGate(unittest.TestCase):
    """调度层取消闸 (run_diagnostics → 并行/顺序执行器)。"""

    def _run(self, keys=_KEYS, parallel=True, cancel_evt=None, **kw):
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
                                      max_workers=1, print_modules=False,
                                      cancel_evt=cancel_evt, **kw)

    # ── P1 取消闸存在 ──
    def test_cancel_evt_accepted_and_default_none(self):
        # run_diagnostics 带 @_restore_stdout_on_exit 装饰器 (wrapper 是
        # (*args, **kwargs)), 拿不到内层签名 → 走源码级断言。
        src = open(os.path.join(ROOT, "netpulse.py"), encoding="utf-8").read()
        self.assertIn("cancel_evt=None):", src)
        # 终端调用点一个都不许传 cancel_evt (传了就等于改了终端行为,
        # 见 verify.md S5.4)。GUI 会话层是唯一该传的地方。
        import re
        head, sep, gui = src.partition("class _GuiSession")
        self.assertTrue(sep, "找不到 GUI 会话类")
        self.assertIn("cancel_evt=self._cancel_evt", gui)
        def_at = head.find("def run_diagnostics(")
        self.assertTrue(def_at > 0, "找不到 run_diagnostics 定义")
        body = head[def_at:]
        body = body[body.find("):") + 2:]          # 跳过函数签名本身
        hits = 0
        for m in re.finditer(r"run_diagnostics\(", body):
            chunk = body[m.start():m.start() + 300]
            hits += 1
            self.assertNotIn(
                "cancel_evt", chunk,
                "终端调用点传了 cancel_evt: %s" % chunk[:100].replace("\n", " "))
        self.assertGreater(hits, 0, "没扫到任何 run_diagnostics 调用点")

    # ── P2/P3 取消后: 未启动的不产生结果, 已完成的保住 ──
    def test_cancelled_modules_have_no_result(self):
        evt = threading.Event()
        events = []

        def _cb(e):
            events.append(e)
            if e.get("event") == "done":
                evt.set()          # 第一个模块跑完就请求停止

        run = self._run(parallel=False, progress_cb=_cb, cancel_evt=evt)
        self.assertIn("gateway", run["results"])
        self.assertNotIn("dns", run["results"])
        self.assertNotIn("wifi", run["results"])
        # 已跑完的那个结果原样保住 (复用续跑要靠它)
        self.assertEqual(run["results"]["gateway"], {"fake": "gateway"})

    def test_parallel_cancelled_modules_have_no_result(self):
        evt = threading.Event()

        def _cb(e):
            if e.get("event") == "done":
                evt.set()

        run = self._run(parallel=True, progress_cb=_cb, cancel_evt=evt)
        self.assertIn("gateway", run["results"])
        self.assertNotIn("dns", run["results"])
        self.assertNotIn("wifi", run["results"])

    # ── P4/P5 两条路径都不再启动后续模块 ──
    def test_sequential_stops_dispatching(self):
        evt = threading.Event()
        started = []

        def _cb(e):
            started.append((e["event"], e["key"]))
            if e.get("event") == "done":
                evt.set()

        self._run(parallel=False, progress_cb=_cb, cancel_evt=evt)
        # 只有 gateway 有 start/done 一对; dns/wifi 连 start 都没有
        self.assertEqual([s for s in started if s[0] == "start"], [("start", "gateway")])

    def test_parallel_stops_dispatching(self):
        evt = threading.Event()
        started = []

        def _cb(e):
            started.append((e["event"], e["key"]))
            if e.get("event") == "done":
                evt.set()

        self._run(parallel=True, progress_cb=_cb, cancel_evt=evt)
        self.assertEqual([s for s in started if s[0] == "start"], [("start", "gateway")])

    # ── P5b 独占段 (测速类模块) 的取消闸 ──
    # 独占段是第二道闸: 普通模块并发跑完后, 测速类逐个串行跑。已请求停止
    # 时不能启动测速 (一跑就是几分钟, spec F1 的核心价值就在这)。
    def test_exclusive_phase_gate_blocks_speedtest(self):
        evt = threading.Event()
        started = []

        def _cb(e):
            started.append((e["event"], e["key"]))
            if e.get("event") == "done":
                evt.set()

        run = self._run(keys=["gateway", "speedtest"], parallel=True,
                        progress_cb=_cb, cancel_evt=evt)
        self.assertNotIn(("start", "speedtest"), started,
                         "已请求停止 → 独占段不得启动测速类模块")
        self.assertNotIn("speedtest", run["results"])
        self.assertIn("gateway", run["results"])

    # ── P6 默认行为不变 ──
    def test_no_cancel_runs_everything(self):
        events = []
        run = self._run(parallel=True, progress_cb=events.append)
        self.assertEqual(sorted(run["results"]), sorted(_KEYS))
        starts = sorted(e["key"] for e in events if e["event"] == "start")
        dones = sorted(e["key"] for e in events if e["event"] == "done")
        self.assertEqual(starts, sorted(_KEYS))
        self.assertEqual(dones, sorted(_KEYS))

    # ── P7 done 事件带完整结果 ──
    def test_done_event_carries_result(self):
        events = []
        self._run(parallel=True, progress_cb=events.append)
        dones = {e["key"]: e for e in events if e["event"] == "done"}
        self.assertEqual(sorted(dones), sorted(_KEYS))
        for k, e in dones.items():
            self.assertEqual(e["result"], {"fake": k})
            self.assertEqual(e["status"], "完成")

    # ── P8 run dict 结构不变 (keys 仍是请求全集) ──
    def test_keys_stay_full_request_set(self):
        evt = threading.Event()

        def _cb(e):
            if e.get("event") == "done":
                evt.set()

        run = self._run(parallel=False, progress_cb=_cb, cancel_evt=evt)
        # 请求了 3 项 → run["keys"] 仍是 3 项 (报告据此显示「未检测」占位)
        self.assertEqual(list(run["keys"]), _KEYS)


class TestResumePoint(unittest.TestCase):
    """续跑点落盘 (v1.24.0): 原子写 / 读取 / 过期清理 / 损坏容错。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="np_resume_")
        self.path = os.path.join(self.tmp, "resume.json")
        patcher = mock.patch.object(np, "_gui_resume_path",
                                    return_value=self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _payload(self, **kw):
        p = {"schema": 1, "saved_at_ts": 1700000000.0,
             "profile": "slow", "label": "网络很慢",
             "keys": ["gateway", "dns", "wifi"],
             "completed": {"gateway": {"status": "完成", "result": {"ok": 1}}},
             "duration_ms": 1000, "total_modules": 24}
        p.update(kw)
        return p

    # ── P9 存取往返 ──
    def test_save_then_load(self):
        ok, err = np._gui_resume_save(self._payload())
        self.assertTrue(ok)
        self.assertIsNone(err)
        pt, err = np._gui_resume_load()
        self.assertIsNone(err)
        self.assertEqual(pt["profile"], "slow")
        self.assertEqual(sorted(pt["completed"]), ["gateway"])
        self.assertEqual(pt["completed"]["gateway"]["result"], {"ok": 1})
        self.assertEqual(pt["completed"]["gateway"]["status"], "完成")

    # ── P10 没有续跑点不是错误 ──
    def test_missing_is_not_error(self):
        pt, err = np._gui_resume_load()
        self.assertIsNone(pt)
        self.assertIsNone(err)

    # ── P11 文件损坏 → 忽略, 不崩溃 ──
    def test_corrupt_file_ignored(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("{not json")
        pt, err = np._gui_resume_load()
        self.assertIsNone(pt)
        self.assertTrue(err)

    # ── P12 结构非法 → 忽略 ──
    def test_invalid_structure_ignored(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"keys": "not-a-list", "completed": {}}, f)
        pt, err = np._gui_resume_load()
        self.assertIsNone(pt)
        self.assertTrue(err)

    # ── P13 坏模块剔除 (续跑时重跑它) ──
    def test_bad_module_dropped(self):
        payload = self._payload(completed={
            "gateway": {"status": "完成", "result": {"ok": 1}},
            "dns": {"status": "完成", "result": "不是 dict"},
            "wifi": "整个条目都不是 dict",
        })
        np._gui_resume_save(payload)
        pt, err = np._gui_resume_load()
        self.assertIsNone(err)
        self.assertEqual(sorted(pt["completed"]), ["gateway"])

    # ── P14 过期自动清理 ──
    def test_expired_point_removed(self):
        np._gui_resume_save(self._payload())
        old = time.time() - (np._GUI_RESUME_MAX_AGE + 3600)
        os.utime(self.path, (old, old))
        pt, err = np._gui_resume_load()
        self.assertIsNone(pt)
        self.assertIsNone(err)
        self.assertFalse(os.path.exists(self.path))

    # ── P15 落盘失败不抛异常, 只回报文案 ──
    def test_save_failure_reported(self):
        with mock.patch.object(np.os, "makedirs", side_effect=OSError("denied")):
            ok, err = np._gui_resume_save(self._payload())
        self.assertFalse(ok)
        self.assertTrue(err and "续跑点" in err)

    # ── P16 原子写不留临时文件 ──
    def test_no_tmp_left_behind(self):
        np._gui_resume_save(self._payload())
        self.assertFalse(os.path.exists(self.path + ".tmp"))

    # ── P17 摘要 ──
    def test_summary_shape(self):
        s = np._gui_resume_summary(self._payload())
        self.assertEqual(s["done"], 1)
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["label"], "网络很慢")
        self.assertIsNone(np._gui_resume_summary(None))

    # ── P18 丢弃 ──
    def test_discard_removes(self):
        np._gui_resume_save(self._payload())
        self.assertTrue(np._gui_resume_discard())
        self.assertFalse(os.path.exists(self.path))
        self.assertFalse(np._gui_resume_discard())


if __name__ == "__main__":
    unittest.main()
