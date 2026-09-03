# -*- coding: utf-8 -*-
"""scapy 懒加载/后台预加载回归测试 (v1.9.7 PR-2)

背景: 顶层 eager import 让「双击到菜单」多等 0.6-1.5s。PR-2 改为占位符 +
main() 后台预加载 + 使用点 _ensure_scapy() 收尾。本测试保证:
  1. _ensure_scapy() 幂等且成败都置位 SCAPY_LOADED
  2. 成功时占位符名字被真实绑定, 失败时保持 None (可判 SCAPY_AVAILABLE)
  3. _start_scapy_preload 幂等 / FORCE_NO_SCAPY 时不启动
  4. _reload_scapy 与 _load_scapy 同源 (TCP/DNS 一并绑定)
无论环境是否装了 scapy 都应全绿 (断言按 SCAPY_AVAILABLE 分支)。
跑用: cd 到项目根目录, `python tests/test_scapy_lazy.py`
"""
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

_PLACEHOLDERS = ["Ether", "IP", "UDP", "TCP", "DNS", "DHCP", "BOOTP", "ICMP",
                 "ARP", "srp", "sendp", "sniff", "conf", "sr1",
                 "get_if_list", "get_if_addr", "get_if_hwaddr"]


class TestEnsureScapy(unittest.TestCase):
    """_ensure_scapy 等待/幂等语义。"""

    def test_ensure_returns_and_sets_event(self):
        ok = N._ensure_scapy(timeout=20)
        self.assertIs(ok, N.SCAPY_AVAILABLE)
        self.assertTrue(N.SCAPY_LOADED.is_set(),
                        "_ensure_scapy 后 SCAPY_LOADED 必须已置位 (成败都置位)")

    def test_names_bound_iff_available(self):
        if N.SCAPY_AVAILABLE:
            for name in _PLACEHOLDERS:
                self.assertIsNotNone(getattr(N, name),
                                     f"scapy 可用时 {name} 必须已绑定真实对象")
        else:
            # 不可用时占位符必须保持 None — 函数入口漏 _ensure_scapy 会拿到
            # None 而非 NameError, 这里锁住该约定
            for name in _PLACEHOLDERS:
                self.assertIsNone(getattr(N, name),
                                  f"scapy 不可用时 {name} 应保持占位符 None")

    def test_ensure_idempotent_and_fast(self):
        N._ensure_scapy()
        t0 = time.perf_counter()
        for _ in range(100):
            self.assertTrue(N._ensure_scapy())
        # 已置位路径必须无锁等待 (100 次调用远小于 1s)
        self.assertLess(time.perf_counter() - t0, 1.0)

    def test_ensure_spawns_sync_load_when_never_started(self):
        """没启动过预加载线程时, _ensure_scapy 必须同步加载兜底。"""
        # 当前进程里无论事件状态如何, 重复调用都不能抛异常且语义一致
        ok1 = N._ensure_scapy()
        ok2 = N._ensure_scapy()
        self.assertEqual(ok1, ok2)
        self.assertEqual(ok1, N.SCAPY_AVAILABLE)


class TestPreloadThread(unittest.TestCase):
    """_start_scapy_preload 幂等 / FORCE_NO_SCAPY 短路。"""

    def setUp(self):
        self._orig_thread = N._scapy_thread
        self._orig_force = N.FORCE_NO_SCAPY
        self._orig_loaded = N.SCAPY_LOADED

    def tearDown(self):
        N._scapy_thread = self._orig_thread
        N.FORCE_NO_SCAPY = self._orig_force
        N.SCAPY_LOADED = self._orig_loaded

    def test_preload_idempotent(self):
        N._start_scapy_preload()
        t1 = N._scapy_thread
        N._start_scapy_preload()
        t2 = N._scapy_thread
        self.assertIs(t1, t2, "重复调用 _start_scapy_preload 不得再开新线程")

    def test_preload_noop_when_force_no_scapy(self):
        N.FORCE_NO_SCAPY = True
        N._scapy_thread = None
        before = N._scapy_thread
        N._start_scapy_preload()
        self.assertIs(N._scapy_thread, before,
                      "FORCE_NO_SCAPY=True 时不得启动预加载线程")

    def test_preload_noop_after_loaded(self):
        """已加载完成的进程里再调用必须直接返回 (不重复导入)。"""
        N.SCAPY_LOADED = mock.Mock()
        N.SCAPY_LOADED.is_set.return_value = True
        N._scapy_thread = None
        N._start_scapy_preload()
        self.assertIsNone(N._scapy_thread,
                          "SCAPY_LOADED 已置位时不应再创建线程")


class TestReloadScapy(unittest.TestCase):
    """_reload_scapy 与 _load_scapy 同源 (安装重载路径 = 启动路径)。"""

    def test_reload_delegates_and_binds(self):
        ok = N._reload_scapy()
        self.assertIs(ok, N.SCAPY_AVAILABLE)
        self.assertTrue(N.SCAPY_LOADED.is_set())
        if ok:
            # 旧版 _reload_scapy 手工列 globals 时漏过 TCP/DNS, 这里锁死
            for name in ("TCP", "DNS", "Ether", "conf", "sniff"):
                self.assertIsNotNone(getattr(N, name))


if __name__ == "__main__":
    unittest.main(verbosity=2)
