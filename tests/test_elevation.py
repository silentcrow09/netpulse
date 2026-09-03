# -*- coding: utf-8 -*-
"""自提权重启回归测试 (v1.9.7 PR-3)

覆盖:
  - _build_elevated_launch 纯函数: wt 有/无、源码/frozen、含空格参数引号
  - _relaunch_elevated: ShellExecuteW 成功/失败分支
  - _offer_elevation_relaunch: 取消跳过 / 成功 sys.exit(0) / 失败降级不抛
  - --install-npcap CLI 落点: 装完回菜单, 不跑诊断
  - 场景菜单 [A] 键: 提议被调用一次, 取消后落回菜单
无管理员权限依赖 (全部 mock ShellExecuteW / _relaunch_elevated)。
跑用: cd 到项目根目录, `python tests/test_elevation.py`
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

# PR-2 契约: 打补丁前先完成 scapy 懒加载绑定 (本文件其实不碰 scapy, 保险起见)
N._ensure_scapy()


class TestBuildElevatedLaunch(unittest.TestCase):
    """纯函数: (lp_file, lp_params) 构造。"""

    def test_source_run_no_wt(self):
        with mock.patch.object(N, "_find_windows_terminal", return_value=None):
            lp_file, lp_params = N._build_elevated_launch(["--install-npcap"])
        # 源码运行: lp_file = python.exe, params = "脚本" + tail
        self.assertEqual(lp_file, sys.executable)
        self.assertIn('"', lp_params)
        self.assertIn("--install-npcap", lp_params)

    def test_no_wt_tail_appended(self):
        with mock.patch.object(N, "_find_windows_terminal", return_value=None):
            _, lp_params = N._build_elevated_launch(["--monitor", "10"])
        self.assertIn("--monitor", lp_params)
        self.assertIn("10", lp_params)

    def test_wt_used_when_available(self):
        wt = r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\wt.exe"
        with mock.patch.object(N, "_find_windows_terminal", return_value=wt):
            lp_file, lp_params = N._build_elevated_launch(["--monitor", "10"])
        self.assertEqual(lp_file, wt)
        self.assertTrue(lp_params.startswith('-d "'), "wt 启动须带 -d <workdir>")
        self.assertIn("--monitor", lp_params)

    def test_args_with_spaces_get_quoted(self):
        with mock.patch.object(N, "_find_windows_terminal", return_value=None):
            _, lp_params = N._build_elevated_launch(
                ["--debug-bundle", r"C:\My Dir\out"])
        self.assertIn(r'"C:\My Dir\out"', lp_params,
                      "含空格的参数必须加引号")


class TestRelaunchElevated(unittest.TestCase):
    """ShellExecuteW 分支。"""

    def test_success_returns_true(self):
        with mock.patch("ctypes.windll.shell32.ShellExecuteW",
                        return_value=33) as m_se, \
             mock.patch.object(N, "_find_windows_terminal", return_value=None):
            ok, msg = N._relaunch_elevated(["--install-npcap"])
        self.assertTrue(ok)
        self.assertIn("runas", str(m_se.call_args))
        self.assertEqual(m_se.call_args[0][1], "runas")

    def test_user_cancel_returns_false(self):
        # ShellExecuteW <= 32 = 失败 (2 = 文件未找到, 用户取消常见返回值)
        with mock.patch("ctypes.windll.shell32.ShellExecuteW",
                        return_value=2), \
             mock.patch.object(N, "_find_windows_terminal", return_value=None):
            ok, msg = N._relaunch_elevated()
        self.assertFalse(ok)
        self.assertIn("拒绝提权", msg)

    def test_exception_returns_false_not_raise(self):
        with mock.patch("ctypes.windll.shell32.ShellExecuteW",
                        side_effect=OSError("boom")):
            ok, msg = N._relaunch_elevated()
        self.assertFalse(ok)
        self.assertIn("提权重启失败", msg)


class TestOfferElevationRelaunch(unittest.TestCase):
    """确认交互: 取消 / 成功退出 / 失败降级。"""

    def test_non_tty_skips_silently(self):
        with mock.patch.object(N.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(N, "_relaunch_elevated") as m_re:
            N._offer_elevation_relaunch(["--x"], reason="测试")
        m_re.assert_not_called()

    def test_decline_keeps_running(self):
        with mock.patch.object(N.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="n"), \
             mock.patch.object(N, "_relaunch_elevated") as m_re:
            N._offer_elevation_relaunch(["--x"], reason="测试")
        m_re.assert_not_called()

    def test_accept_and_success_exits_zero(self):
        with mock.patch.object(N.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="y"), \
             mock.patch.object(N, "_relaunch_elevated",
                               return_value=(True, "ok")) as m_re:
            with self.assertRaises(SystemExit) as ctx:
                N._offer_elevation_relaunch(["--monitor", "10"], reason="测试")
            self.assertEqual(ctx.exception.code, 0)
        m_re.assert_called_once_with(["--monitor", "10"])

    def test_accept_but_failure_degrades(self):
        """提权失败 (用户取消 UAC): 不抛异常, 流程继续 (不藏退路)。"""
        with mock.patch.object(N.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="y"), \
             mock.patch.object(N, "_relaunch_elevated",
                               return_value=(False, "拒绝")):
            # 不应抛 SystemExit
            N._offer_elevation_relaunch(["--x"], reason="测试")


class TestInstallNpcapEntry(unittest.TestCase):
    """--install-npcap CLI 落点。"""

    def test_main_install_npcap_enters_menu(self):
        calls = {"install": 0, "menu": 0, "diag": 0}

        def fake_entry():
            calls["install"] += 1

        def fake_menu(*a, **kw):
            calls["menu"] += 1

        with mock.patch.object(sys, "argv", ["netpulse", "--install-npcap"]), \
             mock.patch.object(N, "_run_install_npcap_entry",
                               side_effect=fake_entry), \
             mock.patch.object(N, "interactive_menu", side_effect=fake_menu), \
             mock.patch.object(N, "run_diagnostics",
                               side_effect=lambda *a, **kw: calls.__setitem__(
                                   "diag", calls["diag"] + 1)):
            N.main()
        self.assertEqual(calls["install"], 1, "--install-npcap 必须触发安装入口")
        self.assertEqual(calls["menu"], 1, "装完必须继续进菜单 (提权窗口保持可用)")
        self.assertEqual(calls["diag"], 0, "不得顺带跑诊断")


class TestSceneMenuAdminKey(unittest.TestCase):
    """场景菜单 [A] 一键提权重启。"""

    def test_admin_key_offers_relaunch_then_falls_back(self):
        offers = []

        def fake_offer(reason="", **kw):
            offers.append(reason)
            # 模拟用户取消: 正常返回 (不 sys.exit)

        with mock.patch("builtins.input", side_effect=["a", "0"]), \
             mock.patch.object(N, "_menu_clear", return_value=None), \
             mock.patch.object(N, "_offer_elevation_relaunch",
                               side_effect=fake_offer):
            self.assertFalse(N._scene_menu(), "取消提权后 [0] 仍应正常退出")
        self.assertEqual(len(offers), 1, "[A] 必须触发一次提权提议")


if __name__ == "__main__":
    unittest.main(verbosity=2)
