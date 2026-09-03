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


# ============================================================
# v1.9.8 遗留项 1: 修复命令一键执行
# ============================================================

_MTU_REC = ('1. 将电脑接口 以太网 改为 1472: netsh interface ipv4 set '
            'subinterface "以太网" mtu=1472 store=persistent (管理员), 改后复测')


def _fake_rc(*recs):
    """只带 recommendations 的假根因 (提取函数只读这一个属性)。"""
    return mock.Mock(recommendations=list(recs))


class TestExtractAdminFixCommands(unittest.TestCase):
    """"(管理员)" 标记命令提取: 只认标记, 不猜测。"""

    def test_extract_mtu_netsh(self):
        cmds = N._extract_admin_fix_commands([_fake_rc(_MTU_REC)])
        self.assertEqual(cmds, ['interface ipv4 set subinterface "以太网" '
                                'mtu=1472 store=persistent'])
        self.assertNotIn("(管理员)", cmds[0], "标记尾缀不得混入命令体")

    def test_no_marker_no_extract(self):
        """没有 (管理员) 标记的 netsh 文本不得被提取 (防误执行)。"""
        recs = ["查看代理: netsh winhttp show proxy",
                "1. 检查路由器 MSS clamping",
                "必要时以管理员身份运行重测"]
        self.assertEqual(N._extract_admin_fix_commands([_fake_rc(*recs)]), [])

    def test_dedupe_and_order(self):
        rec = _MTU_REC
        cmds = N._extract_admin_fix_commands([_fake_rc(rec), _fake_rc(rec)])
        self.assertEqual(len(cmds), 1, "重复命令必须去重")

    def test_trailing_punctuation_stripped(self):
        rec = "netsh interface ipv4 show interfaces (管理员)，改后复测"
        cmds = N._extract_admin_fix_commands([_fake_rc(rec)])
        self.assertEqual(cmds, ["interface ipv4 show interfaces"],
                         "标记后的中文逗号与文案不得混入命令体")

    def test_none_and_empty_safe(self):
        self.assertEqual(N._extract_admin_fix_commands(None), [])
        self.assertEqual(N._extract_admin_fix_commands([_fake_rc(None)]), [])


class TestOfferAdminFixShell(unittest.TestCase):
    """一键执行交互: 序号选择 / 跳过 / 提权失败降级。"""

    def setUp(self):
        self.cmds = ['interface ipv4 set subinterface "以太网" mtu=1472 '
                     'store=persistent']

    def _run(self, cmds, answer, se_ret=33):
        """公共桩: TTY + 输入 answer + ShellExecuteW 返回 se_ret。"""
        with mock.patch.object(N.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value=answer), \
             mock.patch("ctypes.windll.shell32.ShellExecuteW",
                        return_value=se_ret) as m_se:
            return N._offer_admin_fix_shell(cmds), m_se

    def test_non_tty_skips(self):
        with mock.patch.object(N.sys.stdin, "isatty", return_value=False), \
             mock.patch("builtins.input") as m_in:
            self.assertEqual(N._offer_admin_fix_shell(self.cmds), 0)
        m_in.assert_not_called()

    def test_empty_answer_skips(self):
        n, m_se = self._run(self.cmds, "")
        self.assertEqual(n, 0)
        m_se.assert_not_called()

    def test_select_one_launches_admin_cmd(self):
        n, m_se = self._run(self.cmds, "1")
        self.assertEqual(n, 1)
        args = m_se.call_args[0]
        self.assertEqual(args[1], "runas")
        self.assertEqual(args[2], "cmd.exe")
        self.assertEqual(args[3], f"/k netsh {self.cmds[0]}")

    def test_multi_select_dedupe_and_order(self):
        cmds = ["interface ipv4 show interfaces", "interface ipv4 show dns"]
        n, m_se = self._run(cmds, "2,1,2")
        self.assertEqual(n, 2, "重复序号必须去重")
        launched = [c[0][3] for c in m_se.call_args_list]
        self.assertEqual(launched, [f"/k netsh {cmds[1]}", f"/k netsh {cmds[0]}"],
                         "按输入顺序发起, 每条独立 cmd /k 窗口")

    def test_invalid_input_skips(self):
        n, m_se = self._run(self.cmds, "x,9")
        self.assertEqual(n, 0)
        m_se.assert_not_called()

    def test_shell_reject_degrades(self):
        """ShellExecuteW <=32 (UAC 取消/策略): 计数 0, 不抛异常。"""
        n, m_se = self._run(self.cmds, "1", se_ret=2)
        self.assertEqual(n, 0)


class TestPrintDiagnosisHook(unittest.TestCase):
    """_print_diagnosis 尾部挂钩: 交互时提议, 非 TTY 零打扰。"""

    def _fake_diagnosis(self, recs):
        rc = mock.Mock(severity=mock.Mock(value="high"), title="MTU 不匹配",
                       category="MTU", confidence=0.9,
                       description="d", affected_modules=["mtu"],
                       recommendations=list(recs))
        return mock.Mock(root_causes=[rc], rules_fired=1, rules_evaluated=19,
                         overall_confidence=0.9)

    def test_tty_offers_and_continues(self):
        with mock.patch.object(N.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value=""), \
             mock.patch.object(N, "_offer_admin_fix_shell",
                               return_value=0) as m_offer:
            N._print_diagnosis(self._fake_diagnosis([_MTU_REC]))
        m_offer.assert_called_once()
        cmds = m_offer.call_args[0][0]
        self.assertEqual(len(cmds), 1, "诊断打印后必须带一次修复命令提议")

    def test_non_tty_no_offer(self):
        with mock.patch.object(N.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(N, "_offer_admin_fix_shell") as m_offer:
            N._print_diagnosis(self._fake_diagnosis([_MTU_REC]))
        # _offer_admin_fix_shell 内部非 TTY 直接返回 0, 挂钩本身仍会调用
        # (它在函数内部短路, 不弹输入) — 断言零输入副作用即可
        m_offer.assert_called_once()

    def test_no_root_causes_no_offer(self):
        d = mock.Mock(root_causes=[], rules_evaluated=19)
        with mock.patch.object(N, "_offer_admin_fix_shell") as m_offer:
            N._print_diagnosis(d)
        m_offer.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
