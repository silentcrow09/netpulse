# -*- coding: utf-8 -*-
"""v1.9.6 交互菜单补口验证 (设计稿 design/menu-entry-plan.html, mock 隔离)。

验证点 (装维不加参数原则 — CLI 功能必须有菜单入口):
  M1  _prompt_for_capture: 非 TTY 跳过 / 不可用不出选择题 / y=f=s=Enter 四分支
      + s 的 MB 解析 (非法输入回退默认)
  M2  _run_scene_monitor 把 (capture_mode, capture_mb) 透传给 run_monitor_mode
  M3  工程师菜单 d 键: 无数据只提示 / 有数据调 _export_debug_bundle(_report_dir())
  M4  _prompt_for_web_targets: 合法/非法/超 5 截断 / Enter 不追加
  M5  测速节点 JIT: 数字 ID → ookla_server_id+node / host:port → node /
      一次会话只问一次 (_node_prompted)
  M6  iperf3 口径 JIT: 服务器具备时 u → iperf3_udp=True, Enter 不改
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


class TestPromptForCapture(unittest.TestCase):
    """M1: 抓包询问四分支 + 降级态 (设计稿图 A/B)。"""

    def _sess(self, ok, reason=""):
        s = mock.Mock()
        s.precheck.return_value = ok
        s.unavailable_reason = reason
        return s

    def test_non_tty_skips_entirely(self):
        # 非 TTY (脚本/管道): 一个字不打, 直接默认不开启
        with mock.patch("sys.stdin.isatty", return_value=False):
            mode, mb = np._prompt_for_capture()
        self.assertIsNone(mode)
        self.assertEqual(mb, np.CAPTURE_DEFAULT_MB)

    def test_unavailable_shows_reason_no_question(self):
        # 不可用: 只有「按 Enter 继续」, 没有选择题 (input 恰好一次)
        s = self._sess(False, "Npcap 默认只允许管理员抓包 — 请以管理员身份重跑")
        with mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("netpulse._PcapCaptureSession", return_value=s), \
             mock.patch("builtins.input", return_value="") as m_in:
            mode, mb = np._prompt_for_capture()
        self.assertIsNone(mode)
        self.assertEqual(mb, np.CAPTURE_DEFAULT_MB)
        self.assertEqual(m_in.call_count, 1)

    def _ask(self, answers, sess_ok=True):
        s = self._sess(sess_ok)
        with mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("netpulse._PcapCaptureSession", return_value=s), \
             mock.patch("builtins.input", side_effect=answers):
            return np._prompt_for_capture()

    def test_enter_defaults_off(self):
        mode, mb = self._ask([""])
        self.assertIsNone(mode)
        self.assertEqual(mb, np.CAPTURE_DEFAULT_MB)

    def test_y_selects_slice(self):
        mode, mb = self._ask(["y"])
        self.assertEqual(mode, "slice")
        self.assertEqual(mb, np.CAPTURE_DEFAULT_MB)

    def test_f_selects_full(self):
        mode, _ = self._ask(["f"])
        self.assertEqual(mode, "full")

    def test_s_custom_mb(self):
        mode, mb = self._ask(["s", "128"])
        self.assertEqual(mode, "slice")
        self.assertEqual(mb, 128)

    def test_s_invalid_mb_falls_back(self):
        # MB 输入非数字: 回退默认 64, 不拦盯障
        mode, mb = self._ask(["s", "abc"])
        self.assertEqual(mode, "slice")
        self.assertEqual(mb, np.CAPTURE_DEFAULT_MB)


class TestSceneMonitorPassthrough(unittest.TestCase):
    """M2: 场景 [7] 盯障把抓包选择透传给 run_monitor_mode。"""

    def test_capture_args_passed(self):
        with mock.patch("builtins.input", return_value="10"), \
             mock.patch("netpulse._prompt_for_capture",
                        return_value=("slice", 128)), \
             mock.patch("netpulse.run_monitor_mode") as m_run, \
             mock.patch("netpulse._pause_enter"):
            np._run_scene_monitor()
        m_run.assert_called_once_with(600, capture_mode="slice", capture_mb=128)

    def test_scene_menu_7_routes_to_monitor(self):
        # 场景层 [7] → _run_scene_monitor (接线检查)
        with mock.patch("builtins.input", side_effect=["7", "0"]), \
             mock.patch.object(np, "_menu_clear"), \
             mock.patch("netpulse._run_scene_monitor") as m_mon:
            np._scene_menu()
        m_mon.assert_called_once()


class TestModuleMenuDebugKey(unittest.TestCase):
    """M3: 工程师菜单 d 键两态。输入流: d → Enter 返回 → q 退出。"""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="np_menu_d_")
        self._old = np.LAST_RUN
        np.LAST_RUN = None

    def tearDown(self):
        np.LAST_RUN = self._old
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_d_no_data_hints_only(self):
        with mock.patch("builtins.input", side_effect=["d", "", "q"]), \
             mock.patch.object(np, "_menu_clear"), \
             mock.patch("netpulse._export_debug_bundle") as m_exp:
            np._module_menu()
        self.assertFalse(m_exp.called)

    def test_d_with_data_exports_to_report_dir(self):
        np.LAST_RUN = {"results": {"gateway": {}}, "keys": ["gateway"]}
        with mock.patch("builtins.input", side_effect=["d", "", "q"]), \
             mock.patch.object(np, "_menu_clear"), \
             mock.patch("netpulse._report_dir", return_value=self._tmp), \
             mock.patch("netpulse._export_debug_bundle") as m_exp:
            np._module_menu()
        m_exp.assert_called_once_with(self._tmp)


class TestWebTargetsPrompt(unittest.TestCase):
    """M4: 网页体检追加目标询问。"""

    def test_enter_no_extra(self):
        with mock.patch("builtins.input", return_value=""):
            self.assertEqual(np._prompt_for_web_targets(), [])

    def test_mixed_validity_and_over_limit(self):
        # 6 合法 + 1 非法: 非法忽略, 合法截到 5 (3 默认站 + 5 = 模块上限 8)
        spec = ("foo, https://a.com, https://b.com, https://c.com, "
                "https://d.com, https://e.com, https://f.com")
        with mock.patch("builtins.input", return_value=spec):
            urls = np._prompt_for_web_targets()
        self.assertEqual(len(urls), 5)
        self.assertTrue(all(u.startswith("https://") for u in urls))
        self.assertNotIn("foo", urls)

    def test_module_menu_wiring(self):
        # 工程师菜单单选 web (序号 14) → 询问追加 → 写入 WEB_CONFIG
        old = np.WEB_CONFIG["targets"]
        try:
            with mock.patch("builtins.input",
                            side_effect=["14", "https://crm.example.com", "",
                                         "q"]), \
                 mock.patch("sys.stdout.isatty", return_value=True), \
                 mock.patch.object(np, "_menu_clear"), \
                 mock.patch("netpulse.run_diagnostics"), \
                 mock.patch("netpulse.prompt_export_report"):
                np._module_menu()
            self.assertEqual(np.WEB_CONFIG["targets"],
                             ["https://crm.example.com"])
        finally:
            np.WEB_CONFIG["targets"] = old


class TestSpeedtestNodeJit(unittest.TestCase):
    """M5: 测速换节点 JIT (单选 speedtest=7)。"""

    def setUp(self):
        self._saved = (np.SPEEDTEST_CONFIG.get("node"),
                       np.SPEEDTEST_CONFIG.get("ookla_server_id"))
        np.SPEEDTEST_CONFIG["node"] = None
        np.SPEEDTEST_CONFIG.pop("_node_prompted", None)

    def tearDown(self):
        node, sid = self._saved
        np.SPEEDTEST_CONFIG["node"] = node
        np.SPEEDTEST_CONFIG["ookla_server_id"] = sid
        np.SPEEDTEST_CONFIG.pop("_node_prompted", None)

    def _run_menu(self, answers):
        # 输入流: 7 (speedtest) → 节点回答 → Enter 返回 → q
        with mock.patch("builtins.input",
                        side_effect=["7"] + answers + ["", "q"]), \
             mock.patch("sys.stdout.isatty", return_value=True), \
             mock.patch.object(np, "_menu_clear"), \
             mock.patch("netpulse.run_diagnostics"), \
             mock.patch("netpulse.prompt_export_report"):
            np._module_menu()

    def test_numeric_id_switches_ookla(self):
        self._run_menu(["5396"])
        self.assertEqual(np.SPEEDTEST_CONFIG["ookla_server_id"], 5396)
        self.assertEqual(np.SPEEDTEST_CONFIG["node"], "5396")

    def test_hostport_sets_node_only(self):
        self._run_menu(["112.25.80.50:8080"])
        self.assertEqual(np.SPEEDTEST_CONFIG["node"], "112.25.80.50:8080")
        self.assertEqual(np.SPEEDTEST_CONFIG["ookla_server_id"],
                         self._saved[1])

    def test_asked_once_per_session(self):
        # 第二次单选 speedtest 不再问: 输入流里没有节点回答位
        self._run_menu([""])
        self.assertNotIn("_node_prompted_pending", np.SPEEDTEST_CONFIG)
        self.assertIsNone(np.SPEEDTEST_CONFIG["node"])
        self.assertTrue(np.SPEEDTEST_CONFIG.get("_node_prompted"))


class TestIperf3ModeJit(unittest.TestCase):
    """M6: iperf3 口径 JIT (服务器已具备时单选 iperf3=9)。"""

    def setUp(self):
        self._saved = (np.SPEEDTEST_CONFIG.get("iperf3_server"),
                       np.SPEEDTEST_CONFIG.get("iperf3_udp"))
        np.SPEEDTEST_CONFIG["iperf3_server"] = "192.168.1.10"
        np.SPEEDTEST_CONFIG["iperf3_udp"] = False
        np.SPEEDTEST_CONFIG.pop("_iperf3_mode_prompted", None)

    def tearDown(self):
        server, udp = self._saved
        np.SPEEDTEST_CONFIG["iperf3_server"] = server
        np.SPEEDTEST_CONFIG["iperf3_udp"] = udp
        np.SPEEDTEST_CONFIG.pop("_iperf3_mode_prompted", None)

    def _run_menu(self, mode_answer):
        # 输入流: 9 (iperf3, 服务器已有 → 跳过 server 询问) → 口径回答 → Enter → q
        with mock.patch("builtins.input",
                        side_effect=["9", mode_answer, "", "q"]), \
             mock.patch("sys.stdout.isatty", return_value=True), \
             mock.patch.object(np, "_menu_clear"), \
             mock.patch("netpulse.run_diagnostics"), \
             mock.patch("netpulse.prompt_export_report"):
            np._module_menu()

    def test_u_selects_udp(self):
        self._run_menu("u")
        self.assertTrue(np.SPEEDTEST_CONFIG["iperf3_udp"])

    def test_enter_keeps_tcp(self):
        self._run_menu("")
        self.assertFalse(np.SPEEDTEST_CONFIG["iperf3_udp"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
