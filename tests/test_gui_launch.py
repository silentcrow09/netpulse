# -*- coding: utf-8 -*-
"""GUI 启动链 (v1.21.0): --app → 默认浏览器 → 打印URL 三级降级 + 控制台隐藏。

验证点:
  P1 有 Chromium → Popen 拉起 --app=URL (含 token), 返回 "app"
  P2 Chromium 拉起失败 → webbrowser.open, 返回 "tab"
  P3 全失败 → 返回 "none"
  P4 _console_is_exclusive 纯逻辑 (注入进程数)
  P5 _run_gui: URL 已打印当拉起失败; 退出事件触发后干净返回
  P6 _GUI_RESET_FOR_TEST 清理类属性
"""
import os
import sys
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


class TestGuiLaunch(unittest.TestCase):

    def setUp(self):
        np._GUI_RESET_FOR_TEST()

    def test_app_launch(self):
        procs = []
        with mock.patch.object(np, "_find_pdf_browser",
                               return_value="C:/x/msedge.exe"), \
             mock.patch.object(np.subprocess, "Popen",
                               side_effect=lambda *a, **k: procs.append(a)):
            how = np._gui_launch_browser("http://127.0.0.1:1/?t=abc")
        self.assertEqual(how, "app")
        self.assertEqual(len(procs), 1)
        args = procs[0][0]
        self.assertEqual(args[0], "C:/x/msedge.exe")
        self.assertIn("--app=http://127.0.0.1:1/?t=abc", args)

    def test_tab_fallback(self):
        with mock.patch.object(np, "_find_pdf_browser", return_value=None), \
             mock.patch.object(np.webbrowser, "open", return_value=True) as m:
            how = np._gui_launch_browser("http://127.0.0.1:1/?t=abc")
        self.assertEqual(how, "tab")
        m.assert_called_once_with("http://127.0.0.1:1/?t=abc")

    def test_none_fallback(self):
        with mock.patch.object(np, "_find_pdf_browser", return_value=None), \
             mock.patch.object(np.webbrowser, "open", return_value=False):
            self.assertEqual(np._gui_launch_browser("http://x/"), "none")

    def test_console_exclusive_logic(self):
        with mock.patch.object(np, "_gui_console_process_count", return_value=1):
            self.assertTrue(np._console_is_exclusive())
        with mock.patch.object(np, "_gui_console_process_count", return_value=3):
            self.assertFalse(np._console_is_exclusive())

    def test_run_gui_lifecycle(self):
        s = np._GuiSession()
        evt = threading.Event()
        printed = {}
        with mock.patch.object(np, "_start_gui_server",
                               return_value=(None, 54321, "tok")), \
             mock.patch.object(np, "_gui_conn_check", return_value=True), \
             mock.patch.object(np, "_gui_launch_browser",
                               side_effect=lambda url: printed.update(
                                   url=url) or "none"), \
             mock.patch("builtins.print",
                        side_effect=lambda *a, **k: printed.setdefault(
                            "lines", []).append(a)):
            runner = threading.Thread(
                target=np._run_gui, kwargs={"shutdown_evt": evt}, daemon=True)
            runner.start()
            time.sleep(0.3)
            self.assertIn("54321", printed["url"])
            evt.set()
            runner.join(timeout=5)
        self.assertFalse(runner.is_alive())

    def test_reset_for_test(self):
        np._GuiHandler.token = "x"
        np._GUI_RESET_FOR_TEST()
        self.assertIsNone(np._GuiHandler.token)


if __name__ == "__main__":
    unittest.main()
