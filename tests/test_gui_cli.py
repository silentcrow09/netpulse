# -*- coding: utf-8 -*-
"""GUI CLI 集成 (v1.21.0): 入口判定纯函数 + main 分线。

验证点:
  P1 _gui_wanted 真值表: --gui=进 / --cli=不进 / --json=不进 /
     无参数 TTY=进 / 无参数非TTY=不进 / --gui+--json=不进
  P2 main: 无参数 TTY → _run_gui; 无参数非TTY → interactive_menu;
     --cli → interactive_menu; --gui+--cli → exit 4
  P3 既有顶层模式 (--diagnose/--site/--monitor) 不受影响 (分线仍在 GUI 判定之前)
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


class _Args:
    def __init__(self, gui=False, cli=False, json=False):
        self.gui, self.cli, self.json = gui, cli, json


class TestGuiWanted(unittest.TestCase):

    def test_truth_table(self):
        self.assertTrue(np._gui_wanted(_Args(gui=True), True))
        self.assertTrue(np._gui_wanted(_Args(gui=True), False))
        self.assertFalse(np._gui_wanted(_Args(cli=True), True))
        self.assertFalse(np._gui_wanted(_Args(json=True), True))
        self.assertTrue(np._gui_wanted(_Args(), True))
        self.assertFalse(np._gui_wanted(_Args(), False))
        self.assertFalse(np._gui_wanted(_Args(gui=True, json=True), True))


class TestMainWiring(unittest.TestCase):

    def _main(self, argv, is_tty):
        with mock.patch.object(sys, "argv", ["netpulse.py"] + argv), \
             mock.patch.object(np, "_run_gui") as mg, \
             mock.patch.object(np, "interactive_menu") as mi, \
             mock.patch.object(np, "_start_scapy_preload"), \
             mock.patch.object(np, "_prime_update_state_from_cache"), \
             mock.patch.object(np, "_start_update_check"), \
             mock.patch.object(np.sys.stdout, "isatty",
                               return_value=is_tty, create=True):
            np.main()
        return mg, mi

    def test_noargs_tty_runs_gui(self):
        mg, mi = self._main([], True)
        mg.assert_called_once()
        mi.assert_not_called()

    def test_noargs_nontty_keeps_menu(self):
        mg, mi = self._main([], False)
        mi.assert_called_once()
        mg.assert_not_called()

    def test_gui_receives_pip_mirror(self):
        """终审 #4: GUI 分支必须把 --pip-mirror 透传给 _run_gui (不变量)。"""
        mg, _ = self._main(["--pip-mirror", "https://mirr.example/pip"], True)
        mg.assert_called_once_with(install=True,
                                   pip_mirror="https://mirr.example/pip")

    def test_cli_flag_keeps_menu(self):
        mg, mi = self._main(["--cli"], True)
        mi.assert_called_once()
        mg.assert_not_called()

    def test_gui_and_cli_conflict(self):
        with mock.patch.object(sys, "argv",
                               ["netpulse.py", "--gui", "--cli"]), \
             self.assertRaises(SystemExit) as cm:
            np.main()
        self.assertEqual(cm.exception.code, 4)

    def test_diagnose_untouched(self):
        called = {}
        with mock.patch.object(sys, "argv",
                               ["netpulse.py", "--diagnose", "wifi"]), \
             mock.patch.object(np, "_run_diagnostics_on_screen",
                               side_effect=lambda *a, **k:
                               called.update(on_screen=True)), \
             mock.patch.object(np, "_exit_with_status",
                               side_effect=lambda: called.update(exit=True)), \
             mock.patch.object(np, "diagnose", side_effect=lambda *a, **k: None), \
             mock.patch.object(np, "_print_diagnosis"), \
             mock.patch.object(np, "_start_scapy_preload"), \
             mock.patch.object(np, "_start_update_check"):
            np.main()
        self.assertTrue(called.get("on_screen"))
        self.assertTrue(called.get("exit"))


if __name__ == "__main__":
    unittest.main()
