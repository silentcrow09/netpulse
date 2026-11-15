# -*- coding: utf-8 -*-
"""v1.26.2 回归: GUI 窗口尺寸真的生效 + 主页撑满一屏。

背景 (2026-11-15 用户实测):
  Chromium 只在「自己不是已在运行的实例」时才应用 `--window-size`; 用户
  自己的 Chrome 开着时, app 窗口落回浏览器默认尺寸 (实测 945x1012),
  `--window-size=1180,680` 形同虚设。主页内容又是恒定的 485px (与窗口
  无关) → 底下空 421px, 用户报「主页高度太高, 下面一大段空白」。

两个闸:
  A 启动链必须给 app 窗口独立 profile (否则 --window-size 被忽略);
  B 主页必须撑满一屏 (min-height 扣顶栏 + 卡片行吃掉剩余高度)。

页面高度的**实测**不在本文件 (要真浏览器): 用开发期工具
tests/_gui_height_probe.py (八视图内容高) 与 tests/_gui_real_window.py
(真 --app 窗口客户区尺寸)。
"""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


class TestWindowSizeEffective(unittest.TestCase):
    """A · 窗口尺寸参数要真的落到浏览器进程上"""

    def setUp(self):
        np._GUI_RESET_FOR_TEST()

    def test_app_launch_uses_dedicated_profile(self):
        """app 窗口必须带 --user-data-dir (独立 profile → --window-size 生效)"""
        procs = []
        with mock.patch.object(np, "_find_pdf_browser",
                               return_value="C:/x/msedge.exe"), \
             mock.patch.object(np.subprocess, "Popen",
                               side_effect=lambda *a, **k: procs.append(a)):
            how = np._gui_launch_browser("http://127.0.0.1:1/?t=abc")
        self.assertEqual(how, "app")
        args = procs[0][0]
        self.assertIn("--app=http://127.0.0.1:1/?t=abc", args)
        self.assertIn("--window-size=1180,680", args)
        self.assertTrue(any(a.startswith("--user-data-dir=") for a in args),
                        "app 窗口必须用独立 profile, 否则用户 Chrome 在跑时"
                        " --window-size 会被忽略")
        self.assertIn("--no-first-run", args)
        self.assertIn("--no-default-browser-check", args)

    def test_profile_dir_under_localappdata(self):
        """profile 目录落在 %LOCALAPPDATA%\\NetPulse\\ 下 (持久化, 可写)"""
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": "C:/fake/local"}):
            d = np._gui_app_profile_dir()
        self.assertTrue(d)
        self.assertIn("NetPulse", d)
        self.assertIn("gui-chrome-profile", d)

    def test_profile_dir_fallback_when_unwritable(self):
        """不可写时退化到临时目录, 不能抛异常挡住 GUI 启动"""
        with mock.patch.object(np.os, "makedirs", side_effect=OSError("ro")):
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": "C:/fake/local"}):
                d = np._gui_app_profile_dir()
        self.assertTrue(d)          # 临时目录兜底


class TestHomeFillsViewport(unittest.TestCase):
    """B · 主页撑满一屏 (不留底白)"""

    @classmethod
    def setUpClass(cls):
        cls.css = np._GUI_CSS

    def test_home_min_height_covers_viewport(self):
        self.assertIn("min-height:calc(100vh - 52px)", self.css)
        self.assertIn("display:flex; flex-direction:column;", self.css)

    def test_cards_grid_absorbs_free_height(self):
        self.assertIn(".g-cards{ display:grid; grid-template-columns:repeat(3,1fr); "
                      "gap:12px; margin-top:14px;\n          flex:1; }", self.css)

    def test_card_height_bounded(self):
        """卡片高度有上限: 窗口被拉很高时不至于变成空壳"""
        self.assertIn("max-height:215px;", self.css)

    def test_home_padding_bottom(self):
        self.assertIn("padding:22px 32px 16px", self.css)


if __name__ == "__main__":
    unittest.main()
