# -*- coding: utf-8 -*-
"""v1.26.0 场景合并 + 主页紧凑化 验收闸 (docs/verify.md S1/S3-S8 机械检查项)。

- S1 场景载荷 6 项: web/disconnect/gaming/wifi/site/monitor, 标题「网页打开慢」
- S3 合并场景执行口径: 11 项并集 / 7 条规则并集 / slow 全仓退役 / start 拒绝
- S4 终端菜单同步: 4 场景 + 工具区 5/6/7/A + 键位分派
- S5 卡片规模副行: 页面资产无「点击开始 →」, 副行走 modules 字段
- S6 窗口默认 1180×720
- S7 现场检测页 760 居中
- S8 旧续跑点 (profile:"slow") 不崩溃、不露英文 id

主页一屏 (S2) 属几何断言, 由实现侧无头浏览器量取, 不在本文件
(纯静态壳无浏览器依赖; 判定口径见 docs/verify.md 备注)。
"""
import http.client
import json
import threading
import unittest
from unittest import mock

import netpulse as np


# ── S1 · /api/scenarios 场景载荷 ──

class TestScenarioPayload(unittest.TestCase):

    def test_six_scenarios_in_order(self):
        meta = np._gui_meta()
        ids = [s["id"] for s in meta["scenarios"]]
        self.assertEqual(ids, ["web", "disconnect", "gaming", "wifi",
                               "site", "monitor"])

    def test_merged_label(self):
        meta = np._gui_meta()
        web = [s for s in meta["scenarios"] if s["id"] == "web"]
        self.assertEqual(len(web), 1)
        self.assertEqual(web[0]["label"], "网页打开慢")
        self.assertEqual(web[0]["modules"], 11)
        for gone in ("网络很慢", "网页打不开"):
            self.assertNotIn(gone, json.dumps(meta, ensure_ascii=False),
                             f"旧场景文案「{gone}」不应再出现")


# ── S3 · 合并场景数据口径与拒绝语义 ──

class TestMergedProfile(unittest.TestCase):

    def test_web_union_modules(self):
        self.assertEqual(set(np.DIAGNOSE_PROFILES["web"]),
                         {"gateway", "external", "dns", "wifi", "web",
                          "tcp", "tcpstats", "mtu", "route", "speedtest",
                          "bufferbloat"})
        self.assertEqual(len(np.DIAGNOSE_PROFILES["web"]), 11)

    def test_slow_retired(self):
        self.assertNotIn("slow", np.DIAGNOSE_PROFILES)
        self.assertNotIn("slow", np.SCENE_LABELS)
        self.assertNotIn("slow", np.SCENE_MENU_DESC)
        self.assertNotIn("slow", np.SCENE_MENU_KEYS.values())

    def test_web_union_rules(self):
        self.assertEqual(set(np.PROFILE_RULES["web"]),
                         {"bufferbloat", "gateway_loss", "dns_failure",
                          "wifi_weak", "tcp_loss_burst", "wan_interruption",
                          "mtu_blackhole"})

    def test_scene_menu_keys_renumbered(self):
        self.assertEqual(np.SCENE_MENU_KEYS,
                         {"1": "web", "2": "disconnect", "3": "gaming",
                          "4": "wifi"})
        self.assertEqual([k for k, _n, _d in np._SCENE_TOOL_ITEMS],
                         ["5", "6", "7", "A"])

    def test_merged_desc_matches_union(self):
        desc = np.SCENE_MENU_DESC["web"]
        for kw in ("测速", "缓冲膨胀", "DNS", "网页体验", "WiFi",
                   "MTU/路由", "TCP 质量"):
            self.assertIn(kw, desc, f"合并场景副行缺「{kw}」")

    def test_start_rejects_slow_profile(self):
        s = np._GuiSession()
        ok, err = s.start("slow")
        self.assertFalse(ok)
        self.assertIn("未知场景", err)
        self.assertNotEqual(s.snapshot()["phase"], "running")


# ── S4 · 终端菜单同步 ──

class TestTerminalMenu(unittest.TestCase):
    ANSI = np._ANSI_RE

    def _plain_lines(self, show_desc=True):
        text = "\n".join(np._menu_item_lines(show_desc=show_desc))
        return self.ANSI.sub("", text)

    def test_scene_rows(self):
        text = self._plain_lines()
        for name in ("网页打开慢", "经常断网", "游戏卡顿", "WiFi 信号差"):
            self.assertIn(name, text)
        self.assertNotIn("网络很慢", text)
        self.assertNotIn("网页打不开\n", text)

    def test_tool_rows_renumbered(self):
        text = self._plain_lines()
        for key, name in (("5", "现场检测"), ("6", "持续盯障"),
                          ("7", "高级选项"), ("A", "管理员模式")):
            self.assertIn(key, text)
            self.assertIn(name, text)

    def test_dispatch_key1_to_web_scene(self):
        with mock.patch("builtins.input", side_effect=["1", "0"]), \
             mock.patch.object(np, "_menu_clear"), \
             mock.patch.object(np, "_run_scene") as m_scene:
            np._scene_menu()
        m_scene.assert_called_once()
        self.assertEqual(m_scene.call_args[0][0], "web")

    def test_dispatch_key5_site_key6_monitor(self):
        with mock.patch("builtins.input", side_effect=["5", "0"]), \
             mock.patch.object(np, "_menu_clear"), \
             mock.patch.object(np, "run_site_visit") as m_site:
            np._scene_menu()
        m_site.assert_called_once()
        with mock.patch("builtins.input", side_effect=["6", "0"]), \
             mock.patch.object(np, "_menu_clear"), \
             mock.patch.object(np, "_run_scene_monitor") as m_mon:
            np._scene_menu()
        m_mon.assert_called_once()

    def test_dispatch_key7_advanced(self):
        with mock.patch("builtins.input", side_effect=["7", "q"]), \
             mock.patch.object(np, "_menu_clear"), \
             mock.patch.object(np, "_module_menu", return_value=False) as m_mm:
            self.assertFalse(np._scene_menu())
        m_mm.assert_called_once()

    def test_key9_is_invalid_now(self):
        # v1.26.0: 9 退役 → 无效选择路径 (重渲染 + 按 Enter 继续)
        with mock.patch("builtins.input", side_effect=["9", "", "0"]), \
             mock.patch.object(np, "_menu_clear"):
            self.assertFalse(np._scene_menu())


# ── S5/S6/S7 · 页面资产 (纯字符串闸, 静态壳零插值) ──

class TestPageAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.page = np._GUI_PAGE_HTML
        cls.css = np._GUI_CSS
        cls.js = np._GUI_JS

    def test_no_click_to_start_copy(self):
        self.assertNotIn("点击开始", self.js + self.page,
                         "卡片副行「点击开始 →」应退役")

    def test_scale_subrow_from_modules_field(self):
        self.assertIn("CARD_GO_TEXT", self.js)
        self.assertIn('s.modules + " 项模块"', self.js)

    def test_web_icon_is_gauge(self):
        # 合并卡用仪表 (慢) 图标; 原 slow 键退役
        self.assertNotIn("slow:", self.js.split("var CARD_GO_TEXT")[0])
        self.assertIn("M5 16a8 8 0 1 1 14 0", self.js)

    def test_window_size_1180x720(self):
        src = open(np.__file__, encoding="utf-8").read()
        self.assertIn("--window-size=1180,720", src)
        self.assertNotIn("1280,860", src)

    def test_home_compact_css(self):
        self.assertIn(".g-top{ height:52px;", self.css)
        self.assertIn(".g-h1{ font-size:22px;", self.css)
        self.assertIn("padding:22px 32px 20px", self.css)
        self.assertIn("min-height:140px", self.css)
        self.assertIn(".g-card-ic{ width:32px;", self.css)

    def test_site_page_centered_760(self):
        self.assertIn("max-width:760px; margin:0 auto;", self.css)
        self.assertIn("#site-check{ max-width:760px; margin:0 auto; }", self.css)

    def test_no_iframe_regression(self):
        self.assertNotIn("<iframe", self.page)


# ── S8 · 旧续跑点兼容 ──

class TestOldResumePoint(unittest.TestCase):

    def test_old_slow_point_label_passthrough(self):
        # 旧点 label 是落盘时的中文文案, 原样展示不崩溃
        summary = np._gui_resume_summary({
            "profile": "slow", "label": "网络很慢",
            "keys": ["gateway", "dns"], "completed": {"gateway": {}},
            "saved_at_ts": 1700000000})
        self.assertIsNotNone(summary)
        self.assertEqual(summary["label"], "网络很慢")
        self.assertEqual(summary["done"], 1)
        self.assertEqual(summary["total"], 2)

    def test_label_absent_no_english_id(self):
        summary = np._gui_resume_summary({
            "profile": "slow", "label": None,
            "keys": ["gateway"], "completed": {}, "saved_at_ts": None})
        self.assertEqual(summary["label"], "")


if __name__ == "__main__":
    unittest.main()
