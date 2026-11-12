"""控制台 UI 基础设施测试（控制台现代化批次 1）。

覆盖 docs/verify.md 的 S1 (VT 不可用自动降色) / S2 (VT 可用颜色不变)
/ S3 (终端状态色板覆盖且语义对齐)。
"""
import ctypes
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


class _FakeKernel32:
    """kernel32 桩: 模拟 GetConsoleMode / SetConsoleMode 的三种形态。"""

    def __init__(self, mode_fail=False, vt_fail=False):
        self.mode_fail = mode_fail      # GetConsoleMode 失败 = 重定向/无控制台
        self.vt_fail = vt_fail          # SetConsoleMode 拒绝 VT 标志 = 旧 conhost

    def GetStdHandle(self, what):
        return 999

    def GetConsoleMode(self, h, ref_mode):
        return 0 if self.mode_fail else 1

    def SetConsoleMode(self, h, mode):
        return 0 if self.vt_fail else 1


class TestVtAutoNoColor(unittest.TestCase):
    """S1/S2: VT 确认失败 -> 自动 _C_NOCOLOR; 成功 -> 颜色行为不变。"""

    def setUp(self):
        # 全量套件里, 先于本文件的测试可能在管道环境触发**真实** _cli_enable_vt(),
        # 其自动降色副作用会全局置 True 且无人还原 (产品行为正确, 测试环境需隔离)。
        # 因此这里不只保存, 还要归零基线 —— 用例自己控制起始状态, 顺序无关。
        self._saved = N._C_NOCOLOR
        N._C_NOCOLOR = False

    def tearDown(self):
        N._C_NOCOLOR = self._saved

    def _run_with(self, fake):
        """在 mock 的 kernel32 下调 _cli_enable_vt, 返回 (返回值, 输出文本)。"""
        fake_loader = mock.Mock()
        fake_loader.kernel32 = fake
        with mock.patch.object(ctypes, "windll", fake_loader):
            ok = N._cli_enable_vt()
        return ok, N._c("测试", N.C_CYAN)

    def test_vt_rejected_forces_nocolor(self):
        """旧 conhost 拒绝 VT 标志 -> 无色, 输出无转义序列 (Win7 乱码修复)。"""
        ok, out = self._run_with(_FakeKernel32(vt_fail=True))
        self.assertFalse(ok)
        self.assertTrue(N._C_NOCOLOR, "VT 失败必须自动置 _C_NOCOLOR")
        self.assertNotIn("\x1b[", out, "无色模式下不得再输出 ANSI 码")

    def test_no_console_forces_nocolor(self):
        """GetConsoleMode 失败 (重定向/无控制台) -> 同样自动无色。"""
        ok, out = self._run_with(_FakeKernel32(mode_fail=True))
        self.assertFalse(ok)
        self.assertTrue(N._C_NOCOLOR)
        self.assertNotIn("\x1b[", out)

    def test_vt_ok_keeps_color(self):
        """VT 启用成功 -> 返回 True 且颜色行为与原先一致。"""
        ok, out = self._run_with(_FakeKernel32())
        self.assertTrue(ok)
        self.assertFalse(N._C_NOCOLOR)
        self.assertIn("\x1b[", out, "VT 可用时不得被误降级为无色")

    def test_explicit_no_color_still_forced(self):
        """--no-color (直接置 _C_NOCOLOR) 后 VT 成功也不复活颜色。"""
        N._C_NOCOLOR = True
        ok, out = self._run_with(_FakeKernel32())
        self.assertTrue(ok)
        self.assertTrue(N._C_NOCOLOR, "用户显式 --no-color 必须保持")
        self.assertNotIn("\x1b[", out)


class TestStatusStylePalette(unittest.TestCase):
    """S3: 终端状态色板覆盖 STATUS_BAR_ORDER 全部键且语义对齐报告层。"""

    def test_covers_all_statuses(self):
        for st in N.STATUS_BAR_ORDER:
            self.assertIn(st, N.STATUS_STYLE, f"状态 {st} 缺少终端配色")

    def test_semantics_aligned_with_report(self):
        """超时=灰 (对齐报告层中性色), 异常/错误=红, 完成/正常=绿, 警告=黄。"""
        self.assertEqual(N.STATUS_STYLE["超时"], N.C_GRAY,
                         "超时不是故障, 不得与异常/错误同级刺眼")
        self.assertEqual(N.STATUS_STYLE["异常"], N.C_RED)
        self.assertEqual(N.STATUS_STYLE["错误"], N.C_RED)
        self.assertEqual(N.STATUS_STYLE["完成"], N.C_GREEN)
        self.assertEqual(N.STATUS_STYLE["正常"], N.C_GREEN)
        self.assertEqual(N.STATUS_STYLE["警告"], N.C_YELLOW)
        self.assertEqual(N.STATUS_STYLE["未检测"], N.C_GRAY)

    def test_badge_width_ignores_ansi(self):
        """徽章显示宽度 (ANSI 不计, CJK=2) 必须等于纯文本宽度。"""
        for st in N.STATUS_BAR_ORDER:
            badge = N._cli_status_badge(st)
            self.assertEqual(N._disp_width(badge), N._disp_width(f"[{st}]"),
                             f"状态 {st} 徽章显示宽度被 ANSI 码污染")


# ══ 控制台现代化批次 2 (docs/verify.md S5-S8) ══

def _plain(rows):
    """剥 ANSI 取纯文本行 (对齐断言用)。"""
    return [N._ANSI_RE.sub("", r) for r in rows]


class TestBoxRenderer(unittest.TestCase):
    """S5/S8 基础: _draw_box 闭环 / 等宽 / 标题嵌框 / 空行占位。"""

    def test_closed_and_equal_width(self):
        rows = _plain(N._draw_box(["中文内容", "", "abc 123"], title="标题"))
        self.assertEqual(len(rows), 5)  # 上框 + 3 内容 + 下框
        widths = {N._disp_width(r) for r in rows}
        self.assertEqual(len(widths), 1, f"框各行宽度不一致: {sorted(widths)}")
        self.assertTrue(rows[0].startswith("  ┌") and rows[0].endswith("┐"))
        self.assertTrue(rows[-1].startswith("  └") and rows[-1].endswith("┘"))
        for r in rows[1:-1]:
            self.assertTrue(r.startswith("  │") and r.rstrip().endswith("│"))

    def test_title_embedded_in_top_border(self):
        rows = _plain(N._draw_box(["x"], title="异常自动上报"))
        self.assertIn("┌─ 异常自动上报 ", rows[0])

    def test_width_adapts_to_content(self):
        narrow = _plain(N._draw_box(["短"])[0:1])
        wide = _plain(N._draw_box(["这是一条明显更长的提示内容行"])[0:1])
        self.assertLess(N._disp_width(narrow[0]), N._disp_width(wide[0]))


class TestProgressPrimitives(unittest.TestCase):
    """S6 基础: 进度条比例与钳制 / 状态符号双编码。"""

    def setUp(self):
        # 与 TestVtAutoNoColor 同理: 套件里更早的测试可能在管道环境触发真实
        # _cli_enable_vt() 把 _C_NOCOLOR 全局置 True, 颜色断言需要归零基线。
        self._saved = N._C_NOCOLOR
        N._C_NOCOLOR = False

    def tearDown(self):
        N._C_NOCOLOR = self._saved

    def test_bar_ratio_and_clamp(self):
        self.assertEqual(N._progress_bar(12, 23).count("█"), (36 * 12) // 23)
        self.assertEqual(N._progress_bar(0, 23).count("█"), 0)
        self.assertEqual(N._progress_bar(99, 23).count("░"), 0, "超界要钳制")
        self.assertIn("12/23", N._progress_bar(12, 23))
        self.assertIn("正在 网页体验", N._progress_bar(12, 23, "网页体验"))

    def test_row_marks_colors(self):
        for st, mark, color in (("完成", "✓", N.C_GREEN), ("警告", "⚠", N.C_YELLOW),
                                ("异常", "✗", N.C_RED), ("错误", "✗", N.C_RED),
                                ("超时", "○", N.C_GRAY), ("未检测", "○", N.C_GRAY)):
            row = N._module_progress_row(1, 23, "模块", st)
            self.assertIn(mark, row, f"状态 {st} 缺符号")
            self.assertIn(color, row, f"状态 {st} 缺配色")
        row_pending = N._module_progress_row(1, 23, "模块", None)
        self.assertIn("…", row_pending)

    def test_marks_cover_all_statuses(self):
        for st in N.STATUS_BAR_ORDER:
            self.assertIn(st, N.CLI_STATUS_MARKS)


class TestMenuItems(unittest.TestCase):
    """S5: 双分区菜单行 / 全部键位 / 副行可收起 / 无底色 (实机反馈修订)。"""

    def test_two_sections_all_items(self):
        text = N._ANSI_RE.sub("", "\n".join(N._menu_item_lines(show_desc=True)))
        self.assertIn("按问题选场景", text)
        self.assertIn("工具与报告", text)
        for key in "12345679A":
            self.assertIn(f" {key} ", text, f"菜单缺键位 {key}")

    def test_desc_toggle(self):
        wide = "\n".join(_plain(N._menu_item_lines(show_desc=True)))
        narrow = "\n".join(_plain(N._menu_item_lines(show_desc=False)))
        desc = N.SCENE_MENU_DESC["slow"]
        self.assertIn(desc, wide)
        self.assertNotIn(desc, narrow, "窄终端应收起副行")
        for p, d in N.SCENE_MENU_DESC.items():
            self.assertTrue(d, f"场景 {p} 缺副行文案")

    def test_desc_matches_profile_modules(self):
        """副行不得承诺场景模块之外的能力 (抽查关键词)。"""
        pairs = {"gaming": "NAT", "wifi": "WiFi", "slow": "测速",
                 "web": "DNS", "disconnect": "外网"}
        for p, kw in pairs.items():
            self.assertIn(kw, N.SCENE_MENU_DESC[p])

    def test_no_background_fill(self):
        """菜单行不得铺底色 (实机反馈: ANSI 100 在经典 conhost 是明显灰带)。"""
        for ln in N._menu_item_lines(show_desc=True):
            self.assertNotIn("[100", ln, f"菜单行带底色: {ln!r}")


class TestMenuBanner(unittest.TestCase):
    """S5: 闭环框横幅 (权限/本机网络进框, 公网补行在框外)。"""

    def test_box_uniform_pub_outside(self):
        fake = ({"ip": "192.168.1.23", "gw": "192.168.1.1", "dns": "223.5.5.5"},
                ("117.32.1.2", "中国 / 浙江 / 杭州", "电信"))
        with mock.patch.object(N, "_menu_net_info", return_value=fake):
            rows = _plain(N._menu_banner_lines(notice=None))
        widths = {N._disp_width(r) for r in rows[:3]}   # 框体三行
        self.assertEqual(len(widths), 1, f"横幅框宽度不一致: {sorted(widths)}")
        self.assertIn("本机 192.168.1.23", rows[1])
        self.assertIn("网关 192.168.1.1", rows[1])
        self.assertTrue(any("公网 117.32.1.2" in r for r in rows[3:]),
                        "公网补行应在框外")

    def test_pub_absent_no_line(self):
        fake = ({"ip": "192.168.1.23", "gw": None, "dns": None}, None)
        with mock.patch.object(N, "_menu_net_info", return_value=fake):
            rows = _plain(N._menu_banner_lines(notice=None))
        self.assertFalse(any("公网" in r for r in rows), "取不到公网不得占位")

    def test_narrow_terminal_drops_net_segs(self):
        fake = ({"ip": "192.168.1.23", "gw": "192.168.1.1", "dns": "223.5.5.5"},
                None)
        with mock.patch.object(N, "_menu_net_info", return_value=fake), \
             mock.patch.object(N, "_term_width", return_value=44):
            rows = _plain(N._menu_banner_lines(notice=None))
        self.assertNotIn("223.5.5.5", rows[1], "窄终端应从右往左丢网络段")


class TestHealthBox(unittest.TestCase):
    """S7: 完成屏健康分区与 HTML 报告同源。"""

    @staticmethod
    def _report():
        keys = ["gateway", "dns", "wifi", "external", "tcpstats", "mtu",
                "web", "loop", "route", "arp", "dhcp", "proxy", "ipv6",
                "nattype", "linkspeed", "speedtest", "bufferbloat",
                "iperf3", "tcpcc", "port", "lan", "ping", "webq"]
        summary = {}
        for i, k in enumerate(keys):
            summary[k] = ("完成" if i < 19 else "警告" if i < 21 else
                          "异常" if i == 21 else "未检测")
        return {
            "health": {"score": 87, "grade": "B", "label": "良好"},
            "summary": summary,
            "counts": {"完成": 19, "警告": 2, "异常": 1, "错误": 0,
                       "超时": 0, "未检测": 1},
            "selected_modules": 23, "total_modules": 23,
            "duration_ms": 102000,
        }

    def test_score_grade_and_bar(self):
        rows = _plain(N._health_box_lines(self._report()))
        self.assertIn("87 / 100", rows[0])
        self.assertIn("B 级", rows[0])
        self.assertEqual(rows[1].count("█"), (26 * 87) // 100)
        self.assertIn("实检 23/23 项", rows[0])

    def test_distribution_uses_summary_scope(self):
        """分布条按 summary (全口径, 与 HTML 状态分布条同源) 计数。"""
        rows = _plain(N._health_box_lines(self._report()))
        dist = rows[2]
        for seg in ("✓ 完成 19", "⚠ 警告 2", "✗ 异常 1", "○ 未检测 1"):
            self.assertIn(seg, dist)

    def test_empty_health_no_lines(self):
        self.assertEqual(N._health_box_lines({"health": {}}), [])
        self.assertEqual(N._health_box_lines(None), [])

    def test_score_none_is_honest(self):
        """健康分不可用时框内如实说明, 不伪装 (AGENTS.md 口径矛盾教训)。"""
        import io as _io

        class _Tty(_io.StringIO):
            def isatty(self):
                return True

        buf = _Tty()
        with mock.patch.object(N, "_print_diagnosis"), \
             mock.patch("sys.stdout", new=buf):
            N._scene_summary("slow", "网络很慢", None, report={"health": {}})
        out = N._ANSI_RE.sub("", buf.getvalue())
        self.assertIn("本次未能计算健康分", out)


class TestPauseMenuOrOpen(unittest.TestCase):
    """S7: 完成屏快捷键 Enter 回菜单 / [H] 打开报告。"""

    def test_h_opens_report_once(self):
        opened = []
        with mock.patch("builtins.input", return_value="h"), \
             mock.patch("os.startfile", side_effect=opened.append,
                        create=True):
            N._pause_menu_or_open(r"D:\x\r.html")
        self.assertEqual(opened, [r"D:\x\r.html"])

    def test_enter_never_opens(self):
        opened = []
        with mock.patch("builtins.input", return_value=""), \
             mock.patch("os.startfile", side_effect=opened.append,
                        create=True):
            N._pause_menu_or_open(r"D:\x\r.html")
        self.assertEqual(opened, [])

    def test_no_path_no_open_branch(self):
        opened = []
        with mock.patch("builtins.input", return_value="h"), \
             mock.patch("os.startfile", side_effect=opened.append,
                        create=True):
            N._pause_menu_or_open(None)
        self.assertEqual(opened, [], "无报告路径时 [H] 不得触发打开")


class TestSceneSummary(unittest.TestCase):
    """S7: 完成屏整屏 (健康分区框 + 根因区 + 统一分隔线)。"""

    def test_renders_health_box(self):
        import io as _io

        class _Tty(_io.StringIO):
            def isatty(self):
                return True

        report = TestHealthBox._report()
        buf = _Tty()
        with mock.patch.object(N, "_print_diagnosis"), \
             mock.patch.object(N.sys.stdout, "isatty", return_value=True), \
             mock.patch("sys.stdout", new=buf):
            N._scene_summary("slow", "网络很慢", None, report=report)
        out = N._ANSI_RE.sub("", buf.getvalue())
        self.assertIn("NetPulse › 网络很慢 › 检测完成", out)
        self.assertIn("┌─ 网络健康", out)
        self.assertIn("└", out)
        self.assertIn("87 / 100", out)
        self.assertNotIn("=====", out, "等号横线应彻底退场")


class TestModuleMenuCompact(unittest.TestCase):
    """2026-11-12 反馈: 高级菜单内容多到默认窗口放不下 —— 行数预算锁。"""

    def test_line_budget_fits_default_window(self):
        """横幅 3 行 + 菜单体 + 空行 + 脚注 + 分隔线 ≤ 25 行 (默认窗口 30 行)。"""
        total = 3 + len(N._module_menu_lines()) + 3
        self.assertLessEqual(total, 25, f"高级菜单超出一屏预算: {total} 行")

    def test_all_modules_listed(self):
        text = N._ANSI_RE.sub("", "\n".join(N._module_menu_lines()))
        for _cat, keys, _d in N.MODULE_CATEGORIES:
            for k in keys:
                self.assertIn(N.MODULE_MAP[k][0], text, f"菜单缺模块 {k}")
        for letter in ("a", "b", "c"):
            self.assertIn(f"[{letter}]", text)
        self.assertNotIn("快捷:", text, "旧版重复的快捷行应已移除")


class TestDiagnosisSummary(unittest.TestCase):
    """2026-11-12 反馈: 多模块诊断终端只给一段总结, 不逐模块铺开。"""

    def test_summary_counts_and_attention(self):
        results = {"gateway": "完成", "dns": "完成", "wifi": "警告",
                   "tcpstats": "异常", "web": "超时", "arp": "未检测"}
        rows = _plain(N._diagnosis_summary_lines(results))
        self.assertIn("✓ 完成 2", rows[0])
        self.assertIn("⚠ 警告 1", rows[0])
        self.assertIn("✗ 异常 1", rows[0])
        self.assertIn("○ 超时 1", rows[0])
        self.assertIn("○ 未检测 1", rows[0])
        self.assertIn("需关注", rows[1])
        # 需关注名单必须带模块中文名与状态 (未检测不算关注项)
        self.assertIn(f"{N.MODULE_MAP['wifi'][0]} (警告)", rows[1])
        self.assertIn(f"{N.MODULE_MAP['tcpstats'][0]} (异常)", rows[1])
        self.assertNotIn(N.MODULE_MAP["arp"][0], rows[1])

    def test_summary_all_ok(self):
        rows = _plain(N._diagnosis_summary_lines(
            {"gateway": "完成", "dns": "完成"}))
        self.assertIn("✓ 全部完成，未发现问题", rows[1])

    def test_print_modules_false_skips_flood(self):
        """print_modules=False: 无 ▶ 逐模块块, 保留诊断汇总框。"""
        import io as _io

        class _Buf(_io.StringIO):
            def isatty(self):
                return True

        buf = _Buf()
        fake = ({"gateway": "完成"}, {"gateway": {"status": "完成"}})
        with mock.patch.object(N, "_run_diagnostics_sequential",
                               return_value=fake), \
             mock.patch("sys.stdout", new=buf):
            N.run_diagnostics(["gateway"], banner=False,
                              print_modules=False)
        out = buf.getvalue()
        self.assertNotIn("▶", out, "print_modules=False 不得逐模块打印")
        self.assertIn("诊断汇总", out)
        self.assertIn("┌─ 诊断汇总", out)

    def test_print_modules_default_keeps_details(self):
        """默认 (CLI) 行为不变: 逐模块块照打, 既有测试的 ▶ 断言不回归。"""
        import io as _io

        class _Buf(_io.StringIO):
            def isatty(self):
                return True

        buf = _Buf()
        fake = ({"gateway": "完成"}, {"gateway": {"status": "完成"}})
        with mock.patch.object(N, "_run_diagnostics_sequential",
                               return_value=fake), \
             mock.patch("sys.stdout", new=buf):
            N.run_diagnostics(["gateway"], banner=False)
        self.assertIn("▶", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
