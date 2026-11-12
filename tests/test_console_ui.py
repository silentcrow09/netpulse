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


if __name__ == "__main__":
    unittest.main()
