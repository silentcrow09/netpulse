"""控制台全屏层测试 (v1.19.1): 备用屏幕缓冲区 + 固定画布 + 框内折行。

起因 (2026-11-12 实机反馈): 程序没有固定终端窗口尺寸, 终端一窄, 框内长行
就超出终端宽度被终端折行, 右边框被挤到下一行 → "边框线条错位"。

覆盖:
  S1 备用屏幕: 进/出序列 (ANSI 1049h/1049l)、嵌套只计数、非 TTY 与无 VT
     时整层跳过、异常路径也还原用户原屏幕;
  S2 固定画布: 宽高冻结 (min(固定常量, 真实终端尺寸)), 用户改窗口不重排;
  S3 框宽上限: _draw_box 不再无限撑, 超宽内容在框内折行 → 边框恒对齐;
  S4 CLI 接线: --json 不进备用屏幕 (stdout 必须是纯 JSON), 其余路径退出
     备用屏幕后把诊断汇总写回正常屏幕。
"""
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


class _Tty(io.StringIO):
    def isatty(self):
        return True


def _plain(rows):
    return [N._ANSI_RE.sub("", r) for r in rows]


class TestFullscreenSession(unittest.TestCase):
    """S1: 备用屏幕缓冲区会话。"""

    def setUp(self):
        self._depth = N._FULLSCREEN_DEPTH
        N._FULLSCREEN_DEPTH = 0

    def tearDown(self):
        N._FULLSCREEN_DEPTH = self._depth

    def test_enter_writes_smcup_exit_writes_rmcup(self):
        buf = _Tty()
        with mock.patch("sys.stdout", new=buf), \
             mock.patch.object(N, "_cli_enable_vt", return_value=True):
            self.assertTrue(N._console_fullscreen_enter())
            self.assertTrue(N._console_fullscreen_exit())
        out = buf.getvalue()
        self.assertIn("\x1b[?1049h", out, "进备用屏幕应写 smcup")
        self.assertIn("\x1b[?1049l", out, "退备用屏幕应写 rmcup")
        self.assertLess(out.index("\x1b[?1049h"), out.index("\x1b[?1049l"),
                        "必须先进后出")

    def test_nested_enter_counts_only(self):
        """已在备用屏幕里再 enter → 只加计数, 不重复切屏 (菜单内跑诊断)。"""
        buf = _Tty()
        with mock.patch("sys.stdout", new=buf), \
             mock.patch.object(N, "_cli_enable_vt", return_value=True):
            N._console_fullscreen_enter()
            self.assertFalse(N._console_fullscreen_enter())
            self.assertEqual(N._FULLSCREEN_DEPTH, 2)
            N._console_fullscreen_exit()
            self.assertEqual(N._FULLSCREEN_DEPTH, 1)
            N._console_fullscreen_exit()
        out = buf.getvalue()
        self.assertEqual(out.count("\x1b[?1049h"), 1, "嵌套不应重复切屏")
        self.assertEqual(out.count("\x1b[?1049l"), 1)

    def test_non_tty_never_enters(self):
        """管道 / 重定向 → 不进备用屏幕 (机器可读输出不能被终端模式吞掉)。"""
        buf = io.StringIO()
        with mock.patch("sys.stdout", new=buf), \
             mock.patch.object(N, "_cli_enable_vt", return_value=True):
            self.assertFalse(N._console_fullscreen_enter())
        self.assertEqual(buf.getvalue(), "")

    def test_no_vt_never_enters(self):
        """Win7 老 conhost 不认 1049 → 整层跳过 (只保留固定画布排版)。"""
        buf = _Tty()
        with mock.patch("sys.stdout", new=buf), \
             mock.patch.object(N, "_cli_enable_vt", return_value=False):
            self.assertFalse(N._console_fullscreen_enter())
        self.assertEqual(buf.getvalue(), "")

    def test_context_manager_restores_on_exception(self):
        """异常路径也必须退出备用屏幕 (别把用户终端留在里面)。"""
        buf = _Tty()
        with mock.patch("sys.stdout", new=buf), \
             mock.patch.object(N, "_cli_enable_vt", return_value=True):
            with self.assertRaises(RuntimeError):
                with N._console_fullscreen():
                    raise RuntimeError("boom")
        self.assertIn("\x1b[?1049l", buf.getvalue())
        self.assertEqual(N._FULLSCREEN_DEPTH, 0)

    def test_exit_without_enter_is_noop(self):
        """没进过就退 → 无副作用 (不许打出裸转义序列)。"""
        buf = _Tty()
        with mock.patch("sys.stdout", new=buf):
            self.assertFalse(N._console_fullscreen_exit())
        self.assertEqual(buf.getvalue(), "")


class TestConsoleLayout(unittest.TestCase):
    """S2: 固定画布 (宽高)。"""

    def setUp(self):
        self._saved = dict(N._CONSOLE_LAYOUT)
        N._CONSOLE_LAYOUT = {"cols": None, "rows": None}

    def tearDown(self):
        N._CONSOLE_LAYOUT = self._saved

    def test_wide_terminal_uses_fixed_canvas(self):
        """终端比画布宽 → 按固定常量排版 (布局稳定, 不随窗口宽度漂移)。"""
        with mock.patch.object(N.shutil, "get_terminal_size",
                               return_value=os.terminal_size((160, 60))):
            self.assertEqual(N._console_layout_size(),
                             (N.CONSOLE_FIXED_COLS, N.CONSOLE_FIXED_ROWS))

    def test_narrow_terminal_uses_real_size(self):
        """终端比画布窄 → 按真实尺寸排版: 任何一行都不折行 (边框恒对齐)。"""
        with mock.patch.object(N.shutil, "get_terminal_size",
                               return_value=os.terminal_size((60, 20))):
            self.assertEqual(N._console_layout_size(), (60, 20))

    def test_layout_frozen_once(self):
        """尺寸只冻结一次: 用户中途改窗口大小不重排。"""
        with mock.patch.object(N.shutil, "get_terminal_size",
                               return_value=os.terminal_size((120, 40))):
            first = N._console_layout_size()
        with mock.patch.object(N.shutil, "get_terminal_size",
                               return_value=os.terminal_size((200, 60))):
            self.assertEqual(N._console_layout_size(), first)

    def test_term_width_follows_canvas(self):
        with mock.patch.object(N.shutil, "get_terminal_size",
                               return_value=os.terminal_size((60, 20))):
            self.assertEqual(N._term_width(), 60)
            self.assertEqual(N._term_height(), 20)


class TestBoxWidthGuard(unittest.TestCase):
    """S3: 框宽上限 + 框内折行 (边框恒对齐)。"""

    def setUp(self):
        # 套件里更早的测试可能触发真实 _cli_enable_vt(), 把 _C_NOCOLOR 全局
        # 置 True (无色) —— 本类要断言 ANSI 续行样式, 自己控制基线。
        self._saved_nocolor = N._C_NOCOLOR
        N._C_NOCOLOR = False

    def tearDown(self):
        N._C_NOCOLOR = self._saved_nocolor

    def test_box_never_exceeds_canvas(self):
        """框宽不得超过画布宽度 (超出会被终端折行 → 右边框错位)。"""
        rows = N._draw_box(["超长内容" * 200], title="测试")
        widths = {N._disp_width(N._ANSI_RE.sub("", r)) for r in rows}
        self.assertEqual(len(widths), 1, f"框各行宽度不一致: {sorted(widths)}")
        self.assertLessEqual(widths.pop(), N._term_width())

    def test_long_content_wrapped_inside_box(self):
        """长内容在框内折成多行 (不是溢出到终端之外)。"""
        rows = N._draw_box(["A" * 300], title="测试")
        self.assertGreater(len(rows), 3, "长内容应折成多行")
        for r in rows:
            plain = N._ANSI_RE.sub("", r).rstrip()
            self.assertTrue(plain.endswith(("│", "┐", "┘")),
                            f"折行后边框不完整: {plain!r}")

    def test_wrap_display_respects_width(self):
        s = N._c("中文" * 30, N.C_CYAN)
        lines = N._wrap_display(s, 20)
        self.assertGreater(len(lines), 1)
        for ln in lines:
            self.assertLessEqual(N._disp_width(ln), 20)

    def test_wrap_display_reopens_style(self):
        """续行重发当前 SGR 样式, 行尾复位 (颜色不能串到下一行)。"""
        s = N._c("中文" * 30, N.C_CYAN)
        lines = N._wrap_display(s, 20)
        self.assertTrue(lines[1].startswith("\x1b[96m"), "续行应重发样式")
        self.assertTrue(lines[0].endswith("\x1b[0m"), "折行处应复位")

    def test_truncate_display_marks_cut(self):
        out = N._truncate_display("超长内容" * 20, 10)
        self.assertLessEqual(N._disp_width(out), 10)
        self.assertTrue(out.endswith("…"))

    def test_truncate_display_keeps_short_string(self):
        self.assertEqual(N._truncate_display("短", 10), "短")


class TestRunOnScreen(unittest.TestCase):
    """S4: CLI 路径接线。"""

    def setUp(self):
        self._depth = N._FULLSCREEN_DEPTH
        N._FULLSCREEN_DEPTH = 0

    def tearDown(self):
        N._FULLSCREEN_DEPTH = self._depth

    def test_json_mode_never_enters_fullscreen(self):
        """--json 的 stdout 必须是纯 JSON, 不能被终端模式吞进备用屏幕。"""
        buf = _Tty()
        with mock.patch.object(N, "run_diagnostics",
                               return_value={"status": {}}) as m, \
             mock.patch("sys.stdout", new=buf), \
             mock.patch.object(N, "_cli_enable_vt", return_value=True):
            _run, fs = N._run_diagnostics_on_screen(["gateway"], as_json=True)
        self.assertFalse(fs)
        self.assertNotIn("\x1b[?1049h", buf.getvalue())
        m.assert_called_once()

    def test_summary_written_back_after_fullscreen(self):
        """退出备用屏幕后把这一轮输出原样回写正常屏幕 (细节与结论不丢)。"""
        buf = _Tty()

        def _fake_run(*_a, **_kw):
            print("┌─ 诊断汇总 ─┐")
            print("│ 健康分 87 / 100 │")
            return {"status": {"gateway": "完成"}}

        with mock.patch.object(N, "run_diagnostics", side_effect=_fake_run), \
             mock.patch("sys.stdout", new=buf), \
             mock.patch.object(N, "_cli_enable_vt", return_value=True):
            _run, fs = N._run_diagnostics_on_screen(["gateway"])
        out = buf.getvalue()
        self.assertTrue(fs)
        plain = N._ANSI_RE.sub("", out)
        self.assertIn("诊断汇总", plain)
        self.assertIn("健康分 87 / 100", plain)
        # 回写必须发生在退出备用屏幕之后 (屏上先实时显示, 退出后回写一份)
        self.assertLess(out.index("\x1b[?1049l"), out.rindex("诊断汇总"),
                        "回写必须写在退出备用屏幕之后")
        # 屏幕上 (备用屏幕内) 与回滚缓冲 (回写后) 各有一份 → 输出没丢
        self.assertEqual(plain.count("健康分 87 / 100"), 2)

    def test_no_fullscreen_when_not_tty(self):
        """非交互终端 → 保持普通屏幕; 汇总由 run_diagnostics 自己打印。"""
        buf = io.StringIO()
        with mock.patch.object(N, "run_diagnostics",
                               return_value={"status": {"gateway": "完成"}}) as m, \
             mock.patch("sys.stdout", new=buf):
            _run, fs = N._run_diagnostics_on_screen(["gateway"])
        self.assertFalse(fs)
        self.assertNotIn("\x1b[?1049h", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
