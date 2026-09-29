# -*- coding: utf-8 -*-
"""v1.14.7 终端排版回归: _print_cols 两列进度行对齐 (CJK 按显示宽计 2)。

跑用: cd 到项目根目录, `python tests/test_cli_layout.py`
"""
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N


def _capture(rows):
    """跑 _print_cols, 返回输出行列表 (mock _safe_print 免终端依赖)。"""
    buf = io.StringIO()
    with mock.patch.object(N, "_safe_print", lambda s: buf.write(s + "\n")):
        N._print_cols(rows)
    return buf.getvalue().splitlines()


def _col2_disp(lines, i, cell):
    """第 i 行中 cell 的起始**显示宽**位置 (CJK 行字符数 ≠ 显示宽)。"""
    j = lines[i].index(cell)
    return N._disp_width(lines[i][:j])


class TestPrintCols(unittest.TestCase):
    def test_even_rows_two_cols(self):
        rows = [(t, t) for t in ("  [1/4] 正在 链路速率 …", "  [2/4] 正在 DHCP …",
                                 "  [3/4] 正在 DNS …", "  [4/4] 正在 网页体检 …")]
        lines = _capture(rows)
        self.assertEqual(len(lines), 2)
        w = max(N._disp_width(p) for p, _ in rows) + 3
        # 第 2 列起点两行一致 (按显示宽对齐, CJK 行字符位置 ≠ 显示宽)
        self.assertEqual(_col2_disp(lines, 0, "  [2/4]"), w)
        self.assertEqual(_col2_disp(lines, 1, "  [4/4]"), w)

    def test_odd_rows_last_single_col(self):
        rows = [("aaa", "aaa"), ("bbbb", "bbbb"), ("cc", "cc")]
        lines = _capture(rows)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], "cc")

    def test_cjk_ascii_mixed_align_by_display_width(self):
        """CJK 名 (显示宽 2) 与 ASCII 名混排, 对齐按显示宽而非字符数。"""
        l1 = "  [1/2] 正在 网页体检 …"    # CJK 4 字 = 宽 8
        l2 = "  [2/2] 正在 speedtest …"  # ASCII 9 字 = 宽 9
        lines = _capture([(l1, l1), (l2, l2)])
        w = max(N._disp_width(x) for x in (l1, l2)) + 3
        self.assertEqual(_col2_disp(lines, 0, l2), w)

    def test_ansi_in_colored_not_counted(self):
        """colored 串里的 ANSI 转义不参与宽度计算 (_disp_width 已剥)。"""
        colored = N._c("  [1/1] 正在 X …", "\x1b[90m")
        lines = _capture([("  [1/1] 正在 X …", colored)])
        self.assertEqual(lines[0], colored)

    def test_empty_rows_no_output(self):
        self.assertEqual(_capture([]), [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
    print("OK")
