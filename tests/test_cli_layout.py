# -*- coding: utf-8 -*-
"""v1.14.7 终端排版回归: _print_cols 两列进度行对齐 (CJK 按显示宽计 2)。

跑用: cd 到项目根目录, `python tests/test_cli_layout.py`
"""
import contextlib
import io
import json
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


class TestJsonStdoutPure(unittest.TestCase):
    """v1.15.0 审查 P1-12: `--json` 的 stdout 必须是**纯 JSON**。

    旧版 stdout = banner + ANSI + 每模块一个 JSON 对象 + 尾部汇总,
    脚本 json.loads 直接失败 (README 承诺「便于脚本解析」)。
    现在: 人读输出整体改走 stderr, stdout 只留一个 JSON 文档
    {模块 key: 该模块完整结果}。
    """

    _KEYS = ("dns", "gateway")

    def _patches(self, results, full):
        return [
            mock.patch.object(N, "_run_diagnostics_sequential",
                              return_value=(results, full)),
            mock.patch.object(N, "get_local_ip", return_value="192.168.1.5"),
            mock.patch.object(N, "get_default_gateway", return_value="192.168.1.1"),
            mock.patch.object(N, "get_dns_servers", return_value=["223.5.5.5"]),
            mock.patch.object(N, "get_public_ip", return_value="1.2.3.4"),
            mock.patch.object(N, "get_ip_geo", return_value=None),
            mock.patch.object(N, "get_public_ipv6", return_value=""),
        ]

    def _run(self, as_json=True):
        out, err = io.StringIO(), io.StringIO()
        results = {k: "完成" for k in self._KEYS}
        full = {k: {"summary": f"{k} 正常", "issues": []} for k in self._KEYS}
        with contextlib.ExitStack() as st:
            for p in self._patches(results, full):
                st.enter_context(p)
            st.enter_context(contextlib.redirect_stdout(out))
            st.enter_context(contextlib.redirect_stderr(err))
            N.run_diagnostics(list(self._KEYS), as_json=as_json)
        return out.getvalue(), err.getvalue()

    def test_stdout_is_single_json_document(self):
        out, _err = self._run()
        data = json.loads(out)          # 旧版这里直接 JSONDecodeError
        self.assertEqual(sorted(data.keys()), sorted(self._KEYS))
        self.assertEqual(data["dns"]["summary"], "dns 正常")

    def test_no_human_text_in_stdout(self):
        out, _err = self._run()
        for kw in ("NetPulse v", "本机IP", "诊断汇总", "=====", "▶", "[完成]"):
            self.assertNotIn(kw, out, f"stdout 混进了人读内容: {kw}")

    def test_human_output_goes_to_stderr(self):
        _out, err = self._run()
        self.assertIn("NetPulse v", err)
        self.assertIn("诊断汇总", err)

    def test_stdout_restored_after_call(self):
        before = sys.stdout
        self._run()
        self.assertIs(sys.stdout, before, "stdout 未还原")

    def test_normal_mode_still_prints_to_stdout(self):
        """非 --json 模式不受影响 (人读输出照旧走 stdout)。"""
        out, _err = self._run(as_json=False)
        self.assertIn("诊断汇总", out)
        self.assertIn("▶", out)
        with self.assertRaises(ValueError):
            json.loads(out)      # 普通模式本就不是 JSON

    def test_json_mode_evidence_key_filtered(self):
        """_evidence 过渡键不进机器可读输出 (v1.9.2 契约保持)。"""
        out, _err = io.StringIO(), io.StringIO()
        results = {"dns": "完成"}
        full = {"dns": {"summary": "dns 正常", "_evidence": [{"id": "x"}]}}
        with contextlib.ExitStack() as st:
            for p in self._patches(results, full):
                st.enter_context(p)
            st.enter_context(contextlib.redirect_stdout(out))
            st.enter_context(contextlib.redirect_stderr(io.StringIO()))
            N.run_diagnostics(["dns"], as_json=True)
        data = json.loads(out.getvalue())
        self.assertNotIn("_evidence", data["dns"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
    print("OK")
