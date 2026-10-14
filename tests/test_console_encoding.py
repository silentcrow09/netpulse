# -*- coding: utf-8 -*-
"""v1.14.14: 控制台编码兜底 (_ensure_console_safe) 回归。

背景: 面向中文 Windows 装维机, 默认代码页 cp936 编不了报告/菜单里的符号
(✓ ✗ ⚠ 🔴 📊)。修复前 print 直接抛 UnicodeEncodeError 让进程崩在诊断中途 ——
tests/test_elevation.py (13 errors) / test_v160_scene.py /
test_v196_menu_entry.py 三个文件在未设 PYTHONIOENCODING 时全挂。

覆盖:
  1. 窄编码流上打印非 GBK 字符不再抛 UnicodeEncodeError
  2. 只改 errors 不改 encoding —— --json 输出字节 / 管道重定向语义不受影响
  3. 幂等 + 对没有 reconfigure 的流 (StringIO) 安全跳过
  4. 真实诊断打印路径 (_print_diagnosis) 在窄流下不崩

运行: cd 到项目根目录, `python tests/test_console_encoding.py`
"""
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

# 报告/菜单里真实出现的非 GBK 字符 (取自 netpulse.py 的 print 站点)
NARROW_SYMBOLS = "\u2713 \u2717 \u26a0 \U0001f534 \U0001f4ca \u6b63\u5e38\u4e2d\u6587"


class TestConsoleEncodingFallback(unittest.TestCase):

    def _fresh_flag(self):
        """重置一次性标志, 让被测函数真正执行。"""
        patcher = mock.patch.object(N, "_CONSOLE_SAFE_DONE", False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _narrow_stream(self):
        """一个 cp936 + strict 的真实文本流 (复现中文 Windows 控制台)。"""
        return io.TextIOWrapper(io.BytesIO(), encoding="cp936", errors="strict",
                                line_buffering=True)

    def test_narrow_stream_does_not_raise(self):
        """核心回归: 修复前必然抛 UnicodeEncodeError。"""
        self._fresh_flag()
        stream = self._narrow_stream()
        with mock.patch.object(sys, "stdout", stream):
            N._ensure_console_safe()
            try:
                stream.write(NARROW_SYMBOLS)
                stream.flush()
            except UnicodeEncodeError as e:      # pragma: no cover - 修复后不应到达
                self.fail(f"cp936 窄流仍崩溃: {e}")

    def test_only_errors_relaxed_encoding_untouched(self):
        """--json 依赖 encoding 语义, 不能被兜底改掉。"""
        self._fresh_flag()
        stream = self._narrow_stream()
        with mock.patch.object(sys, "stdout", stream):
            N._ensure_console_safe()
            self.assertEqual(stream.encoding.lower().replace("-", ""), "cp936")
            self.assertEqual(stream.errors, "replace")

    def test_idempotent(self):
        """重复调用不得抛异常 (幂等): 首次生效, 二次短路后状态不变。"""
        self._fresh_flag()
        stream = self._narrow_stream()
        with mock.patch.object(sys, "stdout", stream):
            N._ensure_console_safe()
            N._ensure_console_safe()            # 第二次走 _CONSOLE_SAFE_DONE 短路
            self.assertEqual(stream.errors, "replace")

    def test_stream_without_reconfigure_skipped(self):
        """StringIO 没有 reconfigure, 必须静默跳过而不是崩。"""
        self._fresh_flag()
        sio = io.StringIO()
        with mock.patch.object(sys, "stdout", sio):
            N._ensure_console_safe()            # 不抛即通过

    def test_diagnosis_print_path_survives_narrow_console(self):
        """真实诊断打印路径在窄控制台下不崩 (覆盖 13 errors 的原始现场)。"""
        self._fresh_flag()
        d = mock.MagicMock()
        d.rules_fired, d.rules_evaluated = 1, 8
        d.root_causes, d.summary, d.top = [], "", []
        stream = self._narrow_stream()
        with mock.patch.object(sys, "stdout", stream):
            N._ensure_console_safe()
            try:
                N._print_diagnosis(d)
                stream.flush()
            except UnicodeEncodeError as e:      # pragma: no cover
                self.fail(f"_print_diagnosis 在 cp936 窄流崩溃: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
