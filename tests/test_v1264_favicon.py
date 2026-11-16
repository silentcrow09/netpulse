# -*- coding: utf-8 -*-
"""GUI 任务栏图标 (v1.26.4): 页面内嵌 favicon → Chromium --app 窗口图标。

背景: GUI 窗口是 Chromium ``--app`` 模式, 这类窗口的任务栏/标题栏图标
取自页面 icon; 页面此前没有 favicon, 任务栏落成系统默认文档图标。
修法: ``_gui_page()`` 的 ``<head>`` 加一条 ``<link rel="icon">``,
href 是内嵌 data URI (PNG-in-ICO 多尺寸), 零网络请求, 守零外链契约。

验证点:
  P1 页面恰好一条 favicon link, href 为 data:image/x-icon;base64 且在 </head> 前
  P2 link 载荷与 _FAVICON_B64 常量一致 (单一来源, 页面不会拼丢字节)
  P3 常量解码为合法 ICO: magic 00 00 01 00, 目录帧数 >=5,
     含 256/48/32/16 四个关键尺寸 (任务栏/Alt-Tab/高 DPI 各取所需)
  P4 体积上限 64KB base64 (防手滑把大图贴进单文件)
"""
import base64
import io
import os
import re
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


class TestGuiFavicon(unittest.TestCase):

    def setUp(self):
        self.page = np._gui_page()

    def _favicon_href(self):
        links = re.findall(r'<link\b[^>]*>', self.page)
        fav = [t for t in links if 'rel="icon"' in t]
        self.assertEqual(len(fav), 1, "favicon link 恰好一条, 实际: %s" % links)
        m = re.search(r'href="data:image/x-icon;base64,([^"]+)"', fav[0])
        self.assertIsNotNone(m, "favicon href 必须是内嵌 data URI")
        return m.group(1)

    def test_p1_link_shape(self):
        href = self._favicon_href()
        self.assertTrue(href)
        head = self.page.split("</head>")[0]
        self.assertIn('rel="icon"', head, "favicon link 必须在 </head> 之前")

    def test_p2_single_source(self):
        self.assertEqual(self._favicon_href(), np._FAVICON_B64,
                         "页面 link 载荷与 _FAVICON_B64 常量必须一致")

    def test_p3_valid_multi_size_ico(self):
        raw = base64.b64decode(np._FAVICON_B64)
        self.assertEqual(raw[:4], b"\x00\x00\x01\x00", "ICO 文件头不符")
        count = struct.unpack("<H", raw[4:6])[0]
        self.assertGreaterEqual(count, 5, "ICO 目录帧数不足: %d" % count)
        sizes = set()
        for i in range(count):
            off = 6 + i * 16
            w = raw[off] or 256          # 0 表示 256
            h = raw[off + 1] or 256
            sizes.add((w, h))
        for need in (256, 48, 32, 16):
            self.assertIn((need, need), sizes,
                          "ICO 缺 %dpx 帧 (任务栏/Alt-Tab 需要)" % need)
        # 每帧载荷是可解码 PNG (PNG-in-ICO)
        for i in range(count):
            off = 6 + i * 16
            length = struct.unpack("<I", raw[off + 8:off + 12])[0]
            start = struct.unpack("<I", raw[off + 12:off + 16])[0]
            self.assertEqual(raw[start:start + 8],
                             b"\x89PNG\r\n\x1a\n",
                             "第 %d 帧不是 PNG" % i)

    def test_p4_size_cap(self):
        self.assertLess(len(np._FAVICON_B64), 64 * 1024,
                        "favicon base64 超过 64KB, 疑似嵌错资源")
        self.assertLess(len(base64.b64decode(np._FAVICON_B64)), 48 * 1024)


if __name__ == "__main__":
    unittest.main()
