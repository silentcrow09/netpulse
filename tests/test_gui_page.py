# -*- coding: utf-8 -*-
"""GUI 页面资产 (v1.21.0): 静态壳 / 零外链 / 动态数据 textContent 规则。

验证点:
  P1 _gui_page() 是完整 HTML 文档 (doctype/关闭标签)
  P2 零外链: 无 http(s):// 资源引用、无 <link、无 <script src、无 <img
  P3 页面为纯静态: 无 format 占位符痕迹 ({...} 模板残留)
  P4 JS 轮询 /api/progress, sendBeacon 关窗, iframe 加载 /api/report
  P5 动态渲染只用 textContent: JS 中不得出现 innerHTML(动态串) —— 允许
     的例外: 常量模板不含变量插值 (grep 不到 `innerHTML =` 且非纯静态赋值)
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


class TestGuiPage(unittest.TestCase):

    def setUp(self):
        self.page = np._gui_page()

    def test_document_shape(self):
        p = self.page
        self.assertTrue(p.lstrip().startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", p)

    def test_no_external_resources(self):
        p = self.page
        self.assertNotIn('<link', p)
        self.assertNotIn('<script src', p)
        self.assertNotIn('<img', p)
        for bad in ('http://', 'https://'):
            self.assertNotIn(bad, p, "外链资源: %s" % bad)

    def test_no_template_placeholder(self):
        self.assertNotIn('{profile}', self.page)
        self.assertNotIn('%s', self.page.split('<style>')[0])

    def test_key_mechanics(self):
        p = self.page
        self.assertIn('/api/progress', p)
        self.assertIn('/api/scenarios', p)
        self.assertIn('/api/report', p)
        self.assertIn('sendBeacon', p)

    def test_no_innerhtml_interpolation(self):
        import re as _re
        p = self.page
        # innerHTML 只允许出现在注释里说明禁止; 赋值形式一律禁止
        self.assertIsNone(_re.search(r'\.innerHTML\s*=', p),
                          "动态渲染必须用 textContent, 禁止 innerHTML")


if __name__ == "__main__":
    unittest.main()
