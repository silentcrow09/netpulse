# -*- coding: utf-8 -*-
"""GUI 页面资产 (v1.21.0): 静态壳 / 零外链 / 动态数据 textContent 规则。

验证点:
  P1 _gui_page() 是完整 HTML 文档 (doctype/关闭标签)
  P2 零外链: 无 http(s):// 资源引用、无 <link、无 <script src、无 <img
     (v1.22.0: SVG 命名空间标识符 "http://www.w3.org/2000/svg" 是 URI 标识
     而非外链资源 — createElementNS 必需、浏览器从不对其发起请求, 白名单放行)
  P3 页面为纯静态: 无 format 占位符痕迹 ({...} 模板残留)
  P4 JS 轮询 /api/progress 与 /api/netstatus, sendBeacon 关窗, iframe 加载
     /api/report; v1.22.0: /api/monitor/* 五条 + createElementNS 曲线 +
     confirm 停止
  P5 动态渲染只用 textContent: innerHTML 赋值一律禁止 (含 += 逃逸形态);
     insertAdjacentHTML 只允许注入全大写常量标识符 (零插值常量模板),
     其余参数形态 (字符串拼接 / 小写变量 / 函数调用) 一律 FAIL
  P6 v1.22.0 盯障三视图锚点 (mon-config/mon-live/mon-report) + 第 7 卡
     (ICONS.monitor + /api/scenarios 下发 monitor 条目, 与终端菜单同语义)
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


def _html_guard_violations(p):
    """动态渲染规则闸: 返回违规片段清单 (空列表 = 通过)。

    R1 任何形式的 innerHTML 赋值一律禁止 (= 与 += 两种形态都拦, F3 逃逸 1);
    R2 insertAdjacentHTML 只允许注入【全大写常量标识符】(零插值常量模板,
       如 ICON; F3 逃逸 2)。参数含字符串拼接/小写标识符/函数调用即违规 ——
       fails closed: 按括号截断后解析不出白名单形态的一律算违规。
    """
    import re as _re
    bad = []
    if _re.search(r'\.innerHTML\s*\+?=', p):
        bad.append("innerHTML 赋值")
    for m in _re.finditer(r'\.insertAdjacentHTML\(([^)]*)\)', p):
        args = m.group(1)
        parts = args.split(",")
        target = parts[1].strip() if len(parts) > 1 else ""
        if not _re.match(r'^[A-Z][A-Z0-9_]*$', target):
            bad.append("insertAdjacentHTML 非白名单参数: %s" % args)
    return bad


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
        # SVG 命名空间是 URI 标识符而非外链资源 (浏览器从不 dereference),
        # createElementNS 必需; 白名单这一处, 其余 http(s):// 一律禁止。
        p = p.replace('"http://www.w3.org/2000/svg"', "")
        for bad in ('http://', 'https://'):
            self.assertNotIn(bad, p, "外链资源: %s" % bad)
        self.assertIn('"http://www.w3.org/2000/svg"', self.page,
                      "createElementNS 的 SVG 命名空间常量必须存在")

    def test_no_template_placeholder(self):
        self.assertNotIn('{profile}', self.page)
        self.assertNotIn('%s', self.page.split('<style>')[0])

    def test_key_mechanics(self):
        p = self.page
        self.assertIn('/api/progress', p)
        self.assertIn('/api/scenarios', p)
        self.assertIn('/api/report', p)
        self.assertIn('/api/netstatus', p)
        self.assertIn('sendBeacon', p)
        # v1.22.0 盯障: 五条 API + createElementNS 逐点绘制 + confirm 后停止
        for api in ("/api/monitor/progress", "/api/monitor/curve",
                    "/api/monitor/report", "/api/monitor/start",
                    "/api/monitor/stop"):
            self.assertIn(api, p, "盯障 API 缺失: %s" % api)
        self.assertIn("createElementNS", p,
                      "曲线 SVG 必须用 createElementNS 逐点绘制")
        self.assertIn("confirm(", p, "停止盯障必须先 confirm")

    def test_monitor_view_anchors(self):
        # P6: 三视图锚点 + 第 7 卡链路 (图标常量 / data-p 机制 / 元数据通道)
        p = self.page
        for vid in ("view-mon-config", "view-mon-live", "view-mon-report"):
            self.assertIn('id="%s"' % vid, p, "缺视图锚点: %s" % vid)
        self.assertIn('show("mon-config")', p, "第 7 卡点击必须进配置页")
        self.assertIn('show("mon-live")', p, "runbar 必须能回实时页")
        self.assertIn("monitor: '<svg", p, "第 7 卡图标常量缺失")
        self.assertIn("dataset.p", p, "卡片 data-p 机制缺失")
        # 第 7 卡数据通道: /api/scenarios 下发 monitor 条目 (与终端菜单同语义)
        meta = np._gui_meta()
        mon = [s for s in meta["scenarios"] if s["id"] == "monitor"]
        self.assertEqual(len(mon), 1, "场景载荷缺「持续盯障」条目")
        self.assertEqual(mon[0]["label"], "持续盯障")
        self.assertIn("偶发掉线", mon[0]["desc"])

    def test_no_innerhtml_interpolation(self):
        # F3 (审查): 新闸 —— += 形态与 insertAdjacentHTML 非常量参数都要拦
        self.assertEqual(_html_guard_violations(self.page), [],
                         "动态渲染必须用 textContent / 零插值常量注入 (见 _html_guard_violations)")

    def test_guard_rejects_malformed(self):
        # 新闸对恶意形态必须 FAIL, 对合法常量注入放行 (构造样本验证)
        self.assertTrue(_html_guard_violations('el.innerHTML += evil;'),
                        ".innerHTML += 逃逸形态未被拦截")
        self.assertTrue(_html_guard_violations(
            'box.insertAdjacentHTML("afterbegin", "<b>" + s.id + "</b>");'),
            "insertAdjacentHTML 字符串拼接/变量插值未被拦截")
        self.assertTrue(_html_guard_violations(
            'box.insertAdjacentHTML("afterbegin", renderIcon(s.id));'),
            "insertAdjacentHTML 函数调用参数未被拦截")
        self.assertEqual(_html_guard_violations(
            'box.insertAdjacentHTML("afterbegin", ICON);'), [],
            "全大写常量标识符注入被误拦")


if __name__ == "__main__":
    unittest.main()
