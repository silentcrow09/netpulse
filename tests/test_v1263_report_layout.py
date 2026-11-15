# -*- coding: utf-8 -*-
"""v1.26.3 回归: 客户版报告 DOM 结构 + GUI 报告页「模块明细」数值。

两个用户实测到的 bug (2026-11-15):

A **导出报告排版乱**: 「未匹配到根因 / 未定位到根因」两个分支的
  `<section class="diagnosis">` 模板里多了一个 `</div>` (dhead 只开了一个)。
  HTML 解析器遇到这个落单的 `</div>` 会一路弹栈, 把 `<main>` 和外层
  `<div class="main">` 一起关掉 → 之后的 band / todo / 各分区变成 body 的
  直接子节点 (从 x=282 退回 x=0 通栏), 左侧 position:fixed 导航正好压在
  上面。窗口宽 (>960px 显示导航) 时尤其明显。

B **GUI 报告页「模块明细」只显示标签不显示数值**: 渲染 metric 格子的 JS
  造出了 `vv` (值元素) 也上了色, 却漏了 `cell.appendChild(vv)` → 每格只剩
  标签(「重传率」), 数值不见了。

闸:
  A1/A2 客户版 HTML 解析后, band/todo/分区都必须在 div.main 之内;
  B  页面 JS 必须把值元素挂进格子。
"""
import os
import sys
import unittest
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import netpulse as np
import _a4_pagecheck as A


class _Ancestry(HTMLParser):
    """记下带指定 class 的元素出现在哪条祖先链上 (判定 DOM 嵌套)。"""

    def __init__(self, watch):
        super().__init__(convert_charrefs=True)
        self.watch = set(watch)
        self.stack = []
        self.found = {}

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        cls = (d.get("class") or "").split()
        for w in self.watch:
            if w in cls and w not in self.found:
                self.found[w] = [t for t, _ in self.stack] + [tag]
        self.stack.append((tag, d.get("class", "")))

    def handle_startendtag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break


def _mk_report(**kw):
    mod = A._mk_module("tcpstats", "TCP 传输质量", "警告",
                       [{"severity": "警告", "text": "TCP 重传率 2.19% 偏高",
                         "impact": "影响业务", "action": "现场复核"}])
    mod["key_metrics"] = [{"label": "重传率", "value": "2.19%", "level": "warn"}]
    return A._mk_report([mod], health={"score": 98, "grade": "A", "label": "优秀",
                                       "verdict": "良好"}, **kw)


class TestCustomerReportStructure(unittest.TestCase):
    """A · 客户版报告的 DOM 嵌套 (导航不能压内容)"""

    def _sections_inside_main(self, report):
        html = np.render_report_html_customer(report)
        p = _Ancestry(["band", "todo", "sec", "hero"])
        p.feed(html)
        self.assertIn("band", p.found, "报告里应有 band 段")
        for name in ("band", "todo"):
            chain = p.found.get(name, [])
            self.assertIn("main", chain,
                          "%s 段不在 <main> 之内 (链: %s) —— 说明有落单的 "
                          "</div> 把 main 提前关掉了" % (name, chain))
            self.assertIn("main", chain, "同名 div.main 与 main 标签需在链上")

    def test_no_rootcause_branch_structure(self):
        """无根因分支 (用户那份报告同型)"""
        self._sections_inside_main(_mk_report())

    def test_unfinished_branch_structure(self):
        """有未完成模块的分支 (同样多过一个 </div>)"""
        rep = _mk_report()
        rep["summary"] = {"tcpstats": "超时"}
        rep["counts"] = {"超时": 1}
        self._sections_inside_main(rep)

    def test_no_stray_end_div_in_diagnosis(self):
        """模板层面: dhead 只开一个就得只关一个"""
        with open(np.__file__, encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("'</div></div>'\n                    '</section>'", src)
        self.assertNotIn("'</div></div>'\n                '</section>'", src)


class TestGuiReportMetricValue(unittest.TestCase):
    """B · GUI 报告页「模块明细」的数值必须挂进格子"""

    @classmethod
    def setUpClass(cls):
        cls.js = np._GUI_JS

    def test_metric_value_appended(self):
        self.assertIn("cell.appendChild(vv);", self.js,
                      "metric 值元素 vv 必须 append 进 cell, 否则只显示标签")

    def test_metric_value_cell_present(self):
        self.assertIn('el("div", "v", String(me.value))', self.js)
        self.assertIn('el("div", "k", me.label)', self.js)


if __name__ == "__main__":
    unittest.main()
