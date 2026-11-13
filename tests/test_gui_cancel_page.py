# -*- coding: utf-8 -*-
"""GUI 取消 / 续跑 的页面行为 (v1.24.0 · Task 4)。

真实浏览器里的行为由 `.superpowers/sdd/cancel-resume/evidence/page_dom_check.py`
(无头 Chrome --dump-dom) 逐条验证; 这里是不依赖浏览器的**回归闸** ——
把关键分支与文案钉在页面上, 改坏了立刻红。

验证点:
  P1 三个相位 (running / stopping / cancelled) 在主页态都要拉回进度页
     (停止后刷新页面不能落在主页 —— 那样「已停止」结论条就看不见了)
  P2 停止按钮: 能停才显示; 已请求停止 → 禁用 + 文案「正在收尾…」
  P3 收尾条 / 已停止条文案与设计稿文案表逐字一致
  P4 继续跑按钮带项数「继续跑剩下的 N 项」
  P5 停止确认框文案含「已完成的项目会保留」
  P6 主页续跑横幅: 标题 + 两个按钮文案
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np  # noqa: E402


class TestGuiCancelPage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.page = np._gui_page()

    def _js(self):
        return self.page

    # ── P1 三相位都回进度页 ──
    def test_three_phases_return_to_progress_view(self):
        p = self._js()
        self.assertIn(
            'd.phase === "running" || d.phase === "stopping" '
            '|| d.phase === "cancelled"', p,
            "running/stopping/cancelled 三个相位都要拉回进度页")

    # ── P2 停止按钮 ──
    def test_stop_button_states(self):
        p = self._js()
        self.assertIn('stopBtn.style.display = canStop ? "" : "none";', p,
                      "不能停时隐藏停止按钮")
        self.assertIn("stopBtn.disabled = !!d.stop_requested;", p,
                      "已请求停止 → 按钮禁用")
        self.assertIn('t.textContent = d.stop_requested ? "正在收尾…" : "停止";',
                      p, "收尾中文案=正在收尾…")

    # ── P3 收尾条 / 已停止条文案 ──
    def test_stop_and_done_bar_text(self):
        p = self._js()
        self.assertIn("已停止调度，等当前项目跑完就出报告", p)
        self.assertIn("手头这项目最长要 3 分钟，跑完就出结果，剩下的不再测。", p)
        self.assertIn(
            '"已停止 · 实检 " + d.done + "/" + d.total + " 项"', p,
            "已停止结论条标题带实检项数")
        self.assertIn(
            '"剩下的 " + d.remaining + " 项没测。报告已生成，可以先看结果，'
            '或者接着跑。"', p, "已停止结论条副行文案与设计稿一致")

    # ── P4 继续跑按钮带项数 ──
    def test_resume_button_shows_count(self):
        p = self._js()
        self.assertIn('rb.textContent = "继续跑剩下的 " + d.remaining + " 项";',
                      p, "继续跑按钮必须带「N 项」")

    # ── P5 停止确认框 ──
    def test_stop_confirm_copy(self):
        p = self._js()
        self.assertIn("已完成的项目会保留", p,
                      "确认框必须说清已完成的项目会保留")
        self.assertIn("确认停止本轮诊断？", p)

    # ── P6 主页续跑横幅 ──
    def test_resume_banner_copy(self):
        p = self._js()
        self.assertIn("上次诊断没跑完", p)
        self.assertIn(">接着跑<", p)
        self.assertIn(">重新开始<", p)
        self.assertIn("已完成的项目都还在", p)

    # ── 页面动态数据仍只用 textContent (v1.21.0 铁律不被本次改动破坏) ──
    def test_no_innerhtml_assignment(self):
        import re
        self.assertIsNone(re.search(r"\.innerHTML\s*\+?=", self.page),
                          "页面动态数据只能走 textContent")


if __name__ == "__main__":
    unittest.main()
