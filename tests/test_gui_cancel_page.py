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
        self.assertIn('"剩下的 " + d.remaining', p)
        self.assertIn('" 项没测。报告已生成，可以先看结果，或者接着跑。"', p,
                      "已停止结论条副行文案与设计稿一致")

    # ── P3b 落盘失败要提示 (spec 风险表) ──
    def test_resume_save_failure_copy(self):
        p = self._js()
        self.assertIn("if (d.resume_error)", p,
                      "已停止条必须区分「续跑点没存下来」这一支")
        self.assertIn("这次没法接着跑", p)

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

    # ── P7 收尾期关窗: beacon 必须发 force=true (终审审查 #2) ──
    def test_unload_beacon_counts_stopping_as_busy(self):
        p = self._js()
        i = p.find('window.addEventListener("unload"')
        self.assertTrue(i > 0, "找不到 unload 处理")
        seg = p[i:i + 900]
        self.assertIn('state.data.phase === "stopping"', seg,
                      "收尾中也要算忙 → beacon 发 force=true, 否则服务端回 409")
        j = p.find('window.addEventListener("beforeunload"')
        self.assertTrue(j > 0)
        seg2 = p[j:j + 700]
        self.assertIn('state.data.phase === "stopping"', seg2,
                      "收尾中关窗也要提示用户")

    # ── P8 续跑失败要在进度页看得见 (终审审查 #4) ──
    def test_resume_failure_shows_on_progress_page(self):
        p = self._js()
        i = p.find("function resumeRun()")
        self.assertTrue(i > 0)
        seg = p[i:i + 800]
        self.assertIn('$("#p-err")', seg,
                      "续跑失败要写到进度页的错误位 (只写主页那个等于没提示)")

    # ── 页面动态数据仍只用 textContent (v1.21.0 铁律不被本次改动破坏) ──
    def test_no_innerhtml_assignment(self):
        import re
        self.assertIsNone(re.search(r"\.innerHTML\s*\+?=", self.page),
                          "页面动态数据只能走 textContent")


if __name__ == "__main__":
    unittest.main()
