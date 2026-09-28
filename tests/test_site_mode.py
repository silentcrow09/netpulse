# -*- coding: utf-8 -*-
"""现场检测模式回归测试 (v1.13.0 引入)

覆盖:
  - SITE_CHECK_ITEMS 常量契约 (6 项 / key 唯一 / 建议文案 ≤24 字 / 选项非空)
  - _normalize_site_check 白名单校验 (未知 key / 非法值 / 非字符串 一律忽略)
  - build_report 手输字段透传 (site_check / meta_manual / site_note)
  - render_report_html_brief 一页版渲染: 标题 / 问题卡 / 机房区块 /
    签约达标格出现与隐藏 / XSS 转义 / 截断上限
  - export_report(layout="brief") 落盘分支

跑用: cd 到项目根目录, `python tests/test_site_mode.py`
"""
import os
import sys
import datetime
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _fake_report(**overrides):
    """构造最小可用 report dict (结构同 build_report 输出, 不依赖 LAST_RUN)."""
    generated = datetime.datetime(2026, 9, 28, 14, 11, 0)
    modules = [
        {"key": "gateway", "name": "网关连通性", "status": "完成",
         "verdict": "网关可达", "key_metrics": [], "issues": [],
         "has_tech_details": False,
         "raw": {"ping": {"sent": 10, "received": 10, "loss_pct": 0,
                          "avg_ms": 3.2, "min_ms": 2.8, "max_ms": 4.1,
                          "rtts": [3.2, 3.0, 3.4]}},
         },
        {"key": "speedtest", "name": "宽带测速", "status": "完成",
         "verdict": "测速正常", "key_metrics": [], "issues": [],
         "has_tech_details": False,
         "raw": {"speedtest": {"download_mbps": 468.2, "upload_mbps": 52.3,
                               "server_latency_ms": 8.0}},
         },
        {"key": "wifi", "name": "无线环境", "status": "警告",
         "verdict": "信道拥堵", "key_metrics": [], "issues": [],
         "has_tech_details": False,
         "raw": {"current_channel": 6, "network_count": 8,
                 "overall_interference": "存在干扰"},
         },
    ]
    report = {
        "app": "NetPulse", "version": "1.13.0", "schema_version": "1.2.0",
        "generated_at": generated,
        "system": {"local_ip": "192.168.1.23", "gateway": "192.168.1.1",
                   "dns": "202.96.128.86", "public_ip": "113.249.115.93",
                   "geo": "杭州", "asn": "AS4134"},
        "health": {"score": 66, "grade": "C", "label": "一般",
                   "verdict": "一般 · 4 个模块需关注 (含 1 个异常)"},
        "counts": {"完成": 18, "警告": 2, "异常": 1, "错误": 0, "超时": 1,
                   "未检测": 1},
        "exempt_count": 4,
        "summary": {m["key"]: m["status"] for m in modules},
        "duration_ms": 102000, "selected_modules": 22, "total_modules": 23,
        "diagnosis": {"root_causes": [
            {"id": "wifi_weak", "title": "2.4G 信道拥堵叠加弱信号",
             "severity": "high", "confidence": 0.8,
             "description": "信道 6 上有 8 个 AP 同时竞争，协商速率仅 86Mbps。",
             "recommendations": ["信道改为 11 或改用 5G 频段",
                                 "路由器移至开阔处"],
             "affected_modules": ["wifi"], "evidence_ids": []},
        ], "overall_confidence": 0.8, "rules_evaluated": 8, "rules_fired": 1},
        "modules": modules,
        "site_check": {}, "site_note": "", "meta_manual": {},
        "tech": {},
    }
    report.update(overrides)
    return report


class TestSiteCheckItems(unittest.TestCase):
    """SITE_CHECK_ITEMS 常量契约 — 二期扩项时这些红线不能破."""

    def test_six_items_with_unique_keys(self):
        """6 项常用检查, key 唯一且都能在 BY_KEY 索引到."""
        self.assertEqual(len(N.SITE_CHECK_ITEMS), 6)
        keys = [it["key"] for it in N.SITE_CHECK_ITEMS]
        self.assertEqual(len(keys), len(set(keys)))
        for k in keys:
            self.assertIn(k, N.SITE_CHECK_BY_KEY)

    def test_advice_within_24_chars(self):
        """建议文案 ≤24 字 — 超出会折行, 破坏一页版机房行恒单行的高度锁."""
        for it in N.SITE_CHECK_ITEMS:
            self.assertLessEqual(len(it["advice"]), 24,
                                 msg=f'{it["key"]} 建议超长: {it["advice"]}')

    def test_every_option_has_bad_subset(self):
        """每个选项都是 bad 的元素或「正常」档 — 不允许出现未判定的中间态."""
        for it in N.SITE_CHECK_ITEMS:
            self.assertTrue(it["options"])
            for o in it["options"]:
                self.assertTrue(o in it["bad"] or o == it["options"][0],
                                msg=f'{it["key"]} 选项 {o} 未判定')
            self.assertTrue(it["advice"])


class TestNormalizeSiteCheck(unittest.TestCase):
    """白名单校验 — 手输脏数据不进报告."""

    def test_valid_passthrough(self):
        out = N._normalize_site_check({"onu_led": "LOS 告警",
                                       "power_ups": "正常"})
        self.assertEqual(out, {"onu_led": "LOS 告警", "power_ups": "正常"})

    def test_unknown_key_dropped(self):
        """未知 key 一律忽略 (防字典注入式脏数据)."""
        out = N._normalize_site_check({"hacker": "x", "onu_led": "LOS 告警"})
        self.assertEqual(out, {"onu_led": "LOS 告警"})

    def test_invalid_value_dropped(self):
        """值不在选项清单里 → 忽略该项 (按未检查渲染)."""
        out = N._normalize_site_check({"onu_led": "随便写的"})
        self.assertEqual(out, {})

    def test_non_string_and_none(self):
        self.assertEqual(N._normalize_site_check(None), {})
        self.assertEqual(N._normalize_site_check({"onu_led": 3}), {})
        self.assertEqual(N._normalize_site_check("not-a-dict"), {})


class TestBuildReportSiteFields(unittest.TestCase):
    """build_report 手输字段透传 (显式传参, 不依赖 LAST_RUN 内容)."""

    def test_fields_pass_through(self):
        """手输字段透传 (需 LAST_RUN 存在 — 用最小 fake, 用后还原)."""
        saved = N.LAST_RUN
        N.LAST_RUN = {"app": "NetPulse", "version": "1.13.0",
                      "generated_at": datetime.datetime(2026, 9, 28, 14, 11),
                      "system": {}, "status": {}, "results": {},
                      "keys": [], "total_modules": 23}
        try:
            r = N.build_report(site_check={"onu_led": "LOS 告警"},
                               meta_manual={"customer": "测试客户",
                                            "tested_at": "2026-09-28 14:11",
                                            "plan": "500M"},
                               site_note="  机柜钥匙在前台。 ")
        finally:
            N.LAST_RUN = saved
        self.assertIsNotNone(r)
        self.assertEqual(r["site_check"], {"onu_led": "LOS 告警"})
        self.assertEqual(r["meta_manual"]["customer"], "测试客户")
        self.assertEqual(r["site_note"], "机柜钥匙在前台。")

    def test_absent_fields_default_empty(self):
        """不传 = 空白 (普通模式生成的报告不受影响 — 向后兼容)."""
        saved = N.LAST_RUN
        N.LAST_RUN = None
        try:
            self.assertIsNone(N.build_report())
        finally:
            N.LAST_RUN = saved


class TestBriefRenderer(unittest.TestCase):
    """一页客户报告渲染 — 版式契约与转义."""

    def _brief(self, **overrides):
        return N.render_report_html_brief(_fake_report(**overrides))

    def test_title_contains_customer(self):
        html = self._brief(meta_manual={"customer": "杭州××机械制造有限公司",
                                        "tested_at": "2026-09-28 14:11",
                                        "plan": "500M"})
        self.assertIn("杭州××机械制造有限公司</span> 网络检测报告", html)
        self.assertIn("🎯 签约带宽达标", html)
        self.assertIn("93.6", html)  # 468.2 / 500 = 93.6%

    def test_geo_chip_removed(self):
        """v1.13.1: 📍 地域/ASN chips 删除 (用户反馈展示多余)."""
        html = self._brief()
        self.assertNotIn("📍", html)
        self.assertNotIn("AS4134", html)

    def test_plan_absent_hides_cell(self):
        """没填签约带宽 → 整格隐藏 (第五轮拍板: 终端手输, 有值才显示)."""
        html = self._brief()
        self.assertNotIn("签约带宽达标", html)

    def test_site_block_states(self):
        """待整改逐条 + 正常项汇总 + 备注行; 全空时显示未检查."""
        html = self._brief(site_check={"onu_led": "LOS 告警",
                                       "power_ups": "正常",
                                       "cable_label": "较乱"},
                           site_note="钥匙在前台")
        self.assertIn("⚠ LOS 告警", html)
        self.assertIn("⚠ 较乱", html)
        self.assertIn("其余 1 项检查正常", html)
        self.assertIn("现场备注（装维手输）", html)
        self.assertIn("钥匙在前台", html)
        empty = self._brief()
        self.assertIn("本次未进行机房环境检查", empty)

    def test_problem_card_and_more_line(self):
        html = self._brief()
        self.assertIn("2.4G 信道拥堵叠加弱信号", html)
        self.assertIn("详见随附完整报告", html)  # 提示级/未完成计数 > 0

    def test_no_problems_shows_clean(self):
        r = _fake_report(diagnosis={"root_causes": [],
                                    "overall_confidence": 1.0,
                                    "rules_evaluated": 8, "rules_fired": 0})
        html = N.render_report_html_brief(r)
        self.assertIn("未发现明确故障", html)

    def test_xss_escaped(self):
        """客户名 / 备注是手输 — 必须过 _html_esc, 不得出现裸标签."""
        html = self._brief(meta_manual={"customer": '<script>alert(1)</script>'},
                           site_note='"><img src=x>')
        self.assertNotIn("<script>alert", html)
        self.assertNotIn('<img src=x>', html)
        self.assertIn("&lt;script&gt;", html)

    def test_clip_limits_applied(self):
        """超长根因标题按 26 字截断 + 省略号 (一页高度锁)."""
        long_title = "超" * 60
        r = _fake_report(diagnosis={"root_causes": [
            {"id": "x", "title": long_title, "severity": "high",
             "confidence": 0.9, "description": "d", "recommendations": [],
             "affected_modules": [], "evidence_ids": []}],
            "overall_confidence": 0.9, "rules_evaluated": 8,
            "rules_fired": 1})
        html = N.render_report_html_brief(r)
        self.assertIn("超" * 26 + "…", html)
        self.assertNotIn("超" * 40, html)

    def test_coverage_count_matches_badges(self):
        """v1.14.3 回归: 「网络自动检测 N 项」必须与右侧徽章同源同数
        (summary 实跑口径), 不得用 total_modules 全量宇宙口径 —
        现场模式剔除 tcpcc/port/iperf3 后 20 ≠ 23, 客户看见像算错。
        """
        r = _fake_report()      # 3 个模块, total_modules=23 (宇宙口径)
        self.assertLess(len(r["summary"]), r["total_modules"])
        html = N.render_report_html_brief(r)
        self.assertIn(f'网络自动检测 {len(r["summary"])} 项', html)
        self.assertNotIn(f'网络自动检测 {r["total_modules"]} 项', html)

    def test_a4_print_css_present(self):
        html = self._brief()
        self.assertIn("@page{ size:A4 portrait;", html)
        self.assertIn("data:image/png;base64,", html)  # 官方 logo 内嵌


class TestBriefIssueFallback(unittest.TestCase):
    """v1.13.1: 无根因但有模块级异常/警告 → 回退为 issue 行 (真实现场首跑暴露).

    场景: ipv6=异常 / proxy=警告 均为评分豁免模块 → 不触发根因规则,
    旧版自拼"未发现明确故障"与检测覆盖的红黄徽章自相矛盾。
    """

    def _report_with_module_issues(self):
        r = _fake_report(diagnosis={"root_causes": [],
                                    "overall_confidence": 1.0,
                                    "rules_evaluated": 8, "rules_fired": 0})
        mods = r["modules"]
        for m in mods:
            if m["key"] == "wifi":
                m["status"] = "异常"
                m["issues"] = [{"severity": "异常",
                                "text": "当前信道 6 拥堵，邻居 AP 达 8 个",
                                "impact": "", "action": ""}]
            if m["key"] == "gateway":
                m["status"] = "警告"
                m["issues"] = [{"severity": "警告",
                                "text": "网关延迟轻微抖动",
                                "impact": "", "action": ""}]
        # 模拟评分豁免模块的非完成状态 (徽章展示但不扣分)
        r["summary"]["ipv6"] = "异常"
        r["health"] = {"score": 100, "grade": "A", "label": "优秀",
                       "verdict": "优秀 · 2 个模块需关注 (含 1 个异常)"}
        return r

    def test_issue_rows_rendered(self):
        html = N.render_report_html_brief(self._report_with_module_issues())
        self.assertIn("当前信道 6 拥堵", html)
        self.assertIn("网关延迟轻微抖动", html)
        self.assertIn("bissues", html)

    def test_verdict_used_as_headline(self):
        """结论行必须用全口径 verdict — 不再自拼"未发现明确故障"."""
        html = N.render_report_html_brief(self._report_with_module_issues())
        self.assertIn("2 个模块需关注", html)
        self.assertNotIn("未发现明确故障", html)

    def test_cap_names_exempt_modules(self):
        """检测覆盖 cap 点破豁免模块不计分 (满分 + 红黄徽章不再像算错)."""
        r = self._report_with_module_issues()
        html = N.render_report_html_brief(r)
        self.assertIn("属评分豁免模块", html)
        self.assertIn("IPv6", html)  # MODULE_MAP 中文名

    def test_clean_branch_still_works(self):
        """无根因且无模块级问题 → 仍走绿色"未发现明确故障"分支."""
        r = _fake_report(diagnosis={"root_causes": [],
                                    "overall_confidence": 1.0,
                                    "rules_evaluated": 8, "rules_fired": 0})
        for m in r["modules"]:
            m["issues"] = []
        html = N.render_report_html_brief(r)
        self.assertIn("未发现明确故障", html)


class TestExportBrief(unittest.TestCase):
    """export_report(layout="brief") 落盘分支 + 默认 full 向后兼容."""

    def test_brief_export_writes_file(self):
        with tempfile_dir() as d:
            path = os.path.join(d, "brief.html")
            err = N.export_report(path, report=_fake_report(), layout="brief")
            self.assertIsNone(err)
            with open(path, encoding="utf-8") as f:
                content = f.read()
        self.assertIn("网络检测报告", content)
        self.assertIn("@page{ size:A4 portrait;", content)

    def test_full_layout_unchanged(self):
        """默认 layout=full 仍走完整版 (向后兼容 — 不带现场数据也不报错)."""
        with tempfile_dir() as d:
            path = os.path.join(d, "full.html")
            err = N.export_report(path, report=_fake_report())
            self.assertIsNone(err)
            with open(path, encoding="utf-8") as f:
                content = f.read()
        self.assertNotIn("@page{ size:A4 portrait;", content)


class tempfile_dir:
    """最小临时目录上下文 (避免引入 tempfile 之外的依赖语义)."""

    def __init__(self):
        import tempfile
        self._path = tempfile.mkdtemp(prefix="np_site_test_")

    def __enter__(self):
        return self._path

    def __exit__(self, *a):
        import shutil
        shutil.rmtree(self._path, ignore_errors=True)
        return False


class TestPdfHelpers(unittest.TestCase):
    """v1.14.0: 现场模式自动 PDF — Chrome 探测与 HTML→PDF."""

    def test_find_chrome_returns_path_or_none(self):
        """探测结果要么 None (无 Chrome), 要么指向真实存在的 chrome.exe."""
        result = N._find_pdf_browser()
        self.assertTrue(result is None
                        or (isinstance(result, str) and os.path.isfile(result)),
                        msg=f"非法探测结果: {result!r}")

    def test_html_to_pdf_real_when_chrome_available(self):
        """本机有 Chrome 时真实转换一次 (1~2s); 无 Chrome 跳过."""
        browser = N._find_pdf_browser()
        if not browser:
            self.skipTest("本机无 Chrome/Edge")
        with tempfile_dir() as d:
            html = os.path.join(d, "in.html")
            with open(html, "w", encoding="utf-8") as f:
                f.write("<html><head><meta charset='utf-8'>"
                        "<title>测试</title></head>"
                        "<body><h1>测试 PDF 转换</h1></body></html>")
            pdf = os.path.join(d, "out.pdf")
            err = N._html_to_pdf(browser, html, pdf)
            self.assertIsNone(err)
            self.assertTrue(os.path.isfile(pdf)
                            and os.path.getsize(pdf) > 1000)

    def test_html_to_pdf_bad_target_returns_error_text(self):
        """输出路径非法 → 返回错误文本而非抛异常 (现场流程不能因 PDF 中断)."""
        browser = N._find_pdf_browser()
        if not browser:
            self.skipTest("本机无 Chrome/Edge")
        with tempfile_dir() as d:
            html = os.path.join(d, "in.html")
            with open(html, "w", encoding="utf-8") as f:
                f.write("<html><body>x</body></html>")
            bad = os.path.join(d, "no_such_dir", "out.pdf")
            err = N._html_to_pdf(browser, html, bad, timeout=30)
            self.assertIsNotNone(err)
            self.assertIsInstance(err, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
