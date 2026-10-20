# -*- coding: utf-8 -*-
"""一页版客户报告「主要发现」区回归 (代码审查 P0-3 / P0-4 · v1.15.0 引入)

背景 (两项都是交客户的一页版 A4 报告上的真实缺陷):

- **P0-3 整改建议结构性丢失**: `RootCause.to_dict()` 的建议键是
  **recommendations (列表)**, 而 brief_v2 读的是 `action`/`recommendation`
  (这两个键不存在) → 建议恒为空 → 一页版只说"出了什么问题"、从不说
  "该做什么"。v1.14.10 切模板 D 时引入, 真实产物已带此缺陷。

- **P0-4 严重度徽章表不匹配**: `Severity` 枚举值是
  info/low/medium/high/critical, 而 `sev_pill` 只认 high/mid/exempt →
  **critical 根因** (网关丢包>=20% / WAN 中断 / F 级 bufferbloat) 落到默认值
  → 空徽章 + low 样式 —— 最严重的根因看起来最不严重。

跑用: cd 到项目根目录, `python tests/test_v1150_brief_v2_findings.py`
"""
import os
import sys
import datetime
import unittest
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _report_with_rootcause(severity="high", recommendations=None, title="根因标题"):
    """构造只含一条根因的最小 report (结构同 build_report 输出)."""
    recs = ["信道改为 11 或改用 5G 频段", "路由器移至开阔处"] \
        if recommendations is None else recommendations
    modules = [{
        "key": "wifi", "name": "无线环境", "status": "警告",
        "verdict": "信道拥堵", "key_metrics": [], "issues": [],
        "has_tech_details": False, "raw": {},
    }]
    return {
        "app": "NetPulse", "version": "1.15.0", "schema_version": "1.2.0",
        "generated_at": datetime.datetime(2026, 10, 20, 12, 0, 0),
        "system": {"local_ip": "192.168.1.23", "gateway": "192.168.1.1",
                   "dns": "223.5.5.5", "public_ip": "1.2.3.4"},
        "health": {"score": 70, "grade": "C", "label": "一般", "verdict": "一般"},
        "counts": {"完成": 1, "警告": 1},
        "exempt_count": 0,
        "summary": {m["key"]: m["status"] for m in modules},
        "duration_ms": 1000, "selected_modules": 1, "total_modules": 1,
        "diagnosis": {"root_causes": [{
            "id": "wifi_weak", "title": title, "severity": severity,
            "confidence": 0.8, "description": "现象描述",
            "recommendations": recs,
            "affected_modules": ["wifi"], "evidence_ids": [],
        }], "overall_confidence": 0.8, "rules_evaluated": 8, "rules_fired": 1},
        "modules": modules,
        "site_check": {}, "site_note": "", "meta_manual": {}, "tech": {},
    }


def _findings_block(html):
    m = re.search(r'<div class="findings">(.*?)</div></div>\s*<div class="sec-h"',
                  html, re.S)
    return m.group(1) if m else ""


class TestBriefV2AdvicePresent(unittest.TestCase):
    """P0-3: 根因的整改建议必须出现在一页版上."""

    def test_advice_line_rendered(self):
        html = N.render_report_html_brief_v2(_report_with_rootcause())
        blk = _findings_block(html)
        self.assertIn("整改建议", blk,
                      "一页版「主要发现」必须带整改建议 (P0-3)")
        self.assertIn("信道改为 11", blk)

    def test_advice_taken_from_recommendations_list(self):
        """回归锚点: 根因只有 recommendations 列表 (RootCause.to_dict 的真实形状)."""
        report = _report_with_rootcause(
            recommendations=["唯一建议: 换一根超五类网线"])
        html = N.render_report_html_brief_v2(report)
        blk = _findings_block(html)
        self.assertIn("整改建议", blk)
        self.assertIn("唯一建议", blk)

    def test_advice_clipped_to_limit(self):
        long_advice = "A" * 120
        html = N.render_report_html_brief_v2(
            _report_with_rootcause(recommendations=[long_advice]))
        blk = _findings_block(html)
        shown = re.search(r'<div class="act"><span class="lbl">整改建议</span>\s*(.*?)</div>',
                          blk, re.S)
        self.assertIsNotNone(shown)
        text = re.sub(r"<[^>]+>", "", shown.group(1)).strip()
        self.assertLessEqual(len(text), N._BRIEF_CLIP["advice"] + 1,
                             "建议正文须受 _BRIEF_CLIP[advice] 截断 (A4 高度锁)")

    def test_advice_html_escaped(self):
        report = _report_with_rootcause(
            recommendations=['<img src=x onerror=alert(1)>'])
        html = N.render_report_html_brief_v2(report)
        blk = _findings_block(html)
        self.assertNotIn("<img src=x", blk, "建议文案必须转义")
        self.assertIn("&lt;img", blk)

    def test_no_advice_no_empty_row(self):
        report = _report_with_rootcause(recommendations=[])
        html = N.render_report_html_brief_v2(report)
        blk = _findings_block(html)
        self.assertNotIn("整改建议", blk, "无建议时不应出现空的建议行")

    def test_action_key_still_supported(self):
        """兼容另一种键形态 (防御: 键名再漂移也不丢建议)."""
        report = _report_with_rootcause(recommendations=[])
        report["diagnosis"]["root_causes"][0]["action"] = "备选形态的建议"
        html = N.render_report_html_brief_v2(report)
        self.assertIn("备选形态的建议", _findings_block(html))


class TestBriefV2SeverityPill(unittest.TestCase):
    """P0-4: 每种 Severity 都必须有可见徽章, critical 最显眼."""

    EXPECT = {
        "critical": ("严重", "high"),
        "high": ("异常", "high"),
        "medium": ("警告", "mid"),
        "low": ("提示", "low"),
        "info": ("提示", "low"),
    }

    def test_every_severity_has_non_empty_badge(self):
        for sev, (text, cls) in self.EXPECT.items():
            with self.subTest(severity=sev):
                html = N.render_report_html_brief_v2(
                    _report_with_rootcause(severity=sev))
                blk = _findings_block(html)
                m = re.search(r'<span class="badge ([^"]*)">(.*?)</span>', blk, re.S)
                self.assertIsNotNone(m, "severity=%s 必须有徽章" % sev)
                self.assertEqual(re.sub(r"<[^>]+>", "", m.group(2)).strip(), text)
                self.assertEqual(m.group(1), cls)

    def test_critical_is_not_low_styled(self):
        """回归锚点: critical 曾渲染成空徽章 + low 样式."""
        html = N.render_report_html_brief_v2(
            _report_with_rootcause(severity="critical"))
        blk = _findings_block(html)
        self.assertIn('class="f high"', blk,
                      "critical 根因必须用 high (红) 样式, 不能是 low")
        self.assertNotIn('class="f low"', blk)

    def test_low_badge_has_background_css(self):
        """low/info 徽章必须有底色 (此前透明 = 看不见)."""
        import netpulse
        css = netpulse.CSS_BRIEF_V2
        self.assertIn(".f.low .badge", css)
        self.assertRegex(css, r"\.f\.low \.badge\s*\{[^}]*background")


if __name__ == "__main__":
    unittest.main(verbosity=2)
