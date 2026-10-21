# -*- coding: utf-8 -*-
"""v1.15.2 审查 P1-15c · brief_v2「主要发现」无根因回退 回归测试。

旧版实现 (审查前): brief_v2 的「主要发现」只渲染 root_causes[:4] ——
无根因时**只留一个区块标题, 内容为空** (顶多再加一张「豁免项显示异常」卡)。
于是 23 个模块全超时的现场报告: 健康分 0 分 F 级, 第 1 页「主要发现」区空白,
第 2 页明细表才看得出「全超时」—— 同一份交付物自相矛盾。
(完整版早有「⚠ 未定位到根因」, 旧 brief v1 早有模块级问题回退, 只有 brief_v2 缺。)

修后口径 (与完整版/brief v1 对齐):
  ① 有根因 → 列根因 (维持现状)
  ② 无根因但有模块级问题 → 逐条列问题
  ③ 两者皆无但有未完成模块 → 「未定位到根因」
  ④ 全都没有 → 「未发现明确故障」
豁免卡在有回退卡时让位 (否则「主要发现」区唯一一张卡是「豁免项显示异常」,
极易被读成「本次只发现豁免项有问题」)。

跑用: cd 到项目根目录, `py -3.13 tests/test_v1152_brief_v2_findings.py`
"""
import datetime
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _mk_module(key, name, status, issues=None):
    return {"key": key, "name": name, "status": status,
            "verdict": "—", "key_metrics": [], "issues": issues or [],
            "has_tech_details": False, "raw": {}}


def _mk_report(modules, root_causes=None, summary=None, health=None):
    summary = summary if summary is not None else {m["key"]: m["status"] for m in modules}
    return {
        "app": "NetPulse", "version": "1.15.2", "schema_version": "1.2.0",
        "generated_at": datetime.datetime(2026, 10, 21, 14, 11, 0),
        "system": {"local_ip": "192.168.1.23", "gateway": "192.168.1.1",
                   "dns": "202.96.128.86", "public_ip": "113.249.115.93",
                   "geo": "杭州", "asn": "AS4134"},
        "health": health or {"score": 0, "grade": "F", "label": "严重",
                             "verdict": "未完成检测"},
        "counts": {"完成": 0, "警告": 0, "异常": 0, "错误": 0, "超时": len(modules),
                   "未检测": 0},
        "exempt_count": 0,
        "summary": summary,
        "duration_ms": 102000, "selected_modules": len(modules), "total_modules": 23,
        "diagnosis": {"root_causes": root_causes or [], "overall_confidence": 0.0,
                      "rules_evaluated": 8, "rules_fired": 0},
        "modules": modules,
        "site_check": {}, "site_note": "", "meta_manual": {}, "tech": {},
    }


def _findings_html(report):
    """抽出 brief_v2 的「主要发现」区内容。"""
    html = N.render_report_html_brief_v2(report)
    m = re.search(r'<div class="findings">(.*?)</div>\s*<div class="sec-h">', html, re.S)
    if not m:
        m = re.search(r'<div class="findings">(.*?)</div>', html, re.S)
    return m.group(1) if m else ""


TIMEOUT_ISSUE = {
    "severity": "异常",
    "text": "模块执行超时, 本次未取得该模块检测结果",
    "impact": "未在超时阈值内完成, 相关指标与结论均不可信",
    "action": "现场排查后重新运行本模块",
}


class TestBriefV2FindingsFallback(unittest.TestCase):
    """「主要发现」区不得空着, 也不得只显示豁免卡。"""

    # ── 闸门 1: 23 模块全超时 → 该区必须有内容 ──
    def test_all_timeout_findings_not_empty(self):
        mods = [_mk_module(f"m{i}", f"模块{i}", "超时", [dict(TIMEOUT_ISSUE)])
                for i in range(3)]
        body = _findings_html(_mk_report(mods))
        self.assertTrue(body.strip(),
                        "模块全超时时「主要发现」区不得为空 (旧版只留空标题)")

    def test_all_timeout_mentions_unfinished_or_timeout(self):
        mods = [_mk_module(f"m{i}", f"模块{i}", "超时", [dict(TIMEOUT_ISSUE)])
                for i in range(3)]
        body = _findings_html(_mk_report(mods))
        self.assertTrue("未定位到根因" in body or "超时" in body,
                        "应明确写出「未定位到根因」或超时问题, 不能让人猜: %r" % body[:200])

    # ── 闸门 2: 无根因但有模块级问题 → 列出该问题 ──
    def test_module_issue_listed_when_no_rootcause(self):
        issue = {"severity": "异常", "text": "网关丢包率 35%, 链路质量差",
                 "impact": "语音与视频通话会卡顿", "action": "检查网线与接口协商"}
        mods = [_mk_module("gateway", "网关连通性", "异常", [issue]),
                _mk_module("dns", "DNS 解析", "完成")]
        body = _findings_html(_mk_report(mods))
        self.assertIn("网关丢包率", body,
                      "无根因时必须列出模块级问题 (旧版该区空白)")

    def test_module_issue_source_is_shown(self):
        issue = {"severity": "警告", "text": "无线信道拥堵", "impact": "", "action": ""}
        mods = [_mk_module("wifi", "无线环境", "警告", [issue])]
        body = _findings_html(_mk_report(mods))
        self.assertIn("来源", body, "应标明问题来源模块")

    # ── 闸门 3: 有根因时维持根因卡, 不混入「未发现明确故障」 ──
    def test_rootcause_kept_when_present(self):
        rc = {"id": "wifi_weak", "title": "2.4G 信道拥堵叠加弱信号",
              "severity": "high", "confidence": 0.8,
              "description": "信道 6 上有 8 个 AP 同时竞争。",
              "recommendations": ["信道改为 11"], "affected_modules": ["wifi"],
              "evidence_ids": []}
        mods = [_mk_module("wifi", "无线环境", "警告")]
        body = _findings_html(_mk_report(mods, root_causes=[rc]))
        self.assertIn("信道拥堵", body, "有根因时必须列根因")
        self.assertNotIn("未发现明确故障", body,
                         "有根因时不得再显示「未发现明确故障」")

    # ── 正向: 真健康 → 明确说没发现故障 ──
    def test_healthy_shows_no_fault(self):
        mods = [_mk_module("gateway", "网关连通性", "完成"),
                _mk_module("dns", "DNS 解析", "完成")]
        body = _findings_html(_mk_report(
            mods, health={"score": 100, "grade": "A", "label": "优秀",
                          "verdict": "良好"}))
        self.assertIn("未发现明确故障", body, "真健康时应明确说明")

    # ── 闸门 4: 豁免卡必须让位给回退卡 ──
    def test_exempt_card_yields_to_fallback(self):
        """23 模块全超时 + 豁免项也异常时, 不得只显示豁免卡。"""
        mods = [_mk_module(f"m{i}", f"模块{i}", "超时", [dict(TIMEOUT_ISSUE)])
                for i in range(3)]
        # 让一个评分豁免模块 (ipv6) 处于异常 → 触发 exempt_bad
        mods.append(_mk_module("ipv6", "IPv6 连通性", "异常",
                               [{"severity": "警告", "text": "未获取到 IPv6 地址",
                                 "impact": "", "action": ""}]))
        body = _findings_html(_mk_report(mods))
        self.assertTrue(body.strip())
        self.assertFalse(
            "豁免项显示异常" in body and len(body.strip()) < 400,
            "全超时时豁免卡不得独占整个「主要发现」区 (现在只显示豁免卡, "
            "客户会读成「本次只发现豁免项有问题」)")

    # ── 闸门 5: 同一文案波及多个模块时要标明总数 ──
    def test_scope_mentions_module_count(self):
        mods = [_mk_module("m1", "模块甲", "超时", [dict(TIMEOUT_ISSUE)]),
                _mk_module("m2", "模块乙", "超时", [dict(TIMEOUT_ISSUE)]),
                _mk_module("m3", "模块丙", "超时", [dict(TIMEOUT_ISSUE)])]
        body = _findings_html(_mk_report(mods))
        self.assertTrue("3 个模块" in body or "涉及" in body,
                        "同一文案波及多模块时应标明总数, 别让人以为只有 1 个模块: %r"
                        % body[:300])


if __name__ == "__main__":
    unittest.main(verbosity=2)
