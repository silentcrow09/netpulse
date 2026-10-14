# -*- coding: utf-8 -*-
"""HTML 报告 XSS 回归测试 (审计 §9 · v1.8.1 引入)

SSID / hostname / DNS 域名 / URL 都是不可信外部输入, 会流入客户报告。
本测试把四类恶意样本塞进合成 LAST_RUN 的各文本位 (含走属性通道的
data-copy / title), 渲染后断言: 不产生新标签、属性不被闭合注入。

跑用: cd 到项目根目录, `python tests/test_html_escape.py`
"""
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as np  # noqa: E402

# 四类恶意样本 (审计 §9) + 属性闭合向量
X_TAG_IMG = "'><img src=x onerror=alert(1)>"          # SSID 形态
X_ATTR = '" onmouseover="alert(1)'                    # 属性闭合形态
X_SCRIPT = "<script>alert('xss')</script>"            # DNS 域名形态
X_SVG = "'><svg/onload=alert(1)>"                     # URL/redirect 形态
X_URL_ATTR = 'https://x" onmouseover="alert(1)'      # Ookla result_url 形态 (属性闭合)

# 渲染产物中绝不允许出现的原始序列 (页面自身 <script> 不受影响)。
# 只查"标签注入"向量: 文本节点通道 (_html_esc, quote=False) 不转义引号,
# 但元素内容里的裸引号是惰性的, 不构成注入 — 属性通道单独断言 (见下)。
FORBIDDEN_RAW = [
    "<img src=x",
    "<script>alert",
    "<svg/onload",
    "onerror=alert(1)>",
]


def _hostile_last_run():
    return {
        "app": "NetPulse", "version": "1.8.1",
        "generated_at": datetime.now(),
        "status": {"wifi": "警告", "gateway": "完成"},
        "results": {
            "wifi": {"ssid": X_TAG_IMG, "bssid": X_ATTR,
                     "issues": [{"severity": "警告", "message": X_SCRIPT,
                                 "detail": X_SVG, "action": X_TAG_IMG}],
                     "summary": "x"},
            "gateway": {"ping": {"loss_pct": 0, "avg_ms": 2, "jitter_ms": 1},
                        "issues": []},
        },
        "keys": ["wifi", "gateway"],
        "duration_ms": 5, "total_modules": 23,
        "system": {"hostname": X_ATTR, "local_ip": "192.168.1.10",
                   "gateway": "192.168.1.1", "dns": X_SCRIPT,
                   "public_ip": "1.2.3.4", "geo": X_ATTR, "asn": X_TAG_IMG},
    }


def _hostile_diagnosis():
    return {
        "root_causes": [{
            "id": "xss", "severity": "high", "title": X_TAG_IMG,
            "description": X_ATTR, "category": "wan", "confidence": 0.9,
            "affected_modules": ["wifi", X_ATTR],
            "recommendations": [X_SCRIPT],
            "supports": [{"text": X_SVG, "ok": False}],
            "excludes": [{"text": X_TAG_IMG, "ok": True}],
        }],
        "overall_confidence": 0.9, "rules_evaluated": 8, "rules_fired": 1,
    }


class TestHtmlEscape(unittest.TestCase):
    def setUp(self):
        self._saved = np.LAST_RUN

    def tearDown(self):
        np.LAST_RUN = self._saved

    def test_customer_renderer_never_emits_raw_injection(self):
        """恶意样本全链路: 合成 LAST_RUN → build_report → customer 渲染."""
        np.LAST_RUN = _hostile_last_run()
        report = np.build_report(diagnosis=_hostile_diagnosis())
        html = np.render_report_html_customer(report)

        for raw in FORBIDDEN_RAW:
            self.assertNotIn(raw, html, msg=f"原始注入序列泄漏: {raw!r}")

    def test_attribute_channel_escapes_quotes(self):
        """属性通道 (data-copy 等走 _html_attr): 引号必须被转义, 属性不得被闭合.

        X_ATTR 进了 affected_modules → 复测命令 data-copy 属性。"""
        np.LAST_RUN = _hostile_last_run()
        report = np.build_report(diagnosis=_hostile_diagnosis())
        html = np.render_report_html_customer(report)

        self.assertNotIn('data-copy="netpulse wifi " onmouseover', html)
        self.assertIn("onmouseover=&quot;alert(1)", html)

    def test_payloads_present_but_escaped(self):
        """payload 必须真的流过渲染管道 (转义形态可见), 防止测试假绿."""
        np.LAST_RUN = _hostile_last_run()
        report = np.build_report(diagnosis=_hostile_diagnosis())
        html = np.render_report_html_customer(report)

        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_trouble_ticket_plain_text_by_design(self):
        """报障文本是纯文本 (嵌入 <pre> 前统一 _html.escape), payload 以
            文字形态出现是预期行为; 置信度走分档文案。"""
        import html as _h
        np.LAST_RUN = _hostile_last_run()
        report = np.build_report(diagnosis=_hostile_diagnosis())
        ticket = np._build_trouble_ticket_text(report, report["diagnosis"])
        self.assertIn(X_SCRIPT, ticket)                 # 纯文本原样保留
        self.assertIn("高置信度", ticket)                # 分档而非伪精确百分比
        # 渲染嵌入时必须转义 (customer renderer 的 ticket_html 路径)
        self.assertIn(_h.escape(X_SCRIPT)[:20],
                      np.render_report_html_customer(report))


class TestSpeedtestReportEscape(unittest.TestCase):
    """v1.14.14 P1: 测速报告族 (speedtest / iperf3 / 盯障) 的本地 `_esc_html`
    历史上只转义 & < >, 被拼进 href="..." 时可闭合属性注入。

    数据源是 speedtest.exe 的**远端 JSON** (result_data["result"]["url"]),
    配合用户可选的 --speedtest-node, 不是纯自造输入。
    """

    @staticmethod
    def _res():
        return {
            "download": 100.0, "upload": 20.0, "latency": 10.0,
            "jitter_ms": 1.0, "packet_loss_pct": 0.0,
            "server": "上海电信", "history": [],
            # Ookla 对照结果走 res["speedtest"], 且需 download_mbps 才渲染面板
            "speedtest": {
                "valid": True, "note": "", "server": "上海电信 3633",
                "isp": "China Telecom", "download_mbps": 101.0,
                "upload_mbps": 21.0, "latency_ms": 9.0,
                "jitter_ms": 0.8, "packet_loss_pct": 0.0,
                "result_url": X_URL_ATTR,
            },
        }

    def test_result_url_cannot_close_href_attribute(self):
        html = np._render_speedtest_html(self._res())
        self.assertNotIn(X_URL_ATTR, html,
                         "Ookla 结果链接以原始形态进了 HTML —— 属性被闭合注入")
        self.assertIn("&quot; onmouseover=&quot;", html,
                      "引号未被转义 (应在 _html_attr 通道)")
        for raw in ("<img src=x", "<script>alert", "onerror=alert(1)>"):
            self.assertNotIn(raw, html)

    def test_esc_html_now_escapes_quotes(self):
        """_esc_html 必须与 _html_attr 同口径 (文本节点里多转义引号无害)。"""
        out = np._esc_html(X_URL_ATTR)
        self.assertNotIn('"', out)
        self.assertIn("&quot;", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
