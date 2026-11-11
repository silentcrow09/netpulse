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


class TestPortMapEscape(unittest.TestCase):
    """v1.18.3: 网口对照表 (端口定位) 的网卡名/描述是**用户可自定义**的
    不可信输入 (网卡可以改名, 描述来自驱动), 且直接进客户报告表格 ——
    必须走 _html_esc 通道。"""
    def setUp(self):
        self._saved = np.LAST_RUN

    def tearDown(self):
        np.LAST_RUN = self._saved

    def _hostile_port_map_run(self):
        return {
            "app": "NetPulse", "version": "1.18.3",
            "generated_at": datetime.now(),
            "status": {"linkspeed": "完成"},
            "results": {"linkspeed": {
                "adapters": [
                    {"name": X_TAG_IMG, "description": X_SCRIPT,
                     "status": "Up", "media_type": "802.3", "is_wifi": False,
                     "link_speed_raw": "1 Gbps", "speed_mbps": 1000.0,
                     "assessment": ""},
                    {"name": X_ATTR, "description": X_SVG,
                     "status": "Down", "media_type": "802.3", "is_wifi": False,
                     "link_speed_raw": "", "speed_mbps": 0, "assessment": ""},
                ],
                "wifi_details": {}, "wifi_interfaces": [],
                "nic_errors": {"total_errors": 0, "total_discarded": 0},
                "egress_interface": X_TAG_IMG,
                "issues": [], "timestamp": "", "summary": "x",
            }},
            "keys": ["linkspeed"],
            "duration_ms": 5, "total_modules": 23,
            "system": {"hostname": "PC-01", "local_ip": "192.168.1.10",
                       "gateway": "192.168.1.1", "dns": "223.5.5.5",
                       "public_ip": "1.2.3.4", "geo": "", "asn": ""},
        }

    def test_port_map_never_emits_raw_injection(self):
        np.LAST_RUN = self._hostile_port_map_run()
        html = np.render_report_html_customer(np.build_report())
        for raw in FORBIDDEN_RAW:
            self.assertNotIn(raw, html, msg=f"原始注入序列泄漏: {raw!r}")

    def test_port_map_payload_reaches_table_escaped(self):
        """payload 必须真的进了网口对照表 (转义形态), 防止测试假绿。"""
        np.LAST_RUN = self._hostile_port_map_run()
        html = np.render_report_html_customer(np.build_report())
        self.assertIn('id="portmap"', html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_brief_v2_port_summary_never_emits_raw_injection(self):
        """一页版的网口摘要行同样吃网卡名 —— 它在 <div class="portline"> 里
        拼了出口口名, 逃逸漏一处就是客户版被注入。"""
        np.LAST_RUN = self._hostile_port_map_run()
        html = np.render_report_html_brief_v2(np.build_report())
        self.assertIn('class="portline"', html)
        for raw in FORBIDDEN_RAW:
            self.assertNotIn(raw, html, msg=f"原始注入序列泄漏: {raw!r}")
        # 摘要行里的网卡名会被 _short_iface 截断到 24 字符, 只断言截断后仍存活的片段
        self.assertIn("&lt;img src=x", html)


class TestLoopbackEscape(unittest.TestCase):
    """v1.19.0: 环回测速 (终端→网关) 的不可信输入。

    环回测速会往客户报告里写三类外部文本: 网关/适配器描述 (网卡可以改名,
    描述来自驱动)、失败原因 (Npcap 缺失 / 网关无 ARP 应答等)、发现项文案。
    它们分别流进「环回测速」章节的 note、模块卡的指标值与发现项 —— 任何一处
    漏转义, 客户拿到的就是一份能被注入的报告。
    """

    def setUp(self):
        self._saved = np.LAST_RUN

    def tearDown(self):
        np.LAST_RUN = self._saved

    def _hostile_loopback_run(self, failed=False):
        if failed:
            lb = {"error": "环回测速未执行: " + X_TAG_IMG, "reason": X_TAG_IMG}
            status = "错误"
        else:
            lb = {
                "gateway": "192.168.1.1", "gateway_mac": "4c-09-b4-fc-ac-f0",
                "interface": X_ATTR, "scope": "unknown",
                "scope_label": X_TAG_IMG,
                "mbps": 312.5, "negotiated_mbps": 1000.0, "ratio_pct": 31.3,
                "at_ceiling": False, "offered_mbps": 900.0,
                "load_limited": False, "saturated": True, "is_wireless": False,
                "return_ratio": 0.35, "frames": 89000, "bytes": 124600000,
                "seconds": 5.0, "duration_s": 5,
                "issues": [{"severity": "警告", "message": X_TAG_IMG,
                            "detail": X_SCRIPT, "action": X_SVG}],
                "timestamp": "", "summary": "x",
            }
            status = "完成"
        return {
            "app": "NetPulse", "version": "1.19.0",
            "generated_at": datetime.now(),
            "status": {"loopback": status},
            "results": {"loopback": lb},
            "keys": ["loopback"],
            "duration_ms": 5, "total_modules": 24,
            "system": {"hostname": "PC-01", "local_ip": "192.168.1.10",
                       "gateway": "192.168.1.1", "dns": "223.5.5.5",
                       "public_ip": "1.2.3.4", "geo": "", "asn": ""},
        }

    def test_loopback_module_never_emits_raw_injection(self):
        np.LAST_RUN = self._hostile_loopback_run()
        html = np.render_report_html_customer(np.build_report())
        for raw in FORBIDDEN_RAW:
            self.assertNotIn(raw, html, msg=f"原始注入序列泄漏: {raw!r}")

    def test_loopback_section_escapes_hostile_text(self):
        """payload 必须真的流到「环回测速」章节并以转义形态出现 (防测试假绿)。"""
        np.LAST_RUN = self._hostile_loopback_run()
        html = np.render_report_html_customer(np.build_report())
        self.assertIn('id="loopback"', html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
        self.assertNotIn("<img src=x", html)

    def test_loopback_failure_reason_never_emits_raw_injection(self):
        """未测成的原因 (Npcap 缺失 / 网关无应答) 同样进报告, 也要转义。"""
        np.LAST_RUN = self._hostile_loopback_run(failed=True)
        html = np.render_report_html_customer(np.build_report())
        for raw in FORBIDDEN_RAW:
            self.assertNotIn(raw, html, msg=f"原始注入序列泄漏: {raw!r}")

    def test_brief_v2_loopback_line_never_emits_raw_injection(self):
        """一页版的环回摘要行同样吃这些文本。"""
        np.LAST_RUN = self._hostile_loopback_run()
        html = np.render_report_html_brief_v2(np.build_report())
        for raw in FORBIDDEN_RAW:
            self.assertNotIn(raw, html, msg=f"原始注入序列泄漏: {raw!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
