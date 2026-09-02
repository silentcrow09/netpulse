# -*- coding: utf-8 -*-
"""Debug-bundle 脱敏单元测试 (阶段 D · v1.4.1 修复)

覆盖: 公网 IPv4/IPv6 打码、STUN mapped 地址、文案内嵌 ip:port、
内网地址保留。跑用: python tests/test_redaction.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


class TestKeyLevelRedaction(unittest.TestCase):
    """key 级规则: 命中隐私 key 的字段整值打码."""

    def test_ipv6_public_ip_masked(self):
        v = N._redact_value("ipv6_public_ip", "2408:8207:1234:abcd:5678:ef01:2222:3333")
        self.assertNotIn("3333", v)
        self.assertIn("2408:8207", v)  # 保留前两组 (与 IPv4 a.b.X.X 同粒度)

    def test_public_ipv4_masked(self):
        v = N._redact_value("public_ip", "112.65.44.98")
        self.assertEqual(v, "112.65.X.X")

    def test_mapped_ip_masked(self):
        """STUN 映射地址是用户出口身份, 必须打码."""
        self.assertEqual(N._redact_value("mapped_ip", "112.65.44.98"), "112.65.X.X")
        self.assertEqual(N._redact_value("mapped_addr", "112.65.44.98:51820"),
                         "112.65.X.X:X")
        self.assertEqual(N._redact_value("mapped_port", 51820), "X")

    def test_ssid_and_mac_masked(self):
        self.assertEqual(N._redact_value("ssid", "MyHomeWiFi"), "***")
        self.assertEqual(N._redact_value("wifi_mac", "AA:BB:CC:DD:EE:FF"),
                         "XX:XX:XX:XX:XX:XX")

    def test_private_ip_kept(self):
        """内网/回环/组播地址是排障刚需, 保留."""
        for ip in ("192.168.1.1", "10.0.0.1", "172.16.5.4", "127.0.0.1",
                   "169.254.1.1", "224.0.0.1"):
            self.assertEqual(N._redact_value("gateway", ip), ip)


class TestTextLevelRedaction(unittest.TestCase):
    """文案级规则: summary/message 等自由文本里嵌的公网地址打码."""

    def test_nat_summary_ip_port_masked(self):
        s = "NAT 类型: 对称型 — 映射 112.65.44.98:51820, UDP 出口 112.65.44.98 ≠ HTTP 出口 112.65.44.98"
        v = N._redact_value("summary", s)
        self.assertNotIn("112.65.44.98", v)
        self.assertNotIn("51820", v)
        self.assertIn("对称型", v)  # 非地址内容不动

    def test_summary_ipv6_masked(self):
        v = N._redact_value("summary", "IPv6: 2408:8207:1234:abcd::1 可达")
        self.assertNotIn("abcd", v)
        self.assertIn("可达", v)

    def test_summary_private_ip_kept(self):
        v = N._redact_value("summary", "网关 192.168.1.1 平均 1.2ms")
        self.assertIn("192.168.1.1", v)

    def test_link_local_ipv6_kept(self):
        v = N._redact_value("summary", "链路本地 fe80::1a2b:3c4d:5e6f 可达")
        self.assertIn("fe80::1a2b", v)

    def test_error_text_masked(self):
        v = N._redact_value("error", "连接 8.8.8.8:53 失败")
        self.assertNotIn("8.8.8.8", v)


class TestNestedRedaction(unittest.TestCase):
    """_redact_dict 递归: NATTypeTester.results 形状的嵌套结构."""

    def _nat_results(self):
        return {
            "nat_behavior": "对称型", "cone_type": "—",
            "mapped_ip": "112.65.44.98", "mapped_port": 51820,
            "mapped_addr": "112.65.44.98:51820",
            "public_ip_tcp": "112.65.44.98",
            "servers": [
                {"server": "stun1.example", "ok": True,
                 "mapped_addr": "112.65.44.98:51820", "rtt_ms": 30.0},
            ],
            "local_lan_ip": "192.168.1.100",
            "issues": [],
            "summary": "NAT 类型: 对称型 — 映射 112.65.44.98:51820",
        }

    def test_nat_results_no_leak(self):
        r = N._redact_dict(self._nat_results())
        blob = repr(r)
        self.assertNotIn("112.65.44.98", blob)
        self.assertNotIn("51820", blob)
        # 内网与判定结论保留 (排障需要)
        self.assertEqual(r["local_lan_ip"], "192.168.1.100")
        self.assertEqual(r["nat_behavior"], "对称型")
        self.assertEqual(r["servers"][0]["server"], "stun1.example")

    def test_system_snapshot_no_leak(self):
        r = N._redact_dict({
            "local_ip": "192.168.1.100", "gateway": "192.168.1.1",
            "public_ip": "112.65.44.98", "ipv6_public_ip": "2408:8207:11:22::33",
            "asn": "中国电信", "geo": "上海 / 上海",
        })
        blob = repr(r)
        self.assertNotIn("112.65.44.98", blob)
        self.assertNotIn("22", r["ipv6_public_ip"])  # 后段全遮
        self.assertEqual(r["gateway"], "192.168.1.1")
        self.assertEqual(r["asn"], "中国电信")


if __name__ == "__main__":
    unittest.main(verbosity=2)
