# -*- coding: utf-8 -*-
"""Parsers 单元测试 (阶段 B · v1.2.0 引入)

覆盖: parse_ipconfig / parse_route_print / parse_arp_a / parse_netsh_wlan_interfaces
跑法: cd 到项目根目录, `python -m pytest tests/test_parsers.py -v`
或直接: `python tests/test_parsers.py` (用最小自实现 runner, 不依赖 pytest)
"""
import os
import sys
import unittest

# 让 import netpulse 可工作
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "windows")


def _read(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


class TestParseIpconfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _read("ipconfig_zh.txt")

    def test_parses_at_least_one_adapter(self):
        adapters = N.parse_ipconfig(self.raw)
        self.assertGreaterEqual(len(adapters), 1)

    def test_strips_preferred_suffix(self):
        adapters = N.parse_ipconfig(self.raw)
        for a in adapters:
            if a.ipv4:
                self.assertNotIn("(", a.ipv4, f"{a.name}.ipv4 含括号: {a.ipv4!r}")
                self.assertNotIn(")", a.ipv4)

    def test_extracts_ipv6_dns(self):
        """'2001:4860:4860::8888' 这样的 IPv6 DNS 不应被截断成 '2001'."""
        adapters = N.parse_ipconfig(self.raw)
        all_dns = sum((a.dns_servers for a in adapters), [])
        has_ipv6 = any(":" in d for d in all_dns)
        # 用户的 fixture 应包含 IPv6 DNS (ZeroTier 适配器)
        self.assertTrue(has_ipv6, f"IPv6 DNS 应被完整抓取: {all_dns}")

    def test_mac_normalized_to_colon_lowercase(self):
        adapters = N.parse_ipconfig(self.raw)
        for a in adapters:
            if a.mac:
                self.assertNotIn("-", a.mac[1:],
                                 f"{a.name}.mac 应转 colons: {a.mac!r}")
                self.assertEqual(a.mac, a.mac.lower())

    def test_up_adapters_have_no_disconnected_in_state(self):
        adapters = N.parse_ipconfig(self.raw)
        for a in adapters:
            if a.is_up:
                self.assertNotIn("disconnected", a.media_state.lower())

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(N.parse_ipconfig(""), [])


class TestParseRoutePrint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _read("route_zh.txt")

    def test_has_at_least_one_default_route(self):
        routes = N.parse_route_print(self.raw)
        defaults = [r for r in routes if r.is_default]
        self.assertGreaterEqual(len(defaults), 1, "至少应有 1 条默认路由")

    def test_onlink_marked_correctly(self):
        routes = N.parse_route_print(self.raw)
        for r in routes:
            if r.gateway.lower() == "on-link":
                self.assertTrue(r.is_onlink)
            else:
                self.assertFalse(r.is_onlink)

    def test_metric_is_int(self):
        routes = N.parse_route_print(self.raw)
        for r in routes:
            self.assertIsInstance(r.metric, int)

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(N.parse_route_print(""), [])


class TestParseArpA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _read("arp_zh.txt")

    def test_has_entries(self):
        entries = N.parse_arp_a(self.raw)
        self.assertGreaterEqual(len(entries), 1)

    def test_mac_lower_normalized(self):
        entries = N.parse_arp_a(self.raw)
        for e in entries:
            self.assertEqual(e.mac, e.mac.lower())

    def test_type_lowercase(self):
        entries = N.parse_arp_a(self.raw)
        for e in entries:
            self.assertIn(e.type_, ("dynamic", "static"),
                          f"type 必须是 dynamic/static 之一: {e.type_!r}")

    def test_interface_ip_set(self):
        entries = N.parse_arp_a(self.raw)
        for e in entries:
            self.assertTrue(e.interface_ip,
                            f"每条 ARP 都应绑定到接口 IP: {e!r}")

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(N.parse_arp_a(""), [])


class TestParseArpAChinese(unittest.TestCase):
    """中文 Windows 的 arp -a 输出 ('接口:' 段落 / 'Internet 地址' 表头 / 动态-静态)."""

    @classmethod
    def setUpClass(cls):
        cls.raw = _read("arp_cn.txt")

    def test_chinese_interface_section_parsed(self):
        """'接口: <ip> --- 0x<n>' 段落必须被识别 (否则整个解析返回空)."""
        entries = N.parse_arp_a(self.raw)
        self.assertGreaterEqual(len(entries), 8)
        self.assertIn("192.168.1.20", {e.interface_ip for e in entries})
        self.assertIn("192.168.56.1", {e.interface_ip for e in entries})

    def test_header_line_not_an_entry(self):
        """'Internet 地址 物理地址 类型' 表头行不能被当成条目."""
        entries = N.parse_arp_a(self.raw)
        ips = {e.ip for e in entries}
        self.assertNotIn("Internet", "".join(ips))

    def test_chinese_type_preserved(self):
        entries = N.parse_arp_a(self.raw)
        types = {e.type_ for e in entries}
        self.assertIn("动态", types)
        self.assertIn("静态", types)


class TestParseNetshWlanChinese(unittest.TestCase):
    """中文 Windows 的 netsh wlan show interfaces 输出 (名称/状态/物理地址/信号/通道)."""

    @classmethod
    def setUpClass(cls):
        cls.raw = _read("netsh_wlan_cn.txt")

    def test_finds_wlan_interface(self):
        wifis = N.parse_netsh_wlan_interfaces(self.raw)
        self.assertEqual(len(wifis), 1)
        self.assertEqual(wifis[0].name, "WLAN")

    def test_extracts_chinese_fields(self):
        wifis = N.parse_netsh_wlan_interfaces(self.raw)
        w = wifis[0]
        self.assertEqual(w.state, "已连接")
        self.assertEqual(w.ssid, "MyHomeWiFi")
        self.assertEqual(w.bssid, "02:33:a7:3a:12:74")
        self.assertEqual(w.signal_pct, 86)
        self.assertEqual(w.channel, 36)
        self.assertEqual(w.radio, "802.11ax")
        self.assertEqual(w.physical_mac, "02-4e-5a-b7-2f-a9")
        self.assertIn("AX201", w.description)

    def test_chinese_header_only_returns_empty(self):
        """'系统上有 0 个接口' 头部 (无接口) 应返回 []."""
        self.assertEqual(N.parse_netsh_wlan_interfaces("系统上没有无线接口。\r\n"), [])


class TestParseNetshWlan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = _read("netsh_wlan_zh.txt")

    def test_finds_wlan_interface(self):
        wifis = N.parse_netsh_wlan_interfaces(self.raw)
        self.assertEqual(len(wifis), 1)
        self.assertEqual(wifis[0].name, "WLAN")

    def test_extracts_mac(self):
        wifis = N.parse_netsh_wlan_interfaces(self.raw)
        self.assertEqual(wifis[0].physical_mac, "02:4e:5a:b7:2f:a9")

    def test_extracts_state(self):
        wifis = N.parse_netsh_wlan_interfaces(self.raw)
        self.assertEqual(wifis[0].state, "disconnected")

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(N.parse_netsh_wlan_interfaces(""), [])

    def test_header_only_returns_empty(self):
        """只有 'There is N interface(s)...' 头部 (无线关闭场景) 应返回 []."""
        header_only = "There is no wireless interface on the system.\r\n\r\n"
        self.assertEqual(N.parse_netsh_wlan_interfaces(header_only), [])


class TestDataclassSerialization(unittest.TestCase):
    """dataclass to_dict() / 字段类型契约 — 阶段 A 数据模型保障."""

    def test_network_adapter_to_dict_keys(self):
        a = N.NetworkAdapter(name="WLAN", desc="x", mac="00:11:22:33:44:55",
                             ipv4="1.2.3.4", prefix_len=24, dns_servers=["8.8.8.8"])
        d = a.to_dict() if hasattr(a, "to_dict") else a.__dict__
        self.assertEqual(d["name"], "WLAN")
        self.assertEqual(d["mac"], "00:11:27:33:44:55"[:0] + "00:11:22:33:44:55")
        self.assertEqual(d["dns_servers"], ["8.8.8.8"])

    def test_route_entry_is_default(self):
        r1 = N.RouteEntry(destination="0.0.0.0", netmask="0.0.0.0",
                          gateway="192.168.1.1", interface_ip="192.168.1.2", metric=10)
        r2 = N.RouteEntry(destination="192.168.1.0", netmask="255.255.255.0",
                          gateway="192.168.1.2", interface_ip="192.168.1.2", metric=10)
        self.assertTrue(r1.is_default)
        self.assertFalse(r2.is_default)

    def test_network_adapter_is_up(self):
        a1 = N.NetworkAdapter(name="x", desc="x", media_state="")
        a2 = N.NetworkAdapter(name="x", desc="x", media_state="Media disconnected")
        self.assertTrue(a1.is_up)
        self.assertFalse(a2.is_up)


if __name__ == "__main__":
    # 不依赖 pytest, 直接用 unittest 跑
    unittest.main(verbosity=2)