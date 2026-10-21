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


class TestValueLevelRedaction(unittest.TestCase):
    """v1.15.0 审查 P1-10: 未知 key 里的公网地址也必须打码。

    旧版只按 key 命中脱敏 (public_ip / mapped_ip / ssid / mac / 文案字段),
    未知 key 里的公网 IP 原样落盘:
      traceroute[].ip / detail[].resolved_ip / path_mtus[].target
    而调试包 log 声明「公网 IPv4+IPv6 已脱敏」—— 承诺与行为不符。
    """

    def test_unknown_key_public_ipv4_masked(self):
        self.assertEqual(N._redact_value("ip", "202.96.128.86"), "202.96.X.X")

    def test_traceroute_entry_masked(self):
        r = N._redact_dict({"traceroute": [{"hop": 3, "ip": "202.96.128.86",
                                            "rtt_ms": 12.0}]})
        self.assertNotIn("202.96.128.86", repr(r))
        self.assertEqual(r["traceroute"][0]["ip"], "202.96.X.X")
        self.assertEqual(r["traceroute"][0]["rtt_ms"], 12.0)   # 非地址不动

    def test_resolved_ip_masked(self):
        r = N._redact_dict({"detail": [{"dns_server": "223.5.5.5",
                                        "resolved_ip": "110.242.68.66",
                                        "domain": "www.baidu.com"}]})
        self.assertNotIn("110.242.68.66", repr(r))
        self.assertEqual(r["detail"][0]["domain"], "www.baidu.com")

    def test_public_ipv6_in_unknown_key_masked(self):
        r = N._redact_dict({"path_mtus": [{"target": "2408:8207:11:22::33",
                                           "path_mtu": 1400}]})
        self.assertNotIn("11:22", repr(r))
        self.assertEqual(r["path_mtus"][0]["path_mtu"], 1400)

    def test_mac_value_masked(self):
        """MAC 形态的值即便 key 不含 mac (如 hwaddr) 也要打码."""
        r = N._redact_dict({"hwaddr": "AA-BB-CC-DD-EE-FF",
                            "peer": "aa:bb:cc:dd:ee:ff"})
        self.assertNotIn("AA-BB-CC-DD-EE-FF", repr(r))
        self.assertNotIn("aa:bb:cc:dd:ee:ff", repr(r))

    def test_private_ip_kept_in_unknown_key(self):
        r = N._redact_dict({"ip": "192.168.1.1", "ip6": "fe80::1a2b:3c4d"})
        self.assertEqual(r["ip"], "192.168.1.1")
        self.assertIn("fe80::1a2b", r["ip6"])

    def test_masking_is_idempotent(self):
        once = N._redact_value("ip", "202.96.128.86")
        twice = N._redact_value("ip", once)
        self.assertEqual(once, twice)
        v6_once = N._redact_value("addr", "2408:8207:11:22::33")
        self.assertEqual(v6_once, N._redact_value("addr", v6_once))

    def test_redact_any_handles_list_top_level(self):
        """模块结果是 list 时也要脱敏 (旧版 else v 直接放行)."""
        out = N._redact_any([{"ip": "202.96.128.86"}, "文本 110.242.68.66"])
        self.assertNotIn("202.96.128.86", repr(out))
        self.assertNotIn("110.242.68.66", repr(out))


class TestDebugBundleRedactionEndToEnd(unittest.TestCase):
    """端到端: 调试包 zip 里不得出现公网 IP / MAC / hostname。"""

    def _bundle_blob(self, results):
        import json
        import os
        import tempfile
        import zipfile
        from datetime import datetime
        old = N.LAST_RUN
        N.LAST_RUN = {
            "app": "NetPulse", "version": N.APP_VERSION,
            "generated_at": datetime(2026, 10, 20, 12, 0, 0),
            "status": {"dns": "完成", "external": "警告"},
            "keys": ["dns", "external"], "duration_ms": 1234,
            "total_modules": 2,
            "system": {"hostname": "PC-SH-01", "local_ip": "192.168.1.10",
                       "gateway": "192.168.1.1", "dns": "223.5.5.5",
                       "public_ip": "61.153.2.254",
                       "ipv6_public_ip": "240e:3b1:2c0d::1"},
            "results": results,
            "evidence": {"mtu": {"probe": {"path_mtu": [
                {"target": "202.96.128.86", "path_mtu": 1400}]}}},
        }
        d = tempfile.mkdtemp(prefix="np_bundle_test_")
        try:
            N._export_debug_bundle(d, N.LAST_RUN)
            zips = [f for f in os.listdir(d) if f.endswith(".zip")]
            self.assertTrue(zips, "没生成 zip")
            blob = ""
            with zipfile.ZipFile(os.path.join(d, zips[0])) as z:
                for nm in z.namelist():
                    blob += z.read(nm).decode("utf-8", "replace")
            return blob
        finally:
            N.LAST_RUN = old

    def test_no_public_ip_in_bundle(self):
        blob = self._bundle_blob({
            "dns": {"detail": [{"dns_server": "223.5.5.5",
                                "resolved_ip": "110.242.68.66"}],
                    "issues": []},
            "external": {"traceroute": [{"hop": 3, "ip": "202.96.128.86"}],
                         "issues": []},
        })
        for ip in ("61.153.2.254", "110.242.68.66", "202.96.128.86",
                   "223.5.5.5", "240e:3b1:2c0d::1", "PC-SH-01"):
            self.assertNotIn(ip, blob, f"调试包里仍出现 {ip}")

    def test_claim_line_present_and_scope_documented(self):
        blob = self._bundle_blob({"dns": {"issues": []}})
        self.assertIn("Redacted:", blob)
        self.assertIn("Redaction scope:", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
