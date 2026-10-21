# -*- coding: utf-8 -*-
"""v1.15.2 审查 P2 · 公网 IP/geo 与 LAN 厂商补查的隐私口径 回归测试。

旧版实现 (审查前):
  1. get_ip_geo() 用**明文 HTTP** 的 ip-api.com —— 公网 IP 明文躺在 URL path 里,
     路径上任何一跳 (公共 WiFi 的 AP / 运营商透明代理) 都能直接读到;
     且该服务免费版不支持 HTTPS (实测 https 返回 403)。
  2. 公网 IP / 出口位置 / 厂商 查询**无任何披露**, 也**无离线开关** ——
     38 个 CLI 参数与全部环境变量里都没有能关掉它们的入口。
  3. LAN 厂商补查把**完整 MAC** 发给 mac.bmcx.com, 同样无披露无开关。

修后:
  - geo 查询改用 ipwho.is (HTTPS + lang=zh-CN 中文返回, 字段对齐)
  - NP_OFFLINE=1 → 公网 IP / IPv6 / 地理 / egress 的 IP 池全部不发请求
  - NP_NO_ONLINE_OUI=1 → 不发任何厂商补查请求
  - 报告披露: 客户报告「主机信息」区列出实际会请求的第三方域名 (从常量生成)
  - LAN 扫描在实际发生补查时, issues 里披露补查次数与域名

跑用: cd 到项目根目录, `py -3.13 tests/test_v1152_privacy_egress.py`
"""
import contextlib
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


class _FakeResp:
    """urlopen 返回值的最小替身。"""

    def __init__(self, payload=b"", status=200):
        self._payload = payload
        self.status = status

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestGeoQueryOverHttps(unittest.TestCase):
    """地理/ASN 查询不得走明文 HTTP。"""

    def test_geo_query_uses_https(self):
        payload = json.dumps({
            "success": True, "ip": "1.2.3.4", "country": "中国",
            "region": "江苏", "city": "南京",
            "connection": {"isp": "中国电信", "org": "China Telecom",
                           "asn": 137702},
        }).encode("utf-8")
        seen = {}

        def _fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            return _FakeResp(payload)

        with mock.patch("netpulse.urlopen", side_effect=_fake_urlopen):
            geo = N.get_ip_geo("1.2.3.4")
        self.assertIn("url", seen, "应当发出过请求")
        self.assertTrue(seen["url"].startswith("https://"),
                        "地理查询必须走 HTTPS (明文 HTTP 会把公网 IP 暴露给路径上每一跳): %s"
                        % seen["url"])
        self.assertNotIn("http://", seen["url"])
        self.assertIsNotNone(geo)
        self.assertEqual("中国", geo.get("country"))
        self.assertEqual("江苏", geo.get("region"))
        self.assertEqual("南京", geo.get("city"))
        self.assertEqual("中国电信", geo.get("isp"))
        self.assertEqual("AS137702", geo.get("asn"))

    def test_geo_service_constant_is_https(self):
        svc = getattr(N, "IP_GEO_SERVICE", "")
        self.assertTrue(svc.startswith("https://"),
                        "IP_GEO_SERVICE 必须是 https: %r" % svc)


class TestOfflineSwitch(unittest.TestCase):
    """NP_OFFLINE=1 → 一个外网请求都不发。"""

    def _cfg(self):
        cfg = getattr(N, "NETWORK_CONFIG", None)
        if cfg is None:
            self.fail("缺少 NETWORK_CONFIG 离线开关 (旧版无此能力)")
        return cfg

    def test_offline_blocks_public_ip(self):
        with mock.patch.dict(self._cfg(), {"offline": True}), \
             mock.patch("netpulse.urlopen") as m_open:
            self.assertIsNone(N.get_public_ip())
        self.assertFalse(m_open.called, "离线模式下不得请求公网 IP 服务")

    def test_offline_blocks_public_ipv6(self):
        with mock.patch.dict(self._cfg(), {"offline": True}), \
             mock.patch("netpulse.urlopen") as m_open:
            self.assertIsNone(N.get_public_ipv6())
        self.assertFalse(m_open.called, "离线模式下不得请求 IPv6 服务")

    def test_offline_blocks_geo(self):
        with mock.patch.dict(self._cfg(), {"offline": True}), \
             mock.patch("netpulse.urlopen") as m_open:
            self.assertIsNone(N.get_ip_geo("1.2.3.4"))
        self.assertFalse(m_open.called, "离线模式下不得查询地理信息")

    def test_offline_suppresses_disclosure(self):
        """离线时不该再提第三方查询 (没查就没得披露)。"""
        with mock.patch.dict(self._cfg(), {"offline": True}):
            self.assertEqual("", N._public_ip_disclosure())

    def test_env_flag_parsing(self):
        flag = getattr(N, "_env_flag", None)
        if flag is None:
            self.fail("缺少 _env_flag")
        with mock.patch.dict(os.environ, {"NP_TEST_FLAG": "1"}):
            self.assertTrue(flag("NP_TEST_FLAG"))
        for v in ("", "0", "false", "no", "off", "FALSE"):
            with mock.patch.dict(os.environ, {"NP_TEST_FLAG": v}):
                self.assertFalse(flag("NP_TEST_FLAG"),
                                 "值 %r 应视为关闭" % v)


class TestPublicIpDisclosure(unittest.TestCase):
    """报告必须披露公网 IP 是谁查的, 且域名从常量生成。"""

    def test_disclosure_lists_real_service_domains(self):
        disc = getattr(N, "_public_ip_disclosure", None)
        if disc is None:
            self.fail("缺少公网 IP 第三方查询披露")
        text = disc()
        self.assertIn("公网 IP", text)
        for url, _mode in getattr(N, "PUBLIC_IP_SERVICES", ()):
            host = url.split("//", 1)[-1].split("/")[0]
            self.assertIn(host, text,
                          "披露必须列出实际会请求的域名 %s" % host)
        self.assertIn("ipwho.is", text, "地理查询服务也要披露")

    def test_disclosure_follows_constants(self):
        """域名清单改了, 披露文案必须跟着变 (不能各写一份)。"""
        disc = getattr(N, "_public_ip_disclosure", None)
        if disc is None:
            self.fail("缺少公网 IP 第三方查询披露")
        with mock.patch.object(N, "PUBLIC_IP_SERVICES",
                               (("https://example-test-host.invalid/ip", "text"),)):
            self.assertIn("example-test-host.invalid", disc())


class TestOuiOnlineSwitchAndDisclosure(unittest.TestCase):
    """LAN 厂商补查: 开关 + 披露。"""

    def test_switch_blocks_online_lookup(self):
        with mock.patch.object(N, "_OUI_ONLINE_ENABLED", False, create=True), \
             mock.patch("netpulse._urlopen_with_proxy") as m_open:
            v = N._oui_vendor_online("AA-BB-CC-DD-EE-FF")
        self.assertEqual("", v)
        self.assertFalse(m_open.called,
                         "关闭在线补查后不得把 MAC 发给第三方")

    def test_lookup_counts_requests_for_disclosure(self):
        """实际发出的补查请求要被计数, 供披露用。"""
        counter = getattr(N, "_OUI_ONLINE_SENT", None)
        if counter is None:
            self.fail("缺少 _OUI_ONLINE_SENT 计数 (无法披露)")
        with mock.patch.object(N, "_OUI_ONLINE_ENABLED", True, create=True), \
             mock.patch.object(N, "_OUI_ONLINE_CACHE", {}, create=True), \
             mock.patch("netpulse._urlopen_with_proxy",
                        return_value=_FakeResp(b"<html></html>")):
            N._oui_vendor_online("11-22-33-44-55-66")
        self.assertGreaterEqual(counter["n"], 1,
                                "发出的补查请求必须被计数 (披露要用)")

    def test_service_constant_is_https_and_single_source(self):
        svc = getattr(N, "OUI_ONLINE_SERVICE", "")
        self.assertTrue(svc.startswith("https://"),
                        "厂商补查必须走 HTTPS: %r" % svc)
        self.assertIn("mac.bmcx.com", svc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
