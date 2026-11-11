# -*- coding: utf-8 -*-
"""网口对照表 (端口定位) 测试 — v1.18.3

装维现场最常见的三个问题, 这张表要一眼答得出:
  1. 网线插错口了          → 哪块口承载默认路由 (出口口)
  2. 链路降速了 (千兆掉百兆) → 协商速率档位 + 提示
  3. 虚拟网卡在捣乱        → WiFi 口 / 虚拟口要单列, 不能当物理口

跑用: cd 到项目根目录, `py -3.13 tests/test_v1183_port_map.py`
"""
import math
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as np  # noqa: E402


def _adapter(name, speed=None, status="Up", wifi=False,
             desc="Realtek PCIe GbE Family Controller", virtual=False):
    """构造一个 linkspeed adapters[] 样本 (字段名对齐 netpulse.py 的真实结构)。"""
    a = {
        "name": name,
        "description": desc,
        "status": status,
        "media_type": "Native 802.11" if wifi else "802.3",
        "is_wifi": wifi,
        "link_speed_raw": ("" if speed is None else f"{speed} Mbps"),
        "speed_mbps": (0.0 if speed is None else float(speed)),
        "assessment": "",
        "virtual": virtual,
    }
    return a


def _linkspeed_res(egress="以太网 2", adapters=None):
    """构造 linkspeed 模块结果 (字段名对齐 netpulse.py 的真实结构)。"""
    if adapters is None:
        adapters = [
            _adapter("以太网 2", 1000),
            _adapter("以太网 3", 100),
            _adapter("WLAN", 866, wifi=True, desc="Intel(R) AX201"),
            _adapter("ZeroTier One [a1b2]", 10000, desc="ZeroTier One [a1b2]"),
            _adapter("USB 以太网 5", None, status="Down", desc="USB Ethernet"),
        ]
    return {
        "adapters": adapters,
        "wifi_details": {},
        "wifi_interfaces": [],
        "nic_errors": {"total_errors": 0, "total_discarded": 0},
        "issues": [],
        "egress_interface": egress,
        "timestamp": datetime.now().isoformat(),
        "summary": "检测到 5 个网络适配器",
    }


def _last_run(linkspeed=None, keys=None):
    """构造最小可用的 LAST_RUN (结构参照 tests/test_html_escape.py)。"""
    if linkspeed is None:
        linkspeed = _linkspeed_res()
    return {
        "app": "NetPulse", "version": "1.18.3",
        "generated_at": datetime.now(),
        "status": {"linkspeed": "完成"},
        "results": {"linkspeed": linkspeed},
        "keys": keys or ["linkspeed"],
        "duration_ms": 42, "total_modules": 23,
        "system": {"hostname": "PC-01", "local_ip": "192.168.1.10",
                   "gateway": "192.168.1.1", "dns": "223.5.5.5",
                   "public_ip": "1.2.3.4", "geo": "北京", "asn": "AS4134"},
    }


def _portline(html):
    """取出一页版里的网口摘要行 (没有则返回空串)。"""
    i = html.find('<div class="portline">')
    if i < 0:
        return ""
    j = html.find("</div>", i)
    return html[i:j]


class TestLinkspeedTier(unittest.TestCase):
    """共享档位 helper: 速率阈值与 VPN 关键字表只允许存在一份实现。"""

    def test_wired_thresholds(self):
        self.assertEqual(np._linkspeed_tier(_adapter("以太网", 1000))[2], "ok")
        self.assertEqual(np._linkspeed_tier(_adapter("以太网", 100))[2], "warn")
        self.assertEqual(np._linkspeed_tier(_adapter("以太网", 50))[2], "err")

    def test_wifi_thresholds(self):
        self.assertEqual(np._linkspeed_tier(_adapter("WLAN", 866, wifi=True))[2], "ok")
        self.assertEqual(np._linkspeed_tier(_adapter("WLAN", 100, wifi=True))[2], "warn")
        self.assertEqual(np._linkspeed_tier(_adapter("WLAN", 30, wifi=True))[2], "err")

    def test_virtual_adapter_not_penalised(self):
        """虚拟口速率再低也不判异常 —— 隧道速率不代表物理链路。"""
        kind, speed, level, hint, is_virt = np._linkspeed_tier(
            _adapter("ZeroTier One", 10, desc="ZeroTier One"))
        self.assertEqual(kind, "虚拟")
        self.assertTrue(is_virt)
        self.assertEqual(level, "ok")
        self.assertIn("不代表物理链路", hint)

    def test_verdict_text_unchanged(self):
        """抽取共享 helper 后, verdict 文案必须逐字不变 (零回归)。"""
        res = _linkspeed_res()
        res["adapters"] = [_adapter("以太网 3", 100)]
        self.assertIn("部分档位偏低 (千兆期望下百兆)", np._verdict_linkspeed(res))

    def test_metrics_hint_text_unchanged(self):
        """_metrics_linkspeed 的 hint 文案必须逐字不变。"""
        res = _linkspeed_res()
        res["adapters"] = [_adapter("以太网 3", 100)]
        out = np._metrics_linkspeed(res)
        hints = [h for _, _, _, h in out]
        self.assertIn("协商到百兆, 千兆环境应达 1000 Mbps", hints)

    def test_verdict_zero_float_speed_matches_baseline(self):
        """speed_mbps = 0.0 时 verdict 文案与既有实现逐字一致 ("0 Mbps")。

        既有实现写的是 `a.get("speed_mbps", 0) or 0` —— 0.0 被归一成 int 0。
        抽成共享 helper 后若直接返回 0.0, 文案会变成 "0.0 Mbps", 即零回归。
        """
        a = _adapter("以太网 2", 1000)
        a["speed_mbps"] = 0.0
        res = _linkspeed_res(egress="以太网 2", adapters=[a])
        verdict = np._verdict_linkspeed(res)
        self.assertIn("0 Mbps", verdict)
        self.assertNotIn("0.0 Mbps", verdict)

    def test_metrics_missing_speed_key_keeps_zero_mbps(self):
        """探测器没给 speed_mbps 时, 既有渲染是 "0 Mbps" (不是 "0.0 Mbps")。"""
        a = _adapter("以太网 2", 1000)
        a.pop("speed_mbps")
        out = np._metrics_linkspeed(_linkspeed_res(egress="以太网 2", adapters=[a]))
        self.assertIn("0 Mbps", out[0][1])
        self.assertNotIn("0.0 Mbps", out[0][1])

    def test_software_bridge_kind_is_virtual(self):
        """软件桥接网卡 (VirtualBox/Hyper-V/WSL) 的类型是「虚拟」。

        全报告统一一个词义: 别让 linkspeed 模块卡说「有线 / 检查网线」,
        而对照表说「虚拟口」—— 同一份报告自相矛盾, 装维会去查一根不存在的网线。
        """
        a = _adapter("VirtualBox Host-Only Network", 1000,
                     desc="VirtualBox Host-Only Ethernet Adapter", virtual=True)
        kind, _speed, level, hint, is_virt = np._linkspeed_tier(a)
        self.assertEqual(kind, "虚拟")
        self.assertTrue(is_virt)
        self.assertEqual(level, "ok")
        self.assertNotIn("网线", hint)

    def test_software_bridge_tier_threshold_unchanged(self):
        """档位 (扣分) 口径不变 —— 软件桥接口仍按有线阈值算。

        本期只改**类型标签与提示措辞**, 不动既有模块的健康分口径。
        """
        a = _adapter("VirtualBox Host-Only Network", 10,
                     desc="VirtualBox Host-Only Ethernet Adapter", virtual=True)
        kind, _speed, level, hint, _virt = np._linkspeed_tier(a)
        self.assertEqual(kind, "虚拟")
        self.assertEqual(level, "err")       # 与既有 linkspeed 模块口径一致
        self.assertNotIn("检查网线", hint)


class TestDerivePortMap(unittest.TestCase):
    """角色判定: 出口口 / 内网口 / WiFi 口 / 虚拟口 / 未插口。"""

    def _roles(self, res):
        return {e["name"]: e["role"] for e in np._derive_port_map(res)}

    def test_role_assignment(self):
        roles = self._roles(_linkspeed_res())
        self.assertEqual(roles["以太网 2"], "出口口")
        self.assertEqual(roles["以太网 3"], "内网口")
        self.assertEqual(roles["WLAN"], "WiFi 口")
        self.assertEqual(roles["ZeroTier One [a1b2]"], "虚拟口")
        self.assertEqual(roles["USB 以太网 5"], "未插口")

    def test_exactly_one_egress(self):
        rows = np._derive_port_map(_linkspeed_res())
        egress = [e for e in rows if e["role"] == "出口口"]
        self.assertEqual(len(egress), 1)
        self.assertEqual(egress[0]["name"], "以太网 2")

    def test_unplugged_adapter_not_flagged_as_low_speed(self):
        """未插的网卡 speed=0, 不能被判成「协商速率过低」。"""
        rows = {e["name"]: e for e in np._derive_port_map(_linkspeed_res())}
        down = rows["USB 以太网 5"]
        self.assertEqual(down["role"], "未插口")
        self.assertNotIn("协商速率过低", down["hint"])

    def test_down_speed_kept_as_zero(self):
        rows = {e["name"]: e for e in np._derive_port_map(_linkspeed_res())}
        self.assertEqual(rows["USB 以太网 5"]["speed_mbps"], 0)

    def test_virtual_adapter_never_downgrades_wired_tier(self):
        """虚拟口速率 10 Mbps 不得把整体档位拖到异常 (档位不适用 = n/a)。"""
        rows = {e["name"]: e for e in np._derive_port_map(_linkspeed_res())}
        self.assertEqual(rows["ZeroTier One [a1b2]"]["level"], "n/a")

    def test_low_speed_wired_gets_existing_hint_verbatim(self):
        rows = {e["name"]: e for e in np._derive_port_map(_linkspeed_res())}
        self.assertEqual(rows["以太网 3"]["hint"],
                         "协商到百兆, 千兆环境应达 1000 Mbps")
        self.assertEqual(rows["以太网 3"]["level"], "warn")

    def test_unknown_egress_marks_wired_as_undetermined(self):
        """拿不到默认路由出口时, 有线口不能瞎标成「内网口」。"""
        roles = self._roles(_linkspeed_res(egress=""))
        self.assertEqual(roles["以太网 2"], "未判定")
        self.assertEqual(roles["以太网 3"], "未判定")

    def test_empty_adapters_returns_empty_list(self):
        self.assertEqual(np._derive_port_map({"adapters": []}), [])

    def test_missing_adapters_key_returns_empty_list(self):
        self.assertEqual(np._derive_port_map({}), [])

    def test_disconnected_wifi_hint_mentions_no_ethernet_cable(self):
        """无线口没连上时不能说「网线未接」—— 无线口根本没有网线。"""
        adapters = [_adapter("WLAN", 130, status="Disconnected", wifi=True)]
        rows = np._derive_port_map(_linkspeed_res(egress="以太网", adapters=adapters))
        self.assertEqual(rows[0]["role"], "未插口")
        self.assertNotIn("网线", rows[0]["hint"])

    def test_port_map_carries_driver_description(self):
        """描述 (驱动名) 要带上 —— 靠它分辨物理口与 VirtualBox 这类虚拟网卡。"""
        rows = np._derive_port_map(_linkspeed_res())
        self.assertIn("Realtek PCIe GbE Family Controller", rows[0]["description"])

    def test_disconnected_adapter_drops_stale_negotiated_speed(self):
        """未连接的网卡, 驱动报的协商速率是上次连接留下的陈旧值, 不能当实测展示。"""
        adapters = [_adapter("WLAN", 130, status="Disconnected", wifi=True)]
        rows = np._derive_port_map(_linkspeed_res(egress="以太网", adapters=adapters))
        self.assertEqual(rows[0]["speed_mbps"], 0)

    def test_non_connected_adapter_level_is_na_not_ok(self):
        """未连接 = 无速率可判, 不能报「ok」(那会让 JSON 里一个没插线的口看着正常)。"""
        rows = np._derive_port_map(_linkspeed_res())
        down = [r for r in rows if r["role"] == "未插口"][0]
        self.assertEqual(down["level"], "n/a")

    def test_hardware_virtual_flag_marks_virtual_adapter(self):
        """VirtualBox/Hyper-V 这类本地桥接口: Windows Virtual 属性为 True,
        不能被标成「有线/内网口」—— 客户会去找一根不存在的网线。"""
        adapters = [_adapter("VirtualBox Host-Only Network", 1000,
                             desc="VirtualBox Host-Only Ethernet Adapter",
                             virtual=True)]
        rows = np._derive_port_map(_linkspeed_res(egress="以太网 2", adapters=adapters))
        self.assertEqual(rows[0]["kind"], "虚拟")
        self.assertEqual(rows[0]["role"], "虚拟口")

    def test_virtual_adapter_not_penalised_in_port_map(self):
        """虚拟桥接口的速率不代表物理链路, 不该被判成降速口 (档位不适用)。"""
        adapters = [_adapter("VirtualBox Host-Only Network", 10,
                             desc="VirtualBox Host-Only Ethernet Adapter",
                             virtual=True)]
        rows = np._derive_port_map(_linkspeed_res(egress="以太网 2", adapters=adapters))
        self.assertEqual(rows[0]["level"], "n/a")
        self.assertNotIn("协商速率过低", rows[0]["hint"])

    def test_unmatched_egress_alias_marks_wired_as_undetermined(self):
        """出口别名对不上任何网卡 → 视作未知, 有线口标「未判定」而不是「内网口」。"""
        rows = np._derive_port_map(_linkspeed_res(
            egress="以太网 99", adapters=[_adapter("以太网 2", 1000)]))
        self.assertEqual(rows[0]["role"], "未判定")
        self.assertEqual([r for r in rows if r["role"] == "出口口"], [])

    def test_down_egress_adapter_still_marked_as_egress(self):
        """默认路由指着的那块口没连: 仍要标「出口口」, 否则装维不知道该查哪块口。"""
        rows = np._derive_port_map(_linkspeed_res(
            egress="以太网 2", adapters=[_adapter("以太网 2", 1000, status="Down")]))
        self.assertEqual(rows[0]["role"], "出口口")
        self.assertIn("未连接", rows[0]["hint"])

    def test_non_numeric_speed_does_not_raise(self):
        """speed_mbps 传成非数值字符串也不能抛异常 (port_map 已是公开 JSON 契约)。"""
        a = _adapter("以太网 2", 1000)
        a["speed_mbps"] = "abc"
        rows = np._derive_port_map(_linkspeed_res(egress="以太网 2", adapters=[a]))
        self.assertEqual(rows[0]["speed_mbps"], 0)

    def test_numeric_string_speed_is_parsed(self):
        a = _adapter("以太网 2", 1000)
        a["speed_mbps"] = "1000"
        rows = np._derive_port_map(_linkspeed_res(egress="以太网 2", adapters=[a]))
        self.assertEqual(rows[0]["speed_mbps"], 1000.0)

    def test_int_zero_speed_keeps_int_type(self):
        """LinkSpeedDetector 在 LinkSpeed 不可解析时给的是 int 0 ——
        渲染必须保持 "0 Mbps", 不能变成 "0.0 Mbps" (既有文案逐字不变)。"""
        a = _adapter("以太网 2", 1000)
        a["speed_mbps"] = 0
        self.assertIn("0 Mbps", np._metrics_linkspeed(
            _linkspeed_res(egress="以太网 2", adapters=[a]))[0][1])

    def test_short_iface_respects_max_len(self):
        """方括号分支此前无视 max_len, 截断结果可能超预算。"""
        out = np._short_iface("ZeroTier One [9f77fc393e225015]", 24)
        self.assertLessEqual(len(out), 24)

    def test_short_iface_keeps_distinguishing_part(self):
        """裁剪时必须保留方括号里的区分段 —— 同名不同 GUID 的网卡要能区分。"""
        out = np._short_iface("Some Really Long Adapter Name [abcdefghijklmnop]", 36)
        self.assertLessEqual(len(out), 36)
        self.assertIn("[", out)
        self.assertIn("]", out)

    def test_duplicate_adapter_name_yields_single_egress(self):
        """同名网卡: 出口口只能有一行 (S2 要求唯一), 第二行不能也标「出口口」。"""
        adapters = [_adapter("以太网 2", 1000), _adapter("以太网 2", 1000)]
        rows = np._derive_port_map(_linkspeed_res(egress="以太网 2", adapters=adapters))
        self.assertEqual(len([r for r in rows if r["role"] == "出口口"]), 1)
        self.assertEqual(rows[1]["role"], "未判定")
        self.assertIn("同名", rows[1]["hint"])

    def test_port_map_speed_always_json_number(self):
        """speed_mbps 是 null / NaN / Inf 时也必须落成数字。

        schema 声明的是 "type": "number", 且 port_map 是公开 JSON 契约 ——
        NaN 写进 JSON 会让严格解析器直接报错。
        """
        for bad in (None, float("nan"), float("inf"), float("-inf")):
            a = _adapter("以太网 2", 1000)
            a["speed_mbps"] = bad
            rows = np._derive_port_map(_linkspeed_res(egress="以太网 2", adapters=[a]))
            v = rows[0]["speed_mbps"]
            self.assertIsInstance(v, (int, float), msg=f"{bad!r} 未落成数字")
            self.assertNotIsInstance(v, bool)
            self.assertTrue(math.isfinite(v), msg=f"{bad!r} 落成了非有限值")


class TestLinkspeedEgress(unittest.TestCase):
    """linkspeed 模块结果要带出口网卡别名, 单跑该模块也能定位出口口。"""

    def test_result_carries_egress_interface(self):
        det = np.LinkSpeedDetector()
        saved = np._default_route_if_mtu
        np._default_route_if_mtu = lambda: (1500, "以太网 2")
        try:
            res = det.detect()
        finally:
            np._default_route_if_mtu = saved
        self.assertEqual(res.get("egress_interface"), "以太网 2")

    def test_egress_interface_empty_when_lookup_fails(self):
        """取不到默认路由 (无网络 / PowerShell 受限) 不能抛异常, 留空串降级。"""
        det = np.LinkSpeedDetector()
        saved = np._default_route_if_mtu
        np._default_route_if_mtu = lambda: (None, "")
        try:
            res = det.detect()
        finally:
            np._default_route_if_mtu = saved
        self.assertEqual(res.get("egress_interface"), "")


class TestReportPortMapSection(unittest.TestCase):
    """完整版报告要有一级章节「网口对照」。"""

    def setUp(self):
        self._saved = np.LAST_RUN

    def tearDown(self):
        np.LAST_RUN = self._saved

    def test_section_exists_with_table(self):
        np.LAST_RUN = _last_run()
        html = np.render_report_html_customer(np.build_report())
        self.assertIn("网口对照", html)
        self.assertIn("出口口", html)
        self.assertIn("内网口", html)
        self.assertIn("虚拟口", html)
        self.assertIn("未插口", html)

    def test_section_lists_every_adapter(self):
        np.LAST_RUN = _last_run()
        html = np.render_report_html_customer(np.build_report())
        for name in ("以太网 2", "以太网 3", "WLAN", "ZeroTier One", "USB 以太网 5"):
            self.assertIn(name, html, msg=f"网口 {name} 未出现在对照表里")

    def test_section_shows_driver_description_column(self):
        """驱动名列要在表里 —— 靠它分辨物理口与虚拟网卡。"""
        np.LAST_RUN = _last_run()
        html = np.render_report_html_customer(np.build_report())
        self.assertIn("描述 (驱动)", html)
        self.assertIn("Realtek PCIe GbE Family Controller", html)

    def test_section_absent_when_no_linkspeed_module(self):
        """没跑 linkspeed 的子集运行不该出现空章节。

        断言结构标识 (id="portmap"), 不用章节标题文字 —— CSS 注释里也含
        "网口对照" 字样, 用文字断言会假红。"""
        np.LAST_RUN = _last_run(keys=["gateway"])
        np.LAST_RUN["results"] = {}
        html = np.render_report_html_customer(np.build_report())
        self.assertNotIn('id="portmap"', html)

    def test_report_dict_exposes_port_map(self):
        np.LAST_RUN = _last_run()
        report = np.build_report()
        self.assertIn("port_map", report)
        self.assertEqual(len(report["port_map"]), 5)

    def test_portmap_subcap_has_style(self):
        """章节里的副标题要有样式。

        全局只有 `details.collapse .subcap` 一条规则, 对照表不在折叠区里 ——
        副标题会退回默认 16px 黑体, 与整章格格不入。
        """
        np.LAST_RUN = _last_run()
        html = np.render_report_html_customer(np.build_report())
        self.assertIn(".portmap .subcap{", html)


class TestBriefV2PortSummary(unittest.TestCase):
    """一页版第 1 页要有一行网口摘要 —— 现场交付给客户的就是它。"""

    def setUp(self):
        self._saved = np.LAST_RUN

    def tearDown(self):
        np.LAST_RUN = self._saved

    def test_brief_v2_contains_port_summary(self):
        np.LAST_RUN = _last_run()
        html = np.render_report_html_brief_v2(np.build_report())
        self.assertIn("网口", html)
        self.assertIn("以太网 2", html)

    def test_brief_v2_without_linkspeed_has_no_summary(self):
        """断言结构标识 (class="portline"), 不用文字 —— CSS 注释里也含「网口」。"""
        np.LAST_RUN = _last_run(keys=["gateway"])
        np.LAST_RUN["results"] = {}
        html = np.render_report_html_brief_v2(np.build_report())
        self.assertNotIn('class="portline"', html)

    def test_unplugged_physical_port_not_claimed_normal(self):
        """一根线都没插时, 摘要不能说「各物理口速率正常」。

        未连接的口没有速率可判 (档位 n/a), 说"正常"就是交到客户手上的假绿。
        """
        adapters = [_adapter("USB 以太网 5", None, status="Down", desc="USB Ethernet")]
        np.LAST_RUN = _last_run(linkspeed=_linkspeed_res(
            egress="USB 以太网 5", adapters=adapters))
        line = _portline(np.render_report_html_brief_v2(np.build_report()))
        self.assertNotIn("速率正常", line)
        self.assertIn("无在线物理口", line)
        self.assertIn("1 口未连接", line)

    def test_summary_speed_precision_matches_table(self):
        """摘要与完整版对照表的速率精度必须一致 (不能一边 116 一边 115.6)。"""
        adapters = [_adapter("WLAN", 115.6, wifi=True, desc="Intel(R) AX201")]
        np.LAST_RUN = _last_run(linkspeed=_linkspeed_res(
            egress="WLAN", adapters=adapters))
        report = np.build_report()
        line = _portline(np.render_report_html_brief_v2(report))
        full = np.render_report_html_customer(report)
        self.assertIn("115.6 Mbps", line)
        self.assertNotIn("116 Mbps", line)
        self.assertIn("115.6 Mbps", full)

    def test_summary_counts_match_table_roles(self):
        """摘要里的口数必须与对照表的列一一对应。

        反例: 表里两行类型是「虚拟」(一行已连接一行未连接), 摘要只说「1 个虚拟
        网卡」, 而未连接那行又没被任何数字覆盖 —— 摘要与表打架。
        """
        adapters = [
            _adapter("以太网", 1000),
            _adapter("WLAN", 866, wifi=True, desc="Intel(R) AX201"),
            _adapter("ZeroTier One", 100, desc="ZeroTier One"),
            _adapter("WSL", None, status="Down", desc="WSL Adapter", virtual=True),
        ]
        np.LAST_RUN = _last_run(linkspeed=_linkspeed_res(
            egress="以太网", adapters=adapters))
        report = np.build_report()
        rows = report["port_map"]
        self.assertEqual(sum(1 for r in rows if r["kind"] == "虚拟"), 2)
        self.assertEqual(sum(1 for r in rows
                             if r["status"] not in ("Up", "已启用", "Disabled")), 1)
        line = _portline(np.render_report_html_brief_v2(report))
        self.assertIn("1 口未连接", line)
        self.assertIn("2 个虚拟网卡", line)

    def test_disconnected_egress_still_counted_as_unconnected(self):
        """默认路由指着的那块口没连上: 角色是「出口口」, 但它确实没连接 ——
        摘要的「N 口未连接」要算上它 (按状态列统计, 不按角色列)。"""
        adapters = [_adapter("USB 以太网 5", None, status="Down", desc="USB Ethernet")]
        np.LAST_RUN = _last_run(linkspeed=_linkspeed_res(
            egress="USB 以太网 5", adapters=adapters))
        line = _portline(np.render_report_html_brief_v2(np.build_report()))
        self.assertIn("1 口未连接", line)
        self.assertNotIn("速率正常", line)


class TestSoftwareBridgeWording(unittest.TestCase):
    """软件桥接网卡 (VirtualBox / Hyper-V / WSL) 在报告各处口径一致。

    第四轮独立验证 F1/F2: 类型标签改了, 但 issue 文案还在说「有线适配器 …
    建议检查网线类别」, 而这类网卡根本没有网线 —— 装维会照着去查一根不存在
    的网线。
    """

    def _detect_with(self, adapters, egress="VirtualBox Host-Only Network"):
        """用假的网卡清单跑一次真实探测器, 拿它生成的 issues。"""
        saved_ad = np.get_network_adapters
        saved_mtu = np._default_route_if_mtu
        np.get_network_adapters = lambda: adapters
        np._default_route_if_mtu = lambda: (1500, egress)
        try:
            return np.LinkSpeedDetector().detect()
        finally:
            np.get_network_adapters = saved_ad
            np._default_route_if_mtu = saved_mtu

    def _virtual_adapter(self, speed="10 Mbps"):
        return [{"name": "VirtualBox Host-Only Network",
                 "description": "VirtualBox Host-Only Ethernet Adapter",
                 "status": "Up", "link_speed": speed, "media_type": "802.3",
                 "physical_media": "", "virtual": True}]

    def test_issue_message_does_not_call_software_bridge_wired(self):
        res = self._detect_with(self._virtual_adapter())
        issues = [i for i in res.get("issues", [])
                  if "VirtualBox" in str(i.get("message", ""))]
        self.assertTrue(issues, "软件桥接网卡低速时应产生 issue")
        self.assertNotIn("有线适配器", issues[0]["message"])
        self.assertIn("虚拟网卡", issues[0]["message"])
        self.assertNotIn("检查网线", issues[0]["detail"])

    def test_issue_type_and_severity_unchanged(self):
        """只换文案 —— issue 的类型与严重度不动 (扣分口径不变)。"""
        res = self._detect_with(self._virtual_adapter())
        issues = [i for i in res.get("issues", [])
                  if "VirtualBox" in str(i.get("message", ""))]
        self.assertEqual(issues[0]["type"], "ethernet_rate_low")
        self.assertEqual(issues[0]["severity"], "warning")

    def test_issue_action_not_tell_to_check_physical_link(self):
        out = np._issues_linkspeed({"issues": [{
            "type": "ethernet_rate_low", "severity": "warning", "virtual": True,
            "message": "虚拟网卡 X 协商速率仅 10.0 Mbps",
            "detail": "虚拟网卡的协商速率不代表物理链路"}]})
        self.assertNotIn("检查物理连接", out[0]["action"])
        self.assertIn("虚拟网卡", out[0]["action"])

    def test_wired_issue_wording_untouched(self):
        """物理有线口的 issue 文案必须逐字不变 (零回归)。"""
        out = np._issues_linkspeed({"issues": [{
            "type": "ethernet_rate_low", "severity": "warning",
            "message": "有线适配器 以太网 协商速率仅 10.0 Mbps",
            "detail": "有线协商到非千兆可能是网线/端口/驱动降速, 建议检查网线类别 (千兆需 Cat5e+) 与端口"}]})
        self.assertEqual(out[0]["text"], "有线适配器 以太网 协商速率仅 10.0 Mbps")
        self.assertEqual(out[0]["action"], "检查物理连接或网卡驱动")

    def test_software_bridge_err_hint_states_reason(self):
        """F2: 红/黄档的提示要给出理由, 不能只剩一句「不代表物理链路」。"""
        a = _adapter("VirtualBox Host-Only Network", 10,
                     desc="VirtualBox Host-Only Ethernet Adapter", virtual=True)
        _kind, _speed, level, hint, _virt = np._linkspeed_tier(a)
        self.assertEqual(level, "err")
        self.assertIn("档位过低", hint)
        self.assertIn("不代表物理链路", hint)


class TestBriefV2EgressWording(unittest.TestCase):
    """摘要里的出口口写法 (第四轮独立验证 F3/F4)。"""

    def setUp(self):
        self._saved = np.LAST_RUN

    def tearDown(self):
        np.LAST_RUN = self._saved

    def test_virtual_egress_omits_tunnel_rate(self):
        """F3: 出口口是虚拟网卡时不报隧道速率 —— 免得被当成物理带宽。"""
        adapters = [_adapter("ZeroTier One", 10000, desc="ZeroTier One")]
        np.LAST_RUN = _last_run(linkspeed=_linkspeed_res(
            egress="ZeroTier One", adapters=adapters))
        line = _portline(np.render_report_html_brief_v2(np.build_report()))
        self.assertIn("出口口 ZeroTier One", line)
        self.assertNotIn("10000 Mbps", line)

    def test_disconnected_egress_is_marked(self):
        """F4: 出口口本身没连上时摘要要标「未连接」, 别让它读成正常。"""
        adapters = [_adapter("以太网 2", 1000, status="Down")]
        np.LAST_RUN = _last_run(linkspeed=_linkspeed_res(
            egress="以太网 2", adapters=adapters))
        line = _portline(np.render_report_html_brief_v2(np.build_report()))
        self.assertIn("出口口 以太网 2 (未连接)", line)


class TestJsonPortMap(unittest.TestCase):
    """JSON 顶层要有 port_map, 且 schema 必须同步声明 (防再次漂移)。"""

    def setUp(self):
        self._saved = np.LAST_RUN

    def tearDown(self):
        np.LAST_RUN = self._saved

    def test_json_export_has_port_map(self):
        np.LAST_RUN = _last_run()
        import json as _json
        data = _json.loads(np.render_report_json(np.build_report()))
        self.assertIn("port_map", data)
        self.assertEqual(len(data["port_map"]), 5)
        self.assertIn("role", data["port_map"][0])

    def test_schema_declares_port_map(self):
        import json as _json
        import io
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with io.open(os.path.join(root, "schema", "netpulse-result-v1.2.json"),
                     encoding="utf-8") as f:
            schema = _json.load(f)
        self.assertIn("port_map", schema.get("properties", {}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
