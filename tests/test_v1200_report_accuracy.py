# -*- coding: utf-8 -*-
"""v1.20.0 报告判级纠偏 + 扣分明细 · 场景级回归测试。

背景 (2026-11-12 实机全量诊断反馈, docs/spec.md):
  1. MTU 误报: 报告写「到 223.5.5.5 的路径 MTU (1499) 小于标准 1500, 可能
     导致分片」, 实测 `ping -f -l 1472` 5/5 通、`-l 1473` 3/3 需拆分 → 路径
     MTU 就是 1500。根因: 二分探测把「ICMP 没回包」当「包太大」, 丢一个包
     就把收敛值压低几字节, 而结果里记着的「不确定 10%」判定时压根没用。
  2. IPv6 误判: 唯一全局地址挂在 ZeroTier 虚拟接口上, 工具判成「IPv6 配置
     异常」并建议「联系运营商开通」—— 本机根本没运营商原生 IPv6。
  3. DNS 假警告: 指标把 6 台服务器 (含 5 台用户不用的对比机) 混算成
     「平均 157ms 较慢」, 建议固定写「换阿里/腾讯/114」—— 用户本来就在
     阿里 DNS 上且实测 5.5ms (全场最快)。
  4. 总分 92 但没有明细, 不知道扣在哪。
  5. 「✓ 无故障 / 整体高置信度 / 评估 8 条规则」是无依据断言。
  6. LAN 因「OUI 在线补查」这条**隐私披露串**被判警告, 白扣 2 分且卡片
     里查无此因。

跑用: cd 到项目根目录, `py -m pytest tests/test_v1200_report_accuracy.py -q`
"""
import os
import re
import sys
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


# ─────────────────────────────── fixtures ───────────────────────────────

def _mk_last_run(status=None, results=None, keys=None):
    """构造一份 LAST_RUN (结构同 run_diagnostics 装配结果)。"""
    status = status or {}
    results = results if results is not None else {}
    keys = keys if keys is not None else list(status.keys())
    return {
        "app": "NetPulse", "version": N.APP_VERSION,
        "generated_at": datetime(2026, 11, 12, 15, 17, 6),
        "system": {"local_ip": "172.25.131.131", "gateway": "172.25.131.254",
                   "dns": "223.5.5.5", "public_ip": "61.153.2.254", "asn": "",
                   "geo": "", "ipv6_public_ip": ""},
        "status": dict(status),
        "results": dict(results),
        "evidence": {},
        "keys": list(keys),
        "duration_ms": 151000,
        "total_modules": len(N.MODULE_MAP),
    }


def _build(status, results, keys=None):
    old = N.LAST_RUN
    N.LAST_RUN = _mk_last_run(status, results, keys)
    try:
        return N.build_report()
    finally:
        N.LAST_RUN = old


def _fake_ping(max_payload=1472, drop_first_1472=False):
    """伪造 ping: 载荷 > max_payload 报「需要拆分」, 否则回包。

    drop_first_1472=True → 第一次 1472 字节的探测丢包 (复现实测那次
    「二分最后一个包丢了 → 收敛成 1499」)。
    """
    state = {"dropped": False}

    def _run(cmd, timeout=None, **kw):
        m = re.search(r"-l (\d+)", cmd)
        size = int(m.group(1)) if m else 0
        if size > max_payload:
            return 1, "需要拆分数据包但是设置 DF。", ""
        if size == 1472 and drop_first_1472 and not state["dropped"]:
            state["dropped"] = True
            return 1, "请求超时。", ""
        return 0, f"Reply from 223.5.5.5: bytes={size} time=3ms TTL=52", ""
    return _run


MTU_OK_RESULT = {
    "target": "223.5.5.5", "max_payload": 1472, "path_mtu": 1500,
    "fragmentation_risk": False, "indeterminate_pct": 0.0, "probes": 10,
    "mtu_confirmed": True, "confirm_result": "3/3 通过",
}

MTU_PPPOE_RESULT = {
    "target": "223.5.5.5", "max_payload": 1464, "path_mtu": 1492,
    "fragmentation_risk": True, "indeterminate_pct": 0.0, "probes": 10,
    "mtu_confirmed": False, "confirm_result": "0/3 通过",
}

DNS_CURRENT_FAST = {
    "system_dns": ["223.5.5.5"],
    "assessment": "正常",
    "dns_hijack": False,
    "success_count": 21, "total_count": 24,
    "avg_time_ms": 157.1,
    "current_success_count": 4, "current_total_count": 4,
    "current_avg_ms": 5.8,
    "fastest_server": {"dns_server": "223.5.5.5", "dns_name": "AliDNS",
                       "ok": 4, "total": 4, "avg_ms": 5.8, "status": "正常"},
    "failed_items": [{"dns_server": "1.2.4.8", "dns_name": "CNNIC SDNS",
                      "domain": "www.jd.com", "time_ms": 2500.0}],
    "per_server": [
        {"dns_server": "223.5.5.5", "dns_name": "AliDNS", "ok": 4, "total": 4,
         "avg_ms": 5.8, "status": "正常"},
        {"dns_server": "1.2.4.8", "dns_name": "CNNIC SDNS", "ok": 1, "total": 4,
         "avg_ms": 300.0, "status": "部分失败"},
    ],
    "issues": [],
}

DNS_CURRENT_SLOW = {
    "system_dns": ["223.5.5.5"],
    "assessment": "DNS 响应慢",
    "dns_hijack": False,
    "success_count": 24, "total_count": 24,
    "avg_time_ms": 160.0,
    "current_success_count": 4, "current_total_count": 4,
    "current_avg_ms": 300.0,
    "fastest_server": {"dns_server": "119.29.29.29", "dns_name": "DNSPod",
                       "ok": 4, "total": 4, "avg_ms": 11.0, "status": "正常"},
    "failed_items": [],
    "per_server": [
        {"dns_server": "223.5.5.5", "dns_name": "AliDNS", "ok": 4, "total": 4,
         "avg_ms": 300.0, "status": "正常"},
        {"dns_server": "119.29.29.29", "dns_name": "DNSPod", "ok": 4, "total": 4,
         "avg_ms": 11.0, "status": "正常"},
    ],
    "issues": [],
}

IPV6_VIRTUAL = {
    "local_ipv6": ["2a01:7a7:2:3d47::9a08:415a"],
    "has_global_ipv6": True, "has_link_local": True, "has_ipv6_route": False,
    "ipv6_connectivity": False, "ipv6_dns": False,
    "ipv6_target": "2400:3200::1",
    "ipv6_source": "virtual", "ipv6_native": False,
    "native_ifaces": [], "virtual_ifaces": ["ZeroTier One [9f77fc393e225015]"],
    "issues": [{
        "severity": "info",
        "message": "全局 IPv6 地址来自虚拟接口 (ZeroTier One [9f77fc393e225015]), "
                   "本机没有运营商下发的原生 IPv6",
        "detail": "隧道/虚拟网卡会自行分配全球单播地址, 但本机没有 IPv6 默认路由",
        "action": "如需 IPv6 请联系运营商开通并确认路由器下发前缀; 仅使用 VPN/隧道时可忽略本项",
    }],
    "assessment": "IPv6 来自虚拟接口（本机无原生 IPv6）",
}

LAN_WITH_DISCLOSURE = {
    "local_ip": "172.25.131.131", "gateway": "172.25.131.254",
    "subnet": "172.25.131.0/24",
    "devices": [{"ip": "172.25.131.254", "mac": "a4-17-8b-3a-12-74",
                 "vendor": "HUAWEI", "is_gateway": "是"}],
    "device_count": 1,
    "issues": [],
    "disclosures": ["5 个未知厂商前缀经 mac.bmcx.com 在线补查 "
                    "(只发该设备的 MAC 地址); 设 NP_NO_ONLINE_OUI=1 可关闭"],
    "assessment": "发现 1 台设备",
    "summary": "LAN 扫描: 发现 1 台设备",
}


# ─────────────────────── S1/S2 · MTU 误报与修复命令 ───────────────────────

class TestMtuProbeConfirmation(unittest.TestCase):
    """S1: 二分丢一个包不得把路径 MTU 判成 1499。"""

    def test_lost_probe_does_not_produce_false_1499(self):
        """复现实测: 1472 字节的包丢一次 → 旧实现报 1499 并报警。"""
        with mock.patch.object(N, "run_cmd", side_effect=_fake_ping(1472, True)):
            res = N._probe_path_mtu("223.5.5.5")
        self.assertEqual(res["path_mtu"], 1500)
        self.assertFalse(res["fragmentation_risk"])
        self.assertTrue(res["mtu_confirmed"])
        self.assertEqual(res["confirm_result"], "3/3 通过")

    def test_clean_probe_reports_standard_mtu(self):
        with mock.patch.object(N, "run_cmd", side_effect=_fake_ping(1472)):
            res = N._probe_path_mtu("223.5.5.5")
        self.assertEqual(res["path_mtu"], 1500)
        self.assertFalse(res["fragmentation_risk"])

    def test_real_pppoe_mtu_is_not_overwritten(self):
        """真实 PPPoE (1492) 不能被确认探测"洗"成 1500。"""
        with mock.patch.object(N, "run_cmd", side_effect=_fake_ping(1464)):
            res = N._probe_path_mtu("223.5.5.5")
        self.assertEqual(res["path_mtu"], 1492)
        self.assertTrue(res["fragmentation_risk"])
        self.assertFalse(res["mtu_confirmed"])


class TestMtuDetectorThreshold(unittest.TestCase):
    """S1/S2: 判定门槛与可执行命令。"""

    def _detect(self, path_result, iface_mtu=1500, iface="以太网"):
        """按目标区分探测结果: 网关 1500, 223.5.5.5 用给定值。"""
        def _probe(target):
            if target == "223.5.5.5":
                return dict(path_result)
            return dict(MTU_OK_RESULT, target=target)

        with mock.patch.object(N, "get_default_gateway", return_value="192.168.1.1"), \
             mock.patch.object(N, "_probe_path_mtu", side_effect=_probe), \
             mock.patch.object(N, "run_ps", return_value=(
                 0, f'[{{"InterfaceAlias":"{iface}","NlMtu":{iface_mtu}}}]', "")), \
             mock.patch.object(N, "_default_route_if_mtu",
                               return_value=(iface_mtu, iface)):
            return N.MTUDetector().detect()

    def test_no_issue_when_path_mtu_is_1500(self):
        res = self._detect(MTU_OK_RESULT)
        self.assertEqual(res["issues"], [])
        self.assertEqual(res["summary"], "MTU 检测: 正常")

    def test_real_mismatch_reports_with_verify_and_fix_commands(self):
        res = self._detect(MTU_PPPOE_RESULT)
        warns = [i for i in res["issues"]
                 if isinstance(i, dict) and i.get("severity") == "warning"]
        self.assertEqual(len(warns), 1)
        issue = warns[0]
        self.assertIn("1492", issue["message"])
        action = issue["action"]
        self.assertIn("ping -f -l 1472 -n 5 223.5.5.5", action)
        self.assertIn("netsh interface ipv4 set subinterface", action)
        self.assertIn("mtu=1492", action)
        self.assertIn("netsh interface ipv4 show subinterfaces", action)

    def test_path_mtu_not_below_interface_is_not_a_fault(self):
        """接口本身就是 1492 且路径也是 1492 → 一致, 不是故障。"""
        res = self._detect(MTU_PPPOE_RESULT, iface_mtu=1492)
        warns = [i for i in res["issues"]
                 if isinstance(i, dict) and i.get("severity") == "warning"]
        self.assertEqual(warns, [])

    def test_interface_below_standard_is_info_not_warning(self):
        """本机接口 MTU < 1500 (PPPoE 常见) 本身不是故障 → 信息级。"""
        res = self._detect(MTU_OK_RESULT, iface_mtu=1492)
        info = [i for i in res["issues"] if isinstance(i, dict)
                and i.get("severity") == "info"]
        self.assertTrue(any("MTU (1492)" in i["message"] for i in info))
        warns = [i for i in res["issues"]
                 if isinstance(i, dict) and i.get("severity") == "warning"]
        self.assertEqual(warns, [])

    def test_report_layer_uses_structured_issue_commands(self):
        issues = N._issues_mtu({"issues": [
            {"severity": "warning", "message": "到 x 的路径 MTU (1492) 小于标准 1500",
             "detail": "d", "target": "223.5.5.5", "path_mtu": 1492,
             "iface": "以太网"}]})
        self.assertEqual(len(issues), 1)
        self.assertIn("ping -f -l 1472 -n 5 223.5.5.5", issues[0]["action"])
        self.assertIn('subinterface "以太网" mtu=1492', issues[0]["action"])


# ─────────────────────── S3/S4 · IPv6 虚拟接口与顶栏出口 ───────────────────────

class TestIpv6VirtualInterface(unittest.TestCase):
    """S3/S4: 虚拟接口来源 → 提示级, 不进待办, 顶栏标出口。"""

    def test_virtual_iface_recognised(self):
        for name in ("ZeroTier One [9f77fc393e225015]", "Wintun", "vEthernet (WSL)",
                     "Tailscale", "Clash"):
            self.assertTrue(N._is_virtual_iface(name), name)
        for name in ("以太网", "Realtek PCIe GbE Family Controller", "WLAN"):
            self.assertFalse(N._is_virtual_iface(name), name)

    def test_virtual_only_is_info_not_critical(self):
        issues = N._issues_ipv6(IPV6_VIRTUAL)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["severity"], "信息")
        self.assertIn("虚拟接口", issues[0]["text"])

    def test_badge_shows_hint_not_done(self):
        rep = _build({"ipv6": "完成"}, {"ipv6": IPV6_VIRTUAL}, ["ipv6"])
        mod = [m for m in rep["modules"] if m["key"] == "ipv6"][0]
        self.assertEqual(mod.get("badge_text"), "提示")
        html = N.render_report_html_customer(rep)
        self.assertIn("提示", html)
        self.assertNotIn("IPv6 配置异常", html)

    def test_not_in_todo_list(self):
        rep = _build({"ipv6": "完成"}, {"ipv6": IPV6_VIRTUAL}, ["ipv6"])
        todo = N._todo_issues_section(rep["modules"])
        self.assertNotIn("虚拟接口", todo.split("<div class=\"todo\">")[0]
                         .split("需要您关注")[0] if "<div class=\"todo\">" in todo else "")

    def test_header_chip_marks_egress_not_native(self):
        rep = _build({"ipv6": "完成"}, {"ipv6": IPV6_VIRTUAL}, ["ipv6"])
        rep["system"]["ipv6_public_ip"] = "2a01:7e03::2000:83ff:fe3c:3cca"
        html = N.render_report_html_customer(rep)
        self.assertIn("IPv6 出口", html)
        self.assertIn("非本机原生 IPv6", html)

    def test_native_ipv6_keeps_plain_label(self):
        native = dict(IPV6_VIRTUAL)
        native["ipv6_source"] = "native"
        native["ipv6_native"] = True
        native["native_ifaces"] = ["以太网"]
        rep = _build({"ipv6": "完成"}, {"ipv6": native}, ["ipv6"])
        rep["system"]["ipv6_public_ip"] = "240e:1234::1"
        html = N.render_report_html_customer(rep)
        self.assertIn("IPv6 <b>240e:1234::1</b>", html)
        self.assertNotIn("IPv6 出口", html)


# ───────────────────────── S5/S6 · DNS 口径 ─────────────────────────

class TestDnsCurrentScope(unittest.TestCase):
    """S5/S6: 指标与判定按当前 DNS, 建议动态化。"""

    def test_metric_uses_current_dns_average(self):
        metrics = N._metrics_dns(DNS_CURRENT_FAST)
        labels = [m[0] for m in metrics]
        self.assertIn("当前 DNS 平均", labels)
        vals = dict((m[0], m[1]) for m in metrics)
        self.assertEqual(vals["当前 DNS 平均"], "5.8 ms")
        self.assertNotIn("157.1 ms", [m[1] for m in metrics])

    def test_no_slow_warning_when_current_dns_is_fastest(self):
        issues = N._issues_dns(DNS_CURRENT_FAST)
        sev = [i["severity"] for i in issues]
        self.assertNotIn("警告", sev)
        self.assertNotIn("异常", sev)
        text = " ".join(i["text"] for i in issues)
        self.assertIn("无需更换", text)

    def test_fixed_suggestion_text_removed(self):
        for res in (DNS_CURRENT_FAST, DNS_CURRENT_SLOW):
            blob = " ".join(i["action"] for i in N._issues_dns(res))
            self.assertNotIn("阿里/腾讯/114", blob)

    def test_slow_current_dns_names_fastest_server(self):
        issues = N._issues_dns(DNS_CURRENT_SLOW)
        warn = [i for i in issues if i["severity"] == "警告"]
        self.assertEqual(len(warn), 1)
        self.assertIn("119.29.29.29", warn[0]["action"])
        self.assertIn("netsh interface ipv4 set dnsservers", warn[0]["action"])

    def test_failed_comparison_queries_reported_separately(self):
        issues = N._issues_dns(DNS_CURRENT_FAST)
        text = " ".join(i["text"] for i in issues)
        self.assertIn("失败", text)

    def test_slow_server_inside_current_dns_is_named(self):
        """当前 DNS 里混了一台慢的 (实测: 223.5.5.5 + 8.8.8.8, 后者被限速)
        → 明确点名那台, 而不是笼统说"平均慢"。"""
        res = {
            "system_dns": ["223.5.5.5", "8.8.8.8"],
            "dns_hijack": False,
            "success_count": 22, "total_count": 24, "avg_time_ms": 76.4,
            "current_success_count": 7, "current_total_count": 8,
            "current_avg_ms": 76.4,
            "fastest_server": {"dns_server": "223.5.5.5", "dns_name": "AliDNS",
                               "ok": 4, "total": 4, "avg_ms": 6.0,
                               "status": "正常"},
            "current_best_server": {"dns_server": "223.5.5.5",
                                    "dns_name": "AliDNS", "ok": 4, "total": 4,
                                    "avg_ms": 6.0, "status": "正常"},
            "current_slow_servers": [{"dns_server": "8.8.8.8",
                                      "dns_name": "系统DNS", "ok": 3,
                                      "total": 4, "avg_ms": 146.8,
                                      "status": "部分失败"}],
            "failed_items": [],
            "dns_interfaces": {"223.5.5.5": "以太网", "8.8.8.8": "以太网"},
            "per_server": [
                {"dns_server": "223.5.5.5", "dns_name": "AliDNS", "ok": 4,
                 "total": 4, "avg_ms": 6.0, "status": "正常"},
                {"dns_server": "8.8.8.8", "dns_name": "系统DNS", "ok": 3,
                 "total": 4, "avg_ms": 146.8, "status": "部分失败"},
            ],
            "issues": [],
        }
        issues = N._issues_dns(res)
        warn = [i for i in issues if i["severity"] == "警告"]
        self.assertEqual(len(warn), 1)
        self.assertIn("8.8.8.8", warn[0]["text"])
        self.assertIn("223.5.5.5", warn[0]["text"])
        self.assertIn("netsh interface ipv4 set dnsservers", warn[0]["action"])
        self.assertIn("以太网", warn[0]["action"])

    def test_slow_current_dns_makes_badge_match_card(self):
        """徽章必须与卡片一致: 卡片有警告 → 模块状态不能还是「完成」。"""
        raw = {
            "system_dns": ["223.5.5.5", "8.8.8.8"],
            "assessment": "DNS 响应慢",
            "issues": [],
        }
        self.assertEqual(N.determine_status(raw), "警告")


class TestCommandInterpolationWhitelist(unittest.TestCase):
    """建议命令里插值的接口名与**地址**都必须过白名单 (项目铁律)。

    这条命令是给用户复制后提权执行的, 而系统 DNS 列表来自
    Get-DnsClientServerAddress (本地注册表字符串), 不能直接内插。
    """

    def _res(self, best_ip="223.5.5.5", iface="以太网"):
        return {
            "system_dns": [best_ip, "8.8.8.8"],
            "dns_hijack": False,
            "success_count": 22, "total_count": 24, "avg_time_ms": 76.4,
            "current_success_count": 7, "current_total_count": 8,
            "current_avg_ms": 76.4,
            "fastest_server": {"dns_server": best_ip, "dns_name": "AliDNS",
                               "ok": 4, "total": 4, "avg_ms": 6.0,
                               "status": "正常"},
            "current_best_server": {"dns_server": best_ip,
                                    "dns_name": "AliDNS", "ok": 4, "total": 4,
                                    "avg_ms": 6.0, "status": "正常"},
            "current_slow_servers": [{"dns_server": "8.8.8.8",
                                      "dns_name": "系统DNS", "ok": 3,
                                      "total": 4, "avg_ms": 146.8,
                                      "status": "部分失败"}],
            "failed_items": [],
            "dns_interfaces": {best_ip: iface},
            "per_server": [],
            "issues": [],
        }

    def _netsh_action(self, res):
        acts = [i.get("action", "") for i in N._issues_dns(res)
                if "set dnsservers" in i.get("action", "")]
        self.assertEqual(len(acts), 1, f"期望恰好一条 netsh 建议, 实际 {acts}")
        return acts[0]

    def test_valid_ip_and_iface_pass_through(self):
        action = self._netsh_action(self._res())
        self.assertIn('name="以太网"', action)
        self.assertIn("address=223.5.5.5", action)

    def test_invalid_ip_becomes_placeholder(self):
        """地址非法 → 退化成占位符, 绝不带脏字符进命令。"""
        action = self._netsh_action(self._res(best_ip='"><script>alert(1)</script>'))
        cmd = action[action.find("netsh"):]
        self.assertNotIn("<script>", cmd)
        self.assertIn("address=<DNS服务器地址>", cmd)

    def test_invalid_iface_becomes_placeholder(self):
        """接口名非法 → 退化成占位符。"""
        action = self._netsh_action(self._res(iface='"><script>alert(1)</script>'))
        cmd = action[action.find("netsh"):]
        self.assertNotIn("<script>", cmd)
        self.assertIn('name="<接口名>"', cmd)

    def test_safe_ip_literal_helper(self):
        self.assertEqual(N._safe_ip_literal("223.5.5.5"), "223.5.5.5")
        self.assertEqual(N._safe_ip_literal("2400:3200::1"), "2400:3200::1")
        self.assertIsNone(N._safe_ip_literal("223.5.5.5 & calc"))
        self.assertIsNone(N._safe_ip_literal(""))
        self.assertIsNone(N._safe_ip_literal(None))


# ─────────────────────── S7 · 扣分明细可见 ───────────────────────

class TestScoreBreakdown(unittest.TestCase):
    """S7: 模块标题栏扣分标记 + hero 算式行。"""

    def _report(self):
        status = {"lan": "警告", "dns": "警告", "tcpstats": "警告",
                  "mtu": "警告", "gateway": "完成", "proxy": "警告"}
        results = {
            "lan": LAN_WITH_DISCLOSURE,
            "dns": DNS_CURRENT_FAST,
            "tcpstats": {"retrans_rate_pct": 2.67, "issues": []},
            "mtu": {"path_mtus": [MTU_OK_RESULT], "local_mtus": [], "issues": []},
            "gateway": {"ping": {"avg_ms": 1.0}},
            "proxy": {"issues": []},
        }
        return _build(status, results, list(status))

    def test_formula_lists_deductions(self):
        rep = self._report()
        formula = N._score_formula(rep)
        self.assertIn("警告 4×2", formula)
        # 4 个计分警告 (lan/dns/tcpstats/mtu) × 2 = 8 → 92; proxy 是豁免模块不扣
        self.assertIn("92 / 100", formula)

    def test_formula_uses_single_penalty_source(self):
        self.assertEqual(N.SCORE_PENALTY["警告"], 2)
        self.assertEqual(N.SCORE_PENALTY["异常"], 20)
        self.assertEqual(N.SCORE_PENALTY["错误"], 30)
        self.assertEqual(N.SCORE_PENALTY["超时"], 10)

    def test_formula_reads_counts_not_summary(self):
        """算式必须与分数同源 (report["counts"]), 不从 summary 重拆豁免。

        summary 按 keys 生成; 若手工构造 status 有键、keys 没列 (或反之),
        从 summary 重拆会漏项 → 算式与分数对不上。counts 与 score 同源,
        永远一致。
        """
        rep = self._report()
        # counts 是扣分口径: 4 个警告 (lan/dns/tcpstats/mtu), proxy 豁免不在内
        self.assertEqual(rep["counts"].get("警告"), 4)
        self.assertNotIn("proxy", rep["counts"])
        formula = N._score_formula(rep)
        self.assertIn("警告 4×2", formula)
        self.assertIn(f'{rep["health"]["score"]} / 100', formula)

    def test_formula_consistent_when_keys_diverge_from_status(self):
        """keys 与 status 键集合不一致的构造下, 算式仍与分数一致。"""
        status = {"lan": "警告", "dns": "警告", "mtu": "警告", "proxy": "警告"}
        results = {
            "lan": LAN_WITH_DISCLOSURE, "dns": DNS_CURRENT_FAST,
            "mtu": {"path_mtus": [], "local_mtus": [], "issues": []},
            "proxy": {"issues": []},
        }
        rep = _build(status, results, ["lan", "dns", "mtu"])  # keys 故意少了 proxy
        # score 按 status 全集算: proxy 豁免不扣分 → 扣分 lan/dns/mtu 2×2=4 → 96?
        # 不 —— 3 个计分警告 ×2 = 6 → 94 (proxy 不扣, 但也不改变其他模块的扣分)
        self.assertEqual(rep["health"]["score"], 94)
        formula = N._score_formula(rep)
        self.assertIn("警告 3×2", formula)
        self.assertIn("94 / 100", formula)

    def test_module_header_shows_deduct_tag(self):
        rep = self._report()
        html = N.render_report_html_customer(rep)
        self.assertIn("−2 分", html)
        self.assertIn("豁免", html)
        self.assertIn("class='dt deduct", html)

    def test_todo_list_has_no_score_marks(self):
        rep = self._report()
        todo = N._todo_issues_section(rep["modules"])
        self.assertNotIn("−2 分", todo)

    def test_no_deduct_tag_for_completed_module(self):
        rep = _build({"gateway": "完成"}, {"gateway": {"ping": {"avg_ms": 1.0}}},
                     ["gateway"])
        html = N.render_report_html_customer(rep)
        self.assertNotIn("−0 分", html)
        self.assertNotIn("−2 分", html)


# ───────────────────────── S8 · 诊断条不断言 ─────────────────────────

class TestDiagnosisNoAssertion(unittest.TestCase):
    """S8: 无根因时不说「无故障 / 高置信度 / 评估 N 条规则」。"""

    def _section(self):
        # dns 用「当前 DNS 慢」的口径 → 产出 1 条警告级问题
        rep = _build({"gateway": "完成", "dns": "警告"},
                     {"gateway": {"ping": {"avg_ms": 1.0}},
                      "dns": DNS_CURRENT_SLOW},
                     ["gateway", "dns"])
        return N._render_diagnosis_section_html(rep["diagnosis"], report=rep)

    def test_no_no_fault_claim(self):
        sec = self._section()
        self.assertNotIn("无故障", sec)
        self.assertNotIn("高置信度", sec)
        self.assertNotIn("条规则", sec)
        self.assertIn("未匹配到根因", sec)

    def test_points_to_issue_count(self):
        sec = self._section()
        self.assertIn("1 项问题已列在下方", sec)


# ───────────────────────── S9 · LAN 披露不算问题 ─────────────────────────

class TestLanDisclosure(unittest.TestCase):
    """S9: OUI 隐私披露不再当问题, 但披露内容不能丢。"""

    def test_disclosure_not_in_issues(self):
        res = dict(LAN_WITH_DISCLOSURE)
        self.assertEqual(N.determine_status(res), "完成")

    def test_disclosure_still_visible_in_report(self):
        rep = _build({"lan": "完成"}, {"lan": LAN_WITH_DISCLOSURE}, ["lan"])
        html = N.render_report_html_customer(rep)
        self.assertIn("mac.bmcx.com", html)

    def test_disclosure_is_info_level_issue(self):
        issues = N._issues_lan(LAN_WITH_DISCLOSURE)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["severity"], "信息")


if __name__ == "__main__":
    unittest.main(verbosity=2)
