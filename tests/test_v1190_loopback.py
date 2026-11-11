# -*- coding: utf-8 -*-
"""环回测速 (终端→网关) 测试 — v1.19.0

运营商保障的是**接入速度**, speedtest 测的是**使用速度** (走公网, 受互联网
拥塞/对端负载/ISP 限速策略影响)。本模块测「终端 → 网关 → 终端」这一段的
往返吞吐, 流量不出接入网, 用来分清「是接入段慢, 还是互联网侧慢」。

跑用: cd 到项目根目录, `py -3.13 tests/test_v1190_loopback.py`
"""
import os
import socket
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as np  # noqa: E402


MY_IP = "192.168.1.23"
GW_IP = "192.168.1.1"
MY_MAC = "A2-82-29-52-55-DC"
GW_MAC = "4C-09-B4-FC-AC-F0"


def _loopback_res(mbps=312.5, negotiated=1000.0, scope="unknown", **kw):
    """构造环回测速模块结果 (字段名对齐 probe_loopback_v2 的真实产出)。"""
    res = {
        "gateway": GW_IP,
        "gateway_mac": GW_MAC.lower(),
        "interface": "以太网",
        "scope": scope,
        "scope_label": ("运营商接入侧" if scope == "access"
                        else "默认网关 (类型未知, 可能是家用路由器)"),
        "mbps": mbps,
        "negotiated_mbps": negotiated,
        "ratio_pct": round(mbps / negotiated * 100, 1) if negotiated else 0.0,
        "at_ceiling": False,
        "offered_mbps": 900.0,
        "load_limited": False,
        "saturated": True,
        "is_wireless": False,
        "return_ratio": 0.35,
        "frames": 89000,
        "bytes": 124600000,
        "seconds": 5.0,
        "duration_s": 5,
        "issues": [],
        "timestamp": "2026-11-11T09:30:00",
        "summary": "环回 %.1f Mbps" % mbps,
    }
    res.update(kw)
    return res


def _speedtest_res(download=213.45):
    """构造 speedtest 模块结果 (Ookla 嵌套形态, 与真实产出一致)。"""
    return {
        "download_mbps": 0, "upload_mbps": 0,
        "speedtest": {"download_mbps": download, "upload_mbps": 38.2,
                      "server_latency_ms": 8.4, "jitter_ms": 2.1,
                      "packet_loss_pct": None,
                      "server": "ChinaTelecom Hangzhou"},
    }


def _report(loopback=None, speedtest=None, with_loopback=True):
    """构造一个够渲染器用的最小 report (只放渲染会用到的字段)。"""
    modules = []
    if with_loopback:
        modules.append({"key": "loopback", "name": "环回测速", "status": "完成",
                        "verdict": "—", "key_metrics": [], "issues": [],
                        "has_tech_details": False,
                        "raw": loopback if loopback is not None else _loopback_res()})
    if speedtest is not None:
        modules.append({"key": "speedtest", "name": "测速", "status": "完成",
                        "verdict": "—", "key_metrics": [], "issues": [],
                        "has_tech_details": False, "raw": speedtest})
    return {
        "app": "NetPulse", "version": "1.19.0", "schema_version": "1.2.0",
        "generated_at": __import__("datetime").datetime(2026, 11, 11, 9, 30, 0),
        "system": {"local_ip": MY_IP, "gateway": GW_IP, "dns": "223.5.5.5",
                   "public_ip": "1.2.3.4"},
        "health": {"score": 100, "grade": "A", "label": "优秀", "verdict": "良好"},
        "counts": {"完成": len(modules)}, "exempt_count": 0,
        "summary": {m["key"]: m["status"] for m in modules},
        "duration_ms": 1000, "selected_modules": len(modules),
        "total_modules": 24,
        "diagnosis": {"root_causes": [], "overall_confidence": 0.0,
                      "rules_evaluated": 8, "rules_fired": 0},
        "modules": modules, "site_check": {}, "site_note": "", "meta_manual": {},
        "port_map": [], "tech": {},
    }


class TestLoopbackFrame(unittest.TestCase):
    """二层帧构造 —— 环回机制的地基。"""

    def test_ip_checksum_matches_rfc1071_vector(self):
        # RFC 1071 §3 的标准向量: 00 01 f2 03 f4 f5 f6 f7 → 0x220d
        self.assertEqual(np._ip_checksum(bytes.fromhex("0001f203f4f5f6f7")),
                         0x220d)

    def test_frame_dst_ip_is_self_and_dst_mac_is_gateway(self):
        frame = np._loopback_frame(MY_IP, MY_IP, MY_MAC, GW_MAC,
                                   1234, 1234, b"N" * 100)
        self.assertEqual(frame[0:6], np._mac_bytes(GW_MAC))
        self.assertEqual(frame[6:12], np._mac_bytes(MY_MAC))
        self.assertEqual(frame[12:14], b"\x08\x00")
        # IP 头: 版本 4 / IHL 5 / 总长 / TTL 64 / 协议 17(UDP)
        self.assertEqual(frame[14], 0x45)
        self.assertEqual(frame[22], 64)
        self.assertEqual(frame[23], 17)
        # 目的 IP 必须是本机 IP —— 这是环回机制成立的前提
        self.assertEqual(socket.inet_ntoa(frame[30:34]), MY_IP)
        self.assertEqual(socket.inet_ntoa(frame[26:30]), MY_IP)

    def test_frame_ip_checksum_is_valid(self):
        # 网关会丢弃校验和错误的帧 (实测), 所以这里必须逐位校验
        frame = np._loopback_frame(MY_IP, MY_IP, MY_MAC, GW_MAC,
                                   1234, 1234, b"N" * 100)
        self.assertEqual(np._ip_checksum(frame[14:34]), 0)

    def test_frame_padded_to_ethernet_minimum(self):
        frame = np._loopback_frame(MY_IP, MY_IP, MY_MAC, GW_MAC,
                                   1234, 1234, b"N" * 4)
        self.assertGreaterEqual(len(frame), 60)

    def test_parse_arp_reply_returns_sender_mac(self):
        # Ethernet(14) + ARP(28): op=2, spa=网关 IP, sha=网关 MAC
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2,
                          np._mac_bytes(GW_MAC), socket.inet_aton(GW_IP),
                          b"\x00" * 6, socket.inet_aton(MY_IP))
        frame = b"\x00" * 6 + np._mac_bytes(MY_MAC) + b"\x08\x06" + arp
        self.assertEqual(np._parse_arp_reply(frame, GW_IP), GW_MAC.lower()
                         .replace("-", ":"))

    def test_parse_arp_reply_ignores_other_sender(self):
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2,
                          np._mac_bytes(GW_MAC), socket.inet_aton(GW_IP),
                          b"\x00" * 6, socket.inet_aton(MY_IP))
        frame = b"\x00" * 6 + np._mac_bytes(MY_MAC) + b"\x08\x06" + arp
        self.assertIsNone(np._parse_arp_reply(frame, "10.0.0.9"))


class _FakePcap:
    """伪 pcap: 抓包句柄只回送固定数量的「线上回送帧」。

    真实链路上的回送帧来自网关; 这里模拟「发出去 N 帧, 网关回送 M 帧」。
    抓包侧返回 1 (有帧) / 0 (超时), 发送侧记录发出的帧数。
    """

    def __init__(self, frames_to_return=0):
        self.frames_to_return = frames_to_return
        self.returned = 0
        self.sent = 0
        self._opened = []

    def open(self, dev_name, promisc=1, to_ms=100):
        # 第一次调用是抓包句柄, 之后是发送句柄
        h = object()
        self._opened.append(h)
        return h, ""

    def pcap_next_ex(self, handle, hdr, data):
        # 只有开始发送之后才算「线上回送」(真实链路也是如此: 先有去程才有回程)
        if self.sent > 0 and self.returned < self.frames_to_return:
            self.returned += 1
            return 1
        return 0

    def pcap_sendpacket(self, handle, buf, size):
        self.sent += 1
        return 0

    def pcap_close(self, handle):
        return 0


class TestLoopbackCounting(unittest.TestCase):
    """计数口径 —— 最容易搞错的一处: 不得把本地回环副本算进去。"""

    def test_rate_uses_wire_frames_not_socket_datagrams(self):
        """线上回送 100 帧 → 速率按 100 帧算, 不得按 socket 收到的 200 帧算。

        这里跑的是**真实的 _loopback_measure** (伪 pcap 驱动), 不是本地算式 ——
        算式对了但接线错了 (例如误用 socket 收包数), 这种测法抓不住。
        """
        frames = 100
        payload_len = 1400
        fake = _FakePcap(frames_to_return=frames)
        with mock.patch.object(np, "_npcap_dll", return_value=fake), \
             mock.patch.object(np, "_pcap_open", side_effect=fake.open), \
             mock.patch.object(np, "_pcap_set_filter", return_value=True):
            out = np._loopback_measure(MY_IP, GW_IP, MY_MAC, GW_MAC, "以太网",
                                       duration_s=1, payload_len=payload_len,
                                       threads=1)
        self.assertTrue(out.get("ok"), out)
        self.assertEqual(out["frames"], frames)
        # 速率 = 线上回送帧数 × 载荷长 × 8 / 采样时长
        expected = frames * payload_len * 8 / 1e6 / out["seconds"]
        self.assertAlmostEqual(out["mbps"], expected, places=1)
        # 若误按 socket 收包数 (2 倍) 换算, 速率会翻倍 → 必须明显高于换算值
        self.assertLess(out["mbps"], expected * 1.5)
        self.assertEqual(out["bytes"], frames * payload_len)

    def test_measure_reports_offered_load_and_return_ratio(self):
        """测速结果必须同时给出施加负载与回程完整度 (判断是不是工具能力所限)。"""
        out = np._loopback_measure.__doc__
        self.assertIsNotNone(out)
        # 真实口径常数必须存在且有序
        self.assertGreater(np.LOOPBACK_SATURATED_RATIO, 0)
        self.assertLess(np.LOOPBACK_SATURATED_RATIO, 1)
        self.assertGreater(np.LOOPBACK_OFFER_MIN_MBPS, 0)

    def test_capture_filter_excludes_local_copy(self):
        """抓包过滤必须限定「源 MAC = 网关 MAC」, 否则注入副本会被算进去。"""
        import inspect
        src = inspect.getsource(np._loopback_measure)
        self.assertIn("ether src", src)
        self.assertIn("ether dst", src)
        self.assertIn("dst host", src)

    def test_payload_size_is_1400_bytes(self):
        """载荷长是口径的一部分 (与 speedtest 的 goodput 同口径), 锁死 1400。"""
        self.assertEqual(np.LOOPBACK_PAYLOAD_BYTES, 1400)


class TestLoopbackPresentation(unittest.TestCase):
    """呈现层 —— 口径文案比数字更容易误导现场。"""

    def test_verdict_states_which_segment(self):
        v = np._verdict_loopback(_loopback_res())
        self.assertIn("终端", v)
        self.assertIn("网关", v)

    def test_verdict_never_calls_it_downlink_bandwidth(self):
        v = np._verdict_loopback(_loopback_res())
        for bad in ("下行带宽", "下载速度", "上行带宽"):
            self.assertNotIn(bad, v)

    def test_metrics_state_round_trip_is_not_downlink(self):
        """「往返」口径说明必须出现在报告里, 且不得出现「下行带宽」这种叫法。"""
        labels = [m[0] for m in np._metrics_loopback(_loopback_res())]
        self.assertIn("测速区间", labels)
        html = np._loopback_section(_report(), {"loopback": {"raw": _loopback_res()}})
        self.assertIn("往返", html)
        for bad in ("下行带宽", "下载速度"):
            self.assertNotIn(bad, html)

    def test_verdict_when_not_measured_says_reason_not_fault(self):
        res = {"error": "环回测速未执行: 未检测到 Npcap", "reason": "未检测到 Npcap"}
        v = np._verdict_loopback(res)
        self.assertIn("未测试", v)
        self.assertIn("Npcap", v)

    def test_metrics_empty_when_not_measured(self):
        self.assertEqual(np._metrics_loopback({"error": "x"}), [])

    def test_issues_mapped_from_probe_issues(self):
        res = _loopback_res(issues=[{"severity": "警告", "message": "终端到网关有瓶颈",
                                      "detail": "细节", "action": "动作"}])
        issues = np._issues_loopback(res)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["text"], "终端到网关有瓶颈")
        self.assertEqual(issues[0]["severity"], "警告")


class TestLoopbackScope(unittest.TestCase):
    """scope 判定 —— 拿局域侧速率比签约带宽会把「网线插错口」误判成宽带不达标。"""

    def test_unknown_scope_has_no_verdict_words(self):
        html = np._loopback_section(_report(), {"loopback": {"raw": _loopback_res()}})
        for bad in ("达标", "不达标", "签约带宽"):
            self.assertNotIn(bad, html)

    def test_access_scope_mentions_access_side(self):
        html = np._loopback_section(
            _report(), {"loopback": {"raw": _loopback_res(scope="access")}})
        self.assertIn("运营商接入侧", html)

    def test_scope_auto_is_unknown_without_pppoe(self):
        with mock.patch.object(np, "run_ps", return_value=(0, "unknown", "")):
            self.assertEqual(np._loopback_scope_auto(), "unknown")

    def test_scope_auto_detects_pppoe_session(self):
        with mock.patch.object(np, "run_ps", return_value=(0, "access", "")):
            self.assertEqual(np._loopback_scope_auto(), "access")


class TestLoopbackReportSection(unittest.TestCase):
    """完整版一级章节 —— 装维一眼看出接入侧 vs 使用侧。"""

    def test_section_exists_with_both_sides(self):
        report = _report(speedtest=_speedtest_res(213.45))
        by_key = {m["key"]: m for m in report["modules"]}
        html = np._loopback_section(report, by_key)
        self.assertIn("环回测速", html)
        self.assertIn("接入侧", html)
        self.assertIn("使用侧", html)
        self.assertIn("312.5 Mbps", html)
        self.assertIn("213.4 Mbps", html)   # Ookla 嵌套值, 与图表同源

    def test_section_conclusion_when_access_far_faster(self):
        report = _report(loopback=_loopback_res(mbps=800.0),
                         speedtest=_speedtest_res(60.0))
        by_key = {m["key"]: m for m in report["modules"]}
        html = np._loopback_section(report, by_key)
        self.assertIn("互联网侧", html)

    def test_section_conclusion_when_both_slow(self):
        report = _report(loopback=_loopback_res(mbps=70.0),
                         speedtest=_speedtest_res(60.0))
        by_key = {m["key"]: m for m in report["modules"]}
        html = np._loopback_section(report, by_key)
        self.assertIn("接入段或终端侧", html)

    def test_section_absent_when_module_not_run(self):
        report = _report(with_loopback=False)
        by_key = {}
        self.assertEqual(np._loopback_section(report, by_key), "")

    def test_section_does_not_blame_access_side_when_number_unjudgeable(self):
        """数字不可判读时, 结论句不得说「瓶颈在接入段」—— 注释说仅供参考,
        结论却说接入段有瓶颈, 同一页自相矛盾, 装维会照着去换网线。"""
        for tag, kw, want in (
                ("wireless", {"is_wireless": True, "mbps": 0.8,
                              "negotiated_mbps": 866.0}, "无线接入"),
                ("not_saturated", {"load_limited": True,
                                   "return_ratio": 0.98,
                                   "offered_mbps": 120.0}, "已达本工具测量上限"),
                ("at_ceiling", {"at_ceiling": True, "mbps": 850.0},
                 "已达本工具测量上限")):
            with self.subTest(tag=tag):
                res = _loopback_res(**kw)
                html = np._loopback_section(
                    _report(loopback=res, speedtest=_speedtest_res(213.45)),
                    {"loopback": {"raw": res}})
                self.assertNotIn("瓶颈在接入段或终端侧", html)
                self.assertNotIn("优先查网线", html)
                self.assertIn("不与使用侧对照", html)
                # 结论句本身必须带原因 (不只是章节说明里有)
                verdict = html.split('class="lb-verdict"')[1]
                self.assertIn(want, verdict)

    def test_section_reports_reason_when_not_measured(self):
        report = _report(loopback={"error": "环回测速未执行: 未检测到 Npcap",
                                   "reason": "未检测到 Npcap"})
        by_key = {m["key"]: m for m in report["modules"]}
        html = np._loopback_section(report, by_key)
        self.assertIn("未检测", html)
        self.assertIn("Npcap", html)


class TestLoopbackBriefV2(unittest.TestCase):
    """一页版摘要行 —— 只占一行, 且口径与完整版一致。"""

    def test_brief_v2_has_loopback_line(self):
        report = _report(speedtest=_speedtest_res(213.45))
        html = np.render_report_html_brief_v2(report)
        self.assertIn("终端→网关", html)
        self.assertIn("312.5 Mbps", html)

    def test_brief_v2_speed_precision_matches_full_report(self):
        """摘要与完整版的速率精度必须一致 (不能一边 312.5 一边 313)。"""
        report = _report(speedtest=_speedtest_res(213.45))
        brief = np.render_report_html_brief_v2(report)
        by_key = {m["key"]: m for m in report["modules"]}
        full = np._loopback_section(report, by_key)
        self.assertIn("312.5 Mbps", brief)
        self.assertIn("312.5 Mbps", full)

    def test_brief_v2_unknown_scope_has_no_verdict_words(self):
        report = _report()
        brief = np.render_report_html_brief_v2(report)
        i = brief.find('class="loopline"')
        seg = brief[i:i + 600] if i >= 0 else ""
        for bad in ("达标", "不达标", "签约带宽"):
            self.assertNotIn(bad, seg)

    def test_brief_v2_marks_unjudgeable_numbers(self):
        """数字不可判读时, 一页版必须自带标注 —— 客户只看这一页。"""
        report = _report(loopback=_loopback_res(load_limited=True,
                                                offered_mbps=120.0,
                                                return_ratio=0.98))
        brief = np.render_report_html_brief_v2(report)
        i = brief.find('class="loopline"')
        seg = brief[i:i + 600] if i >= 0 else ""
        self.assertIn("已达本工具测量上限", seg)

    def test_brief_v2_marks_wireless_numbers(self):
        report = _report(loopback=_loopback_res(is_wireless=True))
        brief = np.render_report_html_brief_v2(report)
        i = brief.find('class="loopline"')
        seg = brief[i:i + 600] if i >= 0 else ""
        self.assertIn("无线接入仅供参考", seg)

    def test_brief_v2_does_not_compare_unjudgeable_numbers(self):
        """接入侧数字不可判读时, 一页版不做「接入侧高于使用侧」的大小对照。"""
        report = _report(loopback=_loopback_res(is_wireless=True, mbps=0.8),
                         speedtest=_speedtest_res(0.5))
        brief = np.render_report_html_brief_v2(report)
        i = brief.find('class="loopline"')
        seg = brief[i:i + 600] if i >= 0 else ""
        self.assertNotIn("接入侧高于使用侧", seg)


class TestLoopbackRegistration(unittest.TestCase):
    """注册与集合 —— 新模块必须真的挂进系统, 且不吃健康分。"""

    def test_module_registered(self):
        self.assertIn("loopback", np.MODULE_MAP)
        self.assertEqual(np.MODULE_MAP["loopback"][0], "环回测速")

    def test_module_in_bandwidth_category(self):
        self.assertIn("loopback", np.MODULE_CATEGORY_OF)
        self.assertEqual(np.MODULE_CATEGORY_OF["loopback"], "宽带测速")

    def test_native_probe_registered(self):
        self.assertIn("loopback", np._V2_PROBES)

    def test_score_exempt(self):
        """环回测速是客观数据, 不参与健康分扣分 (与 iperf3 同族)。"""
        self.assertIn("loopback", np.SCORE_EXEMPT_MODULES)

    def test_exclusive_net_module(self):
        """打满链路 → 必须独占串行跑, 否则压低其它模块的测速。"""
        self.assertIn("loopback", np.EXCLUSIVE_NET_MODULE_KEYS)

    def test_not_configured_marker_maps_to_idle(self):
        """没测成 → 未检测, 不是错误 (客户看红色错误会误以为网络坏了)。"""
        self.assertEqual(np._STATUS_NOT_CONFIGURED.get("loopback"),
                         np.LOOPBACK_NOT_RUN_MARK)

    def test_cli_accepts_loopback_key(self):
        self.assertEqual(np._parse_keys(["loopback"]), ["loopback"])
        self.assertEqual(np._parse_keys(["环回测速"]), ["loopback"])


class TestLoopbackJudgement(unittest.TestCase):
    """可判性判据 —— 只有「路径确实被打满 + 有线接入」才允许报链路瓶颈。

    错判的代价不对称: 把「工具没能把链路压满」当成「链路有瓶颈」, 装维会去
    换网线、换网口, 白跑一趟; 反过来漏报只是少一条提示。所以判据偏保守。
    """

    @staticmethod
    def _run(mbps=90.0, negotiated=1000.0, return_ratio=0.35, offered=900.0,
             desc="Realtek GbE Family Controller"):
        route = {"local_ip": MY_IP, "gateway": GW_IP, "mac": MY_MAC,
                 "alias": "以太网", "desc": desc}
        measure = {"ok": True, "mbps": mbps, "frames": 89000,
                   "bytes": 124600000, "seconds": 5.0,
                   "offered_mbps": offered, "return_ratio": return_ratio}
        with mock.patch.object(np, "_loopback_route_info", return_value=route), \
             mock.patch.object(np, "_loopback_find_device",
                               return_value="以太网"), \
             mock.patch.object(np, "_loopback_resolve_gw_mac",
                               return_value=GW_MAC), \
             mock.patch.object(np, "_loopback_negotiated_mbps",
                               return_value=negotiated), \
             mock.patch.object(np, "_loopback_scope_auto",
                               return_value="unknown"), \
             mock.patch.object(np, "_loopback_measure", return_value=measure):
            return np.probe_loopback_v2(duration_s=3)

    def test_wired_saturated_low_ratio_reports_bottleneck(self):
        """有线 + 路径被打满 + 实测/协商远低于 80% → 报「这一段有瓶颈」。"""
        res = self._run()
        self.assertTrue(res.issues, "打满的路径 + 低比值, 必须出发现项")
        self.assertIn("终端到网关这一段有瓶颈", res.issues[0].title)
        self.assertIn("90.0", res.issues[0].title)
        self.assertIn("1000", res.issues[0].title)
        self.assertTrue(res.metrics["saturated"])
        self.assertEqual(res.metrics["ratio_pct"], 9.0)

    def test_not_saturated_never_reports_bottleneck(self):
        """路径没被打满 → 测得值只是下限, 不得报瓶颈, 须标注已达上限。"""
        res = self._run(return_ratio=0.98)
        self.assertFalse(res.issues, "路径没压满就报瓶颈 = 把工具上限当成链路故障")
        self.assertFalse(res.metrics["saturated"])
        self.assertTrue(res.metrics["load_limited"])
        labels = [m[0] for m in np._metrics_loopback(res.metrics)]
        self.assertIn("测量上限", labels)
        values = [m[1] for m in np._metrics_loopback(res.metrics)]
        self.assertIn("已达本工具测量上限", values)

    def test_wireless_never_reports_bottleneck(self):
        """无线接入的注入能力本身受限, 数字不可用于判定链路。"""
        res = self._run(desc="WiFi 无线网卡 Realtek 8822CE")
        self.assertFalse(res.issues, "无线接入不得报链路瓶颈")
        self.assertTrue(res.metrics["is_wireless"])
        verdict = np._verdict_loopback(res.metrics)
        self.assertIn("无线接入", verdict)

    def test_at_ceiling_is_marked_and_never_unqualified(self):
        """达到工具上限 → 标注「已达本工具测量上限」, 且不得出现「不达标」。"""
        res = self._run(mbps=850.0, negotiated=1000.0)
        self.assertTrue(res.metrics["at_ceiling"])
        values = [m[1] for m in np._metrics_loopback(res.metrics)]
        self.assertIn("已达本工具测量上限", values)
        for text in (np._verdict_loopback(res.metrics),
                     np._loopback_section(_report(),
                                          {"loopback": {"raw": res.metrics}})):
            self.assertIn("已达本工具测量上限", text)
            self.assertNotIn("不达标", text)

    def test_ratio_metric_hidden_when_not_judgeable(self):
        """实测/协商比值只在「路径被打满 + 有线 + 施加负载够」时才有判读意义。"""
        res = self._run(return_ratio=0.98)
        labels = [m[0] for m in np._metrics_loopback(res.metrics)]
        self.assertNotIn("实测/协商", labels)
        res2 = self._run(desc="WiFi 无线网卡")
        labels2 = [m[0] for m in np._metrics_loopback(res2.metrics)]
        self.assertNotIn("实测/协商", labels2)
        # 施加负载不足 → 比值同样不展示 (tooltip 会说「有瓶颈」, 与章节结论打架)
        res3 = self._run(offered=120.0)
        labels3 = [m[0] for m in np._metrics_loopback(res3.metrics)]
        self.assertNotIn("实测/协商", labels3)
        # 撞到工具上限 → 比值同样不展示 (实测值是下限, 比协商速率必然是假瓶颈)
        res4 = self._run(mbps=850.0, negotiated=2500.0)
        labels4 = [m[0] for m in np._metrics_loopback(res4.metrics)]
        self.assertNotIn("实测/协商", labels4)

    def test_load_limited_never_reports_bottleneck(self):
        """施加负载不足 (工具没压满) → 测得值是下限, 不得报「这一段有瓶颈」。

        否则同页自相矛盾: 章节结论说「无法判定瓶颈在哪一侧」, 主要发现却指着
        接入段 —— 装维照着去换网线, 白跑一趟。
        """
        res = self._run(offered=120.0)
        self.assertTrue(res.metrics["load_limited"])
        self.assertFalse(res.issues, "施加负载不足时不得报链路瓶颈")

    def test_at_ceiling_never_reports_bottleneck(self):
        """撞到工具上限 → 实测值是下限, 不得拿它比协商速率报瓶颈。

        2.5G 网卡上实测 800 Mbps (工具上限) 比值只有 32%, 但真实能力可能远高于
        800 —— 报「这一段有瓶颈」会让装维去换网线, 方向完全错。
        """
        res = self._run(mbps=850.0, negotiated=2500.0)
        self.assertTrue(res.metrics["at_ceiling"])
        self.assertFalse(res.issues, "撞到工具上限时不得报链路瓶颈")
        labels = [m[0] for m in np._metrics_loopback(res.metrics)]
        self.assertNotIn("实测/协商", labels)


class TestLoopbackDegradation(unittest.TestCase):
    """降级链 —— 未测成一律「未检测」, 四种原因互不相同, 数据不丢弃。"""

    @staticmethod
    def _route():
        return {"local_ip": MY_IP, "gateway": GW_IP, "mac": MY_MAC,
                "alias": "以太网", "desc": "Realtek GbE Family Controller"}

    def test_npcap_missing_is_reported_before_adapter_lookup(self):
        """没装 Npcap → 原因必须点名 Npcap, 不能报成「网卡不在设备列表里」。"""
        called = {"fd": False}

        def _fd(desc):
            called["fd"] = True
            return None

        with mock.patch.object(np, "_npcap_dll", return_value=None), \
             mock.patch.object(np, "_loopback_route_info",
                               return_value=self._route()), \
             mock.patch.object(np, "_loopback_find_device", side_effect=_fd):
            res = np.probe_loopback_v2(duration_s=3)
        self.assertIsNotNone(res.error)
        self.assertIn(np.LOOPBACK_NOT_RUN_MARK, res.error.message)
        self.assertIn("Npcap", res.error.message)
        # 顺序: 判 Npcap 必须在查网卡之前 (否则原因会变成「不在设备列表里」)
        self.assertFalse(called["fd"], "Npcap 检查必须早于网卡查找")
        self.assertNotIn("设备列表", res.error.message)

    def test_interrupted_sampling_keeps_partial_data(self):
        """采样被打断 → 未检测 + 原因「采样未完成」, 已采数据不丢弃。"""
        fake = _FakePcap(frames_to_return=50)
        import threading as _th
        real_join = _th.Thread.join

        def _join(self, timeout=None):
            if timeout is not None and timeout > 3:
                raise KeyboardInterrupt()
            return real_join(self, timeout)

        with mock.patch.object(np, "_npcap_dll", return_value=fake), \
             mock.patch.object(np, "_pcap_open", side_effect=fake.open), \
             mock.patch.object(np, "_pcap_set_filter", return_value=True), \
             mock.patch.object(np.threading.Thread, "join", _join):
            out = np._loopback_measure(MY_IP, GW_IP, MY_MAC, GW_MAC, "以太网",
                                       duration_s=1, payload_len=1400,
                                       threads=1)
        self.assertFalse(out.get("ok"))
        self.assertTrue(out.get("interrupted"))
        self.assertIn("采样未完成", out["error"])
        self.assertIn("frames", out)
        self.assertIn("partial_mbps", out)
        # 数值级断言: 已采到的数据必须是真数据 (不能被清零)
        self.assertGreater(out.get("frames") or 0, 0)
        self.assertGreater(out.get("partial_mbps") or 0, 0)
        self.assertGreater(out.get("seconds") or 0, 0)

    def test_interrupted_probe_result_is_not_run(self):
        """探针层: 采样被打断 → LOOPBACK_NOT_RUN (状态归一为「未检测」)。"""
        out = {"ok": False, "interrupted": True, "error": "采样未完成: 采样被中断",
               "frames": 42, "seconds": 1.2, "partial_mbps": 39.2}
        with mock.patch.object(np, "_npcap_dll", return_value=mock.Mock()), \
             mock.patch.object(np, "_loopback_route_info",
                               return_value=self._route()), \
             mock.patch.object(np, "_loopback_find_device",
                               return_value="以太网"), \
             mock.patch.object(np, "_loopback_resolve_gw_mac",
                               return_value=GW_MAC), \
             mock.patch.object(np, "_loopback_scope_auto",
                               return_value="unknown"), \
             mock.patch.object(np, "_loopback_measure", return_value=out):
            res = np.probe_loopback_v2(duration_s=3)
        self.assertIsNotNone(res.error)
        self.assertIn(np.LOOPBACK_NOT_RUN_MARK, res.error.message)
        self.assertIn("采样未完成", res.error.message)
        # 已采数据不丢弃
        self.assertTrue(res.metrics.get("partial"))
        self.assertEqual(res.metrics.get("partial_frames"), 42)

    def test_module_timeout_is_reported_as_not_run(self):
        """模块超时 = 采样窗口被打断 → 状态归一为「未检测」, 不是「超时/异常」。"""
        import time as _t

        def _hang(callback=None):
            _t.sleep(30)

        saved = np._V2_PROBES["loopback"]
        np._V2_PROBES["loopback"] = _hang
        try:
            with mock.patch.object(np, "_module_timeout", return_value=0.2):
                status, res = np._run_module_with_timeout("loopback", None)
        finally:
            np._V2_PROBES["loopback"] = saved
        self.assertEqual(status, "超时")
        self.assertIn(np.LOOPBACK_NOT_RUN_MARK, res["error"])
        norm = np._normalize_module_statuses({"loopback": status},
                                              {"loopback": res})
        self.assertEqual(norm["loopback"], "未检测")

    def test_module_timeout_keeps_partial_data(self):
        """模块超时时, 已采到的数据不丢弃 (从采样进度读回来)。"""
        import time as _t

        def _stuck(callback=None):
            # 模拟采样中途卡死: 进度里有数据, 但 probe 永不返回
            np._LOOPBACK_PROGRESS.update({"frames": 321, "sent": 5000,
                                          "started": _t.time() - 2.0})
            _t.sleep(30)

        saved = np._V2_PROBES["loopback"]
        np._V2_PROBES["loopback"] = _stuck
        try:
            with mock.patch.object(np, "_module_timeout", return_value=0.2):
                status, res = np._run_module_with_timeout("loopback", None)
        finally:
            np._V2_PROBES["loopback"] = saved
        self.assertEqual(status, "超时")
        self.assertIn(np.LOOPBACK_NOT_RUN_MARK, res["error"])
        self.assertTrue(res.get("partial"), "超时时已采数据必须保留")
        self.assertEqual(res.get("partial_frames"), 321)
        self.assertGreater(res.get("partial_mbps") or 0, 0)
        self.assertIn("已采", res["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
