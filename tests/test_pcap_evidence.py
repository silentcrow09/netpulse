# -*- coding: utf-8 -*-
"""抓包证据联动结论单元测试 (阶段 F · v1.8.0 PR-F4 引入)

覆盖: _apply_capture_evidence 的结论追加/verdict 升级/置信度/事件根因标注/
信号 C 联动 (统计层 path_mtu)/失败兜底 (坏文件·缺文件)/无证据不改结论,
以及 _render_monitor_html 的置信度徽标与证据分析行。
全部合成数据, 不需要 Npcap/管理员。
跑用: cd 到项目根目录, `python tests/test_pcap_evidence.py`
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

try:
    from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, wrpcap
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

T0 = 1700000000.0
CLI, SRV = "192.168.1.5", "203.0.113.10"


def tcp(sport, dport, flags, seq=100, ack=1, payload=b"", mss=None, ts=T0):
    opts = [("MSS", mss)] if mss else []
    p = (Ether(src="aa", dst="bb") / IP(src=CLI, dst=SRV) /
         TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
             options=opts) / (Raw(payload) if payload else b""))
    p.time = ts
    return p


def tcp_srv(sport, dport, flags, seq=1, ack=1, payload=b"", mss=None, ts=T0):
    opts = [("MSS", mss)] if mss else []
    p = (Ether(src="bb", dst="aa") / IP(src=SRV, dst=CLI) /
         TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
             options=opts) / (Raw(payload) if payload else b""))
    p.time = ts
    return p


def icmp_frag_needed(nexthop_mtu, ts=T0):
    # nexthopmtu 用字段名传 (unused= 原始字节会在 wrpcap build 时被抹零)
    p = (Ether(src="cc", dst="aa") / IP(src="10.0.0.1", dst=CLI) /
         ICMP(type=3, code=4, nexthopmtu=nexthop_mtu) /
         IP(src=CLI, dst=SRV) / TCP(sport=5000, dport=443, flags="PA"))
    p.time = ts
    return p


def stall_pkts(mss=1460):
    """握手 + 1448B 段同 seq ×3 + 小包正常流动 (信号 B)。"""
    return [
        tcp(5000, 443, "S", seq=100, mss=mss, ts=T0),
        tcp_srv(443, 5000, "SA", seq=200, ack=101, mss=mss, ts=T0 + 0.02),
        tcp(5000, 443, "A", seq=101, ack=201, ts=T0 + 0.04),
        tcp(5000, 443, "PA", seq=101, ack=201, payload=b"D" * 1448, ts=T0 + 0.10),
        tcp(5000, 443, "PA", seq=101, ack=201, payload=b"D" * 1448, ts=T0 + 0.35),
        tcp(5000, 443, "PA", seq=101, ack=201, payload=b"D" * 1448, ts=T0 + 0.60),
        tcp(5000, 443, "A", seq=1549, ack=5000, ts=T0 + 0.80),
        tcp(5000, 443, "A", seq=1549, ack=6000, ts=T0 + 0.90),
        tcp_srv(443, 5000, "A", seq=5000, ack=1549, ts=T0 + 0.95),
    ]


def congestion_pkts():
    """多流散布重传 ~10%, 无停滞 (链路丢包形态)。"""
    pkts = []
    for f in range(5):
        sp = 6000 + f
        pkts.append(tcp(sp, 443, "S", seq=100, mss=1460, ts=T0 + f))
        pkts.append(tcp_srv(443, sp, "SA", seq=200, ack=101, mss=1460,
                            ts=T0 + f + 0.02))
        for i in range(20):
            pkts.append(tcp(sp, 443, "PA", seq=101 + i * 50, ack=201,
                            payload=b"x" * 40, ts=T0 + 1 + f + i * 0.1))
            if i % 10 == 0:
                pkts.append(tcp(sp, 443, "PA", seq=101 + i * 50, ack=201,
                                payload=b"x" * 40, ts=T0 + 1 + f + i * 0.1 + 0.05))
    return pkts


def dns_slow_pkts():
    pkts = []
    for i, gap in enumerate((1.2, 1.5)):
        qid, port = 100 + i, 40000 + i
        name = f"slow{i}.example.com"
        q = (Ether(src="aa", dst="bb") / IP(src=CLI, dst="223.5.5.5") /
             UDP(sport=port, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
        q.time = T0 + i * 10
        r = (Ether(src="bb", dst="aa") / IP(src="223.5.5.5", dst=CLI) /
             UDP(sport=53, dport=port) / DNS(id=qid, qr=1, qd=DNSQR(qname=name)))
        r.time = T0 + i * 10 + gap
        pkts += [q, r]
    return pkts


def _base_result(events=None, path_mtu=1500, slices=("s0.pcap",)):
    return {
        "verdict": "stable",
        "conclusion_text": "监测期内未复现掉线 (网关丢包 0.0% / 外网丢包 0.0%)",
        "advice": "原有建议",
        "summary": "盯障 90s: 无中断",
        "events": events or [],
        "mtu": {"path_mtus": ([{"target": "223.5.5.5", "path_mtu": path_mtu}]
                              if path_mtu else [])},
        "capture": {"mode": "slice", "slices": [
            {"path": p, "event_type": "outage", "rel": f"captures/{p}"}
            for p in slices]},
    }


def _ev(etype, cls="", **kw):
    e = {"id": 1, "type": etype, "cls": cls, "stream": "ext",
         "start_ts": T0 + 10, "end_ts": T0 + 12, "duration_s": 2,
         "start_disp": "12:00:10", "end_disp": "12:00:12", "detail": "x",
         "root_cause": "原根因"}
    e.update(kw)
    return e


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestApplyCaptureEvidence(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="npcap_ev_")
        _p = mock.patch("netpulse._captures_dir", return_value=self._tmp)
        _p.start()
        self.addCleanup(_p.stop)

    def _write(self, name, pkts):
        wrpcap(os.path.join(self._tmp, name), pkts)

    def test_blackhole_icmp_confirms_and_upgrades(self):
        """场景 1: 切片含 ICMP 3/4 → 结论追加 + verdict 升级 + 置信度 92。"""
        self._write("s0.pcap", stall_pkts() + [icmp_frag_needed(1280, T0 + 2)])
        events = [_ev("mtu_mismatch", "mtu"), _ev("tcp_retrans_burst", "l4_loss")]
        r = _base_result(events=events)
        N._apply_capture_evidence(r)
        self.assertEqual(r["verdict"], "degraded")
        self.assertEqual(r["confidence"], 92)
        self.assertIn("PMTU 黑洞确认", r["conclusion_text"])
        self.assertTrue(r["conclusion_text"].startswith("监测期内未复现掉线"))
        self.assertIn("下一跳 MTU 1280", r["conclusion_text"])
        self.assertIn("PMTU 黑洞", events[0]["pcap_evidence"])
        self.assertIn("抓包佐证", events[1]["root_cause"])
        self.assertIn("抓包确认 PMTU 黑洞", r["summary"])
        self.assertTrue(r["capture"]["analysis"]["suspected_pmtud_blackhole"])
        self.assertEqual(r["capture"]["analysis_files"], 1)
        json.dumps(r["capture"], ensure_ascii=False)      # 可序列化

    def test_blackhole_via_signal_c_from_stats_layer(self):
        """场景 2: 无 ICMP, 统计层 path_mtu=1280 提供 C 信号 → B∧C 判黑洞。"""
        self._write("s0.pcap", stall_pkts())
        r = _base_result(path_mtu=1280)
        N._apply_capture_evidence(r)
        self.assertEqual(r["confidence"], 92)
        self.assertIn("判 PMTU 黑洞", r["conclusion_text"])
        self.assertIn("分片指示 ICMP 被链路丢弃", r["conclusion_text"])

    def test_loss_evidence_confidence_85(self):
        """场景 3: 拥塞形态 → 链路丢包佐证, 置信度 85, 不判黑洞。"""
        self._write("s0.pcap", congestion_pkts())
        events = [_ev("tcp_retrans_burst", "l4_loss")]
        r = _base_result(events=events)
        N._apply_capture_evidence(r)
        self.assertEqual(r["confidence"], 85)
        self.assertFalse(r["capture"]["analysis"]["suspected_pmtud_blackhole"])
        self.assertIn("链路丢包/拥塞佐证", r["conclusion_text"])
        self.assertIn("链路丢包/拥塞", events[0]["pcap_evidence"])

    def test_dns_slow_evidence(self):
        self._write("s0.pcap", dns_slow_pkts())
        events = [_ev("dns_fail", "dns")]
        r = _base_result(events=events)
        N._apply_capture_evidence(r)
        self.assertEqual(r["confidence"], 85)
        self.assertIn("DNS 解析超 1s", r["conclusion_text"])
        self.assertIn("DNS 解析慢", events[0]["pcap_evidence"])

    def test_clean_traffic_changes_nothing(self):
        """正常流量切片: 分析块存在但结论/置信度不变 (抓包不是前置条件)。"""
        self._write("s0.pcap", [
            tcp(5001, 443, "S", seq=100, mss=1460, ts=T0),
            tcp_srv(443, 5001, "SA", seq=200, ack=101, mss=1460, ts=T0 + 0.02),
            tcp(5001, 443, "PA", seq=101, ack=201, payload=b"d" * 80,
                ts=T0 + 0.1),
        ])
        r = _base_result()
        before = (r["verdict"], r["conclusion_text"], r["advice"], r["summary"])
        N._apply_capture_evidence(r)
        self.assertEqual((r["verdict"], r["conclusion_text"], r["advice"],
                          r["summary"]), before)
        self.assertNotIn("confidence", r)
        self.assertFalse(r["capture"]["analysis"]["suspected_pmtud_blackhole"])

    def test_missing_and_corrupt_files_are_skipped(self):
        """缺文件 + 坏文件 (rdpcap 抛异常) → 全部跳过, result 原样。"""
        with open(os.path.join(self._tmp, "bad.pcap"), "wb") as f:
            f.write(b"\x00\x01garbage-not-a-pcap")
        r = _base_result(slices=("missing.pcap", "bad.pcap"))
        before = dict(r)
        N._apply_capture_evidence(r)
        self.assertNotIn("analysis", r["capture"])
        self.assertEqual(r["verdict"], "stable")
        self.assertNotIn("confidence", r)
        self.assertEqual(r["events"], before["events"])

    def test_no_slices_noop(self):
        r = _base_result(slices=())
        before = dict(r)
        N._apply_capture_evidence(r)
        self.assertNotIn("analysis", r["capture"])

    def test_mixed_slices_merged(self):
        """多切片合并: 计数累加, 任一切片确认即整体确认。"""
        self._write("s0.pcap", stall_pkts())
        self._write("s1.pcap", congestion_pkts())
        r = _base_result(path_mtu=1280, slices=("s0.pcap", "s1.pcap"))
        N._apply_capture_evidence(r)
        a = r["capture"]["analysis"]
        self.assertEqual(r["capture"]["analysis_files"], 2)
        self.assertTrue(a["suspected_pmtud_blackhole"])   # s0 的 B∧C
        self.assertGreater(a["tcp_retransmit_count"], 10)  # s1 的拥塞重传并入


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestEvidenceHtml(unittest.TestCase):
    """报告渲染: 置信度徽标 / 证据分析行 / 事件 "🔬 抓包分析" 标记。"""

    def _res(self, with_analysis=True, with_events=True):
        events = ([_ev("mtu_mismatch", "mtu", pcap_slice="captures/s0.pcap",
                       pcap_evidence="PMTU 黑洞 (抓包确认)")]
                  if with_events else [])
        r = _base_result(events=events)
        r.update({
            "started_at": "2026-09-01 12:00:00", "duration_actual_s": 90,
            "duration_planned_s": 90, "early_terminated": False,
            "local_ip": "192.168.1.5", "notes": [],
            "targets": {"gateway": "192.168.1.1", "external": "223.5.5.5",
                        "dns_server": "223.5.5.5"},
            "samples": {}, "stats": {"gw": {"loss_pct": 0.0},
                                     "ext": {"loss_pct": 0.0},
                                     "dns": {"ok_pct": 100.0}},
            "mtu": {"path_mtus": [{"target": "223.5.5.5", "path_mtu": 1500}],
                    "probe_status": "ok"},
            "tcp_quality": {"retrans_rate_pct": None, "series": []},
            "verdict": "degraded",
        })
        if with_analysis:
            r["confidence"] = 92
            r["confidence_basis"] = \
                "抓包证据确认 (ICMP 分片指示/大包停滞直接佐证)"
        if with_analysis:
            r["capture"]["analysis"] = {
                "icmp_count": 1, "icmp_frag_needed": [[T0 + 2, 1280]],
                "streams": [{"key": f"{CLI}:5000>{SRV}:443", "syn_mss": 1460,
                             "synack_mss": 1460, "syn_retrans_n": 0,
                             "rst_n": 0, "zero_win_n": 0,
                             "fullsize_stall": True}],
                "tcp_retransmit_count": 2, "tcp_dup_ack_count": 0,
                "tcp_rst_count": 0, "tcp_zero_window_n": 0,
                "dns_query_count": 0, "dns_slow_queries": [],
                "http_hosts": ["api.example.com"],
                "tls_sni": ["www.example.com", "sni_truncated"],
                "udp443_pkts": 3, "retrans_rate": 0.6667,
                "suspected_pmtud_blackhole": True,
                "suspected_tcp_loss_burst": False,
                "suspected_dns_slow": False}
            r["capture"]["analysis_files"] = 1
        r["capture"].update({"iface": "10", "ring_bytes": 1024, "ring_limit_mb": 8,
                             "packets_captured": 500, "dropped_old": 0,
                             "slice_before_s": 30, "retention_days": 7,
                             "max_slice_files": 10})
        return r

    def test_banner_confidence_and_analysis_rows(self):
        html = N._render_monitor_html(self._res())
        # v1.8.1 (审计 P1-04): UI 置信度改为高/中/低分档, 不再显示伪精确百分比
        self.assertIn("结论高置信度", html)
        self.assertIn("抓包证据确认", html)
        self.assertIn("证据分析", html)
        self.assertIn("疑似 PMTU 黑洞 (三信号判定)", html)
        self.assertIn("下一跳 MTU 1280", html)
        self.assertIn("www.example.com", html)
        self.assertIn("1 个域名超出 384B", html)
        self.assertIn("🔬 抓包分析", html)

    def test_no_confidence_badge_without_evidence(self):
        html = N._render_monitor_html(self._res(with_analysis=False,
                                                with_events=False))
        self.assertNotIn("结论置信度", html)
        self.assertNotIn("证据分析", html)
        self.assertNotIn("🔬 抓包分析", html)
        self.assertIn("抓包取证", html)          # 面板仍在 (规格+隐私声明)

    def test_confidence_band_scale_is_percent_normalized(self):
        """v1.9.1 (审查修复): 抓包置信度是百分数, 74% 须按 0.74 分档为中
        (原先直接喂 0-1 阈值, 1-74 区间会全部误判"高置信度")."""
        r = self._res()
        r["confidence"] = 74
        r["confidence_basis"] = "测试"
        html = N._render_monitor_html(r)
        self.assertIn("结论中置信度", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
