# -*- coding: utf-8 -*-
"""PcapAnalyzer 单元测试 (阶段 F · v1.8.0 PR-F3 引入)

全部合成数据 (scapy 构造, 无需 Npcap)。场景对齐方案 §9.1:
三信号 PMTUD 判定 / 流重组 (重传·dup-ack·SYN 重传·停滞) / DNS 慢查询 /
SNI 与 Host 提取 / 判据边界。
负向守则: v1 方案虚构的「重传 SYN 携带小 MSS」场景 (协议上不存在) 禁止
作为通过性用例 — 本文件不构造该签名。
跑用: cd 到项目根目录, `python tests/test_pcap_analyzer.py`
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

try:
    from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

T0 = 1700000000.0
CLI, SRV = "192.168.1.5", "203.0.113.10"


def tcp(sport, dport, flags, seq=100, ack=1, win=65535, payload=b"",
        mss=None, ts=T0):
    opts = [("MSS", mss)] if mss else []
    p = (Ether(src="aa", dst="bb") / IP(src=CLI, dst=SRV) /
         TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
             window=win, options=opts) / (Raw(payload) if payload else b""))
    p.time = ts
    return p


def tcp_srv(sport, dport, flags, seq=1, ack=1, win=65535, payload=b"",
            mss=None, ts=T0):
    opts = [("MSS", mss)] if mss else []
    p = (Ether(src="bb", dst="aa") / IP(src=SRV, dst=CLI) /
         TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
             window=win, options=opts) / (Raw(payload) if payload else b""))
    p.time = ts
    return p


def icmp_frag_needed(nexthop_mtu, ts=T0):
    """ICMP type=3 code=4 (frag-needed)。nexthopmtu 用字段名传 —
    走 unused= 原始字节会被 build 时的 MultipleTypeField 默认值抹零。"""
    p = (Ether(src="cc", dst="aa") / IP(src="10.0.0.1", dst=CLI) /
         ICMP(type=3, code=4, nexthopmtu=nexthop_mtu) /
         IP(src=CLI, dst=SRV) / TCP(sport=5000, dport=443, flags="PA"))
    p.time = ts
    return p


def dns_query(qid, name, port=33333, ts=T0):
    p = (Ether(src="aa", dst="bb") / IP(src=CLI, dst="223.5.5.5") /
         UDP(sport=port, dport=53) /
         DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
    p.time = ts
    return p


def dns_resp(qid, name, port=33333, ts=T0):
    p = (Ether(src="bb", dst="aa") / IP(src="223.5.5.5", dst=CLI) /
         UDP(sport=53, dport=port) /
         DNS(id=qid, qr=1, qd=DNSQR(qname=name)))
    p.time = ts
    return p


def _sni_record(name: bytes, pad_before=0):
    """合成 ClientHello (含 SNI 扩展); pad_before>0 时先放一段大 padding 扩展。"""
    def ext(etype, data):
        return struct.pack(">HH", etype, len(data)) + data
    sni_entry = b"\x00" + struct.pack(">H", len(name)) + name
    sni_data = struct.pack(">H", len(sni_entry)) + sni_entry
    exts = b""
    if pad_before:
        exts += ext(0x0015, b"\x00" * pad_before)      # padding 扩展
    exts += ext(0x0000, sni_data)                      # SNI
    ch_body = (b"\x03\x01" + b"\x00" * 32 + b"\x00" +  # ver, random, sid_len
               b"\x00\x02\xc0\x2f" + b"\x01\x00" +     # cipher suites, comp
               struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestBlackholeSignals(unittest.TestCase):
    """三信号综合 (方案 §6.1): A=ICMP 3/4, B=行为签名, C=MSS>path_mtu-40。"""

    def _handshake_and_stall(self, mss=1460):
        """SYN/SYN-ACK(MSS) + ACK + 1448B 段同 seq ×3 + 小包 ACK 正常流动。"""
        pkts = [
            tcp(5000, 443, "S", seq=100, mss=mss, ts=T0),
            tcp_srv(443, 5000, "SA", seq=200, ack=101, mss=mss, ts=T0 + 0.02),
            tcp(5000, 443, "A", seq=101, ack=201, ts=T0 + 0.04),
            # full-size 段同 seq ×3 (停滞重传)
            tcp(5000, 443, "PA", seq=101, ack=201,
                payload=b"D" * 1448, ts=T0 + 0.10),
            tcp(5000, 443, "PA", seq=101, ack=201,
                payload=b"D" * 1448, ts=T0 + 0.35),
            tcp(5000, 443, "PA", seq=101, ack=201,
                payload=b"D" * 1448, ts=T0 + 0.60),
            # 小包 (纯 ACK / keepalive) 正常流动
            tcp(5000, 443, "A", seq=1549, ack=5000, ts=T0 + 0.80),
            tcp(5000, 443, "A", seq=1549, ack=6000, ts=T0 + 0.90),
            tcp_srv(443, 5000, "A", seq=5000, ack=1549, ts=T0 + 0.95),
        ]
        return pkts

    def test_signal_a_icmp_direct_evidence(self):
        """场景 1: 有 ICMP 3/4 → 黑洞 (信号 A 直接成立)。"""
        pkts = self._handshake_and_stall() + [icmp_frag_needed(1280, T0 + 2)]
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertTrue(d.suspected_pmtud_blackhole)
        self.assertEqual(len(d.icmp_frag_needed), 1)
        ts, mtu = d.icmp_frag_needed[0]
        self.assertEqual(mtu, 1280)
        self.assertAlmostEqual(ts, T0 + 2, places=3)
        self.assertEqual(d.icmp_count, 1)

    def test_signal_b_and_c_without_icmp(self):
        """场景 2 (最典型): 无 ICMP (黑洞吞掉 3/4) — B 且 C → 黑洞。"""
        pkts = self._handshake_and_stall()
        d = N.PcapAnalyzer(path_mtu=1280).analyze(pkts)
        self.assertTrue(d.suspected_pmtud_blackhole)
        st = d.streams[0]
        self.assertTrue(st["fullsize_stall"])
        self.assertEqual(st["syn_mss"], 1460)
        self.assertEqual(st["synack_mss"], 1460)

    def test_signal_b_alone_not_blackhole(self):
        """仅 B 无 C (未提供 path_mtu) → 不判黑洞 (无法区分拥塞)。"""
        pkts = self._handshake_and_stall()
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertFalse(d.suspected_pmtud_blackhole)
        self.assertTrue(d.streams[0]["fullsize_stall"])

    def test_pppoe_normal_no_fire(self):
        """场景 3: PPPoE 正常 — MSS 1452, 零星重传无停滞, 两规则都不触发。"""
        pkts = [
            tcp(5001, 443, "S", seq=100, mss=1452, ts=T0),
            tcp_srv(443, 5001, "SA", seq=200, ack=101, mss=1452, ts=T0 + 0.02),
            tcp(5001, 443, "A", seq=101, ack=201, ts=T0 + 0.04),
        ]
        for i in range(30):                       # 30 段正常数据
            pkts.append(tcp(5001, 443, "PA", seq=101 + i * 100,
                            ack=201, payload=b"d" * 80, ts=T0 + 0.1 + i * 0.05))
        # 零星重传: 两个不同 seq 各重复 1 次 (间隔 <1s)
        pkts.append(tcp(5001, 443, "PA", seq=201, ack=201,
                        payload=b"d" * 80, ts=T0 + 1.0))
        pkts.append(tcp(5001, 443, "PA", seq=501, ack=201,
                        payload=b"d" * 80, ts=T0 + 1.3))
        d = N.PcapAnalyzer(path_mtu=1500).analyze(pkts)
        self.assertFalse(d.suspected_pmtud_blackhole)
        self.assertFalse(d.suspected_tcp_loss_burst)

    def test_congestion_loss_not_blackhole(self):
        """场景 4: 拥塞丢包 — 多流散布重传 ~10%, 无 full-size 停滞。"""
        pkts = []
        for f in range(5):
            sp = 6000 + f
            pkts.append(tcp(sp, 443, "S", seq=100, mss=1460, ts=T0 + f))
            pkts.append(tcp_srv(443, sp, "SA", seq=200, ack=101,
                                mss=1460, ts=T0 + f + 0.02))
            for i in range(20):
                pkts.append(tcp(sp, 443, "PA", seq=101 + i * 50,
                                ack=201, payload=b"x" * 40,
                                ts=T0 + 1 + f + i * 0.1))
                if i % 10 == 0:                    # 每流 2 次重传 → ~10%
                    pkts.append(tcp(sp, 443, "PA", seq=101 + i * 50,
                                    ack=201, payload=b"x" * 40,
                                    ts=T0 + 1 + f + i * 0.1 + 0.05))
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertTrue(d.suspected_tcp_loss_burst)
        self.assertFalse(d.suspected_pmtud_blackhole)
        self.assertEqual(d.tcp_retransmit_count, 10)


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestStreamReassembly(unittest.TestCase):
    """流重组轻量判据 (方案 §6.3)。"""

    def test_syn_retransmit_counted_separately(self):
        """场景 6: 同流 SYN×5 无 SYN-ACK → SYN 重传计数, 不算数据重传。"""
        pkts = [tcp(7000, 443, "S", seq=100, mss=1460, ts=T0 + i * 0.5)
                for i in range(5)]
        d = N.PcapAnalyzer().analyze(pkts)
        st = d.streams[0]
        self.assertEqual(st["syn_retrans_n"], 5)
        self.assertEqual(d.tcp_retransmit_count, 0)

    def test_same_seq_gap_over_1s_not_retrans(self):
        """场景 8 边界: 同 seq 间隔 >1s (慢速/应用层重发) 不计重传。"""
        pkts = [
            tcp(5002, 443, "PA", seq=101, ack=201, payload=b"z" * 300,
                ts=T0),
            tcp(5002, 443, "PA", seq=101, ack=201, payload=b"z" * 300,
                ts=T0 + 2.5),
        ]
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertEqual(d.tcp_retransmit_count, 0)

    def test_dup_ack_below_threshold_not_counted(self):
        """场景 8 边界: 重复 ack <3 次不计 dup ack。"""
        pkts = [
            tcp_srv(443, 5003, "A", seq=5000, ack=900, ts=T0),
            tcp_srv(443, 5003, "A", seq=5000, ack=900, ts=T0 + 0.01),
        ]
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertEqual(d.tcp_dup_ack_count, 0)

    def test_dup_ack_3x_counted(self):
        pkts = [tcp_srv(443, 5004, "A", seq=5000, ack=900, ts=T0 + i * 0.01)
                for i in range(4)]
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertGreaterEqual(d.tcp_dup_ack_count, 1)

    def test_rst_counted(self):
        pkts = [
            tcp(5005, 443, "S", seq=1, mss=1460, ts=T0),
            tcp_srv(443, 5005, "RA", seq=1, ack=2, ts=T0 + 0.02),
        ]
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertEqual(d.tcp_rst_count, 1)

    def test_zero_window_counted(self):
        pkts = [
            tcp(5006, 443, "A", seq=100, ack=200, win=0, ts=T0),
            tcp_srv(443, 5006, "A", seq=200, ack=100, win=0, ts=T0 + 0.1),
        ]
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertEqual(sum(s["zero_win_n"] for s in d.streams), 2)

    def test_directional_streams(self):
        """(src,sport,dst,dport) 有方向 — 客户端流与服务端流是两条记录。"""
        pkts = [
            tcp(5007, 443, "PA", seq=1, ack=1, payload=b"a" * 100, ts=T0),
            tcp_srv(443, 5007, "PA", seq=1, ack=101, payload=b"b" * 100,
                    ts=T0 + 0.1),
        ]
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertEqual(len(d.streams), 2)


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestDnsAndL7(unittest.TestCase):
    """DNS 慢查询 + SNI/Host 提取 (384B 内)。"""

    def test_dns_slow_queries(self):
        """场景 5: 3 组 query→resp 间隔 1.2~1.8s → 记录时长并触发。"""
        pkts = []
        names = []
        for i, gap in enumerate((1.2, 1.5, 1.8)):
            qid, port = 100 + i, 40000 + i
            name = f"slow{i}.example.com"
            names.append(name)
            pkts.append(dns_query(qid, name, port, ts=T0 + i * 10))
            pkts.append(dns_resp(qid, name, port, ts=T0 + i * 10 + gap))
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertEqual(d.dns_query_count, 3)
        self.assertEqual(len(d.dns_slow_queries), 3)
        durations = {r[2]: r[1] - r[0] for r in d.dns_slow_queries}
        for i, gap in enumerate((1.2, 1.5, 1.8)):
            self.assertAlmostEqual(durations[f"slow{i}.example.com"], gap,
                                   places=2)
        self.assertTrue(d.suspected_dns_slow)

    def test_dns_fast_not_flagged(self):
        pkts = [dns_query(1, "fast.example.com", 40001, ts=T0),
                dns_resp(1, "fast.example.com", 40001, ts=T0 + 0.03)]
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertEqual(d.dns_slow_queries, [])
        self.assertFalse(d.suspected_dns_slow)

    def test_sni_and_http_host_extracted(self):
        """场景 7: ClientHello SNI + HTTP GET Host。"""
        rec = _sni_record(b"www.example.com")
        get = (b"GET /path?q=1 HTTP/1.1\r\nHost: api.example.com\r\n"
               b"User-Agent: t\r\n\r\n")
        pkts = [
            tcp(5008, 443, "PA", seq=101, ack=201, payload=rec, ts=T0),
            tcp(5009, 80, "PA", seq=101, ack=201, payload=get, ts=T0 + 0.1),
        ]
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertIn("www.example.com", d.tls_sni)
        self.assertIn("api.example.com", d.http_hosts)

    def test_sni_truncated_recorded(self):
        """SNI 超出 384B 截断窗口 → 记 sni_truncated, 不崩不误报。"""
        rec = _sni_record(b"long.example.com", pad_before=400)
        pkts = [tcp(5010, 443, "PA", seq=101, ack=201,
                    payload=rec[:384], ts=T0)]   # 模拟抓包层 384B 截断
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertIn("sni_truncated", d.tls_sni)
        self.assertNotIn("long.example.com", d.tls_sni)

    def test_quic_counted(self):
        pkts = [
            Ether(src="aa", dst="bb") / IP(src=CLI, dst=SRV) /
            UDP(sport=50000, dport=443) / Raw(b"Q" * 40),
            Ether(src="aa", dst="bb") / IP(src=CLI, dst=SRV) /
            UDP(sport=50001, dport=443) / Raw(b"Q" * 40),
        ]
        for p, t in zip(pkts, (T0, T0 + 0.1)):
            p.time = t
        d = N.PcapAnalyzer().analyze(pkts)
        self.assertEqual(d.udp443_pkts, 2)


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestAnalyzerIntegration(unittest.TestCase):
    """pcap 文件输入 + 可序列化输出 (挂 results_dict["capture"])。"""

    def test_analyze_pcap_file(self):
        from scapy.all import wrpcap
        import tempfile
        pkts = self_sync = [tcp(5011, 443, "S", seq=100, mss=1460, ts=T0),
                            tcp_srv(443, 5011, "SA", seq=200, ack=101,
                                    mss=1460, ts=T0 + 0.02)]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "slice.pcap")
            wrpcap(path, pkts)
            d = N.PcapAnalyzer().analyze(path)
        self.assertEqual(len(d.streams), 2)
        self.assertEqual(d.streams[0]["syn_mss"], 1460)

    def test_to_dict_json_serializable(self):
        pkts = [tcp(5012, 443, "S", seq=100, mss=1460, ts=T0)]
        d = N.PcapAnalyzer(path_mtu=1280).analyze(pkts)
        import json
        blob = json.dumps(d.to_dict(), ensure_ascii=False)
        self.assertIn("streams", blob)
        self.assertIn("suspected_pmtud_blackhole", blob)

    def test_empty_input(self):
        d = N.PcapAnalyzer().analyze([])
        self.assertFalse(d.suspected_pmtud_blackhole)
        self.assertEqual(d.streams, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
