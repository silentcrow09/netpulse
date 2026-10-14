# -*- coding: utf-8 -*-
"""v1.14.14 P0 回归: 抓包离线分析必须走**生产管线**才有效。

背景 (真实缺陷): 隐私剥除发生在 sniffer 回调里 (`_PcapCaptureSession.start`
的 `_prn`), 环形缓冲 / 事件切片 / PcapAnalyzer 全都只见过"剥掉载荷的包"。
分析器此前用 `bytes(tcp.payload)` 判段长 —— 剥后恒为 0, 于是:
  * 数据段被当成纯 ACK → 信号 B (full-size 段同序号停滞) 永不触发,
    对外主推的 "A 或 B∧C 判 PMTU 黑洞" 实际只剩 A;
  * `tcp_retransmit_count` 恒 0, `LOSS_MIN_SEGS` 门槛不可达;
  * 被剥掉载荷的数据段喂进 `_dup_ack` → **正常传输被伪报成 dup-ack 突发**。
`tests/test_pcap_analyzer.py` 20 个用例全绿是因为它们用**未剥离**的合成包
直接喂分析器, 从不经过 `_capture_strip_packet` —— 测试验的是错误的对象。

修法: 剥除时不再改写 IP 总长 (保留原值), 并给包挂 `.wirelen` = 线上原始
长度; wrpcap 据此写出 caplen < wirelen 的标准 snaplen 截断记录。分析器改用
「IP 总长 − 头长」反推真实段长。

本文件锁住整条链路: _capture_strip_packet → _PcapRingBuffer → _write_pcap
→ PcapAnalyzer。任何一环退回"按幸存载荷判段长"都会红。

运行: cd 到项目根目录, `python tests/test_pcap_pipeline_e2e.py`
"""
import os
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

N._ensure_scapy()          # scapy 懒加载契约: 碰裸名之前先保证已加载

try:
    from scapy.all import Ether, IP, TCP, Raw
    SCAPY_OK = True
except Exception:                                        # pragma: no cover
    SCAPY_OK = False

T0 = 1700000000.0
CLI = ("192.168.1.5", 40000, "223.5.5.5", 443)


def _mk(src, sport, dst, dport, flags, seq, ack=0, n=0, t=0.0, mss=None):
    opts = [("MSS", mss)] if mss else []
    p = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
         IP(src=src, dst=dst) /
         TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, options=opts))
    if n:
        p = p / Raw(b"D" * n)
    p.time = T0 + t
    return p


def _stalled_blackhole_flow():
    """PMTU 黑洞的经典形态: 握手 MSS 1460 + full-size 段同 seq 停滞重传 3 次
    + 小包仍在流动 (信号 B 的两个前提)。"""
    return [
        _mk(*CLI, "S", 1000, 0, 0, 0.00, mss=1460),
        _mk(CLI[2], CLI[3], CLI[0], CLI[1], "SA", 5000, 1001, 0, 0.02, mss=1460),
        _mk(*CLI, "PA", 1001, 5001, 1448, 0.10),
        _mk(*CLI, "PA", 1001, 5001, 1448, 0.35),
        _mk(*CLI, "PA", 1001, 5001, 1448, 0.60),
        _mk(*CLI, "A", 1549, 5000, 0, 0.80),
        _mk(*CLI, "A", 1549, 6000, 0, 0.85),
        _mk(*CLI, "A", 1549, 7000, 0, 0.90),
    ]


def _healthy_flow():
    """正常传输: 满载段各不重复 (无重传), 不应产生任何异常证据。"""
    out = [
        _mk(*CLI, "S", 1000, 0, 0, 0.00, mss=1460),
        _mk(CLI[2], CLI[3], CLI[0], CLI[1], "SA", 5000, 1001, 0, 0.02, mss=1460),
    ]
    for k in range(6):
        out.append(_mk(*CLI, "PA", 1001 + k * 1448, 5001, 1448, 0.1 + k * 0.02))
    return out


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestCapturePipelineEndToEnd(unittest.TestCase):
    """走真实管线: 剥载荷 → 环形缓冲 → 切片落盘 → 离线分析。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="np_e2e_")
        patcher = mock.patch.object(N, "_captures_dir", lambda: self.tmp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run_pipeline(self, flow):
        """生产管线原样复现 (剥载荷在回调里 → 环形缓冲 → _write_pcap)。"""
        ring = N._PcapRingBuffer(4 * 1024 * 1024)
        flow_state = {}
        for p in flow:
            ring.push(N._capture_strip_packet(p, flow_state))

        sess = N._PcapCaptureSession.__new__(N._PcapCaptureSession)
        sess._start_stamp = "TEST"
        path = N._PcapCaptureSession._write_pcap(sess, ring.packets(), "e2e")
        self.assertTrue(path and os.path.exists(path), "切片落盘失败")
        return path

    @staticmethod
    def _records(path):
        """解 pcap 记录头, 返回 [(caplen, wirelen), ...]。"""
        out, off = [], 24
        with open(path, "rb") as f:
            data = f.read()
        while off + 16 <= len(data):
            _, _, incl, orig = struct.unpack("<IIII", data[off:off + 16])
            out.append((incl, orig))
            off += 16 + incl
        return out

    # ---- 信号 B 必须在生产路径上真的触发 -------------------------------
    def test_signal_b_survives_stripping(self):
        path = self._run_pipeline(_stalled_blackhole_flow())
        d = N.PcapAnalyzer(path_mtu=1280).analyze(path).to_dict()
        self.assertTrue(
            d["streams"][0]["fullsize_stall"],
            "full-size 段停滞未被识别 —— 分析器可能在按剥后 payload 判段长")
        self.assertTrue(
            d["suspected_pmtud_blackhole"],
            "B∧C 应判 PMTU 黑洞 (path_mtu=1280 < MSS 1460)")
        self.assertGreater(d["tcp_retransmit_count"], 0,
                           "重传统计为 0 —— 同 seq 重复段未被计入")

    def test_no_fabricated_dup_ack_on_normal_traffic(self):
        """反向回归: 正常传输不得被伪报成 dup-ack 突发。"""
        path = self._run_pipeline(_healthy_flow())
        d = N.PcapAnalyzer().analyze(path).to_dict()
        self.assertEqual(d["tcp_dup_ack_count"], 0,
                         "正常传输被伪报成 dup-ack —— 数据段又被当成纯 ACK 了")
        self.assertEqual(d["tcp_retransmit_count"], 0)
        self.assertFalse(d["suspected_pmtud_blackhole"])
        self.assertFalse(d["suspected_tcp_loss_burst"])

    # ---- pcap 文件形态: 标准 snaplen 截断 -------------------------------
    def test_pcap_records_use_snaplen_truncation(self):
        """截断记录必须 caplen < wirelen (等价 tcpdump -s): 记录自己声明
        "线上更长、只抓到前 N 字节", Wireshark 才不会按序列空洞误报
        ACKed lost segment。"""
        path = self._run_pipeline(_stalled_blackhole_flow())
        recs = self._records(path)
        self.assertTrue(recs)
        truncated = [r for r in recs if r[0] < r[1]]
        self.assertTrue(truncated, "没有任何记录带截断信息 —— .wirelen 没写进去")

    def test_ip_total_length_preserved_after_strip(self):
        """剥除后 IP 总长必须保留原值 (分析器据此反推段长)。"""
        raw = _mk(*CLI, "PA", 1001, 5001, 1448, 0.10)
        kept = N._capture_strip_packet(raw, {})
        self.assertLess(len(bytes(kept)), len(bytes(raw)), "包未被截断")
        self.assertEqual(int(kept[IP].len), int(1448 + 20 + 20),
                         "IP 总长被改写 —— 无法反推真实段长")
        self.assertEqual(getattr(kept, "wirelen", None), len(bytes(raw)),
                         ".wirelen 未挂上原始线长")

    def test_timestamps_survive_strip_and_write(self):
        """时间轴是盯障报告的地基, 截断重建不能把时间戳弄丢。"""
        path = self._run_pipeline(_stalled_blackhole_flow())
        d = N.PcapAnalyzer().analyze(path)
        self.assertTrue(d.streams, "没有解析出任何流")


if __name__ == "__main__":
    unittest.main(verbosity=2)
