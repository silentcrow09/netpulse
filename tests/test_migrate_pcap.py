# -*- coding: utf-8 -*-
"""_migrate_pcap.py 回归测试 (v1.9.10)

覆盖 fix_pcap_bytes 的边界:
  - UDP 包被 snaplen 截到 L4 头中间: 必须原样跳过 (旧版越界写 IndexError)
  - 完整 UDP 头 + 载荷被截: IP 总长 / UDP 长度修正 + 校验和重算
  - 未截断 / 非 IPv4: 原样跳过
跑用: cd 到项目根目录, `python tests/test_migrate_pcap.py`
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402,F401  (迁移脚本 import 时需在同目录可寻)

try:
    import _migrate_pcap as M   # 模块顶层 _ensure_scapy; 无 scapy 环境 ImportError
except ImportError:
    M = None


def _ipv4_udp_raw(udp_bytes, ip_total=200, flags_frag=0):
    """手工以太帧: Ether(14) + IPv4(20, proto=17, 总长字段=ip_total) + udp_bytes。

    flags_frag: 16-bit Flags+分片偏移字段 (0x2000=MF)。布局: [0:6] dst /
    [6:12] src / [12:14] 0x0800 / [14] 0x45 / [16:18] IP 总长 /
    [20:22] Flags+frag / [23] proto=17 / [24:26] IP 校验和(先置 0) / [34:] UDP。"""
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    ip = bytes([0x45, 0, (ip_total >> 8) & 0xFF, ip_total & 0xFF,
                0, 0, (flags_frag >> 8) & 0xFF, flags_frag & 0xFF,
                64, 17, 0, 0]) \
        + b"\x0a\x00\x00\x01" + b"\xc0\xa8\x01\x01"
    return eth + ip + udp_bytes


@unittest.skipUnless(M is not None, "scapy 不可用, 跳过迁移脚本测试")
class TestFixPcapBytes(unittest.TestCase):

    def test_truncated_udp_header_skipped_no_indexerror(self):
        """v1.9.10 回归: UDP 头不完整 (36B, 到 dport 只剩 2B) 必须跳过。

        旧版无守卫, _patch_ip_lengths 写 buf[l4_off+4..7] 越界 → IndexError
        中途崩、无输出文件。"""
        raw = _ipv4_udp_raw(b"\x01\xbb")            # 14+20+2 = 36 字节
        self.assertEqual(len(raw), 36)
        self.assertIsNone(M.fix_pcap_bytes(raw),
                          "UDP 头不完整必须原样跳过 (不得越界写/抛 IndexError)")

    def test_truncated_quic_payload_patched(self):
        """完整 UDP 头 + 载荷截断 (50B, IP 总长虚报 200): 长度修正 + 校验和重算。"""
        raw = _ipv4_udp_raw(b"\x01\xbb\x01\xbb\x00\x30\x00\x18" + b"\xff" * 8)
        fixed = M.fix_pcap_bytes(raw)
        self.assertIsNotNone(fixed)
        self.assertEqual(fixed[16:18], (36).to_bytes(2, "big"),
                         "IP 总长须修为 帧长-14 = 36")
        self.assertEqual(fixed[38:40], (16).to_bytes(2, "big"),
                         "UDP 长度须修为 帧长-34 = 16")
        self.assertEqual(fixed[40:42], b"\x00\x00",
                         "UDP 校验和须置 0 (载荷已剥, RFC 768 0=未计算)")
        self.assertNotEqual(fixed[24:26], b"\x00\x00",
                            "IP 校验和必须重算 (原值已随长度字段失效)")

    def test_full_packet_untouched(self):
        """IP 总长与实际一致 (整包或已修正): 原样跳过。"""
        raw = _ipv4_udp_raw(b"\x01\xbb\x01\xbb\x00\x30\x00\x18" + b"\xff" * 8,
                            ip_total=36)
        self.assertIsNone(M.fix_pcap_bytes(raw))

    def test_first_fragment_left_untouched(self):
        """v1.9.11: MF 首片不做长度改写 — 改短会与后续分片偏移脱节, 重组报错。"""
        raw = _ipv4_udp_raw(b"\x01\xbb\x01\xbb\x00\x30\x00\x18" + b"\xff" * 8,
                            ip_total=200, flags_frag=0x2000)
        self.assertIsNone(M.fix_pcap_bytes(raw), "分片包必须原样跳过")

    def test_non_ipv4_skipped(self):
        raw = b"\xaa" * 6 + b"\xbb" * 6 + b"\x86\xdd" + b"\x00" * 40
        self.assertIsNone(M.fix_pcap_bytes(raw), "非 IPv4 (IPv6) 不得改写")


if __name__ == "__main__":
    unittest.main(verbosity=2)
