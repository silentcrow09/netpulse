# -*- coding: utf-8 -*-
"""一次性迁移: 修复 v1.9.8 及更早版本落盘的截断 pcap (IP.len 虚高)。

旧版 _capture_strip_packet 截断重建未改 IP Total Length → Wireshark 对
61.8% 的包误报 ACKed lost/Dup ACK 满屏红。本脚本复用 v1.9.9 的
_patch_ip_lengths 对旧文件就地修正, 输出 _fixed.pcap (字节级修复,
不重新截断/不丢包), 供 Wireshark 对照。
用法: python _migrate_pcap.py <输入.pcap> [输出.pcap]
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netpulse as N  # noqa: E402
N._ensure_scapy()
from scapy.all import rdpcap, wrpcap, Ether, IP  # noqa: E402


def fix_pcap_bytes(raw):
    """对单包原始字节做长度修正 (与 _capture_strip_packet 同源解析)。"""
    if len(raw) < 34:
        return None
    ethertype = (raw[12] << 8) | raw[13]
    ip_off = 14
    if ethertype == 0x8100:            # 单层 VLAN
        if len(raw) < 38:
            return None
        ethertype = (raw[16] << 8) | raw[17]
        ip_off = 18
    if ethertype != 0x0800:
        return None
    ihl = (raw[ip_off] & 0x0F) * 4
    if ihl < 20 or len(raw) < ip_off + ihl:
        return None
    ip_total = (raw[ip_off + 2] << 8) | raw[ip_off + 3]
    actual = len(raw) - ip_off
    if ip_total <= actual:             # 无需修正 (整包或已修正)
        return None
    proto = raw[ip_off + 9]
    l4_off = ip_off + ihl
    if proto == 17 and len(raw) < l4_off + 8:
        return None                   # UDP 头不完整: 修长度会越界写 (主代码同守卫)
    buf = bytearray(raw)
    N._patch_ip_lengths(buf, ip_off, ihl, l4_off, proto)
    return bytes(buf)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.splitext(src)[0] + "_fixed.pcap"
    pkts = rdpcap(src)
    fixed = unchanged = 0
    out = []
    for p in pkts:
        rb = fix_pcap_bytes(bytes(p))
        if rb is None:
            unchanged += 1
            out.append(p)
        else:
            fixed += 1
            np_ = Ether(rb)
            np_.time = p.time
            out.append(np_)
    wrpcap(dst, out)
    print(f"输入: {src}")
    print(f"修正: {fixed} 包 | 无需修正: {unchanged} 包")
    print(f"输出: {dst}  (用 Wireshark 打开对照红底)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
