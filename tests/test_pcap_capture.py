# -*- coding: utf-8 -*-
"""盯障抓包层单元测试 (阶段 F · v1.8.0 PR-F1/F2 引入)

覆盖: _PcapRingBuffer 字节记账 / _capture_strip_packet 剥 payload 矩阵 /
切片窗口与落盘命名 / 清理策略 / 检查链降级 (无 Npcap 也能跑, 全合成数据)。
跑用: cd 到项目根目录, `python tests/test_pcap_capture.py`
"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

# v1.9.7 PR-2 (scapy 懒加载) 契约: 任何 mock netpulse.conf / netpulse.get_if_list
# 的测试必须在打补丁前先完成 scapy 绑定 — 否则函数入口 _ensure_scapy() 触发的
# _load_scapy() 会把真实对象写回 globals, 覆盖 mock。
N._ensure_scapy()

try:
    from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, wrpcap, rdpcap
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

_t0 = 1700000000.0


def _pkt(payload=b"X" * 800, sport=5000, dport=443, proto=TCP, ts=None):
    l4 = (proto() if proto is ICMP else proto(sport=sport, dport=dport))
    p = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
        IP(src="192.168.1.5", dst="223.5.5.5") / l4 / Raw(payload)
    p.time = ts if ts is not None else _t0
    return p


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestPcapRingBuffer(unittest.TestCase):
    """字节记账 (v1 方案的 maxlen 数包不数字节, 会把预算用爆)。"""

    def _fill(self, limit_bytes, n=1000, size=1000):
        ring = N._PcapRingBuffer(limit_bytes)
        for k in range(n):
            p = Ether() / IP() / TCP(sport=1000 + k, dport=22) / Raw(b"R" * size)
            p.time = _t0 + k
            ring.push(p)
        return ring

    def test_byte_limit_keeps_newest(self):
        ring = self._fill(64 * 1024)
        self.assertLessEqual(ring.cur_bytes, 64 * 1024 + 1100)  # 挤到 ≤1 包超额
        self.assertGreater(ring.dropped, 0)
        newest = ring.packets()[-1]
        self.assertLess(abs(float(newest.time) - (_t0 + 999)), 0.001)

    def test_slice_window_filters_by_time(self):
        ring = self._fill(10 * 1024 * 1024, n=100)   # 不触发挤出
        got = ring.slice_window(_t0 + 10, _t0 + 12)
        self.assertEqual(len(got), 3)
        self.assertTrue(all(_t0 + 10 <= float(p.time) <= _t0 + 12 for p in got))

    def test_zero_ring_edge(self):
        ring = N._PcapRingBuffer(1024)
        self.assertEqual(ring.slice_window(0, 1e12), [])
        self.assertEqual(len(ring), 0)


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestCaptureStripPacket(unittest.TestCase):
    """剥 payload 矩阵 (方案 §5.2)。"""

    def test_plain_tcp_truncated_to_header(self):
        out = N._capture_strip_packet(_pkt(dport=22, proto=TCP), {})
        self.assertEqual(len(bytes(out)), 14 + 20 + 20)   # Ether+IP+TCP 头

    def test_web_port_first_two_pkts_keep_384(self):
        fs = {}
        p = _pkt(dport=443)
        sizes = [len(bytes(N._capture_strip_packet(p, fs))) for _ in range(3)]
        self.assertEqual(sizes, [54 + 384, 54 + 384, 54])

    def test_reverse_direction_is_separate_flow(self):
        fs = {}
        N._capture_strip_packet(_pkt(sport=5000, dport=443), fs)
        rev = N._capture_strip_packet(_pkt(sport=443, dport=5000), fs)
        self.assertEqual(len(bytes(rev)), 54 + 384)

    def test_port_80_8080_same_policy(self):
        for port in (80, 8080):
            fs = {}
            a = len(bytes(N._capture_strip_packet(_pkt(dport=port), fs)))
            b = len(bytes(N._capture_strip_packet(_pkt(dport=port), fs)))
            c = len(bytes(N._capture_strip_packet(_pkt(dport=port), fs)))
            self.assertEqual((a, b, c), (54 + 384, 54 + 384, 54), f"port {port}")

    def test_dns_kept_whole(self):
        p = _pkt(payload=b"D" * 200, sport=53, dport=5000, proto=UDP)
        self.assertEqual(len(bytes(N._capture_strip_packet(p, {}))),
                         len(bytes(p)))

    def test_icmp_kept_whole(self):
        p = _pkt(payload=b"I" * 64, proto=ICMP)
        # ICMP 无端口概念 — 构造时 sport/dport 参数被忽略
        self.assertEqual(len(bytes(N._capture_strip_packet(p, {}))),
                         len(bytes(p)))

    def test_quic_truncated_to_16b(self):
        out = N._capture_strip_packet(_pkt(payload=b"Q" * 400, dport=443,
                                           proto=UDP), {})
        self.assertEqual(len(bytes(out)), 14 + 20 + 8 + 16)

    def test_short_packet_passthrough(self):
        p = Ether(src="aa", dst="bb") / b"\x08\x00"   # 不满 IP 头
        out = N._capture_strip_packet(p, {})
        self.assertEqual(bytes(out), bytes(p))

    def test_timestamp_preserved_after_trim(self):
        out = N._capture_strip_packet(_pkt(dport=22), {})
        self.assertEqual(float(out.time), _t0)

    def test_no_payload_packet_not_rebuilt(self):
        """纯头包 (ACK) 无 payload 可剥 — 原对象直接返回 (零成本)。"""
        p = _pkt(payload=b"", dport=22)
        out = N._capture_strip_packet(p, {})
        self.assertIs(out, p)

    # ---- v1.9.9: 截断包长度字段修正 (Wireshark 满屏红底修复) ----

    @staticmethod
    def _ip_checksum_valid(ip_bytes):
        """IPv4 头校验和验证: 16-bit 反码求和 (含 checksum 字段) 折叠后为 0xFFFF。"""
        ihl = (ip_bytes[0] & 0x0F) * 4
        total = 0
        for i in range(0, ihl, 2):
            total += (ip_bytes[i] << 8) | ip_bytes[i + 1]
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return total == 0xFFFF

    def test_trimmed_tcp_ip_len_consistent(self):
        """截断后 IP Total Length 必须等于实际字节数 (否则 Wireshark 假阳性)。"""
        out = N._capture_strip_packet(_pkt(dport=22), {})
        ipb = bytes(out[IP])
        self.assertEqual(out[IP].len, len(ipb),
                         f"IP.len={out[IP].len} 实际={len(ipb)} — 必须一致")

    def test_trimmed_tcp_ip_checksum_recomputed(self):
        out = N._capture_strip_packet(_pkt(dport=22), {})
        ipb = bytes(out[IP])
        self.assertTrue(self._ip_checksum_valid(ipb),
                        "改 IP.len 后校验和必须重算, 否则 Wireshark 报 checksum 错")

    def test_trimmed_web_first_pkt_len_consistent(self):
        """每流前 2 包保留 384B 的截断路径同样修正长度。"""
        out = N._capture_strip_packet(_pkt(dport=443), {})
        ipb = bytes(out[IP])
        self.assertEqual(out[IP].len, len(ipb))
        self.assertTrue(self._ip_checksum_valid(ipb))

    def test_quic_ip_len_and_udp_fields_fixed(self):
        """UDP (QUIC) 截断: IP.len + UDP length 修正, UDP checksum 置 0。"""
        out = N._capture_strip_packet(_pkt(payload=b"Q" * 400, dport=443,
                                           proto=UDP), {})
        ipb = bytes(out[IP])
        self.assertEqual(out[IP].len, len(ipb))
        self.assertTrue(self._ip_checksum_valid(ipb))
        self.assertEqual(out[UDP].len, 8 + 16,
                         f"UDP length 应=头+保留 16B, 实际 {out[UDP].len}")
        self.assertEqual(out[UDP].chksum, 0,
                         "载荷已剥, UDP checksum 应置 0 (未计算)")

    def test_roundtrip_ip_len_stable(self):
        """写盘重读后字段保持一致 (wrpcap/rdpcap 不再改长度)。"""
        from scapy.all import wrpcap, rdpcap
        out = N._capture_strip_packet(_pkt(dport=22), {})
        with tempfile.NamedTemporaryFile(suffix=".pcap",
                                         delete=False) as tf:
            tpath = tf.name
        try:
            wrpcap(tpath, [out])
            back = rdpcap(tpath)[0]
            self.assertEqual(back[IP].len, len(bytes(back[IP])))
        finally:
            try:
                os.unlink(tpath)
            except OSError:
                pass

    # ---- v1.9.11: 分片包整包保留 (改写首片 IP 总长会与后续分片偏移脱节) ----

    def test_mf_first_fragment_kept_whole(self):
        """MF 置位首片: 不得截断 (改短 IP 总长 → Wireshark 重组报 hole)。"""
        p = _pkt(payload=b"F" * 400, dport=443, proto=UDP)
        p[IP].flags = "MF"
        out = N._capture_strip_packet(p, {})
        self.assertEqual(len(bytes(out)), len(bytes(p)), "MF 首片必须整包保留")

    def test_nonfirst_fragment_kept_whole(self):
        """frag_off≠0 非首片 (BPF 端口过滤本不该放行, 防御性整包保留)。"""
        p = _pkt(payload=b"F" * 400, dport=443, proto=UDP)
        p[IP].frag = 185                       # 1480/8, 单位 8 字节
        out = N._capture_strip_packet(p, {})
        self.assertEqual(len(bytes(out)), len(bytes(p)), "非首片必须整包保留")


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestSliceWriteAndCleanup(unittest.TestCase):
    """切片落盘命名 + 清理策略 (PR-F2)。"""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="npcap_test_")
        self._patch = mock.patch("netpulse._captures_dir",
                                 return_value=self._tmp)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_write_pcap_naming_and_roundtrip(self):
        sess = N._PcapCaptureSession("slice", 8)
        sess.available = True
        sess._start_stamp = "20260901_120000"
        pkts = [_pkt(dport=22, ts=_t0 + k) for k in range(5)]
        path = sess._write_pcap(pkts, f"{sess._start_stamp}_slice_outage")
        self.assertIsNotNone(path)
        self.assertTrue(path.endswith(
            "monitor_20260901_120000_slice_outage.pcap"))
        back = rdpcap(path)
        self.assertEqual(len(back), 5)
        self.assertTrue(all(bytes(a) == bytes(b)
                            for a, b in zip(pkts, back)))

    def test_flush_due_slices_window_and_pending(self):
        sess = N._PcapCaptureSession("slice", 8)
        sess.available = True
        sess._start_stamp = "20260901_120000"
        for k in range(100):
            sess.ring = sess.ring or N._PcapRingBuffer(1024 * 1024)
            p = _pkt(dport=22, ts=_t0 + k)
            sess.ring.push(p)
        ev = {"type": "outage", "stream": "ext", "start_ts": _t0 + 50,
              "end_ts": _t0 + 53}
        now = _t0 + 100
        sess._pending = [{"due": _t0 + 83, "ev": ev}]     # 已到期
        sess._flush_due_slices(now)
        self.assertEqual(sess._pending, [])               # 已消费
        self.assertEqual(len(sess.slices), 1)
        s = sess.slices[0]
        self.assertEqual(s["event_type"], "outage")
        # 窗口 [start-30, min(end+30, now)] = [20, 83], 整数时间戳 64 个包
        self.assertEqual(s["pkts"], 64)
        self.assertEqual(sess._pending, [])
        # 未到期的不落盘
        sess._pending = [{"due": now + 50, "ev": ev}]
        sess._flush_due_slices(now)
        self.assertEqual(len(sess._pending), 1)

    def test_cleanup_by_age_and_count(self):
        d = self._tmp
        # 场景 1: 12 个文件, 最老 3 个超龄 → 删 3; 剩 9 ≤ 上限 10, 不再删
        paths = []
        for i in range(12):
            p = os.path.join(d, f"monitor_slice_{i:02d}.pcap")
            with open(p, "w") as f:
                f.write("x")
            paths.append(p)
        old = time.time() - 8 * 86400
        for p in paths[:3]:
            os.utime(p, (old, old))
        removed = N._cleanup_old_captures(d)
        self.assertEqual(removed, 3)
        remain = set(os.listdir(d))
        self.assertEqual(len(remain), 9)
        self.assertFalse(any(os.path.basename(p) in remain for p in paths[:3]))
        # 场景 2: 全新 12 个文件 (无超龄) → 只按个数删最旧 2 个, 剩 10
        now = time.time()
        alive = [p for p in paths if os.path.exists(p)]      # 9 个
        for i in range(3):                                   # 补到 12 个
            p = os.path.join(d, f"monitor_slice_{12 + i:02d}.pcap")
            with open(p, "w") as f:
                f.write("x")
            alive.append(p)
        for i, p in enumerate(alive):                        # mtime 按序递增
            os.utime(p, (now - 2000 + i, now - 2000 + i))
        removed2 = N._cleanup_old_captures(d)
        self.assertEqual(removed2, 2)
        remain2 = set(os.listdir(d))
        self.assertEqual(len(remain2), N.CAPTURE_MAX_FILES)
        self.assertNotIn(os.path.basename(alive[0]), remain2)   # 最旧先删
        self.assertNotIn(os.path.basename(alive[1]), remain2)

    def test_cleanup_missing_dir_silent(self):
        self.assertEqual(N._cleanup_old_captures(
            os.path.join(self._tmp, "nope")), 0)


class TestCapturePrecheckChain(unittest.TestCase):
    """检查链降级 (方案 §5.4): 任一失败 → available=False + 客户语言提示,
    不抛异常。全合成前置, 不需要 Npcap/管理员。"""

    def test_no_scapy_flag_disables(self):
        sess = N._PcapCaptureSession("slice", 8)
        with mock.patch("netpulse.FORCE_NO_SCAPY", True):
            self.assertFalse(sess.precheck())
        self.assertIn("--no-scapy", sess.unavailable_reason)

    def test_scapy_missing_disables(self):
        sess = N._PcapCaptureSession("slice", 8)
        with mock.patch("netpulse.FORCE_NO_SCAPY", False), \
             mock.patch("netpulse.SCAPY_AVAILABLE", False):
            self.assertFalse(sess.precheck())
        self.assertIn("scapy", sess.unavailable_reason)

    def test_no_npcap_disables_with_install_hint(self):
        sess = N._PcapCaptureSession("slice", 8)
        with mock.patch("netpulse.SCAPY_AVAILABLE", True), \
             mock.patch("netpulse._npcap_installed", return_value=False):
            self.assertFalse(sess.precheck())
        self.assertIn("npcap.com", sess.unavailable_reason)

    def test_non_admin_disables(self):
        sess = N._PcapCaptureSession("slice", 8)
        with mock.patch("netpulse.SCAPY_AVAILABLE", True), \
             mock.patch("netpulse._npcap_installed", return_value=True), \
             mock.patch("netpulse._is_admin", return_value=False):
            self.assertFalse(sess.precheck())
        self.assertIn("管理员", sess.unavailable_reason)

    def test_max_mb_clamped(self):
        self.assertEqual(N._PcapCaptureSession("slice", 1).max_mb, 8)

    def test_capture_mb_minimum_in_cli(self):
        """CLI --capture-mb 声明默认值与 help (防漂移)。"""
        self.assertEqual(N.CAPTURE_DEFAULT_MB, 64)
        self.assertEqual(N.CAPTURE_PAYLOAD_KEEP, 384)
        self.assertEqual(N.CAPTURE_TRIGGER_TYPES,
                         ("outage", "jitter_burst", "tcp_fail",
                          "tcp_retrans_burst"))
        self.assertNotIn("mtu_mismatch", N.CAPTURE_TRIGGER_TYPES)


class TestCaptureDefaultIface(unittest.TestCase):
    """默认路由接口解析: scapy 2.7 route() 3 元组 iface 在 [0] —
    实机踩过 [2]=网关 IP 当接口名, 嗅探线程静默死掉 0 包 (v1.8.0 修复)。"""

    def test_route_first_element_used_when_in_iflist(self):
        with mock.patch("netpulse.conf") as m_conf, \
             mock.patch("netpulse.get_if_list",
                        return_value=["\\Device\\NPF_{A}", "\\Device\\NPF_{B}"]):
            m_conf.route.route.return_value = ("\\Device\\NPF_{A}",
                                               "192.168.133.5", "172.25.131.254")
            self.assertEqual(N._capture_default_iface(), "\\Device\\NPF_{A}")

    def test_fallback_to_conf_iface_when_route_iface_unknown(self):
        with mock.patch("netpulse.conf") as m_conf, \
             mock.patch("netpulse.get_if_list", return_value=["\\Device\\NPF_{X}"]):
            m_conf.route.route.return_value = ("172.25.131.254",   # 网关被误当 iface
                                               "192.168.133.5", "0.0.0.0")
            m_conf.iface = "\\Device\\NPF_{X}"
            self.assertEqual(N._capture_default_iface(), "\\Device\\NPF_{X}")

    def test_route_exception_falls_back(self):
        with mock.patch("netpulse.conf") as m_conf, \
             mock.patch("netpulse.get_if_list", return_value=[]):
            m_conf.route.route.side_effect = RuntimeError("boom")
            m_conf.iface = "\\Device\\NPF_{X}"
            self.assertEqual(N._capture_default_iface(), "\\Device\\NPF_{X}")

    def test_all_fail_returns_none(self):
        with mock.patch("netpulse.conf") as m_conf, \
             mock.patch("netpulse.get_if_list", return_value=[]):
            m_conf.route.route.side_effect = RuntimeError("boom")
            m_conf.iface = ""
            self.assertIsNone(N._capture_default_iface())

    def test_precheck_sets_iface_from_helper(self):
        sess = N._PcapCaptureSession("slice", 8)
        with mock.patch("netpulse.SCAPY_AVAILABLE", True), \
             mock.patch("netpulse._npcap_installed", return_value=True), \
             mock.patch("netpulse._is_admin", return_value=True), \
             mock.patch("netpulse._capture_default_iface",
                        return_value="\\Device\\NPF_{OK}"):
            self.assertTrue(sess.precheck())
        self.assertEqual(sess.iface, "\\Device\\NPF_{OK}")


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestSnifferLivenessGuard(unittest.TestCase):
    """start() 验活: 嗅探线程静默死亡 (接口错/驱动错) → 按启动失败降级,
    不再出现「已启动」后面跟 0 包的假成功。"""

    def test_dead_thread_reported_as_start_failure(self):
        sess = N._PcapCaptureSession("slice", 8)
        sess.available = True
        _dead = mock.Mock()
        _dead.is_alive.return_value = False
        _sniffer = mock.Mock(thread=_dead)
        with mock.patch("scapy.all.AsyncSniffer", return_value=_sniffer), \
             mock.patch("netpulse._cleanup_old_captures", return_value=0):
            self.assertFalse(sess.start())
        self.assertIn("接口或驱动异常", sess.unavailable_reason)
        _sniffer.stop.assert_called()               # 死线程也走收尾

    def test_live_thread_starts_ok(self):
        sess = N._PcapCaptureSession("slice", 8)
        sess.available = True
        _alive = mock.Mock()
        _alive.is_alive.return_value = True
        _sniffer = mock.Mock(thread=_alive)
        with mock.patch("scapy.all.AsyncSniffer", return_value=_sniffer), \
             mock.patch("netpulse._cleanup_old_captures", return_value=0):
            self.assertTrue(sess.start())
        self.assertIs(sess._sniffer, _sniffer)


class TestCaptureFirstUseConfirm(unittest.TestCase):
    """首次 --capture 隐私确认 (PR-F5): 只问一次 / y 落标记 / 拒绝即降级。"""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="npcap_ack_")
        self._patch = mock.patch("netpulse._captures_dir",
                                 return_value=self._tmp)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self._ack = os.path.join(self._tmp, ".capture_ack")

    def _tty(self, answer):
        """模拟交互 TTY: isatty=True + input 返回 answer。"""
        _stdin = mock.patch("sys.stdin")
        m = _stdin.start()
        m.isatty.return_value = True
        self.addCleanup(_stdin.stop)
        return mock.patch("builtins.input", return_value=answer)

    def test_ack_file_skips_prompt(self):
        with open(self._ack, "w") as f:
            f.write("x")
        asked = []
        self.assertTrue(N._capture_confirm_once(
            input_fn=lambda p: asked.append(p) or "n"))
        self.assertEqual(asked, [])                    # 标记在, 不再问

    def test_yes_confirms_and_persists(self):
        with self._tty("y"):
            self.assertTrue(N._capture_confirm_once())
        self.assertTrue(os.path.exists(self._ack))     # 下次免问
        asked = []
        self.assertTrue(N._capture_confirm_once(
            input_fn=lambda p: asked.append(p) or "n"))
        self.assertEqual(asked, [])

    def test_decline_and_default_no(self):
        for ans in ("n", ""):
            with self._tty(ans):
                self.assertFalse(N._capture_confirm_once())
        self.assertFalse(os.path.exists(self._ack))

    def test_non_tty_allows_and_writes_ack(self):
        """非交互 (管道/CI): 不阻塞不提问, 视为确认并落标记。"""
        _stdin = mock.patch("sys.stdin")
        m = _stdin.start()
        m.isatty.return_value = False
        self.addCleanup(_stdin.stop)
        self.assertTrue(N._capture_confirm_once(
            input_fn=lambda *_: (_ for _ in ()).throw(
                AssertionError("非交互不该提问"))))
        self.assertTrue(os.path.exists(self._ack))

    def test_eof_stream_allows(self):
        """input 抛 EOFError (输入流关闭) → 不拦显式授权。"""
        def _eof(_p):
            raise EOFError
        with mock.patch("sys.stdin") as m:
            m.isatty.return_value = True
            self.assertTrue(N._capture_confirm_once(input_fn=_eof))


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestCaptureFinishBlock(unittest.TestCase):
    """finish(): 切片挂到权威事件 + 可序列化摘要块。"""

    def test_finish_attaches_slice_link_to_event(self):
        with tempfile.TemporaryDirectory(prefix="npcap_fin_") as tmp, \
             mock.patch("netpulse._captures_dir", return_value=tmp), \
             mock.patch("netpulse._report_dir", return_value=tmp):
            sess = N._PcapCaptureSession("slice", 8)
            sess.available = True
            sess._start_stamp = "20260901_130000"
            sess.ring = N._PcapRingBuffer(1024 * 1024)
            for k in range(60):
                sess.ring.push(_pkt(dport=22, ts=_t0 + k))
            sess.slices = [{
                "event_type": "outage", "event_stream": "ext",
                "event_start": round(_t0 + 50, 3),
                "ts": "2026-09-01 13:00:30", "path": "x.pcap",
                "pkts": 10, "rel": "x.pcap"}]
            result = {"events": [{"id": 1, "type": "outage", "stream": "ext",
                                  "start_ts": round(_t0 + 50, 3)}]}
            block = sess.finish(result)
            self.assertIsNotNone(block)
            self.assertTrue(result["events"][0]["pcap_slice"])
            # 摘要块可 JSON 序列化 (挂 result["capture"] 进 JSON 报告)
            import json
            json.dumps(block, ensure_ascii=False)
            self.assertEqual(block["mode"], "slice")
            self.assertEqual(block["ring_limit_mb"], 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
