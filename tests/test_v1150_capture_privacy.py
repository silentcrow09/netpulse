# -*- coding: utf-8 -*-
"""v1.15.0 审查 P0-6 回归测试: 抓包隐私声明与实际保留内容一致。

缺陷基线 (修复前, HEAD 551d151):
  CAPTURE_WEB_PORTS = (80, 443, 8080) 同时兼任「保留 payload 字节的端口」,
  于是明文 HTTP (80/8080) 每流每方向前 2 包保留 384B **应用载荷**。
  实跑一个 271B 的 `POST /api/login` 明文原样落盘 —— Authorization / Cookie /
  password 全在包里 —— 而抓包确认弹窗与盯障报告都写着
  「账号、密码、Cookie、聊天内容均不落盘」。承诺与行为不符,
  而 pcap 恰恰是要交给运营商的附件。

修复后契约 (本文件逐条锁死):
  1. CAPTURE_PAYLOAD_PORTS = (443,) —— 只有 TLS 保留载荷字节 (内容已加密,
     保留的只是 ClientHello 里的 SNI 访问域名)
  2. 明文 HTTP (80/8080) 一律截到 TCP 头 —— 任何应用字节都不落盘
  3. 弹窗 / 盯障报告 / --capture help 三处文案按「实际保留什么」表述

跑用: cd 到项目根目录, `py -3.13 tests/test_v1150_capture_privacy.py`
"""
import contextlib
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

# v1.9.7 PR-2 (scapy 懒加载) 契约: 打补丁前先完成 scapy 绑定, 否则函数入口
# _ensure_scapy() 触发的 _load_scapy() 会把真实对象写回 globals, 覆盖 mock。
N._ensure_scapy()

try:
    from scapy.all import Ether, IP, TCP, Raw
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

_t0 = 1700000000.0

# 一个真实的明文登录请求 (刻意 < 384B: 落在旧策略「每流前 2 包保留 384B」
# 的窗口内 —— 也就是说旧实现一定会把它原样写进 pcap)。
_LOGIN_REQ = (
    b"POST /api/login HTTP/1.1\r\n"
    b"Host: portal.example.com\r\n"
    b"Authorization: Bearer SECRETTOKEN123\r\n"
    b"Cookie: sid=abc123\r\n"
    b"Content-Type: application/json\r\n"
    b"\r\n"
    b'{"user":"demo","password":"Hunter2Secret"}'
)
_SECRET_MARKERS = (b"SECRETTOKEN123", b"Hunter2Secret", b"abc123",
                   b"Authorization", b"Cookie", b"password")


def _pkt(payload=b"X" * 800, sport=5000, dport=443, proto=TCP, ts=None):
    l4 = proto(sport=sport, dport=dport)
    p = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / \
        IP(src="192.168.1.5", dst="223.5.5.5") / l4 / Raw(payload)
    p.time = ts if ts is not None else _t0
    return p


class TestPayloadPortContract(unittest.TestCase):
    """常量契约: 「保留载荷的端口」与「有应用层信息的端口」必须拆开。"""

    def test_payload_ports_is_tls_only(self):
        self.assertEqual(N.CAPTURE_PAYLOAD_PORTS, (443,),
                         "只允许 TLS 保留载荷字节 —— 明文端口一律不进白名单")

    def test_plaintext_ports_not_in_payload_whitelist(self):
        for port in (80, 8080):
            self.assertNotIn(port, N.CAPTURE_PAYLOAD_PORTS,
                             f"明文端口 {port} 不得保留应用载荷")

    def test_web_ports_still_lists_plaintext_for_l7(self):
        """CAPTURE_WEB_PORTS 保留 (80/443/8080) 作「有应用层信息的端口」,
        供 _l7_extract 识别 Host/SNI 头; 但它不再决定是否保留载荷。"""
        self.assertEqual(N.CAPTURE_WEB_PORTS, (80, 443, 8080))

    def test_payload_keep_and_first_pkts_unchanged(self):
        """TLS 侧的保留窗口不变 (384B / 前 2 包) —— 不因收窄白名单而丢 SNI。"""
        self.assertEqual(N.CAPTURE_PAYLOAD_KEEP, 384)
        self.assertEqual(N.CAPTURE_FIRST_PKTS, 2)


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestPlaintextHttpTruncated(unittest.TestCase):
    """明文 HTTP 一律截到 TCP 头。"""

    def test_port_80_truncated_to_tcp_header(self):
        out = N._capture_strip_packet(_pkt(dport=80), {})
        self.assertEqual(len(bytes(out)), 14 + 20 + 20)   # Ether+IP+TCP 头

    def test_port_8080_truncated_to_tcp_header(self):
        out = N._capture_strip_packet(_pkt(dport=8080), {})
        self.assertEqual(len(bytes(out)), 14 + 20 + 20)

    def test_plaintext_reverse_direction_also_truncated(self):
        """服务器 → 客户端方向 (sport=80) 同样截断。"""
        out = N._capture_strip_packet(_pkt(sport=80, dport=5000), {})
        self.assertEqual(len(bytes(out)), 14 + 20 + 20)

    def test_plaintext_flow_never_bumps_window(self):
        """明文端口的流量不参与 payload 窗口计数 (连续 3 包全部截断)。"""
        fs = {}
        sizes = [len(bytes(N._capture_strip_packet(_pkt(dport=80), fs)))
                 for _ in range(3)]
        self.assertEqual(sizes, [54, 54, 54])

    def test_tls_port_still_keeps_window(self):
        """能力未被误伤: 443 前 2 包仍保留 384B (SNI 提取靠它)。"""
        fs = {}
        sizes = [len(bytes(N._capture_strip_packet(_pkt(dport=443), fs)))
                 for _ in range(3)]
        self.assertEqual(sizes, [54 + 384, 54 + 384, 54])

    def test_plaintext_truncation_keeps_original_length_fields(self):
        """截断只去载荷, 头部一个字节不改 (离线分析器仍能反推真实段长)。"""
        src = _pkt(dport=80)
        out = N._capture_strip_packet(src, {})
        self.assertEqual(out[IP].len, len(bytes(src[IP])))
        self.assertEqual(getattr(out, "wirelen", None), len(bytes(src)))


@unittest.skipUnless(SCAPY_OK, "scapy 未安装")
class TestCredentialsNeverOnDisk(unittest.TestCase):
    """端到端: 明文凭据不得出现在剥包产物里。"""

    def test_login_request_fits_in_old_window(self):
        """前提: 该请求 < 384B —— 旧实现一定会原样保留它 (证明用例有效)。"""
        self.assertLess(len(_LOGIN_REQ), N.CAPTURE_PAYLOAD_KEEP)

    def test_credentials_absent_from_port_80_output(self):
        out = bytes(N._capture_strip_packet(
            _pkt(payload=_LOGIN_REQ, dport=80), {}))
        for marker in _SECRET_MARKERS:
            self.assertNotIn(marker, out,
                             f"明文凭据 {marker!r} 出现在落盘字节里")

    def test_credentials_absent_from_port_8080_output(self):
        out = bytes(N._capture_strip_packet(
            _pkt(payload=_LOGIN_REQ, dport=8080), {}))
        for marker in _SECRET_MARKERS:
            self.assertNotIn(marker, out,
                             f"明文凭据 {marker!r} 出现在落盘字节里")

    def test_credentials_absent_from_reverse_direction(self):
        out = bytes(N._capture_strip_packet(
            _pkt(payload=_LOGIN_REQ, sport=80, dport=5000), {}))
        for marker in _SECRET_MARKERS:
            self.assertNotIn(marker, out,
                             f"明文凭据 {marker!r} 出现在落盘字节里")

    def test_credentials_absent_across_flow(self):
        """连发 5 个包也不漏 (旧实现前 2 包都留, 现在一个都不留)。"""
        fs = {}
        for _ in range(5):
            out = bytes(N._capture_strip_packet(
                _pkt(payload=_LOGIN_REQ, dport=80), fs))
            for marker in _SECRET_MARKERS:
                self.assertNotIn(marker, out)


class TestPrivacyWording(unittest.TestCase):
    """文案必须与实现同源: 三处都按「实际保留什么」表述。"""

    def test_confirm_dialog_lists_payload_and_plaintext_ports(self):
        """抓包确认弹窗: 载荷端口与明文端口分开写, 且明文声明不落盘。"""
        buf = io.StringIO()
        with mock.patch.object(N, "_capture_ack_path",
                               return_value=os.path.join(
                                   os.environ.get("TEMP", "."),
                                   "np_cap_ack_should_not_exist")), \
             mock.patch.object(N, "_write_capture_ack"), \
             mock.patch("sys.stdin.isatty", create=True, return_value=True), \
             contextlib.redirect_stdout(buf):
            ok = N._capture_confirm_once(input_fn=lambda _p: "y")
        text = buf.getvalue()
        self.assertTrue(ok)
        self.assertIn("仅 HTTPS (443)", text)
        self.assertIn("明文 HTTP (80/8080)", text)
        self.assertIn("不保存任何应用载荷", text)
        self.assertIn("账号、密码、Cookie、聊天内容均不落盘", text)

    def test_monitor_report_privacy_statement(self):
        """盯障报告隐私声明: 端口文案来自常量, 明文端口写明不保存应用载荷。"""
        res = {"stats": {}, "events": [], "targets": {}, "samples": {},
               "duration_actual_s": 60, "duration_planned_s": 60,
               "capture": {"iface": "eth0", "ring_bytes": 1024,
                           "ring_limit_mb": 64, "packets_captured": 10}}
        html = N._render_monitor_html(res)
        self.assertIn("隐私声明", html)
        self.assertIn("HTTPS (443)", html)
        self.assertIn("明文 HTTP (80/8080)", html)
        self.assertIn("一律不保存应用载荷", html)
        self.assertIn("账号、密码、Cookie、聊天内容均不落盘", html)

    def test_capture_help_text_matches_constants(self):
        """--capture 的 help 也必须按实际保留内容表述 (第三处文案)。"""
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", ["netpulse.py", "--help"]), \
             mock.patch.dict(os.environ, {"COLUMNS": "200"}), \
             contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                N.main()
        text = " ".join(buf.getvalue().split())
        self.assertIn("HTTPS(443)", text)
        self.assertIn("明文 HTTP(80/8080)", text)
        self.assertIn("不存应用内容", text)
        self.assertIn("账号/密码/Cookie 不落盘", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
