# -*- coding: utf-8 -*-
"""上行测速写路径回归测试 (v1.18.1)

背景
----
v1.18.0 用 `conn.send(256KB)` + socket `timeout=20` 做上行测速。CPython 的
socket 超时覆盖**整个 sendall**, 于是 256KB 一块必须在 20s 内全部写完
(每连接 ≥12.8KB/s; 4 连接共享一条上行 ⇒ 上行低于约 0.5~1Mbps 必然超时)。
结果:

  1. 慢上行链路上行测速直接失败 —— 恰恰是最该测出来的链路;
  2. worker 线程抛 TimeoutError, 被当成**程序缺陷**上报到日志服务器
     (v1.18.0 线上收到的 `线程:upload-speed TimeoutError` 就是这条);
  3. sendall 超时会把已写出的那一部分字节一起丢掉 ⇒ 上行速率被低估。

本测试锁死的不变量
------------------
  A. 慢但活着的对端 → 能测出速率, 不抛异常, 不上报
  B. 死对端 (收但不回) → 有界时间内返回, 记为「连接中断」, **不上报**
     (网络状况不是软件缺陷)
  C. 部分连接中断 → 结果照常返回, 并如实带上中断连接数
  D. 真实 socket 路径 (本地回环 HTTP 服务端) 能跑通, 且耗时受 duration 约束

跑用: cd 到项目根目录, `python tests/test_v1181_upload_stall.py`
"""
import os
import re
import socket
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


# ── 假的对端 ────────────────────────────────────────────────────────
class _FakeSocket:
    """模拟一个「慢但活着」的对端。

    真实内核的非阻塞 socket: send() 立刻返回「实际收下多少字节」, 收满
    时抛 BlockingIOError。这个假实现按固定速率放行字节, 让测试可以在
    毫秒级模拟任意慢的上行链路。

    mode="slow": 每次放行 per_call 字节 (并按 rate 限速)
    mode="dead": 永远收不下 (抛 BlockingIOError)
    """

    def __init__(self, mode="slow", per_call=8192, rate=None):
        self.mode = mode
        self.per_call = per_call
        self.rate = rate            # bytes/s, None = 不限速
        self.accepted = 0
        self.blocking = True
        self.closed = False
        self._next_at = 0.0

    def setblocking(self, flag):
        self.blocking = flag

    def send(self, view):
        if self.mode == "dead":
            raise BlockingIOError("would block")
        if self.rate:
            now = time.time()
            if now < self._next_at:
                time.sleep(self._next_at - now)
            n = min(self.per_call, len(view))
            self._next_at = time.time() + n / float(self.rate)
        else:
            n = min(self.per_call, len(view))
        self.accepted += n
        return n

    def close(self):
        self.closed = True


class _FakeConn:
    """替代 http.client.HTTPConnection, 交出上面那个假 socket。"""

    def __init__(self, sock):
        self.sock = sock
        self.closed = False

    def putrequest(self, *a, **kw):
        pass

    def putheader(self, *a, **kw):
        pass

    def endheaders(self, *a, **kw):
        pass

    def send(self, data):
        # 旧实现的路径 (sendall 语义): 整块发不出就抛超时
        return self.sock.send(data)

    def close(self):
        self.closed = True


class _UploadTestBase(unittest.TestCase):
    def setUp(self):
        # 记录一切「线程失败上报」—— 网络状况不应该走到这里
        self.reported = []
        self._orig_emit = N._emit_thread_failure
        N._emit_thread_failure = (lambda exc, scope, detail=None:
                                  self.reported.append((type(exc).__name__, scope, detail)))
        self._orig_conn = N.http.client.HTTPConnection
        self._orig_wait = N._wait_writable

    def tearDown(self):
        N._emit_thread_failure = self._orig_emit
        N.http.client.HTTPConnection = self._orig_conn
        N._wait_writable = self._orig_wait

    def _install_conn(self, factory):
        N.http.client.HTTPConnection = factory


class TestSlowPeer(_UploadTestBase):
    """A: 慢但活着的对端 —— 上行测速必须测得出来。"""

    def test_slow_peer_is_measured_not_failed(self):
        """32KB/s 的慢上行: 必须出速率, 不抛异常, 不上报。"""
        sock = _FakeSocket(mode="slow", per_call=4096, rate=32 * 1024)
        self._install_conn(lambda *a, **kw: _FakeConn(sock))

        res = N._upload_speed_multi("127.0.0.1:8080", threads=1, duration=1.2,
                                    chunk_size=64 * 1024, stall_timeout=5.0)

        self.assertIsNotNone(res, "慢链路不应判为测速失败")
        self.assertGreater(res["uploaded_bytes"], 0, "必须有实际写出的字节")
        self.assertGreater(res["upload_mbps"], 0.0, "必须给出速率")
        self.assertEqual(self.reported, [], "网络状况不得当成程序缺陷上报")
        self.assertNotIn("dropped", res, "对端活着就不该有中断连接")

    def test_measured_rate_tracks_peer_rate(self):
        """实测速率要贴近对端真实速率 (旧实现在这里会 0 或直接失败)。"""
        rate = 64 * 1024          # 对端 64KB/s
        sock = _FakeSocket(mode="slow", per_call=4096, rate=rate)
        self._install_conn(lambda *a, **kw: _FakeConn(sock))

        res = N._upload_speed_multi("127.0.0.1:8080", threads=1, duration=1.5,
                                    chunk_size=64 * 1024, stall_timeout=5.0)
        self.assertIsNotNone(res)
        expect_mbps = rate * 8 / 1e6
        self.assertAlmostEqual(res["upload_mbps"], expect_mbps, delta=expect_mbps * 0.35,
                               msg="实测速率应贴近对端速率, 实际 %.3f Mbps (期望约 %.3f)"
                                   % (res["upload_mbps"], expect_mbps))

    def test_byte_count_equals_accepted_bytes(self):
        """计入的字节数必须等于对端实际收下的字节数 (sendall 超时会丢字节)。"""
        sock = _FakeSocket(mode="slow", per_call=4096, rate=64 * 1024)
        self._install_conn(lambda *a, **kw: _FakeConn(sock))

        res = N._upload_speed_multi("127.0.0.1:8080", threads=1, duration=1.0,
                                    chunk_size=64 * 1024, stall_timeout=5.0)
        self.assertIsNotNone(res)
        self.assertEqual(res["uploaded_bytes"], sock.accepted,
                         "统计字节数必须与实际写出一致")

    def test_keeps_sending_chunk_after_chunk(self):
        """窗口内要连着发多块 —— 发完一块就退出会让速率采样失真。"""
        sock = _FakeSocket(mode="slow", per_call=8192, rate=256 * 1024)
        self._install_conn(lambda *a, **kw: _FakeConn(sock))

        chunk = 16 * 1024
        res = N._upload_speed_multi("127.0.0.1:8080", threads=1, duration=1.0,
                                    chunk_size=chunk, stall_timeout=5.0)
        self.assertIsNotNone(res)
        self.assertGreater(res["uploaded_bytes"], chunk * 2,
                           "窗口内应发出多块 (实测 %d 字节, 块大小 %d)"
                           % (res["uploaded_bytes"], chunk))


class TestDeadPeer(_UploadTestBase):
    """B: 死对端 —— 有界返回 + 记为连接中断 + 不上报。"""

    @staticmethod
    def _wait_timeout(sock, timeout):
        """模拟 select 真等到超时: 等满再返回「不可写」。"""
        time.sleep(timeout + 0.02)
        return False

    def test_dead_peer_returns_bounded_and_is_not_reported(self):
        sock = _FakeSocket(mode="dead")
        self._install_conn(lambda *a, **kw: _FakeConn(sock))
        # 永远等不到可写
        N._wait_writable = self._wait_timeout

        t0 = time.time()
        res = N._upload_speed_multi("127.0.0.1:8080", threads=2, duration=1.0,
                                    chunk_size=64 * 1024, stall_timeout=0.3)
        dt = time.time() - t0

        self.assertIsNone(res, "一个字节都没发出去 → 判失败 (由上层转成「上行测速失败」)")
        self.assertEqual(self.reported, [], "对端死了是网络状况, 不是软件缺陷")
        self.assertLess(dt, 5.0, "必须在有界时间内返回, 实际 %.1fs" % dt)

    def test_partial_drop_still_returns_result(self):
        """C: 一部分连接死了, 其余正常 → 结果照常返回, 并带上中断连接数。"""
        socks = [_FakeSocket(mode="dead"), _FakeSocket(mode="slow", per_call=4096,
                                                       rate=64 * 1024)]
        idx = [0]

        def factory(*a, **kw):
            s = socks[min(idx[0], len(socks) - 1)]
            idx[0] += 1
            return _FakeConn(s)

        self._install_conn(factory)
        N._wait_writable = self._wait_timeout

        res = N._upload_speed_multi("127.0.0.1:8080", threads=2, duration=1.0,
                                    chunk_size=64 * 1024, stall_timeout=0.3)
        self.assertIsNotNone(res, "还有连接在跑就该出结果")
        self.assertEqual(res.get("dropped"), 1, "必须如实标出中断的连接数")
        self.assertGreater(res["uploaded_bytes"], 0)
        self.assertEqual(self.reported, [], "连接中断属于网络状况, 不上报")

    def test_window_end_is_not_a_drop(self):
        """窗口自然结束 (对端没死, 只是慢) 不能算「连接中断」。

        这是 v1.18.1 真实节点实测踩到的坑: select 恰好在窗口末尾返回
        「不可写」, 若按「等不到可写=链路死了」判, 每次测速都会误报中断。
        """
        socks = [_FakeSocket(mode="dead"), _FakeSocket(mode="slow", per_call=4096,
                                                       rate=64 * 1024)]
        idx = [0]

        def factory(*a, **kw):
            s = socks[min(idx[0], len(socks) - 1)]
            idx[0] += 1
            return _FakeConn(s)

        self._install_conn(factory)
        N._wait_writable = self._wait_timeout

        # 窗口 1s 远小于停滞阈值 5s → 等不到可写只是因为窗口到了
        res = N._upload_speed_multi("127.0.0.1:8080", threads=2, duration=1.0,
                                    chunk_size=64 * 1024, stall_timeout=5.0)
        self.assertIsNotNone(res)
        self.assertNotIn("dropped", res,
                         "窗口结束不等于连接中断 (实际 dropped=%r)" % res.get("dropped"))


class TestRealSocketPath(unittest.TestCase):
    """D: 真实 socket 路径 —— 本地回环 HTTP 服务端, 不 mock 任何东西。"""

    def _serve(self, mode):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                try:
                    srv.settimeout(0.5)
                    conn, _ = srv.accept()
                except (socket.timeout, OSError):
                    continue
                if mode == "dead":
                    threading.Thread(target=_hold, args=(conn, stop),
                                     daemon=True).start()
                else:
                    threading.Thread(target=_drain, args=(conn, stop),
                                     daemon=True).start()

        def _hold(conn, stop):
            # 收下连接后什么都不做 (对端不收 body)
            while not stop.is_set():
                time.sleep(0.1)
            try:
                conn.close()
            except OSError:
                pass

        def _drain(conn, stop):
            conn.settimeout(0.5)
            while not stop.is_set():
                try:
                    if not conn.recv(65536):
                        break
                except socket.timeout:
                    continue
                except OSError:
                    break
            try:
                conn.close()
            except OSError:
                pass

        threading.Thread(target=loop, daemon=True).start()
        return srv, port, stop

    def test_real_socket_slow_server(self):
        """真实 socket: 服务端只收不回的正文, 上行测速仍要有界返回且无异常上报。"""
        srv, port, stop = self._serve("drain")
        reported = []
        orig = N._emit_thread_failure
        N._emit_thread_failure = (lambda exc, scope, detail=None:
                                  reported.append((type(exc).__name__, scope)))
        try:
            t0 = time.time()
            res = N._upload_speed_multi("127.0.0.1:%d" % port, threads=2, duration=1.0,
                                        chunk_size=64 * 1024, stall_timeout=1.0)
            dt = time.time() - t0
        finally:
            N._emit_thread_failure = orig
            stop.set()
            srv.close()

        self.assertEqual(reported, [], "真实路径也不该把网络状况报成程序缺陷")
        self.assertLess(dt, 6.0, "耗时受 duration 约束, 实际 %.1fs" % dt)
        if res is not None:
            self.assertGreater(res["uploaded_bytes"], 0)
            self.assertGreater(res["upload_mbps"], 0.0)


class TestConnectFailure(_UploadTestBase):
    """建链失败 = 节点不可达 —— 属网络状况, 不得上报成程序缺陷。"""

    def test_connect_refused_is_not_reported(self):
        class _RefusedConn:
            def __init__(self, *a, **kw):
                raise OSError("[WinError 10061] 目标计算机积极拒绝")

        self._install_conn(_RefusedConn)
        res = N._upload_speed_multi("127.0.0.1:8080", threads=2, duration=0.6,
                                    chunk_size=64 * 1024, stall_timeout=0.3)
        self.assertIsNone(res, "建不上链就测不出速率 → 判失败")
        self.assertEqual(self.reported, [], "节点不可达不是软件缺陷, 不得上报")

    def test_handshake_timeout_is_not_reported(self):
        class _TimeoutConn:
            def __init__(self, *a, **kw):
                pass

            def putrequest(self, *a, **kw):
                pass

            def putheader(self, *a, **kw):
                pass

            def endheaders(self, *a, **kw):
                raise socket.timeout("timed out")

            def close(self):
                pass

        self._install_conn(_TimeoutConn)
        res = N._upload_speed_multi("127.0.0.1:8080", threads=1, duration=0.6,
                                    chunk_size=64 * 1024, stall_timeout=0.3)
        self.assertIsNone(res)
        self.assertEqual(self.reported, [], "握手超时是网络状况, 不得上报")


class TestReportShowsDropped(unittest.TestCase):
    """报告必须如实呈现「有几条连接没跑完」, 不能让人把部分结果当全量。"""

    @staticmethod
    def _res(dropped):
        up = {"upload_mbps": 12.34, "uploaded_bytes": 12345678, "uploaded_mb": 12.35,
              "elapsed_s": 8.0, "threads": 4, "server": "speedtest1.online.sh.cn:8080",
              "method": "speedtest-cn", "sponsor": "中国电信",
              "server_host": "speedtest1.online.sh.cn:8080", "server_latency_ms": 12.5}
        if dropped:
            up["dropped"] = dropped
        return {
            "download_mbps": 120.5, "upload_mbps": 12.34, "upload_method": "speedtest-cn",
            "upload_server": "speedtest1.online.sh.cn:8080", "idle_rtt_ms": 8.2,
            "loaded_rtt_ms": 21.0, "bufferbloat_ms": 12.8,
            "bufferbloat_grade": "A (优秀, 无缓冲膨胀)",
            "latency_target": "192.168.1.1",
            "http": {"url": "http://mirrors.aliyun.com/x", "threads": 4},
            "up_result": up,
            "down_series": [], "up_series": [], "lat_series": [],
            "timestamp": "2026-11-03T12:00:00",
        }

    def test_speedtest_page_shows_drop_note(self):
        """独立测速页的上行测速行要标出中断连接数。"""
        html = N._render_speedtest_html(self._res(2))
        row = re.search(r"<tr><td>上行测速</td><td>(.*?)</td></tr>", html)
        self.assertIsNotNone(row, "测速页缺少「上行测速」行")
        self.assertIn("2/4 连接中断", row.group(1))

    def test_speedtest_page_clean_when_no_drop(self):
        """没有中断时不要多此一举地提示。"""
        html = N._render_speedtest_html(self._res(0))
        row = re.search(r"<tr><td>上行测速</td><td>(.*?)</td></tr>", html)
        self.assertIsNotNone(row)
        self.assertNotIn("连接中断", row.group(1))

    def test_main_report_metric_card_shows_drop(self):
        """主报告的测速模块卡要有「连接中断」指标格。"""
        from datetime import datetime
        saved = N.LAST_RUN
        N.LAST_RUN = {
            "app": "NetPulse", "version": "1.18.1",
            "generated_at": datetime.now(),
            "status": {"speedtest": "完成"},
            "results": {"speedtest": self._res(2)},
            "keys": ["speedtest"], "duration_ms": 5000, "total_modules": 23,
            "system": {"hostname": "PC", "local_ip": "192.168.1.10",
                       "gateway": "192.168.1.1", "dns": "223.5.5.5",
                       "public_ip": "1.2.3.4", "geo": "上海", "asn": "AS4134"},
        }
        try:
            html = N.render_report_html_customer(N.build_report())
        finally:
            N.LAST_RUN = saved
        self.assertIn("连接中断", html, "主报告缺少「连接中断」指标")
        self.assertIn("2/4 条", html, "主报告的连接中断数量不对")


if __name__ == "__main__":
    unittest.main(verbosity=2)
