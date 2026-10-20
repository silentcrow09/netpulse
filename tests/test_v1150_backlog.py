# -*- coding: utf-8 -*-
"""v1.15.0 审查第二批 (待办清单剩余项) 回归测试。

覆盖 12 项修复:
  P1-20 上行测速 elapsed 在 join 之后取 → 速率被低估最多 38%
  P1-21 get_dns_servers 漏掉 ipconfig /all 续行里的第 2/3 个 DNS
  P1-17 客户名不限长 → 文件名超 MAX_PATH → 落盘失败, 三份交付物全丢
  P1-18 --diagnose + --monitor 顶层模式静默吞并 (无任何提示)
  P1-19 netsh 命令里的接口名未校验 → cmd.exe 上下文下可闭合引号串联命令
  P2   顺序模式错误/超时模块标题打印两次 (且 CLI 结论用误导性 verdict)
  P2   --list 宣称「all / 0 / * 运行全部」但 CLI 只认 all
  P2   盯障进度行用 ANSI 转义却没开 VT (旧 conhost 打出字面 [K)
  P2   MonitorSession.start() 失败时网关 ping 进程泄漏
  P2   编码回退顺序 ANSI > GBK > UTF-8 → Win11 UTF-8 输出乱码且被永久缓存
  P2   抓包保留期「下次运行清理」实为「下次再抓包时清理」
  P2   main() 零 try/except → 现场崩溃是裸 traceback 且零交付物

跑用: cd 到项目根目录, `py -3.13 tests/test_v1150_backlog.py`
"""
import contextlib
import io
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


class TestUploadSpeedElapsed(unittest.TestCase):
    """P1-20: 上行速率的有效传输时长不能被 join 等待拉长。"""

    class _SlowCloseConn:
        """模拟 HTTPConnection: send 正常, close 故意卡 3 秒。

        真实场景: 上传线程跑满 duration 后还要收尾 (close/flush), 这段收尾
        时间**不在传输窗口内**。旧版用 join 之后的墙钟当 elapsed, 于是
        elapsed = duration + 收尾时间, 速率被稀释。
        """

        CLOSE_DELAY = 3.0

        def __init__(self, host, port, timeout=None):
            self.host = host

        def putrequest(self, *a, **k):
            pass

        def putheader(self, *a, **k):
            pass

        def endheaders(self):
            pass

        def send(self, payload):
            time.sleep(0.01)

        def close(self):
            time.sleep(self.CLOSE_DELAY)

    def test_elapsed_is_transfer_window_not_join_wait(self):
        duration = 1.0
        chunk = 4096
        with mock.patch.object(N.http.client, "HTTPConnection", self._SlowCloseConn):
            res = N._upload_speed_multi("example.com:8080", threads=2,
                                        duration=duration, chunk_size=chunk)
        self.assertIsNotNone(res, "上传应有结果")
        # 有效传输窗口 ≈ duration (最后一个字节发出的时刻)
        self.assertLess(res["elapsed_s"], duration + 0.5,
                        "elapsed 必须以最后字节发出时刻为准, 不能被 join 等待拉长")

    def test_speed_matches_bytes_over_window(self):
        duration = 1.0
        with mock.patch.object(N.http.client, "HTTPConnection", self._SlowCloseConn):
            res = N._upload_speed_multi("example.com:8080", threads=2,
                                        duration=duration, chunk_size=4096)
        expect = res["uploaded_bytes"] * 8 / 1e6 / res["elapsed_s"]
        self.assertAlmostEqual(res["upload_mbps"], expect, places=1)


class TestDnsServersContinuation(unittest.TestCase):
    """P1-21: ipconfig /all 的多 DNS 走续行, 不能只认带标签的首行。"""

    IPCONFIG_ALL = (
        "Windows IP 配置\r\n"
        "\r\n"
        "适配器 上网_1:\r\n"
        "\r\n"
        "   DNS 服务器 . . . . . . . . . . . . . : 223.5.5.5\r\n"
        "                                      119.29.29.29\r\n"
        "                                      114.114.114.114\r\n"
        "\r\n"
        "   默认网关. . . . . . . . . . . . . . : 192.168.1.1\r\n"
    )

    def test_continuation_lines_are_collected(self):
        with mock.patch.object(N, "run_cmd",
                               return_value=(0, self.IPCONFIG_ALL, "")):
            servers = N.get_dns_servers()
        self.assertIn("223.5.5.5", servers)
        self.assertIn("119.29.29.29", servers, "续行里的第 2 个 DNS 必须被收集")
        self.assertIn("114.114.114.114", servers, "续行里的第 3 个 DNS 必须被收集")

    def test_block_ends_at_next_section(self):
        with mock.patch.object(N, "run_cmd",
                               return_value=(0, self.IPCONFIG_ALL, "")):
            servers = N.get_dns_servers()
        self.assertNotIn("192.168.1.1", servers, "网关不属于 DNS 列表")


class TestSiteReportBaseTruncation(unittest.TestCase):
    """P1-17: 客户名过长 → 文件名超 MAX_PATH → 落盘失败。"""

    def test_long_name_truncated(self):
        long_name = "某某机械制造有限公司" * 40
        base = N._site_report_base(long_name, report_dir=r"C:\Reports\2026-10-21")
        name = os.path.basename(base)
        self.assertLessEqual(len(name), 11 + 60 + 1 + 15,
                             "文件名主体必须被截断 (现场检测_ + 60 + _ + 时间戳)")

    def test_full_path_with_longest_suffix_fits_max_path(self):
        long_name = "客户名称" * 100
        report_dir = r"C:\Program Files\NetPulse\reports\2026-10-21"
        base = N._site_report_base(long_name, report_dir=report_dir)
        longest = base + "_完整版.html"
        self.assertLessEqual(len(longest), 240,
                             "最长后缀拼上后仍须留出 MAX_PATH 余量")

    def test_illegal_filename_chars_replaced(self):
        base = N._site_report_base('a/b\\c:d*e?f"g<h>i|j', report_dir=r"C:\R")
        name = os.path.basename(base)
        for ch in '\\/:*?"<>|':
            self.assertNotIn(ch, name, f"非法文件名字符必须被替换: {ch}")

    def test_empty_name_falls_back(self):
        base = N._site_report_base("", report_dir=r"C:\R")
        self.assertIn("客户", os.path.basename(base))


class TestExclusiveModeNotice(unittest.TestCase):
    """P1-18: 顶层模式互斥必须明确告知被忽略的是谁。"""

    def test_notice_mentions_both_modes(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            N._warn_ignored_mode("diagnose", "monitor")
        out = buf.getvalue()
        self.assertIn("--monitor", out)
        self.assertIn("--diagnose", out)
        self.assertIn("互斥", out)

    def test_diagnose_branch_warns_monitor_ignored(self):
        buf = io.StringIO()
        with mock.patch.object(sys, "argv",
                               ["netpulse.py", "--diagnose", "slow", "--monitor", "60"]), \
             mock.patch.object(N, "run_diagnostics", return_value=None), \
             mock.patch.object(N, "LAST_RUN",
                               {"status": {"slow": "完成"}, "results": {}}), \
             contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                N.main()
        self.assertIn("已忽略 --monitor", buf.getvalue(),
                      "--diagnose 与 --monitor 同时给出时必须提示忽略了 monitor")


class TestIfaceNameWhitelist(unittest.TestCase):
    """P1-19: 接口名会插值进要提权执行的 netsh 命令 (经 cmd.exe 解释)。"""

    def test_normal_names_allowed(self):
        self.assertEqual(N._safe_iface_name("以太网"), "以太网")
        self.assertEqual(N._safe_iface_name("Ethernet 2"), "Ethernet 2")
        self.assertEqual(N._safe_iface_name("本地连接(2)"), "本地连接(2)")

    def test_shell_metacharacters_rejected(self):
        for bad in ['a&b', 'a"b', "a'b", 'a|b', 'a<b', 'a>b', 'a;b', 'a`b',
                    'a$b', 'a%b', 'a^b', 'a!b', 'a\nb', 'a\tb', '']:
            self.assertIsNone(N._safe_iface_name(bad), f"必须拒绝: {bad!r}")

    def test_cmd_metacharacters_rejected(self):
        for bad in ["x & calc", "x | calc", "x > out", "x < in", "x `id`",
                    "x $(id)", "x %PATH%", "x ^& calc"]:
            self.assertIsNone(N._SAFE_CMD_CHARS_RE.fullmatch(bad),
                              f"必须拒绝: {bad!r}")

    def test_existing_real_commands_allowed(self):
        self.assertIsNotNone(N._SAFE_CMD_CHARS_RE.fullmatch(
            'interface ipv4 set subinterface "以太网" mtu=1500 store=persistent'))
        self.assertIsNotNone(N._SAFE_CMD_CHARS_RE.fullmatch(
            '-Name "以太网" -RegistryKeyword "*SpeedDuplex" -RegistryValue 4'))

    def test_mtu_rule_does_not_put_dirty_iface_into_command(self):
        results = {
            "mtu": {
                "path_mtus": [{"path_mtu": 1400}],
                "local_mtus": [{"interface": "以太网&calc", "mtu": 1500,
                                "egress": True}],
            },
            "tcpstats": {"retrans_rate_pct": 8},
        }
        rc = N._rule_mtu_blackhole(results)
        self.assertIsNotNone(rc, "该 fixture 应触发 MTU 黑洞规则")
        rec = rc.recommendations[0]
        cmd_part = rec.split("netsh", 1)[1]
        self.assertNotIn("&", cmd_part,
                         "命令段不得带接口名里的 shell 元字符")
        self.assertIn("接口名", cmd_part, "非法接口名应退化成占位符")


class TestSequentialNoDuplicateTitle(unittest.TestCase):
    """P2: 顺序模式下错误/超时模块的标题与错误文本只能出现一次。"""

    def test_error_module_printed_once(self):
        buf = io.StringIO()
        with mock.patch.object(N, "_run_module_with_timeout",
                               return_value=("错误", {"error": "探测炸了"})), \
             contextlib.redirect_stdout(buf):
            N.run_diagnostics(["gateway"], banner=False)
        out = buf.getvalue()
        self.assertEqual(out.count("▶ 网关检测"), 1, "错误模块标题只能出现一次")
        self.assertEqual(out.count("探测炸了"), 1, "错误文本只能出现一次")

    def test_cli_conclusion_uses_error_text_not_misleading_verdict(self):
        """verdict_fn 会把 {"error": ...} 当空数据解读 → 结论与故障无关。"""
        buf = io.StringIO()
        with mock.patch.object(N, "_run_module_with_timeout",
                               return_value=("超时", {"error": "模块执行超时"})), \
             contextlib.redirect_stdout(buf):
            N.run_diagnostics(["linkspeed"], banner=False)
        out = buf.getvalue()
        self.assertIn("模块执行超时", out)
        self.assertNotIn("适配器", out,
                         "超时结论不得用「检测到 0 个适配器」这类无关文案")


class TestParseKeysAllAliases(unittest.TestCase):
    """P2: --list 明说「all / 0 / * 运行全部」, CLI 必须三个都认。"""

    def test_aliases_expand_to_full_set(self):
        full = N.full_module_keys()
        for alias in ("all", "0", "*", "ALL"):
            got = N._parse_keys([alias], strict=False)
            self.assertEqual(got, full, f"{alias!r} 必须展开为全部模块")

    def test_alias_mixed_with_other_keys(self):
        got = N._parse_keys(["0", "dns"], strict=False)
        self.assertIn("dns", got)
        # dns 本就在全部模块里 → 去重后仍是全量
        self.assertEqual(len(got), len(N.full_module_keys()))


class TestMonitorModeSessionHygiene(unittest.TestCase):
    """P2: 盯障必须开 VT; start() 失败必须清理已启动的 ping 进程。"""

    def test_vt_enabled_and_session_cleaned_on_start_failure(self):
        calls = {"vt": 0, "stop": 0}

        class _FakeSession:
            def __init__(self, *a, **k):
                pass

            def start(self):
                return False

            def stop(self):
                calls["stop"] += 1

        with mock.patch.object(N, "MonitorSession", _FakeSession), \
             mock.patch.object(N, "_cli_enable_vt",
                               side_effect=lambda: calls.__setitem__(
                                   "vt", calls["vt"] + 1) or True), \
             contextlib.redirect_stdout(io.StringIO()):
            N.run_monitor_mode(60)
        self.assertGreaterEqual(calls["vt"], 1,
                                "进度行用 ANSI 转义, 进模式必须先确认 VT 可用")
        self.assertEqual(calls["stop"], 1,
                         "start() 失败必须清理已启动的 ping 进程 (否则孤儿 ping.exe)")


class TestDecodeOrderUtf8First(unittest.TestCase):
    """P2: UTF-8 输出被按 cp936 解码 = 乱码, 且错误编码被永久缓存。"""

    def test_utf8_is_first_in_order(self):
        with mock.patch.object(N, "_system_ansi_codepage", return_value="cp936"):
            order = N._build_decode_order()
        self.assertEqual(order[0], "utf-8", "UTF-8 自校验, 必须优先尝试")
        self.assertIn("cp936", order, "仍要保留 ANSI 回退")

    def test_utf8_bytes_decoded_correctly_and_cached_as_utf8(self):
        # 关键 fixture: 这串 UTF-8 字节按 cp936 **能成功解码** (GBK 双字节表
        # 覆盖广), 但解出来是乱码 —— 旧版因此把 cp936 缓存住, 之后一直乱码。
        raw = "测试é".encode("utf-8")
        with mock.patch.object(N, "_system_ansi_codepage", return_value="cp936"):
            N._DECODE_CACHE.clear()
            so, se = N._decode_bytes_pair("netsh fake", raw, b"")
            cached = N._DECODE_CACHE.get("netsh fake")
        self.assertEqual(so, "测试é", "UTF-8 输出必须被正确解码")
        self.assertEqual(cached, "utf-8", "命中的编码必须缓存为 utf-8")

    def test_gbk_bytes_still_fallback_to_ansi(self):
        raw = "网关检测".encode("gbk")
        with mock.patch.object(N, "_system_ansi_codepage", return_value="cp936"):
            N._DECODE_CACHE.clear()
            so, _ = N._decode_bytes_pair("arp fake", raw, b"")
        self.assertEqual(so, "网关检测", "GBK 输出仍要能正确解码 (回退 cp936)")


class TestCaptureCleanupOnStartup(unittest.TestCase):
    """P2: 「下次运行 NetPulse 时自动清理」必须真的每次运行都清。"""

    def test_cleanup_called_on_plain_run(self):
        called = []
        with mock.patch.object(N, "_cleanup_old_captures",
                               side_effect=lambda *a, **k: called.append(1)), \
             mock.patch.object(sys, "argv", ["netpulse.py", "--list"]), \
             contextlib.redirect_stdout(io.StringIO()):
            N.main()
        self.assertTrue(called, "每次运行都应清理超期切片 (不只在下次抓包时)")

    def test_cleanup_removes_expired_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            old = os.path.join(td, "old.pcap")
            new = os.path.join(td, "new.pcap")
            for p in (old, new):
                with open(p, "wb") as f:
                    f.write(b"\x00")
            ancient = time.time() - (N.CAPTURE_RETENTION_DAYS + 2) * 86400
            os.utime(old, (ancient, ancient))
            removed = N._cleanup_old_captures(cap_dir=td)
            self.assertEqual(removed, 1)
            self.assertFalse(os.path.exists(old), "超期切片必须被删")
            self.assertTrue(os.path.exists(new), "未超期切片必须保留")


class TestCliEntryCrashGuard(unittest.TestCase):
    """P2: 现场崩溃不该是裸 traceback, 且要留下可回传的日志。"""

    def test_unexpected_error_gets_exit_code_3_and_log(self):
        buf = io.StringIO()
        with mock.patch.object(N, "main", side_effect=RuntimeError("炸了")), \
             mock.patch.object(N, "_write_crash_log",
                               return_value=r"C:\tmp\netpulse_error.log"), \
             contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                N._cli_entry()
        self.assertEqual(cm.exception.code, 3,
                         "工具自身失败用退出码 3 (与 compute_exit_code 同口径)")
        self.assertIn("未预期错误", buf.getvalue())

    def test_system_exit_passes_through(self):
        with mock.patch.object(N, "main", side_effect=SystemExit(4)), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                N._cli_entry()
        self.assertEqual(cm.exception.code, 4, "argparse 等的退出码必须原样透传")

    def test_keyboard_interrupt_is_not_an_error(self):
        buf = io.StringIO()
        with mock.patch.object(N, "main", side_effect=KeyboardInterrupt), \
             contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                N._cli_entry()
        self.assertEqual(cm.exception.code, 130)
        self.assertNotIn("未预期错误", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
