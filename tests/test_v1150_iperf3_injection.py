# -*- coding: utf-8 -*-
"""v1.15.0 审查 P1-7 回归测试: iperf3 服务器地址 → 命令行注入。

缺陷基线 (修复前, HEAD 551d151):
  `_run_one_direction` 把用户输入的 server 直接拼进字符串命令, 再用
  `run_cmd(cmd)` (默认 shell=True) 执行 → cmd.exe 参与解析 →
  `--iperf3-server "127.0.0.1 & echo INJECTED > f"` 会真的建出标记文件。
  同时 `--iperf3-server` / 菜单输入只校验端口、不校验 host。

修复后契约:
  1. 地址只接受 IP 字面量或合法主机名 (_valid_iperf3_host)
  2. 命令用参数数组 + shell=False 执行 (不经 shell 解析)
  3. detect() 里再设一道硬闸: 非法地址直接报错, 绝不进命令行

跑用: cd 到项目根目录, `py -3.13 tests/test_v1150_iperf3_injection.py`
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


# 典型注入串 (cmd.exe 上下文): & 串接命令, > 重定向写文件
_INJECTIONS = [
    "127.0.0.1 & echo INJECTED > f",
    "127.0.0.1 && calc",
    "127.0.0.1 | whoami",
    "127.0.0.1 & del /f important.txt",
    "127.0.0.1; echo INJECTED",
    "127.0.0.1 `echo INJECTED`",
    "127.0.0.1 $(echo INJECTED)",
    "127.0.0.1 & echo INJECTED > C:\\Windows\\Temp\\x.txt",
    "127.0.0.1\" & echo INJECTED & \"",
    "127.0.0.1\n& echo INJECTED",
    "127.0.0.1 &",
    "127.0.0.1\t& echo INJECTED",
    "127.0.0.1 & echo INJECTED > \"C:\\path\\with space\\x.txt\"",
    "-oProxyCommand=evil",
    "127.0.0.1 & echo %USERNAME% > f",
]


class TestHostValidation(unittest.TestCase):
    """_valid_iperf3_host: 只放行 IP 字面量与合法主机名."""

    def test_ipv4_accepted(self):
        for host in ("127.0.0.1", "10.0.0.1", "223.5.5.5", "0.0.0.0"):
            self.assertTrue(N._valid_iperf3_host(host), host)

    def test_ipv6_accepted(self):
        for host in ("::1", "2400::1", "fe80::1%eth0"):
            self.assertTrue(N._valid_iperf3_host(host), host)

    def test_hostname_accepted(self):
        for host in ("host", "host.example.com", "iperf-server",
                     "my_server", "a-b.c-d.example.org", "example.com."):
            self.assertTrue(N._valid_iperf3_host(host), host)

    def test_injection_strings_rejected(self):
        for host in _INJECTIONS:
            self.assertFalse(N._valid_iperf3_host(host),
                             f"注入串竟然通过了校验: {host!r}")

    def test_empty_and_oversize_rejected(self):
        self.assertFalse(N._valid_iperf3_host(""))
        self.assertFalse(N._valid_iperf3_host("   "))
        self.assertFalse(N._valid_iperf3_host("a" * 300))
        self.assertFalse(N._valid_iperf3_host("a" * 64 + ".com"))

    def test_non_string_rejected(self):
        for bad in (None, 123, [], {}):
            self.assertFalse(N._valid_iperf3_host(bad))

    def test_port_validation(self):
        self.assertTrue(N._valid_iperf3_port(1))
        self.assertTrue(N._valid_iperf3_port(5201))
        self.assertTrue(N._valid_iperf3_port(65535))
        for bad in (0, -1, 65536, 99999, "abc", None, ""):
            self.assertFalse(N._valid_iperf3_port(bad), repr(bad))


class TestParseServerSpec(unittest.TestCase):
    """_parse_iperf3_server: 解析与校验合一, 非法一律 None."""

    def test_plain_host(self):
        self.assertEqual(N._parse_iperf3_server("1.2.3.4"), ("1.2.3.4", 5201))
        self.assertEqual(N._parse_iperf3_server("host.example.com"),
                         ("host.example.com", 5201))

    def test_host_port(self):
        self.assertEqual(N._parse_iperf3_server("1.2.3.4:5201"), ("1.2.3.4", 5201))
        self.assertEqual(N._parse_iperf3_server("host.example.com:9999"),
                         ("host.example.com", 9999))

    def test_ipv6_forms(self):
        self.assertEqual(N._parse_iperf3_server("::1"), ("::1", 5201))
        self.assertEqual(N._parse_iperf3_server("[2400::1]:5201"),
                         ("2400::1", 5201))

    def test_whitespace_trimmed(self):
        self.assertEqual(N._parse_iperf3_server("  1.2.3.4  "), ("1.2.3.4", 5201))

    def test_invalid_returns_none(self):
        for spec in _INJECTIONS + ["", "   ", "1.2.3.4:abc", "1.2.3.4:99999",
                                   "a..b", "-x.com", "x-.com", "[bad", "a b"]:
            self.assertIsNone(N._parse_iperf3_server(spec), repr(spec))


class TestCommandExecutionSafety(unittest.TestCase):
    """命令必须走参数数组 + shell=False."""

    def test_argv_list_not_string(self):
        with mock.patch("netpulse.run_cmd", return_value=(0, "", "")) as rc:
            N.Iperf3Tester()._run_one_direction(
                "C:\\np\\iperf3.exe", "10.0.0.1", 5201, 5, True, None)
        cmd = rc.call_args[0][0]
        self.assertIsInstance(cmd, list, "命令必须是参数数组, 不能是拼接字符串")
        self.assertEqual(cmd[0], "C:\\np\\iperf3.exe")
        self.assertIn("-c", cmd)
        self.assertIn("10.0.0.1", cmd)

    def test_shell_false(self):
        with mock.patch("netpulse.run_cmd", return_value=(0, "", "")) as rc:
            N.Iperf3Tester()._run_one_direction(
                "C:\\np\\iperf3.exe", "10.0.0.1", 5201, 5, True, None)
        self.assertIs(rc.call_args[1].get("shell"), False,
                      "shell 必须显式为 False —— cmd.exe 不参与解析")

    def test_udp_flags_in_argv(self):
        with mock.patch("netpulse.run_cmd", return_value=(0, "", "")) as rc:
            N.Iperf3Tester()._run_one_direction(
                "iperf3.exe", "10.0.0.1", 5201, 5, False, None, udp=True)
        cmd = rc.call_args[0][0]
        self.assertIn("-u", cmd)
        self.assertIn("-b", cmd)
        self.assertIn("1M", cmd)

    def test_run_cmd_accepts_argv_list(self):
        """run_cmd 支持参数数组 (缓存 key 必须可哈希)."""
        rc, out, _err = N.run_cmd([sys.executable, "-c", "print('ok-argv')"],
                                  shell=False, use_cache=False)
        self.assertEqual(rc, 0)
        self.assertIn("ok-argv", out)

    def test_run_cmd_list_cache_key_works(self):
        """参数数组也要能进 TTL 缓存 (key 转 tuple)."""
        N._CMD_CACHE.clear()
        cmd = [sys.executable, "-c", "print('cached')"]
        rc1, out1, _ = N.run_cmd(cmd, shell=False)
        rc2, out2, _ = N.run_cmd(cmd, shell=False)
        self.assertEqual((rc1, rc2), (0, 0))
        self.assertEqual(out1, out2)


class TestDetectGate(unittest.TestCase):
    """detect(): 非法地址直接拒, 绝不进命令行."""

    def test_injected_server_rejected(self):
        res = N.Iperf3Tester().detect(
            server="127.0.0.1 & echo INJECTED > f", save_report=False)
        self.assertIn("error", res)
        self.assertIn("非法", res["error"])

    def test_invalid_port_rejected(self):
        res = N.Iperf3Tester().detect(server="1.2.3.4", port=99999,
                                      save_report=False)
        self.assertIn("error", res)
        self.assertIn("端口", res["error"])

    def test_missing_server_still_reports_missing(self):
        res = N.Iperf3Tester().detect(server=None, save_report=False)
        self.assertIn("error", res)
        self.assertIn("未指定", res["error"])

    def test_valid_server_passes_gate(self):
        """合法地址不该被误杀 (只拦非法, 不拦全部)."""
        with mock.patch.object(N.Iperf3Tester, "_find_iperf3",
                               return_value="iperf3.exe"), \
             mock.patch("netpulse.run_cmd", return_value=(0, "", "")):
            res = N.Iperf3Tester().detect(server="1.2.3.4", port=5201,
                                          duration=1, save_report=False)
        self.assertNotIn("非法", str(res.get("error", "")))
        self.assertNotIn("端口", str(res.get("error", "")))


class TestRealInjectionNotExecuted(unittest.TestCase):
    """真机证明: 注入串不会建出标记文件 (cmd.exe 扮演 iperf3.exe)。"""

    def test_marker_file_not_created(self):
        tmp = tempfile.mkdtemp(prefix="np_inject_")
        marker = os.path.join(tmp, "INJECTED.txt")
        payload = f'127.0.0.1 & echo INJECTED > "{marker}"'
        cmd_exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                "System32", "cmd.exe")
        with mock.patch.object(N.Iperf3Tester, "_find_iperf3",
                               return_value=cmd_exe):
            N.Iperf3Tester().detect(server=payload, duration=2,
                                    save_report=False)
        self.assertFalse(os.path.exists(marker),
                         "注入被执行了 —— 标记文件被创建")


class TestInputPathsRejectBadServer(unittest.TestCase):
    """两个入口 (CLI / 交互菜单) 都必须拒非法地址."""

    def test_cli_rejects_bad_server(self):
        argv = ["netpulse.py", "gateway", "--iperf3-server",
                "127.0.0.1 & echo INJECTED > f", "--no-update-check"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch("netpulse.run_diagnostics"), \
             mock.patch("netpulse._start_update_check"):
            with self.assertRaises(SystemExit) as cm:
                N.main()
        self.assertEqual(cm.exception.code, 4, "非法地址必须按参数错退出 (4)")

    def test_cli_accepts_valid_server(self):
        argv = ["netpulse.py", "gateway", "--iperf3-server", "10.0.0.1:5201",
                "--no-update-check"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch("netpulse.run_diagnostics"), \
             mock.patch("netpulse._start_update_check"):
            try:
                N.main()
            except SystemExit as e:
                self.assertNotEqual(e.code, 4,
                                    "合法地址被误杀 (按参数错退出)")
        self.assertEqual(N.SPEEDTEST_CONFIG.get("iperf3_server"), "10.0.0.1")
        self.assertEqual(N.SPEEDTEST_CONFIG.get("iperf3_port"), 5201)

    def test_menu_prompt_rejects_bad_server(self):
        with mock.patch("builtins.input",
                        return_value="127.0.0.1 & echo INJECTED > f"):
            got = N._prompt_for_iperf3()
        self.assertIsNone(got, "交互菜单不得接受含 shell 元字符的地址")

    def test_menu_prompt_accepts_valid_server(self):
        with mock.patch("builtins.input", return_value="10.0.0.1:5201"):
            got = N._prompt_for_iperf3()
        self.assertEqual(got, ("10.0.0.1", 5201))


if __name__ == "__main__":
    unittest.main(verbosity=2)
