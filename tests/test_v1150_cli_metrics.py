# -*- coding: utf-8 -*-
"""v1.15.0 审查 P1-8 回归测试: CLI 关键指标不得被静默吞掉。

缺陷基线 (修复前, HEAD 551d151):
  `_cli_print_result` 写死 `for label, value, level in metrics:` — 遇到
  2 元组 (label, value) 或 4 元组 (label, value, level, hint) 直接抛
  ValueError, 又被外层 `except Exception: pass` 吞掉 → 该模块的指标行
  全部消失 (实测 `netpulse.py arp` 命令行一行指标都不显示)。
  报告层 (_present_module) 早已兼容 2/3/4 元组, 只有 CLI 还在硬解包。

修复后契约:
  1. CLI 指标解包兼容 2/3/4 元组 (与报告层同口径)
  2. metrics_fn 自身抛异常时不得连带崩掉整个模块打印
  3. 全部 23 个模块的关键指标都必须在命令行显示出来

跑用: cd 到项目根目录, `py -3.13 tests/test_v1150_cli_metrics.py`
"""
import contextlib
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


# 每个模块一份「典型结果」夹具 —— 键名对齐真实生产者 (R-C1 教训:
# 喂想象键名的测试全绿但规则全不触发)。
_FIX = {
    "dhcp": {"servers": ["192.168.1.1", "192.168.1.2"], "interference": True},
    "gateway": {"ping": {"loss_pct": 0, "avg_ms": 3, "jitter_ms": 1}},
    "loop": {"loop_detected": True},
    "external": {"avg_rtt_ms": 10, "avg_loss_pct": 0, "tcp_ok": 1,
                 "tcp_total": 1, "targets": []},
    "linkspeed": {"adapters": [{"status": "Up", "speed_mbps": 1000,
                                "name": "以太网", "description": "Intel I219"}]},
    "wifi": {"network_count": 5, "overall_interference": "正常",
             "current_channel": 6, "best_2g_channel": {"channel": 1}},
    "tcp": {"total": 10, "by_state": {"ESTABLISHED": 5, "TIME_WAIT": 2}},
    "port": {"targets": [{"status": "开放"}, {"status": "关闭"}], "proto": "tcp",
             "probe_count": 1},
    "egress": {"default_routes": [], "public_ips": ["1.2.3.4"]},
    "dns": {"dns_servers": ["223.5.5.5"], "success_count": 3, "total_count": 3},
    "mtu": {"path_mtus": [{"target": "223.5.5.5", "path_mtu": 1500}],
            "local_mtus": [{"interface": "以太网", "mtu": 1500}]},
    "arp": {"total_entries": 3, "unique_macs": 2, "gateway_mac": "aa:bb:cc"},
    "bufferbloat": {"idle_rtt_ms": 5, "loaded_rtt_ms": 8, "bloat_ms": 3.0,
                    "grade": "A (优秀)"},
    "ipv6": {"has_ipv6": True, "addresses": []},
    "route": {"routes": []},
    "speedtest": {"download_mbps": 100, "upload_mbps": 10, "idle_rtt_ms": 5},
    "iperf3": {"download_mbps": 100, "upload_mbps": 50, "server": "1.2.3.4"},
    "lan": {"devices": [{"mac": "aa:bb:cc:dd:ee:ff"}]},
    "tcpstats": {"retrans_rate_pct": 0.1, "segments_sent": 100,
                 "current_connections": 20},
    "proxy": {"proxy_type": "无"},
    "nattype": {"nat_behavior": "锥形"},
    "web": {"sites": []},
    "tcpcc": {"max_sustained": 1000},
}

_MODULE_KEYS = sorted(N.MODULE_PRESENTATION.keys())


def _metric_lines(text):
    """从 CLI 输出里挑出指标行 (4 空格缩进 + 'label: value')。"""
    return [ln for ln in text.splitlines()
            if ln.startswith("    ") and ": " in ln]


class _NoColorMixin:
    def setUp(self):
        self._old = N._C_NOCOLOR
        N._C_NOCOLOR = True
        self.addCleanup(setattr, N, "_C_NOCOLOR", self._old)


class TestMetricsShapeContract(_NoColorMixin, unittest.TestCase):
    """元数契约: 所有模块的指标元组只能是 2/3/4 元 (与报告层同口径)。"""

    def test_module_count(self):
        self.assertEqual(len(_MODULE_KEYS), 23, "模块数变了, 契约测试要跟着更新")

    def test_every_module_metrics_shape_valid(self):
        bad = []
        for key in _MODULE_KEYS:
            mfn = N.MODULE_PRESENTATION[key].get("metrics_fn")
            if not mfn:
                bad.append((key, "no metrics_fn"))
                continue
            try:
                items = mfn(_FIX.get(key, {}))
            except Exception as e:
                bad.append((key, f"raised {type(e).__name__}: {e}"))
                continue
            for it in items:
                if not isinstance(it, (tuple, list)) or not (2 <= len(it) <= 4):
                    bad.append((key, f"bad shape {it!r}"))
        self.assertEqual(bad, [], f"指标元数契约违规: {bad}")

    def test_every_module_produces_metrics(self):
        empty = []
        for key in _MODULE_KEYS:
            mfn = N.MODULE_PRESENTATION[key].get("metrics_fn")
            if not mfn or not mfn(_FIX.get(key, {})):
                empty.append(key)
        self.assertEqual(empty, [], f"这些模块在典型结果下没有任何指标: {empty}")


class TestCliPrintsMetrics(_NoColorMixin, unittest.TestCase):
    """CLI 必须把关键指标打出来 (原来 2/4 元组直接被吞)。"""

    def _print(self, key, res=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            N._cli_print_result(dict(_FIX.get(key, {})) if res is None else res,
                                key=key)
        return buf.getvalue()

    def test_all_modules_print_at_least_one_metric(self):
        missing = []
        for key in _MODULE_KEYS:
            if not _metric_lines(self._print(key)):
                missing.append(key)
        self.assertEqual(missing, [],
                         f"这些模块的指标行在命令行消失了: {missing}")

    def test_arp_metrics_visible(self):
        """审查原始复现: `netpulse.py arp` 命令行一行指标都不显示."""
        out = self._print("arp")
        self.assertIn("ARP 条目", out)
        self.assertIn("MAC 数", out)
        self.assertIn("网关 MAC", out)

    def test_wifi_metrics_visible(self):
        out = self._print("wifi")
        self.assertIn("当前信道", out)
        self.assertIn("邻居数", out)
        self.assertIn("推荐信道", out)

    def test_two_tuple_metrics_visible(self):
        """2 元组 (label, value) 不得整条丢失 (tcp/port/egress/route 同型)."""
        out = self._print("tcp")
        self.assertIn("已建立", out)
        self.assertIn("等待关闭", out)
        out2 = self._print("port")
        self.assertIn("协议", out2)
        self.assertIn("每目标采样", out2)

    def test_four_tuple_hint_visible(self):
        """4 元组的第 4 位 (hint/说明) 也要显示, 不得被解包异常吃掉."""
        out = self._print("linkspeed")
        self.assertTrue(_metric_lines(out), "linkspeed 没有指标行")
        self.assertIn("档位", out + "  ")   # 4 元组带说明 (括号内)

    def test_metrics_fn_exception_does_not_break_cli(self):
        """metrics_fn 自己抛异常 → 不得连带崩掉整个模块打印."""
        key = "gateway"
        with mock.patch.dict(
                N.MODULE_PRESENTATION[key],
                {"metrics_fn": mock.Mock(side_effect=RuntimeError("boom"))}):
            out = self._print(key)
        self.assertIsInstance(out, str)          # 没崩
        self.assertNotIn("boom", out)            # 也不该把异常糊到屏幕上

    def test_verbose_mode_still_prints_raw_fields(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            N._cli_print_result({"total_entries": 3, "unique_macs": 2},
                                verbose=True, key="arp")
        out = buf.getvalue()
        self.assertIn("total_entries", out)
        self.assertIn("unique_macs", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
