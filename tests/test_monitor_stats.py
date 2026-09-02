# -*- coding: utf-8 -*-
"""盯障模式统计层单元测试 (阶段 F · v1.7.0 PR-F0 引入)

覆盖: _probe_path_mtu 双语 ping 输出解析 / _tcp_stats_snapshot 双路采集 /
_default_route_if_mtu / _detect_monitor_events 的 mtu_mismatch 与
tcp_retrans_burst / _monitor_conclusion 追加式结论矩阵。
跑用: cd 到项目根目录, `python tests/test_monitor_stats.py`
"""
import json
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


T0 = 1000.0


def _mk_stream(ok_ts, loss_ts, t0=T0, ms=3.0):
    st = [("ok", t0 + t, ms) for t in ok_ts] + \
         [("loss", t0 + t, None) for t in loss_ts]
    st.sort(key=lambda x: x[1])
    return st


_FULL = [float(i) for i in range(600)]


def _snap(**extra):
    """健康基线快照 (无丢包无事件), extra 覆盖/追加统计层键."""
    snap = {"gw_stream": _mk_stream(_FULL, []),
            "ext_stream": _mk_stream(_FULL, []),
            "tcp": [], "dns": []}
    snap.update(extra)
    return snap


def _events(snap, t_end=600.0):
    return N._detect_monitor_events(snap, T0, T0 + t_end)


def _stats_ok():
    return {"gw": {"loss_pct": 0.0}, "ext": {"loss_pct": 0.0}}


# ── ping 输出合成 (中文系统/英文系统双语回归, 见 windows-ping-locale-gotcha) ──

_PING_EN = {
    "fits": "Reply from 223.5.5.5: bytes=32 time=4ms TTL=55",
    "too_big": "Packet needs to be fragmented but DF set.",
    "timeout": "Request timed out.",
}
_PING_ZH = {
    "fits": "来自 223.5.5.5 的回复: 字节=32 时间=4ms TTL=55",
    "too_big": "需要拆分数据包但是设置 DF。",
    "timeout": "请求超时。",
}


def _fake_ping_run_cmd(true_payload_cap, lang, timeout_payloads=frozenset()):
    """合成 ping -f -l <mid> 的 run_cmd 替身: ≤ cap 回 fits, > cap 回 too_big."""
    texts = _PING_EN if lang == "en" else _PING_ZH

    def fake(cmd, timeout=30, **kw):
        m = re.search(r"-l (\d+)", cmd)
        mid = int(m.group(1)) if m else 0
        if mid in timeout_payloads:
            return 1, texts["timeout"], ""
        if mid <= true_payload_cap:
            return 0, texts["fits"], ""
        return 1, texts["too_big"], ""

    return fake


class TestProbePathMtu(unittest.TestCase):
    """_probe_path_mtu: 二分查找 + 三态判读 (太大/放行/无信号)."""

    def test_converges_english_output(self):
        """真实路径 MTU 1280 (payload cap 1252), 英文输出 → 精确收敛."""
        with mock.patch("netpulse.run_cmd",
                        side_effect=_fake_ping_run_cmd(1252, "en")):
            r = N._probe_path_mtu("223.5.5.5")
        self.assertNotIn("error", r)
        self.assertEqual(r["path_mtu"], 1280)
        self.assertEqual(r["max_payload"], 1252)
        self.assertTrue(r["fragmentation_risk"])
        self.assertEqual(r["indeterminate_pct"], 0)

    def test_converges_chinese_output(self):
        """中文系统输出 (需要拆分数据包但是设置 DF / 的回复) 同样收敛."""
        with mock.patch("netpulse.run_cmd",
                        side_effect=_fake_ping_run_cmd(1252, "zh")):
            r = N._probe_path_mtu("223.5.5.5")
        self.assertNotIn("error", r)
        self.assertEqual(r["path_mtu"], 1280)

    def test_all_no_signal_bails_out_with_error(self):
        """ICMP 全程被滤 (防火墙/禁 ping): 不得返回假 path_mtu."""
        with mock.patch("netpulse.run_cmd",
                        side_effect=_fake_ping_run_cmd(0, "en",
                                                       timeout_payloads=set(range(576, 1473)))):
            r = N._probe_path_mtu("10.0.0.1")
        self.assertTrue(r.get("error"))
        self.assertIsNone(r.get("path_mtu"))
        self.assertTrue(r.get("indeterminate"))
        # MAX_INDETERMINATE=4 次即放弃, 不打满 MAX_TOTAL=15
        self.assertEqual(r["probes"], 4)

    def test_early_timeout_converges_conservatively(self):
        """首个探测无信号 → 范围收缩后继续, 结果偏保守 (≤ 真值) 且标注不确定."""
        # 首个二分点 mid=1024 超时 (其余按 cap=1252): high 收缩到 1023,
        # 之后全 fits → best=1023, path_mtu=1051, 1/10 次不确定
        with mock.patch("netpulse.run_cmd",
                        side_effect=_fake_ping_run_cmd(1252, "en",
                                                       timeout_payloads={1024})):
            r = N._probe_path_mtu("223.5.5.5")
        self.assertNotIn("error", r)
        self.assertEqual(r["path_mtu"], 1051)
        self.assertEqual(r["indeterminate_pct"], 10.0)


class TestTcpStatsSnapshot(unittest.TestCase):
    """_tcp_stats_snapshot: PowerShell 主路 + netstat -s 回退."""

    _PS_JSON = json.dumps({
        "SegmentSent": 200000, "SegmentReceived": 190000,
        "RetransmittedSegments": 1600, "Errors": 2,
        "FailureCounts": 10, "ConnectionsInitiated": 500,
        "ConnectionsAccepted": 80, "CurrentConnections": 25,
    })
    _ANO = ("  TCP    192.168.1.5:50001   223.5.5.5:443   ESTABLISHED   1234\n"
            "  TCP    192.168.1.5:50002   119.29.29.29:53  ESTABLISHED   1234\n"
            "  UDP    192.168.1.5:50003   *:*              \n")

    def test_powershell_primary_path(self):
        with mock.patch("netpulse.run_ps", return_value=(0, self._PS_JSON, "")), \
             mock.patch("netpulse.run_cmd", return_value=(0, self._ANO, "")) as rc:
            stats = N._tcp_stats_snapshot()
        self.assertEqual(stats["segments_sent"], 200000)
        self.assertEqual(stats["retransmitted"], 1600)
        self.assertEqual(stats["conn_failures"], 10)
        # current_connections 以 netstat -ano 实数为准 (Get-NetTCPStatistics 假零修正)
        self.assertEqual(stats["current_connections"], 2)
        # 主路成功就不再跑 netstat -s 回退
        self.assertFalse(any("netstat -s" in str(c) for c in rc.call_args_list))

    def test_netstat_s_fallback_chinese(self):
        zh = ("TCP 统计信息\n\n"
              "  活动的连接 = 2\n\n"
              "  发送的分段 = 150000\n"
              "  接收的分段 = 148000\n"
              "  重新传输的分段 = 1200\n"
              "  错误的分段 = 0\n"
              "  失败 = 5\n")
        def fake_cmd(cmd, timeout=30, **kw):
            if "netstat -s" in cmd:
                return 0, zh, ""
            return 0, self._ANO, ""
        with mock.patch("netpulse.run_ps", return_value=(1, "", "err")), \
             mock.patch("netpulse.run_cmd", side_effect=fake_cmd):
            stats = N._tcp_stats_snapshot()
        self.assertEqual(stats["segments_sent"], 150000)
        self.assertEqual(stats["retransmitted"], 1200)
        self.assertEqual(stats["conn_failures"], 5)

    def test_netstat_s_fallback_english(self):
        en = ("TCP Statistics\n\n"
              "  Segments Sent = 310000\n"
              "  Segments Received = 305000\n"
              "  Segments Retransmitted = 9000\n")
        def fake_cmd(cmd, timeout=30, **kw):
            if "netstat -s" in cmd:
                return 0, en, ""
            return 0, "", ""
        with mock.patch("netpulse.run_ps", return_value=(0, "", "")), \
             mock.patch("netpulse.run_cmd", side_effect=fake_cmd):
            stats = N._tcp_stats_snapshot()
        self.assertEqual(stats["segments_sent"], 310000)
        self.assertEqual(stats["retransmitted"], 9000)
        self.assertIsNone(stats["current_connections"])

    def test_both_paths_fail_no_fake_numbers(self):
        """PS 空 + netstat -s 不可解析 → 不产出可被误读的计数."""
        with mock.patch("netpulse.run_ps", return_value=(0, "", "")), \
             mock.patch("netpulse.run_cmd", return_value=(0, "garbage output", "")):
            stats = N._tcp_stats_snapshot()
        self.assertEqual(stats.get("segments_sent", 0), 0)
        self.assertIsNone(stats.get("current_connections"))


class TestDefaultRouteIfMtu(unittest.TestCase):
    """_default_route_if_mtu: 默认路由出口接口 MTU."""

    def test_single_object_json(self):
        out = json.dumps({"InterfaceAlias": "以太网", "NlMtu": 1500})
        with mock.patch("netpulse.run_ps", return_value=(0, out, "")):
            self.assertEqual(N._default_route_if_mtu(), (1500, "以太网"))

    def test_list_json_takes_first(self):
        out = json.dumps([{"InterfaceAlias": "WLAN", "NlMtu": 1400}])
        with mock.patch("netpulse.run_ps", return_value=(0, out, "")):
            self.assertEqual(N._default_route_if_mtu(), (1400, "WLAN"))

    def test_empty_output_returns_none(self):
        with mock.patch("netpulse.run_ps", return_value=(0, "", "")):
            self.assertEqual(N._default_route_if_mtu(), (None, ""))

    def test_zero_mtu_treated_as_missing(self):
        out = json.dumps({"InterfaceAlias": "VPN", "NlMtu": 0})
        with mock.patch("netpulse.run_ps", return_value=(0, out, "")):
            mtu, name = N._default_route_if_mtu()
            self.assertIsNone(mtu)
            self.assertEqual(name, "VPN")


class TestMonitorEventsMtu(unittest.TestCase):
    """_detect_monitor_events 的 mtu_mismatch 分支."""

    def _mtu_snap(self, path_mtu, if_mtu=1500, done_ts=None, extra_paths=()):
        paths = [{"target": "223.5.5.5", "path_mtu": path_mtu}]
        paths += list(extra_paths)
        block = {"path_mtus": paths, "local_if_mtu": if_mtu}
        if done_ts is not None:
            block["done_ts"] = done_ts
        return _snap(mtu=block)

    def test_trigger_diff_220(self):
        evs = _events(self._mtu_snap(1280, 1500, done_ts=T0 + 300))
        mtu_evs = [e for e in evs if e["type"] == "mtu_mismatch"]
        self.assertEqual(len(mtu_evs), 1)
        e = mtu_evs[0]
        self.assertEqual(e["cls"], "mtu")
        self.assertEqual(e["stream"], "mtu")
        self.assertEqual(e["path_mtu"], 1280)
        self.assertEqual(e["if_mtu"], 1500)
        self.assertIn("差 220", e["detail"])
        self.assertEqual(e["start_ts"], T0 + 300)   # done_ts 定位事件时刻

    def test_pppoe_1492_not_fired(self):
        evs = _events(self._mtu_snap(1492, 1500))
        self.assertEqual([e for e in evs if e["type"] == "mtu_mismatch"], [])

    def test_probe_error_not_fired(self):
        snap = _snap(mtu={"path_mtus": [{"target": "x", "error": "ICMP 被过滤",
                                         "path_mtu": None}],
                          "local_if_mtu": 1500})
        self.assertEqual([e for e in _events(snap)
                          if e["type"] == "mtu_mismatch"], [])

    def test_mixed_paths_use_minimum(self):
        extra = ({"target": "y", "error": "无响应", "path_mtu": None},
                 {"target": "z", "path_mtu": 1400})
        evs = _events(self._mtu_snap(1280, 1500, extra_paths=extra))
        mtu_evs = [e for e in evs if e["type"] == "mtu_mismatch"]
        self.assertEqual(len(mtu_evs), 1)
        self.assertEqual(mtu_evs[0]["path_mtu"], 1280)

    def test_missing_if_mtu_not_fired(self):
        snap = _snap(mtu={"path_mtus": [{"target": "x", "path_mtu": 1280}]})
        self.assertEqual([e for e in _events(snap)
                          if e["type"] == "mtu_mismatch"], [])

    def test_legacy_snap_without_mtu_key_no_crash(self):
        """旧快照/合成输入无 mtu 键 → 防御性 .get, 不崩不出事件."""
        self.assertEqual([e for e in _events(_snap())
                          if e["type"] == "mtu_mismatch"], [])


class TestMonitorEventsRetrans(unittest.TestCase):
    """_detect_monitor_events 的 tcp_retrans_burst 分支 (会话差分口径)."""

    def _tq(self, rate, series=((30.0, 100000, 8000), (330.0, 200000, 16000)),
            **extra):
        d = {"retrans_rate_pct": rate, "sent_delta": 100000,
             "retrans_delta": 8000, "samples": 11, "series": list(series)}
        d.update(extra)
        return d

    def test_trigger_8pct(self):
        evs = _events(_snap(tcp_quality=self._tq(8.0)))
        rt = [e for e in evs if e["type"] == "tcp_retrans_burst"]
        self.assertEqual(len(rt), 1)
        e = rt[0]
        self.assertEqual(e["cls"], "l4_loss")
        self.assertEqual(e["stream"], "tcpq")
        self.assertIn("重传率 8.0%", e["detail"])
        self.assertEqual(e["start_ts"], T0 + 30)    # series[0][0]
        self.assertEqual(e["end_ts"], T0 + 330)     # series[-1][0]

    def test_rate_none_no_event(self):
        """分母保护 (sent_delta < 5000) → retrans_rate_pct=None → 不判."""
        evs = _events(_snap(tcp_quality=self._tq(None)))
        self.assertEqual([e for e in evs if e["type"] == "tcp_retrans_burst"], [])

    def test_below_threshold_no_event(self):
        evs = _events(_snap(tcp_quality=self._tq(2.5)))
        self.assertEqual([e for e in evs if e["type"] == "tcp_retrans_burst"], [])

    def test_empty_series_still_events(self):
        evs = _events(_snap(tcp_quality=self._tq(6.0, series=())))
        rt = [e for e in evs if e["type"] == "tcp_retrans_burst"]
        self.assertEqual(len(rt), 1)
        self.assertEqual(rt[0]["start_ts"], T0)
        self.assertEqual(rt[0]["end_ts"], T0)

    def test_legacy_snap_without_tcp_quality_no_crash(self):
        self.assertEqual([e for e in _events(_snap())
                          if e["type"] == "tcp_retrans_burst"], [])


class TestMonitorConclusionV17(unittest.TestCase):
    """_monitor_conclusion 追加式结论: MTU/重传与任何 verdict 并存."""

    def test_stable_plus_mtu_upgrades_to_degraded(self):
        snap = _snap(mtu={"path_mtus": [{"target": "223.5.5.5", "path_mtu": 1280}],
                          "local_if_mtu": 1500, "done_ts": T0 + 300})
        verdict, text, advice = N._monitor_conclusion(
            _events(snap), _stats_ok(), snap)
        self.assertEqual(verdict, "degraded")
        self.assertIn("路径 MTU 1280", text)
        self.assertIn("netsh interface ipv4 set subinterface", advice)
        self.assertIn("mtu=1280", advice)

    def test_carrier_outage_plus_retrans_keeps_carrier(self):
        snap = _snap(
            ext_stream=_mk_stream([t for t in _FULL if t not in (100, 101, 102)],
                                  [100.0, 101.0, 102.0]),
            tcp_quality={"retrans_rate_pct": 8.0, "sent_delta": 200000,
                         "retrans_delta": 16000, "samples": 11,
                         "series": [(30.0, 100000, 8000)]})
        verdict, text, advice = N._monitor_conclusion(
            _events(snap), {"gw": {"loss_pct": 0.0}, "ext": {"loss_pct": 0.5}}, snap)
        self.assertEqual(verdict, "carrier")       # 中断定位不被统计层覆盖
        self.assertIn("TCP 重传率 8.0%", text)
        self.assertIn("报障", advice)

    def test_mtu_and_retrans_together_same_origin_advice(self):
        snap = _snap(
            mtu={"path_mtus": [{"target": "223.5.5.5", "path_mtu": 1280}],
                 "local_if_mtu": 1500, "done_ts": T0 + 300},
            tcp_quality={"retrans_rate_pct": 9.0, "sent_delta": 200000,
                         "retrans_delta": 18000, "samples": 11,
                         "series": [(30.0, 100000, 9000)]})
        verdict, text, advice = N._monitor_conclusion(
            _events(snap), _stats_ok(), snap)
        self.assertEqual(verdict, "degraded")
        self.assertIn("路径 MTU 1280", text)
        self.assertIn("TCP 重传率 9.0%", text)
        self.assertIn("同源", advice)

    def test_retrans_only_no_mtu(self):
        snap = _snap(tcp_quality={"retrans_rate_pct": 7.0, "sent_delta": 200000,
                                  "retrans_delta": 14000, "samples": 11,
                                  "series": [(30.0, 100000, 7000)]})
        verdict, text, advice = N._monitor_conclusion(
            _events(snap), _stats_ok(), snap)
        self.assertEqual(verdict, "degraded")
        self.assertIn("MTU 正常而重传率超标", advice)

    def test_stable_unaffected_without_new_events(self):
        verdict, text, advice = N._monitor_conclusion(
            _events(_snap()), _stats_ok(), _snap())
        self.assertEqual(verdict, "stable")


class TestMonitorSessionContractV17(unittest.TestCase):
    """MonitorSession 统计层常量/入参契约 (防漂移)."""

    def test_constants(self):
        self.assertEqual(N.MonitorSession.TCPSTAT_INTERVAL_S, 30)
        self.assertEqual(N.MonitorSession.TCPSTAT_MIN_SENT_DELTA, 5000)
        self.assertEqual(N.MonitorSession.MTU_MISMATCH_MIN_DIFF, 100)
        self.assertEqual(N.MonitorSession.TCP_RETRANS_ERR_PCT, 5.0)
        self.assertTrue(N.MonitorSession.MONITOR_LOAD_URL.startswith("https://"))

    def test_init_accepts_load_url(self):
        s = N.MonitorSession(60, ext_target="223.5.5.5",
                             load_url="https://example.com/f.bin")
        self.assertEqual(s._load_url, "https://example.com/f.bin")
        self.assertIsNone(N.MonitorSession(60)._load_url)

    def test_run_monitor_mode_signature(self):
        import inspect
        params = inspect.signature(N.run_monitor_mode).parameters
        self.assertIn("load_url", params)


if __name__ == "__main__":
    unittest.main(verbosity=2)
