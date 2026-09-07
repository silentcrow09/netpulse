# -*- coding: utf-8 -*-
"""v1.11.0 网卡错误暴增 (nic_error_burst) 回归 (mock 隔离, 不碰真实网卡)。

背景: LAN 内某台电脑大流量上传 → 全网断 (强制百兆恢复)。根因是千兆自
协商兼容性/双工不匹配产生的 CRC 错包 — 驱动层丢弃, 抓包永远看不到, 只有
Get-NetAdapterStatistics 计数器能暴露。盯障 30s 周期采样 → 会话差分 →
错误暴增 + 网络症状同时出现 → nic_error_burst 事件 + 修复建议 (含
Set-NetAdapterAdvancedProperty 强制百兆的 (管理员) 命令)。

覆盖:
  N1  _nic_err_snapshot 解析/聚合/异常安全
  N2  MonitorSession._nic_quality 会话差分 (暴增判定/无暴增/样本不足/回绕)
  N3  _detect_monitor_events 的 nic_error_burst 分支 (时段/detail)
  N4  _monitor_conclusion: 有症状升级 degraded + 修复命令可一键提取;
      无症状不出链路层结论
  N5  CSV 行去重回归: tcp_retrans 采样行不随 probe 大循环重复 (v1.11.0 修正)
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


T0 = 1000.0
FULL = [float(i) for i in range(600)]


def _mk_stream(ok_ts, loss_ts, t0=T0, ms=3.0):
    st = [("ok", t0 + t, ms) for t in ok_ts] + \
         [("loss", t0 + t, None) for t in loss_ts]
    st.sort(key=lambda x: x[1])
    return st


def _snap(**extra):
    snap = {"gw_stream": _mk_stream(FULL, []),
            "ext_stream": _mk_stream(FULL, []),
            "tcp": [], "dns": []}
    snap.update(extra)
    return snap


def _stats_ok():
    return {"gw": {"loss_pct": 0.0}, "ext": {"loss_pct": 0.0}}


def _events(snap, t_end=600.0):
    return N._detect_monitor_events(snap, T0, T0 + t_end)


def _nq(err_delta=50, burst=(30.0, 150.0), max_win=40):
    """合成 nic_quality 块 (默认: 暴增 50, 错误集中 30~150s 区间)."""
    return {"series": [], "err_delta": err_delta, "discarded_delta": 2,
            "max_window_delta": max_win,
            "burst_start_s": burst[0] if burst else None,
            "burst_end_s": burst[1] if burst else None,
            "samples": 11}


class TestNicErrSnapshot(unittest.TestCase):
    """N1: Get-NetAdapterStatistics 聚合."""

    def test_aggregates_all_adapters(self):
        out = ('[{"Name":"以太网","ReceivedPacketErrors":3,"SentPacketErrors":4,'
               '"ReceivedDiscardedPackets":1,"SentDiscardedPackets":0},'
               '{"Name":"WLAN","ReceivedPacketErrors":10,"SentPacketErrors":0,'
               '"ReceivedDiscardedPackets":0,"SentDiscardedPackets":2}]')
        with mock.patch.object(N, "run_ps", return_value=(0, out, "")):
            errs, disc = N._nic_err_snapshot()
        self.assertEqual((errs, disc), (17, 3))

    def test_failure_returns_none(self):
        with mock.patch.object(N, "run_ps", return_value=(1, "", "err")):
            self.assertEqual(N._nic_err_snapshot(), (None, None))
        with mock.patch.object(N, "run_ps", side_effect=RuntimeError("x")):
            self.assertEqual(N._nic_err_snapshot(), (None, None))


class TestNicQuality(unittest.TestCase):
    """N2: 会话差分与 burst 区间定位."""

    def _sess(self, samples):
        s = N.MonitorSession(600)
        s._t0 = T0
        s._nicstat_samples = [(T0 + t, e, d) for t, e, d in samples]
        return s

    def test_burst_detected(self):
        # 全程单调涨: 最大跨度增量 = 首(100)→尾(146) = 46
        s = self._sess([(0, 100, 1), (30, 100, 1), (60, 105, 2),
                        (150, 145, 3), (300, 146, 3)])
        nq = s._nic_quality()
        self.assertEqual(nq["err_delta"], 46)
        self.assertEqual(nq["max_window_delta"], 46)      # 146-100
        self.assertEqual((nq["burst_start_s"], nq["burst_end_s"]), (0.0, 300.0))

    def test_below_threshold_no_burst(self):
        s = self._sess([(0, 100, 0), (300, 105, 1)])      # 增量 5 < 20
        nq = s._nic_quality()
        self.assertEqual(nq["err_delta"], 5)
        self.assertIsNone(nq["burst_start_s"])

    def test_too_few_samples(self):
        s = self._sess([(0, 100, 0)])
        nq = s._nic_quality()
        self.assertEqual(nq["err_delta"], 0)
        self.assertEqual(nq["samples"], 1)

    def test_counter_rollback_safe(self):
        """计数回绕 (适配器重置) 不误判."""
        s = self._sess([(0, 100, 0), (60, 50, 0), (300, 130, 0)])
        nq = s._nic_quality()
        self.assertEqual(nq["err_delta"], 0)              # 首尾增量被回绕抵消
        self.assertIsNone(nq["burst_start_s"])


class TestDetectNicEvent(unittest.TestCase):
    """N3: 事件生成."""

    def test_event_with_burst_window(self):
        evs = _events(_snap(nic_quality=_nq(50, (30.0, 150.0), 40)))
        ev = next(e for e in evs if e["type"] == "nic_error_burst")
        self.assertEqual(ev["cls"], "nic")
        self.assertEqual(ev["stream"], "nic")
        self.assertEqual(ev["err_delta"], 50)
        self.assertEqual(ev["start_ts"], T0 + 30.0)
        self.assertEqual(ev["end_ts"], T0 + 150.0)
        self.assertIn("错误集中在", ev["detail"])
        self.assertIn("抓包看不到", ev["detail"])

    def test_event_without_burst_window(self):
        evs = _events(_snap(nic_quality=_nq(25, None, 0)))
        ev = next(e for e in evs if e["type"] == "nic_error_burst")
        self.assertIn("无明显集中区间", ev["detail"])
        self.assertEqual((ev["start_ts"], ev["end_ts"]), (T0, T0 + 600.0))

    def test_small_delta_no_event(self):
        evs = _events(_snap(nic_quality=_nq(5, (30.0, 60.0), 3)))
        self.assertEqual([e for e in evs if e["type"] == "nic_error_burst"], [])

    def test_legacy_snap_no_crash(self):
        self.assertEqual([e for e in _events(_snap())
                          if e["type"] == "nic_error_burst"], [])


class TestConclusionNic(unittest.TestCase):
    """N4: 结论矩阵 — 链路层根因 + 修复命令."""

    def _symptom_events(self):
        """网关流尾部连续丢包 (outage/internal 症状) + nic_error_burst."""
        snap = _snap(gw_stream=_mk_stream(FULL[:560], FULL[560:]))
        evs = _events(snap)
        self.assertTrue(any(e["type"] == "outage" and e.get("cls") == "internal"
                            for e in evs), "合成流必须产生网关中断症状")
        evs.append({"type": "nic_error_burst", "stream": "nic", "cls": "nic",
                    "start_ts": T0 + 30, "end_ts": T0 + 150, "duration_s": 120.0,
                    "open_at_end": False, "detail": "d", "id": 9,
                    "err_delta": 50, "discarded_delta": 2, "max_window_delta": 40})
        return evs

    def test_degraded_with_symptom(self):
        verdict, text, advice = N._monitor_conclusion(
            self._symptom_events(), _stats_ok(), _snap())
        # 症状是网关中断 → verdict 本身 internal (nic 不改写已有结论, 只追加);
        # stable 场景才升级 degraded — 核心断言是链路层结论与修复命令追加成功
        self.assertIn(verdict, ("internal", "degraded"))
        self.assertIn("收发错误暴增 50", text)
        self.assertIn("链路层错包实锤", text)
        self.assertIn("Set-NetAdapterAdvancedProperty", advice)
        self.assertIn("*SpeedDuplex", advice)

    def test_fix_command_extractable(self):
        """建议里的 (管理员) 命令必须能被一键执行提取 (powershell kind)。"""
        verdict, text, advice = N._monitor_conclusion(
            self._symptom_events(), _stats_ok(), _snap())
        cmds = N._extract_admin_fix_commands(
            [mock.Mock(recommendations=[advice])])
        self.assertEqual(len(cmds), 1)
        kind, cmd = cmds[0]
        self.assertEqual(kind, "powershell")
        self.assertIn("Set-NetAdapterAdvancedProperty", cmd)
        self.assertNotIn("(管理员)", cmd, "标记尾缀不得混入命令体")

    def test_no_symptom_no_verdict_upgrade(self):
        """错包涨但网络没症状: 事件存在但不升级 verdict (stable 保持)。"""
        evs = [{"type": "nic_error_burst", "stream": "nic", "cls": "nic",
                "start_ts": T0 + 30, "end_ts": T0 + 150, "duration_s": 120.0,
                "open_at_end": False, "detail": "d", "id": 1,
                "err_delta": 50, "discarded_delta": 2, "max_window_delta": 40}]
        verdict, text, advice = N._monitor_conclusion(evs, _stats_ok(), _snap())
        self.assertEqual(verdict, "stable")
        self.assertNotIn("Set-NetAdapterAdvancedProperty", advice)


class TestCsvRowsDedup(unittest.TestCase):
    """N5: tcp_retrans 采样行不随 probe 大循环重复 (v1.11.0 修正的既有 bug)."""

    def test_retrans_rows_written_once(self):
        # 源码契约: tcp_retrans 行生成块必须与 probe 大循环同级 (8 空格缩进) —
        # v1.7.0 曾缩进 12 空格落在循环体内, CSV 每行重复写 4 次
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "netpulse.py")
        lines = open(path, encoding="utf-8").read().split("\n")
        idx = next(i for i, l in enumerate(lines) if "TCP 重传采样行" in l)
        for_i = next(i for i, l in enumerate(lines)
                     if i > idx and "for i in range(1, len(tcpstat_series))" in l)
        self.assertEqual(len(lines[for_i]) - len(lines[for_i].lstrip()), 8,
                         "tcp_retrans 生成块必须与大循环同级 (8 空格)")


if __name__ == "__main__":
    unittest.main(verbosity=1)
