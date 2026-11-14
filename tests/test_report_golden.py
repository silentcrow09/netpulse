# -*- coding: utf-8 -*-
"""报告渲染 golden 基线 (v1.25.0)。

固定 fixture 渲染 customer / brief / brief_v2 三份 HTML, 与
tests/fixtures/golden/ 下基线**逐字节**比对 —— 这是导出链渲染器的回归安全网,
把 AGENTS.md「报告渲染」节规定的「改前/改后 Compare-Object 逐行比对」手工流程
自动化为测试。

- 基线生成: `python tests/test_report_golden.py --bless`
- 基线变更必须显式重生成并审查 diff (测试失败文案里有指引)
- fixture 覆盖: 图表 (网关延迟折线 / 测速柱状 / 状态分布条) + 待办清单
  (警告卡) + Hero 检测范围 + 未检测模块, 保证基线不是贫瘠快照
"""
import argparse
import io
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np  # noqa: E402

GOLDEN_DIR = os.path.join(ROOT, "tests", "fixtures", "golden")

# (文件名, 标记集) —— 标记用于防止「基线在但内容贫瘠」的假安全网
RICH_MARKERS = {
    "report_customer.html": (
        "网关延迟时间序列", "宽带测速", "状态分布", "需要您关注",
        "检测范围", "主机信息", "未检测",
        # 根因命中分支 (fixture: DNS 失败率 55% 触发 _rule_dns_failure):
        # rcard/证据链/「已展开首要问题项」是导出报告最复杂的区块, 必须在基线覆盖内
        "主要问题", "已展开首要问题项"),
    "report_brief.html": ("<html", "NetPulse"),
    "report_brief_v2.html": ("NetPulse",),
    "monitor_report.html": ("盯障",),
}


def _fixture_run():
    """富 fixture: 2 警告 + 4 完成 + 2 未检测, 网关带 ping 序列, 测速带上下行。"""
    rtts = [2.1, 2.4, 2.2, 2.5, 8.1, 2.3, 2.2, 2.4, 2.6, 2.2,
            2.3, 2.5, 2.4, 2.2, 2.3, 2.6, 2.4, 2.2, 2.5, 2.3]
    results = {
        "gateway": {"gateway": "192.168.1.1", "issues": [],
                    "ping": {"rtts": rtts, "avg_ms": 2.3, "loss_pct": 0.0,
                             "sent": 20, "recv": 20}},
        "dns": {"system_dns": ["221.228.255.1"], "avg_time_ms": 118,
                "current_avg_ms": 118, "success_count": 9, "total_count": 20,
                "current_total_count": 20},
        "wifi": {"ssid": "Home-2.4G", "rssi": -72, "channel": 6,
                 "issues": [{"severity": "warning",
                             "message": "Wi-Fi 信号偏弱（RSSI -72dBm）",
                             "detail": "弱信号区间, 速率与稳定性受影响"}]},
        "speedtest": {"download_mbps": 285.4, "upload_mbps": 31.2,
                      "issues": []},
        "mtu": {"path_mtu": 1500, "issues": []},
        "tcpstats": {"established": 42, "issues": []},
        "ipv6": {"ipv6_native": False, "issues": []},
        "iperf3": {"error": "未配置 iperf3 服务器", "issues": []},
    }
    statuses = {"gateway": "完成", "dns": "警告", "wifi": "警告",
                "speedtest": "完成", "mtu": "完成", "tcpstats": "完成",
                "ipv6": "完成", "iperf3": "未检测"}
    keys = ["gateway", "dns", "wifi", "speedtest", "mtu", "tcpstats",
            "ipv6", "iperf3"]
    return {
        "app": "NetPulse", "version": "1.25.0",
        "generated_at": datetime(2026, 1, 2, 3, 4, 5),
        "system": {"local_ip": "192.168.1.2", "hostname": "PC-01",
                   "gateway": "192.168.1.1", "dns": "221.228.255.1",
                   "public_ip": "203.0.113.7"},
        "status": statuses, "results": results, "evidence": {},
        "keys": keys, "duration_ms": 252000, "total_modules": len(keys),
    }


def _monitor_fixture_res():
    """盯障导出固定 res: 与 save_monitor_report 消费的字段同形, 全部定值
    (时间戳/样本/事件均硬编码 —— _render_monitor_html 无 now() 依赖)。"""
    t0 = 1796000000
    return {
        "mode": "monitor",
        "timestamp": "2026-01-02T03:04:05",
        "started_at": "2026-01-02 03:04:05",
        "ended_at": "2026-01-02 03:34:05",
        "duration_planned_s": 1800,
        "duration_actual_s": 1800,
        "early_terminated": False,
        "targets": {"gateway": "192.168.1.1", "external": "223.5.5.5",
                    "external_resolved": "223.5.5.5",
                    "tcp_target": "223.5.5.5:53",
                    "dns_server": "223.5.5.5",
                    "dns_domain": "www.baidu.com"},
        "notes": [{"t": 15, "text": "负载窗结束"}],
        "samples": {
            "gw_rtt": [[i * 5.0, 2.0 + (i % 3)] for i in range(300)],
            "gw_loss": [120.0, 121.5, 400.0],
            "ext_rtt": [[i * 5.0, 20.0 + (i % 7)] for i in range(300)],
            "ext_loss": [610.0, 612.0],
            "tcp": [[i * 30.0, 21.0] for i in range(60)],
            "dns": [[i * 30.0, 30.0, "ok"] for i in range(60)],
        },
        "stats": {"gw": {"ok": 297, "loss": 3, "loss_pct": 1.0,
                         "avg_ms": 2.5, "p50_ms": 2.0, "p95_ms": 4.0,
                         "max_ms": 4.9},
                  "ext": {"ok": 298, "loss": 2, "loss_pct": 0.67,
                          "avg_ms": 21.0, "p50_ms": 20.0, "p95_ms": 26.0,
                          "max_ms": 27.1},
                  "tcp": {"ok": 60, "fail": 0, "ok_pct": 100.0,
                          "avg_ms": 21.0},
                  "dns": {"ok": 60, "fail": 0, "ok_pct": 100.0,
                          "avg_ms": 30.0}},
        "mtu": {"probe_status": "ok",
                "path_mtus": [{"target": "223.5.5.5", "path_mtu": 1500,
                               "probes": 3}],
                "local_if_mtu": 1500, "local_if_name": "以太网"},
        "tcp_quality": {"retrans_rate_pct": 0.42, "retrans_delta": 7,
                        "sent_delta": 1667,
                        "series": [[0, 100, 0], [30, 120, 1], [60, 140, 1]]},
        "nic_quality": {"err_delta": 0, "series": []},
        "events": [
            {"type": "jitter_burst", "stream": "ext", "cls": "carrier",
             "start_ts": t0 + 600, "end_ts": t0 + 637,
             "duration_s": 37.0, "open_at_end": False,
             "detail": "37s 内丢包 2 次 (0.7%)",
             "root_cause": "运营商/上联侧抖动",
             "start_disp": "03:14:05", "end_disp": "03:14:42"},
        ],
        "verdict": "degraded",
        "conclusion_text": "外网侧存在短暂抖动",
        "advice": "结合事件时间对照用户操作",
        "summary": "盯障 1800s: 网关丢包 1.0%, 外网丢包 0.67%, 无中断, "
                   "抖动集中 1 段",
        "local_ip": "192.168.1.2",
        "_csv_rows": [["2026-01-02 03:04:05", "gw_ping", 1, 2.0, 1, ""]],
    }


def _render_monitor_golden_html():
    """盯障导出 HTML (第四份 golden, v1.25.0 独立验证 P1-1): 走真实
    save_monitor_report 落盘链路后读回。json 快照内含落盘绝对路径 (随
    tmp 变化), 故只把 HTML 入基线; csv 内容固定 (fixture 定值)。"""
    res = _monitor_fixture_res()
    old_dir = np._report_dir
    tmp = tempfile.mkdtemp(prefix="np_golden_mon_")
    np._report_dir = lambda: tmp
    try:
        pair = np.save_monitor_report(res)
        if not pair:
            raise RuntimeError("save_monitor_report(fixture) 返回 None")
        with io.open(pair[0], "r", encoding="utf-8", newline="") as f:
            return f.read()
    finally:
        np._report_dir = old_dir
        shutil.rmtree(tmp, ignore_errors=True)


def _render_all():
    rep = np.build_report(run=_fixture_run())
    if rep is None:
        raise RuntimeError("build_report(run=fixture) 返回 None")
    return [
        ("report_customer.html", np.render_report_html_customer(rep)),
        ("report_brief.html", np.render_report_html_brief(rep)),
        ("report_brief_v2.html", np.render_report_html_brief_v2(rep)),
        ("monitor_report.html", _render_monitor_golden_html()),
    ]


def _norm(s):
    """换行归一: 渲染器恒输出 LF; 基线文件经 git 检出可能变 CRLF。
    内容不变性归本测试管, 行尾归 git 策略管 —— 归一后比内容。"""
    return s.replace("\r\n", "\n")


class TestReportGolden(unittest.TestCase):

    def test_golden_unchanged(self):
        if not os.path.isdir(GOLDEN_DIR) or not os.listdir(GOLDEN_DIR):
            self.skipTest("golden 基线缺失: 先运行 "
                          "python tests/test_report_golden.py --bless")
        for name, html in _render_all():
            path = os.path.join(GOLDEN_DIR, name)
            self.assertTrue(os.path.exists(path), "缺基线文件: %s" % name)
            with io.open(path, "r", encoding="utf-8", newline="") as f:
                base = f.read()
            self.assertEqual(
                _norm(html), _norm(base),
                "%s 与基线不一致 —— 导出渲染器被改动。确认为有意变更后运行 "
                "`python tests/test_report_golden.py --bless` 重新生成基线, "
                "并逐行审查 diff (AGENTS.md 报告渲染节)" % name)

    def test_golden_richness(self):
        if not os.path.isdir(GOLDEN_DIR) or not os.listdir(GOLDEN_DIR):
            self.skipTest("golden 基线缺失")
        for name, markers in RICH_MARKERS.items():
            path = os.path.join(GOLDEN_DIR, name)
            if not os.path.exists(path):
                continue
            with io.open(path, "r", encoding="utf-8") as f:
                base = f.read()
            for mk in markers:
                self.assertIn(mk, base,
                              "基线 %s 缺标记 %r —— fixture 可能退化了, "
                              "禁止在贫瘠快照上 --bless" % (name, mk))


def _bless():
    os.makedirs(GOLDEN_DIR, exist_ok=True)
    for name, html in _render_all():
        path = os.path.join(GOLDEN_DIR, name)
        with io.open(path, "w", encoding="utf-8", newline="") as f:
            f.write(html)
        print("blessed %s (%d bytes)" % (path, len(html.encode("utf-8"))))
    # 生成后立即跑 richness 自检, 防止把贫瘠快照固化为基线
    for name, markers in RICH_MARKERS.items():
        with io.open(os.path.join(GOLDEN_DIR, name), "r",
                     encoding="utf-8") as f:
            base = f.read()
        missing = [mk for mk in markers if mk not in base]
        if missing:
            raise SystemExit("%s 缺标记 %s —— fixture 贫瘠, 已拒绝固化"
                             % (name, missing))
    print("richness 自检通过")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--bless", action="store_true",
                    help="重新生成 golden 基线 (须人工审查 diff)")
    args = ap.parse_args()
    if args.bless:
        _bless()
    else:
        unittest.main()
