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
import sys
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
        "检测范围", "主机信息", "未检测"),
    "report_brief.html": ("<html", "NetPulse"),
    "report_brief_v2.html": ("NetPulse",),
}


def _fixture_run():
    """富 fixture: 2 警告 + 4 完成 + 2 未检测, 网关带 ping 序列, 测速带上下行。"""
    rtts = [2.1, 2.4, 2.2, 2.5, 8.1, 2.3, 2.2, 2.4, 2.6, 2.2,
            2.3, 2.5, 2.4, 2.2, 2.3, 2.6, 2.4, 2.2, 2.5, 2.3]
    results = {
        "gateway": {"gateway": "192.168.1.1", "issues": [],
                    "ping": {"rtts": rtts, "avg_ms": 2.3, "loss_pct": 0.0,
                             "sent": 20, "recv": 20}},
        "dns": {"system_dns": "221.228.255.1", "avg_ms": 86.0, "fail": 0,
                "total": 20,
                "issues": [{"severity": "warning",
                            "message": "DNS 解析偏慢（平均 86ms）",
                            "detail": "当前系统 DNS 平均响应 86ms, "
                                      "高于网关直连参考水平"}]},
        "wifi": {"ssid": "Home-2.4G", "rssi": -72, "channel": 6,
                 "issues": [{"severity": "warning",
                             "message": "Wi-Fi 信号偏弱（RSSI -72dBm）",
                             "detail": "弱信号区间, 速率与稳定性受影响"}]},
        "speedtest": {"download_mbps": 285.4, "upload_mbps": 31.2,
                      "issues": []},
        "mtu": {"path_mtu": 1500, "issues": []},
        "tcpstats": {"established": 42, "issues": []},
    }
    statuses = {"gateway": "完成", "dns": "警告", "wifi": "警告",
                "speedtest": "完成", "mtu": "完成", "tcpstats": "完成"}
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


def _render_all():
    rep = np.build_report(run=_fixture_run())
    if rep is None:
        raise RuntimeError("build_report(run=fixture) 返回 None")
    return [
        ("report_customer.html", np.render_report_html_customer(rep)),
        ("report_brief.html", np.render_report_html_brief(rep)),
        ("report_brief_v2.html", np.render_report_html_brief_v2(rep)),
    ]


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
                html, base,
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
