# -*- coding: utf-8 -*-
"""实测 brief_v2 的 A4 页数 (改「主要发现」区后必须验: 不能从双页变三页)。

开发期工具, **不属于回归套件** (文件名不带 test_ 前缀, 全量回归不会跑它)。
brief_v2 有 A4 高度锁这条硬约束, 改该区后用本工具复测页数。

用法:
    py -3.13 tests/_a4_pagecheck.py cur     # 测当前工作区
    py -3.13 tests/_a4_pagecheck.py head    # 测 HEAD 版 (在临时目录里 checkout 一份)

用项目自己的 PDF 出口 (_find_pdf_browser + _html_to_pdf) 打印, 数 PDF 页数。
"""
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

REPO = r"D:\Work\Projects\NetPulse"


def _mk_module(key, name, status, issues=None):
    return {"key": key, "name": name, "status": status, "verdict": "—",
            "key_metrics": [], "issues": issues or [],
            "has_tech_details": False, "raw": {}}


TIMEOUT_ISSUE = {"severity": "异常",
                 "text": "模块执行超时, 本次未取得该模块检测结果",
                 "impact": "未在超时阈值内完成, 相关指标与结论均不可信",
                 "action": "现场排查后重新运行本模块"}


def _mk_report(modules, root_causes=None, health=None):
    return {
        "app": "NetPulse", "version": "1.15.2", "schema_version": "1.2.0",
        "generated_at": datetime.datetime(2026, 10, 21, 14, 11, 0),
        "system": {"local_ip": "192.168.1.23", "gateway": "192.168.1.1",
                   "dns": "202.96.128.86", "public_ip": "113.249.115.93",
                   "geo": "杭州", "asn": "AS4134"},
        "health": health or {"score": 0, "grade": "F", "label": "严重",
                             "verdict": "未完成检测"},
        "counts": {"完成": 0, "警告": 0, "异常": 0, "错误": 0, "超时": len(modules),
                   "未检测": 0},
        "exempt_count": 0,
        "summary": {m["key"]: m["status"] for m in modules},
        "duration_ms": 102000, "selected_modules": len(modules), "total_modules": 23,
        "diagnosis": {"root_causes": root_causes or [], "overall_confidence": 0.0,
                      "rules_evaluated": 8, "rules_fired": 0},
        "modules": modules, "site_check": {}, "site_note": "", "meta_manual": {},
        "tech": {},
    }


def _rc(i, sev, title, desc):
    return {"id": "rc%d" % i, "title": title, "severity": sev, "confidence": 0.8,
            "description": desc, "recommendations": ["联系运营商核对出口策略"],
            "affected_modules": ["gateway"], "evidence_ids": []}


def scenarios():
    return {
        "all_timeout": _mk_report(
            [_mk_module("m%d" % i, "模块%d" % i, "超时", [dict(TIMEOUT_ISSUE)])
             for i in range(23)]),
        "many_issues_no_rootcause": _mk_report(
            [_mk_module("m%d" % i, "模块%d" % i, "异常",
                        [{"severity": "异常",
                          "text": "模块%d 检测到异常指标, 数值超出阈值范围" % i,
                          "impact": "影响业务", "action": "现场复核"}])
             for i in range(8)]),
        "four_rootcauses": _mk_report(
            [_mk_module("m%d" % i, "模块%d" % i, "异常",
                        [{"severity": "异常", "text": "模块%d 异常" % i,
                          "impact": "", "action": ""}]) for i in range(4)],
            root_causes=[_rc(1, "critical", "WAN 中断 (运营商链路故障)", "网关可达但外网不可达。"),
                         _rc(2, "high", "DNS 解析异常", "多个域名解析超时。"),
                         _rc(3, "medium", "无线环境干扰较高", "2.4G 信道拥堵。"),
                         _rc(4, "low", "MTU 偏小", "路径 MTU 探测到 1400。")]),
        "healthy": _mk_report(
            [_mk_module("m%d" % i, "模块%d" % i, "完成") for i in range(23)],
            health={"score": 100, "grade": "A", "label": "优秀", "verdict": "良好"}),
    }


def pdf_pages(pdf_path):
    raw = open(pdf_path, "rb").read()
    return len(re.findall(rb"/Type\s*/Page[^s]", raw))


def measure(M, tag):
    browser = M._find_pdf_browser()
    if not browser:
        return {"err": "找不到 Chrome/Edge"}
    tmp = tempfile.mkdtemp(prefix="np_a4_%s_" % tag)
    out = {}
    for name, report in scenarios().items():
        html = M.render_report_html_brief_v2(report)
        hp = os.path.join(tmp, "%s.html" % name)
        pp = os.path.join(tmp, "%s.pdf" % name)
        with open(hp, "w", encoding="utf-8") as f:
            f.write(html)
        err = M._html_to_pdf(browser, hp, pp)
        out[name] = ("ERR:" + err) if err else pdf_pages(pp)
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "cur"
    if mode == "cur":
        sys.path.insert(0, REPO)
        import netpulse as M
        print(json.dumps(measure(M, "cur"), ensure_ascii=False))
        return 0
    # head: 在临时目录放一份 HEAD 版 netpulse.py, 再导入
    d = os.path.join(tempfile.gettempdir(), "np_head_a4")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "netpulse.py"), "wb") as f:
        f.write(subprocess.run(["git", "-C", REPO, "show", "HEAD:netpulse.py"],
                               capture_output=True, check=True).stdout)
    with open(os.path.join(d, "measure_head.py"), "w", encoding="utf-8") as f:
        f.write("import sys, json, os\n"
                "sys.path.insert(0, %r)\n"
                "sys.path.insert(0, %r)\n"
                "import netpulse as M\n"
                "import _a4_lib as L\n"
                "print(json.dumps(L.measure(M, 'head'), ensure_ascii=False))\n"
                % (d, os.path.dirname(os.path.abspath(__file__))))
    # 把本脚本当库用
    import shutil
    shutil.copy(os.path.abspath(__file__),
                os.path.join(d, "_a4_lib.py"))
    r = subprocess.run([sys.executable, os.path.join(d, "measure_head.py")],
                       capture_output=True, text=True, errors="replace")
    print((r.stdout or "").strip()[-2000:])
    if r.returncode != 0:
        print("STDERR:", (r.stderr or "")[-1500:])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
