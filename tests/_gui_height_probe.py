# -*- coding: utf-8 -*-
"""实测 GUI 八个视图的内容高度 (评估窗口高度用)。

开发期工具, **不属于回归套件** (文件名不带 test_ 前缀, 全量回归不会跑它)。

用法:
    py -3.13 tests/_gui_height_probe.py                 # 全部视图, 只打印高度
    py -3.13 tests/_gui_height_probe.py --shot out_dir  # 顺带截图 (PNG)
    py -3.13 tests/_gui_height_probe.py home site       # 只测指定视图

做法: 起真 GUI 服务 (真实 API 数据) → 给页面 HTML 打三处补丁:
  1) show()/openReport()/openMonReport() 暴露到 window —— 让注入脚本能切视图
     (函数声明提升, 补丁插在声明之前即可拿到函数对象);
  2) 注入测量脚本 —— 切到目标视图后把 docH/mainH/vh 写进 #__probe。
用 Chrome headless --dump-dom 取回测量结果。

数据状态: 进度页用假 running 会话 (真跑一轮要几分钟); 报告页用合成报告;
盯障两页跑一轮真盯障 (30s, 最短档)。
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

VIEWS = ["home", "progress", "report", "site",
         "modules", "mon-config", "mon-live", "mon-report"]

# 真实 Chromium --app 窗口 1180x680 → 客户区 (网页可见区) 1164x672
TARGET_VH = 672
HEADLESS_OFFSET = 95      # headless --window-size 高度 与 视口高度 的差

PROBE_JS = """
<script>
(function(){
  window.__errs = [];
  window.addEventListener("error", function(e){ window.__errs.push(String(e.message)); });
  function meas(){
    var v = new URLSearchParams(location.search).get("v") || "home";
    try {
      if (v === "report" && window.__openReport) window.__openReport();
      if (v === "mon-report" && window.__openMonReport) window.__openMonReport();
      if (window.__show) window.__show(v);
    } catch(e){ window.__errs.push("probe: " + e); }
    setTimeout(function(){
      var m = document.getElementById("view-" + v);
      var r = m ? m.getBoundingClientRect() : null;
      var d = document.createElement("div");
      d.id = "__probe";
      d.setAttribute("data-probe", JSON.stringify({
        view: v,
        vh: window.innerHeight,
        docH: document.documentElement.scrollHeight,
        bodyH: document.body.scrollHeight,
        mainH: r ? Math.round(r.height) : null,
        mainScroll: m ? m.scrollHeight : null,
        errs: window.__errs
      }));
      document.body.appendChild(d);
    }, 2500);
  }
  window.addEventListener("load", function(){ setTimeout(meas, 600); });
})();
</script>
"""


def _patch_html(html):
    """把 show/openReport/openMonReport 暴露到 window + 注入测量脚本。"""
    patches = [
        ("  function show(view) {", "  window.__show = show;\n  function show(view) {"),
        ("  function openReport() {", "  window.__openReport = openReport;\n  function openReport() {"),
        ("  function openMonReport() {", "  window.__openMonReport = openMonReport;\n  function openMonReport() {"),
    ]
    for old, new in patches:
        assert old in html, "源码形态变了, 补丁失效: %r" % old
        html = html.replace(old, new, 1)
    return html.replace("</body>", PROBE_JS + "</body>")


def _sample_report():
    """一份「典型」报告: 23 项模块 + 若干问题 + 根因 —— 供报告视图渲染。"""
    sys.path.insert(0, os.path.join(REPO, "tests"))
    import _a4_pagecheck as A
    mods = []
    for i in range(23):
        st = ["完成", "完成", "完成", "警告", "异常", "完成"][i % 6]
        issues = []
        if st in ("警告", "异常"):
            issues = [{"severity": st,
                       "text": "模块%d 检测到异常指标, 数值超出阈值范围" % i,
                       "impact": "影响业务体验", "action": "现场复核"}]
        mods.append(A._mk_module("m%d" % i, "模块%d" % i, st, issues))
    return A._mk_report(mods, root_causes=[A._rc(1, "critical", "WAN 中断 (运营商链路故障)",
                                                "网关可达但外网不可达。"),
                                           A._rc(2, "high", "DNS 解析异常", "多个域名解析超时。")],
                        health={"score": 62, "grade": "C", "label": "一般", "verdict": "部分指标异常"})


def _fake_running(session, keys):
    """把会话伪造成「正在跑」—— 进度页要模块灯阵, 真跑一轮太慢。"""
    with session._lock:
        session._phase = "running"
        session._profile = "full"
        session._keys = list(keys)
        session._started_at = time.time() - 42
        session._module_status = {k: "完成" for k in list(keys)[:9]}
        session._module_status[keys[9]] = "警告"
        session._running = {keys[10]}
        session._verdict = {"score": 62, "grade": "C", "label": "一般",
                            "summary": {"完成": 9, "警告": 1}}


def _set_state(session, keys, view):
    """按视图摆会话状态: 进度页要 running, 其余要 done + 有报告。"""
    with session._lock:
        session._phase = "running" if view == "progress" else "done"
        session._keys = list(keys) if view == "progress" else []
        session._started_at = time.time() - 42
        session._module_status = ({k: "完成" for k in list(keys)[:9]}
                                   if view == "progress" else {})
        session._running = {keys[10]} if view == "progress" else set()
        session._verdict = {"score": 62, "grade": "C", "label": "一般",
                            "summary": {"完成": 9, "警告": 1}}


def _run_chrome(url, shot_dir=None, tag="", vh=TARGET_VH):
    tmp = tempfile.mkdtemp(prefix="np_gui_probe_")
    w = 1164
    h = vh + HEADLESS_OFFSET
    cmd = [CHROME, "--headless=new", "--disable-gpu",
           "--user-data-dir=" + tmp,
           "--virtual-time-budget=30000",
           "--window-size=%d,%d" % (w, h),
           "--dump-dom", url]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                       timeout=300)
    out = r.stdout or ""
    res = None
    m = re.search(r'<div id="__probe" data-probe="([^"]*)"', out)
    if m:
        raw = (m.group(1).replace("&quot;", '"').replace("&amp;", "&")
               .replace("&lt;", "<").replace("&gt;", ">"))
        try:
            res = json.loads(raw)
        except Exception:
            res = {"raw": raw}
    if shot_dir:
        os.makedirs(shot_dir, exist_ok=True)
        cmd2 = [CHROME, "--headless=new", "--disable-gpu",
                "--user-data-dir=" + tempfile.mkdtemp(prefix="np_gui_shot_"),
                "--virtual-time-budget=30000", "--window-size=%d,%d" % (w, h),
                "--screenshot=" + os.path.abspath(
                    os.path.join(shot_dir, "%s.png" % (tag or "home"))),
                url]
        subprocess.run(cmd2, capture_output=True, text=True, errors="replace",
                       timeout=300)
    return res


def main():
    shot_dir = None
    views = list(VIEWS)
    args = sys.argv[1:]
    if "--shot" in args:
        i = args.index("--shot")
        shot_dir = args[i + 1]
        args = args[:i] + args[i + 2:]
    if args:
        views = args
    sys.path.insert(0, REPO)
    import netpulse as M

    M._GUI_PAGE_HTML = _patch_html(M._GUI_PAGE_HTML)

    session = M._GuiSession()
    monitor = M._GuiMonitor()
    evt = threading.Event()
    keys = [m[0] for m in M.MODULE_REGISTRY] if hasattr(M, "MODULE_REGISTRY") else []
    if not keys:
        keys = ["m%d" % i for i in range(23)]
    try:
        session._report = _sample_report()
    except Exception as e:
        print("合成报告失败: %s" % e)
    srv, port, token = M._start_gui_server(session, evt, monitor)

    # 真盯障一轮 (最短 30s 档) —— 盯障两页要真实曲线/报告才有意义
    if any(v.startswith("mon-") for v in views):
        try:
            ok, err, eff = monitor.start(30)
            print("盯障启动: ok=%s err=%s eff=%s" % (ok, err, eff))
        except Exception as e:
            print("盯障启动异常: %s" % e)

    rows = []
    try:
        for v in views:
            _set_state(session, keys, v)
            url = "http://127.0.0.1:%d/?t=%s&v=%s" % (port, token, v)
            res = _run_chrome(url, shot_dir, v)
            rows.append((v, res))
            if v == "mon-live":
                print("…等盯障收尾 (30s)")
                time.sleep(38)
    finally:
        try:
            monitor.stop()
        except Exception:
            pass
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass

    print("%-12s %6s %7s %7s %7s" % ("view", "vh", "docH", "mainH", "余白"))
    for v, res in rows:
        if not res:
            print("%-12s  (测量失败)" % v)
            continue
        blank = res["vh"] - (res["mainH"] or 0)
        print("%-12s %6s %7s %7s %7s" % (v, res["vh"], res["docH"],
                                         res["mainH"], blank))
    return 0


if __name__ == "__main__":
    sys.exit(main())
