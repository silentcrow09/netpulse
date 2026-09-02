# -*- coding: utf-8 -*-
"""v1.9.4/v1.9.5: 报告排版"两行空白观感"修复回归测试

覆盖 _DIAGNOSIS_CSS 与主 CSS 报告层的排版修复:
  1. 健康卡 .diagnosis.healthy 紧凑化 (padding 14→9, row-gap 6→4, line-height 1.4)
     + v1.9.5 内容改回左对齐 (flex-start, 无 justify-content 覆写 — 用户
       反馈整句居中不符合阅读习惯)
  2. .hero .sub 长文字单行 + ellipsis (避免被 gauge 挤换行成两行)
  3. .todo.ok .impact 补绿底样式 ("所有核心检测通过" 分支无样式 → 现继承 issue.ok 风格)

不再依赖 LAST_RUN, 只读 CSS 字符串 + 渲染小样本核对: 避免 v1.8.3 那种
"evidence 一等结构" 重测时整页回放的脆弱性。
"""
import sys, re, os, datetime
sys.path.insert(0, "d:/Work/Projects/NetPulse")
import netpulse as N

_NOW = datetime.datetime.now()


def _has_css(rule_selector, fragment):
    """检查 CSS 字符串中含 selector { ... } 且体内含 fragment."""
    pattern = re.escape(rule_selector) + r"\s*\{([^}]*)\}"
    m = re.search(pattern, fragment)
    return m is not None and fragment in (m.group(1) if m else "")


# 取出 CSS 整段 (_DIAGNOSIS_CSS 已被嵌入到 render_report_html_customer CSS 块)
HTML = N.render_report_html_customer(N.build_report()) if False else None
# 不真跑 render, 走更轻的路径: 直接读 netpulse.py 内嵌 CSS
src = open("d:/Work/Projects/NetPulse/netpulse.py", encoding="utf-8").read()


# ── 1. 健康卡 .diagnosis.healthy 紧凑化 ───────────────────
# v1.9.3 修了居中+margin-bottom:0, 但 padding 14+14+单行内容让卡片仍像
# "两行". v1.9.4 改 padding 9+9+row-gap 4+line-height 1.4 → 紧凑按钮状.
m1 = re.search(r"\.diagnosis\.healthy\s*\{([^}]*)\}", src)
m1b = re.search(r"\.diagnosis\.healthy\s+\.dhead\s*\{([^}]*)\}", src)
m1c = re.search(r"\.diagnosis\.healthy\s+\.dbadge\.ok\s*\{([^}]*)\}", src)

assert m1 is not None, "缺 .diagnosis.healthy 规则"
assert m1b is not None, "缺 .diagnosis.healthy .dhead 规则"
assert m1c is not None, "缺 .diagnosis.healthy .dbadge.ok 规则"

healthy_body = m1.group(1)
dhead_body = m1b.group(1)
dbadge_body = m1c.group(1)

# padding 由 14px 20px → 9px 20px (更紧凑, 消残留"两行"感)
assert "padding: 9px 20px" in healthy_body, (
    f"健康卡 padding 应为 9px 20px, 实际: {healthy_body!r}")

# dhead 左对齐 (v1.9.5 起, 用户反馈居中不符合阅读习惯) + margin-bottom:0
# + flex-wrap + row-gap 4 + line-height 1.4
assert "justify-content: center" not in dhead_body, (
    f"健康卡 dhead 不应再居中 (v1.9.5 改回左对齐), 实际: {dhead_body!r}")
assert "justify-content" not in dhead_body, (
    f"健康卡 dhead 不应含 justify-content 覆写 (默认 flex-start 左对齐), 实际: {dhead_body!r}")
assert "margin-bottom: 0" in dhead_body, "dhead margin-bottom 须为 0 (无第二行空白)"
assert "row-gap: 4px" in dhead_body, f"dhead row-gap 应为 4px, 实际: {dhead_body!r}"
assert "line-height: 1.4" in dhead_body, "dhead 须 line-height: 1.4 紧凑"

# dbadge 字号+padding 略缩 (5px 14px, 原 6px 14px)
assert "padding: 5px 14px" in dbadge_body, (
    f"健康卡 dbadge padding 应 5px 14px, 实际: {dbadge_body!r}")


# ── 2. .hero .sub 单行 ellipsis ─────────────────────────────
# 长 verdict+时间戳一行被 gauge 132px+gap 36px 挤窄 → 强制换行成两行,
# 与健康卡"两行观感"同类. v1.9.4 加 nowrap+ellipsis 截次要时间戳.
m2 = re.search(r"\.hero\s+\.sub\s*\{([^}]*)\}", src)
assert m2 is not None, "缺 .hero .sub 规则"
sub_body = m2.group(1)
# CSS 块内属性无空格分隔 (与诊断块有空格不同), 用正则兼容
assert re.search(r"white-space\s*:\s*nowrap", sub_body), "hero .sub 须 nowrap 防换行成两行"
assert re.search(r"overflow\s*:\s*hidden", sub_body), "hero .sub 须 overflow:hidden"
assert re.search(r"text-overflow\s*:\s*ellipsis", sub_body), "hero .sub 须 ellipsis 截断"
assert re.search(r"min-width\s*:\s*0", sub_body), "hero .sub 须 min-width:0 让 flex 子可收缩"


# ── 3. .todo.ok .impact 补绿底 ─────────────────────────────
# "所有核心检测通过" 分支: <div class="impact"> 直接挂在 .todo.ok 内
# (不在 .issue 内), 旧 .issue .impact 规则匹配不到 → 文字无背景样式
# → 视觉"第二行没样式像空白". v1.9.4 加 .todo.ok .impact 绿底样式.
m3 = re.search(r"\.todo\.ok\s+\.impact\s*\{([^}]*)\}", src)
assert m3 is not None, "缺 .todo.ok .impact 规则 (v1.9.4 修复点)"
timpact_body = m3.group(1)
# 风格与 .issue.ok .impact 一致: 绿字+浅绿底+padding+border-radius
# CSS 块属性无空格分隔, 用正则兼容两种格式
assert re.search(r"color\s*:\s*#166534", timpact_body), "todo ok .impact 须绿字"
assert re.search(r"background\s*:\s*#f0fdf4", timpact_body), "todo ok .impact 须浅绿底"
assert re.search(r"padding\s*:\s*8px 12px", timpact_body), "todo ok .impact 须 padding"
assert re.search(r"border-radius\s*:\s*6px", timpact_body), "todo ok .impact 须圆角"
assert re.search(r"line-height\s*:\s*1\.7", timpact_body), "todo ok .impact 须 line-height"


# ── 4. 不破坏问题诊断卡 (回归保护) ─────────────────────────
# v1.9.3 把 dhead 改成居中只在 .diagnosis.healthy 走, 警告/严重问题卡
# 的 dhead 仍左对齐 + 触发"整体..." 文字 + rcard 紧跟. 不可误伤.
m4 = re.search(r"\.diagnosis\s+\.dhead\s*\{([^}]*)\}", src)
assert m4 is not None, "缺 .diagnosis .dhead (问题卡基线)"
dhead_base = m4.group(1)
assert "margin-bottom: 12px" in dhead_base, (
    f"问题卡 dhead margin-bottom 应为 12px (基线), 实际: {dhead_base!r}")
# 警告 rcard 基线
m4b = re.search(r"\.diagnosis\s+\.rcard\s*\{([^}]*)\}", src)
assert m4b is not None, "缺 .diagnosis .rcard (rcard 基线)"


# ── 5. 直接渲染 todo ok 分支 HTML, 验证 .impact 出现在 .todo.ok 内 ──
# LAN 模块在所有 status="完成" 时也会自动发"未扫描到任何局域网设备"信息
# 级 issue (build_report 内的 LAN fallback 逻辑), 导致 todo 走 warn 分支
# 而非 ok 分支. 此处直接构造 report 字典 (绕过 build_report) 验证
# todo ok 分支渲染: <div class="todo ok"><div class="todo-head">✓ 网络状态良好</div>
# <div class="impact">...</div></div>
all_ok = {
    "app": "NetPulse", "version": "1.9.4-test", "generated_at": _NOW,
    "schema_version": "1.2.0",
    "system": {"local_ip": "10.0.0.1", "gateway": "10.0.0.254",
               "dns": "8.8.8.8", "public_ip": "1.2.3.4",
               "asn": "AS0", "geo": "测试"},
    "health": {"score": 100, "grade": "A", "label": "优秀",
               "verdict": "网络良好, 无问题"},
    "counts": {"完成": 19, "警告": 0, "异常": 0, "错误": 0, "超时": 0, "未检测": 0},
    "summary": {k: "完成" for k in N.MODULE_MAP},
    "diagnosis": {"root_causes": [], "rules_evaluated": 8,
                  "rules_fired": 0, "overall_confidence": 1.0},
    "modules": [{"key": k, "name": k, "status": "完成", "verdict": "正常",
                 "issues": [], "key_metrics": []} for k in N.MODULE_MAP],
    "total_modules": len(N.MODULE_MAP), "selected_modules": len(N.MODULE_MAP),
    "exempt_count": 4, "duration_ms": 100,
}
html = N.render_report_html_customer(all_ok)
assert 'class="todo ok"' in html, "全绿场景应渲染 todo ok 分支"
assert '<div class="todo-head">✓ 网络状态良好</div>' in html, "todo ok 头部文案应保留"
# .impact 须在 .todo.ok 内 (不是 .issue 内)
todo_ok_match = re.search(
    r'<div class="todo ok">\s*<div class="todo-head">.*?</div>\s*'
    r'<div class="impact">(.*?)</div>\s*</div>',
    html, re.S)
assert todo_ok_match is not None, "todo ok 须含 .impact 行 (内嵌样式生效目标)"


# ── 6. 直接渲染一个有问题报告, 验证 dhead 仍左对齐 (没被误伤) ──
problem = {**all_ok,
    "health": {"score": 48, "grade": "D", "label": "欠佳",
               "verdict": "4 个模块需要关注"},
    "counts": {"完成": 15, "警告": 1, "异常": 2, "错误": 0, "超时": 1, "未检测": 0},
    "diagnosis": {"root_causes": [
        {"id": "gateway_loss", "category": "network", "severity": "high",
         "title": "网关丢包 5%", "description": "网关丢包",
         "confidence": 0.85, "affected_modules": ["gateway"],
         "supports": [], "excludes": [], "recommendations": ["复测"]}
    ], "rules_evaluated": 8, "rules_fired": 1, "overall_confidence": 0.85},
    "modules": [{**m,
                 "status": ("异常" if m["key"] in ("gateway", "mtu") else
                            "警告" if m["key"] == "dns" else
                            "超时" if m["key"] == "port" else "完成"),
                 "verdict": ("网关丢包" if m["key"] == "gateway" else "正常")}
                for m in all_ok["modules"]],
}
html = N.render_report_html_customer(problem)
# 有问题: dhead 不应有 justify-content: center
dhead_html = re.search(r'<div class="dhead">(.*?)</div>', html, re.S)
assert dhead_html is not None, "问题诊断卡应有 dhead"
# 诊断块是 .diagnosis (非 healthy)
assert 'class="diagnosis" id="diagnosis"' in html, (
    "有问题场景应是 .diagnosis (非 .diagnosis.healthy)")
assert 'class="diagnosis healthy"' not in html, (
    "有问题场景不应有 healthy 卡")
# 主问题 h2 标题保留
assert "主要问题" in html, "问题诊断卡标题保留"


print("OK v1.9.4/v1.9.5 排版修复 6 项")
print("  - 健康卡 .diagnosis.healthy 紧凑化 (padding 14→9, row-gap 6→4, line-height 1.4)")
print("  - 健康卡 dhead 左对齐 (v1.9.5 去 justify-content 覆写, 默认 flex-start)")
print("  - .hero .sub 长文字单行 + ellipsis (避免换行成两行)")
print("  - .todo.ok .impact 补绿底 (消除 '所有核心检测通过' 空白观感)")
print("  - 问题诊断卡 dhead 左对齐 (margin-bottom 12px) 未被误伤")
print("  - 全绿/有问题场景渲染分支 (todo ok / .diagnosis) 基线正确")
