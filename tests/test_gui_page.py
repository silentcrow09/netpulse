# -*- coding: utf-8 -*-
"""GUI 页面资产 (v1.21.0): 静态壳 / 零外链 / 动态数据 textContent 规则。

验证点:
  P1 _gui_page() 是完整 HTML 文档 (doctype/关闭标签)
  P2 零外链: 无 http(s):// 资源引用、无 <link、无 <script src、无 <img
     (v1.22.0: SVG 命名空间标识符 "http://www.w3.org/2000/svg" 是 URI 标识
     而非外链资源 — createElementNS 必需、浏览器从不对其发起请求, 白名单放行)
  P3 页面为纯静态: 无 format 占位符痕迹 ({...} 模板残留)
  P4 JS 轮询 /api/progress 与 /api/netstatus, sendBeacon 关窗, iframe 加载
     /api/report; v1.22.0: /api/monitor/* 五条 + createElementNS 曲线 +
     confirm 停止
  P5 动态渲染只用 textContent: innerHTML 赋值一律禁止 (含 += 逃逸形态);
     insertAdjacentHTML 只允许注入全大写常量标识符 (零插值常量模板),
     其余参数形态 (字符串拼接 / 小写变量 / 函数调用) 一律 FAIL
  P6 v1.22.0 盯障三视图锚点 (mon-config/mon-live/mon-report) + 第 7 卡
     (ICONS.monitor + /api/scenarios 下发 monitor 条目, 与终端菜单同语义)
  P7 F1 回修: runbar 三态优先级 monRun → diagRun → monDone (盯障完成的
     粘滞终态不得覆盖诊断进行中入口); beforeunload 两条文案标点统一全角
  P8 v1.22.0 终审修复波: 自定义分钟放行 0/负数交服务端钳位 + 钳位回显
     配置页/实时页双写; 负载倒计时 / DNS-TCP 等待灰 / runbar 错误入口 /
     连通率外网口径 四项锚点
  P9 v1.23.0 模块勾选面板: 次级入口 g-modpanel + #view-modules 三分组 +
     tcpcc 红字警示 + DOM 确认弹层 (非 window.confirm) + 条件子项显隐 +
     Ookla 真布尔直发 + 每组全选/清空 (spec F2) + 旧错清理/请求体锚点
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


def _html_guard_violations(p):
    """动态渲染规则闸: 返回违规片段清单 (空列表 = 通过)。

    R1 任何形式的 innerHTML 赋值一律禁止 (= 与 += 两种形态都拦, F3 逃逸 1);
    R2 insertAdjacentHTML 只允许注入【全大写常量标识符】(零插值常量模板,
       如 ICON; F3 逃逸 2)。参数含字符串拼接/小写标识符/函数调用即违规 ——
       fails closed: 按括号截断后解析不出白名单形态的一律算违规。
    """
    import re as _re
    bad = []
    if _re.search(r'\.innerHTML\s*\+?=', p):
        bad.append("innerHTML 赋值")
    for m in _re.finditer(r'\.insertAdjacentHTML\(([^)]*)\)', p):
        args = m.group(1)
        parts = args.split(",")
        target = parts[1].strip() if len(parts) > 1 else ""
        if not _re.match(r'^[A-Z][A-Z0-9_]*$', target):
            bad.append("insertAdjacentHTML 非白名单参数: %s" % args)
    return bad


class TestGuiPage(unittest.TestCase):

    def setUp(self):
        self.page = np._gui_page()

    def test_document_shape(self):
        p = self.page
        self.assertTrue(p.lstrip().startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", p)

    def test_no_external_resources(self):
        p = self.page
        self.assertNotIn('<link', p)
        self.assertNotIn('<script src', p)
        self.assertNotIn('<img', p)
        # SVG 命名空间是 URI 标识符而非外链资源 (浏览器从不 dereference),
        # createElementNS 必需; 白名单这一处, 其余 http(s):// 一律禁止。
        p = p.replace('"http://www.w3.org/2000/svg"', "")
        for bad in ('http://', 'https://'):
            self.assertNotIn(bad, p, "外链资源: %s" % bad)
        self.assertIn('"http://www.w3.org/2000/svg"', self.page,
                      "createElementNS 的 SVG 命名空间常量必须存在")

    def test_no_template_placeholder(self):
        self.assertNotIn('{profile}', self.page)
        self.assertNotIn('%s', self.page.split('<style>')[0])

    def test_key_mechanics(self):
        p = self.page
        self.assertIn('/api/progress', p)
        self.assertIn('/api/scenarios', p)
        self.assertIn('/api/report', p)
        self.assertIn('/api/netstatus', p)
        self.assertIn('sendBeacon', p)
        # v1.22.0 盯障: 五条 API + createElementNS 逐点绘制 + confirm 后停止
        for api in ("/api/monitor/progress", "/api/monitor/curve",
                    "/api/monitor/report", "/api/monitor/start",
                    "/api/monitor/stop"):
            self.assertIn(api, p, "盯障 API 缺失: %s" % api)
        self.assertIn("createElementNS", p,
                      "曲线 SVG 必须用 createElementNS 逐点绘制")
        self.assertIn("confirm(", p, "停止盯障必须先 confirm")

    def test_no_iframe_native_report(self):
        # v1.25.0: iframe 嵌套退役 —— 报告与盯障报告都是页面内原生渲染容器
        # (div#g-frame / div#mon-frame), 由 JS 从投影 JSON 渲染
        p = self.page
        self.assertNotIn("<iframe", p, "页面不得再有 iframe (web 嵌套 web 已废除)")
        self.assertIn('id="g-frame" class="g-rpt"', p, "原生报告容器缺失")
        self.assertIn('id="mon-frame" class="g-rpt"', p, "原生盯障报告容器缺失")
        # 渲染器入口锚点: fetch 投影 → renderReport / renderMonReport
        self.assertIn("function renderReport(", p)
        self.assertIn("function renderMonReport(", p)
        self.assertIn("get(API.report)", p)
        self.assertIn("get(API.monReport)", p)
        self.assertNotIn('API.report;', p, "不得再用 iframe.src 加载 /api/report")

    def test_monitor_view_anchors(self):
        # P6: 三视图锚点 + 第 7 卡链路 (图标常量 / data-p 机制 / 元数据通道)
        p = self.page
        for vid in ("view-mon-config", "view-mon-live", "view-mon-report"):
            self.assertIn('id="%s"' % vid, p, "缺视图锚点: %s" % vid)
        self.assertIn('show("mon-config")', p, "第 7 卡点击必须进配置页")
        self.assertIn('show("mon-live")', p, "runbar 必须能回实时页")
        self.assertIn("monitor: '<svg", p, "第 7 卡图标常量缺失")
        self.assertIn("dataset.p", p, "卡片 data-p 机制缺失")
        # 第 7 卡数据通道: /api/scenarios 下发 monitor 条目 (与终端菜单同语义)
        meta = np._gui_meta()
        mon = [s for s in meta["scenarios"] if s["id"] == "monitor"]
        self.assertEqual(len(mon), 1, "场景载荷缺「持续盯障」条目")
        self.assertEqual(mon[0]["label"], "持续盯障")
        self.assertIn("偶发掉线", mon[0]["desc"])

    def test_runbar_priority_diag_over_mon_done(self):
        # P7 (F1 回修): applyHomeState 的 runbar 分支顺序必须是
        # monRun → diagRun → monDone —— monDone 是粘滞终态 (下次盯障前
        # 一直在), 若优先于 diagRun, 盯障完成后跑诊断时 runbar 仍显示
        # 「盯障完成」点开旧报告, 诊断入口被覆盖。
        js = self.page.split("<script>")[1]
        i_mon = js.find('bar.textContent = "盯障进行中 · 点击查看";')
        i_diag = js.find('bar.textContent = "诊断进行中 · 点击查看进度";')
        i_done = js.find('bar.textContent = "盯障完成 · 点击查看报告";')
        self.assertTrue(0 <= i_mon < i_diag < i_done,
                        "runbar 分支顺序必须 monRun → diagRun → monDone "
                        "(find: %d/%d/%d)" % (i_mon, i_diag, i_done))
        # runbar 点击跳转同优先级: diagRunning 时必须走诊断进度页
        i_click_diag = js.find('} else if (state.diagRunning) {')
        self.assertTrue(i_click_diag > 0,
                        "runbar click 缺 diagRunning 分支")
        self.assertTrue(i_click_diag < js.find(
            '} else if (state.monPhase === "done") {'),
            "click 分支顺序必须 monRun → diagRunning → monDone")

    def test_beforeunload_punctuation_uniform(self):
        # P7b (一致性回修): beforeunload 两条确认文案标点统一全角逗号
        # (盯障文案为任务书钦定原文; 诊断文案向其对齐, 中文 UI 规范)。
        # v1.24.0: 诊断文案改为「关窗会保留已测完的 N 项, 下次可以接着跑」
        # (spec F5 —— 关窗不再等于白跑, 提示要说清保住多少项)。
        self.assertIn("诊断仍在进行，关闭窗口会保留已测完的 ", self.page)
        self.assertNotIn("诊断仍在进行, 关闭窗口会保留已测完的 ", self.page)
        self.assertIn("项，下次可以接着跑", self.page)
        self.assertIn("盯障进行中，关闭窗口将终止本次盯障且丢失未生成的报告",
                      self.page)

    def test_no_innerhtml_interpolation(self):
        # F3 (审查): 新闸 —— += 形态与 insertAdjacentHTML 非常量参数都要拦
        self.assertEqual(_html_guard_violations(self.page), [],
                         "动态渲染必须用 textContent / 零插值常量注入 (见 _html_guard_violations)")

    def test_guard_rejects_malformed(self):
        # 新闸对恶意形态必须 FAIL, 对合法常量注入放行 (构造样本验证)
        self.assertTrue(_html_guard_violations('el.innerHTML += evil;'),
                        ".innerHTML += 逃逸形态未被拦截")
        self.assertTrue(_html_guard_violations(
            'box.insertAdjacentHTML("afterbegin", "<b>" + s.id + "</b>");'),
            "insertAdjacentHTML 字符串拼接/变量插值未被拦截")
        self.assertTrue(_html_guard_violations(
            'box.insertAdjacentHTML("afterbegin", renderIcon(s.id));'),
            "insertAdjacentHTML 函数调用参数未被拦截")
        self.assertEqual(_html_guard_violations(
            'box.insertAdjacentHTML("afterbegin", ICON);'), [],
            "全大写常量标识符注入被误拦")

    def test_monitor_minutes_pass_through_and_clamp_echo(self):
        # 终审修复 #1: 自定义分钟不再前端拒收 0/负数 (n<=0 拦截删除),
        # 任意整数放行交服务端钳位 (0→30 / 2000→86400, P11 已锁); 非整数
        # 仍前端拦截; 钳位回显写配置页 + 实时页 (#mon-clamp) 两处 ——
        # 跳转后两处都可见, 不再「返回配置页才看得到」。
        js = self.page.split("<script>")[1]
        i0 = js.find("function monMinutes()")
        i1 = js.find("function startMon()")
        self.assertTrue(0 <= i0 < i1, "monMinutes 函数定位失败")
        body = js[i0:i1]
        self.assertNotIn("n <= 0", body,
                         "0/负数不得在前端拦截 (须放行交服务端钳位)")
        self.assertIn("Math.floor(n) !== n", body, "非整数仍须前端拦截")
        self.assertIn('id="mon-clamp"', self.page, "实时页钳位回显锚点缺失")
        self.assertIn('$("#mon-clamp")', js, "实时页钳位回显写入缺失")
        self.assertIn("执行（最短 30 秒，最长 24 小时）", js, "钳位回显文案缺失")

    def test_monitor_fixwave_live_anchors(self):
        # 终审修复 #3/#4/#5/#6 页面锚点:
        #   #3 负载提示倒计时 (等待倒计时 → 负载窗进行中);
        #   #4 DNS/TCP 无样本等待灰 (qSt 判 null → "wait" + 「等待数据」);
        #   #5 盯障 error 态主页 runbar 入口 (不静默隐藏, 点击回实时页);
        #   #6 连通率「外网」口径小字标注。
        js = self.page.split("<script>")[1]
        self.assertIn("后开始（15 秒下载）", js, "#3 倒计时文案缺失")
        self.assertIn("下载负载进行中", js, "#3 负载窗进行中文案缺失")
        self.assertIn("function qSt(", js, "#4 无样本判据 helper 缺失")
        self.assertIn('"等待数据"', js, "#4 等待态副文案缺失")
        self.assertIn("盯障启动失败 · 点击查看", js, "#5 runbar 错误入口缺失")
        i_done = js.find('bar.textContent = "盯障完成 · 点击查看报告";')
        i_err = js.find('bar.textContent = "盯障启动失败 · 点击查看";')
        self.assertTrue(0 <= i_done < i_err, "#5 错误分支必须在 monDone 之后")
        self.assertIn('} else if (state.monPhase === "error") {\n'
                      '        show("mon-live");', js,
                      "#5 点击必须回实时页看错误信息")
        self.assertIn('<small class="v-scope">外网</small>', self.page,
                      "#6 连通率外网口径标注缺失")

    # ── P9: v1.23.0 模块勾选面板 (次级入口 + #view-modules + 确认弹层) ──

    def test_modules_entry_and_view_anchors(self):
        # 变体 A 次级文字入口 → show("modules"); 面板视图骨架齐全;
        # 目录/分类消费 /api/scenarios 载荷 (服务端唯一来源, 页面不内嵌清单)
        p = self.page
        js = p.split("<script>")[1]
        self.assertIn('id="g-modpanel"', p, "主页次级入口缺失")
        self.assertIn('class="g-link2"', p, "次级入口样式类缺失")
        self.assertIn("高级模块组合 ›", p)
        self.assertIn('show("modules")', js, "入口必须跳面板视图")
        self.assertIn('"modules", "mon-config"', js,
                      "show() 视图清单未纳入 modules")
        self.assertIn('id="view-modules"', p, "面板视图缺失")
        for anchor in ("mp-count", "mp-total", "mp-all", "mp-none", "mp-inv",
                       "mp-groups", "mp-err", "btn-mp-run", "mp-run-n",
                       "btn-mp-back"):
            self.assertIn(anchor, p, "面板锚点缺失: %s" % anchor)
        meta = np._gui_meta()
        self.assertEqual(len(meta["module_catalog"]), 24)
        self.assertEqual(set(meta["module_cats"]), {"a", "b", "c"})
        self.assertIn("module_catalog", js, "页面未消费 module_catalog")
        self.assertIn("module_cats", js, "页面未消费 module_cats")
        # 运行中互斥: 面板运行按钮跟随 diagRunning/monRun 禁用 (复用既有状态)
        i0 = js.find("function applyHomeState")
        i1 = js.find("function renderProgress")
        self.assertTrue(0 <= i0 < i1, "applyHomeState 定位失败")
        self.assertIn("updateMpRunBtn();", js[i0:i1],
                      "主页状态合成必须联动面板运行按钮禁用")
        # 旧错误文案不残留: 进面板与改选组合都要清 #mp-err (审查 F1 波小项)
        i_gm = js.find('$("#g-modpanel").addEventListener')
        self.assertTrue(i_gm > 0, "入口绑定缺失")
        self.assertIn('$("#mp-err").textContent = "";',
                      js[i_gm:i_gm + 200], "进面板必须清旧错误文案")
        i0 = js.find("function updateMpCount")
        i1 = js.find("function updateMpRunBtn")
        self.assertTrue(0 <= i0 < i1, "updateMpCount 定位失败")
        self.assertIn('$("#mp-err").textContent = "";', js[i0:i1],
                      "改选组合必须清旧错误文案 (updateMpCount 单点)")

    def test_modules_tcpcc_warning(self):
        # tcpcc 行红字压测警示 (设计稿第 2 节原文), 且运行前特判弹确认
        p = self.page
        js = p.split("<script>")[1]
        self.assertIn("压测：短时建立大量连接，勿对客户网络使用", p,
                      "tcpcc 红字警示缺失")
        self.assertIn('indexOf("tcpcc")', js, "运行前必须特判 tcpcc")
        # 审查 F2: 初次渲染整行即带 stress 红调 (设计稿静态 class="mrow stress"),
        # 不得等交互后 mpSyncRow 才补
        self.assertIn(
            'row.className = "mrow" + (it.key === "tcpcc" ? " stress" : "");',
            js, "初次渲染 tcpcc 行必须自带 stress 红调")

    def test_modules_confirm_modal_dom(self):
        # 确认弹层必须是 DOM 遮罩实现 (遮罩+居中卡片+确认/返回), 非 window.confirm
        p = self.page
        js = p.split("<script>")[1]
        self.assertIn('id="mp-overlay"', p, "DOM 遮罩缺失")
        self.assertIn('id="btn-mp-confirm"', p, "确认按钮缺失")
        self.assertIn('id="btn-mp-cancel"', p, "返回按钮缺失")
        self.assertIn("运行确认", p, "弹层标题缺失")
        i0 = js.find("function runModules")
        i1 = js.find("function mpRun")
        self.assertTrue(0 <= i0 < i1, "runModules/mpRun 定位失败")
        self.assertNotIn("confirm(", js[i0:i1],
                         "面板运行不得使用 window.confirm")

    def test_modules_conditional_subs(self):
        # 条件子项: speedtest→Ookla 开关(默认关) / iperf3→服务器输入 /
        # port→目标输入; 勾选显示、取消收起 (静态机制断言)
        p = self.page
        js = p.split("<script>")[1]
        self.assertIn("function mpSyncSub", js, "条件子项显隐机制缺失")
        self.assertIn("留空则按未检测处理", p, "iperf3 输入占位缺失")
        self.assertIn("如 223.5.5.5:53，多个逗号分隔", p, "port 输入占位缺失")
        # Ookla 开关默认关; use_speedtest_net 必须发真布尔 (服务端 bool() 直写)
        self.assertIn("var mpOokla = false;", js, "Ookla 开关必须默认关")
        self.assertIn("mpOokla = !mpOokla;", js, "开关切换缺失")
        self.assertIn("body.use_speedtest_net = mpOokla;", js,
                      "use_speedtest_net 必须发真布尔, 不得发字符串")
        # 审查 F1 波小项: 请求体组装锚点——可选字段只在对应模块勾选中才发
        # (留空不发, 未勾选不发); 运行按钮禁用判定锚点 (诊断+盯障双忙源)
        i0 = js.find("function mpRun")
        i1 = js.find("── 主页状态合成")
        self.assertTrue(0 <= i0 < i1, "mpRun 定位失败")
        run_body = js[i0:i1]
        for guard in ('if (keys.indexOf("port") >= 0)',
                      'if (keys.indexOf("iperf3") >= 0)',
                      'if (keys.indexOf("speedtest") >= 0)'):
            self.assertIn(guard, run_body,
                          "可选字段必须按勾选守卫: %s" % guard)
        i0 = js.find("function updateMpRunBtn")
        i1 = js.find("function mpSetAll")
        self.assertTrue(0 <= i0 < i1, "updateMpRunBtn 定位失败")
        btn_body = js[i0:i1]
        self.assertIn('state.monPhase === "running"', btn_body,
                      "盯障运行中必须参与禁用判定")
        self.assertIn("disabled = !mpSelectedKeys().length || busy", btn_body,
                      "运行按钮禁用判定锚点缺失")

    def test_modules_group_ops(self):
        # spec F2 明文「每组全选/清空」——顶部全选=全 24 项, 无法一键只操作
        # 一组 (范围重审裁定: 设计稿没画不能豁免 spec)。组头尾部组级文字
        # 按钮, 复用 mpSetAll 同款逐行同步, 计数联动照旧。
        p = self.page
        js = p.split("<script>")[1]
        self.assertIn("function mpSetGroup", js, "组级全选/清空函数缺失")
        self.assertIn("grp.dataset.cat = letter", js, "组容器未携带分类字母")
        self.assertIn('el("button", "txtbtn", "全选")', js, "组级全选按钮缺失")
        self.assertIn('el("button", "txtbtn", "清空")', js, "组级清空按钮缺失")
        # mpSetGroup 主体: 只作用于该组 .ck (data-cat 限定) + 行同步 + 子项联动 + 计数
        i0 = js.find("function mpSetGroup")
        i1 = js.find("function runModules")
        self.assertTrue(0 <= i0 < i1, "mpSetGroup 定位失败")
        body = js[i0:i1]
        self.assertIn('.grp[data-cat="', body,
                      "mpSetGroup 未按组限定作用域")
        self.assertIn("mpSyncRow(c);", body, "组级操作必须同步行高亮")
        self.assertIn("mpSyncSub(c.dataset.k, on);", body,
                      "组级操作必须联动条件子项显隐")
        self.assertIn("updateMpCount();", body, "组级操作必须联动计数")
        # 组级按钮动态渲染, 事件必须走 #mp-groups 点击委托
        self.assertIn('ev.target.closest("button[data-cat]")', js,
                      "组级按钮点击委托缺失")
        self.assertIn("mpSetGroup(btn.dataset.cat", js,
                      "委托必须把组字母传给 mpSetGroup")


if __name__ == "__main__":
    unittest.main()
