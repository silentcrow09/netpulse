# -*- coding: utf-8 -*-
"""v1.6.0 PR-B/PR-C 功能验证 (mock 隔离, 不碰真实桌面/网络)。

验证点:
  P1  diagnose rule_filter: gaming 过滤后 wifi_weak 不触发 (规则集生效)
  P2  diagnose 过滤无命中 → 退回全规则 (异常不藏)
  P3  rules_evaluated 反映实际评估数
  P4  CLI --diagnose 走 rule_filter (代码路径存在)
  P5  _format_error_for_user 各异常分支文案
  P6  _desktop_netpulse_dir: OneDrive 优先 / 不可写退化 None
  P7  _export_scene_report: 桌面路径 + 报告生成 (mock export_report)
  P8  _scene_menu 交互: [9]→q 退出 / [0] 退出 / 非法输入重提

v1.6.1 追加 (代码审查 10 项修复回归, 见 TestV161):
  P9  Ctrl+C 中断走客户文案 + 暂停 (不再裸回溯)
  P10 场景报告文件名含时分秒 (同日复测不覆盖)
  P11 规则注册表单一来源 (ALL_RULES/_RULE_BY_ID/_RULE_ID_OF 同源)
  P12 web 场景补采 gateway/external 后规则可触发
  P13 _run_scene 诊断只评一次, 完成屏/导出复用同一份
"""
import os
import sys
import socket
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


def _mk_results(bufferbloat=False, wifi=False, dns_fail=False, gw_loss=False,
                nat_restricted=False, wan=False):
    """构造能触发指定规则的最小 results dict (键名对齐真实生产者)。

    键名来自规则真实读取 (R-C1 教训: 喂想象键名的测试全绿但规则全不触发):
      bufferbloat: idle_rtt_ms/loaded_rtt_ms/grade
      wifi_weak:   overall_interference
      dns_failure: dns.success_count/total_count + gateway.ping.loss_pct
      gateway_loss: gateway.ping.loss_pct
      nat_restricted: nattype.nat_behavior
      wan_interruption: external.tcp_ok/tcp_total + gateway.ping.loss_pct
    """
    gw_ok = {"ping": {"loss_pct": 0.0}}
    r = {}
    if bufferbloat:
        r["bufferbloat"] = {"idle_rtt_ms": 8.0, "loaded_rtt_ms": 68.0,
                            "grade": "D级 一般"}
    if wifi:
        r["wifi"] = {"overall_interference": "干扰较高"}
    if gw_loss:
        r["gateway"] = {"ping": {"loss_pct": 25.0}}
    if dns_fail:
        r["dns"] = {"success_count": 0, "total_count": 3}
        r.setdefault("gateway", gw_ok)  # DNS 规则要求网关可达
    if nat_restricted:
        r["nattype"] = {"nat_behavior": "对称型"}
    if wan:
        r["external"] = {"tcp_ok": 0, "tcp_total": 3}
        r.setdefault("gateway", gw_ok)  # WAN 规则要求网关可达
    return r


class TestPRB(unittest.TestCase):

    def test_gaming_excludes_wifi_weak(self):
        # 同时有 wifi 弱 + bufferbloat 的证据
        results = _mk_results(bufferbloat=True, wifi=True)
        d = np.diagnose(results, rule_filter="gaming")
        ids = {rc.id for rc in d.root_causes}
        self.assertNotIn("wifi_weak", ids, "gaming 场景不应报 wifi 弱")
        self.assertIn("bufferbloat", ids)
        self.assertEqual(d.rules_evaluated, 5)  # gaming = 5 条规则 (v1.7.0 +2)

    def test_gaming_only_wifi_evidence_no_report(self):
        # 只有 wifi 弱证据: 首轮规则集无命中 → 兜底全规则, 但排除集
        # 禁止 wifi_weak 借兜底绕回 → 结果为空 (gaming 下 wifi 弱是噪音)
        results = _mk_results(wifi=True)
        d = np.diagnose(results, rule_filter="gaming")
        ids = {rc.id for rc in d.root_causes}
        self.assertNotIn("wifi_weak", ids)
        self.assertEqual(d.rules_evaluated, 7)  # 8 条 - 排除 1 条

    def test_slow_includes_wifi_weak(self):
        results = _mk_results(bufferbloat=True, wifi=True)
        d = np.diagnose(results, rule_filter="slow")
        ids = {rc.id for rc in d.root_causes}
        self.assertIn("wifi_weak", ids, "slow 场景默认含 wifi 弱")
        self.assertEqual(d.rules_evaluated, 5)

    def test_no_hit_falls_back_to_all_rules(self):
        # wifi 场景规则集不含 bufferbloat, 但证据里只有 bufferbloat
        results = _mk_results(bufferbloat=True)
        d = np.diagnose(results, rule_filter="wifi")
        ids = {rc.id for rc in d.root_causes}
        self.assertIn("bufferbloat", ids, "过滤无命中应退回全规则, 不藏异常")
        self.assertEqual(d.rules_evaluated, 8)  # 退回后评估 8 条

    def test_no_filter_full_rules(self):
        results = _mk_results(gw_loss=True)
        d = np.diagnose(results)
        ids = {rc.id for rc in d.root_causes}
        self.assertIn("gateway_loss", ids)
        self.assertEqual(d.rules_evaluated, 8)  # 无过滤 = 全 8 条

    def test_unknown_filter_ignored(self):
        # 未知 profile → 不触发过滤 (全规则)
        results = _mk_results(gw_loss=True)
        d = np.diagnose(results, rule_filter="nope")
        ids = {rc.id for rc in d.root_causes}
        self.assertIn("gateway_loss", ids)
        self.assertEqual(d.rules_evaluated, 8)

    def test_cli_diagnose_uses_filter(self):
        # main() 里 CLI --diagnose 分支已传 rule_filter (代码路径检查)
        src = open(os.path.join(ROOT, "netpulse.py"),
                   encoding="utf-8").read()
        self.assertIn('diagnose(LAST_RUN["results"], rule_filter=profile)', src)


class TestPRC(unittest.TestCase):

    def test_error_format(self):
        self.assertEqual(
            np._format_error_for_user(socket.gaierror("no name"))[0],
            "DNS 解析失败：无法解析域名（请检查 DNS 设置或联系运营商）")
        self.assertEqual(
            np._format_error_for_user(PermissionError(5))[0],
            "权限不足：无法执行该检测（请以管理员身份重新运行）")
        self.assertEqual(
            np._format_error_for_user(TimeoutError())[0],
            "网络超时：请求响应太慢（可能是网络拥堵或运营商故障）")
        user, detail = np._format_error_for_user(ValueError("boom"))
        self.assertIn("检测过程中出错", user)
        self.assertIn("[ValueError]", detail)

    def test_desktop_dir_onedrive_first(self):
        # OneDrive 桌面重定向真实存在 → 优先 OneDrive 路径
        fake_home = os.path.join(
            os.environ.get("TEMP", "."), "np_test_home_onedrive")
        import shutil
        shutil.rmtree(fake_home, ignore_errors=True)  # 清上次运行残留
        one_desktop = os.path.join(fake_home, "OneDrive", "Desktop")
        os.makedirs(one_desktop, exist_ok=True)  # 模拟重定向已生效
        onedrive = os.path.join(one_desktop, "NetPulse")
        with mock.patch.dict(os.environ, {"USERPROFILE": fake_home}, clear=False), \
             mock.patch.object(np, "_known_folder_desktop", return_value=None):
            got = np._desktop_netpulse_dir()
        self.assertEqual(os.path.normpath(got), os.path.normpath(onedrive))
        shutil.rmtree(fake_home, ignore_errors=True)

    def test_desktop_dir_plain_desktop(self):
        # 无 OneDrive 重定向 → 普通 Desktop
        fake_home = os.path.join(
            os.environ.get("TEMP", "."), "np_test_home_plain")
        import shutil
        shutil.rmtree(fake_home, ignore_errors=True)  # 清上次运行残留
        plain = os.path.join(fake_home, "Desktop", "NetPulse")
        with mock.patch.dict(os.environ, {"USERPROFILE": fake_home}, clear=False), \
             mock.patch.object(np, "_known_folder_desktop", return_value=None):
            got = np._desktop_netpulse_dir()
        self.assertEqual(os.path.normpath(got), os.path.normpath(plain))
        shutil.rmtree(fake_home, ignore_errors=True)

    def test_export_scene_report_mocked(self):
        fake_home = os.path.join(
            os.environ.get("TEMP", "."), "np_test_home_export")
        with mock.patch.dict(os.environ, {"USERPROFILE": fake_home}, clear=False):
            np.LAST_RUN = {
                "app": "NetPulse", "version": "1.6.0",
                "generated_at": "x", "status": {}, "results": {},
                "keys": ["gateway"], "duration_ms": 1, "total_modules": 23}
            with mock.patch.object(np, "export_report",
                                   return_value=None) as m_exp:
                path, err = np._export_scene_report("slow", "网络很慢")
        self.assertIsNone(err)
        self.assertIn("Desktop", path)
        self.assertIn("网络很慢.html", path)
        m_exp.assert_called_once_with(path, rule_filter="slow", report=None)
        import shutil
        shutil.rmtree(fake_home, ignore_errors=True)
        np.LAST_RUN = None

    def test_scene_menu_exit_zero(self):
        with mock.patch("builtins.input", side_effect=["0"]), \
             mock.patch.object(np, "_menu_clear", return_value=None):
            self.assertFalse(np._scene_menu())

    def test_scene_menu_advance_then_exit(self):
        with mock.patch("builtins.input", side_effect=["9", "q"]), \
             mock.patch.object(np, "_menu_clear", return_value=None), \
             mock.patch.object(np, "_module_menu", return_value=False):
            self.assertFalse(np._scene_menu())

    def test_scene_menu_invalid_then_exit(self):
        # "xx" 无效 → 按 Enter 继续 ("") → 重渲染 → 选 "0" 退出
        with mock.patch("builtins.input", side_effect=["xx", "", "0"]), \
             mock.patch.object(np, "_menu_clear", return_value=None):
            self.assertFalse(np._scene_menu())


class TestPRA(unittest.TestCase):

    def test_scene_mapping_consistency(self):
        # 每个场景菜单键必须映射到存在的 profile, 且 profile 有模块组合
        for key, profile in np.SCENE_MENU_KEYS.items():
            self.assertIn(profile, np.DIAGNOSE_PROFILES)
            self.assertIn(profile, np.PROFILE_RULES)
            self.assertIn(profile, np.SCENE_LABELS)
            self.assertTrue(np.DIAGNOSE_PROFILES[profile])

    def test_run_scene_integration_mocked(self):
        """_run_scene: run_diagnostics → diagnose(rule_filter) → 完成屏 → 保存。

        v1.6.1: 诊断只评一次 — build_report 复用完成屏那份 diagnosis
        (审查 #8); 完成屏后有回车暂停。
        """
        fake_home = os.path.join(
            os.environ.get("TEMP", "."), "np_test_home_scene")
        D = type("D", (), {
            "root_causes": [], "rules_evaluated": 3,
            "to_dict": lambda self: {"root_causes": [], "rules_evaluated": 3}})
        with mock.patch.dict(os.environ, {"USERPROFILE": fake_home}, clear=False):
            np.LAST_RUN = {
                "app": "NetPulse", "version": "1.6.1", "generated_at": "x",
                "status": {"gateway": "完成"}, "results": {"gateway": {}},
                "keys": ["gateway"], "duration_ms": 1, "total_modules": 23}
            with mock.patch.object(np, "run_diagnostics") as m_rd, \
                 mock.patch.object(np, "diagnose", return_value=D()) as m_diag, \
                 mock.patch.object(np, "build_report",
                                   return_value={"health": {"score": 90}}) as m_br, \
                 mock.patch.object(np, "_print_diagnosis"), \
                 mock.patch.object(np, "_export_scene_report",
                                   return_value=("x.html", None)) as m_exp, \
                 mock.patch("builtins.input", return_value="") as m_in:
                np._run_scene("slow")
        m_rd.assert_called_once()
        call_kw = m_rd.call_args.kwargs
        self.assertEqual(call_kw.get("parallel"), True)
        m_diag.assert_called_once()
        # diagnose(results_dict, rule_filter=profile) — rule_filter 是关键字参数
        self.assertEqual(m_diag.call_args[1].get("rule_filter"), "slow")
        # 诊断只评一次: build_report 复用同一份 diagnosis (审查 #8)
        m_br.assert_called_once()
        self.assertEqual(m_br.call_args[1].get("diagnosis"),
                         {"root_causes": [], "rules_evaluated": 3})
        # 导出复用同一份报告; 完成屏后暂停等回车
        self.assertTrue(m_exp.called)
        self.assertTrue(m_in.called)
        import shutil
        shutil.rmtree(fake_home, ignore_errors=True)
        np.LAST_RUN = None


class TestV161(unittest.TestCase):
    """v1.6.1 代码审查修复回归 (审查发现 #4-#10)。"""

    def test_registry_single_source(self):
        # ALL_RULES / _RULE_BY_ID / _RULE_ID_OF 由 _RULE_REGISTRY 单一派生 (审查 #10)
        ids = [np._RULE_ID_OF[fn] for fn in np.ALL_RULES]
        self.assertEqual(ids, list(np._RULE_BY_ID.keys()))
        self.assertEqual(len(set(np.ALL_RULES)), len(np.ALL_RULES))
        for profile_rules in np.PROFILE_RULES.values():
            for rid in profile_rules:
                self.assertIn(rid, np._RULE_BY_ID,
                              f"PROFILE_RULES 引用了不存在的规则 id: {rid}")

    def test_web_profile_collects_rule_dependencies(self):
        # web 场景 3 条规则全依赖 gateway/external 数据, profile 必须采集 (审查 #2)
        for mod in ("gateway", "external"):
            self.assertIn(mod, np.DIAGNOSE_PROFILES["web"])
        results = {
            "dns": {"success_count": 0, "total_count": 4},
            "gateway": {"ping": {"loss_pct": 0.0}},
            "external": {"tcp_ok": 0, "tcp_total": 4},
        }
        d = np.diagnose(results, rule_filter="web")
        ids = {rc.id for rc in d.root_causes}
        self.assertIn("dns_failure", ids, "web 场景 DNS 全挂必须报 dns_failure")
        self.assertIn("wan_interruption", ids)

    def test_fallback_no_double_evaluation(self):
        # 兜底只补评首轮没跑过的规则, 不整轮重评 (审查 #9)
        bb = {"idle_rtt_ms": 8.0, "loaded_rtt_ms": 68.0, "grade": "D级 一般"}
        # wifi: 2 条首评 + 6 条补评 = 8 (旧实现首评 2 条会被兜底重评, 计 8 但跑 10 次)
        d = np.diagnose({"bufferbloat": bb}, rule_filter="wifi")
        self.assertEqual(d.rules_evaluated, 8)
        # gaming 只有 wifi 证据: 5 条首评 + (8-5-1 排除) 2 条补评 = 7
        d2 = np.diagnose({"wifi": {"overall_interference": "干扰较高"}},
                         rule_filter="gaming")
        self.assertEqual(d2.rules_evaluated, 7)

    def test_keyboard_interrupt_friendly(self):
        # Ctrl+C (KeyboardInterrupt) 也走客户文案 + 暂停, 不裸抛回溯 (审查 #4)
        with mock.patch.object(np, "run_diagnostics",
                               side_effect=KeyboardInterrupt), \
             mock.patch("builtins.input", return_value="") as m_in:
            np._run_scene("slow")  # 不应抛异常
        self.assertTrue(m_in.called)

    def test_scene_report_filename_has_time(self):
        # 文件名含时分秒: 同日复测不再静默覆盖 (审查 #5)
        tmp = os.path.join(os.environ.get("TEMP", "."), "np_test_v161_fname")
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, exist_ok=True)
        saved = np.LAST_RUN
        np.LAST_RUN = {"app": "NetPulse", "version": "1.6.1",
                       "generated_at": "x", "status": {}, "results": {},
                       "keys": ["gateway"], "duration_ms": 1,
                       "total_modules": 23}
        try:
            with mock.patch.object(np, "_desktop_netpulse_dir",
                                   return_value=tmp), \
                 mock.patch.object(np, "export_report", return_value=None):
                p1, err1 = np._export_scene_report("slow", "网络很慢")
        finally:
            np.LAST_RUN = saved
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertIsNone(err1)
        # ..._YYYY-MM-DD_HHMMSS_网络很慢.html
        self.assertRegex(os.path.basename(p1), r"\d{4}-\d{2}-\d{2}_\d{6}_")

    def test_known_folder_desktop_priority(self):
        # SHGetKnownFolderPath 结果优先于 USERPROFILE 候选探测 (审查 #6)
        fake_kf = os.path.join(os.environ.get("TEMP", "."), "np_test_v161_kf")
        fake_home = os.path.join(os.environ.get("TEMP", "."), "np_test_v161_kfh")
        import shutil
        for d in (fake_kf, fake_home):
            shutil.rmtree(d, ignore_errors=True)
        try:
            with mock.patch.dict(os.environ, {"USERPROFILE": fake_home},
                                 clear=False), \
                 mock.patch.object(np, "_known_folder_desktop",
                                   return_value=fake_kf):
                got = np._desktop_netpulse_dir()
            self.assertEqual(os.path.normpath(got),
                             os.path.normpath(os.path.join(fake_kf, "NetPulse")))
        finally:
            for d in (fake_kf, fake_home):
                shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromName("__main__")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
