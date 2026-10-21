# -*- coding: utf-8 -*-
"""v1.15.2 审查 P1-16 · 调试包不再直读全局 LAST_RUN 回归测试。

AGENTS.md 收口规则: 「停止新增 LAST_RUN 全局依赖 —— 数据流向
runner → report → renderer; 新代码 (报告/Debug Bundle/Monitor) 不得直接
读写全局 LAST_RUN, 存量引用只减不增」, 且该规则**明令点名 Debug Bundle**。

旧版实现 (审查前): `_export_debug_bundle(out_dir)` 内部直读全局 LAST_RUN 共
**8 处** (存在性门 ×2 + system/results/evidence/status/keys/result-error)。

修后: 显式传参 `_export_debug_bundle(out_dir, run)`; run=None 时兜底跑一次
全诊断并取 run_diagnostics 的**返回值**; run_diagnostics 改为返回完整 run dict。

跑用: cd 到项目根目录, `py -3.13 tests/test_v1152_debug_bundle_explicit.py`
"""
import ast
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


def _mk_run(marker, keys=("dns",)):
    """造一份 LAST_RUN 形状的 run dict, 带一个可区分的 marker。"""
    return {
        "app": "NetPulse",
        "version": N.APP_VERSION,
        "generated_at": "2026-10-21 00:00:00",
        "system": {"local_ip": "10.0.0.1", "gateway": "10.0.0.254"},
        "status": {k: "完成" for k in keys},
        "results": {k: {"marker": marker} for k in keys},
        "evidence": {k: {"marker": marker} for k in keys},
        "keys": list(keys),
        "duration_ms": 1234,
        "total_modules": 23,
    }


class TestDebugBundleExplicitRun(unittest.TestCase):
    """调试包必须用它被显式告知的 run, 而不是全局 LAST_RUN。"""

    def _bundle_text(self, run, global_run=None):
        d = tempfile.mkdtemp(prefix="np_bundle_exp_")
        old = N.LAST_RUN
        try:
            if global_run is not None:
                N.LAST_RUN = global_run
            with contextlib.redirect_stdout(io.StringIO()):
                N._export_debug_bundle(d, run)
            zips = [f for f in os.listdir(d) if f.endswith(".zip")]
            self.assertTrue(zips, "没生成 zip")
            with zipfile.ZipFile(os.path.join(d, zips[0])) as z:
                blob = ""
                for nm in z.namelist():
                    blob += z.read(nm).decode("utf-8", "replace")
            return blob
        finally:
            N.LAST_RUN = old

    # ── 闸门 1: 传参的内容才是导出的内容 ──
    def test_bundle_uses_passed_run_not_global(self):
        """全局 LAST_RUN 与传入 run 内容不同时, 必须以传入的为准。

        旧版: 签名只收 out_dir, 传第二个参数直接 TypeError → 红。
        """
        blob = self._bundle_text(_mk_run("FROM_ARG"),
                                  global_run=_mk_run("FROM_GLOBAL"))
        self.assertIn("FROM_ARG", blob, "调试包内容必须来自显式传入的 run")
        self.assertNotIn("FROM_GLOBAL", blob,
                         "不得读全局 LAST_RUN (收口规则明令点名 Debug Bundle)")

    # ── 闸门 2: 函数体内不得再出现 LAST_RUN (静态扫描) ──
    def test_bundle_function_body_has_no_last_run_reference(self):
        """用 AST 扫函数体 —— 比正则可靠, 注释骗不过 AST。"""
        src = open(os.path.abspath(N.__file__), encoding="utf-8").read()
        tree = ast.parse(src)
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_export_debug_bundle":
                fn = node
                break
        self.assertIsNotNone(fn, "找不到 _export_debug_bundle")
        hits = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Name) and node.id == "LAST_RUN":
                hits.append(node.lineno)
            elif (isinstance(node, ast.Attribute)
                  and isinstance(node.value, ast.Name)
                  and node.value.id == "LAST_RUN"):
                hits.append(node.lineno)
        self.assertEqual([], hits,
                         "_export_debug_bundle 体内不得直读全局 LAST_RUN (行 %s)" % hits)

    # ── 闸门 3: run_diagnostics 返回完整 run dict ──
    def _run_diagnostics(self, keys=("dns",)):
        buf = io.StringIO()
        patches = [
            mock.patch.object(N, "_run_module_with_timeout",
                              return_value=("完成", {"probe": "ok"})),
            mock.patch.object(N, "get_local_ip", return_value="10.0.0.1"),
            mock.patch.object(N, "get_default_gateway", return_value="10.0.0.254"),
            mock.patch.object(N, "get_dns_servers", return_value=["223.5.5.5"]),
            mock.patch.object(N, "get_public_ip", return_value="1.2.3.4"),
            mock.patch.object(N, "get_ip_geo", return_value=None),
            mock.patch.object(N, "get_public_ipv6", return_value=None),
        ]
        with contextlib.ExitStack() as st:
            for p in patches:
                st.enter_context(p)
            with contextlib.redirect_stdout(buf):
                run = N.run_diagnostics(list(keys), banner=False)
        return run

    def test_run_diagnostics_returns_full_run_dict(self):
        """返回值要能替代全局 LAST_RUN —— 含 results/evidence/status/keys。"""
        run = self._run_diagnostics()
        self.assertIsInstance(run, dict, "run_diagnostics 必须返回 run dict")
        for k in ("system", "status", "results", "evidence", "keys"):
            self.assertIn(k, run, "返回值缺 %s —— 下游无法显式取数" % k)
        self.assertEqual(["dns"], run["keys"])
        self.assertIn("dns", run["results"])
        self.assertIn("dns", run["status"])

    def test_returned_status_key_keeps_legacy_shape(self):
        """向后兼容: 旧返回值 {key: status} 的内容现在在 status 键里。"""
        run = self._run_diagnostics()
        self.assertEqual({"dns": "完成"}, run["status"])

    # ── 闸门 4: run=None 时兜底跑诊断, 仍不读全局 ──
    def test_run_none_falls_back_to_running_diagnostics(self):
        """CLI --debug-bundle 路径: 没传 run 时自己跑一次, 拿返回值。"""
        fake_run = _mk_run("FALLBACK")
        old = N.LAST_RUN
        try:
            N.LAST_RUN = _mk_run("FROM_GLOBAL")
            with mock.patch.object(N, "run_diagnostics",
                                   return_value=fake_run) as m_rd, \
                 contextlib.redirect_stdout(io.StringIO()):
                d = tempfile.mkdtemp(prefix="np_bundle_fb_")
                N._export_debug_bundle(d, None)
                zips = [f for f in os.listdir(d) if f.endswith(".zip")]
                self.assertTrue(zips)
                with zipfile.ZipFile(os.path.join(d, zips[0])) as z:
                    blob = "".join(z.read(nm).decode("utf-8", "replace")
                                   for nm in z.namelist())
            self.assertTrue(m_rd.called, "run=None 时应自己跑一次诊断")
            self.assertIn("FALLBACK", blob)
            self.assertNotIn("FROM_GLOBAL", blob,
                             "兜底路径也不得读全局 LAST_RUN")
        finally:
            N.LAST_RUN = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
