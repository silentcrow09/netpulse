# -*- coding: utf-8 -*-
"""远程日志上报回归测试 (v1.17.0)

覆盖:
  - 协议: payload 字段/取值合法、X-Token 头、ts 为 RFC3339、os 不含 hostname
  - 脱敏: 用户目录名 / 公网 IP / MAC / 机器名 / SSID 不出现在上报正文
  - 开关: 默认开启、可关闭、状态持久化、非 TTY 静默跳过
  - 限流: 同指纹超限不再报; 本地日志同样限频 (盯障 24h 循环不撑爆日志)
  - 单轮预算: 客户网络全断时模块异常不会几十条齐飞
  - 健壮性: 网络失败 / 401 / 400 都不抛异常、不影响退出码
  - 接入: _cli_entry 崩溃路径会触发上报; 后台线程异常钩子已安装
  - **探针异常保栈** (核心): 模块异常上报必须带完整 traceback 与异常类型
  - **端到端**: 本地 mock 服务端真收一条 POST (不依赖外网)

无外网依赖 (全部 mock 或本地回环); 跑用: cd 到项目根目录,
`python tests/test_log_report.py`
"""
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


class _TmpCfg(unittest.TestCase):
    """把上报配置指向临时目录, 避免污染真实 %LOCALAPPDATA%。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="np_log_")
        self._old_env = os.environ.get("LOCALAPPDATA")
        os.environ["LOCALAPPDATA"] = self.tmp
        # 限流计数与本地日志计数都是进程内状态, 每个用例从零开始
        N._LOG_LOCAL_SEEN.clear()
        N._LOG_RUN_STATE["sent"] = 0
        # v1.18.2: 本文件专门验证上报链路, 显式放行源码运行 —— 否则新加的
        # 「源码不自动上报」防线会把这里的用例全部挡掉 (而这正是要测的)。
        # 本文件的推送要么 mock 掉 _post_log, 要么指向本地 mock 服务端,
        # 不会打到线上日志服务器。
        os.environ[N.LOG_ALLOW_SOURCE_ENV] = "1"

    def tearDown(self):
        os.environ.pop(N.LOG_ALLOW_SOURCE_ENV, None)
        if self._old_env is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = self._old_env
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestLogPayloadProtocol(_TmpCfg, unittest.TestCase):
    """协议形状 —— 服务端实测约束: message 非空 / type 合法 / ts 为 RFC3339。"""

    def test_payload_has_exact_protocol_fields(self):
        """负载字段必须恰好是协议约定的那些 (app/type/message/ts/os + 可选 stack)。"""
        allowed = {"app", "type", "message", "stack", "ts", "os"}
        p = N._log_payload("error", "boom")
        self.assertEqual(set(p.keys()), allowed - {"stack"},
                         "无栈时不得有多余字段")
        p2 = N._log_payload("error", "boom", stack="Traceback...")
        self.assertEqual(set(p2.keys()), allowed,
                         "带栈时字段集必须正好是协议约定的 6 个")

    def test_app_is_netpulse(self):
        self.assertEqual(N._log_payload("info", "x")["app"], "netpulse")

    def test_stack_only_present_when_given(self):
        self.assertNotIn("stack", N._log_payload("info", "x"))
        self.assertIn("stack", N._log_payload("info", "x", stack="Traceback..."))

    def test_type_falls_back_to_error_when_invalid(self):
        """非法 type 服务端直接 400 —— 客户端先兜住。"""
        self.assertEqual(N._log_payload("bogus", "x")["type"], "error")
        for t in N.LOG_LEVELS:
            self.assertEqual(N._log_payload(t, "x")["type"], t)

    def test_empty_message_gets_placeholder(self):
        """message 为空服务端 400 —— 客户端兜底成占位摘要, 不丢这次事件。"""
        p = N._log_payload("error", "   ")
        self.assertTrue(p["message"].strip(), "message 不得为空")

    def test_ts_is_rfc3339_with_offset(self):
        """ts 必须是 RFC3339 且带时区偏移 (服务端会归一化成 UTC)。"""
        ts = N._log_payload("info", "x")["ts"]
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}"
                             r"[+-]\d{2}:\d{2}$")

    def test_os_is_system_string_without_hostname(self):
        """os 用系统版本串, 不含 hostname (会带出客户机名)。"""
        osv = N._log_payload("info", "x")["os"]
        self.assertTrue(osv)
        try:
            import socket
            hostname = socket.gethostname()
        except Exception:
            hostname = ""
        if hostname and len(hostname) >= 4:
            self.assertNotIn(hostname.lower(), osv.lower(),
                             "os 字段不得含机器名")

    def test_message_encodes_version_and_scope(self):
        """协议没有独立 metadata 字段 —— 上下文必须编码进 message。"""
        exc = ValueError("x")
        msg = N._log_message("模块:dns", exc)
        self.assertIn(N.APP_VERSION, msg)
        self.assertIn("模块:dns", msg)
        self.assertIn("ValueError", msg)


class TestLogSanitize(_TmpCfg, unittest.TestCase):
    """上报内容脱敏 —— 隐私红线, 必须锁死。"""

    def test_username_path_masked(self):
        os.environ["USERPROFILE"] = r"C:\Users\张三"
        text = r'File "C:\Users\张三\AppData\Local\Temp\netpulse.py", line 1'
        out = N._log_sanitize_text(text)
        self.assertNotIn("张三", out, "用户名必须被脱敏")
        self.assertIn("<user>", out)

    def test_public_ipv4_masked(self):
        out = N._log_sanitize_text("remote 203.0.113.45 failed")
        self.assertNotIn("203.0.113.45", out, "公网 IP 必须打码")

    def test_private_ipv4_kept(self):
        """内网 IP 保留 —— 定位现场问题必需。"""
        out = N._log_sanitize_text("local 192.168.1.10 ok")
        self.assertIn("192.168.1.10", out)

    def test_mac_masked(self):
        out = N._log_sanitize_text("nic AA:BB:CC:DD:EE:FF")
        self.assertNotIn("AA:BB:CC:DD:EE:FF", out, "MAC 必须打码")

    def test_hostname_masked(self):
        import socket
        hostname = socket.gethostname()
        if not hostname or len(hostname) < 4:
            self.skipTest("本机机器名过短, 跳过")
        out = N._log_sanitize_text("machine %s failed" % hostname)
        self.assertNotIn(hostname, out, "机器名必须被脱敏")
        self.assertIn("<host>", out)

    def test_ssid_masked(self):
        out = N._log_sanitize_text("SSID: MyHomeWifi")
        self.assertNotIn("MyHomeWifi", out, "SSID 必须打码")

    def test_payload_is_sanitized(self):
        """载荷里的 message 与 stack 都要过脱敏。"""
        os.environ["USERPROFILE"] = r"C:\Users\李四"
        p = N._log_payload("error", r"路径 C:\Users\李四\a.py 出错",
                           stack=r'File "C:\Users\李四\a.py", line 3')
        blob = p["message"] + p.get("stack", "")
        self.assertNotIn("李四", blob, "载荷不得含用户名")
        self.assertNotIn("203.0.113.7", N._log_payload(
            "error", "ip 203.0.113.7")["message"])


class TestLogSwitch(_TmpCfg, unittest.TestCase):
    """开关语义: 默认开 / 可关 / 持久化。"""

    def test_enabled_by_default(self):
        self.assertTrue(N._log_reporting_enabled(),
                        "默认应开启 (首次运行弹窗告知)")

    def test_disable_persists(self):
        self.assertTrue(N._set_log_reporting_enabled(False))
        self.assertFalse(N._log_reporting_enabled())
        self.assertFalse(N._load_log_config().get("enabled", True))

    def test_enable_persists(self):
        N._set_log_reporting_enabled(False)
        N._set_log_reporting_enabled(True)
        self.assertTrue(N._log_reporting_enabled())

    def test_env_var_can_force_disable(self):
        """环境变量 NETPULSE_LOG_REPORT=0 是最高优先级的关闭开关。"""
        os.environ["NETPULSE_LOG_REPORT"] = "0"
        try:
            self.assertFalse(N._log_reporting_enabled())
        finally:
            os.environ.pop("NETPULSE_LOG_REPORT", None)

    def test_notice_shown_flag(self):
        self.assertFalse(N._log_notice_shown())
        N._mark_log_notice_shown()
        self.assertTrue(N._log_notice_shown())

    def test_config_path_uses_log_report_json(self):
        self.assertTrue(N._log_config_path().endswith(
            os.path.join("NetPulse", "log_report.json")))


class TestLogEndpointOverride(_TmpCfg, unittest.TestCase):
    """端点 / token 可用环境变量覆盖 (换服务器不必重新打包)。"""

    def test_url_env_override(self):
        os.environ[N.LOG_URL_ENV] = "http://example.test/v1/logs"
        try:
            self.assertEqual(N._log_endpoint(), "http://example.test/v1/logs")
        finally:
            os.environ.pop(N.LOG_URL_ENV, None)

    def test_token_env_override(self):
        os.environ[N.LOG_TOKEN_ENV] = "app-tk_other"
        try:
            self.assertEqual(N._log_token(), "app-tk_other")
        finally:
            os.environ.pop(N.LOG_TOKEN_ENV, None)

    def test_default_endpoint(self):
        self.assertEqual(N._log_endpoint(), N.LOG_SERVER_URL)
        self.assertTrue(N.LOG_SERVER_URL.endswith("/v1/logs"))
        self.assertTrue(N.LOG_SERVER_TOKEN.startswith("app-tk_"))

    def test_default_endpoint_is_https(self):
        """端点必须走 HTTPS —— 栈信息不能明文躺在链路上。"""
        self.assertTrue(N.LOG_SERVER_URL.startswith("https://"),
                        "日志端点必须是 https, 当前: %s" % N.LOG_SERVER_URL)


class TestLogTls(_TmpCfg, unittest.TestCase):
    """TLS —— 服务端用 Let's Encrypt 公用 CA 证书, 客户端走系统信任链。"""

    def test_no_embedded_certificate(self):
        """客户端**不得内置任何证书**。

        Let's Encrypt 证书 90 天轮换 —— 内置进 exe 等于给所有客户端埋
        90 天后的定时炸弹 (换证后全部客户端证书校验失败, 上报静默失效)。
        """
        src = open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "netpulse.py"),
            encoding="utf-8").read()
        self.assertNotIn("-----BEGIN CERTIFICATE-----", src,
                         "客户端不得内置证书 (LE 证书 90 天轮换)")
        self.assertFalse(hasattr(N, "LOG_PINNED_CERT_PEM"),
                         "不得存在内置证书常量")

    def test_ssl_context_keeps_verification_on(self):
        """**校验永不关闭** —— 关闭等于加密但不认证, 中间人可读全部栈信息。"""
        import ssl as _ssl
        ctx = N._log_ssl_context()
        self.assertTrue(ctx.check_hostname, "必须校验主机名")
        self.assertEqual(ctx.verify_mode, _ssl.CERT_REQUIRED, "必须 CERT_REQUIRED")

    def test_ssl_context_uses_system_ca_only(self):
        """信任链 = 系统 CA 原样, 没有额外塞进去的证书。"""
        import ssl as _ssl
        base = len(_ssl.create_default_context().get_ca_certs())
        self.assertEqual(len(N._log_ssl_context().get_ca_certs()), base,
                         "不得往信任链里塞额外证书")

    def test_cert_error_is_actionable(self):
        """证书校验失败要给出可行动原因 (服务端可能换了证书)。"""
        import urllib.error

        def _raise_verify(*a, **kw):
            raise urllib.error.URLError(
                "<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] "
                "certificate verify failed: self-signed certificate>")

        with mock.patch.object(N, "_urlopen_with_proxy", side_effect=_raise_verify):
            ok, msg = N._post_log(N._log_payload("info", "x"))
        self.assertFalse(ok)
        self.assertIn("证书", msg)


class _FakeSSLSock:
    """假 TLS socket (自检测试用, 不发真实流量)。"""

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 256)

    def getpeercert(self):
        return {("subject",): (("commonName", "router.silentcrow.top"),),
                ("issuer",): (("organizationName", "Let's Encrypt"),),
                "notAfter": "Jan  2 07:32:27 2027 GMT"}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeSock:
    def wrap_socket(self, sock, server_hostname=None):
        return _FakeSSLSock()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


TLS_LINES = [
    "TLS      : TLSv1.3 / TLS_AES_128_GCM_SHA256",
    "证书     : commonName=router.silentcrow.top",
    "签发者   : organizationName=Let's Encrypt",
]


class TestLogSelfCheck(_TmpCfg, unittest.TestCase):
    """上报自检 —— 把「上报是不是悄悄失效了」变成明确结论。"""

    def test_success_path(self):
        """链路正常 -> ok=True, 且实发一条测试日志。"""
        with mock.patch.object(N, "_log_tls_probe", return_value=TLS_LINES), \
             mock.patch.object(N, "_post_log",
                               return_value=(True, "ok")) as m_post:
            ok, lines = N._log_report_selfcheck(verbose=False)
        self.assertTrue(ok)
        m_post.assert_called_once()
        blob = "\n".join(lines)
        self.assertIn("上报链路可用", blob)
        self.assertIn("Let's Encrypt", blob)

    def test_disabled_skips_real_push(self):
        """开关关闭时不实发 —— 不违背用户的关闭意图。"""
        N._set_log_reporting_enabled(False)
        with mock.patch.object(N, "_log_tls_probe", return_value=TLS_LINES), \
             mock.patch.object(N, "_post_log") as m_post:
            ok, lines = N._log_report_selfcheck(verbose=False)
        self.assertTrue(ok)
        m_post.assert_not_called()
        self.assertIn("已跳过", "\n".join(lines))

    def test_unreachable_endpoint_fails(self):
        """端点不可达 -> ok=False, 明确给出原因。"""
        with mock.patch.object(N, "_log_tls_probe",
                               side_effect=ConnectionRefusedError("refused")):
            ok, lines = N._log_report_selfcheck(verbose=False)
        self.assertFalse(ok)
        self.assertIn("连接失败", "\n".join(lines))

    def test_untrusted_cert_fails(self):
        """证书不受信 -> ok=False, 明确指出是证书问题 (根证书库陈旧)。"""
        import ssl as _ssl
        with mock.patch.object(N, "_log_tls_probe",
                               side_effect=_ssl.SSLCertVerificationError(
                                   "self-signed certificate")):
            ok, lines = N._log_report_selfcheck(verbose=False)
        self.assertFalse(ok)
        blob = "\n".join(lines)
        self.assertIn("证书校验失败", blob)
        self.assertIn("根证书库", blob)

    def test_missing_token_fails(self):
        """没 token -> 直接判不可用。"""
        with mock.patch.object(N, "_log_token", return_value=""), \
             mock.patch.object(N, "_log_tls_probe", return_value=TLS_LINES):
            ok, lines = N._log_report_selfcheck(verbose=False)
        self.assertFalse(ok)
        self.assertIn("未配置 token", "\n".join(lines))

    def test_cli_check_exit_codes(self):
        """CLI --log-report check: 通过 0 / 未通过 6, 且不跑诊断。"""
        for ret, expected in ((0, 0), (6, 6)):
            with mock.patch.object(N, "_log_report_selfcheck_cmd",
                                   return_value=ret), \
                 mock.patch.object(N, "run_diagnostics") as m_run:
                with mock.patch.object(sys, "argv",
                                       ["netpulse.py", "--log-report", "check"]):
                    with self.assertRaises(SystemExit) as ctx:
                        N.main()
            self.assertEqual(ctx.exception.code, expected)
            m_run.assert_not_called()


class TestLogReportFlow(_TmpCfg, unittest.TestCase):
    """上报流程: 降级不抛异常 / 成功后计数 / 超限不再报。"""

    def _boom(self):
        raise ValueError("boom for test")

    def test_network_failure_does_not_raise(self):
        """网络失败必须降级为 False, 不能抛。"""
        with mock.patch.object(N, "_urlopen_with_proxy",
                               side_effect=OSError("network down")):
            try:
                self._boom()
            except ValueError as exc:
                ok, msg = N._emit_runtime_event("error", exc, "模块:x")
        self.assertFalse(ok)
        self.assertIn("上报失败", msg)

    def test_http_401_surfaces_server_reason(self):
        """401 的服务端原因必须透传 (压成 "HTTP Error 401" 等于丢线索)。"""
        import urllib.error

        def _raise_401(*a, **kw):
            raise urllib.error.HTTPError(
                "http://x", 401, "Unauthorized", {},
                __import__("io").BytesIO(
                    json.dumps({"ok": False,
                                "error": "无效 token"}).encode("utf-8")))

        with mock.patch.object(N, "_urlopen_with_proxy", side_effect=_raise_401):
            try:
                self._boom()
            except ValueError as exc:
                ok, msg = N._emit_runtime_event("error", exc, "模块:x")
        self.assertFalse(ok)
        self.assertIn("无效 token", msg)

    def test_http_400_surfaces_server_reason(self):
        """400 的服务端原因 (如 message 不能为空) 必须透传。"""
        import urllib.error

        def _raise_400(*a, **kw):
            raise urllib.error.HTTPError(
                "http://x", 400, "Bad Request", {},
                __import__("io").BytesIO(
                    json.dumps({"ok": False,
                                "error": "第 1 条: message 不能为空"}
                               ).encode("utf-8")))

        with mock.patch.object(N, "_urlopen_with_proxy", side_effect=_raise_400):
            try:
                self._boom()
            except ValueError as exc:
                ok, msg = N._emit_runtime_event("error", exc, "模块:x")
        self.assertFalse(ok)
        self.assertIn("message 不能为空", msg)

    def test_disabled_skips_report(self):
        N._set_log_reporting_enabled(False)
        with mock.patch.object(N, "_post_log") as m_post:
            try:
                self._boom()
            except ValueError as exc:
                ok, msg = N._emit_runtime_event("error", exc, "模块:x")
        self.assertFalse(ok)
        m_post.assert_not_called()
        self.assertIn("关闭", msg)

    def test_success_increments_counter(self):
        with mock.patch.object(N, "_post_log",
                               return_value=(True, "ok")) as m_post:
            try:
                self._boom()
            except ValueError as exc:
                ok, msg = N._emit_runtime_event("error", exc, "模块:x")
        self.assertTrue(ok)
        m_post.assert_called_once()
        self.assertTrue(N._log_reported_counts())

    def test_rate_limit_stops_repeat(self):
        """同类异常超过上限后不再上报 (防崩溃循环刷屏)。"""
        with mock.patch.object(N, "_post_log",
                               return_value=(True, "ok")) as m_post:
            for _ in range(N.LOG_MAX_REPORTS_PER_KEY + 3):
                try:
                    self._boom()
                except ValueError as exc:
                    N._emit_runtime_event("error", exc, "模块:x")
        self.assertLessEqual(m_post.call_count, N.LOG_MAX_REPORTS_PER_KEY)

    def test_rate_limit_is_per_version(self):
        """指纹带版本号 —— 修好了的老问题不会永久停止上报。"""
        try:
            self._boom()
        except ValueError as exc:
            key = N._log_fingerprint("模块:x", exc)
        self.assertIn(N.APP_VERSION, key)


class TestLogLocalLogThrottle(_TmpCfg, unittest.TestCase):
    """本地日志限频 —— 盯障 24h 循环里同一处失败会重复上万次。"""

    def test_local_log_written_only_n_times(self):
        with mock.patch.object(N, "_post_log", return_value=(True, "ok")), \
             mock.patch.object(N, "_write_error_log",
                               return_value="x") as m_log:
            for _ in range(N.LOG_MAX_REPORTS_PER_KEY + 5):
                try:
                    raise ValueError("same")
                except ValueError as exc:
                    N._emit_runtime_event("error", exc, "模块:throttle")
        self.assertLessEqual(m_log.call_count, N.LOG_MAX_REPORTS_PER_KEY)


class TestLogRunBudget(_TmpCfg, unittest.TestCase):
    """单轮预算 —— 客户网络全断时 23 个模块会集体失败。"""

    def test_budget_limits_probe_failures(self):
        with mock.patch.object(N, "_emit_runtime_event_async") as m_async:
            for i in range(N.LOG_RUN_BUDGET + 5):
                try:
                    raise ValueError("boom %d" % i)
                except ValueError as exc:
                    N._emit_probe_failure("m%d" % i, exc, "tb")
        self.assertLessEqual(m_async.call_count, N.LOG_RUN_BUDGET)

    def test_budget_blocks_after_limit(self):
        """预算用尽后不再上报, 但仍写本地日志。"""
        N._LOG_RUN_STATE["sent"] = N.LOG_RUN_BUDGET
        with mock.patch.object(N, "_emit_runtime_event_async") as m_async, \
             mock.patch.object(N, "_write_error_log",
                               return_value="x") as m_log:
            try:
                raise ValueError("x")
            except ValueError as exc:
                N._emit_probe_failure("m", exc, "tb")
        m_async.assert_not_called()
        m_log.assert_called_once()

    def test_budget_reset_on_new_run(self):
        """每轮诊断开头重置预算 —— 否则第二轮开始就完全不报了。"""
        src = open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "netpulse.py"),
            encoding="utf-8").read()
        self.assertIn('_LOG_RUN_STATE["sent"] = 0', src,
                      "run_diagnostics 开头必须重置单轮预算")
        # 语义: 预算归零后第一事件应放行
        N._LOG_RUN_STATE["sent"] = 0
        with mock.patch.object(N, "_emit_runtime_event_async") as m_async:
            try:
                raise ValueError("x")
            except ValueError as exc:
                N._emit_probe_failure("m", exc, "tb")
        m_async.assert_called_once()


class TestLogProbeTraceback(_TmpCfg, unittest.TestCase):
    """核心: 探针异常必须保住异常类型与完整 traceback (旧路径只留 str(e))。"""

    def _register_failing_probe(self, key):
        def _boom(callback=None):
            raise TimeoutError("probe exploded")
        N._V2_PROBES[key] = _boom

    def test_probe_failure_keeps_exception_type_and_stack(self):
        key = "test_probe_boom"
        self._register_failing_probe(key)
        captured = {}

        def _capture(level, exc, scope, detail=None, tb_text=None):
            captured["level"] = level
            captured["exc_type"] = type(exc).__name__
            captured["scope"] = scope
            captured["tb"] = tb_text or ""

        try:
            with mock.patch.object(N, "_emit_runtime_event_async",
                                   side_effect=_capture):
                status, res = N._run_module_with_timeout(key, None)
        finally:
            N._V2_PROBES.pop(key, None)

        self.assertEqual(status, "错误")
        # 异常类型进了模块结果 —— 旧路径只有一句 str(e)
        self.assertEqual(res["_exc"]["type"], "TimeoutError")
        self.assertIn("TimeoutError", captured["exc_type"])
        self.assertIn("模块:" + key, captured["scope"])
        # 完整 traceback 进了上报 —— 旧路径完全没有
        self.assertIn("Traceback (most recent call last)", captured["tb"])
        self.assertIn("TimeoutError", captured["tb"])
        # error 键的值逐字不变 (报告文案零变化)
        self.assertIn("probe exploded", res["error"])

    def test_scheduler_failure_keeps_exception_type(self):
        """调度层异常 (顺序/并行模式) 同样要保住类型与栈。"""
        captured = {}

        def _capture(level, exc, scope, detail=None, tb_text=None):
            captured["exc_type"] = type(exc).__name__
            captured["tb"] = tb_text or ""

        with mock.patch.object(N, "_run_module_with_timeout",
                               side_effect=PermissionError("denied")), \
             mock.patch.object(N, "_emit_runtime_event_async",
                               side_effect=_capture), \
             mock.patch.dict(N.MODULE_MAP, {"dns": ("DNS", object)}):
            results, full = N._run_diagnostics_sequential(["dns"], is_tty=False)

        self.assertEqual(results["dns"], "错误")
        self.assertEqual(full["dns"]["_exc"]["type"], "PermissionError")
        self.assertIn("Traceback (most recent call last)", captured["tb"])


class TestLogIntegration(_TmpCfg, unittest.TestCase):
    """接入点: _cli_entry 崩溃路径 + 线程异常钩子。"""

    def test_cli_entry_reports_on_crash(self):
        """主线程未预期异常 -> 触发上报 + 退出码 3。"""
        with mock.patch.object(N, "main",
                               side_effect=RuntimeError("cli boom")), \
             mock.patch.object(N, "_emit_runtime_event_async",
                               return_value=True) as m_rep, \
             mock.patch.object(N, "_write_error_log", return_value=None):
            with self.assertRaises(SystemExit) as ctx:
                N._cli_entry()
        self.assertEqual(ctx.exception.code, 3, "崩溃退出码必须是 3")
        m_rep.assert_called_once()
        self.assertEqual(m_rep.call_args[0][0], "critical",
                         "顶层崩溃级别必须是 critical")

    def test_report_failure_does_not_break_exit_code(self):
        """上报自身抛异常不能影响退出码。"""
        with mock.patch.object(N, "main",
                               side_effect=RuntimeError("cli boom")), \
             mock.patch.object(N, "_emit_runtime_event_async",
                               side_effect=OSError("report died")), \
             mock.patch.object(N, "_write_error_log", return_value=None):
            with self.assertRaises(SystemExit) as ctx:
                N._cli_entry()
        self.assertEqual(ctx.exception.code, 3,
                         "上报失败不得改变退出码 (工具执行失败口径)")

    def test_keyboard_interrupt_not_reported(self):
        """Ctrl+C 不是错误, 不应上报。"""
        with mock.patch.object(N, "main",
                               side_effect=KeyboardInterrupt()), \
             mock.patch.object(N, "_emit_runtime_event_async") as m_rep:
            with self.assertRaises(SystemExit) as ctx:
                N._cli_entry()
        self.assertEqual(ctx.exception.code, 130)
        m_rep.assert_not_called()

    def test_system_exit_not_reported(self):
        """argparse 的 SystemExit 原样抛出, 不上报。"""
        with mock.patch.object(N, "main", side_effect=SystemExit(2)), \
             mock.patch.object(N, "_emit_runtime_event_async") as m_rep:
            with self.assertRaises(SystemExit) as ctx:
                N._cli_entry()
        self.assertEqual(ctx.exception.code, 2)
        m_rep.assert_not_called()

    def test_thread_excepthook_installed(self):
        """后台线程异常钩子必须装上。"""
        old = threading.excepthook
        try:
            self.assertTrue(N._install_thread_excepthook())
            self.assertNotEqual(threading.excepthook, old, "钩子应被替换")
        finally:
            threading.excepthook = old

    def test_thread_hook_reports(self):
        """线程里的未捕获异常也要上报。"""
        old = threading.excepthook
        try:
            N._install_thread_excepthook()
            with mock.patch.object(N, "_emit_runtime_event_async",
                                   return_value=True) as m_rep, \
                 mock.patch.object(N, "_write_error_log", return_value=None):
                def _boom():
                    raise ValueError("thread boom")
                t = threading.Thread(target=_boom)
                t.start()
                t.join()
            m_rep.assert_called_once()
            self.assertIn("线程:", m_rep.call_args[0][2])
        finally:
            threading.excepthook = old


class TestLogThreadHooks(_TmpCfg, unittest.TestCase):
    """后台线程「静默死亡」改造 —— 这些点原本 except Exception: pass。"""

    def test_emit_thread_failure_reports(self):
        with mock.patch.object(N, "_emit_runtime_event_async") as m_async:
            try:
                raise ValueError("silent death")
            except ValueError as exc:
                N._emit_thread_failure(exc, "线程:monitor-probe",
                                       detail="探测循环异常")
        m_async.assert_called_once()
        args, kwargs = m_async.call_args
        self.assertEqual(args[0], "error")
        self.assertEqual(args[2], "线程:monitor-probe")
        self.assertIn("Traceback", kwargs.get("tb_text") or "")

    def test_probe_loop_failure_is_not_silent(self):
        """盯障探测循环异常必须被接住 —— 原先静默 pass 会呈现「0 丢包」假象。"""
        src = open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "netpulse.py"),
            encoding="utf-8").read()
        self.assertIn('_emit_thread_failure(e, "线程:monitor-probe"',
                      src, "盯障探测循环必须接异常钩子")
        self.assertIn('_emit_thread_failure(e, "线程:monitor-tcpstat"',
                      src, "TCP 重传统计采样必须接异常钩子")
        self.assertIn('_emit_thread_failure(e, "线程:latency-read"',
                      src, "ping 读循环必须接异常钩子")
        self.assertIn('_emit_thread_failure(e, "线程:update-check"',
                      src, "更新检查线程必须接异常钩子")


class TestLogNotice(_TmpCfg, unittest.TestCase):
    """首次告知弹窗。"""

    def test_notice_text_declares_scope(self):
        text = " ".join(N._log_notice_text())
        self.assertIn("异常类型", text)
        self.assertIn("不含", text, "必须声明不含哪些数据")

    def test_non_tty_skips_silently(self):
        """非 TTY (管道/--json) 静默跳过, 不污染机器可读输出。"""
        with mock.patch.object(N.sys.stdin, "isatty", return_value=False):
            with mock.patch("builtins.input") as m_in:
                N._offer_log_reporting_notice()
        m_in.assert_not_called()

    def test_declining_disables(self):
        """用户答 N -> 关闭上报。"""
        with mock.patch.object(N.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(N.sys.stdout, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="n"):
            N._offer_log_reporting_notice()
        self.assertFalse(N._log_reporting_enabled(),
                         "用户明确拒绝后必须关闭")
        self.assertTrue(N._log_notice_shown(), "告知标记要记下, 不反复打扰")

    def test_accepting_keeps_enabled(self):
        with mock.patch.object(N.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(N.sys.stdout, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="y"):
            N._offer_log_reporting_notice()
        self.assertTrue(N._log_reporting_enabled())

    def test_notice_only_once(self):
        """告知过一次不再打扰。"""
        N._mark_log_notice_shown()
        with mock.patch.object(N.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(N.sys.stdout, "isatty", return_value=True), \
             mock.patch("builtins.input") as m_in:
            N._offer_log_reporting_notice()
        m_in.assert_not_called()


class TestLogCliSwitch(_TmpCfg, unittest.TestCase):
    """CLI --log-report 开关 (自动化场景用, 无需进交互菜单)。"""

    def _run_main(self, value):
        """跑 main() 到参数处理完就中断 (用哨兵异常截断, 不真跑诊断)。"""
        class _Stop(Exception):
            pass

        def _stop(*a, **kw):
            raise _Stop()

        with mock.patch.object(N, "_start_scapy_preload"), \
             mock.patch.object(N, "_start_update_check"), \
             mock.patch.object(N, "_prime_update_state_from_cache"), \
             mock.patch.object(N, "run_diagnostics", side_effect=_stop), \
             mock.patch.object(N, "interactive_menu", side_effect=_stop), \
             mock.patch.object(sys, "argv", ["netpulse.py", "--log-report", value]):
            with self.assertRaises(_Stop):
                N.main()

    def test_cli_off_disables(self):
        self._run_main("off")
        self.assertFalse(N._log_reporting_enabled(),
                         "--log-report off 必须关闭上报")

    def test_cli_on_enables(self):
        self._run_main("off")
        self._run_main("on")
        self.assertTrue(N._log_reporting_enabled(),
                        "--log-report on 必须开启上报")

    def test_cli_off_marks_notice_shown(self):
        """显式给过参数 -> 不再弹首次告知。"""
        self._run_main("off")
        self.assertTrue(N._log_notice_shown(),
                        "CLI 显式指定后不应再弹告知")


class _MockLogServer(BaseHTTPRequestHandler):
    """按协议实现的本地 mock 服务端 (回环, 不依赖外网)。"""

    received = []
    fail_with = None      # (status, error_text) —— 测错误透传

    def log_message(self, *a):   # 静音
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        type(self).received.append({
            "path": self.path,
            "headers": dict(self.headers),
            "raw": raw.decode("utf-8", "ignore"),
        })
        if type(self).fail_with:
            status, err = type(self).fail_with
            body = json.dumps({"ok": False, "error": err}).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b'{"ok":true,"data":{"inserted":1}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestLogSourceRunGuard(unittest.TestCase):
    """v1.18.2: 源码运行 (开发机 / 回归测试) 不得往线上日志服务器推送。

    背景: 2026-11-03 跑全量回归时, `tests/test_v1100_full_all.py` 故意抛的
    RuntimeError("boom") 被真推到了线上日志服务器 (id 14/15) —— 厂商通道
    被自家测试污染, 还带着本机目录结构。
    """

    def setUp(self):
        self._saved = os.environ.pop(N.LOG_ALLOW_SOURCE_ENV, None)

    def tearDown(self):
        if self._saved is not None:
            os.environ[N.LOG_ALLOW_SOURCE_ENV] = self._saved

    def test_source_run_is_blocked_by_default(self):
        """非打包运行 + 未放行 → 不允许自动上报。"""
        with mock.patch.object(N.sys, "frozen", False, create=True):
            self.assertFalse(N._report_allowed_from_source())

    def test_frozen_exe_may_report(self):
        """打包后的 exe (客户机) → 照常上报。"""
        with mock.patch.object(N.sys, "frozen", True, create=True):
            self.assertTrue(N._report_allowed_from_source())

    def test_source_run_can_be_opted_in(self):
        """显式放行 (联调) → 允许上报。"""
        os.environ[N.LOG_ALLOW_SOURCE_ENV] = "1"
        with mock.patch.object(N.sys, "frozen", False, create=True):
            self.assertTrue(N._report_allowed_from_source())

    def test_source_run_does_not_push_payload(self):
        """实际出口: 源码运行时不调 _post_log, 但本地日志照写。"""
        with mock.patch.object(N, "_post_log") as m_post, \
             mock.patch.object(N, "_write_error_log", return_value="x") as m_log:
            try:
                raise ValueError("源码运行不该上报")
            except ValueError as exc:
                ok, msg = N._emit_runtime_event("error", exc, "模块:srcguard")
        m_post.assert_not_called()
        self.assertFalse(ok)
        self.assertIn("源码运行", msg)
        m_log.assert_called_once()


class TestLogEndToEnd(_TmpCfg, unittest.TestCase):
    """端到端: 真发一条 POST 到本地 mock 服务端, 校验请求形状。"""

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _MockLogServer)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        super().setUp()
        _MockLogServer.received = []
        _MockLogServer.fail_with = None
        os.environ[N.LOG_URL_ENV] = (
            "http://127.0.0.1:%d/v1/logs" % self.port)

    def tearDown(self):
        os.environ.pop(N.LOG_URL_ENV, None)
        super().tearDown()

    def test_real_post_reaches_server_with_correct_shape(self):
        try:
            raise ValueError("端到端测试异常")
        except ValueError as exc:
            ok, msg = N._emit_runtime_event("error", exc, "模块:e2e")
        self.assertTrue(ok, "上报应成功: %s" % msg)
        self.assertEqual(len(_MockLogServer.received), 1)
        req = _MockLogServer.received[0]
        self.assertEqual(req["path"], "/v1/logs")
        self.assertEqual(req["headers"].get("X-Token"), N.LOG_SERVER_TOKEN)
        self.assertIn("application/json", req["headers"].get("Content-Type", ""))
        data = json.loads(req["raw"])
        self.assertEqual(data["app"], "netpulse")
        self.assertEqual(data["type"], "error")
        self.assertTrue(data["message"].strip())
        self.assertRegex(data["ts"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertIn("stack", data)
        self.assertIn("Traceback", data["stack"])

    def test_server_rejection_is_surfaced(self):
        _MockLogServer.fail_with = (400, "第 1 条: message 不能为空")
        try:
            raise ValueError("x")
        except ValueError as exc:
            ok, msg = N._emit_runtime_event("error", exc, "模块:e2e")
        self.assertFalse(ok)
        self.assertIn("message 不能为空", msg)

    def test_unauthorized_is_surfaced(self):
        _MockLogServer.fail_with = (401, "无效 token")
        try:
            raise ValueError("x")
        except ValueError as exc:
            ok, msg = N._emit_runtime_event("error", exc, "模块:e2e")
        self.assertFalse(ok)
        self.assertIn("无效 token", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
