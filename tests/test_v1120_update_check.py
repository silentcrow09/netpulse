# -*- coding: utf-8 -*-
"""v1.12.0 自动检查更新回归测试 (全 mock, 不依赖真实网络)。

覆盖: 版本解析/比较 | 双源检查 (GitHub API → jsDelivr 回落) |
24h 频控缓存 (LOCALAPPDATA) | _UPDATE_STATE 状态机 | 菜单提示行
(gh-proxy 加速链接) | 后台线程 | --no-update-check 参数。
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N


def _newer_fake_version():
    """构造必然大于当前 APP_VERSION 的假远端版本。

    此前各用例硬编码固定版本 ("1.13.0"/"1.14.0"), 本地 APP_VERSION bump
    追平后 remote == local → is_new False → 用例必挂。改为 minor+1 动态
    构造, 以后发版不再踩 (v1.13.1 修复)。
    """
    parts = (N.APP_VERSION.split(".") + ["0", "0"])[:3]
    major, minor, _patch = (int(x) for x in parts)
    return f"{major}.{minor + 1}.0"


class FakeResp:
    """上下文管理器风格的假 HTTP 响应。"""

    def __init__(self, payload):
        self._data = (payload if isinstance(payload, bytes)
                      else json.dumps(payload).encode("utf-8"))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, _n=-1):
        return self._data


def _resp_side_effect(responses):
    """按调用序返回 FakeResp / 抛异常。responses: [payload|Exception, ...]"""
    it = iter(responses)

    def _call(url, timeout=None, ua=None):
        item = next(it)
        if isinstance(item, Exception):
            raise item
        return FakeResp(item)
    return _call


class TestVersionParse(unittest.TestCase):
    def test_parse_with_v_prefix(self):
        self.assertEqual(N._parse_version("v1.12.0"), (1, 12, 0))
        self.assertEqual(N._parse_version("V2.0"), (2, 0))

    def test_parse_plain_and_short(self):
        self.assertEqual(N._parse_version("1.12.0"), (1, 12, 0))
        self.assertEqual(N._parse_version("1.12"), (1, 12))

    def test_parse_garbage(self):
        self.assertIsNone(N._parse_version(""))
        self.assertIsNone(N._parse_version("latest"))
        self.assertIsNone(N._parse_version(None))
        # 预发布标签 (v1.12.0-beta) 取前缀数字段, 视作 (1,12,0);
        # GitHub tag 无预发布场景, 语义上够用
        self.assertEqual(N._parse_version("v1.12.0-beta"), (1, 12, 0))

    def test_newer_basic(self):
        self.assertTrue(N._version_newer("v1.13.0", "1.12.0"))
        self.assertFalse(N._version_newer("1.12.0", "1.12.0"))
        self.assertFalse(N._version_newer("v1.11.9", "1.12.0"))

    def test_newer_pads_missing_segments(self):
        self.assertFalse(N._version_newer("1.12", "1.12.0"))
        self.assertTrue(N._version_newer("1.13", "1.12.0"))

    def test_newer_bad_input_false(self):
        self.assertFalse(N._version_newer("garbage", "1.12.0"))
        self.assertFalse(N._version_newer("1.13.0", None))


class TestFetchLatestVersion(unittest.TestCase):
    def test_github_api_primary(self):
        with mock.patch.object(N, "_urlopen_with_proxy",
                               side_effect=_resp_side_effect(
                                   [{"tag_name": "v1.13.0"}])):
            self.assertEqual(N._fetch_latest_version(), ("1.13.0", True))

    def test_fallback_jsdelivr(self):
        """API 挂 → jsDelivr version.json 回落 (标记非主源)。"""
        with mock.patch.object(
                N, "_urlopen_with_proxy",
                side_effect=_resp_side_effect(
                    [OSError("timeout"), {"version": "1.14.0"}])):
            self.assertEqual(N._fetch_latest_version(), ("1.14.0", False))

    def test_both_fail_returns_none(self):
        with mock.patch.object(
                N, "_urlopen_with_proxy",
                side_effect=_resp_side_effect([OSError(), OSError()])):
            self.assertEqual(N._fetch_latest_version(), (None, False))

    def test_malformed_json_returns_none(self):
        with mock.patch.object(
                N, "_urlopen_with_proxy",
                side_effect=_resp_side_effect([b"not json{", b"<html>"])):
            self.assertEqual(N._fetch_latest_version(), (None, False))


class TestCache(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.get("LOCALAPPDATA")
        self.tmp = tempfile.mkdtemp()
        os.environ["LOCALAPPDATA"] = self.tmp

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = self._old_env

    def test_roundtrip(self):
        now = time.time()
        N._save_update_cache(now, "1.13.0")
        ts, ver = N._load_update_cache(now + 10)
        self.assertEqual(ver, "1.13.0")
        self.assertAlmostEqual(ts, now, delta=5)

    def test_stale_cache_expired(self):
        N._save_update_cache(time.time() - N.UPDATE_CHECK_INTERVAL_S - 60,
                             "1.13.0")
        self.assertEqual(N._load_update_cache(time.time()), (0.0, None))

    def test_corrupt_cache(self):
        p = N._update_cache_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write("{broken")
        self.assertEqual(N._load_update_cache(time.time()), (0.0, None))

    def test_missing_cache(self):
        self.assertEqual(N._load_update_cache(time.time()), (0.0, None))


class TestCheckUpdate(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.get("LOCALAPPDATA")
        self.tmp = tempfile.mkdtemp()
        os.environ["LOCALAPPDATA"] = self.tmp
        self._reset_state()

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = self._old_env
        self._reset_state()          # 防状态泄漏到后续测试类

    @staticmethod
    def _reset_state():
        with N._UPDATE_LOCK:
            N._UPDATE_STATE.update(latest=None, checked_at=0.0, is_new=False)

    def test_cache_hit_no_network(self):
        newer = _newer_fake_version()
        N._save_update_cache(time.time(), newer)
        with mock.patch.object(N, "_fetch_latest_version") as m_fetch:
            ver = N._check_update()
        m_fetch.assert_not_called()          # 24h 内缓存命中, 不发请求
        self.assertEqual(ver, newer)
        self.assertTrue(N._UPDATE_STATE["is_new"])   # newer > 当前版本

    def test_cache_hit_same_version_not_new(self):
        N._save_update_cache(time.time(), N.APP_VERSION)
        N._check_update()
        self.assertFalse(N._UPDATE_STATE["is_new"])

    def test_cache_miss_fetch_success(self):
        newer = _newer_fake_version()
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(newer, True)):
            ver = N._check_update()
        self.assertEqual(ver, newer)
        self.assertTrue(N._UPDATE_STATE["is_new"])   # newer > 当前版本
        self.assertEqual(N._load_update_cache(time.time())[1], newer)

    def test_fetch_fail_silent_no_cache(self):
        N._save_update_cache(time.time() - N.UPDATE_CHECK_INTERVAL_S - 60,
                             "1.13.0")     # 过期缓存
        self._reset_state()
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(None, False)):
            self.assertIsNone(N._check_update())
        self.assertIsNone(N._UPDATE_STATE["latest"])   # 状态未被污染
        self.assertEqual(N._load_update_cache(time.time()), (0.0, None))

    def test_force_skips_cache(self):
        N._save_update_cache(time.time(), "1.13.0")
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=("1.15.0", True)) as m_fetch:
            ver = N._check_update(force=True)
        m_fetch.assert_called_once()
        self.assertEqual(ver, "1.15.0")

    def test_fallback_stale_answer_not_cached(self):
        """v1.14.1 回归: GitHub API 挂 + jsDelivr @master 快照滞后数周,
        回落源返回旧版本号 → 不得写 24h 频控缓存 (否则陈旧答案锁死提示)。
        """
        old_ver = "1.12.2"          # 确保 < 当前 APP_VERSION
        self.assertTrue(N._version_newer(N.APP_VERSION, old_ver))
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(old_ver, False)):
            self.assertEqual(N._check_update(force=True), old_ver)
        self.assertFalse(N._UPDATE_STATE["is_new"])   # 旧版本不提示, 正常
        self.assertEqual(N._load_update_cache(time.time()), (0.0, None))
        # 下次启动重两 → 网络重试 (不走陈旧缓存)
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(_newer_fake_version(), False)) \
                as m_retry:
            N._check_update()
        m_retry.assert_called_once()
        self.assertTrue(N._UPDATE_STATE["is_new"])

    def test_fallback_newer_answer_cached(self):
        """回落源报告"确有新版"时照常写缓存 (陈旧但仍领先本地即可信)。"""
        newer = _newer_fake_version()
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(newer, False)):
            N._check_update(force=True)
        self.assertEqual(N._load_update_cache(time.time())[1], newer)
        self.assertTrue(N._UPDATE_STATE["is_new"])


class TestNoticeLine(unittest.TestCase):
    def tearDown(self):
        with N._UPDATE_LOCK:
            N._UPDATE_STATE.update(latest=None, checked_at=0.0, is_new=False)

    def test_no_notice_when_no_state(self):
        self.assertIsNone(N._update_notice_line())

    def test_no_notice_when_not_newer(self):
        with N._UPDATE_LOCK:
            N._UPDATE_STATE.update(latest=N.APP_VERSION, checked_at=1.0,
                                   is_new=False)
        self.assertIsNone(N._update_notice_line())

    def test_notice_contains_proxy_link(self):
        with N._UPDATE_LOCK:
            N._UPDATE_STATE.update(latest="1.13.0", checked_at=1.0,
                                   is_new=True)
        line = N._update_notice_line()
        self.assertIn("v1.13.0", line)
        self.assertIn(f"v{N.APP_VERSION}", line)
        self.assertIn(N.UPDATE_DL_PROXY.rstrip("/"), line)
        self.assertIn(
            f"{N.UPDATE_DL_PROXY}https://github.com/{N.GH_REPO}/releases/"
            f"download/v1.13.0/NetPulse.exe", line)


class TestThreadAndArgparse(unittest.TestCase):
    def setUp(self):
        with N._UPDATE_LOCK:
            N._UPDATE_STATE.update(latest=None, checked_at=0.0, is_new=False)

    def tearDown(self):
        with N._UPDATE_LOCK:
            N._UPDATE_STATE.update(latest=None, checked_at=0.0, is_new=False)

    def test_thread_sets_state(self):
        newer = _newer_fake_version()
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(newer, True)), \
             mock.patch.object(N, "_save_update_cache"):
            t = N._start_update_check(force=True)
        t.join(timeout=10)
        self.assertFalse(t.is_alive())
        self.assertTrue(N._UPDATE_STATE["is_new"])
        self.assertEqual(N._UPDATE_STATE["latest"], newer)

    def test_thread_swallows_exception(self):
        """检查崩溃不得影响主流程 (daemon 兜底)。"""
        with mock.patch.object(N, "_check_update",
                               side_effect=RuntimeError("boom")):
            t = N._start_update_check(force=True)
        t.join(timeout=10)
        self.assertFalse(t.is_alive())

    def test_argparse_no_update_check(self):
        old_argv = sys.argv
        sys.argv = ["netpulse.py", "--no-update-check", "--list"]
        try:
            with mock.patch.object(N, "_print_module_list"):
                with mock.patch.object(N, "_start_update_check") as m_start:
                    N.main()
        finally:
            sys.argv = old_argv
        m_start.assert_not_called()


class TestDebugAndSource(unittest.TestCase):
    """v1.14.6: from_primary 状态记录 + NP_UPDATE_DEBUG stderr 输出。"""

    def setUp(self):
        with N._UPDATE_LOCK:
            N._UPDATE_STATE.update(latest=None, checked_at=0.0, is_new=False,
                                   from_primary=None)

    def tearDown(self):
        with N._UPDATE_LOCK:
            N._UPDATE_STATE.update(latest=None, checked_at=0.0, is_new=False,
                                   from_primary=None)
        os.environ.pop("NP_UPDATE_DEBUG", None)

    def test_check_update_records_source(self):
        """网络检查成功后在 _UPDATE_STATE 记录来源 (调试输出用)。"""
        newer = _newer_fake_version()
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(newer, False)), \
             mock.patch.object(N, "_save_update_cache"):
            ver = N._check_update(force=True)
        self.assertEqual(ver, newer)
        self.assertIs(N._UPDATE_STATE["from_primary"], False)

    def test_debug_print_on_success(self):
        newer = _newer_fake_version()
        os.environ["NP_UPDATE_DEBUG"] = "1"
        buf = io.StringIO()
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(newer, True)), \
             mock.patch.object(N, "_save_update_cache"), \
             contextlib.redirect_stderr(buf):
            N._start_update_check(force=True).join(timeout=10)
        out = buf.getvalue()
        self.assertIn("GitHub API", out)
        self.assertIn(newer, out)
        self.assertIn("[NetPulse]", out)

    def test_debug_print_on_failure(self):
        os.environ["NP_UPDATE_DEBUG"] = "1"
        buf = io.StringIO()
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(None, False)), \
             contextlib.redirect_stderr(buf):
            N._start_update_check(force=True).join(timeout=10)
        self.assertIn("双源失败", buf.getvalue())

    def test_silent_without_debug_env(self):
        """未设 NP_UPDATE_DEBUG 时零输出 (stderr 也不写)。"""
        buf = io.StringIO()
        with mock.patch.object(N, "_fetch_latest_version",
                               return_value=(None, False)), \
             contextlib.redirect_stderr(buf):
            N._start_update_check(force=True).join(timeout=10)
        self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main(verbosity=1)
    print("OK")
