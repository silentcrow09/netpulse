# -*- coding: utf-8 -*-
"""v1.15.2 审查 P1-22 · 抓包授权标记不再永久有效 回归测试。

旧版实现 (审查前):
    def _capture_confirm_once(...):
        ack = _capture_ack_path()
        if os.path.exists(ack):
            return True            # ← 只判存在, 内容从没被读过
    def _write_capture_ack(ack):
        f.write(datetime.now().isoformat())   # ← 只写一行时间戳

缺陷: 标记**永久有效** —— ① 从不校验内容  ② 隐私白名单变了也不重新确认
      (ACK 里根本没有白名单信息)  ③ 永不清理。

修后: 标记写 {"ts", "fp"}; 判读时校验 ① 时间戳可解析 ② 未超有效期
      (CAPTURE_ACK_VALID_DAYS 天) ③ 白名单指纹仍一致; 任一不满足 → 重新征求授权。

跑用: cd 到项目根目录, `py -3.13 tests/test_v1152_capture_ack.py`
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


class TestCaptureAckValidity(unittest.TestCase):
    """授权标记的三道校验。"""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="np_ack_")
        self.ack = os.path.join(self._tmp, ".capture_ack")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, payload):
        with open(self.ack, "w", encoding="utf-8") as f:
            if isinstance(payload, (dict, list)):
                json.dump(payload, f)
            else:
                f.write(payload)

    def _valid_payload(self, ts=None, fp=None):
        return {"ts": ts or datetime.now().isoformat(),
                "fp": fp if fp is not None else N._capture_policy_fingerprint()}

    # ── 闸门 1: 过期标记必须失效 ──
    def test_expired_ack_is_invalid(self):
        old = (datetime.now() - timedelta(days=N.CAPTURE_ACK_VALID_DAYS + 1)).isoformat()
        self._write(self._valid_payload(ts=old))
        valid, why = N._capture_ack_valid(self.ack)
        self.assertFalse(valid, "超过有效期的授权必须失效")
        self.assertIn("超过", why)

    # ── 闸门 2: 白名单指纹变了必须失效 ──
    def test_policy_fingerprint_mismatch_is_invalid(self):
        self._write(self._valid_payload(fp="deadbeefdeadbeef"))
        valid, why = N._capture_ack_valid(self.ack)
        self.assertFalse(valid, "隐私白名单变更后旧授权必须失效")
        self.assertIn("白名单", why)

    # ── 闸门 3: 旧格式 (纯时间戳) 必须失效 ──
    def test_legacy_plain_timestamp_ack_is_invalid(self):
        """旧版写的只是一行时间戳, 没有指纹 → 不能当成有效授权。"""
        self._write(datetime.now().isoformat())
        valid, why = N._capture_ack_valid(self.ack)
        self.assertFalse(valid, "旧格式标记必须重新征求授权")
        self.assertIn("过期", why)

    # ── 闸门 4: 损坏内容必须失效 ──
    def test_corrupt_ack_is_invalid(self):
        self._write("{not json at all")
        valid, _ = N._capture_ack_valid(self.ack)
        self.assertFalse(valid, "损坏的标记必须失效")

    # ── 正向: 新格式且在有效期内 → 有效 ──
    def test_fresh_matching_ack_is_valid(self):
        self._write(self._valid_payload())
        valid, why = N._capture_ack_valid(self.ack)
        self.assertTrue(valid, "新格式 + 未过期 + 指纹一致 → 有效 (%s)" % why)

    # ── 闸门 5: 写出来的标记必须带指纹 ──
    def test_write_ack_includes_fingerprint(self):
        N._write_capture_ack(self.ack)
        with open(self.ack, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("fp", data, "标记必须带隐私白名单指纹")
        self.assertEqual(N._capture_policy_fingerprint(), data["fp"])
        self.assertIn("ts", data)

    # ── 闸门 6: 确认流程必须重新征求授权 (而非直接放行) ──
    def test_confirm_prompted_again_when_ack_stale(self):
        """标记过期时, _capture_confirm_once 必须再问一次。"""
        old = (datetime.now() - timedelta(days=N.CAPTURE_ACK_VALID_DAYS + 1)).isoformat()
        self._write(self._valid_payload(ts=old))
        with mock.patch.object(N, "_capture_ack_path", return_value=self.ack), \
             mock.patch.object(N, "_write_capture_ack"), \
             mock.patch("netpulse.sys.stdin.isatty", return_value=True), \
             contextlib.redirect_stdout(io.StringIO()):
            ret = N._capture_confirm_once(input_fn=lambda _p: "n")
        self.assertFalse(ret, "过期标记必须重新征求授权 (用户拒绝 → False)")

    def test_confirm_skipped_when_ack_fresh(self):
        """标记有效时不打扰用户。"""
        self._write(self._valid_payload())
        with mock.patch.object(N, "_capture_ack_path", return_value=self.ack), \
             mock.patch.object(N, "_write_capture_ack") as m_write, \
             contextlib.redirect_stdout(io.StringIO()):
            ret = N._capture_confirm_once(input_fn=lambda _p: "n")
        self.assertTrue(ret, "有效标记应直接放行")
        self.assertFalse(m_write.called, "有效标记不应重写")

    # ── 闸门 7: 文件存在但内容损坏 → 不得静默放行 ──
    def test_corrupt_ack_does_not_silently_pass(self):
        self._write("x")
        with mock.patch.object(N, "_capture_ack_path", return_value=self.ack), \
             mock.patch.object(N, "_write_capture_ack"), \
             mock.patch("netpulse.sys.stdin.isatty", return_value=True), \
             contextlib.redirect_stdout(io.StringIO()):
            ret = N._capture_confirm_once(input_fn=lambda _p: "n")
        self.assertFalse(ret, "损坏标记不得静默放行")

    # ── 闸门 8: 指纹必须随白名单常量变化 ──
    def test_fingerprint_tracks_white_list(self):
        before = N._capture_policy_fingerprint()
        with mock.patch.object(N, "CAPTURE_PAYLOAD_PORTS", (443, 8443)):
            after = N._capture_policy_fingerprint()
        self.assertNotEqual(before, after,
                            "白名单常量变了, 指纹必须跟着变")


if __name__ == "__main__":
    unittest.main(verbosity=2)
