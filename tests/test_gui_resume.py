# -*- coding: utf-8 -*-
"""GUI 会话层的停止 / 取消态 / 续跑 (v1.24.0)。

验证点:
  S1 stop(): 只在 running 时受理, 幂等; 收尾期间仍算「在跑」(互斥不放宽)
  S2 取消后: phase=cancelled, 部分报告已出, 未跑的模块留在网格里(状态 None)
  S3 取消后: 续跑点落盘 (已完成的项目都在)
  S3b 落盘失败: 提示「续跑点保存失败」, 但当轮报告照常出, 不给假入口
  S4 正常跑完: phase=done, 旧续跑点被清掉
  S5 start_resume(): 没有续跑点 → 拒绝; 有 → 只跑剩下的, 合并出完整报告
  S6 续跑合并 (_gui_merge_runs): keys 取全集, results/status 取并集,
     evidence 走既有摘除逻辑, duration_ms 为两段之和
  S7 现场检测停止: 可停, 但不支持续跑 (phase=cancelled + 明确说明)
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


def _run_dict(keys, results=None, status=None, duration=100):
    return {
        "app": "NetPulse", "version": "1.24.0",
        "generated_at": datetime.now(),
        "system": {"local_ip": "192.168.1.2"},
        "status": status if status is not None else {k: "完成" for k in keys},
        "results": results if results is not None else {k: {"fake": k} for k in keys},
        "evidence": {},
        "keys": list(keys),
        "duration_ms": duration,
        "total_modules": len(np.MODULE_MAP),
    }


class _SessionCase(unittest.TestCase):
    """公共装置: 隔离续跑点路径 + 关掉跨类型忙检。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="np_sess_")
        self.resume_path = os.path.join(self.tmp, "resume.json")
        p1 = mock.patch.object(np, "_gui_resume_path",
                               return_value=self.resume_path)
        p1.start()
        self.addCleanup(p1.stop)
        p2 = mock.patch.object(np._GuiHandler, "session", None)
        p2.start()
        self.addCleanup(p2.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _wait(self, session, timeout=5.0):
        t = session._thread
        if t is not None:
            t.join(timeout)
            self.assertFalse(t.is_alive(), "诊断线程没在超时内结束")


class TestGuiSessionCancel(_SessionCase):

    # ── S1 停止受理与幂等 ──
    def test_stop_only_when_running(self):
        s = np._GuiSession()
        self.assertFalse(s.stop())            # idle → 不受理
        started = threading.Event()
        release = threading.Event()

        def _fake(keys, **kw):
            started.set()
            release.wait(5)
            return _run_dict(keys)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            ok, err = s.start(keys=["gateway", "dns"])
            self.assertTrue(ok)
            started.wait(5)
            self.assertTrue(s.stop())         # running → 受理
            # 幂等: 再点一次不报错, 也不重复受理
            snap_mid = s.snapshot()
            self.assertTrue(snap_mid["stop_requested"])
            self.assertEqual(snap_mid["phase"], "stopping")
            self.assertFalse(s.stop())         # 已进入 stopping → 不再受理
            release.set()
            self._wait(s)
        self.assertIn(s.snapshot()["phase"], ("stopping", "cancelled", "done"))

    def test_stopping_still_counts_as_running(self):
        s = np._GuiSession()
        started = threading.Event()
        release = threading.Event()

        def _fake(keys, **kw):
            started.set()
            release.wait(5)
            return _run_dict(keys)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            s.start(keys=["gateway"])
            started.wait(5)
            s.stop()
            # 收尾期间互斥不能放开 (spec F1)
            self.assertTrue(s.is_running())
            release.set()
            self._wait(s)

    # ── S2 取消后: 部分报告 + 未跑模块留网格 ──
    def test_cancelled_phase_and_partial_report(self):
        s = np._GuiSession()

        def _fake(keys, **kw):
            cb = kw.get("progress_cb")
            evt = kw.get("cancel_evt")
            results, status = {}, {}
            for k in keys:
                if evt is not None and evt.is_set():
                    break
                if cb:
                    cb({"event": "start", "key": k})
                results[k] = {"fake": k}
                status[k] = "完成"
                if cb:
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": results[k]})
                if k == "gateway":
                    s.stop()                  # 第一项跑完 → 用户点停止
            return _run_dict(keys, results, status)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            s.start(keys=["gateway", "dns", "wifi"])
            self._wait(s)
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "cancelled")
        self.assertTrue(snap["has_report"], "取消后仍应出部分报告")
        # 未启动的模块留在网格里 (状态 None → 页面显示为空心「未测」)
        self.assertIn("wifi", snap["module_status"])
        self.assertIsNone(snap["module_status"]["wifi"])
        self.assertEqual(snap["done"], 1)
        self.assertEqual(snap["remaining"], 2)
        self.assertTrue(snap["stop_requested"])
        self.assertTrue(snap["cancelled"])

    # ── S3 取消后落盘 ──
    def test_cancelled_saves_resume_point(self):
        s = np._GuiSession()

        def _fake(keys, **kw):
            cb = kw.get("progress_cb")
            evt = kw.get("cancel_evt")
            results, status = {}, {}
            for k in keys:
                if evt is not None and evt.is_set():
                    break
                if cb:
                    cb({"event": "start", "key": k})
                results[k] = {"fake": k}
                status[k] = "完成"
                if cb:
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": results[k]})
                if k == "gateway":
                    s.stop()
            return _run_dict(keys, results, status)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            s.start(keys=["gateway", "dns"])
            self._wait(s)
        self.assertTrue(os.path.exists(self.resume_path))
        with open(self.resume_path, encoding="utf-8") as f:
            pt = json.load(f)
        self.assertEqual(sorted(pt["completed"]), ["gateway"])
        self.assertEqual(pt["keys"], ["gateway", "dns"])

    # ── S4c 一项都没测完就停: 不给假的「继续跑」入口 (终审审查 #4) ──
    def test_no_resume_entry_when_nothing_measured(self):
        s = np._GuiSession()

        def _fake(keys, **kw):
            s.stop()                 # 一项都没测完就点停止
            return _run_dict(keys, {}, {})

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            s.start(keys=["gateway", "dns"])
            self._wait(s)
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "cancelled")
        self.assertIn("还没测出任何结果", snap.get("error") or "")
        self.assertFalse(snap["can_resume"],
                         "没有续跑点 → 不给「继续跑」入口 (点了只会报错)")
        self.assertFalse(os.path.exists(self.resume_path),
                         "一项都没测完 → 不该写续跑点")

    # ── S4d 停止落在最后一个模块之后: 全测完了, 不给死入口 (终审审查 #3) ──
    def test_no_resume_entry_when_everything_done(self):
        s = np._GuiSession()

        def _fake(keys, **kw):
            cb = kw.get("progress_cb")
            results, status = {}, {}
            for k in keys:
                results[k] = {"fake": k}
                status[k] = "完成"
                if cb:
                    cb({"event": "start", "key": k})
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": results[k]})
            s.stop()                 # 全跑完之后才点停止
            return _run_dict(keys, results, status)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            s.start(keys=["gateway", "dns"])
            self._wait(s)
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "cancelled")
        self.assertEqual(snap["remaining"], 0)
        self.assertFalse(snap["can_resume"],
                         "全测完了 → 不给「继续跑剩下的 0 项」这种死入口")
        self.assertFalse(os.path.exists(self.resume_path),
                         "全测完了 → 没有可续的, 不写续跑点 (主页横幅不该"
                         "写「没跑完 · 实测 2/2 项」)")

    # ── S4b 落盘失败: 要提示, 但报告与导出照常 (spec 风险表) ──
    def test_resume_save_failure_is_reported_but_report_intact(self):
        s = np._GuiSession()

        def _fake(keys, **kw):
            cb = kw.get("progress_cb")
            evt = kw.get("cancel_evt")
            results, status = {}, {}
            for k in keys:
                if evt is not None and evt.is_set():
                    break
                if cb:
                    cb({"event": "start", "key": k})
                results[k] = {"fake": k}
                status[k] = "完成"
                if cb:
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": results[k]})
                if k == "gateway":
                    s.stop()
            return _run_dict(keys, results, status)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake), \
                mock.patch.object(np, "_gui_resume_save",
                                  return_value=(False, "续跑点保存失败（磁盘满）")):
            s.start(keys=["gateway", "dns"])
            self._wait(s)
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "cancelled")
        self.assertTrue(snap["has_report"], "落盘失败不该影响当轮报告")
        self.assertIn("续跑点保存失败", snap["resume_error"],
                      "落盘失败必须提示给用户 (spec 风险表)")
        self.assertFalse(snap["can_resume"],
                         "续跑点没存下来 → 不给假的「继续跑」入口")
        self.assertFalse(os.path.exists(self.resume_path))

    # ── S4 正常跑完: 旧续跑点该不该删 ──
    # 口径 (spec 风险表): 「开始新一轮不立即删除旧点, 新一轮停止时覆盖」。
    # 所以**普通新一轮**跑完不动旧点; 只有**续跑轮次**跑完才清掉 (F3)。
    def test_normal_run_keeps_old_resume_point(self):
        np._gui_resume_save({"schema": 1, "keys": ["gateway"],
                             "completed": {"gateway": {"status": "完成",
                                                       "result": {"a": 1}}}})
        self.assertTrue(os.path.exists(self.resume_path))
        s = np._GuiSession()

        def _fake(keys, **kw):
            cb = kw.get("progress_cb")
            for k in keys:
                if cb:
                    cb({"event": "start", "key": k})
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": {"fake": k}})
            return _run_dict(keys)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            s.start(keys=["gateway"])
            self._wait(s)
        self.assertEqual(s.snapshot()["phase"], "done")
        self.assertTrue(os.path.exists(self.resume_path),
                        "普通新一轮跑完不该删旧续跑点 (spec 风险表)")

    def test_finished_resume_discards_resume_point(self):
        s = np._GuiSession()
        point = {"schema": 1, "saved_at": "2026-11-13T15:30:00",
                 "saved_at_ts": time.time(), "profile": "slow",
                 "label": "网络很慢", "keys": ["gateway", "dns"],
                 "completed": {"gateway": {"status": "完成",
                                           "result": {"fake": "gateway"}}},
                 "duration_ms": 1234, "total_modules": 2}
        with open(self.resume_path, "w", encoding="utf-8") as f:
            json.dump(point, f, ensure_ascii=False)

        def _fake(keys, **kw):
            cb = kw.get("progress_cb")
            for k in keys:
                if cb:
                    cb({"event": "start", "key": k})
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": {"fake": k}})
            return _run_dict(keys)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            ok, err = s.start_resume()
            self.assertTrue(ok, err)
            self._wait(s)
        self.assertEqual(s.snapshot()["phase"], "done")
        self.assertFalse(os.path.exists(self.resume_path),
                         "续跑跑完后续跑点要删掉 (主页别再提示「上次没跑完」)")


class TestGuiSessionResume(_SessionCase):

    def _write_point(self, completed=None, keys=("gateway", "dns", "wifi")):
        payload = {
            "schema": 1, "saved_at": "2026-11-13T15:30:00",
            "saved_at_ts": time.time(), "profile": "slow",
            "label": "网络很慢", "keys": list(keys),
            "completed": completed if completed is not None else {
                "gateway": {"status": "完成", "result": {"fake": "gateway"}}},
            "duration_ms": 1234, "total_modules": len(np.MODULE_MAP),
        }
        with open(self.resume_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

    # ── S5 续跑 ──
    def test_resume_without_point_refused(self):
        s = np._GuiSession()
        ok, err = s.start_resume()
        self.assertFalse(ok)
        self.assertTrue(err)

    def test_resume_runs_only_remaining(self):
        self._write_point()
        s = np._GuiSession()
        seen = {}

        def _fake(keys, **kw):
            seen["keys"] = list(keys)
            cb = kw.get("progress_cb")
            for k in keys:
                if cb:
                    cb({"event": "start", "key": k})
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": {"fake": k}})
            return _run_dict(keys)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            ok, err = s.start_resume()
            self.assertTrue(ok, err)
            self._wait(s)
        # 只跑没测过的那两项
        self.assertEqual(seen["keys"], ["dns", "wifi"])
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "done")
        self.assertEqual(snap["done"], 3, "复用的 1 项 + 新跑的 2 项 = 3")
        self.assertEqual(snap["reused"], 1)
        self.assertTrue(snap["has_report"])
        # 标题带「（续跑）」(导出文件名同源)
        self.assertIn("（续跑）", snap["label"])
        # 续跑点跑完即清
        self.assertFalse(os.path.exists(self.resume_path))

    def test_resume_report_keeps_reused_results(self):
        self._write_point()
        s = np._GuiSession()
        captured = {}

        def _fake(keys, **kw):
            cb = kw.get("progress_cb")
            for k in keys:
                if cb:
                    cb({"event": "start", "key": k})
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": {"fake": k}})
            return _run_dict(keys)

        real_build = np.build_report

        def _spy(*a, **k):
            captured["run"] = k.get("run")
            captured["note"] = k.get("note")
            return real_build(*a, **k)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake), \
             mock.patch.object(np, "build_report", side_effect=_spy):
            s.start_resume()
            self._wait(s)
        merged = captured.get("run") or {}
        # 复用的项目数据原样还在
        self.assertEqual(merged.get("results", {}).get("gateway"),
                         {"fake": "gateway"})
        self.assertEqual(sorted(merged.get("keys") or []),
                         ["dns", "gateway", "wifi"])
        self.assertTrue((captured.get("note") or "").startswith("本轮为续跑"))


class TestGuiMergeRuns(unittest.TestCase):

    # ── S6 合并口径 ──
    def test_merge_keeps_full_key_set(self):
        ctx = {"keys": ["gateway", "dns", "wifi"],
               "completed": {"gateway": {"status": "完成",
                                         "result": {"a": 1}}},
               "duration_ms": 1000}
        new = _run_dict(["dns", "wifi"], duration=2000)
        merged = np._gui_merge_runs(ctx, new)
        self.assertEqual(sorted(merged["keys"]), ["dns", "gateway", "wifi"])
        self.assertEqual(sorted(merged["results"]), ["dns", "gateway", "wifi"])
        self.assertEqual(merged["results"]["gateway"], {"a": 1})
        self.assertEqual(merged["status"]["gateway"], "完成")
        self.assertEqual(merged["duration_ms"], 3000)

    def test_merge_strips_transient_evidence_key(self):
        ctx = {"keys": ["gateway"], "completed": {}, "duration_ms": 0}
        new = _run_dict(["gateway"],
                        results={"gateway": {"x": 1, "_evidence": [{"id": "e1"}]}})
        merged = np._gui_merge_runs(ctx, new)
        self.assertNotIn("_evidence", merged["results"]["gateway"])
        self.assertIn("gateway", merged["evidence"])


if __name__ == "__main__":
    unittest.main()
