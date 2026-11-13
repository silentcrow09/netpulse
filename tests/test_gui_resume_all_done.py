# -*- coding: utf-8 -*-
"""「全测完的轮次」不写续跑点 (v1.24.0 终审复核波)。

背景 —— 复核发现的残留:
  最后一个模块刚测完、报告还没建好时关窗, 这一轮其实**全测完了**, 但关窗
  落盘会把「全测完」的点写进磁盘。下次打开主页, 横幅就写成「上次诊断没跑完 ·
  实检 N/N 项」自相矛盾; 点「接着跑」又只会得到一句「已经全测完了」——
  用户点了个寂寞, 页面还跳到一个空进度页。

  spec F4 明文: 「全都测完的轮次不写点（没有可续的）」;
  verify S4.5 明文: 「主页横幅不该出现『没跑完 · 实测 N/N 项』」。

验证点:
  A1 关窗落盘: 本轮全测完 → 磁盘上不留「全测完」的点
  A2 关窗落盘: 本轮没全测完 → 点照写 (别把关窗落盘改坏)
  A3 关窗落盘: 普通新一轮全测完 → **不删**磁盘上的旧续跑点
     (spec F4: 普通新一轮跑完不删旧点 —— 删了等于把上一轮已测完的成果抹掉)
  A4 关窗落盘: 续跑轮次全测完 → 来源点也全测完了 → 删掉 (没有可续的)
  A5 读点: 磁盘上「全测完」的点 → 当作没有 (返回 None, 顺手清掉垃圾文件)
  A6 读点: 没测完的点 → 照常读出来 (别误伤正常续跑点)
  A7 start_resume: 点全测完 → 明确拒绝 (不跑空轮次, 不把人送进空进度页)
  A8 主页横幅数据源: 全测完的点 → 摘要为 None (横幅不出现)
  A9 页面: 横幅渲染对 done>=total 兜底 (不给死入口)
"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import netpulse as np


def _point(keys, completed):
    return {
        "schema": 1, "saved_at": "2026-11-13T15:30:00",
        "saved_at_ts": time.time(), "profile": "slow",
        "label": "网络很慢", "keys": list(keys),
        "completed": completed,
        "duration_ms": 1234, "total_modules": len(np.MODULE_MAP),
    }


def _done(key):
    return {"status": "完成", "result": {"fake": key}}


def _run_dict(keys, results=None, status=None):
    return {"app": "NetPulse", "version": "1.24.0",
            "generated_at": __import__("datetime").datetime.now(),
            "system": {}, "status": status or {k: "完成" for k in keys},
            "results": results or {k: {"fake": k} for k in keys},
            "evidence": {}, "keys": list(keys), "duration_ms": 100,
            "total_modules": len(np.MODULE_MAP)}


class _AllDoneCase(unittest.TestCase):
    """公共装置: 隔离续跑点路径 + 清掉跨类型忙检。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="np_alldone_")
        self.resume_path = os.path.join(self.tmp, "resume.json")
        p1 = mock.patch.object(np, "_gui_resume_path",
                               return_value=self.resume_path)
        p1.start()
        self.addCleanup(p1.stop)
        p2 = mock.patch.object(np._GuiHandler, "session", None)
        p2.start()
        self.addCleanup(p2.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _write_point(self, payload):
        with open(self.resume_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

    def _read_point(self):
        if not os.path.exists(self.resume_path):
            return None
        with open(self.resume_path, encoding="utf-8") as f:
            return json.load(f)

    def _session(self, keys, done_keys, resume_ctx=None, phase="running"):
        """造一个「关窗那一刻」的会话状态。

        done_keys = 本轮已测完的项; _partial 里放它们的实测结果,
        _module_status 放状态 —— 与 on_progress 的 done 事件落的一致。
        """
        s = np._GuiSession()
        s._phase = phase
        s._profile = "slow"
        s._keys = list(keys)
        s._module_status = {k: None for k in keys}
        s._partial = {}
        for k in done_keys:
            s._module_status[k] = "完成"
            s._partial[k] = _done(k)
        s._resume_ctx = resume_ctx
        s._started_at = time.time() - 3
        return s


class TestAllDoneNoResumePoint(_AllDoneCase):

    # ── A1 本轮全测完 → 不写点 ──
    def test_all_done_round_writes_no_point(self):
        s = self._session(["gateway", "dns"], ["gateway", "dns"])
        err = s.save_resume_point_now()
        self.assertIsNone(err)
        self.assertFalse(os.path.exists(self.resume_path),
                         "全测完的轮次不该写续跑点 (spec F4「全都测完的轮次不写点」)")

    # ── A2 没全测完 → 点照写 ──
    def test_partial_round_still_writes_point(self):
        s = self._session(["gateway", "dns", "wifi"], ["gateway", "dns"])
        err = s.save_resume_point_now()
        self.assertIsNone(err)
        pt = self._read_point()
        self.assertIsNotNone(pt, "没测完的轮次关窗必须落盘 (spec F5 关窗不丢)")
        self.assertEqual(sorted(pt["completed"]), ["dns", "gateway"])
        self.assertEqual(sorted(pt["keys"]), ["dns", "gateway", "wifi"])

    # ── A3 普通新一轮全测完 → 不删旧点 ──
    def test_new_round_all_done_keeps_old_point(self):
        old = _point(["gateway", "dns"], {"gateway": _done("gateway")})
        self._write_point(old)
        s = self._session(["wifi", "tcpstats"], ["wifi", "tcpstats"])
        s.save_resume_point_now()
        pt = self._read_point()
        self.assertIsNotNone(pt, "普通新一轮跑完不删旧点 (spec F4)")
        self.assertEqual(sorted(pt["completed"]), ["gateway"])

    # ── A4 续跑轮次全测完 → 来源点删掉 ──
    def test_resume_round_all_done_discards_source_point(self):
        src = _point(["gateway", "dns"], {"gateway": _done("gateway")})
        self._write_point(src)
        s = self._session(["gateway", "dns"], ["gateway", "dns"],
                           resume_ctx=src)
        s.save_resume_point_now()
        self.assertFalse(os.path.exists(self.resume_path),
                         "续跑轮次全测完 → 来源点也没有可续的了, 该删")

    # ── A5 读点: 全测完的点当作没有 ──
    def test_all_done_point_ignored_on_load(self):
        self._write_point(_point(["gateway", "dns"],
                                  {"gateway": _done("gateway"),
                                   "dns": _done("dns")}))
        pt, err = np._gui_resume_load()
        self.assertIsNone(pt, "全测完的点没有可续的 → 当作没有")
        self.assertIn("全测完", err or "",
                      "要说明为什么续不了 (「接着跑」入口照实说, 不给死按钮)")
        self.assertFalse(os.path.exists(self.resume_path),
                         "顺手把这个垃圾点清掉 (别留着下回又说「没跑完」)")

    # ── A6 读点: 没测完的点照常读 ──
    def test_partial_point_still_loads(self):
        self._write_point(_point(["gateway", "dns"], {"gateway": _done("gateway")}))
        pt, err = np._gui_resume_load()
        self.assertIsNone(err)
        self.assertIsNotNone(pt)
        self.assertEqual(sorted(pt["completed"]), ["gateway"])

    # ── A7 start_resume 明确拒绝 ──
    def test_start_resume_refuses_all_done_point(self):
        self._write_point(_point(["gateway", "dns"],
                                  {"gateway": _done("gateway"),
                                   "dns": _done("dns")}))
        s = np._GuiSession()
        ok, err = s.start_resume()
        self.assertFalse(ok, "全测完的点不该开跑 (别跑空轮次)")
        self.assertTrue(err)
        self.assertIn("全测完", err)
        self.assertEqual(s.snapshot()["phase"], "idle",
                         "拒绝时不要把会话推进别的相位")

    # ── A8 主页横幅数据源为 None ──
    def test_home_banner_summary_none_for_all_done(self):
        self._write_point(_point(["gateway", "dns"],
                                  {"gateway": _done("gateway"),
                                   "dns": _done("dns")}))
        summary = np._gui_resume_summary(np._gui_resume_load()[0])
        self.assertIsNone(summary, "横幅数据源为 None → 页面不出现横幅")

    # ── A9 页面兜底: done>=total 不给死入口 ──
    def test_page_banner_hides_for_all_done(self):
        js = np._GUI_JS
        i = js.find("function renderResumeBanner")
        self.assertGreater(i, 0, "页面里找不到 renderResumeBanner")
        seg = js[i:i + 700]
        self.assertIn("r.done >= r.total", seg,
                      "横幅渲染要对「全测完」兜底 (verify S4.5)")

    # ── A10 停止路径全测完 → 旧点保留 (与关窗路径一致) ──
    def test_stop_path_all_done_keeps_old_point(self):
        old = _point(["gateway", "dns"], {"gateway": _done("gateway")})
        self._write_point(old)
        s = np._GuiSession()

        def _fake(keys, **kw):
            cb = kw.get("progress_cb")
            for k in keys:
                if cb:
                    cb({"event": "start", "key": k})
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": {"fake": k}})
            s.stop()                     # 全跑完之后才点停止
            return _run_dict(keys)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            s.start(keys=["wifi", "tcpstats"])
            s._thread.join(5)
        snap = s.snapshot()
        self.assertEqual(snap["phase"], "cancelled", snap["phase"])
        pt = self._read_point()
        self.assertIsNotNone(pt,
                             "停止路径与关窗落盘路径一致: 旧点保留 (别抹掉上一轮成果)")
        self.assertEqual(sorted(pt["completed"]), ["gateway"])

    # ── A11 停止路径 + 续跑轮次全测完 → 来源点删掉 ──
    def test_stop_path_resume_all_done_discards_source_point(self):
        src = _point(["gateway", "dns"], {"gateway": _done("gateway")})
        self._write_point(src)
        s = np._GuiSession()

        def _fake(keys, **kw):
            cb = kw.get("progress_cb")
            for k in keys:
                if cb:
                    cb({"event": "start", "key": k})
                    cb({"event": "done", "key": k, "status": "完成",
                        "result": {"fake": k}})
            s.stop()
            return _run_dict(keys)

        with mock.patch.object(np, "run_diagnostics", side_effect=_fake):
            ok, err = s.start_resume()
            self.assertTrue(ok, err)
            s._thread.join(5)
        self.assertFalse(os.path.exists(self.resume_path),
                         "续跑轮次全测完 → 来源点也没有可续的了, 该删")


if __name__ == "__main__":
    unittest.main()
