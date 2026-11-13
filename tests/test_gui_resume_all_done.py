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
import threading
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

    # ── A5 读点: 全测完的点当作没有 (读路径零副作用, 不删文件) ──
    def test_all_done_point_ignored_on_load(self):
        self._write_point(_point(["gateway", "dns"],
                                  {"gateway": _done("gateway"),
                                   "dns": _done("dns")}))
        pt, err = np._gui_resume_load()
        self.assertIsNone(pt, "全测完的点没有可续的 → 当作没有")
        self.assertIn("全测完", err or "",
                      "要说明为什么续不了 (「接着跑」入口照实说, 不给死按钮)")
        # 读路径**不删文件** —— 删的瞬间若恰好有并发写点 (os.replace 原子替换),
        # 会把刚写好的新点删掉。清理交给「下一次落盘覆盖 / 7 天过期 / 重新开始」。
        self.assertTrue(os.path.exists(self.resume_path),
                        "读点不删文件 (读路径带删除副作用会误删并发写的新点)")

    # ── A12 读点过程中并发写的新点不被删 (锁住「读路径不删」这条) ──
    # 注: 本例锁的是「并发写点不丢」; 「读路径不删」的主闸是 A5 (本例对
    # 「复核读 + 删」那种写法不敏感 —— 复核恰好读到新点时不会删)。
    def test_concurrent_write_during_load_survives(self):
        self._write_point(_point(["gateway", "dns"],
                                  {"gateway": _done("gateway"),
                                   "dns": _done("dns")}))
        new_payload = _point(["wifi", "tcpstats"], {"wifi": _done("wifi")})
        real_clean = np._gui_resume_clean
        state = {"n": 0}

        def _clean(data):
            # 注入并发写点: 读完、判定之前, 另一线程写了个新点 (os.replace 原子替换)
            state["n"] += 1
            if state["n"] == 1:
                np._gui_resume_save(new_payload)
            return real_clean(data)

        with mock.patch.object(np, "_gui_resume_clean", side_effect=_clean):
            np._gui_resume_load()
        pt2, err2 = np._gui_resume_load()
        self.assertIsNone(err2, err2)
        self.assertIsNotNone(pt2, "并发写的新点被读点删掉了 (回归!)")
        self.assertEqual(sorted(pt2["completed"]), ["wifi"],
                         "并发写的新点内容要原样还在")

    # ── A13 Windows: os.replace 撞上占用 → 退避重试后成功 ──
    # 注: `np.os` 就是全局 `os` 模块, 这个 patch 在 with 块内会拦住进程内
    # **所有** os.replace 调用 (本仓库测试串行, 无实害, 但要知道这个影响面)。
    def test_save_retries_when_target_is_locked(self):
        real_replace = os.replace
        calls = {"n": 0}

        def _replace(src, dst):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise PermissionError(5, "拒绝访问")
            return real_replace(src, dst)

        payload = _point(["gateway", "dns"], {"gateway": _done("gateway")})
        with mock.patch.object(np.os, "replace", side_effect=_replace):
            ok, err = np._gui_resume_save(payload)
        self.assertTrue(ok, "目标被占用时应退避重试, 而不是直接判失败: %s" % err)
        self.assertEqual(calls["n"], 3, "应重试到成功为止")
        pt, _ = np._gui_resume_load()
        self.assertIsNotNone(pt)
        self.assertEqual(sorted(pt["completed"]), ["gateway"])

    # ── A14 并发落盘 → 续跑点仍是合法 JSON (成果不能被写坏) ──
    def test_concurrent_saves_keep_file_valid(self):
        """两条落盘路径可能并发 (用户点「停止」后立刻关窗)。

        修复前两条线程共用同一个 tmp 文件名, 各自以 "w" 打开它分多次写,
        内容互相串接 → 落盘文件不是合法 JSON → 读回时当损坏忽略 → 这一轮
        的成果静默丢失 (实测 60 轮里 31 轮损坏)。
        """
        p1 = _point(["gateway", "dns"], {"gateway": _done("gateway")})
        p2 = _point(["gateway", "dns", "wifi"],
                    {"gateway": _done("gateway"), "wifi": _done("wifi")})
        errors, bad = [], []
        for _ in range(20):
            barrier = threading.Barrier(2)

            def _save(p):
                barrier.wait(5)
                ok, err = np._gui_resume_save(p)
                if not ok:
                    errors.append(err)

            ts = [threading.Thread(target=_save, args=(p,))
                  for p in (p1, p2)]
            for t in ts:
                t.start()
            for t in ts:
                t.join(10)
            try:
                with open(self.resume_path, encoding="utf-8") as f:
                    doc = json.load(f)
                # 光是合法 JSON 不够 —— 内容也不能串味: 落盘的应是两条载荷之一
                keys = sorted((doc.get("completed") or {}).keys())
                if keys not in (["gateway"], ["gateway", "wifi"]):
                    bad.append("内容串味: %s" % keys)
            except Exception as e:
                bad.append(repr(e))
        self.assertEqual(bad, [],
                         "并发落盘把续跑点写坏了 (两条线程的内容串接在一起)")
        self.assertEqual(errors, [], "并发落盘不该报错: %s" % errors[:3])
        pt, err = np._gui_resume_load()
        self.assertIsNotNone(pt, "并发落盘后读不出续跑点: %s" % err)

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
