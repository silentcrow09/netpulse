# -*- coding: utf-8 -*-
"""v1.15.2 审查 P2 · Npcap 安装器完整性 回归测试。

旧版实现 (审查前):
    url = "https://npcap.com/dist/npcap-1.80.exe"
    tmp = os.path.join(tempfile.gettempdir(), "npcap-install.exe")   # 固定文件名
    ok, msg = _download_file(url, tmp)
    subprocess.run([tmp, "/S"], ...)                                  # 管理员直接执行

缺陷 (两个, 都实测存在):
  1. 下载与执行之间**零校验** —— 无哈希、无签名。下载被截断 / 被劫持 /
     被同机其它进程替换, 都会**以管理员权限**照跑。
  2. **固定**临时文件名 → 同机其它进程可在下载完成、执行之前抢先替换该文件
     (TOCTOU)。且旧版装完从不清理, %TEMP%\\npcap-install.exe 长期残留。

修后:
  - 唯一临时目录 (tempfile.mkdtemp) + SHA256 基线钉死 (NPCAP_SHA256)
  - 基线不命中时退到 Authenticode 签名校验 (签名者须为 Nmap Software LLC)
  - 两者都不通过 → **拒绝执行**, 并给手动下载链接兜底
  - 装完即清临时目录

跑用: cd 到项目根目录, `py -3.13 tests/test_v1152_npcap_integrity.py`
"""
import contextlib
import hashlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402


_PAYLOAD = b"MZ\x90\x00 fake npcap installer payload"
_PAYLOAD_SHA = hashlib.sha256(_PAYLOAD).hexdigest()
_FAKE_URL = "https://npcap.com/dist/npcap-1.80.exe"


class _RunRecorder:
    """代替 subprocess.run, 分流「签名校验」与「执行安装器」两类调用。"""

    def __init__(self, sign_status="Valid",
                 subject="CN=Nmap Software LLC, O=Nmap Software LLC, L=Beaverton, C=US"):
        self.calls = []          # [(argv, kwargs)]
        self.sign_status = sign_status
        self.subject = subject

    def __call__(self, argv, **kw):
        argv = list(argv) if isinstance(argv, (list, tuple)) else [str(argv)]
        self.calls.append((argv, kw))
        head = str(argv[0]).lower() if argv else ""
        base = os.path.basename(head).split(".")[0]
        if base in ("powershell", "pwsh"):
            out = "STATUS=%s\n" % self.sign_status
            if self.sign_status.lower() == "valid":
                out += "SUBJECT=%s\n" % self.subject
            return mock.Mock(returncode=0, stdout=out, stderr="")
        # 执行安装器 (真实场景是 .exe)
        return mock.Mock(returncode=0, stdout="", stderr="")

    @property
    def installer_calls(self):
        return [a for a, _ in self.calls if a and str(a[0]).lower().endswith(".exe")]

    @property
    def sign_calls(self):
        out = []
        for a, kw in self.calls:
            if not a:
                continue
            base = os.path.basename(str(a[0]).lower()).split(".")[0]
            if base in ("powershell", "pwsh"):
                out.append((a, kw))
        return out


class TestNpcapInstallIntegrity(unittest.TestCase):
    """Npcap 安装器: 校验不通过就不许执行。"""

    def _install(self, recorder, payload=_PAYLOAD, sha_value=None, is_admin=True,
                 download_ok=True):
        """跑一次 _install_npcap, 返回 (返回值, 下载目标路径列表, recorder)。"""
        dests = []

        def _fake_download(url, dest, timeout=180):
            dests.append(dest)
            if not download_ok:
                return False, "下载失败: 模拟"
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(payload)
            return True, ""

        patches = [
            mock.patch.object(N, "_npcap_installed", return_value=False),
            mock.patch.object(N, "_is_admin", return_value=is_admin),
            mock.patch.object(N, "_download_file", side_effect=_fake_download),
            mock.patch("netpulse.subprocess.run", side_effect=recorder),
        ]
        # NPCAP_SHA256 只在新版存在; 旧版没有哈希校验, 补丁与否都不影响其行为
        if sha_value is not None and hasattr(N, "NPCAP_SHA256"):
            patches.append(mock.patch.object(N, "NPCAP_SHA256", sha_value))

        buf = io.StringIO()
        with contextlib.ExitStack() as st:
            for p in patches:
                st.enter_context(p)
            with contextlib.redirect_stdout(buf):
                ret = N._install_npcap()
        return ret, dests, buf.getvalue()

    # ── 闸门 1: 哈希不符且签名无效 → 绝不执行安装器 ──
    def test_hash_mismatch_and_bad_signature_blocks_execution(self):
        """旧版: 无论下载到什么, 直接执行 → 本用例在旧代码上红。"""
        rec = _RunRecorder(sign_status="NotSigned")
        ret, dests, _ = self._install(rec, sha_value="0" * 64)
        self.assertFalse(ret[0], "校验未通过时必须返回失败")
        self.assertEqual([], rec.installer_calls,
                         "哈希与签名都不通过时**不得执行**下载到的安装器")
        self.assertTrue(dests, "应当尝试过下载")
        self.assertIn("npcap.com", ret[1])

    # ── 闸门 2: 哈希不符但签名有效 → 必须走过签名校验才放行 ──
    def test_hash_mismatch_valid_signature_still_installs(self):
        """厂商换版本是合法的: 签名有效即可放行, 但**必须**走签名校验。"""
        rec = _RunRecorder(sign_status="Valid")
        ret, dests, out = self._install(rec, sha_value="0" * 64)
        self.assertTrue(ret[0], "签名有效时应放行安装")
        self.assertEqual(1, len(rec.installer_calls), "签名有效后应执行安装器")
        self.assertTrue(rec.sign_calls,
                        "哈希不命中时必须做 Authenticode 签名校验 (旧版从不校验 → 红)")
        self.assertIn("已通过厂商签名校验", out)

    # ── 闸门 3: 临时路径必须唯一, 不能是固定文件名 ──
    def test_temp_path_is_unique_and_not_fixed_name(self):
        """旧版固定用 %TEMP%\\npcap-install.exe → 两次调用同一路径 → 红。"""
        rec1, rec2 = _RunRecorder(), _RunRecorder()
        _, dests1, _ = self._install(rec1, sha_value=_PAYLOAD_SHA)
        _, dests2, _ = self._install(rec2, sha_value=_PAYLOAD_SHA)
        self.assertEqual(1, len(dests1))
        self.assertEqual(1, len(dests2))
        self.assertNotEqual(dests1[0], dests2[0],
                            "两次安装必须用不同临时路径 (固定名可被同机进程替换 → TOCTOU)")
        fixed = os.path.join(tempfile.gettempdir(), "npcap-install.exe")
        self.assertNotEqual(fixed, dests1[0], "不得再使用固定临时文件名")
        self.assertNotEqual(fixed, dests2[0], "不得再使用固定临时文件名")

    # ── 闸门 4: 装完必须清理临时文件 (旧版从不清理) ──
    def test_temp_file_cleaned_after_install(self):
        rec = _RunRecorder()
        _, dests, _ = self._install(rec, sha_value=_PAYLOAD_SHA)
        self.assertFalse(os.path.exists(dests[0]),
                         "安装器临时文件用完必须删除 (旧版长期残留在 %TEMP%)")

    # ── 闸门 5: 签名校验不得把文件路径拼进命令行 ──
    def test_signature_check_does_not_interpolate_path(self):
        """路径经环境变量传给 PowerShell; 拼进命令行既是注入面也会被空格/引号搞炸。"""
        rec = _RunRecorder(sign_status="NotSigned")
        _, dests, _ = self._install(rec, sha_value="0" * 64)
        self.assertTrue(rec.sign_calls, "应调用过签名校验")
        for argv, kw in rec.sign_calls:
            joined = " ".join(str(x) for x in argv)
            self.assertNotIn(dests[0], joined,
                             "文件路径不得拼进命令行 (命令注入面)")
            env = kw.get("env") or {}
            self.assertEqual(dests[0], env.get("NP_SIGN_TARGET"),
                             "文件路径应经环境变量传给 PowerShell")

    # ── 闸门 6: 签名者不是 Nmap Software LLC → 拒绝 ──
    def test_untrusted_signer_is_rejected(self):
        rec = _RunRecorder(sign_status="Valid", subject="CN=Evil Corp, O=Evil Corp")
        ret, dests, _ = self._install(rec, sha_value="0" * 64)
        self.assertFalse(ret[0], "签名者不在白名单必须拒绝")
        self.assertEqual([], rec.installer_calls)

    # ── 正向回归: 哈希命中基线 → 直接执行, 不必起 PowerShell ──
    def test_hash_match_executes_without_signature_check(self):
        rec = _RunRecorder()
        ret, dests, _ = self._install(rec, sha_value=_PAYLOAD_SHA)
        self.assertTrue(ret[0], "哈希命中内置基线时应正常安装")
        self.assertEqual(1, len(rec.installer_calls))
        self.assertEqual([], rec.sign_calls, "哈希命中时不必再起 PowerShell 验签")
        self.assertTrue(rec.installer_calls[0][1], "应带 /S 静默参数")

    # ── 正向回归: 下载失败不执行 ──
    def test_download_failure_blocks_execution(self):
        rec = _RunRecorder()
        ret, dests, _ = self._install(rec, download_ok=False)
        self.assertFalse(ret[0])
        self.assertEqual([], rec.installer_calls)

    # ── 正向回归: 非管理员不下载不执行 ──
    def test_not_admin_does_not_download(self):
        rec = _RunRecorder()
        ret, dests, _ = self._install(rec, is_admin=False)
        self.assertFalse(ret[0])
        self.assertEqual([], dests, "非管理员不应触发下载")
        self.assertEqual([], rec.installer_calls)

    # ── 正向回归: 已安装时直接返回, 不重复下载 ──
    def test_already_installed_short_circuits(self):
        rec = _RunRecorder()
        with mock.patch.object(N, "_npcap_installed", return_value=True):
            ret = N._install_npcap()
        self.assertTrue(ret[0])
        self.assertEqual([], rec.calls, "已安装时不应有任何子进程调用")

    # ── 单元: SHA256 助手 ──
    def test_file_sha256_matches_hashlib(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.bin")
            with open(p, "wb") as f:
                f.write(_PAYLOAD)
            self.assertEqual(_PAYLOAD_SHA, N._file_sha256(p))
        self.assertIsNone(N._file_sha256(os.path.join(tempfile.gettempdir(),
                                                       "np-not-exist-xyz")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
