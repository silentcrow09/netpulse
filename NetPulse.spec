# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_all

# NETPULSE_ARCH=x86 (GitHub Actions / 手动) 时构建 32 位版:
# 产物 NetPulse_x86.exe, 不打包 speedtest.exe — Ookla 官方无 win32 版,
# 内置 HTTP 多连接测速不受影响, --speedtest-net 对照测速自动降级跳过
IS_X86 = os.environ.get('NETPULSE_ARCH', '') == 'x86'

datas = [] if IS_X86 else [('speedtest/speedtest.exe', 'speedtest')]
binaries = []
hiddenimports = ['scapy.all']
tmp_ret = collect_all('scapy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['netpulse.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['cryptography', 'tkinter'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NetPulse_x86' if IS_X86 else 'NetPulse',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
