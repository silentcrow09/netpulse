# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

# v1.9.7 启动优化 PR-1 (打包瘦身):
#  - datas 不再打包 netpulse.py 源码 (Analysis 已将其冻结进 PYZ, 此前是重复 ~0.7MB)
#  - hiddenimports 删 tkinter (代码零使用, 白拖 ~3MB tcl/tk)
#  - excludes 屏蔽 cryptography (仅 scapy TLS 层需要; NetPulse 只用 ARP/DHCP/DNS/
#    ICMP/TCP, scapy 对缺失 cryptography 自动降级 — 已实测 scapy.all 可正常导入,
#    且导入耗时 1.11s -> 0.64s)
#  - upx 关闭 (UPX 解压发生在每次启动, 反向拖慢 onefile; 且是 Defender/SmartScreen
#    误报大户, 拉长冷启动扫描)
datas = [('speedtest/speedtest.exe', 'speedtest')]
binaries = []
hiddenimports = ['scapy.all']
excludes = ['cryptography', 'tkinter']
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
    excludes=excludes,
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
    name='NetPulse',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
