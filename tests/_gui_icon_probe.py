# -*- coding: utf-8 -*-
"""实测 Chromium --app 窗口的任务栏图标是否为 NetPulse favicon (C 方案)。

开发期工具: 起真 GUI 服务 → --app 拉真窗口 (独立临时 profile) →
EnumWindows 找 "NetPulse 网络诊断" → WM_GETICON / GetClassLongPtr 取 HICON →
GetIconInfo + GetDIBits 读像素 → 判定是否为品牌图标
(墨蓝 #0b2545 圆角方块 + 达标绿弧 + 白色对勾; 反之默认文档图标为灰白方角)。

判定标准 (PIXELS 段输出):
  - 四角 alpha=0 (圆角), 墨蓝主体占比 > 40%, 绿弧像素 > 0, 白勾像素 > 0
    → ICON-OK
  - 读不到彩色位图 / 不满足上述 → ICON-FAIL (附实测数值)

用法: py tests/_gui_icon_probe.py
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import tempfile
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

WM_GETICON = 0x7F
ICON_SMALL, ICON_BIG, ICON_SMALL2 = 0, 1, 2
GCLP_HICON, GCLP_HICONSM = 14, 34
INK = (11, 37, 69)            # C 方案底 #0b2545
TOL = 24


class ICONINFO(ctypes.Structure):
    _fields_ = [("fIcon", wt.BOOL), ("xHotspot", wt.DWORD),
                ("yHotspot", wt.DWORD), ("hbmMask", wt.HBITMAP),
                ("hbmColor", wt.HBITMAP)]


class BITMAP(ctypes.Structure):
    _fields_ = [("bmType", wt.LONG), ("bmWidth", wt.LONG),
                ("bmHeight", wt.LONG), ("bmWidthBytes", wt.LONG),
                ("bmPlanes", wt.WORD), ("bmBitsPixel", wt.WORD),
                ("bmBits", ctypes.c_void_p)]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG),
                ("biHeight", wt.LONG), ("biPlanes", wt.WORD),
                ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
                ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", wt.LONG),
                ("biYPelsPerMeter", wt.LONG), ("biClrUsed", wt.DWORD),
                ("biClrImportant", wt.DWORD)]


class RGBQUAD(ctypes.Structure):
    _fields_ = [("rgbBlue", ctypes.c_ubyte), ("rgbGreen", ctypes.c_ubyte),
                ("rgbRed", ctypes.c_ubyte), ("rgbReserved", ctypes.c_ubyte)]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER),
                ("bmiColors", RGBQUAD * 1)]


def _enum_windows():
    out = []
    cb_t = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def cb(hwnd, _):
        if ctypes.windll.user32.IsWindowVisible(hwnd):
            n = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
            if n > 0:
                buf = ctypes.create_unicode_buffer(n + 1)
                ctypes.windll.user32.GetWindowTextW(hwnd, buf, n + 1)
                out.append((hwnd, buf.value))
        return True

    ctypes.windll.user32.EnumWindows(cb_t(cb), 0)
    return out


def find_app_window(timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        for h, t in _enum_windows():
            if t.strip() == "NetPulse 网络诊断":
                return h
        time.sleep(0.5)
    return None


def icon_pixels(hwnd):
    """从窗口取 HICON (WM_GETICON 优先, 类图标兜底), 返回 (w, h, pixels BGRA)。"""
    u32, g32 = ctypes.windll.user32, ctypes.windll.gdi32
    # 64 位下 HWND/HICON/HBITMAP 都是指针宽度。ctypes 未声明 argtypes 时
    # 默认按 c_int (32 位) 传参, 句柄值 > 2^31-1 就 OverflowError —— 这是
    # 探针自身的老问题 (与图标内容无关), 高句柄机器上必崩。逐个声明原型。
    u32.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    u32.SendMessageW.restype = wt.LPARAM
    u32.GetClassLongPtrW.argtypes = [wt.HWND, ctypes.c_int]
    u32.GetClassLongPtrW.restype = ctypes.c_void_p
    u32.GetIconInfo.argtypes = [wt.HICON, ctypes.c_void_p]
    u32.GetIconInfo.restype = wt.BOOL
    u32.GetDC.argtypes = [wt.HWND]
    u32.GetDC.restype = wt.HDC
    u32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
    u32.ReleaseDC.restype = ctypes.c_int
    g32.GetObjectW.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p]
    g32.GetObjectW.restype = ctypes.c_int
    g32.GetDIBits.argtypes = [wt.HDC, wt.HBITMAP, wt.UINT, wt.UINT,
                              ctypes.c_void_p, ctypes.c_void_p, wt.UINT]
    g32.GetDIBits.restype = ctypes.c_int
    g32.DeleteObject.argtypes = [wt.HANDLE]
    g32.DeleteObject.restype = wt.BOOL
    hicon = u32.SendMessageW(hwnd, WM_GETICON, ICON_BIG, 0)
    src = "WM_GETICON BIG"
    if not hicon:
        hicon = u32.SendMessageW(hwnd, WM_GETICON, ICON_SMALL, 0)
        src = "WM_GETICON SMALL"
    if not hicon:
        hicon = u32.SendMessageW(hwnd, WM_GETICON, ICON_SMALL2, 0)
        src = "WM_GETICON SMALL2"
    if not hicon:
        hicon = u32.GetClassLongPtrW(hwnd, GCLP_HICONSM)
        src = "class HICONSM"
    if not hicon:
        hicon = u32.GetClassLongPtrW(hwnd, GCLP_HICON)
        src = "class HICON"
    if not hicon:
        return None, None, None, "no-icon"
    ii = ICONINFO()
    if not u32.GetIconInfo(hicon, ctypes.byref(ii)):
        return None, None, None, "GetIconInfo failed"
    bmp = BITMAP()
    if not g32.GetObjectW(ii.hbmColor, ctypes.sizeof(bmp),
                          ctypes.byref(bmp)):
        g32.DeleteObject(ii.hbmMask)
        if ii.hbmColor:
            g32.DeleteObject(ii.hbmColor)
        return None, None, None, "no color bitmap"
    w, h = bmp.bmWidth, bmp.bmHeight
    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = w
    bmi.bmiHeader.biHeight = -h          # 负高 = 自上而下
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = 0      # BI_RGB
    buf = ctypes.create_string_buffer(w * h * 4)
    hdc = u32.GetDC(0)
    got = g32.GetDIBits(hdc, ii.hbmColor, 0, h, buf, ctypes.byref(bmi), 0)
    u32.ReleaseDC(0, hdc)
    g32.DeleteObject(ii.hbmMask)
    g32.DeleteObject(ii.hbmColor)
    if not got:
        return None, None, None, "GetDIBits failed"
    return w, h, buf.raw, src


def judge(w, h, px):
    """判定像素是否为 C 方案图标: 墨蓝主体 + 达标绿弧 + 白对勾 + 透明圆角。"""
    ink = green = white = opaque = 0
    total = w * h
    corners_clear = 0
    pts = [(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)]
    for i in range(total):
        b, g, r, a = px[i * 4:i * 4 + 4]
        if a < 40:
            continue
        opaque += 1
        if abs(r - INK[0]) <= TOL and abs(g - INK[1]) <= TOL \
                and abs(b - INK[2]) <= TOL:
            ink += 1
        elif g > 140 and r < 100 and b < 150:      # 达标绿 #22c55e
            green += 1
        elif min(r, g, b) >= 200:                  # 白色对勾 / 末端点
            white += 1
    for x, y in pts:
        i = (y * w + x) * 4
        if px[i + 3] < 40:
            corners_clear += 1
    ink_ratio = ink / max(1, opaque)
    ok = (ink_ratio > 0.4 and green > 0 and white > 0
          and corners_clear >= 2 and opaque > total * 0.5)
    return ok, ("ink=%.2f green=%d white=%d corners=%d/4 opaque=%.2f "
                "size=%dx%d") % (ink_ratio, green, white, corners_clear,
                                 opaque / total, w, h)


def main():
    sys.path.insert(0, REPO)
    import netpulse as M
    session = M._GuiSession()
    monitor = M._GuiMonitor()
    evt = threading.Event()
    srv, port, token = M._start_gui_server(session, evt, monitor)
    url = "http://127.0.0.1:%d/?t=%s" % (port, token)
    ud = tempfile.mkdtemp(prefix="np_icon_probe_")
    proc = subprocess.Popen([CHROME, "--app=" + url,
                             "--window-size=1180,680",
                             "--user-data-dir=" + ud,
                             "--no-first-run", "--no-default-browser-check"])
    hwnd = find_app_window()
    if not hwnd:
        print("ICON-FAIL: 没找到窗口")
        proc.kill()
        srv.shutdown()
        return 1
    time.sleep(5.0)      # 等 favicon 加载并被 Chromium 应用为窗口图标
    w, h, px, src = icon_pixels(hwnd)
    if px is None:
        print("ICON-FAIL: %s" % src)
        rc = 1
    else:
        ok, detail = judge(w, h, px)
        print("PIXELS src=%s %s" % (src, detail))
        print("ICON-OK" if ok else "ICON-FAIL")
        rc = 0 if ok else 1
    proc.kill()
    srv.shutdown()
    srv.server_close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
