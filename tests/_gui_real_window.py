# -*- coding: utf-8 -*-
"""实测真实 Chromium --app 窗口的可用内容高度 (窗口外框 vs 客户区)。

开发期工具: 起真 GUI 服务 → 用 --app=URL --window-size=W,H 拉真窗口 →
EnumWindows 找标题含 "NetPulse 网络诊断" 的 HWND → GetClientRect 量客户区
(= 网页实际可见高度, 扣掉标题栏/边框), 同时 PrintWindow 存图。

用法: py -3.13 tests/_gui_real_window.py [W H]
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


def _enum_windows():
    out = []
    EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def cb(hwnd, _):
        if not ctypes.windll.user32.IsWindowVisible(hwnd):
            return True
        n = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        ctypes.windll.user32.GetWindowTextW(hwnd, buf, n + 1)
        out.append((hwnd, buf.value))
        return True

    ctypes.windll.user32.EnumWindows(EnumWindowsProc(cb), 0)
    return out


def _client_rect(hwnd):
    r = wt.RECT()
    ctypes.windll.user32.GetClientRect(hwnd, ctypes.byref(r))
    return (r.left, r.top, r.right, r.bottom)


def _window_rect(hwnd):
    r = wt.RECT()
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(r))
    return (r.left, r.top, r.right, r.bottom)


def main():
    W = int(sys.argv[1]) if len(sys.argv) > 1 else 1180
    H = int(sys.argv[2]) if len(sys.argv) > 2 else 680
    sys.path.insert(0, REPO)
    import netpulse as M
    session = M._GuiSession()
    monitor = M._GuiMonitor()
    evt = threading.Event()
    srv, port, token = M._start_gui_server(session, evt, monitor)
    url = "http://127.0.0.1:%d/?t=%s" % (port, token)
    ud = tempfile.mkdtemp(prefix="np_appwin_")
    proc = subprocess.Popen([CHROME, "--app=" + url,
                             "--window-size=%d,%d" % (W, H),
                             "--user-data-dir=" + ud,
                             "--no-first-run", "--no-default-browser-check"])
    hwnd = None
    t0 = time.time()
    while time.time() - t0 < 30:
        for h, t in _enum_windows():
            if t.strip() == "NetPulse 网络诊断":
                hwnd = h
                break
        if hwnd:
            break
        time.sleep(0.5)
    if not hwnd:
        print("没找到窗口")
        try:
            proc.kill()
        except Exception:
            pass
        return 1
    time.sleep(2.0)
    cl = _client_rect(hwnd)
    wr = _window_rect(hwnd)
    dpi = ctypes.windll.user32.GetDpiForWindow(hwnd)
    print("window rect  : %s (外框 %dx%d)" % (wr, wr[2] - wr[0], wr[3] - wr[1]))
    print("client rect  : %s (内容 %dx%d)" % (cl, cl[2] - cl[0], cl[3] - cl[1]))
    print("dpi          : %s" % dpi)
    print("title        : %s" % dict(_enum_windows()).get(hwnd))
    shot = os.path.join(REPO, "output", "np_real_window.png")
    os.makedirs(os.path.dirname(shot), exist_ok=True)
    hdc = ctypes.windll.user32.GetDC(hwnd)
    memdc = ctypes.windll.gdi32.CreateCompatibleDC(hdc)
    bmp = ctypes.windll.gdi32.CreateCompatibleBitmap(hdc, wr[2] - wr[0], wr[3] - wr[1])
    ctypes.windll.gdi32.SelectObject(memdc, bmp)
    ctypes.windll.user32.PrintWindow(hwnd, memdc, 2)
    ctypes.windll.gdi32.DeleteObject(bmp)
    ctypes.windll.gdi32.DeleteDC(memdc)
    ctypes.windll.user32.ReleaseDC(hwnd, hdc)
    print("screenshot   : (PrintWindow 未落盘, 略)")
    try:
        proc.kill()
    except Exception:
        pass
    evt.set()
    try:
        srv.shutdown()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
