# -*- coding: utf-8 -*-
"""NetPulse favicon / EXE 图标生成器 (C 方案「结论仪表」, 开发期工具)。

画一枚「结论仪表」图标: 墨蓝 (#0b2545) 圆角方块 + 270° 仪表环,
达标段为绿弧 (#22c55e), 环内白色对勾 —— 对应产品灵魂「结论先行」,
而不是只丢一堆指标。与页面顶栏 .g-mark、EXE 图标同源。

输出: 7 尺寸 PNG-in-ICO (16/24/32/48/64/128/256, 每帧按几何独立重绘),
--embed 刷新 netpulse.py 的 _FAVICON_B64 (data URI, 零外链),
--out 另存 .ico 供 PyInstaller 的 EXE(icon=...) 使用。

小尺寸不是等比缩放: 16/24 帧换成放大版几何 (更粗的对勾 + 更外扩的绿弧),
并去掉会糊成一片的底环和末端白点 —— 这是 C 方案选型时明确记下的代价,
也是它跟 A/B 方案在落地工作量上的差别。

用法:
    py tests/_make_favicon.py                    # 打印 base64 (Python 字面量)
    py tests/_make_favicon.py --embed            # 刷新 netpulse.py 的 _FAVICON_B64
    py tests/_make_favicon.py --out netpulse.ico # 另存 EXE 图标

自校验: 保存后重新打开 ICO, 断言帧尺寸集合完整, 不达标直接非零退出。
"""
import base64
import io
import os
import re
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PIL import Image, ImageDraw  # noqa: E402

# 品牌色 (C 方案): 墨蓝底比 GUI 的 --navy #0a3b6e 更深, 让绿弧/白勾更跳;
# 未达标段用【实色】而不是半透明白 —— PNG-in-ICO 里半透明像素在深浅背景下
# 表现不一致, 实色等价于「白 18% 混墨蓝」。
INK = (11, 37, 69, 255)          # #0b2545 圆角方块
TRACK = (55, 76, 102, 255)       # 仪表环未达标段
GREEN = (34, 197, 94, 255)       # #22c55e 达标段
WHITE = (255, 255, 255, 255)

# ICO 帧尺寸链: 16/32 任务栏与标题栏, 24 小任务栏, 48/64 资源管理器,
# 128/256 Alt-Tab 与高 DPI。每帧按几何独立重绘 (非位图缩放), 小尺寸不糊。
SIZES = [16, 24, 32, 48, 64, 128, 256]

# 几何基于 256x256 网格, 与 design_ref/logo/C_verdict-gauge.svg 同一套坐标。
# 圆角 56/256 对齐顶栏 .g-mark 内联 SVG 的圆角。
_CORNER = 56.0 / 256.0
# 超采样倍数 (Pillow 无抗锯齿, 4x 画再缩)
_SS = 4

# 仪表环 (圆心 128,128 / r=76) 与对勾 (256 网格)
_RING_BOX = (52, 52, 204, 204)
_CHECK = [(100, 130), (120, 150), (158, 106)]
# 16/24 帧专用: 放大到接近满画布, 只留绿弧 + 对勾
_SMALL_RING_BOX = (28, 28, 228, 228)
_SMALL_CHECK = [(78, 132), (112, 164), (178, 96)]


def q(v, s):
    """256 网格坐标 → 当前超采样画布坐标。"""
    return round(v / 256 * s)


def _stroke(d, s, pts, width, color, floor=2):
    """折线 + 端点/拐点补圆 (round linecap / linejoin 效果)。"""
    p = [(q(x, s), q(y, s)) for x, y in pts]
    w = max(floor, q(width, s))
    d.line(p, fill=color, width=w, joint="curve")
    r = w / 2.0
    for x, y in p:
        d.ellipse([x - r, y - r, x + r, y + r], fill=color)


def _dot(d, s, cx, cy, r, color):
    rr = q(r, s)
    x, y = q(cx, s), q(cy, s)
    d.ellipse([x - rr, y - rr, x + rr, y + rr], fill=color)


def render(size):
    """画一帧: 墨蓝圆角方块 + 270° 仪表环 + 达标绿弧 + 白色对勾。

    三档几何 (不是缩放):
      <=24 : 放大版绿弧 + 放大版对勾, 无底环、无末端点 (16px 仍可辨)
      32/48: 标准环 + 对勾, 去掉末端白点
      >=64 : 完整稿, 补绿弧末端白色圆点
    """
    s = size * _SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, s - 1, s - 1],
                        radius=round(s * _CORNER), fill=INK)
    if size <= 24:
        box = [q(v, s) for v in _SMALL_RING_BOX]
        d.arc(box, start=140, end=330, fill=GREEN,
              width=max(3, q(30, s)))
        _stroke(d, s, _SMALL_CHECK, 32, WHITE, floor=3)
    else:
        box = [q(v, s) for v in _RING_BOX]
        w = max(2, q(16, s))
        d.arc(box, start=135, end=405, fill=TRACK, width=w)
        d.arc(box, start=135, end=337.5, fill=GREEN, width=w)
        _stroke(d, s, _CHECK, 16, WHITE, floor=2)
        if size >= 64:
            _dot(d, s, 198, 99, 11, WHITE)
    return img.resize((size, size), Image.LANCZOS)


def build_ico_bytes():
    """合成多尺寸 ICO, 返回 (bytes, 帧尺寸列表)。"""
    frames = [render(s) for s in SIZES]
    buf = io.BytesIO()
    # 注意: Pillow ICO 保存以【源图尺寸】为帧上限 (比源图大的尺寸一律跳过),
    # 因此 .save() 必须调在最大帧 (256) 上, 其余帧走 append_images 精确提供。
    frames[-1].save(buf, format="ICO",
                    sizes=[(s, s) for s in SIZES],
                    append_images=frames[:-1])
    return buf.getvalue(), SIZES


def verify(ico_bytes, expect):
    """读回 ICO, 断言帧集合完整 (生成器自校验, 假产物不出门)。"""
    from PIL import IcoImagePlugin
    im = IcoImagePlugin.IcoImageFile(io.BytesIO(ico_bytes))
    got = sorted(im.ico.sizes())
    want = sorted((s, s) for s in expect)
    assert got == want, "ICO 帧集合不符: got=%s want=%s" % (got, want)


def b64_literal(ico_bytes):
    """产出可粘贴的 Python 字面量文本 (_FAVICON_B64 = (...))。"""
    b64 = base64.b64encode(ico_bytes).decode("ascii")
    lines = ['    "%s"' % seg for seg in textwrap.wrap(b64, 96)]
    return "_FAVICON_B64 = (\n" + "\n".join(lines) + "\n)"


def embed(path):
    """把常量嵌入源文件: 已有则整块替换, 没有则插到 _gui_page() 定义之前。

    保留原文件行尾 (工作区 CRLF / index LF 由 git autocrlf 处理)。
    """
    raw = open(path, "rb").read().decode("utf-8")
    eol = "\r\n" if "\r\n" in raw else "\n"
    literal = b64_literal(build_ico_bytes()[0]).replace("\n", eol)
    header = eol.join([
        "# ── favicon: C 方案「结论仪表」图标, 7 尺寸 PNG-in-ICO ──",
        "# 生成: py tests/_make_favicon.py --embed (改图标后重跑自动刷新本常量)",
        "# 同源资产: 顶栏 .g-mark 内联 SVG / EXE 图标 netpulse.ico 均由本生成器几何派生。",
        "# 为什么内嵌 data URI: Chromium --app 窗口任务栏图标取页面 icon,",
        "# 无 icon 落默认文档图标; data URI 零网络请求, 守零外链契约。",
    ]) + eol
    pat = re.compile(r"_FAVICON_B64 = \(.*?\n\)", re.S)
    m = pat.search(raw)
    if m:
        new_raw = raw[:m.start()] + header + literal + raw[m.end():]
        action = "已替换既有 _FAVICON_B64"
    else:
        anchor = "def _gui_page():"
        i = raw.index(anchor)
        new_raw = raw[:i] + header + literal + eol + eol + raw[i:]
        action = "已插入 _FAVICON_B64"
    with open(path, "wb") as f:
        f.write(new_raw.encode("utf-8"))
    print("%s (%s, %d 字节 base64)" % (action, path, len(literal)))


def main():
    ico_bytes, sizes = build_ico_bytes()
    verify(ico_bytes, sizes)
    if "--embed" in sys.argv:
        embed(os.path.join(ROOT, "netpulse.py"))
        return
    out_path = None
    if "--out" in sys.argv:
        out_path = sys.argv[sys.argv.index("--out") + 1]
    if out_path:
        with open(out_path, "wb") as f:
            f.write(ico_bytes)
        print("# 已写出 %s (%d 字节)" % (out_path, len(ico_bytes)))
    print(b64_literal(ico_bytes))
    print("# ICO 总字节数: %d, 帧尺寸: %s" % (len(ico_bytes), sizes))


if __name__ == "__main__":
    main()
