# -*- coding: utf-8 -*-
"""NetPulse GUI favicon 生成器 (v1.26.4, 开发期工具)。

画一枚与页面顶栏 ``.g-mark`` 同品牌的图标: navy (#0a3b6e) 圆角方块 +
白色脉搏波形 (NetPulse = 网络脉搏, 心电式折线)。输出多尺寸 PNG-in-ICO
并打印 base64 —— 整体替换 netpulse.py 里的 ``_FAVICON_B64`` 常量
(单文件零外链约定: 页面用 data URI, 浏览器不发任何网络请求)。

用法:
    py tests/_make_favicon.py              # 打印 base64 (Python 字面量, 可直接粘贴)
    py tests/_make_favicon.py --embed      # 直接刷新 netpulse.py 里的 _FAVICON_B64
    py tests/_make_favicon.py --out x.ico  # 另存 .ico 文件 (调试用)

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

# 品牌色: 与 _GUI_CSS 的 --navy 严格一致 (改 CSS 时同步改这里并重跑)
NAVY = (10, 59, 110, 255)        # #0a3b6e
WHITE = (255, 255, 255, 255)

# ICO 帧尺寸链: 16/32 任务栏与标题栏, 24 小任务栏, 48/64 资源管理器,
# 128/256 Alt-Tab 与高 DPI。每帧按几何独立重绘 (非位图缩放), 小尺寸不糊。
SIZES = [16, 24, 32, 48, 64, 128, 256]

# 脉搏折线 (24x24 网格): 平线 → 上冲 → 下探 → 回中 → 平线, 心电波形。
PULSE = [(2.5, 12), (7, 12), (9.2, 6.8), (11.6, 17.2), (13.8, 10.6),
         (15.2, 12), (21.5, 12)]

# 圆角比例对齐顶栏 .g-mark (radius 8px / 边 30px)
_CORNER = 8.0 / 30.0
# 超采样倍数 (Pillow 无抗锯齿, 4x 画再缩)
_SS = 4


def _pulse_width(size):
    """折线宽 (px): 24 网格里 1.8 单位 ≈ 7.5%; 小尺寸钳底 2px 保可辨。"""
    return max(2, round(size * 1.8 / 24))


def render(size):
    """画一帧: navy 圆角方块底 + 白色脉搏折线 (圆端点/圆拐点)。"""
    s = size * _SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=round(s * _CORNER),
                        fill=NAVY)
    w = _pulse_width(size) * _SS
    pts = [(round(x / 24 * s), round(y / 24 * s)) for x, y in PULSE]
    d.line(pts, fill=WHITE, width=w, joint="curve")
    r = w / 2.0
    for px, py in pts:   # 端点与拐点补圆 → linecap/linejoin round 效果
        d.ellipse([px - r, py - r, px + r, py + r], fill=WHITE)
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
        "# ── favicon (v1.26.4): 顶栏 .g-mark 同品牌图标, 多尺寸 PNG-in-ICO ──",
        "# 生成: py tests/_make_favicon.py --embed (改图标后重跑自动刷新本常量)",
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
