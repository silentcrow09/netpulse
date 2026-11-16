# -*- coding: utf-8 -*-
"""Logo 方案总览图生成器（开发期工具，非运行时依赖）。

用 Pillow 按与 4 份 SVG 稿完全相同的几何重绘，产出 preview.png。
为什么不用浏览器截图：本环境的 headless Chrome 静默退出；且项目落地路径
(tests/_make_favicon.py) 本来就是 Pillow 逐帧重绘 —— 这里同时也是一次
「这套图形能不能用 Pillow 画出来」的可落地性验证。

用法: py design_ref/logo/_preview_render.py
"""
import os
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "preview.png")
NAVY = (10, 59, 110, 255)
INK = (11, 37, 69, 255)
BLUE = (22, 104, 201, 255)
GREEN = (34, 197, 94, 255)
CYAN = (125, 211, 252, 255)
WHITE = (255, 255, 255, 255)
SS = 4


def q(v, s):
    return round(v / 256 * s)


def _canvas(size, fill):
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    return img, ImageDraw.Draw(img), s


def _finish(img, size):
    return img.resize((size, size), Image.LANCZOS)


def _plate(d, s, color):
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=q(56, s), fill=color)


def _stroke(d, s, pts, width, color):
    p = [(q(x, s), q(y, s)) for x, y in pts]
    w = max(2, q(width, s))
    d.line(p, fill=color, width=w, joint="curve")
    r = w / 2.0
    for x, y in p:
        d.ellipse([x - r, y - r, x + r, y + r], fill=color)


def _dot(d, s, cx, cy, r, color):
    rr = q(r, s)
    x, y = q(cx, s), q(cy, s)
    d.ellipse([x - rr, y - rr, x + rr, y + rr], fill=color)


def icon_a(size):
    img, d, s = _canvas(size, None)
    _plate(d, s, NAVY)
    _stroke(d, s, [(44, 128), (88, 128), (108, 76), (134, 180),
                   (154, 112), (168, 128), (212, 128)], 14, WHITE)
    return _finish(img, size)


def icon_b(size):
    img, d, s = _canvas(size, None)
    _plate(d, s, BLUE)
    for r, alpha in ((40, 0.95), (72, 0.62), (104, 0.34)):
        box = [q(96 - r, s), q(128 - r, s), q(96 + r, s), q(128 + r, s)]
        d.arc(box, start=-50, end=50, fill=(255, 255, 255, round(255 * alpha)),
              width=q(13, s))
    _dot(d, s, 96, 128, 15, WHITE)
    _dot(d, s, 96, 128, 6, CYAN)
    return _finish(img, size)


def icon_c(size):
    img, d, s = _canvas(size, None)
    _plate(d, s, INK)
    box = [q(52, s), q(52, s), q(204, s), q(204, s)]
    w = q(16, s)
    d.arc(box, start=135, end=405, fill=(255, 255, 255, 46), width=w)
    d.arc(box, start=135, end=337.5, fill=GREEN, width=w)
    _dot(d, s, 198, 99, 11, WHITE)
    _stroke(d, s, [(100, 130), (120, 150), (158, 106)], 16, WHITE)
    return _finish(img, size)


def icon_d(size):
    img, d, s = _canvas(size, None)
    d.rounded_rectangle([q(52, s), q(44, s), q(74, s), q(196, s)],
                        radius=q(11, s), fill=NAVY)
    d.rounded_rectangle([q(182, s), q(44, s), q(204, s), q(196, s)],
                        radius=q(11, s), fill=NAVY)
    _stroke(d, s, [(74, 44), (182, 196)], 22, NAVY)
    _stroke(d, s, [(28, 218), (92, 218), (108, 200), (128, 236),
                   (146, 210), (160, 218), (228, 218)], 9, BLUE)
    return _finish(img, size)


def font(px):
    for path in ("C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/simhei.ttf"):
        if os.path.exists(path):
            return ImageFont.truetype(path, px)
    return ImageFont.load_default()


LABELS = [
    ("A", "脉搏基线", "极简线性 · 现状延续", icon_a),
    ("B", "回波雷达", "几何信号 · 一眼是网络", icon_b),
    ("C", "结论仪表", "工程仪表 · 结论先行", icon_c),
    ("D", "N 字标", "品牌字标 · 对外物料", icon_d),
]


def main():
    W, H = 1200, 580
    img = Image.new("RGB", (W, H), (244, 247, 251))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 78], fill=NAVY)
    d.text((36, 16), "NetPulse  ·  图标 / Logo 方案", font=font(25), fill=WHITE[:3])
    d.text((36, 50), "四套不同的图形语言  |  品牌色 #0A3B6E  |  16px 任务栏可辨 · 单色可印",
           font=font(13), fill=(201, 219, 239))

    f_letter, f_name, f_desc, f_small = font(16), font(20), font(13), font(12)
    col_w, x0 = 282, 24
    notes_by = {
        "A": ["线宽钳底 2px · 16px 表现：优", "只改 PULSE 点列，落地改动最小"],
        "B": ["小尺寸留 2 弧 · 16px 表现：良", "render 改弧线，按档简化"],
        "C": ["需独立简化版 · 16px 表现：中", "弧 + 对勾，三档尺寸分别重绘"],
        "D": ["不建议做任务栏 · 16px 表现：弱", "字标用于报告页眉 / 宣传片"],
    }
    for i, (letter, name, desc, fn) in enumerate(LABELS):
        x = x0 + i * col_w
        d.rounded_rectangle([x, 96, x + col_w - 16, 510], radius=14,
                            fill=(255, 255, 255), outline=(220, 229, 240), width=1)
        d.rounded_rectangle([x + 18, 114, x + 46, 142], radius=7, fill=NAVY)
        d.text((x + 26, 118), letter, font=f_letter, fill=WHITE[:3])
        d.text((x + 56, 116), name, font=f_name, fill=(21, 34, 56))
        d.text((x + 18, 150), desc, font=f_desc, fill=(92, 107, 128))

        big = fn(152)
        plate = Image.new("RGB", (170, 170), (238, 243, 249))
        plate.paste(big, (9, 9), big)
        img.paste(plate, (x + 18, 172))

        sx = x + 18
        for sz in (48, 32, 24, 16):
            small = fn(sz)
            img.paste(small, (sx, 392 - sz), small)
            d.text((sx, 400), str(sz), font=f_small, fill=(92, 107, 128))
            sx += max(sz, 24) + 22

        d.line([x + 18, 424, x + col_w - 34, 424], fill=(220, 229, 240), width=1)
        for k, line in enumerate(notes_by[letter]):
            d.text((x + 18, 440 + k * 26), "· " + line, font=f_desc,
                   fill=(92, 107, 128))

    d.text((24, 536), "选型稿，未改动运行时代码。完整对比、组合标与落地步骤见 logo_proposals.html",
           font=f_desc, fill=(92, 107, 128))
    img.save(OUT)
    print("已生成", OUT, img.size)


if __name__ == "__main__":
    main()
