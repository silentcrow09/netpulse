# design_ref/

设计稿跟踪与备查。**不是运行时依赖**——NetPulse 运行时不读这里的任何文件。

## 目录

```
design_ref/
├── README.md              本文件
├── gui/gui_design_v1.html      ← GUI 设计稿 (v1.21.0, 方案A 已选型)
├── logo/                       ← 品牌图标选型稿 (2026-11-16, C 方案已定案)
│   ├── C_verdict-gauge.svg     ← 选中稿 (运行时几何见 tests/_make_favicon.py)
│   ├── logo_proposals.html     ← 四套方案对比页 (自包含, 零外链)
│   ├── preview.png / frames_check.png
│   ├── _preview_render.py       ← Pillow 重绘工具 (预览图生成)
│   └── A/B/D_*.svg             ← 未采纳备选, 暂留存档
└── report_templates/
    ├── 模板D_现代仪表盘风.html    ← 已接入 (v1.14.10): 选项 6 一页客户报告
    └── assets/ct_logo_white.png     ← 同源 logo, 已被 netpulse.py 内嵌
```

## logo/ 选型记录

2026-11-16 评估了 4 套图形语言（A 线性脉搏 / B 回波雷达 / C 结论仪表 /
D N 字标），Simon 定案 **C**。运行时实现不在本目录：`tests/_make_favicon.py`
是几何唯一来源，`netpulse.py` 的 `_FAVICON_B64` / `_G_MARK_SVG` 与
`netpulse.ico` 都由它派生。未采纳的稿暂留作备选存档；需要清理时先确认范围，
别直接删。

## 模板 D 同步关系

`模板D_现代仪表盘风.html` 是**设计稿**，`netpulse.py` 里
`render_report_html_brief_v2` + `CSS_BRIEF_V2` 是**运行时实现**。

改模板 D 的视觉/数据结构 → **两边同步改**：
1. `design_ref/report_templates/模板D_现代仪表盘风.html`（手动）
2. `netpulse.py` 的 `CSS_BRIEF_V2` 字符串 + `render_report_html_brief_v2` 函数体

加新视觉块（栏目、组件）：先在设计稿里 mock 数据定型 → 再改 `netpulse.py` 注入对应字段。

## 何时该改 design_ref

- 调 UI 排版/颜色/字号：先改设计稿，肉眼确认后改代码
- 改数据契约：先在设计稿里把新字段画出来 → 改 `render_report_html_brief_v2`
  对应读取逻辑 + `MODULES_PRESENTATION` / `build_report()` 字段
- 接入新模板：从 `render_report_html_brief_v2` 复制接口约定 → 在 `netpulse.py`
  加 `render_report_html_brief_X` + 在 `export_report()` 加新 `layout` 路由

## 模板 D 怎么本地预览

```bash
"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless --no-sandbox \
  --window-size=794,2400 --hide-scrollbars --screenshot=preview.png \
  "file:///path/to/模板D_现代仪表盘风.html"
```

或直接双击 HTML 用 DevTools 改 CSS 实时看。

## 已删除的备选设计稿

**v1.14.10 接入前评估过 4 个备选风格**（检测机构评估 / IT 咨询顾问 / 装维验收单 / 现代仪表盘），
最终选用 D (现代仪表盘风) 作为选项 6 一页客户报告的实现。
A/B/C 设计稿随之删除——保留模板 D 风格 + 设计稿作为唯一参考。
如需重启备选，可从 git 历史（`git log -- design_ref/`）找回早期版本。