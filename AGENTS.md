# NetPulse 项目约定

## Git 环境

**当前工作区在 `D:\Work\Projects\NetPulse`，git 读写全部正常**，可直接 `add` / `commit` / `push`。

历史遗留：早期在 UNC 共享路径 `\\172.168.1.1\...` 上出现过 `fatal: unable to write new index file`。该路径目前不使用；若将来回到 UNC 路径，已知两个坑：

1. 提交类操作（写 `.git/index`）可能失败 → 只读操作可用，提交交给用户手动执行
2. `git push` 能成功推到远程，但本地 `origin/master` 跟踪引用可能不刷新（`packed-refs` 写入失败），
   导致 `git status -sb` 误报 `ahead N`。核对用 `git ls-remote origin master`，
   必要时手动写 loose ref：`printf '<sha>\n' > .git/refs/remotes/origin/master`

## 评分口径（改这里前务必看）

`compute_health_score(counts, text_counts=None)`：

- **扣分**：异常 -20 / 错误 -30 / 警告 -2 / **超时 -10** / 未检测 0
- 超时必须扣分：超时模块会被 `_issues_*` 登记成 `severity="异常"` 的 issue，
  若不扣分就会出现「23 个模块全超时 → 100 分 A 级"网络良好"」而报告其它位置说有问题的矛盾

## 两种计数口径并存（易踩坑）

| 口径 | 来源 | 数量 | 用途 |
|---|---|---|---|
| 扣分口径 | `report["counts"]` | 19 | 统计卡、健康分、信息条「扣分项」 |
| 全口径 | `report["summary"]` | 23 | 状态分布条、检测结果一览徽章 |

差值是 4 个评分豁免模块：`iperf3` / `ipv6` / `proxy` / `nattype`。
两者并排展示时界面上必须说明差异，否则看起来像算错。

## 状态与配色

状态语义键与配色的**唯一来源**是 `STATUS_KEY` / `STATUS_COLORS` / `STATUS_BAR_ORDER`，
不要在各渲染函数里另立映射（曾因三份映射并存出现过两种「警告橙」）。
`PROBLEM_STATUSES` 决定哪些状态会被标红 + 默认展开。

## 报告渲染

- `export_report` 只调用 `render_report_html_customer`（客户视图）
- `render_report_html`（技术视图）和 `render_report_text`（纯文本）**当前零调用点**，
  属于死代码；修改后不会被线上路径覆盖，启用前需自行验证
- 报告须**可离线打开**：全部用系统字体，不引入任何在线资源，图表用纯 SVG 手绘

## 验证

```bash
python _smoke_report.py          # 25 项断言: 图表/导航/折叠/打印/复制/超时扣分
```

产物 `reports/_verify_latest.html` 用于人工核对（`reports/` 已 gitignore）。

## 其它

- 打包：`build_exe.bat` 或 `build_exe.ps1` → `dist/NetPulse.exe`。
  改了 `netpulse.py` 后需重新打包，否则 exe 落后于代码
- 根目录 `nul` 是 Windows 保留设备名误产生的 54B 垃圾文件，
  常规删除方式（`rm` / PowerShell / Python）都会被解析成设备路径而失败，已在 `.gitignore` 忽略
- `_smoke_report.py`、`reports/`、`.codefree/`、`speedtest/` 均已 gitignore
