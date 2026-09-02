# NetPulse

单文件 Windows 网络诊断工具。**开发/验证约定见 [AGENTS.md](AGENTS.md)**（AI 协作者先读）。

当前处于**质量收口阶段**（v1.8.1 起），三条硬规则：

1. 冻结新增大 Probe（除非真实场景 + 有测试 + 有报告展示 + 有降级策略）
2. 停止新增 `LAST_RUN` 全局依赖（只减不增）
3. 新 Probe 直接产出原生 `DiagnosticResult`，不走 `_wrap_as_diagnostic_result` 旧包装

新功能合入前过一遍 AGENTS.md 的验收清单；HTML 转义铁律（`_html_esc` vs `_html_attr`）见
AGENTS.md「报告渲染」节。
