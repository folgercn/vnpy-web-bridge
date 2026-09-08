---
name: vnpy-runtime-check
description: 检查指定的 SIMNOW_LAB Windows、M2 或 Dashboard 服务状态、版本和数据时效；仅用于定向只读巡检。
---

# vnpy runtime check

用于回答“指定对象现在是否在运行、版本是什么、最近业务记录何时产生”。先确认对象仅为 Windows、M2 或 Dashboard；只检查用户指定的分支。

先读根 `AGENTS.md`；涉及 Dashboard、M2 one-shot 或 CD 时，读 `docs/simnow-lab-agent-contracts.md` 第 0.1、12 节。Lab 结果始终标为实验结果，不能表述为 production、audited 或正式前瞻业绩。

## Windows Lab

- 通过既有 `simnow_lab_get_run_v1("DASHBOARD")` 读取状态。该分支只读 SQLite，不触发 CTP、锁、订单/持仓查询或执行。
- 报告 `runtime_version`、最后 run、快照时间、`active_order_count`、`unknown_order_count` 与最近错误摘要。
- `UNKNOWN` 或 active orders 只报告并按现有 STOP 契约处理；不得重发、取消、生成 target，或调用 `run-once`、`apply`、`CURRENT`。
- 只查 Windows 时，到此停止；不得顺带访问 Docker、M2、Research、数据库或网络。

## M2 one-shot

- 仅在用户指定 M2 时，读取既有 `com.folgercn.simnow-lab` LaunchAgent 的状态和已生成日志/产物时间；不手动运行 one-shot。
- 不调用 `scripts/windows_simnow_lab/cli_v1.py run-once`，它会进入 `APPLY`；也不以 `CURRENT` 作为普通巡检入口。

## Dashboard Docker

- 仅在用户指定 Dashboard 时，检查 `control-api`、`frontend-edge` 的指定 Compose 状态、镜像/版本、重启次数和本地只读健康/API 响应。
- 服务健康只证明服务层；结合 Dashboard 的最近 run/快照和 active/UNKNOWN 记录说明业务观察，不把旧快照当作当前柜台无活动订单的证明。
- 不重启、部署、构建、迁移或打印环境变量、完整容器配置、全量日志。

## 输出

按“对象、观察时间、服务/版本、只读业务观察、异常与缺失证据”简报。缺失、访问失败和无记录均保持 UNKNOWN/缺失，不写成正常或零。
