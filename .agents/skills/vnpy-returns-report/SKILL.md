---
name: vnpy-returns-report
description: 核验指定 SIMNOW_LAB 时间区间的权益、回撤、成交和滑点覆盖；只读报告，不将账户变化包装为策略收益。
---

# vnpy returns report

用于回答指定时间区间内可核实的 Lab 经济结果。先读根 `AGENTS.md`，并明确对象、请求区间、数据库/导出来源和采集时间。结果是 SIMNOW_LAB 实验观察，不能称为 production、audited 或正式前瞻业绩。

## 读取与口径

- 不使用 Dashboard 的最近 1,000 快照、500 成交截断结果来代表任意完整周期。
- 对 SQLite 区间核验，运行 `scripts/inspect_returns_v1.py DB_PATH --start YYYY-MM-DD --end YYYY-MM-DD`。该工具仅以 `mode=ro` 和 `PRAGMA query_only=ON` 读取 `snapshots`、`trades`，上海时区解释请求日期。
- 若来源不是该 SQLite，先核对字段、时区、费用和出入金口径；不能为报告补采、修数、写库、生成 target 或执行交易。
- 工具的 `observed_span_covers_requested_range` 只表示首末观察时间跨越请求边界，不能单独证明期间没有缺口。`invalid_*_time_rows` 或边界缺失必须写入结论。

## 判读

- `equity_change` 是所选有效快照之间的权益变化，不等于策略净收益；账户出入金、其他活动和未实现盈亏会影响它。
- `realized_pnl_change_estimate` 仅在两端未实现盈亏都有效时给出，仍不是已独立归因的策略净收益。
- `max_drawdown_amount` 基于区间内已观察权益；不把有限采样写成完整周期最大回撤。
- 当前表无手续费字段，因此费用必须报告为 `UNVERIFIED`，不得填 0。滑点只报告已记录的 `slippage × volume` 汇总及缺失行数，不将其断言为费用。
- 任一指标缺数据时保留 `null`/`UNVERIFIED`；missing 不等于 zero。

## 输出

报告对象、请求区间、实际观察覆盖、来源与采集时间；列出权益变化、回撤、成交数、滑点记录和费用归属。分别写“可核实的权益观察”“无法独立核实的策略净收益”和缺失证据。
