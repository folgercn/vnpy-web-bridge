# 商品期货候选 C fast cross-section neutral forward freeze v1

状态：`FROZEN_RESULT_BLIND_COLLECTION_PREFLIGHT_ONLY`

## 冻结对象

- 候选：`C_FAST_CROSS_SECTION_NEUTRAL`，永久标记为 post-discovery，不冒充独立历史 holdout。
- 固定 10 品种：`ag/al/au/bu/cu/rb/ru/sc/sp/zn`。
- 每个品种用 21/63/126 official-day PIT time-series sign 等权投票；raw 为 score/vol60，再对固定 10 品种去 raw mean。
- 正负腿各 50% gross；20% 单品种、35% 板块、100% 组合 gross cap 后，只缩较大腿恢复中性。
- 每个完整 source 月末形成信号，最早在下一跨月 available official day 的 exact-contract open 执行；逐日跟随 PIT main 换月。
- 只封存 3T/5T 压力口径。正式 PIT fee、自融资现金账和整数手数/保证金均未绑定，所以 `tradable=false`。

## 真正 forward 边界

- raw max：`2026-07-10`；sealed source/PnL max：`2026-07-09`；available max：`2026-07-10`。
- 统一 `COLD_START`，历史仓位不得带入；2026-07 右截尾不计数。
- 第一个可计完整 source 月为 `2026-08`，首个 holding 月为 `2026-09`。
- 3/6 个完整月只令 checkpoint due；不授权评分、确认、交易、shadow/testnet/live 或生产。

## A/B/C 隔离

现有 A/B freeze 与 A/B registry 未修改。C 独立新增；A/B/C 必须分别收集、分别报告、分别判断，禁止 winner-select、blend、switch、fallback 和 pooled pass。冻结时未来行读取数为 0，forward PnL 未读取；未联网，也未读取旧事件/交易/持仓/PnL 账本。
