# C_FAST execution-quality 纯 Research scorer

本文档对应 Issue #144 的非激活 scorer 切片。它把已经冻结在 execution
quality policy v2 中的盘口质量规则实现为纯函数，但不采集行情、不持久化、
不启动 sidecar，也不获得任何交易或运行权限。

## 固定边界

scorer 只接受调用方显式提供的：

- 一个严格 `CFastVirtualIntentDTO`；
- `virtual_intent.durably_created_at_utc` 对应的 UTC decision anchor；
- policy v2 及其 canonical SHA256；
- 与 intent exact contract 一致的 contract spec；
- 最多 10,000 条严格 L1–L5 snapshot。

它不接入 Settings、startup、repository、QuestDB、worker、API、RPC、
`TradeService`、`send_order` 或 `cancel_order`。输出固定：

```text
scoring_state=PURE_RESEARCH_SCORE_AUTHORITY_ABSENT
collection_authorized=false
runtime_activation_authorized=false
authority_granted=false
dispatch_allowed=false
order_authorized=false
position_mutation_authorized=false
database_mutation_authorized=false
deployment_mutation_authorized=false
replacement_allowed=false
production_allowed=false
```

本切片不会把 `execution_quality_implemented` 改为 true。

## 输入完整性

- 价格、累计成交量、price tick 和 volume-unit binding 只接受有限普通十进制
  字符串；禁止 binary float、`NaN`、`Infinity` 和科学计数法。
- 每条 book snapshot、contract spec 和最终 score 都有 canonical JSON
  SHA256。严格 DTO reload 会重算 hash。
- `reload_and_verify_execution_quality_score` 还会使用当前 intent、policy、
  contract spec 和全部 snapshots 重新计算完整 score；能够同步改写字段与
  checksum 的自洽伪造仍会因 derivation 不一致而失败。
- intent 的 foundation policy hash 必须等于 policy v2 的
  `foundation_policy_hash`。
- 相同 `ingest_id` 若绑定不同 snapshot 内容直接失败；同合约上相同
  `exchange_timestamp + ingest_seq` 只保留 policy tie-break 后的第一条
  canonical row。

SHA256 仍然只是 checksum，不是签名或 authority。调用方必须在未来独立接线
中重新验证 accepted signed snapshot、raw signed policy chain 和 contract
spec 来源。

## 行情选择与质量优先级

decision 与 `250ms / 1s / 5s / 30s / 60s` horizons 完全使用 policy v2
的闭区间和 tie-break。输入顺序不影响结果，不 carry-forward，也不填补缺失
horizon。

唯一质量优先级为：

```text
CLOCK_INVALID > STALE >= 2000ms > CROSSED > LOCKED >
MISSING_L1 > L1_ONLY > L5_USABLE
```

eligible tick 还必须有正值、on-grid L1。LOCKED 只能生成 markout；L1-only
只能生成 policy v2 允许的 spread、protected-price counterfactual、markout
和真实 L1 coverage；只有 L5 usable 才能额外生成 microprice、depth
imbalance 和 book walk。

## 指标

Marketable counterfactual 按 intent 经济方向 walk 对手方 L1–L5：

- observed L1/L5 covered lots 与 coverage ratio；
- observed covered depth VWAP；
- 相对对手方一档的 adverse ticks；
- `adverse_ticks × price_tick × multiplier × covered_lots` CNY；
- 深度不足显式标记 `PARTIAL_L5_DEPTH_INSUFFICIENT`，不外推剩余档位。

decision 还记录 spread、microprice 和 L1 depth imbalance。markout 使用
方向调整后的 decision midpoint 到 selected horizon midpoint 变化，并同时
输出 ticks 与 intent lots 对应的 CNY。

Passive fill 永远只输出 conservative bounds：

- lower bound 固定为 0；
- 只有 decision/horizon 都为 L5 usable、volume unit 已绑定且区间累计
  volume 单调时，upper bound 才是
  `min(1, positive raw volume delta × lots-per-unit / order lots)`；
- 缺 binding、volume reset/缺失、locked 或 L1-only 均输出
  `UNIDENTIFIED`，而不是 0 或 1；
- `point_probability_output=FORBIDDEN`，schema 中没有 fill probability
  字段。

## 尚未实现

Issue #144 仍需后续独立 PR 完成 collection admission 的消费、durable
virtual-intent record、repository/sidecar、restart recovery、duplicate
protection 的跨重启语义和运行审计。当前纯 scorer 不授权这些能力。

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_scorer.py

PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality.py \
  backend/tests/unit/test_commodity_c_fast_execution_policy.py \
  backend/tests/unit/test_commodity_c_fast_execution_policy_v2.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_scorer.py
```
