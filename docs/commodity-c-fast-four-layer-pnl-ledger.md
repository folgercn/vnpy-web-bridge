# C_FAST 四层 PnL Evidence Ledger v2（纯离线切片）

本文档对应 Issue #145 的首个可独立合并切片。当前只提供 strict typed source
facts、确定性 builder、fresh replay verifier 和 immutable hash-chain audit；
不接 repository、QuestDB、API、worker、runtime、Settings、RPC、
TradeService、订单、派单或部署。

## Architecture Impact

- Plane：Research Plane。
- Authority：无变化。
- Execution / production：无影响。
- 固定状态：

```text
audit_scope=DETERMINISTIC_OFFLINE_RESEARCH_STRUCTURE_ONLY
countable_forward=false
authority_granted=false
dispatch_allowed=false
replacement_allowed=false
production_allowed=false
```

这里的 SHA256 是完整性 checksum，不是签名或事实 authority。接入真实
forward/SimNow 证据前，调用方仍须独立验证签名、custody 和事实来源。本切片
没有产生真实 forward、盘口或 SimNow evidence。

## v2 fresh replay 边界

v1 只校验 DTO 内 caller 提供的 lineage/hash，无法阻止同一组自洽 hash 被协调
挂到另一个 snapshot 或 ledger。v2 不再接收 caller 自报 lineage。

每一层必须嵌入自己的 strict typed source facts，并显式包含：

```text
candidate_id
ledger_id
snapshot_hash
formula_target_binding_sha256
plan_hash
valuation_day
as_of_at_utc
```

builder 从 typed facts 重新派生：

- source artifact ID；
- source artifact/payload SHA256；
- 固定 derivation rule/code SHA256；
- lineage hash；
- layer 所有派生字段与 layer hash；
- envelope layer index、entry ID 和 entry hash。

`reload_and_verify_four_layer_pnl_entry` 先做 DTO/hash 校验，再只使用 entry 内
嵌入的 typed facts 重新执行 builder，要求完整对象全等。改变 derivation rule
并同步重算所有 checksum 虽可通过 DTO，自新 replay 仍会 fail closed。

同一 typed facts 无法挂到不同的 ledger、snapshot、formula binding、plan 或
valuation day；envelope 与四层 source identity 必须逐项完全相同。

## 四层隔离

`CommodityCFastFourLayerPnlLedgerEntryDTO` 强制同时存在：

1. `theoretical_target_pnl`
2. `fee_adjusted_pnl`
3. `execution_quality_interval_pnl`
4. `actual_simnow_calibration_pnl`

每层有独立 source facts、lineage hash 和 layer hash。envelope 再保存四项
`layer_hashes`，禁止覆盖、合并或冒充另一层。

## 1. 理论目标 PnL

理论 source facts 只提供 observed virtual fill 仓位和：

- realized；
- unrealized；
- roll。

builder 派生 total。仓位基准固定为：

```text
OBSERVED_VIRTUAL_FILL_STATE_NEVER_ASSUME_UNFILLED_TARGET
```

`held_lots` 与 `pending_virtual_lots` 分开，未完成虚拟成交不得补成已持有。

## 2. 费用调整 PnL

费用层自动绑定理论层的 layer hash 与 total PnL。caller 不能提交或覆盖这两个
派生字段。

若任一必要费率/金额未绑定，必须使用：

```text
fee_binding_state=UNBOUND_NOT_ASSUMED_ZERO
```

并列入 `unbound_components`。组件与必须为 null 的字段对应如下：

| unbound component | 必须为 null |
|---|---|
| `official_exchange_fee_rate` | official rate 与 official fee CNY |
| `broker_customer_fee_rate` | broker/customer rate 与 fee CNY |
| `preregistered_tick_stress` | tick-stress CNY |
| `roll_round_trip_cost` | roll cost CNY |

即使 caller 传 `0` 或 `0.0` 也拒绝。UNBOUND 时 complete fee schedule、
all-in cost 与 fee-adjusted net PnL 均为 null。只有所有 fee facts 完整
`BOUND` 时，builder 才派生 all-in cost 和 net PnL。

## 3. 盘口可成交区间 PnL

execution-quality typed facts 只提交：

- planned lots；
- filled lower / upper；
- per-filled-lot PnL；
- per-unfilled-lot opportunity cost；
- 可选的 marketable book-walk PnL。

以下字段全部由 builder 派生，caller 作为 source facts 提交会因
`extra=forbid` 被拒绝：

- unfilled lower / upper；
- conservative / optimistic fill PnL；
- opportunity-cost lower / upper。

状态规则：

- `FULL`：filled lower = upper = planned；
- `UNFILLED`：filled lower = upper = 0，fill PnL 为 0，opportunity cost
  由全部 unfilled lots 派生；
- `PARTIAL`：`0 <= lower <= upper < planned` 且 upper > 0；
- `UNIDENTIFIED_BOUNDS_ONLY`：必须保留非点区间。

未校准前固定：

```text
point_fill_probability_state=FORBIDDEN_UNCALIBRATED_BOUNDS_ONLY
```

## 4. 真实 SimNow 校准 PnL

无事实时提交 typed `NOT_PROVIDED` source facts，仍绑定当前
ledger/snapshot/formula/plan/as-of，但不生成 actual 金额。

`FACTS_BOUND` 只接受：

```text
fact_source=SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION
execution_lane=simnow_shakedown
countable_forward=false
production_allowed=false
```

actual facts 必须显式绑定：

- snapshot / formula / plan；
- session / account；
- orders / trades / positions / reconciliation hashes；
- terminal status、terminal reconciliation 和可重算 terminal checksum；
- expected / filled lots 与 order outcome。

只有以下条件全部成立，才允许 `trade_evidence_state=COMPLETE` 并发布 gross
PnL：

```text
terminal_status=COMPLETE
terminal_reconciliation_complete=true
terminal_completed_at_utc!=null
expected_lots>0
filled_lots=expected_lots
order_outcome=FULL_FILL
```

partial、unfilled、cancel、reject、timeout、结果未知、terminal 未完全对账或
`filled_lots != expected_lots` 都必须保持 `INCOMPLETE/INCONSISTENT`，所有
actual PnL/slippage/fee 金额为 null。权威持仓可用于安全收口，但不能把迟到的
trade callback 当作零成交或零 PnL。

完整成交但 actual fee 未绑定时可保留 gross/slippage，net 仍为 null；fee
`BOUND` 后才派生 actual net。

## Strict boolean 与确定性金额

所有固定 false 字段使用 before validator。raw `0`、`0.0` 或其他 truthy/falsy
数值都不能冒充 boolean false。

raw `Decimal` 不直接进入 JSON hashing；builder/verifier 将其转换成受控
`DECIMAL_RAW_INPUT_NOT_ALLOWED` domain error。金额加总/乘法使用本模块固定的
34 位、`ROUND_HALF_EVEN` local Decimal context，不受进程 ambient Decimal
precision/rounding 影响。

## Immutable chain 与 audit

每条 entry 有单调 sequence 和 predecessor hash。完整 chain 要求：

- sequence 从 1 连续递增；
- `created_at_utc` 严格递增；
- valuation day 不倒退；
- 四个 source 的 `as_of_at_utc` 分别不倒退；
- ledger ID 不混用；
- entry ID/hash 不重复；
- 完全相同的四层 source-fact set 不得换 sequence 重放；
- predecessor 精确指向上一 entry hash；
- 单次 audit 最多 10,000 条。

verifier 成功只返回：

```text
PASS_FRESH_REPLAY_STRUCTURE_AND_HASH_CHAIN_ONLY
```

它不是签名验收、forward 计数、晋级、替换或交易许可。

## Python 使用

```python
entry = build_four_layer_pnl_entry(
    ledger_id="cfast-four-layer-ledger-2026-09",
    entry_sequence=1,
    previous_entry_hash=None,
    snapshot_hash="<accepted snapshot sha256>",
    formula_target_binding_sha256="<formula binding sha256>",
    plan_hash="<virtual intent plan sha256>",
    valuation_day="2026-09-02",
    created_at_utc="2026-09-02T08:03:00Z",
    theoretical_target_pnl=theoretical_source_facts,
    fee_adjusted_pnl=fee_source_facts,
    execution_quality_interval_pnl=execution_source_facts,
    actual_simnow_calibration_pnl=actual_source_facts,
)

audit = verify_four_layer_pnl_chain(
    [entry.model_dump(mode="json")]
)
```

严格 JSON Schema 可由
`CommodityCFastFourLayerPnlLedgerEntryDTO.model_json_schema()` 导出。

## 验证

```bash
PYTHONPATH=backend python -m pytest -q \
  backend/tests/unit/test_commodity_c_fast_pnl_ledger.py

PYTHONPATH=backend python -m pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality.py \
  backend/tests/unit/test_commodity_c_fast_simnow.py \
  backend/tests/unit/test_commodity_c_fast_pnl_ledger.py

PYTHONPATH=backend python -m pytest -q backend/tests/unit
```
