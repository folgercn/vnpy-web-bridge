# C_FAST 四层 PnL Evidence Ledger v1（纯离线切片）

本文档对应 Issue #145 的首个可独立合并切片。当前只提供严格 DTO、
确定性 builder、reload verifier 和不可变 hash-chain audit；不接
repository、QuestDB、API、worker、runtime、Settings、RPC、TradeService、
订单、派单或部署。

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

这里的 SHA256 是完整性 checksum，不是签名或事实 authority。接入任何真实
forward/SimNow 证据前，调用方仍必须独立验证签名、custody 和事实来源；本切片
没有产生真实 forward、盘口或 SimNow evidence。

## 四层隔离

`CommodityCFastFourLayerPnlLedgerEntryDTO` 强制同时存在四个不同字段：

1. `theoretical_target_pnl`
2. `fee_adjusted_pnl`
3. `execution_quality_interval_pnl`
4. `actual_simnow_calibration_pnl`

每层有自己的：

- `source_kind`；
- source artifact / payload SHA256；
- derivation rule / code SHA256；
- input cutoff；
- `lineage_hash`；
- `layer_hash`。

envelope 再保存四项 `layer_hashes`，并把它们绑定到 `entry_id` 和
`entry_hash`。任何层都不能覆盖、合并或冒充另一层。

## 1. 理论目标 PnL

只接受 `SIGNED_EXACT_TARGET_MARKS` lineage，并分开记录：

- realized；
- unrealized；
- roll；
- total。

`total` 必须可由前三项重算。仓位基准固定为：

```text
OBSERVED_VIRTUAL_FILL_STATE_NEVER_ASSUME_UNFILLED_TARGET
```

`held_lots` 和 `pending_virtual_lots` 分开保存，未完成虚拟成交不得补成已持有。

## 2. 费用调整 PnL

费用层绑定理论层的 `layer_hash` 与 `total_pnl_cny`，不接受调用方自行替换
这一绑定。

若 broker/customer fee 或其他必要费率尚未绑定，必须使用：

```text
fee_binding_state=UNBOUND_NOT_ASSUMED_ZERO
```

并列出 `unbound_components`。此时：

- `broker_customer_fee_cny=null`
- `all_in_cost_cny=null`
- `fee_adjusted_total_pnl_cny=null`
- `fee_schedule_sha256=null`

禁止用 0 代替未知成本。只有 `BOUND` 才允许输出 all-in cost 和费用调整总
PnL，并要求所有费用、fee schedule hash 与算术关系完整。

## 3. 盘口可成交区间 PnL

只接受 `EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS` lineage。必须同时保存：

- planned lots；
- filled lower / upper；
- 从 fill bounds 唯一派生的 unfilled lower / upper；
- conservative / optimistic PnL；
- 单列的 opportunity-cost lower / upper；
- 可用时的 marketable book-walk PnL。

支持 `FULL / PARTIAL / UNFILLED / UNIDENTIFIED_BOUNDS_ONLY`。未校准前固定：

```text
point_fill_probability_state=FORBIDDEN_UNCALIBRATED_BOUNDS_ONLY
```

不得输出伪精确点成交概率，且 PnL lower 不得大于 upper。

## 4. 真实 SimNow 校准 PnL

无真实事实时使用 `actual_state=NOT_PROVIDED`，此时不得附带 lineage、facts
或任何 actual PnL 数值。

`FACTS_BOUND` 只接受：

```text
fact_source=SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION
execution_lane=simnow_shakedown
countable_forward=false
production_allowed=false
```

还必须显式绑定 session、account、orders、trades、positions 和
reconciliation hashes。partial fill 按实际 `filled_lots` 保存；
cancel/reject/timeout/unknown 不得伪装为 full fill。事实 `INCOMPLETE` 或
`INCONSISTENT` 时所有 actual 金额保持 `null`。

完整事实若费用仍未绑定，可保存 observed-fill gross PnL 和 slippage，但
`actual_net_pnl_cny` 必须保持 `null`；只有 actual fee `BOUND` 才能生成
observed-fill net PnL。

## Immutable chain 与 audit

每条 entry 有单调 `entry_sequence` 和 `previous_entry_hash`：

- genesis 必须是 sequence 1 且 predecessor 为 null；
- 后续 entry 必须指向前一条 `entry_hash`；
- ledger ID 不得混用；
- sequence 必须连续；
- entry ID / hash 重复视为 replay；
- 任一 lineage、layer、index、entry 或 predecessor 篡改均 fail closed；
- 单次离线 audit 最多 10,000 条，金额与手数也有资源上限。

`verify_four_layer_pnl_chain` 返回
`CommodityCFastPnlLedgerAuditDTO`，结论仅为：

```text
PASS_DETERMINISTIC_STRUCTURE_AND_HASH_CHAIN_ONLY
```

它不是签名验收、forward 计数、晋级、替换或交易许可。

## Python 使用

```python
from app.services.commodity_c_fast_pnl_ledger import (
    build_four_layer_pnl_entry,
    verify_four_layer_pnl_chain,
)

entry = build_four_layer_pnl_entry(
    ledger_id="cfast-four-layer-ledger-2026-09",
    entry_sequence=1,
    previous_entry_hash=None,
    snapshot_hash="<accepted snapshot sha256>",
    formula_target_binding_sha256="<formula binding sha256>",
    valuation_day="2026-09-02",
    created_at_utc="2026-09-02T08:02:00Z",
    theoretical_target_pnl=theoretical_input,
    fee_adjusted_pnl=fee_input,
    execution_quality_interval_pnl=execution_interval_input,
    actual_simnow_calibration_pnl=actual_input,
)

audit = verify_four_layer_pnl_chain(
    [entry.model_dump(mode="json")]
)
```

JSON Schema 可由严格 DTO 确定性导出：

```python
from app.schemas.commodity_c_fast_pnl_ledger import (
    CommodityCFastFourLayerPnlLedgerEntryDTO,
)

schema = CommodityCFastFourLayerPnlLedgerEntryDTO.model_json_schema()
```

DTO 及所有嵌套对象均 `extra=forbid`、`allow_inf_nan=false`、frozen。

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
