# C_FAST execution-quality collection policy v2 离线冻结

本文档对应 Issue #114 的 collection-policy v2 切片。v2 把 PR-C0/C1
仍为 deferred 的盘口选择、protected-price counterfactual、质量降级和
passive fill bounds 规则改为完整、确定性的离线 policy，但不授予 collection
或任何运行权限。

## 结论与固定边界

v2 的“collection-ready”只表示规则完整：

```text
policy_rule_completeness=COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT
policy_authority_state=SIGNED_RULES_COMPLETE_REQUIRES_SEPARATE_P0_AND_COLLECTION_RELEASE
```

它不表示 P0 已通过，也不表示 sidecar 可以启动。freeze envelope 和验证
receipt 都固定：

```text
offline_policy_only=true
p0_pass_required_before_collection=true
separate_collection_release_required=true
collection_authorized=false
runtime_activation_authorized=false
authority_granted=false
dispatch_allowed=false
order_authorized=false
position_mutation_authorized=false
dynamic_selection_allowed=false
automatic_promotion_authorized=false
database_mutation_authorized=false
deployment_mutation_authorized=false
replacement_allowed=false
production_allowed=false
```

本切片没有增加 Settings、环境变量、startup hook、API、repository、worker、
QuestDB、行情订阅、RPC、TradeService、订单 reference 或持仓能力。现有
`execution_quality_implemented=false` 不变。

## v1 ancestry

v2 不是可以脱离历史 foundation 自签的平行 policy。它必须显式绑定：

```text
supersedes_schema_version=commodity_c_fast_execution_policy_freeze_v1
supersedes_freeze_id=<v1 freeze_id>
supersedes_freeze_sha256=<v1 unsigned canonical JSON SHA256>
supersedes_freeze_raw_sha256=<v1 signed artifact exact bytes SHA256>
superseded_policy_hash=<v1 embedded foundation policy SHA256>
```

`supersedes_freeze_raw_sha256` 对 v1 原始文件逐 byte 计算，范围包含
`signature`、空白和末尾换行；它不能由 DTO 重新序列化后生成。验证 v2 时必须
同时提供 raw signed v1、raw signed v2 和一个被独立 SHA256 pin 的 trusted
keyring。权威入口只接受 `bytes`，验证器会：

1. 先核对 trusted keyring 的 canonical SHA256 pin 和 key purpose；
2. 严格解析 raw v1/v2，拒绝字符串替代、重复 key、非有限数和 extra field；
3. 重新验证 v2 和 v1 Ed25519 signature；
4. 重算 v1 unsigned canonical SHA256 和 signed raw SHA256；
5. 核对 v1 freeze ID、candidate、policy hash 和两种 parent hash；
6. 核对 v2 policy 的 `foundation_policy_hash` 与 v1 policy hash。

因此，即便重排 key/空白后的 v1 仍能通过 canonical signature，它也会因为
raw hash 改变而 fail closed。只提供 v1 receipt、手填一个匹配 canonical hash
或把解析后的 v1 DTO 重新序列化均不能通过。v2 receipt 同时回显：

```text
freeze_sha256=<v2 unsigned canonical SHA256>
freeze_raw_sha256=<v2 signed exact bytes SHA256>
supersedes_freeze_sha256=<v1 unsigned canonical SHA256>
supersedes_freeze_raw_sha256=<v1 signed exact bytes SHA256>
receipt_authority_state=NON_AUTHORITATIVE_REVERIFY_RAW_SIGNED_FREEZES
```

未来 collection admission 必须重新验证原始 signed v1 和 v2，不能从一个可构造
的 receipt JSON 恢复 authority。

## Protected-price counterfactual

v2 使用同一 decision tick 的对手方一档报价：

```text
BUY_TICKS  = ASK_PRICE_1_TICKS + 1
SELL_TICKS = BID_PRICE_1_TICKS - 1
```

- `PRICE_TICK` 来自 signed snapshot contract spec；
- price 和 price tick 从十进制字符串用 `Decimal` 语义转换为 exact integer
  ticks；禁止 binary float 和 Python `round`；
- 输入价除以 signed decimal price tick 必须是整数，输出以 integer ticks
  乘 decimal price tick 渲染；
- 对手方一档或 price tick 缺失时状态为
  `UNUSABLE_MISSING_OPPOSITE_BEST_OR_PRICE_TICK`；
- 输入不在 tick grid 时状态为 `UNUSABLE_INVALID_PRICE_GRID`；
- 该价格只用于反事实冲击和 markout 计算，不是订单价格；
- `counterfactual_only=true`、`order_price_authorized=false`。

禁止从 Settings、实时默认值或实际成交结果反推/改写该规则。

该 protected-price 公式只与当前 SimNow 的 counterfactual price 目标对齐，
不表示两者的 quote freshness 语义对齐：本 policy 用
`received_at_utc - exchange_timestamp >= 2000ms` 判 stale，而当前 SimNow
另有基于本地 now/received time 和运行配置的 freshness gate。二者不得互相
替代或据此声称 collection/live parity。

## Decision tick 与 horizon tie-break

decision anchor 固定为：

```text
decision_anchor=VIRTUAL_INTENT_DURABLY_CREATED_AT_UTC
decision_anchor_field=virtual_intent.durably_created_at_utc
decision_anchor_source=CREATE_ONLY_DURABLE_VIRTUAL_INTENT_RECORD_AFTER_FILE_AND_DIRECTORY_FSYNC
intent_id_source=virtual_intent.intent_id
snapshot_id_source=virtual_intent.snapshot_id
```

行情字段来源固定为 `market_tick.received_at_utc`、
`market_tick.exchange_timestamp`、`market_tick.ingest_seq` 和
`market_tick.ingest_id`。decision tick 选择：

```text
EARLIEST_ELIGIBLE_TICK_WITH_RECEIVED_AT_UTC_AT_OR_AFTER_DECISION_ANCHOR
decision_max_lateness_ms=1000
[anchor, anchor + 1000ms]
```

horizon 固定为：

```text
250ms, 1s, 5s, 30s, 60s
```

每个目标时间为 `decision_anchor + horizon_ms`，选择闭区间
`[target, target + 1000ms]` 内最早的 eligible tick；两个端点都包含。
eligible 要求 L1 正值且在 tick grid，不能 stale/crossed；locked 和 L1-only
可以被选中，但只能按下文降级，不得产生被禁止的 depth/fill metric。排序和
完全相同时间的 tie-break 固定为：

```text
received_at_utc
exchange_timestamp
ingest_seq
ingest_id
```

相同 `ingest_id`，或同一合约上 `exchange_timestamp + ingest_seq` 都相同，
才视为一个事件并只保留第一条 canonical row。不得把跨重启后重复出现的
`ingest_seq` 单独当成重复事件。不得 carry-forward 前一报价；窗口内没有
eligible tick 时记录
`MISSING_HORIZON_NOT_IMPUTED`。

## Stale、crossed、locked 与 L5 降级

stale age 固定使用：

```text
received_at_utc - exchange_timestamp
```

- age 为负：`UNUSABLE_CLOCK_ORDER_INVALID`；
- age 大于或等于 2,000ms：
  `UNUSABLE_STALE_NO_PRICE_OR_FILL_METRICS`；
- `bid1 > ask1`：`UNUSABLE_CROSSED_BOOK`；
- `bid1 == ask1`：
  `DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS`。

L1 usable 要求 bid1/ask1/size1 均为正、价格在 exact integer-tick grid，
且 `bid1 < ask1`。L5 usable 还要求 L1–L5 每个价格都能由 decimal price
无损转换为 integer ticks、五档数量全部为正且严格单调：

```text
bid1 > bid2 > bid3 > bid4 > bid5
ask1 < ask2 < ask3 < ask4 < ask5
```

多种异常同时出现时，quality precedence 固定为：

```text
CLOCK_INVALID > STALE > CROSSED > LOCKED > MISSING_L1 > L1_ONLY > L5_USABLE
```

metric mask 也被冻结：CLOCK_INVALID/STALE/CROSSED/MISSING_L1 仅记录 quality
state 和 diagnostics；LOCKED 仅允许 markout；L1_ONLY 仅允许 spread、
protected-price counterfactual、markout 和 L1 coverage；只有 L5_USABLE
才允许 L5 book-walk。quality precedence 先选唯一状态，再应用对应 mask，
禁止指标各自绕过 quality 判定。

L1 缺失时不产生 execution metrics。L1 有效但 L2–L5 缺失或异常时，只能标记：

```text
L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO
```

此时只允许保存真实 L1 可覆盖手数/比例以及依赖有效 L1 的 spread、protected
price counterfactual 和 markout；禁止生成 L5 book-walk、L5 fill ratio 或
passive fill bounds。禁止合成缺档、把 L1 深度复制到 L2–L5，或把 L1-only
结果描述为 L5/book-walk 通过。degraded horizon 只能保存该状态允许的真实
observed metrics，不能补写价格、深度或成交。

## Passive fill bounds

CTP 五档不包含自己的队列身份、撤单身份或完整 aggressor side，因此 v2 只允许：

```text
output_mode=LOWER_UPPER_BOUNDS_ONLY
point_probability_output=FORBIDDEN
calibrated_point_probability_allowed=false
```

固定假设：

- 虚拟被动 BUY limit = decision tick 的 `BID_PRICE_1`，被动 SELL limit =
  decision tick 的 `ASK_PRICE_1`；
- 经济方向定义为 BUY 由 limit 价或更低价的卖方主动量成交，SELL 由 limit
  价或更高价的买方主动量成交；
- 观察区间为 `(decision tick, selected horizon tick]`；
- decision 时同侧展示量全部排在虚拟订单之前；
- 没有可识别订单队列和 exchange fill 时，lower bound 为 0；
- cancellation 不给 lower bound 任何 credit，只能进入 optimistic upper；
- `Volume` 先保留为 exchange cumulative volume delta raw units；只有 signed
  contract spec 明确绑定 `1 raw unit = N contract lots` 后才能换算，否则
  bounds 为 `UNIDENTIFIED`；
- CTP 聚合快照的 last price/volume delta 不能证明 aggressor direction，也
  不能证明 at-or-through volume，因此 price-conditioned bound 固定
  `UNIDENTIFIED`；
- 唯一可声称为真正上界的是观察区间内全部正 volume delta 换算为 contract
  lots 后除以 order lots 并 cap 为 1；它故意不按 last price 或方向筛选；
- volume reset、负差分或归因不清时为
  `UNIDENTIFIED_BOUNDS_NOT_ZERO_OR_FULL`；
- locked、crossed、stale 或 L1-only 时为
  `UNIDENTIFIED_NO_PASSIVE_FILL_BOUNDS`。

这些上下界不是点概率。schema 禁止额外 `fill_probability` 字段，也不能通过
重新签名把 `calibrated_point_probability_allowed` 改为 true。

## 离线签署

现有签名工具同时兼容 v1 和 v2，根据 `schema_version` 严格选择 DTO：

```bash
PYTHONPATH=backend python \
  scripts/commodity_c_fast_execution_policy_sign.py \
  --input /secure/c-fast-policy-freeze-v2-unsigned.json \
  --private-key-file /secure/c-fast-policy-freeze.key \
  --output /secure/c-fast-policy-freeze-v2-signed.json
```

签名输入、私钥必须是有界普通非 symlink 文件。读取使用同一 FD 双读，并核对
path/fd 的 device、inode、size、type、owner 和 mode；读取中发生同长度替换也
会失败。私钥必须由当前用户所有且权限为 `0600` 或更严格。输出继续使用
`0600` create-only + fsync，不覆盖历史 artifact。

raw-chain file verifier 对 v1、v2、keyring 也使用 non-symlink、同一 FD
双读和 path/FD identity 检查；keyring 必须由当前用户所有且为 `0600` 或更
严格，并在验签前匹配独立 pin。parser 拒绝重复 key、`NaN`、`Infinity`、
unknown/extra fields、numeric timestamp、float 形式的 integer literal、
schedule reorder/truncate/duplicate、非 UTC `frozen_at_utc`、错误 policy
hash 和未知 schema version。

## 尚未授予的下一步

即使 v1/v2 均验签成功，仍不得创建 execution-quality table/repository/worker。
后续至少还需要：

1. T1 `SUCCEEDED_P0_PASS` 产物的独立签名 P0 acceptance；
2. collection admission release 直接绑定 raw signed v1、v2、P0 terminal、
   manifest、release、consume 和 evidence/proof hashes；
3. 每次 startup/recovery 重新验签原始 artifacts；
4. 独立人工主审 runtime/storage/horizon recovery 失败路径。

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_policy.py \
  backend/tests/unit/test_commodity_c_fast_execution_policy_v2.py

ruff check \
  backend/app/schemas/commodity_c_fast_execution_policy.py \
  backend/app/services/commodity_c_fast_execution_policy.py \
  scripts/commodity_c_fast_execution_policy_sign.py \
  backend/tests/unit/test_commodity_c_fast_execution_policy_v2.py

python -m compileall -q \
  backend/app/schemas/commodity_c_fast_execution_policy.py \
  backend/app/services/commodity_c_fast_execution_policy.py \
  scripts/commodity_c_fast_execution_policy_sign.py
```
