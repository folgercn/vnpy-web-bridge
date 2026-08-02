# C_FAST SimNow Fee Statement 与 all-in net PnL v1

本文档对应 Issue #245。该切片把已完成 terminal reconciliation 的 C_FAST
SimNow session archive 与独立签发的 broker/customer fee statement 做 exact join，
并从不可变输入 fresh replay official exchange fee、broker/customer fee、all-in
cost 与 actual net PnL。缺少任何必要事实时，既有 v4 仍保持
`UNBOUND_NOT_ASSUMED_ZERO`，不会把未知费用解释为零。

## Architecture Impact

- Plane：Research / Evidence Plane。
- Python API：strict DTO、离线 stable-read verifier、settled archive adapter、四层
  PnL builder、repository/export fresh replay。
- CLI：`scripts/commodity_c_fast_fee_statement_verify.py` 只读输入并 create-only
  写出一个 canonical v5 source-facts artifact。
- HTTP API 与 TradeService 下单 authority 不变。C_FAST terminal archive 路径新增
  RPC order/trade callback lock、单调 generation、owner-bound one-shot
  publication capability，并在锁内重放 guard 后 create-only publish；它改变终态
  evidence 的线性化语义，但不提供新的发单、撤单或仓位 authority。
- M2 / forward 计数：无变化；本地验证结果固定 `countable_forward=false`。

## Authority Impact

没有新增 Control、Execution、order、position、database-mutation 或 production
authority。statement、binding evidence、v5 Actual source facts、ledger entry 与 export
中的以下字段全部固定为 false：

```text
countable_forward=false
authority_granted=false
dispatch_allowed=false
replacement_allowed=false
production_allowed=false
```

fee signer 只允许签发 `C_FAST_SIMNOW_FEE_STATEMENT_V1`。它不能复用或替代以下
任何现有签名域：

```text
COMMODITY_BASELINE_EXECUTION_PERMIT
C_FAST_EXECUTION_PERMIT
C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION
C_FAST_RESEARCH_ACCEPTANCE
C_FAST_RESEARCH_BUNDLE
MANUAL_EXECUTION_PERMIT
```

verifier 必须 stable-read 上述五个文件 keyring，并精确解析 manual execution
permit 的 Settings JSON。任意 raw keyring hash 重合、Ed25519 public key material
重合、缺失域或域内 key 重复均 fail closed。即使 formal authority 功能当前未启用，
对应 keyring path 与 raw SHA256 pin 也不可省略；manual JSON 可以是精确的 `{}`。

## Fee statement contract

`CommodityCFastFeeStatementDTO` 与嵌套 schedule 均为 `extra=forbid`。statement
至少精确绑定：

- `account_sha256`，不保存账户原文；
- `execution_environment=SIMNOW` 与真实 resolved `gateway_name` 分开；后者必须
  精确等于 terminal guard 及每条 raw order/trade 的 gateway（例如 `CTP`）；
- `execution_lane=simnow_shakedown`、`session_id`；
- `trading_day` 与 fee schedule 生效起止交易日；
- archive raw SHA256、canonical orders/trades SHA256；
- broker/customer source document 原始字节 SHA256 与 document kind；
- issuer、fee-only signer key、签发/生效/过期时间；
- concrete `vt_symbol`、product、exchange、offset；
- official 与 broker/customer 的按手、按成交额、单笔最低费用规则；
- currency、逐 trade/component rounding mode，以及固定的 CNY 分币 increment
  `0.01`；
- schedule SHA256、signed payload SHA256 与 Ed25519 signature。

每个 `(vt_symbol, offset)` 只能有一条 rule，并按 canonical 顺序提交。每笔真实
trade 必须且只能 join 一个 submitted child、一个 raw order、一个 concrete
contract multiplier 和一个 fee rule；order id、contract、direction、offset、真实
gateway、reference 必须逐项一致，逐 order 成交累计不得超过委托量，并与 execution
snapshot 的 filled volume/trade count 可解释一致。未知或 orphan trade、重复 trade
id、跨 session/account/trading-day 拼接、错合约、错 gateway、错 offset、缺 rule、
错误 multiplier 或 raw hash 均拒绝。SimNow 是环境标签，不得冒充实际 gateway join。
fee-bound replay 要求带逐行 `gateway_name` 的
`commodity_c_fast_terminal_raw_facts_v3`；旧 v2 archive 缺少这项可验证事实，必须
重新采集，不能仅从环境标签或本地配置补写后升级为 BOUND。

## Deterministic fee formula

对每笔真实 trade 的每个 fee component 独立计算：

```text
turnover_cny = price * volume * contract_multiplier
raw_component_fee = max(
  minimum_cny_per_trade,
  by_volume_cny_per_lot * volume + by_turnover_rate * turnover_cny,
)
component_fee = round_to_increment(raw_component_fee)
```

rounding 固定发生在每笔 trade、每个 component，increment 强制为人民币分币
`0.01`；只允许 statement 指定的 `ROUND_HALF_EVEN` 或 `ROUND_HALF_UP`。最终
分别汇总
`official_exchange_fee_cny`、`broker_customer_fee_cny`，两者之和为
`all_in_cost_cny`，并 fresh replay：

```text
actual_net_pnl_cny = cent_quantize_half_even(
  gross_execution_pnl_cny - all_in_cost_cny
)
```

caller 不能直接提交费用总额或 net。

## Settled outcome boundary

v4 contract 不变，仍只接受 `FULL_FILL + COMPLETE`，且费用/net 保持 UNBOUND。
v5 通过独立 `ActualSimNowSettledArchiveReplayFactsDTO` 支持已完成 terminal raw
facts 与 position reconciliation 的：

```text
FULL_FILL
PARTIAL_FILL
UNFILLED_CANCELLED
REJECTED
TIMEOUT_OR_RESULT_UNKNOWN
```

partial 只对 archive 中实际存在的 trades 计费。cancel/reject/unknown 若 raw
archive 精确证明零 trade，则费用可以从空 trade 集确定性算得 0；这是“已验证没有
真实成交”，不是把缺失 fee artifact 或未知成交结果假设为 0。unknown 必须额外
声明 `SETTLED_BY_TERMINAL_RAW_FACTS_AND_POSITION_RECONCILIATION`。未终态对账、
archive chain tip 未绑定或仍可能出现迟到 trade 的 session 不能进入 v5。
fee statement 可以在原 settled PRIMARY 的 `as_of_at_utc` 之后到达。生产 loader
用同一次可信当前 UTC 只向后移动 replay wrapper 的 as-of；内嵌 archive、raw/hash、
session 和 terminal payload 必须与 PRIMARY 完全一致，不能借 correction 替换
execution facts。

## Custody、stable read 与 replay

archive facts、fee statement、fee keyring、source document 和五个 foreign-domain
keyring 都必须使用绝对路径、regular file、当前 owner、无 group/world 权限，且
不能是 symlink。JSON statement/keyring/archive facts 必须是 canonical JSON；单个
输入上限 4 MiB。verifier 比较 fd/path identity，并完整读取两次；两次之间 raw
bytes、parsed payload、source document 或 foreign keyring 改变都会 fail closed。

v5 source facts 内嵌 settled archive、statement、fee keyring、foreign-domain raw/
public-key hashes、逐 trade charge 与 source binding hash。DTO reload、ledger
builder、chain audit 和 repository export 都会从内嵌原始事实 fresh replay；只有
`fee_binding_state=BOUND` 才发布四项费用/net。audit 另计
`actual_net_fee_bound_entry_count`，不会把 v4 的 gross-only entry 误计为 net 已绑定。
如果 settled UNBOUND entry 已经 append，迟到的权威 fee 通过
`NON_COUNTING_FEE_BINDING_CORRECTION` 追加新 entry，并用
`supersedes_entry_hash` 精确指向原 primary；三个非 Actual layer 与 archive 的
immutable identity/payload 必须完全相同，仅 replay wrapper as-of 可向后移动。
chain audit 只计一次 terminal gross、只允许一次 correction，绝不
覆盖原 entry 或重复计入经济 gross。
内嵌 keyring 只能证明该 DTO 自洽，不能自行成为 trust root。所有 v5 build、
reload、chain audit、repository open/append/read/export 必须同时收到由 `Settings`
固定 pin 和稳定读取六个隔离 authority domain 后签发的 process-local
`FeeBindingTrustContext`；该对象不进入 DTO、JSON 或 repository。缺失或不匹配
都会 fail closed，v1-v4 和 fee-unbound replay 不受影响。
deployment 可通过
`COMMODITY_C_FAST_FEE_STATEMENT_HISTORICAL_TRUST_PROFILES_JSON` 显式冻结
版本化旧 profile，使 fee 或其他 authority key rotation 后仍能重放历史 v5。
profile 必须由部署配置预先 pin，不能从 ledger/evidence 自举；未知 profile 仍拒绝。
restart/open/audit/export 不需要伪造一份新的 statement：使用公开的
`load_fee_binding_trust_context_from_settings(settings=...)`，它会稳定读取并验证
当前 fee keyring、五个 file authority keyring、manual keys 和部署固定的历史
profiles，只签发 process-local replay capability，不读取 session/source/archive。

SHA256 仍只是完整性与拼接检测。fee statement 的事实责任来自独立 issuer 与
fee-only Ed25519 signature；本地 repository hash chain 没有外部 genesis/tip anchor，
不能自行证明完整历史未被同 owner 整体替换。

## Python API

```python
archive = load_settled_archive_replay_facts(
    path=archive_facts_path,
    expected_raw_sha256=archive_facts_raw_sha256,
)
archive, fee_binding, fee_trust_context = (
    load_and_verify_late_fee_correction_from_settings(
        settings=settings,
        statement_path=fee_statement_path,
        source_document_path=fee_source_document_path,
        expected_statement_raw_sha256=fee_statement_raw_sha256,
        archive_replay=archive,
    )
)
actual_v5 = build_actual_simnow_fee_bound_source_facts(
    archive_replay=archive,
    fee_binding=fee_binding.model_dump(mode="json"),
    fee_binding_trust_context=fee_trust_context,
)
```

严格 JSON Schema 可由 `CommodityCFastFeeStatementDTO.model_json_schema()`、
`CommodityCFastFeeStatementTrustedKeyringDTO.model_json_schema()` 与
`CommodityCFastFeeBindingEvidenceDTO.model_json_schema()` 导出。

## Offline CLI

先为五个 formal foreign-domain keyring 配置绝对路径和精确 raw SHA256 pin：

```text
COMMODITY_BASELINE_EXECUTION_PERMIT_TRUSTED_KEYRING_PATH
COMMODITY_BASELINE_EXECUTION_PERMIT_EXPECTED_KEYRING_RAW_SHA256
COMMODITY_C_FAST_SIMNOW_EXECUTION_PERMIT_TRUSTED_KEYRING_PATH
COMMODITY_C_FAST_SIMNOW_EXECUTION_PERMIT_EXPECTED_KEYRING_RAW_SHA256
COMMODITY_C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION_TRUSTED_KEYRING_PATH
COMMODITY_C_FAST_EXECUTION_QUALITY_RUNTIME_ADMISSION_EXPECTED_KEYRING_RAW_SHA256
COMMODITY_C_FAST_SIMNOW_RESEARCH_ACCEPTANCE_TRUSTED_KEYRING_PATH
COMMODITY_C_FAST_SIMNOW_RESEARCH_ACCEPTANCE_EXPECTED_KEYRING_RAW_SHA256
COMMODITY_C_FAST_SIMNOW_RESEARCH_KEYRING_PATH
COMMODITY_C_FAST_SIMNOW_RESEARCH_EXPECTED_KEYRING_RAW_SHA256
COMMODITY_C_FAST_FEE_STATEMENT_TRUSTED_KEYRING_PATH
COMMODITY_C_FAST_FEE_STATEMENT_EXPECTED_KEYRING_RAW_SHA256
COMMODITY_C_FAST_FEE_STATEMENT_HISTORICAL_TRUST_PROFILES_JSON
MANUAL_EXECUTION_PERMIT_TRUSTED_PUBLIC_KEYS_JSON
```

然后执行：

```bash
PYTHONPATH=backend python scripts/commodity_c_fast_fee_statement_verify.py \
  --archive-facts /private/cfast/archive-facts.json \
  --archive-facts-raw-sha256 <64-lowercase-hex> \
  --fee-statement /private/cfast/fee-statement.json \
  --fee-statement-raw-sha256 <64-lowercase-hex> \
  --fee-source-document /private/cfast/broker-fee-source.pdf \
  --output /private/cfast/actual-v5.json
```

production image 将该 verifier 作为受限 offline operator tool 打包，但不打包
任何 fee/research/execution signer 或私钥 loader。

output parent 必须已存在；output 必须不存在。写入使用 `O_EXCL`、0600、file
fsync 与 parent-directory fsync，不覆盖已有证据。工具不访问网络或交易接口。
fee keyring 的绝对路径和 raw pin 只能来自 Settings/deployment trust root，CLI
不能覆盖；Compose permit overlay 复用只读
`/run/c-fast-simnow/keyrings` mount，不新增可写 fee custody；
`verified_at_utc` 使用进程当前可信 UTC 时钟，不接受历史时间回填。

## Execution Impact

CLI 本身无 execution impact；成功仅表示本地证据可重放，它不会启用
`commodity_c_fast_simnow_auto_dispatch_enabled`，不会调用 gateway，也不会改变
order/position/database。terminal archive 路径的 callback linearization 影响见
Architecture Impact，但同样不授予交易 authority。

## Security Consideration

- 不保存账户原文、凭据、私钥或 token；keyring 只含 public key。
- statement/keyring/source/archive/foreign keyring 路径必须彼此不同。
- signature、lifetime、effective trading-day、source raw hash、exact archive join、
  foreign-domain key material 隔离均 fail closed。
- 费用签发者必须是能够为真实 broker/customer fee facts 负责的独立责任人；仓库
  代码、开发者或测试 fixture 不得合成真实 M2 fee evidence。

## Validation boundary

仓库 focused/full tests 可以证明 schema、replay、tamper/splice、partial/cancel/
reject/unknown 和 custody 逻辑。Issue #245 的最终 M2 验收仍需要一份真实、可追溯
的 SimNow/broker fee source document 和独立签发的 fee statement。没有该外部输入
时应继续报告 `UNBOUND_NOT_ASSUMED_ZERO`，不得宣称真实 all-in/net 已收口。
