# C_FAST 独立只读 Shadow

本文档对应 Issue #114 的 PR-B。当前接入只完成签名快照验证、独立连续性状态和只读 API；不包含 execution-quality scorer、虚拟 intent、PnL、SimNow shakedown 或任何下单能力。

## 冻结身份

- `candidate_id=C_FAST_CROSS_SECTION_NEUTRAL`
- `schema_version=commodity_c_fast_cross_section_neutral_shadow_v1`
- `frozen_rule_id=commodity_fast_tsmom_forward_freeze_v1`
- `fixed_rule_sha256=d9a6ef4ffb6d74fe0feee8ac8935acbeb79abd4686581611f14135eb5c41040a`
- 固定十品种：`ag, al, au, bu, cu, rb, ru, sc, sp, zn`
- 首个完整 source month：`2026-08`
- 首个 holding/execution month：`2026-09`

`fixed_rule_sha256` 对应 2026-07-17 冻结合同中的 canonical `fixed_rule`。该合同把 raw risk score 写为 `score / max(vol60, 0.05)`；早期实现出现过一个乘数 `0.10`，但它会在截面去均值和双边归一化中完全抵消。Bridge 按已封存哈希验证 `score / max(vol60, 0.05)`，不得借此改写冻结身份。20m 虚拟 NAV、guardband v2 与整数 allocator 由独立 lineage 字段绑定，不伪称属于上述 `fixed_rule_sha256`。

Bridge 固定核对 freeze contract、formula builder、target builder、historical fresh-exact runner、calendar authority、allocator、guardband runner 和 guardband manifest 的已知 SHA256。`historical_fresh_exact_runner_sha256` 只提供历史 lineage，不能被解释为 forward snapshot producer；冻结研究明确 future append runner 尚未实现，因此 schema 同时固定 `snapshot_producer_status=NOT_IMPLEMENTED_REQUIRES_SEPARATE_AUTHORITY`。每月 research manifest、allocation evidence、daily-roll evidence 和 reference-price source 的 SHA256 仍是可信 signer 的签名断言；PR-B 不读取这些外部研究文件，也不声称独立重放其内容。

## 安全边界

C_FAST 使用独立 schema、service、state 和 API，不复用：

- `CommoditySimNowService.current_plan`
- position-manager Shadow state
- position-manager shakedown session
- `TradeService`、`RiskService` 或完整 RPC service
- baseline 的 enable/dispatch/reconcile 状态

服务只接收一个只读 `get_all_contracts` 结果适配器，用来核对签名 exact contract 的 multiplier 和 price tick。它没有 `send_order`、`cancel_order`、持仓修改或 execution reference 能力。

所有状态固定返回：

```text
authority_granted=false
dispatch_allowed=false
replacement_allowed=false
dynamic_selection_allowed=false
production_allowed=false
snapshot_producer_status=NOT_IMPLEMENTED_REQUIRES_SEPARATE_AUTHORITY
```

`valid=true` 只表示输入快照通过 schema、签名、自洽性、连续性和 RPC 合约规格校验，不表示正式 forward producer 已实现或已获得授权。未来 producer 必须走独立 authority 与 schema 变更。

`GET /status` 只返回内存快照，不读文件、不写连续性状态、不调用 RPC。只有 admin `POST /reload` 会读取并重新验证签名快照；失败时当前状态变为 invalid，但不会覆盖最后一次已接受的独立 C_FAST state。`COMMODITY_C_FAST_SHADOW_ENABLED=false` 时 reload 只做 preview validation，不写 state/evidence；启用后才可接受快照。三条 C_FAST 路径必须互异，且不得与 baseline、position-manager snapshot/state/session 路径重合。

## 配置

```env
COMMODITY_C_FAST_SHADOW_ENABLED=false
COMMODITY_C_FAST_SHADOW_SNAPSHOT_PATH=
COMMODITY_C_FAST_SHADOW_STATE_PATH=logs/commodity-c-fast-shadow/state.json
COMMODITY_C_FAST_SHADOW_EVIDENCE_PATH=logs/commodity-c-fast-shadow/evidence.jsonl
COMMODITY_C_FAST_SHADOW_TRUSTED_PUBLIC_KEYS_JSON={}
```

生产环境启用时，snapshot path 和 C_FAST 专用 Ed25519 公钥集必须同时存在。该开关不依赖 `WEB_TRADE_ENABLED`，也不会改变该开关。

## 验证内容

reload 全部通过后才原子接受快照：

1. strict schema，未知字段 fail closed，NaN/Inf 禁止；
2. C_FAST 身份、冻结规则哈希和所有 authority literal；
3. Ed25519 signer key 与签名；
4. Bridge 重算的 `formula_target_binding_sha256`；
5. source month/day、input cutoff、snapshot created time、reference observed time、服务 wall clock 与 next-month execution 的可证明因果/月界；
6. 十品种完整唯一、固定 sector、exact contract 格式；
7. 21/63/126 sign 均值、vol60 floor、raw risk score；
8. signer 输出的 source target 是否满足 20%/35%/100% 和零净敞口；
9. signer 输出的 buffered target 是否满足 12%/27%/80% 和零净敞口；
10. 20m 整数手方向和 15%/35%/100%/10% 严格硬上限；
11. current/previous exact contract 的 RPC multiplier/price tick；
12. reference official open 的 observed time/source hash、LTD/DTE 与 following-DTE 算术；
13. genesis 和逐月 previous snapshot hash 连续性。

尚未进入 authoritative state 的新 snapshot 只能在其 execution day 首次接受，防止把事后回填误标为 forward。已经落入独立 state receipt 的同哈希快照可在后续重启时幂等重载；该豁免不允许新哈希或补月快照绕过首次接受窗口。

Bridge 不用实时行情重算 roll-safe trend，不重算截面 source/buffered target，也不重跑联合 beam allocator。状态明确显示：

```text
calendar_alignment=SIGNED_ASSERTION_NOT_RUNTIME_VERIFIED
allocator_output_validation=SIGNED_ALLOCATOR_OUTPUT_NOT_RECOMPUTED
pit_main_alignment=SIGNED_DAILY_ROLL_ASSERTION_NOT_RUNTIME_VERIFIED
contract_alignment=RPC_SPEC_VERIFIED
```

这意味着 RPC 只独立核对合约目录中的 multiplier/price tick；PIT OI main、官方 calendar mapping、LTD 权威性、daily roll transition 和联合 allocator 最优结果仍由固定 lineage 加当月 signer/evidence hash 负责，不能表述为 Bridge 已独立重放。

月度 snapshot 链只用 source month 和 previous snapshot hash 建链。逐品种 `previous_exact_contract/quantity` 作为签名 daily-roll transition 断言保留，不强行等同于上月 desired snapshot，避免把月内 PIT 换月误判为断链。

`reference_open_price` 只允许在 execution day official open 已观测后签入；因此 PR-B 是零订单 Shadow 输入验证，不是“在同一开盘价之前生成并发单”的授权。

独立 state 文件包含 checksum，是接受事实的 authoritative receipt；JSONL reload evidence 为附加审计记录，写入失败会在 status 中显式显示，但不会反向赋予或撤销任何执行权。

## 签名

研究侧先通过另一条独立授权的 producer 流程生成完整十品种 unsigned JSON，再使用独立签名工具：

```bash
PYTHONPATH=backend python scripts/commodity_c_fast_shadow_sign.py \
  --input /path/to/unsigned-c-fast-shadow.json \
  --output /path/to/signed-c-fast-shadow.json \
  --private-key-file /path/to/ed25519-private-key
```

私钥文件必须为 `0600` 或更严格。工具只验证并签署完整 JSON：它不会生成 signal、target 或 exact contract。它会先重算 `formula_target_binding_sha256`，再对不含 `signature` 的 canonical JSON 做 Ed25519 签名，并以 `0600` 原子写出结果。正式 forward producer 目前为 `NOT_IMPLEMENTED_REQUIRES_SEPARATE_AUTHORITY`，不得把该签名工具当作 producer。

## API

```text
GET  /api/commodity-simnow/c-fast-shadow/status
POST /api/commodity-simnow/c-fast-shadow/reload
```

GET 允许 viewer/trader/admin；reload 仅 admin。PR-B 不提供 start、execute、cancel、reconcile、intent 或 PnL 路由。

## T1 真实 QuestDB 边界

#118 已提供 L1–L5 审计器，但截至本 PR：

- 没有 2026-08 完整 source month 或人工签名的当期十品种 exact-contract manifest；
- 当前 QuestDB DSN 不是数据库权限强制的只读账号；
- 运行镜像不包含仓库 `scripts/`，不能在运行中容器内直接执行；
- 当前生产订阅证据只覆盖部分品种，十品种审计可能如实得到 `UNUSABLE`。

因此不得宣称 T1 已通过。正式 T1 必须使用独立只读 DSN、签名 release envelope 和隔离的临时只读容器，归档 deployed SHA/image、审计窗口、输出哈希和脱敏证据；不得在同一次审计中顺手修改订阅。

## T0

```bash
PYTHONPATH=backend python -m pytest -q \
  backend/tests/unit/test_commodity_c_fast_shadow.py \
  backend/tests/unit/test_commodity_c_fast_shadow_api.py
```
