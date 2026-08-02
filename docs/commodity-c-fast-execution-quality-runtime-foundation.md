# C_FAST execution-quality runtime foundation

本文档记录 Issue #217 已合并的 runtime foundation，以及后续 production assembly
只读接线。它把 #144 的 pure scorer 与离线 durable sidecar 接到 **Settings、startup
生命周期、完整重验、immutable export、API 和 monitoring projection**；仍然不接入
真实 QuestDB adapter 或任何交易能力。

## 本切片交付

- 新增 `COMMODITY_C_FAST_EXECUTION_QUALITY_RUNTIME_ENABLED`，默认 `false`。
- Web Bridge startup 会调用独立 runtime；默认关闭时不调用任何 verifier，也不
  订阅行情。
- 配置为开启但未绑定完整 verifier 时进入
  `BLOCKED_FULL_REVALIDATION_VERIFIER_NOT_BOUND`，不会降级运行。
- startup、reload、recovery 三个生命周期入口每次都必须重新调用 verifier。
- verifier receipt 必须逐项绑定 signed P0 acceptance、collection admission、
  execution policy、signed snapshot、virtual intent plan、exact-contract spec
  set 与 custody pins，并绑定本次 trigger、UTC 时钟、有效期及 canonical hash。
- verifier 失败只把本 runtime 置为 `BLOCKED_FULL_REVALIDATION_FAILED`；不阻断
  baseline、其他 Shadow、行情持久化或 CommoditySimNow。
- shutdown 清除内存中的 revalidation receipt。
- 认证后的 viewer/trader/admin 可读取独立 status；只有 admin 可触发 reload
  或 recovery。API 不提供 start、execute、dispatch、order 或 position mutation
  路由，且两个 lifecycle mutation 仍只返回 fail-closed revalidation 状态。
- runtime enabled 时，进程在 FastAPI startup 前从两个独立的 absolute `0700`
  custody roots 固定构造既有 `CreateOnlyExecutionQualityJournal`、
  `OfflineExecutionQualitySidecar`、exact typed readonly repository 与
  `CreateOnlyExecutionQualityEvidenceExportStore`：

```text
COMMODITY_C_FAST_EXECUTION_QUALITY_JOURNAL_ROOT=
COMMODITY_C_FAST_EXECUTION_QUALITY_EVIDENCE_EXPORT_ROOT=
```

- 每个成功 lifecycle 都从同一个 sidecar fresh replay repository，并将同一 tip
  create-only 发布为 immutable export。repository 的 record count/tip 必须与 export
  receipt 完全一致；并发增长导致不一致时本次 lifecycle fail closed，API 不发布旧
  snapshot。
- `/intents`、`/execution-quality`、`/evidence-export` 均为只读 GET；仅当当前 runtime
  仍 started、receipt/admission 未过期、且当前 lifecycle generation 完整成功时可读。
  后续 reload/recovery 失败或 stop 后旧 snapshot 会返回 `503`，不能形成 stale-success。
- monitoring 增加独立 `c_fast_execution_quality` check；journal/repository/export 失败只
  产生 C_FAST sidecar incident，不触发 baseline、其他 Shadow、行情或 SimNow mutation。
- QuestDB evidence adapter 没有可信独立只读连接输入，因此保持明确
  `questdb_evidence_adapter_bound=false`，不复用行情写入 DSN 冒充只读 capability。

## 能力隔离

本模块只依赖 Settings 与自身的 revalidation schema，不导入或持有：

```text
TradeService
send_order / cancel_order
VnpyRpcService / Gateway
account / position
CommoditySimNow
```

所有 status 固定：

```text
execution_quality_implemented=false
runtime_active=false
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
orders_sent=0
positions_modified=0
```

即使设置 `COMMODITY_C_FAST_EXECUTION_QUALITY_RUNTIME_ENABLED=true`，完成当前
repository/export assembly 后仍只能进入：

```text
REVALIDATED_FOUNDATION_ONLY_TICK_RUNTIME_NOT_BUILT
```

这不是 runtime activation，也不能把现有 Shadow status 的
`execution_quality_implemented` 改为 `true`。

## verifier 接口边界

`bind_full_revalidation_verifier` 只接受一个只读 verifier callback。未来实现必须
独立读取并验证真实 signed artifacts、expiry/replay、exact-contract lineage 和
custody pins；本 foundation 只验证 callback 返回的强类型 receipt 与本次生命周期
调用一致，不能把 callback assertion 伪称为真实 M2 验收。

verifier 必须在 runtime start 前绑定且不能热替换。配置开启但缺 verifier、
receipt trigger/time 不匹配、过期、hash 不一致、authority literal 不为 false
时全部 fail closed。

## 后续 blocker

本切片后仍需独立 PR 完成：

1. 真实 signed P0 acceptance 与 collection admission consumer；
2. exact snapshot/plan/policy/spec/custody 的文件级完整 verifier；
3. 将现有 Tick fan-out、preverified horizon worker 与 production assembly 完整绑定；
4. 独立、可信的 QuestDB read-only evidence adapter（当前明确 unbound）；
5. M2 一个完整 execution window 的真实零订单证据。

在上述能力全部构建并经过真实验收前，
`execution_quality_implemented=false` 必须保持不变。

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_runtime.py

PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality.py \
  backend/tests/unit/test_commodity_c_fast_execution_policy.py \
  backend/tests/unit/test_commodity_c_fast_execution_policy_v2.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_scorer.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_runtime.py
```
