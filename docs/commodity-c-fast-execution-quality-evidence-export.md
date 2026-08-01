# C_FAST execution-quality create-only evidence export

本文档对应 Issue #217 在 Tick fan-out 之后的独立 code-only 切片。它只把既有
create-only sidecar journal 做 fresh replay，投影为确定性的 intent、target 与 sealed
score evidence，并可发布到独立 `0700` custody root 中的 `0600` create-only JSON。

它不是 M2 execution window，也不证明 Tick 来自真实行情源。

## 剩余缺口审计

在本切片开始时，#217 尚有五类边界：

| 边界 | 当前状态 | 本切片 |
|---|---|---|
| repository / evidence export | sidecar journal 已有，缺稳定 generation、tip-bound export | 实现 |
| intents / execution-quality / export API | 只有 lifecycle status/reload/recover | 不接线 |
| monitoring | 没有 C_FAST fan-out、journal、export 独立 checker | 不接线 |
| durable restart / generation | snapshot/evidence 可 replay，但 fan-out freeze 只在进程内 | 实现 export generation 与历史 prefix replay；不宣称完成 runtime generation admission |
| M2 real window | 没有 deployed SHA、真实 signed runtime admission 或外部零订单验收 | 明确保持未验收 |

选择 export adapter 是因为它可以独立验收：输入只有已经完成 fresh replay 的本地
sidecar，输出只有 canonical evidence artifact，不需要 API、QuestDB、RPC、Gateway
或交易能力。后续 API 与监控可以消费同一个强类型 DTO，避免各自重新解释 journal。

## generation 与 journal tip

`generation_id` 稳定绑定：

- journal custody root path hash 与当前目录 identity hash；
- 单一 preverified plan hash 与 source snapshot receipt hash；
- exact-contract set；
- 按 plan expected intent order 排列的 intent record hashes 与 anchor record hashes。

同一 generation 后续追加 Tick 或 sealed evidence 时，generation 不变，journal tip 与
`export_sha256` 改变。export 同时绑定 ordered journal record hash index、记录分类计数、
每个 intent 的六个 target 状态，以及每条 sealed score 的 snapshot record hash 引用。

`OfflineExecutionQualitySidecar.recover_at_tip` 会在完整 journal fresh recovery 后，只对
指定 record count 与 exact tip 的历史前缀再次运行语义 replay。因此 collection 继续
追加后，旧 create-only export 仍可对原 tip 验证；不存在的 tip、错误 count、tamper 或
cross-journal splice 会 fail closed。

## create-only export custody

`CreateOnlyExecutionQualityEvidenceExportStore` 要求调用方预建独立绝对路径：

- 目录必须为当前用户持有的真实目录，权限精确为 `0700`；
- export root 与 source journal root 不得相同、互为父子目录；
- `.export.lock` 必须为当前用户持有的 `0600` 单链接普通空文件；
- artifact 名称只由 generation hash 与 source journal tip 构成；
- JSON 使用 canonical encoding、`O_EXCL + O_NOFOLLOW`、`0600`、file fsync 与 directory
  fsync，不覆盖已有 bytes；
- 同 generation/tip 重复发布 exact bytes 返回 `ALREADY_PRESENT`；不同 bytes 冲突；
- source 在写入期间可以继续前进；artifact 只绑定 build 时 fresh-recover 得到的 exact
  tip，之后仍按该历史 prefix 验证，不宣称是 API 返回瞬间的 latest tip。

## 事实和权限边界

export 固定声明：

```text
source_verification_scope=FRESH_REPLAY_OF_PINNED_LOCAL_CREATE_ONLY_JOURNAL_AT_EXPORT
self_contained_replay_state=NOT_SELF_CONTAINED_REQUIRES_PINNED_SOURCE_JOURNAL
external_custody_anchor_state=NOT_PROVIDED_CODE_ONLY_LOCAL_JOURNAL
signed_runtime_revalidation_binding_state=NOT_INCLUDED_REQUIRES_RUNTIME_ADAPTER
real_tick_source_attestation_state=NOT_INCLUDED_LOCAL_JOURNAL_CANNOT_PROVE_SOURCE
m2_acceptance_state=NOT_EVALUATED_REQUIRES_REAL_SIGNED_EXECUTION_WINDOW
real_execution_window_verified=false
zero_order_t2_evidence_accepted=false
execution_quality_implemented=false
runtime_active=false
orders_sent=0
positions_modified=0
```

所有 collection、activation、dispatch、order、position、database、deployment、
replacement 与 production authority 均为 `false`。本模块不导入 Settings、main、
QuestDB、VnpyRpcService、TradeService、Gateway、account 或 position capability。

`ALL_TARGETS_SEALED_LOCAL_JOURNAL_ONLY` 只说明该本地 journal 的 decision 与
250ms/1s/5s/30s/60s target 均已 sealed。它不能替代真实 signed M2 window、部署 SHA、
外部 custody anchor 或零订单 T2 acceptance。

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_evidence_export.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_horizon_worker.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_tick_fanout.py
```
