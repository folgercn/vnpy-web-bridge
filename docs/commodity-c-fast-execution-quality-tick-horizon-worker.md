# C_FAST 预验证 Tick horizon worker（code-only）

本文对应 Issue #217 在 artifact revalidation adapter 之后的最小并行切片。它只把
已经完成强类型预验证的 virtual intents 与 L1–L5 Tick 驱动到现有 create-only
durable sidecar；不接真实行情、运行启动或外部存储。

## Architecture Impact

- 所属 Plane：Research Plane。
- Authority 变化：无。
- 生产交易影响：无。
- 新增边界：调用方预验证输入与 durable sidecar 之间的同步 horizon 驱动器。

worker 不导入或持有 Settings、startup、QuestDB、API、RPC、TradeService、Gateway、
账户、仓位或订单能力。状态和每次操作结果始终保持：

```text
runtime_active=false
execution_quality_implemented=false
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

## 输入合同

`register_preverified_plan` 只接受已经构造成严格 DTO 的：

- `CFastVirtualIntentPlanDTO`；
- `CFastExecutionQualityCollectionPolicyV2DTO`；
- 与 plan 中 exact-contract 集合完全相等的
  `CFastExecutionQualityContractSpecDTO` tuple；
- 与 plan snapshot hash 完全一致的调用方 receipt hash。

worker 会把 DTO dump 后重新校验，拒绝 raw dict、缺失或额外 contract spec、重复
spec、snapshot/policy hash 错配和空 intent plan。这里的“preverified”是严格调用方
合同，不是 worker 自己完成了签名、P0、collection admission 或 custody 验证。生产
接线仍必须先重放 #222 的七件 artifact 链。

`accept_preverified_tick` 只接受 `CFastL1L5BookSnapshotDTO`。未被 durable intent
接受的 exact contract 会明确返回
`IGNORED_OUTSIDE_DURABLY_ACCEPTED_EXACT_CONTRACTS`，不会写入 journal。重复
snapshot 复用 sidecar 的 ingest/event/content 幂等规则；identity splice、时间回退
或内容冲突会 fail closed。

## horizon 与恢复语义

每次 accepted Tick 持久化后，worker 依 plan 内 intent 的 journal 顺序驱动：

```text
decision, 250ms, 1s, 5s, 30s, 60s
```

具体窗口、watermark、去重和 scorer 重放全部复用现有
`OfflineExecutionQualitySidecar`。窗口内没有可选 Tick 时只封存
`SEALED_MISSING_NOT_IMPUTED`，不 carry-forward、不补价。

`recover()` 会先完整恢复 create-only journal，拒绝缺 durable anchor 的半注册
intent，再用已经持久化的 watermark 补封 crash 前已 ready 的 horizon。已经存在的
evidence 不会重复追加。输入或 sidecar 错误会把 worker 置为
`BLOCKED_FAIL_CLOSED`；继续接收 Tick 前必须显式 `recover()`，或用同一完整
preverified plan/policy/spec 再次调用 `register_preverified_plan`。

多 intent plan 逐 intent 做 create-only durable append，不伪装成跨文件事务。若
第二个及后续 intent 在 I/O/进程故障中断，已经完成的 intent 保持不可变；调用方
必须重启 worker，并用**同一份完整 preverified plan/policy/spec 输入**重试
`register_preverified_plan`。既有 intent/anchor 会幂等复用，缺失 intent 才继续创建。
若故障留下“已有 intent 但无 anchor”，单独 `recover()` 会明确失败关闭；必须由同一
preverified plan 重放补齐，禁止 worker 从不完整 journal 猜测上游签名事实。
`register_preverified_plan` 是 blocked 状态下唯一允许的非 Tick 输入入口，因为它会
从头重验完整强类型集合；成功补齐全部 intent/anchor 后才解除 blocked。普通
`accept_preverified_tick` 在此期间始终拒绝。新建 worker 也不会只筛选已有 anchor
的 intent 后继续：每次 Tick 写入前都要求 journal 的 intent ID 集合与 anchor ID
集合完全相等；任一 orphan intent 会全局 fail closed，且该 Tick 不得落盘。

`status()` 如果无法恢复 journal，不会沿用旧计数或把状态报成健康；它返回
`BLOCKED_FAIL_CLOSED`，计数字段为 `null`，全部 authority 仍为 false。

## 尚未实现、不得宣称

本切片没有实现：

- signed P0 acceptance、collection admission 或其他 concrete verifier；
- Tick fan-out、exact-contract subscription、队列或线程生命周期；
- Settings/startup/reload/API/RBAC/监控；
- QuestDB/repository adapter 或真实 execution window；
- SimNow、订单、成交、仓位或 PnL。

因此不能修改现有 runtime 的 capability flags，也不能把 code-only 测试称为 T2
零订单 Shadow 验收。

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_horizon_worker.py

PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_horizon_worker.py
```
