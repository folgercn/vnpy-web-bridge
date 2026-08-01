# C_FAST execution-quality 只读 Tick fan-out

本文对应 Issue #217 在 PR #218/#222/#224/#226 之后的独立切片。它把 Web Bridge
已经收到的 Tick publication 复制到一个 default-off、本地 exact-contract filter，
再通过有界单线程队列交给 #224 的 `PreverifiedTickHorizonWorker`。它不发起上游行情
订阅，也不取得 RPC client、Gateway、TradeService、账户、仓位或订单能力。

## 既有合同审计

- #218 只提供 Settings、startup/reload/recovery revalidation receipt，成功状态仍为
  `REVALIDATED_FOUNDATION_ONLY_TICK_RUNTIME_NOT_BUILT`。
- #222 验证七件 exact signed artifact 和 custody join，但只返回 hash-bound receipt，
  不暴露或构造 worker 的 plan/policy/spec DTO。
- #224 的 horizon worker 已实现 durable plan registration、Tick/horizon sealing、
  duplicate/restart/missing-not-imputed；输入必须是 caller-preverified 强类型 DTO。
- #226 只有 status/reload/recovery API，不提供 start、execute 或 Tick mutation route。

因此本切片不能从 #222 receipt 猜测 plan/policy/spec，也不伪造 production worker。
production global fan-out 已接到现有 Tick publication hook，但默认关闭；开启 setting
却未先绑定 exact preverified worker/receipt 时固定进入 fail-closed blocked 状态。

## 数据路径

```text
existing vn.py pub Tick callback
  -> existing Tick persistence path (unchanged)
  -> copied local readonly listener payload
  -> C_FAST exact-contract identity filter
  -> bounded non-blocking queue
  -> strict CFastL1L5BookSnapshotDTO conversion
  -> PreverifiedTickHorizonWorker.accept_preverified_tick
  -> existing create-only durable sidecar/horizon sealing
```

`VnpyRpcService.bind_readonly_tick_listener` 只能在 source service 启动前绑定。listener
只收到 `dict` copy；不会收到 service/client handle。listener exception 会被 source path
隔离，不能阻止现有 Tick persistence、memory store 或 websocket 路径。

这不是 `subscribe_market`。fan-out 只消费现有 pub stream 中已经出现的 Tick，状态固定
`external_market_subscription_requested=false`。若上游未发布某个 exact contract，
本组件不会调用 RPC/Gateway 补订阅，也不会把缺 Tick 伪造成价格。

## exact-contract 与 preverified join

启动前必须调用 `bind_preverified_subscription`，同时提供：

- exact `CFastExecutionQualityRuntimeRevalidationDTO`；
- 已完整 durable-register plan/policy/spec 的 exact
  `PreverifiedTickHorizonWorker`。

fan-out 会重新校验 receipt，要求当前 UTC 位于 receipt window，并要求 worker status 的
`accepted_exact_contracts` 与 receipt 中 sorted exact set 逐字相等。绑定只允许一次且
不能在 worker thread 启动后热替换。绑定会冻结 worker 的 exact-contract set；冻结后
拒绝继续注册 plan，contract set 不能在 status 检查与 Tick append 之间扩张。每次入队
和每次 worker delivery 都重查 expiry、durable accepted set 与 frozen set。需要变更
合约集合时必须构造并重新 preverify 新 worker，不能在运行中的 worker 上热扩容。

Web Bridge 的 `vt_symbol` 使用 `symbol.EXCHANGE`，signed contract 使用
`EXCHANGE.symbol`。同时存在 symbol/exchange/vt_symbol 时三者必须 exact 一致；splice
会熔断本 fan-out。contract-set 外 Tick 在 DTO 构造和 journal append 前丢弃。

Tick 入队时生成本 fan-out session 内单调 `ingest_seq`、唯一 `ingest_id` 和 UTC
`received_at_utc`。exchange timestamp 必须自带 timezone 并转为 UTC。L1–L5 price
转为 plain decimal string，depth size 必须是非负整数值；vn.py 的 missing-level zero
price 明确转换为 `None`。NaN、Infinity、fractional/negative size、naive timestamp 和
invalid subscribed Tick 都会只熔断 C_FAST fan-out。

## 隔离和 authority

publisher thread 只执行 identity filter 与 `put_nowait`。sidecar I/O 在 C_FAST 专用
线程完成；queue full、DTO invalid、receipt expiry 或 worker failure 都进入
`BLOCKED_FAIL_CLOSED`，后续 Tick 拒绝，不向 source callback 抛错。

所有 status/offer 结果固定：

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

fan-out 模块只依赖 Settings、revalidation/snapshot DTO 和 preverified worker；静态测试
禁止 vn.py、RPC service、TradeService、Gateway、account/position/order、QuestDB 和
market repository import。

## 仍未完成

本切片没有生成真实 signed worker inputs。#217 仍需：

1. concrete production artifact verifiers，以及从同一 exact #222 custody generation
   安全构造 plan/policy/spec/worker 的 runtime adapter；
2. worker/journal root 的真实 root custody、restart/reload generation replacement 和
   status API join；
3. read-only evidence repository/QuestDB adapter、evidence export 和 monitoring；
4. 上游已具备所需 exact-contract Tick publication 的部署证明；
5. official M2 window 的真实签名、零订单 evidence 与 P0 acceptance。

因此 `execution_quality_implemented` 与 `runtime_active` 仍必须保持 false，不能关闭
#217 或 #114。

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_tick_fanout.py \
  backend/tests/unit/test_rpc_service.py

PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_horizon_worker.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_tick_fanout.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_runtime.py
```
