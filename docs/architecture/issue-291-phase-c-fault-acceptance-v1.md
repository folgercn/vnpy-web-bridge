# Issue #291 Phase C：离线故障验收合同 v1

状态：`offline_acceptance_only`。本合同只产生确定性、离线的故障验收 evidence bundle；不连接网络、Windows RPC、broker、部署环境或私钥，也不构成生产、真实交易或前向计数授权。

## 输入与边界

Harness 只能调用已经存在的 Phase A `LeaderFencer`、`ExecutionOrchestrator`、Windows `WindowsRpcFencedAdmissionV1` 及 Phase B `ArtifactCustody`。不得通过模拟实现放宽其 token、durable intent、unknown-outcome、restart 或 custody 语义。

补强 runner 还会启动独立 POSIX 子进程，以持久 `DurableExecutionRepository`
文件取得 lease；父进程会对旧 leader 发送 `SIGSTOP`、等待真实 lease expiry、
再发送 `SIGKILL` 并启动替代进程。Windows 边界仅是单次 loopback TCP 假件：
它记录实际连接后执行 connection reset 或 `SIGKILL`，从而让真实
`ExecutionOrchestrator` 在 durable intent 后进入 unknown outcome。它不是 Windows
RPC、不是 SimNow、不会访问任何外部网络。

输出必须符合：

* `docs/schemas/issue-291-phase-c-fault-scenario-v1.schema.json`
* `docs/schemas/issue-291-phase-c-fault-evidence-bundle-v1.schema.json`

所有输出固定为 `production=false`、`live=false`、`countable_forward=false`。

## 必须覆盖的失败模式

1. 双主、暂停旧 leader、lease 到期和 partition/rejoin：旧 epoch/token 在新 leader 取得 lease 后不能验证或 admission。
2. Windows 最终 admission 对 send 与 cancel 都拒绝 stale token，且 native handler 不被调用。
3. RPC timeout 进入 `HALTED_UNKNOWN_OUTCOME`；只能查询相同 intent，新 send 不重放。
4. durable state 不可写时 gateway 零调用；已持久化 active intent 的重启转为 unknown 并阻止 mutation，直到同 intent 对账。
5. 延迟/重复 callback 不得导致第二次 gateway mutation 或重复终态归档。
6. custody idempotency replay、receipt-chain tamper、TOCTOU/readback 类别均 fail closed。

## 判定与限制

每个 scenario 的 `status=passed` 仅说明离线 harness 已观察到指定拒绝或持久化状态。每条 evidence record 都携带 canonical SHA-256；timeline 由 record hash 顺序组成，bundle hash 还绑定去重后的 intent/receipt ID 与 gateway-event 计数。固定描述文字不是验收证据。任何失败都应使测试失败，不能输出部分通过 bundle。真实 Windows Gateway、SimNow、partial fill/cancel、生产部署、账户或交易状态不在本 Phase C 离线验收范围内，仍需单独受授权的最终验收证据。
