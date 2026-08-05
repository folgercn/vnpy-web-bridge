# Issue #291 Phase A：终态运行时分离合同 v1

- 状态：`contract_frozen_not_implemented`
- 目标：直接建立最终部署边界，不承担旧单体兼容或迁移链成本
- 关联：[#291](https://github.com/folgercn/vnpy-web-bridge/issues/291)
- 机器可读清单：`docs/architecture/issue-291-phase-a-ownership-v1.json`
- Control→Execution 命令 schema：`docs/schemas/web-bridge-control-execution-command-v1.schema.json`
- Execution 状态 schema：`docs/schemas/web-bridge-execution-status-v1.schema.json`

本文是 Phase A 的实现合同。它冻结模块 owner、进程入口、网络和卷边界、内部 typed command、Execution durable state、leader/fencing 以及 Frontend/Edge 反代与 Compose 拓扑。实现者必须以该合同为输入；若需要改变字段、owner 或安全语义，先更新合同并独立审查。

## 1. 直接终态决策

Issue #291 取代 #267 的渐进迁移路线。Phase A 不做：

- 旧 `web-bridge` 单体兼容层、双读、双写或 N-1 API 窗口；
- legacy state migration、旧服务名兼容、蓝绿/滚动切换；
- 生产部署、生产回滚、`production/live/countable_forward`；
- 让 Control API、Frontend 或普通 worker 继续持有交易 RPC；
- 以进程内变量、容器副本数或进程锁冒充 durable owner/fencing。

现有 `backend/app/main.py` 是拆分前的事实清单，不是 Phase A 的目标入口。最终不能通过再启动一个进程而保留两个 writer 或两个订单主体。

## 2. Phase A 部署单元与入口

| 单元 | 最终入口 | 监听 | Phase A 权限与 owner |
| --- | --- | --- | --- |
| `frontend-edge` | `nginx -c /etc/nginx/nginx.conf -g 'daemon off;'` | 宿主唯一 `8080` | 静态资源、SPA fallback、`/api`/`/ws` 反代；无数据库、RPC、secret、后台任务 |
| `control-api` | `uvicorn app.control_api:app --host 0.0.0.0 --port 8081 --app-dir backend` | 私网 `8081` | REST/WebSocket、认证/RBAC、配置、overview projection、审计索引、typed command issuer；无订单 RPC、执行状态 writer、私钥 |
| `execution-orchestrator` | `python -m app.execution_orchestrator` | 私网 `8090` | Linux 唯一 `send_order`/`cancel_order` 主体；持有 active plan、authority effective state、send intent、unknown outcome、对账、leader/fencing、terminal archive |
| `questdb` | 镜像默认入口 | 私网 `9000/8812/9009` | Tick 时序事实；仅数据库权限 |
| `postgres` | 镜像默认入口 | 私网 `5432` | Control 与 Execution 分 schema/role 的 durable records；不是订单主体 |
| `windows-ctp-gateway` | 外部 `VnpyRpcService` | `2014` 请求、`4102` 发布 | CTP session 与 broker facts、Windows durable fence；只接受 Execution 的 typed send/cancel |

每个单元必须提供独立 `/health/live`、`/health/ready`、`/version`（数据库和外部 Gateway 使用等价的原生/typed health）。Frontend 只发布宿主 `8080:8080`；Control/Execution/QuestDB/Postgres 不发布宿主端口。

## 3. 模块与状态 ownership

### 3.1 Control API

Control API 是用户和浏览器的唯一控制入口。它拥有用户、角色、typed config、审计索引和 command receipt projection。它只能构造并发送合同内命令，不能读取或修改 Execution durable state 的原始记录；状态通过 Execution 的只读 projection 返回并写入自己的审计索引。

Control API 明确禁止：

- 导入 `vnpy_rpc_service`、`TradeService`、CTP/SimNow send/cancel 方法；
- 持有 `WEB_TRADE_ENABLED` 以外的执行 authority 真相；
- 运行 Commodity auto worker、MAP/C_FAST producer 或签名私钥；
- 通过数据库直写 Execution schema 绕过 command API。

### 3.2 Execution Orchestrator

Execution 是 Linux 侧唯一交易权限主体。它负责验证已安装 artifact/authority、计划生命周期、下单前 intent、单笔 send/cancel、RPC callback、恢复对账和终态归档。每一次 broker mutation 都必须由 Execution 自己重新验证状态、版本、风险和 fencing，Control API 的 RBAC 不能替代这些检查。

Windows Gateway 是 broker facts 和最终 fencing admission 的 owner，不决定策略目标，不接受 Frontend/Control/MAP/C_FAST/Signer 的订单调用。

### 3.3 Frontend / data 与 Phase B 预留

Frontend/Edge 只拥有静态 asset version。Tick、Execution Quality、Monitoring、MAP、C_FAST、Signing、Artifact Custody 的最终 owner 已在机器清单中预留给 Phase B；Phase A 不把它们偷偷留在 Control API，也不以同一 FastAPI startup/shutdown 继续持有它们。

## 4. 当前 `main.py` 生命周期迁移清单

`docs/architecture/issue-291-phase-a-ownership-v1.json` 的 `current_app_main_lifecycle.entries` 是从 `origin/main` 精确提取的 20 个 lifecycle/binding call。每项只有一个目标 owner 和一个明确 transition：

- `rpc_service.bind_loop/start/stop` 与 Commodity plan lifecycle 移入 `execution-orchestrator`，但 provider binding 只能消费已验证 immutable artifact；
- `market_data_service`、`tick_persistence_service`、`monitoring_service`、Execution Quality、C_FAST Shadow 的进程内启动/停止全部 retire/replace 到 Phase B worker/producer；
- `commodity_c_fast_execution_permit_service.acceptance_evidence.bind_full_acceptance_verifier` 不再进入 Web/API/Execution 常驻镜像，改由 Signing/Trust Authority 的离线边界负责；
- `rpc_service.bind_readonly_tick_listener` 不得让 Execution 变成 Tick worker，改由 Data/Execution-Quality worker 订阅明确事件合同。

禁止只复制 `main.py`、保留旧 service singleton，再让两个进程同时调用同一 Trade/RPC/状态 writer。

## 5. Control→Execution typed command

私网 command endpoint 只接受 `web-bridge-control-execution-command-v1`。顶层字段固定为：

```text
schema_version
command_id
idempotency_key
correlation_id
issued_at (UTC Z)
actor { service=control-api, principal, operator, role }
command
expected { state_version, optional plan_hash/authority_hash/leader_epoch/fencing_token }
payload
```

允许的 `command` 只有：

`status`、`overview`、`preview`、`enable`、`revoke`、`start`、`stop`、`reconcile`、`drain`、`safe_to_restart`。

`send_order`、`cancel_order`、任意 gateway method、任意私钥操作都不是 Control command；它们只能是 Execution→Windows 的内部 typed RPC。每个命令都必须经过 JSON Schema strict validation，未知字段/命令拒绝。

### 5.1 幂等与审计

- 所有命令带 caller-supplied `idempotency_key` 与 `correlation_id`；Execution 以 `(service, idempotency_key)` 建唯一 durable receipt；
- mutating command 必须携带 `expected.state_version`，并在同一事务中 CAS；版本冲突返回当前 projection，不执行副作用；
- 超时只表示结果未知。Control API 必须用相同 key 查询 receipt，不得自动生成第二个 start/enable/plan/send；
- 每个 receipt 绑定 actor、command hash、expected version、result state version 和 observed time，Control 只保存只读 projection。

## 6. Execution durable state

Execution durable store（Postgres `execution` schema 或等价 root-owned state volume）至少包含以下唯一 writer：

| 状态 | writer | 强制语义 |
| --- | --- | --- |
| `active_plan` | Execution | 下单前/停止时原子更新，带 plan id/hash/version |
| `effective_authority` | Execution | enable/revoke 先持久化 fail-closed projection，再接受后续 mutation |
| `send_intent` | Execution | 每个 send/cancel 先写入 intent；intent id 永不重用 |
| `unknown_outcome` | Execution | timeout/连接断开进入 unknown；只能查询同一 intent 并对账 |
| `broker_reconciliation` | Execution + Gateway facts | restart 默认 frozen；fresh broker snapshot、活动委托、持仓和 pending outcome 对账闭合后才能 mutation |
| `terminal_archive` | Execution | 计划和 intent 终态 append/create-only；不可覆盖历史 |
| `leader_lease/epoch/fencing_token` | Execution lease store + Gateway admission | 单调 CAS，旧 owner 永久失效，不能仅靠内存锁 |

持久化失败、数据库不可判定、schema/version 未知、artifact receipt 缺失、时间回拨或状态 hash 不一致均进入 fail-closed；不允许把内存 projection 或“空状态”重建成可交易状态。

## 7. Single leader 与 send/cancel fencing

Execution leader scope 至少是 `account + environment`：

1. 在 durable lease store 上以 CAS 取得 `(owner_id, epoch, expires_at)`；epoch 严格递增且永不复用。
2. 每次 lease acquisition 生成严格递增 account-scoped `fencing_token`；旧 token 不能续租、send 或 cancel。
3. `active_plan`、checkpoint、每个 intent 与下游请求同时绑定 `leader_epoch`、`fencing_token`、`plan_id`、`plan_hash`、`intent_id` 和 `idempotency_key`。
4. Windows Gateway 最终 admission 对 `send_order` 和 `cancel_order` 都校验 token 当前、account scope、epoch、绑定的 D3/authority receipt（如适用）；应用内 lease、容器名或网络 principal 不能替代该校验。
5. lease 丢失、DB 不可用、网络分区、进程暂停后恢复、旧 token 或双主检测时立即拒绝 mutation；standby 仅可读。
6. 进程重启后先进入 `HALTED_RECONCILE_REQUIRED`，读取同一 durable state，查询 fresh broker snapshot，关闭 unknown outcome，再由新 leader 取得新 epoch/token。恢复期间不得 send/cancel。
7. RPC timeout、callback 延迟或连接重建不得新建业务 intent；只查询原 intent 的 broker outcome。未知 outcome 未关闭时，`safe_to_restart=false` 且所有新 mutation 拒绝。

## 8. Frontend / Edge 反代与 Compose 边界

Phase A Compose 合同文件为 `deployments/docker-compose.phase-a.yml`（实现由 integration worker 负责）。

```text
Browser
   |
   | host :8080
   v
frontend-edge (static + SPA fallback)
   | /api/* and /ws (HTTP/1.1 upgrade)
   v
control-api :8081  ---- private command ---->  execution-orchestrator :8090
       |                                          |
       +--> postgres (control schema)             +--> postgres (execution schema)
                                                  +--> Windows CTP Gateway
questdb <--------------- read/write by data worker only
```

硬边界：

- Edge 只代理 `/api` 和 `/ws`，保留 `Upgrade`/`Connection` header、超时和 correlation header；SPA fallback 只对非 API/WS 路径生效。
- Control API 与 Execution 只加入 `private-control` 内部网络；两者都不向宿主发布端口。
- Frontend image 不包含 `backend/`、`.env`、signing key、RPC client 或数据库 driver；backend images 不复制 `frontend/dist`。
- Control 与 Execution 使用不同 Postgres role/schema 和 distinct writable volumes；Execution durable state 对 Control 只读，Control 不能通过共享卷或 DB 直写执行状态。
- QuestDB/Postgres 不发布管理端口；Edge、Control、Execution 均按 allowlist 访问所需服务，未知网络默认 deny。
- 每个 service 的 health/readiness/version 独立可探针；Edge ready 不能掩盖 Execution 未 reconciled。

## 9. 并行实现边界

实现任务与非冲突路径已冻结在 manifest 的 `parallel_work_packages`。最小拆分如下：

| 任务 | 路径集合（不得越界） | 依赖 |
| --- | --- | --- |
| Contract/schema | `docs/architecture/issue-291-phase-a-*`、`docs/schemas/web-bridge-control-execution-*`、`docs/schemas/web-bridge-execution-status-*`、对应合同测试 | 无 |
| Frontend/Edge | `frontend/**`、`deployments/phase-a/frontend/**` | Contract |
| Control API | `backend/app/control_api.py`、`backend/app/api/control_*.py`、`backend/app/schemas/control_execution.py`、对应测试 | Contract |
| Execution | `backend/app/execution_orchestrator.py`、`backend/app/execution_state.py`、`backend/app/execution_fencing.py`、对应测试 | Contract |
| Compose/integration | `deployments/docker-compose.phase-a.yml`、`deployments/phase-a/Containerfile.*`、health、Phase A workflow | 四项实现完成 |

`backend/app/main.py`、根 `Dockerfile`、现有 production compose 不在上述并行实现路径中，除非 integration owner 在切分收口时取得主智能体明确授权；不能由单个子任务顺手改写旧单体兼容行为。

## 10. Phase A 验收门

合并 Phase A 前至少须证明：

- 前端、Control API、Execution 三个独立 process/image/health/version；宿主 `8080` 仅属于 Frontend；
- backend image 无 `frontend/dist`，FastAPI 无 SPA catch-all；Edge 深链、API、WS 反代均有合同测试；
- Control API 无账户/订单 RPC、无签名私钥；Execution 是 Linux 唯一 send/cancel 主体；Windows Gateway 对 send/cancel 执行最终 fencing；
- typed command 的 unknown field/command、expected-version 冲突、重复 idempotency key、timeout query-only、actor/correlation 审计测试通过；
- active plan、authority、send intent、unknown outcome、leader epoch/token、reconcile 状态可持久化并可重启恢复；
- 双主、旧 token、lease 丢失、RPC timeout、进程崩溃、网络分区均 fail closed；fresh broker snapshot 后才能恢复 mutation，且 unknown outcome 不重放；
- Compose config 只发布 Frontend，内部网络/role/volume/health 约束成立；生产/live/countable 始终为 false。

本合同本身不证明部署、重启、RPC、签名、私钥或 SimNow 验收已执行；运行证据留给后续受明确授权的 acceptance work。
