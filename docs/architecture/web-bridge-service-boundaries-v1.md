# ADR：Web Bridge 服务边界与状态所有权 v1

- 状态：Proposed
- 日期：2026-08-04
- 关联 Issue：[#267](https://github.com/folgercn/vnpy-web-bridge/issues/267)
- 关联文档：`docs/architecture/vnpy-web-bridge-architecture-v1.md`、`docs/architecture/authority-model-v1.md`
- 配套机器清单：`docs/architecture/web-bridge-deployment-ownership-v1.json`
- 实施路线图：`docs/architecture/issue-267-migration-and-acceptance-v1.md`

### 适用与覆盖范围

本 ADR 是 Issue #267 服务边界、状态所有权和部署边界的上位决策。它补充并在以下范围覆盖既有 `vnpy-web-bridge-architecture-v1.md` 与 `authority-model-v1.md` 中“C_FAST 永久属于 Research/Control Plane”或“C_FAST 永久属于 Research Plane”的笼统表述：

- C_FAST allocation producer 属于 Research Plane，只生成候选分配 artifact，无账户、RPC 和订单权限；
- C_FAST Acceptance、Runtime Authorization 和 Permit 的判定属于 Control/Authority Plane，不属于 producer；
- C_FAST Execution Quality 的事实采集、时序存储和观测属于 Data & Observability，不能升级为策略授权或订单权限；
- 只有 Execution Orchestrator 可以消费已验证的 C_FAST 目标与授权并发起订单。

既有文档的 fail-closed、权限逐级提升和 Research 不得直达 Execution 原则继续有效；若分类文字与本 ADR 冲突，以本 ADR 为准。

## 1. 背景

当前 Linux 部署虽然已经把 QuestDB、PostgreSQL 和 Windows CTP Gateway 分开，但应用能力仍集中在一个 `web-bridge` 镜像和一个 FastAPI 进程内：

- 根 `Dockerfile` 先构建 `frontend/`，再把 `frontend/dist`、`backend/`、`shared/`、签名验证脚本和 JSON Schema 一并复制到 Python runtime；
- `backend/app/main.py` 同时注册 REST/WebSocket、提供 SPA 静态文件，并在 startup/shutdown 中管理 RPC、Tick persistence、Monitoring、C_FAST Shadow、Execution Quality 和 CommoditySimNow；
- `deployments/docker-compose.prod.yml` 只把 `web-bridge` 作为应用部署单元，并由它暴露宿主端口 8080；
- PR 1-guard 前的 `.github/workflows/cd.yml` 会将 `frontend/**`、`backend/**`、根 `Dockerfile` 和 `deployments/**` 等变化统一分类为 `web-bridge` 镜像变化；该 workflow 已在 PR 1-guard 删除，PR 1-pre 前禁止自动或手工替换 legacy `web-bridge`；
- `scripts/deploy.sh` 只允许部署 `web-bridge`，因此纯前端发布也会替换承载交易相关内存状态和后台循环的容器；
- `deployments/docker-compose.c-fast-execution-quality.yml` 和 `deployments/docker-compose.c-fast-simnow-permit.yml` 继续通过 Compose overlay 把执行质量、artifact、keyring 和 SimNow 配置注入同一服务。

这种组合扩大了发布故障域和权限域。UI、API、研究生产器、签名授权和下单执行的代码变化不应互相触发重启，也不应共享同一组凭据、网络能力或可写状态。

## 2. 决策

系统按部署故障域、权限边界和状态所有权拆分为九个逻辑层。逻辑层不等于必须立即引入九个常驻网络服务；MAP、C_FAST 和 Signing 优先采用独立批处理镜像、离线工具和 immutable artifact 交接。

```text
Browser
   |
   v
Frontend / Edge -----> Control API --------------------------+
   |                       |                                  |
   |                       v                                  |
   |                 Artifact metadata                        |
   |                                                          |
   +-- /api, /ws             MAP Producer -> C_FAST Producer  |
                                      |             |         |
                                      +------v------+         |
                                      Signing Authority       |
                                              |               |
                                              v               |
                                      Artifact Registry       |
                                              |               |
                                              v               |
                                      Execution Orchestrator <-+
                                              |
                                              v
                                      Windows CTP Gateway

QuestDB / PostgreSQL / archive / audit / metrics support all layers
without granting research or control components order authority.
```

所有权限默认拒绝。研究结果只能沿正式 artifact 和授权链单向进入执行层；任何服务都不能通过共享数据库、共享可写目录或内部便捷调用绕过边界。

## 3. 九层目标边界

| 层 | 目标部署单元 | 职责 | 明确禁止 | 状态所有权 |
| --- | --- | --- | --- | --- |
| 1. Frontend / Edge | `frontend` | Vue 静态资源、SPA fallback、TLS 终止、安全响应头、静态缓存、`/api` 和 `/ws` 反代 | 后台任务、服务端 secret、签名私钥、订单 RPC | 仅静态资源版本；浏览器 token 属于客户端会话，不构成服务端 authority |
| 2. Control API | `control-api` | REST/WebSocket、认证、RBAC、typed config、overview projection、artifact metadata、审计查询、显式控制命令 | 直接 `send_order`、持有订单 RPC、运行 MAP/C_FAST、持有私钥、以进程内变量保存持续授权 | 用户/RBAC、配置版本、审计索引、命令 receipt；应持久化到 PostgreSQL 或正式 custody |
| 3. MAP Strategy Producer | `map-producer` batch/job | 读取批准的数据快照，生成 canonical MAP signal，记录策略、参数、数据和镜像 identity | 账户、持仓、活动订单、TradeService、Windows RPC | 单次 job 输入、输出和运行 receipt；输出后 immutable |
| 4. C_FAST Allocation Producer | `c-fast-producer` batch/job | 消费已批准 MAP signal，完成品种、手数、合约和换月分配，生成 executable target candidate | 查询账户或活动委托来反推目标、订单 RPC、直接安装授权 | 单次 allocation 输入、candidate、校验 receipt；与 MAP 使用独立 identity 域 |
| 5. Signing & Trust Authority | signer、本机 agent 或 HSM | Research、MAP Acceptance、C_FAST Acceptance、Runtime Authorization、Execution Permit 的分域签名 | 对浏览器或普通网络公开私钥接口；把私钥复制到普通镜像、环境变量、日志或 artifact | 私钥、key version、signing audit；各签名域独立 keyring 和 signer role |
| 6. Artifact Registry / Custody | `artifact-authority` 或严格权限的 root-owned volume | create-only 保存 artifact、hash、schema、lineage、consume/revoke/install receipt，提供受控读取和原子安装 | 覆盖历史 artifact、多个无约束 writer、下单 | canonical/raw hash、predecessor chain、安装状态、receipt；必须 durable |
| 7. Execution Orchestrator | `execution-orchestrator` | 验证 target/acceptance/authorization，plan、send intent、close、reconcile、terminal archive；Linux 侧唯一订单主体 | 生成研究结果、签署授权、双主执行、在 unknown outcome 时重放 send | active plan、authority、send intent、订单关联、对账事实、恢复状态、leader epoch/fencing token |
| 8. Windows CTP Gateway | `VnpyRpcService` | vn.py/CTP/SimNow 会话、typed RPC 查询、单笔下单撤单、回传 broker facts | MAP/C_FAST、Acceptance、Web 控制逻辑、推断策略目标 | CTP session、broker order/trade/position facts；不拥有策略 authority |
| 9. Data & Observability | QuestDB、PostgreSQL、archive、monitor worker | Tick/Execution Quality 时序数据、控制元数据、审计、归档、指标和告警 | 通过数据库写入伪造 artifact/authority、向执行层派单 | 各数据集按 schema 和 writer 划分；监控只观察和告警 |

## 4. 故障域

部署单元必须能独立构建、发布、回滚和观测。一个单元失败时，不应通过不必要的进程重启传播到其他单元。

| 变化或故障 | 允许受影响 | 不得受影响 |
| --- | --- | --- |
| 前端资源或 Edge 配置 | `frontend` 连接和静态缓存 | Control API、RPC generation、后台 worker、Execution active plan |
| Control API route、RBAC 或 Web projection | API 请求和 WebSocket 客户端重连 | Execution leader、send intent、MAP/C_FAST job |
| MAP 代码或 job 失败 | 当前 MAP run 和候选 artifact | Control API、C_FAST 已批准版本、Execution |
| C_FAST allocator 变化 | 当前 allocation run 和候选 target | MAP identity、Control API、Execution 已安装 target |
| signer 更新或离线 | 新签名请求 | 已安装有效授权和正在执行的计划；不得自动降级为未签名输入 |
| custody 不可用 | 新安装、consume/revoke receipt | 不得猜测 authority；Execution 必须按合同 fail closed |
| Execution 发布或崩溃 | Execution 本身 | Frontend、Control API、研究任务；恢复不得重复下单 |
| Windows Gateway 断开 | Broker RPC 与 Execution 状态 | 研究、签名和历史 custody；Execution 转入阻塞/对账状态 |
| QuestDB/PostgreSQL 故障 | 对应数据能力 | 不得自动扩大订单权限；关键 durable state 不允许静默丢失 |

前端和 Control API 可采用滚动或蓝绿发布。Execution 不采用普通无条件滚动发布：有活动委托、unknown outcome、未完成对账或未持久化 checkpoint 时必须阻塞替换。

## 5. 权限域

### 5.1 网络与凭据

- Frontend 只能访问 Control API 的公开 HTTP/WebSocket 入口，不连接 Windows RPC、数据库管理端口或 signer；
- Control API 只能调用 Execution 的私有 typed command API，不拥有 Windows trade RPC 凭据；
- MAP/C_FAST 只读批准的数据输入并写入各自受控输出，不读取账户凭据、SimNow 凭据或订单 endpoint；
- 只有 Execution Orchestrator 的运行身份允许访问 Windows Gateway 的交易方法；网络 ACL 还应在主机侧限制来源；
- Data/Observability 的读写 principal 按数据集最小授权，不能因能写 PostgreSQL 就获得 authority；
- 公钥/keyring 可以按角色只读分发，私钥不能进入 Frontend、Control API、MAP、C_FAST、Execution 或普通 CI payload。

### 5.2 签名私钥边界

签名动作必须发生在独立 signer、本机受控 agent 或 HSM 中。Web 只生成 canonical signing request 和接收 signed artifact，不读取私钥路径或私钥内容。

Research、Acceptance、Runtime Authorization 和短时 Execution Permit 使用不同的 key domain、signer role、trusted keyring 和审计记录。某一 key domain 被撤销或轮换时，不得隐式影响其他域，也不得复用旧签名绕过 predecessor、账户、品种、风险范围或有效期绑定。

现有 `scripts/commodity_*_sign*.py`、相关 `docs/schemas/*trusted-keys*.schema.json` 和 Compose keyring 只读挂载是迁移输入，不代表签名工具可以继续打入长期 Web/API/Execution 镜像。拆分时必须保持现有 verifier 的 canonicalization、raw/canonical SHA256、pin、schema 和 fail-closed 语义。

## 6. 状态所有权

每类可变状态必须只有一个权威 writer。缓存和 projection 可以重建，不能反向成为 authority。

| 状态 | 权威 owner | 持久化与恢复要求 | 非 owner 行为 |
| --- | --- | --- | --- |
| 用户、角色、typed config、审计索引 | Control API | PostgreSQL，带版本和审计 | Frontend 仅展示；Execution 不修改用户权限 |
| MAP signal | MAP Producer 是唯一 creator/writer；Custody 只做 durable custodian | immutable artifact，记录 producer/code/data identity | C_FAST 只消费已批准版本 |
| C_FAST target candidate | C_FAST Producer 是唯一 creator/writer；Custody 只做 durable custodian | immutable artifact，记录 MAP predecessor 和 allocation identity | signer/Control 不重算 target |
| Signed target、Acceptance、Authorization、Permit bytes | 对应 key domain 的 Signing Authority 是唯一 creator；不得直接 install/enable | 原子 submit、create-only、hash/schema/lineage/expiry | Control/Execution 只生成请求、验证或消费 |
| Installed artifact 与 install/consume/revoke receipt | Artifact Registry / Custody 是 receipt 唯一 writer | durable、原子安装；Execution 只提交带 fencing/idempotency 的 consume request 并等待 pinned receipt | 共享挂载不得任意覆盖 `current` 文件；Execution 不直接写 receipt |
| Runtime Authorization effective enabled/expired/revoked state | Execution Orchestrator 是唯一 effective-state writer | restart-safe durable state；每次计划与下单前重验 installed artifact 和 receipt | Control API 只发幂等 enable/revoke/revalidate command 并读取 projection；Signer 只产 immutable bytes |
| Active plan、send intent、unknown outcome、reconcile 状态 | Execution Orchestrator | 下单前 durable write；崩溃恢复可判定；terminal 后 archive | Control API 只能发幂等命令并读取 projection |
| Broker orders/trades/positions | Windows Gateway/CTP 是事实 writer；Execution 只持久化关联 projection | 每次恢复必须重新查询并对账 | 研究层不能用账户事实改变策略目标 |
| Tick/Execution Quality | Tick worker/QuestDB | spool、backpressure 和 replay 规则保持兼容 | API 只查询；Execution 不篡改历史数据 |
| Monitoring incidents | monitor worker | 可恢复状态、独立告警去重 | 业务服务只暴露 health/metrics/facts |
| Legacy restart external high-water | 独立 external witness 是唯一 writer | deployment volume/snapshot 域外 append-only CAS；记录 sequence、predecessor、exact activation head 与 ceremony signer/key/two-person approval | Web Bridge 只能提交绑定记录和 readback，不能覆盖或自种空 witness |
| Target runtime identity/lease | M2 host observer 是唯一 writer | root-owned host store；container/image/config/boot/mount/network exact identity 与短 TTL CAS lease | 目标容器不得自证、续租或访问 observer credential |
| Frozen bootstrap attempt | M2 bootstrap coordinator 是唯一 writer/executor | root-owned create-only attempt journal；只能 stop exact old runtime、start exact receipt-bound immutable target、查询同一 attempt | target/container/Web Bridge 不持有 runtime-control credential；崩溃不得另起 replacement |
| Baseline target manifest | 独立 target-manifest signing key domain 是唯一 creator | 双人离线 ceremony 后 create-only custody；与 runtime authorization key 隔离 | Web Bridge/host observer 只能验签和绑定，不能生成 manifest |
| Windows staged/active fencing token | Windows Gateway durable fence store 是唯一 writer | STAGED 永远被 send/cancel 拒绝；D3 CAS 原子永久撤旧并激活绑定 exact grant receipt/hash 的 target token | Linux 只能以 typed stage/query/activate 调用，不能覆盖 store 或把 timeout 当失败 |
| Conditional authority grant | 当前唯一 Commodity owner；Phase 2 后为 Execution Orchestrator | host custody create-only intent/receipt；pre-CAS 单独无效，post-CAS 从 Windows exact receipt恢复 projection | INITIAL/LEGACY 不得恢复旧 authority；Control/API/observer/witness 不得写 grant |

当前 `backend/app/main.py` 中由同一进程拥有的 `rpc_service`、`tick_persistence_service`、`monitoring_service`、`commodity_c_fast_shadow_service`、Execution Quality assembly 和 `commodity_simnow_service` 必须在后续迁移中逐项指定新 owner。未完成 durable migration 前，不得仅通过启动第二个进程来“拆分”，否则会形成双 writer 或双主。

## 7. 三类通信平面

### 7.1 Artifact Plane

MAP → C_FAST → Signing → Custody 优先通过 immutable canonical artifact 交接：

```text
MAP signal
  -> C_FAST executable target candidate
  -> signed target / Acceptance / Runtime Authorization / Permit
  -> install / consume / revoke receipt
```

每个 artifact 必须声明 schema/version、producer identity、canonical/raw hash、predecessor/lineage、生成时间和适用范围。发布必须原子化，历史版本 create-only；消费者只能按明确版本/hash 读取，不能依赖目录中“最新文件”的竞态结果。

### 7.2 Control Plane

Control API → Execution Orchestrator 使用私有 typed command API，至少包含 status/overview、preview、enable/revoke、start/stop、reconcile、drain 和 safe-to-restart。

每条有副作用的命令必须带 expected version/hash、idempotency key、调用主体和 correlation ID，并生成 durable audit receipt。超时表示结果未知，不表示命令未执行；调用方必须查询结果，不能自动重复派发。

传输应使用本机私有网络并逐步采用 mTLS 或等价的双向身份认证。Control API 的 RBAC 不能替代 Execution 自身对 artifact、状态、版本和风险边界的验证。

### 7.3 Execution Plane

Execution Orchestrator → Windows Gateway 使用私有 typed RPC。每个订单动作绑定 plan ID、intent ID 和 correlation ID，并保持 send-intent-first、unknown-outcome no-replay、先平后开、持仓/活动委托对账和 terminal archive 规则。

RPC timeout、连接重建或 Control API 重试均不得生成第二个业务 intent。Windows Gateway 返回 broker facts，不决定策略目标和授权。

## 8. Single leader 与 fencing

Execution Orchestrator 在任何账户和环境范围内只能有一个 active leader。仅依赖 Compose 实例数、进程锁、容器名或“通常只启动一个”不足以证明 single leader。

目标实现必须包含：

1. durable leader lease，明确 owner、scope、epoch、expires_at 和 heartbeat；
2. 每次取得领导权生成单调递增 fencing token；
3. send intent、active plan、checkpoint 和下游执行请求绑定 fencing token；
4. lease 失效、数据库不可判定、token 落后或恢复对账未完成时 fail closed；
5. standby 只能读和准备，不能发送、撤销或重放订单；
6. planned restart 必须先原子进入 `DRAINING` 并拒绝新 command/plan，再签发短 TTL preflight receipt；receipt 绑定 execution epoch、plan version、active-order snapshot、nonce 和 checkpoint hash，部署前必须二次核验；
7. 双实例、网络分区、时钟偏差、进程暂停和旧实例恢复必须进入故障演练。

Windows Gateway 或位于它之前、且旧进程无法绕过的独占执行代理必须对每个 `send_order`/`cancel_order` 强制校验 account-scoped 单调 fencing epoch/token。仅靠应用内 lease、durable journal、容器名或共享网络 principal 不能阻断暂停后恢复的陈旧进程。该最终执行边界校验是 Phase 2C 切换唯一订单权限前的硬门禁；未落地时只能运行 shadow，不能声称 stale leader 已被 fenced。

## 9. 发布与回滚原则

- changed-file classifier 必须输出明确 release plan，列出构建镜像、部署服务、预期重启和禁止重启的服务；
- `frontend/**` 只构建和部署 Frontend；后端容器 ID、启动时间、RPC generation、authority 和 active plan 必须不变；
- Control API 变化不能替换 Execution；MAP/C_FAST 各自只重建对应 producer；
- shared schema 或跨服务合同变化按依赖矩阵联合构建，并提供兼容窗口；
- 每个镜像使用独立 tag 和 digest，回滚只切换对应部署单元；
- Frontend 静态资源使用内容 hash，入口 HTML 不长期缓存，允许快速回滚；
- Execution 发布前必须完成原子 drain 并取得上述绑定 epoch/plan/order snapshot/nonce/checkpoint、短 TTL 的 safe-to-restart receipt。active、unknown、reconcile-required、receipt 过期或二次核验不一致时 CD 阻塞；失败后必须显式保持或解除 drain，不能通过普通 UI/CD 变化绕过；
- signer 默认人工或离线发布，不随普通 CD 自动更新；
- 部署失败不得自动回滚到可能不理解当前 durable state/schema 的旧 Execution 版本；回滚同样需要兼容性检查和安全窗口；
- 每个服务暴露独立 liveness、readiness、version、metrics。聚合入口健康不能替代各服务健康。

## 10. 迁移顺序

### Phase 0：架构合同

维护本 ADR、权限矩阵、状态所有权和文件到部署单元的 ownership 清单；对 `backend/app/main.py` 的每个 startup/shutdown owner 建立迁移去向。

### Phase 1：Frontend 独立部署

建立独立 Frontend 镜像和 Edge 反代；根后端镜像不再复制 `frontend/dist`；FastAPI 删除 SPA catch-all；Compose 仅由 Frontend 暴露宿主 8080，Control API 使用内部端口；CD 证明 frontend-only 发布不重启任何后台业务。

Phase 1 可暂时保留 Compose 服务名 `web-bridge` 作为内部 Control API 的兼容名，避免立即破坏 `deployments/docker-compose.c-fast-*.yml`、private overlay、`scripts/deploy.sh`、watchdog 和现有运行手册。服务重命名必须作为显式兼容迁移，不得混在静态拆分中暗改。

### Phase 2：Control API 与 Execution 分离

先迁移 durable active state、single leader/fencing、typed command 和恢复合同，再移动 CommoditySimNow、交易 RPC ownership 和 continuous execution worker。Phase 2 使用现有 custody 的只读、version-pinned compatibility adapter，唯一旧 writer 保持不变；Phase 4 再切换到独立 Registry/Custody。禁止先复制进程再补状态合同，也禁止为了提前切 Execution 而绕过现有 verifier/custody。

### Phase 3：MAP 与 C_FAST Producer 分离

建立两个独立 producer identity/image/job，只通过 canonical artifact 交接，删除它们对账户、TradeService 和 RPC 的依赖。

### Phase 4：Signing、Trust 与 Custody 分离

私钥迁入独立 signer/agent/HSM；Control API 只管理 signing request 和 signed artifact 上传；custody 实现原子、create-only 和 receipt 链。

### Phase 5：Monitoring 与 Data Worker 分离

按状态 owner 拆出 Tick persistence、Execution Quality fanout 和 monitoring worker，使 API 重启不影响 ingestion、spool 和告警。

### Phase 6：发布安全与 HA

Frontend/Control API 支持蓝绿或滚动；Execution 支持 fenced single-active、checkpoint handoff、阻塞式安全窗口和完整故障演练。

## 11. 兼容约束

拆分是部署边界变化，不授权修改以下既有安全语义：

- production/live/countable_forward 保持 false，Phase 迁移不等于开通生产交易；
- 现有 signed artifact、JSON Schema、canonical serialization、hash、key pin、predecessor 和 receipt 必须保持可验证；需要新版本时使用显式 schema/version 和兼容读取窗口，不能原地改变旧语义；
- 保留账户 hash、品种/手数/风险范围、有效期、Acceptance 和 Runtime Authorization 的精确绑定；
- 保留 send-intent-first、timeout/unknown outcome 不重放、先平后开、持仓与活动委托对账、restart recovery 和 terminal archive；
- QuestDB、PostgreSQL、Tick spool、历史 archive 和 audit 数据在迁移中不得丢失或由新 owner 静默重建为不同含义；
- API/WebSocket 合同发生不兼容变化时，Frontend 与 Control API 必须有联合发布或前后兼容窗口；
- 跨服务重试必须由 idempotency key、expected version、receipt 或 correlation ID 防重；
- 共享目录从当前 Compose 挂载迁移时，先定义唯一 writer、目录权限、原子 publish 和 version pin，再允许多个服务读取；
- Windows `VnpyRpcService` 的部署和防火墙边界独立于 Linux CD，不因本 ADR 自动变化。

## 12. 非目标

- 不拆分仓库；
- 不立即引入 Kubernetes 或服务网格；
- 不把每个 Python 模块改造成网络微服务；
- 不要求 MAP、C_FAST 和 signer 成为常驻 HTTP 服务；
- 不在 Frontend 独立 PR 中同时重构 Control/Execution 状态机；
- 不把签名动作做成普通 Web API；
- 不通过扩大 CORS、开放数据库/RPC 端口或共享高权限凭据来简化通信；
- 不在本 ADR 中开启生产交易或降低现有 SimNow/签名/对账安全检查。

## 13. 验证要求

每个迁移 Phase 至少提供以下证据：

1. changed-file classifier 对该部署单元和共享合同的选择正确；
2. 发布前后未目标服务的 container ID、StartedAt、image digest 和关键 runtime generation 不变；
3. 权限负面测试证明 Frontend、Control API、MAP、C_FAST 和 signer 之外的服务无法读取私钥，非 Execution 服务无法调用订单 RPC；
4. artifact 跨进程验证与现有 verifier 一致，tamper、replay、过期、identity mismatch 均 fail closed；
5. Control 命令重试和 RPC timeout 不重复创建 authorization、plan、send intent 或订单；
6. Execution 双实例、旧 leader 恢复和网络分区测试只有有效 fencing token 可执行；
7. active、unknown 和 reconcile-required 状态阻止 Execution 自动替换；
8. 每个部署单元可独立回滚，且回滚不会读取不兼容 durable state；
9. QuestDB/PostgreSQL、spool、custody 和历史 archive 在迁移前后可对账；
10. SimNow 完成 MAP → C_FAST → sign → install → authorize → execute → archive 的端到端验收，同时 production/live/countable_forward 保持 false。

## 14. 结果

本决策增加镜像、部署配置、版本矩阵和跨服务合同的维护成本，但将 UI/API 发布、研究计算、签名授权和订单执行放入不同故障域与权限域。长期收益是：普通变更不再无条件重启交易状态，私钥和订单权限不再与 Web/Research 共存，状态 owner 可审计，发布、恢复和回滚能够以明确证据证明不会产生双主或重复下单。
