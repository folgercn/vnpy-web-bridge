# Issue #267 全阶段迁移与验收路线图 v1

## 1. 目的与适用范围

本文是 Issue [#267](https://github.com/folgercn/vnpy-web-bridge/issues/267) 的实施、切换、回滚和验收总路线图。它把目标架构拆成可独立审查、测试和回滚的多个 PR，覆盖 Phase 0～6，并建立测试、Acceptance Criteria 与运行证据之间的映射。

服务边界以 `docs/architecture/web-bridge-service-boundaries-v1.md` 为上位 ADR，当前/目标 owner 与权限事实以 `docs/architecture/web-bridge-deployment-ownership-v1.json` 为机器可读清单。三者不一致时必须阻塞实现并先修正合同。

本文不授权生产交易，不授权任何真实或模拟下单，也不替代每次部署前的实时状态检查和人工批准。所有阶段始终保持：

```text
production_allowed=false
live_allowed=false
countable_forward=false
```

本文所称 `execution`，在 Phase 2 切换前指当前同时承载 API、RPC、后台 worker 和 CommoditySimNow 状态机的 `web-bridge`；Phase 2 切换后才指独立的 `execution-orchestrator`。

## 2. 不可妥协原则

1. 合并权限、部署权限、签名权限和执行权限相互独立；任一权限不得推导出另一权限。
2. 每个 PR 只跨越一个可解释的部署或权限边界，禁止用“大重构”掩盖状态所有权变化。
3. 新路径必须先影子验证，再切换读路径，最后切换写入或订单权限。
4. 任一切换必须有明确的前置状态、操作者、命令或工作流、成功判据、失败停止点和回滚目标。
5. 回滚不能依赖重新构建；必须使用已验证的 immutable image digest、schema version 和 artifact hash。
6. Execution 的非幂等 RPC、send intent、active plan、unknown outcome 和恢复状态不得因普通 UI、API、研究或签名工具更新而重启或重放。
7. 数据与 artifact 迁移采用双读、影子写或一次性导入时，必须定义唯一权威源；禁止长期双写且无法判断主源。
8. 私钥不进入浏览器、普通 GitHub Actions、Frontend、Control API、Research producer 或 Execution 镜像。
9. 未知文件影响、未知运行状态、缺失证据或证据不一致一律 fail closed。
10. `production/live/countable_forward=false` 是跨阶段不变量，不得用“后续再处理”暂时放宽。

## 3. 依赖与并行关系

### 3.1 Issue #262

[#262](https://github.com/folgercn/vnpy-web-bridge/issues/262) 已由 PR #268（baseline `4b77d73f`）完成并关闭，当前主干已具备 MAP Strategy Acceptance、C_FAST Allocation Acceptance、逐期 Signed Executable Target Snapshot 和持久 Runtime Authorization。它们目前仍运行在 `web-bridge` 故障/权限域内，是 #267 必须保持字节与生命周期兼容后再迁移的既有权威状态。

- Phase 0 必须把这些对象分配给明确的 owner、schema、custody 和 verifier。
- Phase 2 拆 Execution 时必须迁移 PR #268 的 Runtime Authorization durable state、enable/revoke/expiry/effective projection，不能创建第二套授权真相源。
- Phase 3 的 MAP/C_FAST producer identity 和 artifact plane 必须采用 #262 的正式 identity，不能继续使用含糊 `candidate_id`。
- Phase 4 的 signer domain、keyring、安装与撤权必须覆盖 #262 的四类核心 artifact。
- #262 已关闭不等于跨服务边界已完成；只有 verifier、durable state、receipt 和 Web workflow 在新 owner 间通过兼容/E2E 后，才可宣称 #267 的持续授权链完成。

### 3.2 Issue #264

[#264](https://github.com/folgercn/vnpy-web-bridge/issues/264) 负责 MAP/C_FAST Web Control Plane。

- Phase 1 只拆静态前端部署，不代表 #264 控制台能力完成。
- Phase 2 提供 Control API 到 Execution 的 typed command/status contract，供 #264 使用。
- Phase 4 完成 signing request、artifact install、Runtime Authorization 管理边界后，#264 才能接入完整写操作。
- #264 的浏览器按钮、表单和路由不是权限边界；所有 RBAC、expected version、idempotency、签名和审计必须由后端执行。
- 未完成 #264 的配置、授权、执行和审计闭环前，不得宣称日常运维已不再依赖 SSH/CLI。

### 3.3 依赖图

```text
Phase 0 contracts
  ├─> Phase 1 frontend isolation
  ├─> Phase 2 control/execution split ──> #262 runtime authority
  │                                      └─> #264 execution console
  ├─> Phase 3 MAP/C_FAST producers ─────> #262 identities/artifacts
  └─> Phase 4 signer/custody ───────────> #262 + #264 artifact workflows

Phase 2 + Phase 3 + Phase 4
  └─> Phase 5 worker/data isolation
       └─> Phase 6 release safety/HA and final E2E
```

Phase 1 可以在 #264 完成前交付，并以已合并的 #262/PR #268 为兼容基线。Phase 2、3、4 可在接口合同冻结后部分并行开发，但只能按本路线图的依赖顺序切换运行权威。

## 4. PR 通用生命周期与门禁

每个 PR 必须遵循以下流程。

### 4.1 实现前

1. 在 PR 描述中声明所属 plane、部署单元、状态 owner、authority impact 和不变量。
2. 列出 changed-file classifier 预期结果、将构建的镜像、将重启和明确不得重启的服务。
3. 列出 cutover、rollback 和需要的实时前置条件。
4. 权限、数据格式、状态所有权或网络 ACL 发生变化时，先更新合同或 ADR，再实现代码。

### 4.2 实现与提交

1. 使用小而可审查的提交；生成代码与人工代码分开提交。
2. 每次提交前运行 `git diff --check`、相关 focused tests 和静态合同测试。
3. 禁止把运行 secret、账户 ID、签名私钥、token、M2 SSH key 或私有路径内容提交到仓库。
4. 镜像、schema、release manifest 和运行 artifact 必须有明确版本或 digest，不以 `latest` 作为回滚身份。

### 4.3 自审 P0/P1

1. 提交 PR 前和每次实质更新后审查完整 diff，而不是只看最后一个 commit。
2. P0 包括：重复下单/双主、权限升级、私钥泄露、生产边界放宽、不可恢复数据破坏、错误服务自动重启。
3. P1 包括：fail-open、状态丢失、错误 changed-file 分类、不可用回滚、API 重试非幂等、artifact/schema 不兼容、关键证据缺失。
4. 所有 P0/P1 必须在同一 PR 修复并增加回归测试；存在未解决 P0/P1 时不得转 Ready、不得切换运行流量。
5. P2/P3 可以登记后续 Issue，但不得把实际 P0/P1 降级规避门禁。

### 4.4 CI 门禁

至少要求：

- changed-file classifier 和 workflow contract tests；
- 受影响的 frontend/backend unit、component、integration tests；
- 每个受影响 production image 的真实 OCI build；
- Compose 配置解析和临时环境 smoke；
- schema、artifact compatibility 和安全负面测试；
- 稳定 required check `CI Gate=success`。

条件 job 的 `skipped` 不得掩盖应执行但未执行的测试。classifier 与实际 COPY/import closure 不一致属于 P1。

### 4.5 PR 评论门禁

按照仓库规则，PR 每次更新必须同步添加评论。评论至少包含：

- 当前 commit SHA 和变更范围；
- 实际运行的测试及结果；
- P0/P1 自审结果和修复映射；
- release plan：build、restart、preserve；
- cutover/rollback 状态；
- 已获得和仍缺失的证据；
- 明确列出当前不能宣称完成的 Acceptance Criteria。

只更新 PR 描述、外部文档或聊天消息不能替代对应 PR 评论。

Phase 0B 必须增加可验证的 `PR Update Comment` 门禁：最后一次实质 push 后，机器人或操作者必须在同一 PR 留下包含当前 head SHA 的更新评论；检查失败时 `CI Gate` 不得成功。Issue 关闭 evidence index 必须保存对应 comment URL，不能只依赖人工 checklist。

### 4.6 合并与切换

1. review 通过和 CI 全绿只表示代码可合并，不表示允许部署、签名或执行。
2. 需要运行切换的 PR 必须由操作者在切换前重新检查镜像 digest、配置、账户、持仓、活动委托、plan、RPC 和服务健康。
3. Execution 相关切换必须满足 `safe_to_restart=true`；active order、unknown outcome 或 reconcile-required 时阻塞。
4. 切换后将脱敏 evidence JSON/Markdown 上传为 artifact，并在对应 PR 评论中链接；Issue #267 只引用可追溯证据。

## 5. 分阶段多 PR 路线图

## Phase 0：Architecture Contract

### PR 0A：部署单元、权限与状态所有权 ADR

范围：

- 固化 Frontend、Control API、MAP producer、C_FAST producer、Signer、Custody、Execution、Windows Gateway、Data/Observability 边界；
- 建立当前 `app.main` startup/shutdown 任务到目标 owner 的逐项清单；
- 建立服务到 secret、RPC 方法、volume、database role 和网络 ACL 的权限矩阵；
- 标注所有仅存在于进程内的状态、锁、generation、worker 和恢复事实。

Cutover：无运行切换，仅合同生效。后续 PR 若违反矩阵，必须先更新 ADR 并独立审查。

Rollback：revert 文档只表示撤销提案；已被后续代码依赖后不得单独回滚合同。

证据：ADR review、ownership completeness test、所有 startup task 均有唯一 owner。

不得宣称：任何容器已拆分、权限已隔离或发布已独立。

### PR 0B：部署依赖清单与 release manifest contract

范围：

- 建立文件路径到 build unit、deploy unit 和联合发布依赖的机器可读清单；
- 定义 service version、image digest、config hash、schema compatibility、health/readiness/metrics 字段；
- 定义 release plan、deployment evidence 和 rollback manifest schema；
- 未知路径或未知依赖 fail closed。
- 增加上述 `PR Update Comment` SHA/comment URL 检查，使仓库评论规则成为可验证门禁。

Cutover：CI 开始校验清单，但此 PR 不改变生产 CD 选择。

Rollback：关闭新的 CI contract check；保留已生成 manifest 以便审计。

证据：classifier table tests、COPY/import closure tests、schema validation。

不得宣称：CD 已精准部署或任何服务可以独立回滚。

## Phase 1：Frontend 独立部署

### PR 1-guard：阻断旧 CD 自动替换 Execution

范围：只修改 CD workflow/classifier/contract tests，并修正不完整的发布 schema 安全约束。任何 `backend/**`、`Dockerfile`、Frontend 拆分拓扑或 infrastructure change 的 main push 只 build/test 并输出明确 release plan，不得自动 `compose up web-bridge`；未知路径 fail closed。PR 1-pre 的原子 drain 和短 TTL receipt 可用前，手工 legacy `web-bridge` 发布也保持禁用，人工确认不能替代安全证据。

Bootstrap：GitHub push 使用合并后 revision 的 workflow，因此本 guard 合并本身不得选择或替换 `web-bridge`；用 workflow contract test 和一次 docs-only/guard canary 证明 deploy job 未运行。

Rollback：不能恢复旧的 `image_changed → web-bridge` 自动部署。若 guard 误阻塞，只能修正 classifier/roll forward；Execution 部署在 PR 1-pre 前保持禁用。

证据：合并 push 的 release plan、deploy job skipped、`vnpy-web-bridge` ID/PID/StartedAt/RestartCount 不变。

不得宣称：deployment lock、Frontend 镜像或独立发布已经完成。

### PR 1-pre：现有 monolith 的原子部署冻结门禁

范围：在当前 `web-bridge` 尚未拆分时实现 deployment lock / `DRAINING` 状态、拒绝新 command/plan、短 TTL safe-to-restart receipt 和部署前二次核验。receipt 必须绑定 execution epoch、plan version、活动委托快照、nonce 与 checkpoint hash；失败后显式保持或解除 drain。

Cutover：先以禁交易、无订单方式验证 lock acquisition、并发 command rejection、receipt expiry 和 release；该 PR 不改变 8080、镜像拓扑或订单 owner。

Rollback：只在未持有有效 deployment lock 且无运行迁移时回滚；lock/receipt audit 保留。无法判断 lock 状态时保持冻结并 roll forward。

证据：并发 start/enable 与 drain 的竞态测试、receipt TOCTOU/expiry 测试、M2 IDLE/无活动委托只读演练。

不得宣称：Frontend 已拆分或后续发布不会重启 Execution。

### PR 1A：Frontend/Edge 独立镜像与后端静态解耦

范围：

- 新增 frontend Containerfile 和 Nginx/Caddy edge 配置；
- 静态资源、SPA fallback、CSP/安全头、压缩和 cache policy 归 Frontend；
- `/api`、`/ws` 反代内部 `web-bridge`；
- 后端镜像删除 Node build 和 `frontend/dist`；FastAPI 删除 SPA catch-all；
- Compose 新增 frontend，只有它发布宿主 8080，backend 只暴露内部端口。
- 依赖已合并并验证的 PR 1-guard；在本 PR 完善 backend/frontend 两个 immutable image 的 build 和 `INFRASTRUCTURE_MANUAL` 联合迁移计划，首次联合迁移必须通过显式 workflow dispatch、服务列表和安全确认。

PR 1-guard 和 1-pre 都是端口/镜像拆分可合并的前置，不得推迟到 1B。1B 只负责迁移完成后的日常精准分类、自动 frontend-only canary 和运行证据。

首次 Cutover：

1. 此次是拓扑迁移，当前 8080 从 `web-bridge` 转给 `frontend`，必须先原子 drain，取得绑定 execution epoch、plan version、活动委托快照、nonce 和 checkpoint hash 的短 TTL safe-to-restart receipt；交易关闭、plan IDLE、无活动委托、无 unknown outcome，且部署前二次核验一致。
2. 记录旧 combined image digest、旧 Compose、容器 identity 和回滚命令；停止旧 8080 owner，确认端口释放。
3. 以仅内部端口启动新 backend，先从 Compose 私网验证 backend health、RPC、plan、持仓和活动委托。
4. 启动 frontend 占用宿主 8080，再验证静态页面、深链、API、WebSocket 和聚合 health。
5. 任一步失败：先停止新 frontend，停止新 backend，恢复旧 Compose/image 和 8080 owner；恢复前继续保持 drain，恢复后完成对账并显式解除 drain。禁止依赖一次 `compose up` 的隐含启停顺序。

Rollback：在同等安全窗口恢复旧 combined image 和旧 compose。此回滚会再次重启 `web-bridge`。

证据：两个 image contents、Compose port ownership、backend 无 dist、frontend 无 backend/secret、首次迁移前后状态 reconciliation。

不得宣称：首次迁移没有重启 Execution；不得把 edge 短时断连描述为零中断。

### PR 1B：精准 CD、release plan 与 frontend-only canary

范围：

- `frontend/**` 只 build/deploy frontend；`backend/**` 只 build/deploy backend；`shared/**` 联合；docs only 不部署；infra/未知变化人工或 fail closed；
- 独立 image tag/digest、部署 manifest 和回滚 tag；
- 定向部署固定使用 `up -d --no-deps frontend`；
- frontend-only 不读取或重写 backend deploy env，不安装 execution watchdog，不触碰私有 overlay；
- 增加无业务风险 frontend canary 产生真实发布证据。

Cutover：在 1A 基线完成后合并纯 frontend commit，release plan 必须显示 restart `[frontend]`、preserve `[web-bridge, questdb, postgres]`。

Rollback：只把 frontend 恢复到上一 immutable digest，再次 `--no-deps frontend`。

证据：前后 `web-bridge` container ID、image、PID、StartedAt、RestartCount 完全相同；plan/authority/RPC 摘要相同；frontend digest 改变；API/WS probe 恢复符合阈值。

不得宣称：单副本 edge replacement 保证已有客户端 TCP/WS 零断开。可宣称 backend WebSocket/Execution 进程未重启和客户端按合同重连；若要求连接级零断开，需 Phase 6 稳定 edge/蓝绿能力。

## Phase 2：Control API 与 Execution Orchestrator 分离

### PR 2A：内部 typed contract 与 durable execution state

范围：

- 定义 status、preview、start、stop、reconcile、drain、safe-to-restart typed API；
- 每条 command 绑定 expected version/hash、idempotency key、actor 和 receipt；
- 持久化 active plan、authority、send intent、RPC generation、callback/recovery facts；
- 旧单进程继续是唯一执行 owner，新接口先以 in-process adapter 运行。
- 在 Phase 4 Registry/Custody 切换前，Execution 只通过现有 custody 的 version-pinned 只读 compatibility adapter 读取 artifact；旧 custody 仍是唯一 writer，adapter 不得绕过现有 verifier。

Cutover：只切换 Control API 内部调用到 adapter，不改变订单 owner。

Rollback：状态 schema 必须使用 expand/migrate/contract；旧 N-1 reader 先通过新 idempotency receipt、lease epoch、send intent、plan 和 recovery fixture/replay 兼容测试才允许恢复旧内部调用。durable state 保留只读，不删除或降版；不兼容时只能 roll forward。

证据：旧/新 projection 等价、重试幂等、历史状态 migration/replay、schema compatibility。

不得宣称：进程或网络权限已经隔离。

### PR 2B：Execution shadow process、lease 与 fencing

范围：

- 独立 execution image/process 以无订单权限或 shadow 模式读取 durable state；
- 实现 single-active leader lease/fencing token；此阶段只证明应用 lease 和 shadow 决策，不能在最终执行边界落地前声称陈旧 leader 已被 fence；
- Control API 不再直接依赖 TradeService/Gateway 实现；
- 增加 safe-to-restart/drain/recovery 状态机。

Cutover：shadow process 只比较计划、状态和恢复决策，不调用交易 RPC；连续多个周期与旧 owner 一致后才进入下一 PR。

Rollback：停止 shadow process，不影响旧 owner。

证据：双实例只有一个 lease owner、shadow diff 为零、crash/network partition drills；订单提交保持禁用。`过期 token 无法提交订单` 必须由 2C 的最终执行边界证据证明。

不得宣称：Execution 已成为唯一订单 owner，因为旧进程仍拥有实际权限。

### PR 2C：订单权限切换与 Control API 权限收缩

前置：#262 所需 Runtime Authorization contract 已冻结；2A/2B 证据完成；无 active plan/order/unknown outcome；Windows RPC 或不可绕过的独占执行代理已经对每个 send/cancel 强制校验 account-scoped 单调 fencing epoch/token。

范围：

- ACL 和运行依赖只允许 execution-orchestrator 调用 Windows trade RPC，最终执行边界拒绝陈旧 fencing token；
- web/control-api 删除 send/cancel capability、订单凭据和执行 worker；
- 只通过 typed command API 控制 Execution；
- watchdog、health、metrics 和发布流程按服务拆分。

Cutover：先撤销旧 web-bridge trade capability，再确认不可调用；随后给 fenced execution leader 授权。禁止两个进程同时持有可用订单权限。

Rollback：先 drain/revoke 新 leader并完成对账；默认 roll forward。仅当无 active/unknown、状态 high-water mark 可由旧 N-1 完整理解、兼容 replay 通过时，才可恢复旧已验证 image/capability；禁止同时启动旧 owner或复用旧 fencing token。

证据：负面 ACL、single leader、SimNow 最小闭环、timeout/no-replay、restart recovery、final reconciliation。

不得宣称：MAP/C_FAST、Signer、monitor worker 已拆分。

### PR 2D：control-api-only 发布验收

范围：Control API 无业务风险 canary、精准 classifier 和独立 rollback；safe-to-restart 不是瞬时布尔值，任何 Execution 部署仍使用原子 drain + 短 TTL receipt + 部署前二次核验。

Cutover/rollback：只替换 control-api；execution-orchestrator identity 和 lease 不变。

证据：execution ID/PID/StartedAt/RestartCount/fencing token/plan/RPC generation 不变。

不得宣称：Phase 2 完成，除非 2C 的权限负面测试和本 PR no-restart 证据同时存在。

## Phase 3：MAP 与 C_FAST Producer 分离

### PR 3A：正式 identity 与 canonical artifact contracts

范围：

- 对齐 #262 的 MAP strategy/model identity、C_FAST allocation policy identity；
- 定义 MAP signal、C_FAST target candidate、executable target 的 schema、canonical bytes、lineage 和 producer digest；
- 对历史 artifact 建立只读兼容 fixture。
- 在 Phase 4 Registry 上线前定义现有 host custody 的 version-pinned、create-only candidate writer adapter：MAP/C_FAST 使用不同 dedicated identity 和目录，只能原子创建，不能覆盖；记录 writer epoch/high-water mark，Phase 4 按该水位迁移。

Cutover：旧 producer 同时输出新格式 shadow artifact，旧格式仍为权威；candidate adapter 先做 create-only/双 writer 拒绝测试，不提前切 signed artifact、receipt 或 Execution reader。

Rollback：停止 shadow output和 candidate adapter 新写入；已创建 candidate 冻结保留，历史字节不修改，不反向覆盖旧 custody。

证据：determinism、cross-process verification、tamper/replay/lineage failures。

不得宣称：producer 已独立部署或新 artifact 已获得执行 authority。

### PR 3B：MAP producer 独立 batch image/job

范围：独立 entrypoint、image、scheduler identity、只读数据权限；移除 FastAPI、账户、TradeService、Gateway 和 Windows RPC 依赖。

Cutover：新 MAP job 与旧逻辑并行生成 shadow artifact；核对固定输入下 canonical hash 和语义一致后，原子切换 MAP artifact writer。

Rollback：恢复旧 writer，保留新 artifact 但标记非权威；禁止覆盖已发布 artifact。

证据：image inventory、network/ACL negative tests、deterministic replay、writer uniqueness。

不得宣称：C_FAST 或完整 MAP→Execution 链已拆分。

### PR 3C：C_FAST producer 独立 batch image/job

范围：只消费已批准 MAP artifact，独立 allocator image/job，输出 candidate，不读取账户、持仓、活动委托或订单 RPC。

Cutover：影子比较 selected products、exact contracts、integer targets 和 risk projection；一致后原子切换 C_FAST writer。

Rollback：恢复旧 allocator writer；新 candidate 不被签名或安装。

证据：image inventory、input allowlist、portfolio risk tests、PIT/roll tests、writer uniqueness。

不得宣称：candidate 可直接执行；必须继续通过 signing、custody 和 Execution verifier。

## Phase 4：Signing、Trust 与 Custody 分离

### PR 4A：独立 signer domains 与 signing request

范围：

- 为 Research、MAP Acceptance、C_FAST Acceptance、Runtime Authorization、Execution Permit 建立独立 key domain；
- Web/Control API 只能产生 canonical signing request 和接收 signed artifact；
- signer 为本机工具、隔离 agent 或 HSM，不作为普通公开 Web API。

Cutover：新 signer 先对测试 key/artifact 双验签；正式 key rotation 必须有独立 ceremony 和 pin 更新。

Rollback：可回滚 signer binary，但 trust bundle/history 只能 append/versioned 前进，必须保留已签发在途 artifact 的兼容窗口；不得简单恢复旧 public-key set、重新信任已撤销 key，或让新 key artifact 失去验证能力。key revoke 只能经过独立 ceremony，并带 not-before/not-after/revocation 证据。

证据：image/env/log/browser secret scan、domain collision rejection、known-answer signature tests。

不得宣称：Custody 已 create-only 或 Web 授权闭环已完成。

### PR 4B：Artifact Registry/Custody 与安装 receipts

范围：root-owned volume 或 custody service；create-only/append-only；atomic publish；predecessor/hash/schema；受控 reader/writer；install/consume/revoke receipts。

Cutover：先镜像复制并逐字节校验历史 artifact，再双读比较；记录 migration high-water mark，原子切换唯一 writer/reader 后停止旧共享可写目录写入。

Rollback：权威写入切换后，代码回滚必须继续读取新 custody，不能回到缺少新 install/consume/revoke receipt 的旧源。若数据源必须回迁，先停止写入并 drain，按 high-water mark 逐字节 export、校验完整 lineage/receipts 后再原子切 reader；禁止反向覆盖历史 artifact。

证据：tamper、TOCTOU、partial write、replay、two-writer、backup/restore tests。

不得宣称：私钥由 custody 持有；custody 只保存 public verification material 和 signed artifacts。

### PR 4C：#262 Runtime Authorization 与 #264 Artifact Center 接入

范围：MAP/C_FAST Acceptance、Snapshot、Runtime Authorization 的 draft/download/upload/verify/install/enable/revoke/revalidate；RBAC、expected version、idempotency 和审计。

Cutover：先只读 overview，再启用 install，最后启用 authorization 管理；Execution 继续逐次完整重验。

Rollback：必须先通过仍可用的 typed command path 发出幂等 revoke；Execution 先 durable、fail-closed 地写 effective state=`REVOKED`，再携带 authorization hash、actor、idempotency key 和 fencing epoch 请求 Custody create-only revoke receipt。receipt 写入失败时持续重试且绝不重新 enable；等待 receipt 与 Execution ACK 后完成 plan/order reconciliation，最后才允许禁用写 API 路由。任一步结果未知时只允许 roll forward并保留管理入口；已安装 artifact 和历史 receipts 均保留可审计。

证据：#262 全生命周期测试、#264 RBAC/E2E、浏览器无 secret、重试无重复 artifact/authorization/order。

不得宣称：浏览器具备签名权，或 admin 自动成为 signer。

## Phase 5：Monitoring 与 Data Worker 分离

### PR 5A：Tick persistence 独立 worker

范围：从 Control API 移出 Tick ingestion/persistence、spool/backpressure 和 QuestDB writer；在 Windows pub/sub 无 durable offset 的边界增加持久 ingress sequence/event ID、去重键、replay spool 与 handoff watermark，再定义唯一 writer、health/readiness/metrics。

Cutover：先 shadow read/compare，不双写同一表；旧 listener 持久化 handoff watermark 后停止接收，新 listener 从同一 replay spool/watermark 恢复并拒绝已见 event ID，再切换唯一 writer。没有可重放源时不得声称无丢失/无重复，必须继续保持 `IMPLEMENTED_NOT_ACCEPTED`。

Rollback：停止新 writer并持久化同一 watermark，旧 writer 从 replay source 恢复；禁止两个 writer 同时消费同一未 fencing stream。

证据：load/overflow/fault tests、spool replay、handoff watermark、gap/duplicate 计数为零、QuestDB continuity。

不得宣称：所有 data worker 已拆分。

### PR 5B：Execution Quality fanout/horizon worker 分离

范围：独立 consumer identity、admission、journal、backpressure 和 evidence export；只读执行事实，不获得订单 authority。Market Data 只发布 durable verified tick stream，Execution Quality 独占 EQ fanout/horizon/journal consumer。

Cutover：影子比较 outputs 后切换 consumer；保留旧输出只读。

Rollback：恢复旧 consumer checkpoint；不得重写历史 evidence。

证据：generation join、replay、two-writer serialization、QuestDB readonly 权限。

不得宣称：Execution Quality 结果具有交易授权。

### PR 5C：monitor-worker 与告警独立部署

范围：监控轮询、incident state、Telegram delivery 从 Control API 移出；独立 health、retry、dedupe 和 maintenance window。

Cutover：先 shadow incidents 且禁发通知；比较一致后切换唯一 notifier。

Rollback：禁用新 notifier 后恢复旧 notifier，保留 notification dedupe state。

证据：incident dedupe、failure/recovery、API restart 告警连续性、secret redaction。

不得宣称：Frontend/Control/Execution 具有 HA。

## Phase 6：Release Safety、HA 与最终验收

### PR 6A：dependency-aware release planner 与 execution safety gate

范围：

- shared schema 按依赖矩阵联合 build；
- release plan 明确 build/restart/preserve/block；
- execution 更新强制 `safe_to_restart=true`、drain、checkpoint 和人工批准；
- 每服务 immutable digest、rollback manifest、health/readiness/version/metrics。

Cutover：planner 先 advisory，收集误判；零误判窗口后改为 enforced。未知路径永远阻塞。

Rollback：退回 advisory，但保留 execution 人工 gate；不能恢复“image_changed 就重启 web-bridge”。

证据：classifier exhaustive tests、真实 Containerfile COPY 与 Python/TypeScript import closure、shared schema matrix、未知路径阻塞、unsafe execution block、rollback drill。

不得宣称：HA 已完成。

### PR 6B：Frontend/Control API 蓝绿或滚动发布

范围：稳定 edge/load balancer、版本兼容窗口、连接 drain、Frontend/Control 多副本健康切换。

Cutover：新版本先无流量启动，readiness 通过后逐步切流；WebSocket 连接按 drain/reconnect 合同处理。

Rollback：流量切回旧健康版本；新版本停止接流后再销毁。

证据：HTTP/WS continuity、mixed-version contract、rollback under load。

不得宣称：Execution 可以双 active。

### PR 6C：Execution fenced standby 与 checkpoint handoff

范围：single-active + fenced standby；lease epoch、checkpoint handoff、old leader revocation、network partition 防双主；Windows RPC 或不可绕过的独占代理对每次 send/cancel 强制校验 account-scoped fencing token，并可原子撤销旧 epoch principal/capability。

Cutover：standby 长期 shadow；planned handoff 时先 revoke/drain old leader，再提升新 leader；任何 epoch 不一致阻塞订单。

Rollback：对新 leader revoke/drain/reconcile 后才恢复旧 leader的新 epoch；禁止复用旧 fencing token。

证据：double-leader、process crash、暂停旧进程后 lease 过期再恢复、partition、delayed callback、unknown outcome、checkpoint recovery drills；陈旧 epoch 在最终执行边界的 send/cancel 必须被拒绝。缺少该证据时 Acceptance 保持 `IMPLEMENTED_NOT_ACCEPTED`。

不得宣称：两实例等于可无条件滚动升级；安全状态仍可阻塞切换。

### PR 6D：最终 SimNow E2E 与回滚演练

范围：在显式批准下完成 MAP → C_FAST → sign → custody/install → authorize → execute → archive，并完成每服务回滚演练和最终对账。

Cutover：不是生产切换；只在已核对的 SimNow 账户、允许时段、最小风险范围内执行。每次真实模拟订单前需要用户即时确认。

Rollback：依据失败阶段撤权、停止新计划、对账、撤活动委托并恢复服务版本；unknown outcome 只允许查询和对账，不允许盲目重发。

证据：完整 evidence bundle、最终活动委托为零、持仓符合预期、archive/PnL/fee binding、所有服务 version/digest、回滚结果。

不得宣称：production-ready、live-ready 或可自动晋级生产。

## 6. 阶段性声明边界

| 已完成阶段 | 可以声明 | 不得声明 |
| --- | --- | --- |
| Phase 0 | 合同、owner、依赖和证据格式已冻结 | 已实现隔离或独立发布 |
| Phase 1A | Frontend/Backend 镜像和拓扑已拆分 | 首次迁移未重启 Execution |
| Phase 1B | 后续 frontend-only 发布不重启执行承载容器 | Control API 更新不重启 Execution；现有 edge socket 零断开 |
| Phase 2B | 独立 Execution shadow 和 fencing 已验证 | 独立 Execution 已拥有唯一订单权 |
| Phase 2C/2D | Execution 为唯一 Linux 订单 owner，API-only 发布不重启它 | Research、Signer、Workers 已隔离 |
| Phase 3 | MAP/C_FAST 独立 producer 和 artifact 交接完成 | producer output 自动获得执行权 |
| Phase 4 | signer/private key/custody 边界和 #262/#264 workflow 完成 | Web admin 是 signer；custody 可下单 |
| Phase 5 | 数据与监控 worker 独立，API 重启不影响它们 | 服务已具备 HA |
| Phase 6 | dependency-aware release、fenced handoff、SimNow E2E 与回滚证据完成 | production/live 已授权 |

## 7. Issue #267 二十项测试到证据映射

所有证据必须包含 source SHA、image digest、配置 hash、测试时间、环境、结果和脱敏规则。单元测试不能替代真实 M2 运行证据，真实 smoke 也不能替代 deterministic negative tests。

| # | Issue 测试要求 | 首次负责 PR | 必须保留的证据 |
| --- | --- | --- | --- |
| 1 | frontend-only 只重建/restart frontend | 1B | classifier output、release plan、frontend digest before/after、execution inspect identity unchanged |
| 2 | frontend 发布期间 Execution plan/authority/RPC generation 不变 | 1B | container ID/PID/StartedAt/RestartCount、plan/authority/RPC 摘要 before/after、backend direct WS probe |
| 3 | control-api-only 不重启 execution | 2D | 两服务 digest、execution lease/epoch/process identity、plan/RPC generation before/after |
| 4 | MAP/C_FAST image 不含 TradeService/Gateway/凭据 | 3B/3C | OCI inventory、import negative tests、secret scan、network ACL test |
| 5 | Control API 无法访问 Windows trade RPC | 2C | network ACL 与 capability negative test、send/cancel import absence |
| 6 | signer 私钥不出现在镜像/env/API/log/browser | 4A/4C | image layer/env/API bundle/log scans，已知 secret canary 全部零命中 |
| 7 | signed artifact 跨进程验证与现有 verifier 一致 | 3A/4A | fixed fixtures、canonical hash、old/new verifier result matrix |
| 8 | artifact atomic/create-only/tamper/replay fail closed | 4B | TOCTOU、partial write、inode swap、replay、two-writer tests |
| 9 | Execution single leader，双实例只有一个 fencing token | 2B/6C | concurrent lease drill、epoch records、loser order attempts rejected |
| 10 | active/unknown/reconcile-required 阻止 Execution 部署 | 2B/6A | safe-to-restart state matrix、blocked workflow logs、无容器替换证据 |
| 11 | planned restart checkpoint/recovery 不重复下单 | 2B/6C | send-intent/plan checkpoint、before/after order IDs、recovery receipt |
| 12 | RPC timeout、crash、partition 不重复 send intent | 2C/6C | fault-injection timeline、intent uniqueness、callback/reconcile result |
| 13 | Control API 重试不重复 authorization/plan/order | 2A/4C | idempotency/expected-version concurrency tests、唯一 receipts |
| 14 | 每服务独立 health/readiness/version/metrics | 各拆分 PR，6A 汇总 | endpoint contract tests、service inventory、M2 scrape snapshot |
| 15 | shared schema 选择正确依赖服务 | 0B/6A | exhaustive classifier/dependency matrix、release plan fixtures |
| 16 | 每服务可独立回滚 | 各切换 PR，6D 汇总 | immutable previous digest、rollback manifest、实际 rollback drill |
| 17 | QuestDB/PostgreSQL/archive 迁移兼容 | 4B/5A/5B | backup/restore、row/hash counts、archive replay、schema compatibility |
| 18 | #262/#264 授权与 Web workflow 跨服务完整运行 | 4C | backend/frontend E2E、RBAC、signed request/install/authorize receipts |
| 19 | SimNow MAP→C_FAST→sign→install→authorize→execute→archive | 6D | 经批准的完整 trace、订单/成交/持仓、terminal archive/PnL、最终对账 |
| 20 | full CI、deploy smoke、fault drills、CI Gate 全绿 | 每 PR，6D 汇总 | GitHub checks、artifact links、M2 smoke 与 fault drill report |

## 8. Acceptance Criteria 到证据映射

| Acceptance Criteria | 最早可完成阶段 | 关闭所需证据 |
| --- | --- | --- |
| 架构 ADR、权限矩阵、状态所有权和部署依赖清单完成 | 0B | reviewed ADR、完整 ownership/dependency machine-readable checks |
| Frontend 成为独立容器和独立 CD 单元 | 1B | two-image/compose contract、frontend-only release plan 与实际部署 |
| 纯前端发布不重启任何后台业务或 Execution | 1B | 迁移后的第二次 frontend-only M2 evidence；首次迁移不计 |
| Control API 与 Execution Orchestrator 独立部署 | 2C | 独立 images/process/network/capability、唯一订单 owner 证据 |
| API/Web 发布不重启执行状态机 | 2D | control-api-only 与 frontend-only 两组 execution identity evidence |
| Execution 使用 durable state、single-leader lease 和 fencing | 2B/6C | durability/replay、double-leader/partition、epoch/fencing drills |
| MAP 与 C_FAST 分别拥有独立 producer identity/image/job | 3C | identities、OCI digests、scheduler/job 和 artifact lineage |
| MAP/C_FAST 无账户、RPC 和订单权限 | 3C | image/import/network/credential negative evidence |
| Signing 私钥与 Web/API/Research/Execution 全部分离 | 4A/4C | signer-domain review、secret canary scans、ACL 与 API negative tests |
| Artifact custody create-only、可审计、可独立部署 | 4B | atomic/create-only/tamper/replay/backup tests、独立 digest/health |
| changed-file CD 精确选择服务并展示 release plan | 6A | exhaustive classifier、unknown fail-closed、真实 release plans |
| Execution 更新只在安全窗口，不能由普通 UI/CD 变化触发 | 6A | unsafe states blocked、UI/frontend/control changes preserve execution |
| 每个部署单元可独立构建、测试、发布和回滚 | 6D | service matrix 的 build/test/deploy/rollback evidence 全覆盖 |
| #262 授权模型和 #264 Web 控制台适配新边界 | 4C/6D | 跨服务 RBAC、artifact、authorization、execution、audit E2E |
| SimNow E2E 和重启/故障/双主测试通过 | 6D | Test 9、11、12、19、20 的完整 evidence bundle |
| production/live/countable_forward 始终 false | 每阶段 | config/schema/API/runtime/artifact assertions；最终 bundle 再验证 |

任何一项只有代码、测试计划、截图或人工口头确认而没有对应运行/测试 artifact 时，状态只能是 `IMPLEMENTED_NOT_ACCEPTED`，不能勾选完成。

## 9. Release evidence 最小格式

每次切换或回滚至少记录：

```text
issue / PR / source SHA
environment and captured_at UTC
changed files digest and classifier result
release plan: build / restart / preserve / blocked
service name / image digest / config hash / schema compatibility
container ID / PID / StartedAt / RestartCount before and after
health / readiness / version / metrics before and after
plan / authority / RPC generation or stable digest before and after
account hash only / positions digest / active-order count
cutover operator and explicit approval reference
smoke and fault test results
rollback target and rollback result
secret redaction result
production_allowed / live_allowed / countable_forward assertions
```

Frontend-only evidence还应记录 HTTP probe 最大失败间隔、backend-direct WebSocket disconnect count 和 edge WebSocket reconnect time。不得把 access token、账户原文、RPC secret、DSN、私钥或签名 seed 写入 evidence。

## 10. 最终关闭条件

Issue #267 只有在以下条件全部满足后才能关闭：

1. Phase 0～6 所有必要 PR 已合并，且每个 PR 的 P0/P1、CI 和评论门禁完整；
2. 二十项测试均有可追溯证据，不能用相邻测试替代；
3. 所有 Acceptance Criteria 均从 `IMPLEMENTED_NOT_ACCEPTED` 转为有证据的完成状态；
4. #262 底层授权生命周期和 #264 跨服务 Web workflow 已按新边界验收；
5. M2 SimNow E2E、frontend/control no-restart、Execution 双主/故障/恢复和每服务回滚演练完成；
6. 最终活动委托为零，持仓与批准目标一致，archive/PnL/fee 状态可重放；
7. production/live/countable_forward 仍全部为 false；
8. Issue 关闭评论汇总所有 PR、CI run、deployment evidence、fault drill 和未完成的非目标项。

完成本路线图不代表获得生产交易许可。任何未来 production/live 工作必须作为新的独立架构、权限和验收议题处理。
