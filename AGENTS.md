# Project Agent Notes

## 0. 最高优先级与冲突处理

- 称呼用户为“付哥”。
- 回答简洁、直接，先给结论和下一步。
- 当前最高优先级是 **Issue #473：SIMNOW_LAB M5 自动目标生产与真实自动调仓**；#462 的执行面与 #466 的 Dashboard、M2 runtime/CD、单个 LaunchAgent 已完成并冻结。
- #473 只新增现有月度 producer、DAILY PIT route 到现有 target/run-once 的最薄组合，并允许为 exact-contract roll 修补最小持仓收敛逻辑；未明确变更的 #462/#466 规则继续有效。
- 不新增 service、daemon、常驻 worker、queue、数据库、SQLite 表、RPC、端口、容器类型或第三方依赖；不接回 Custody、TargetPlan、Execution、authority、completion、successor、signer、catalog、ledger 或旧 Phase-C lifecycle。
- 不修改 STATIC_CORE_EQUAL 的 C/D、thermostat、allocator、产品池、权重公式或 DAILY PIT 选主算法；最终仍只使用现有 `com.folgercn.simnow-lab` LaunchAgent。
- 旧 Custody / TargetPlan / preview-enable-start / authority / completion archive / successor / distributed fencing 链已冻结为 **audited execution prototype**：保留代码和历史，但不再作为模型开始运行的前置条件。
- 未经付哥新的明确授权，禁止回到旧重型链继续补 lifecycle blocker。
- 如本文件不同章节发生冲突，以靠前章节和 #473 M5 规则为准。

### 0.0 Issue #488 明确 Owner 例外（2026-09-01）

付哥已明确要求建立并并行推进一条脱离 #480/#482 的全新高频研究线。
本例外只适用于 Issue #488 的 offline P0/P1，且优先于本文中与其冲突的
#473 允许路径、单 Agent 和“当前 milestone”限制；其余安全边界继续有效。

仅允许修改：

- `docs/research/collector-ordered-l1-bbo-change-v1/**`
- `scripts/collector_ordered_l1_bbo_change_v1.py`
- `backend/tests/unit/test_issue488_hft_bbo_change_offline.py`
- `AGENTS.md`

固定边界：

- research-only、offline-only、no-order；不接入 SIMNOW_LAB、audited 或
  production runtime；
- 不访问网络、行情凭证、账户、持仓或订单接口；不新增 service、daemon、
  port、database、queue、第三方依赖或 CI job；
- 不修改现有 market-data journal、Execution/Custody/TargetPlan、RPC、Windows
  runtime、STATIC_CORE_EQUAL 或已有策略；
- 只实现 collector-observed BBO change 的纯函数、离线合同与 focused tests；
  不得声称 exchange-native OFI、queue、passive fill 或 capacity；
- 最多 5 个 production/docs 文件、3 个 test 文件，完成 focused test、compile
  与 diff check 后停止。任何采集、经济结果、forward、shadow、SimNow 或下单
  均需新的明确授权。

当前 M5 完成目标：

```text
STATIC_CORE_EQUAL TARGET AUTO PRODUCING
+ SIMNOW_LAB AUTO REBALANCING
```

Dashboard 是独立只读观测面，任何 Web、Dashboard 或 CD 故障均不得影响 Windows Lab 执行、回调或 SQLite 写入。

---

## 0.1 Issue #466 M4 硬边界

固定闭环：

```text
PR merge → main CI Gate PASS → M2 现有 CD 更新受影响单元
→ launchd one-shot → target → CURRENT(active=0) → apply → get-run
→ Windows SQLite → Control API GET-only → /dashboard
```

- #462 的 apply/send/cancel/UNKNOWN/position/order 语义冻结；不改模型、quantity vector、DAILY PIT route、价格或下单语义。
- 复用现有 Windows RPC、`simnow_lab_get_run_v1`、Vue/Pinia/Router/Naive UI/lightweight-charts 与 `/dashboard`；不新增 RPC、端口、service、daemon、scheduler、queue、SQLite 表、依赖或数据库。
- 不接回 Custody、TargetPlan、Execution、authority、completion、successor 或旧 Phase-C lifecycle；冻结单元不得因开发、部署或 `depends_on` 自动启动/重建。
- M4 允许仅在 Windows SQLite dashboard reader/极薄 RPC glue、M2 one-shot/其 plist、Dashboard schema/service/GET route、frontend feature、focused tests、最小现有 CI/CD glue 与本规范内修改；超出 production/config 34 文件、tests 6 文件或 Issue #466 行数预算立即 STOP。

### 执行与只读隔离

- Windows Lab executor 仍是唯一 send/query/cancel owner。Dashboard reader 只能 `simnow_lab_get_run_v1("DASHBOARD")` 聚合 `runs/orders/trades/snapshots`。
- reader 必须以 SQLite URI `mode=ro` + `PRAGMA query_only=ON` 打开；不得打开 CTP、CURRENT、仓位/订单前置查询、线程/进程锁、后台线程、写表或迁移。
- Control API 只可提供 Dashboard/runs 的 GET；浏览器不得直连 Windows RPC，route 不承载聚合/缓存/RPC，service 使用 5–10 秒 cache 与 `stale=true,last_success_at` fallback。
- RPC 失败只保留最后成功只读结果；绝不触发 CURRENT、恢复、重启、补单、send 或 cancel。停止/重启 Web 或 Control API 不得影响 Windows Lab，恢复后必须可读回其间历史。

### M2 one-shot 与 CI/CD 继承

- 仅用 macOS `launchd`：随系统加载，source target 更新唤醒并以工作日 `09:05/13:35/21:05`（Asia/Shanghai）作 calendar fallback；不用 cron 和常驻调度。
- one-shot 使用本地非阻塞锁；`DONE/NOOP` 正常退出，fresh-tick 或零订单 query rejection 等待下个窗口，`UNKNOWN` 或 active order 立即 STOP 且只查询。
- 开发前只读确认既有 target producer 与 M2 CD job/plist/script；缺失只准确报告，不重建 Research/Custody/CD framework。
- 保留稳定 required context `CI Gate`，只增加 Dashboard focused backend/frontend 与既有 Linux/Windows Lab focused checks；不得恢复旧 Phase A/B/C、OCI、Execution/Custody 全套 CI 或改 branch protection。
- PR merge 后复用既有 M2 CD，拉取 exact merge SHA，按 changed area 原子部署、GET-only smoke、保留上一稳定版本独立回滚。frontend 只动 frontend-edge；Dashboard API 只动 control-api；M2 plist 只 reload 对应 job；Windows reader 只动 Windows runtime。docs 不部署。
- Dashboard/frontend 发布不得重启 `VnpyRpcService`，Control API/frontend 不得启动旧 execution-orchestrator、Custody、QuestDB/Postgres；Windows reader 更新不得重建 Web。CD 失败保持 Lab 与上一稳定版本运行。

### M4 交付门槛

- 页面须显示 Web version、Windows runtime version 与数据时间；CD smoke 必须 GET/read-only。
- 验收隔离：停止 frontend/Control API 后 Lab 与 one-shot 仍可 `DONE/NOOP` 且 SQLite 持续写入；恢复 Web 后可读回历史。纯 frontend 发布时 Windows 和 Control API PID/start time 不变。
- Dashboard reader、one-shot、GET contract/cache/stale、frontend status/chart/portfolio/drawer/mobile/dark 与最小 contracts/lint/typecheck/Vitest/build 必须各有 focused 验证；只做 P0/P1、#466 scope 与视觉规范 review。

---

## 1. 固定成功路径

唯一允许的当前研究执行链：

```text
M2 生成最小 target.json
→ 现有 Windows RPC 进程内 SIMNOW_LAB executor
→ Windows 本地 CTP tick / position / order / trade callbacks
→ Windows 本地 SQLite
→ positions / fills / equity / PnL / slippage / drawdown
```

禁止再提出第二套架构方案后继续讨论。

时间纪律：

- 3 个工作日内完成单品种、完整 10 品种、NOOP、quantity change、restore。
- 最迟第 5 个工作日开始持续运行模型。
- 第 5 天仍未运行，默认判断 scope 再次失控：必须删减，禁止继续加层。

以下不阻塞开始持续运行：

- 自然换月真实验收；
- 完整 restart/disconnect 恢复；
- 高级 partial-fill 算法；
- dashboard；
- production hardening；
- audited lane 接回。

---

## 2. SIMNOW_LAB 架构锁死

实现形态只允许：

- 复用现有 Windows RPC 服务和现有 CTP session；
- 一个进程内串行 Lab executor；
- 一个本地进程锁；
- 一个 SQLite 文件；
- 最多 2 个私有 RPC 方法：
  - `simnow_lab_apply_target_v1`
  - `simnow_lab_get_run_v1`
- 不新建监听端口；
- 不新建 Windows service；
- 不新建 Linux service/container/daemon/worker。

在 `SIMNOW_LAB` lane 内：

- Windows Lab executor 是唯一 send/query/cancel owner；
- 不经过 Custody、TargetPlan、Execution、preview、authority、completion archive、successor；
- audited / production lane 保留不动，不得被 Lab 修改或削弱；
- 永久保持：
  - `production=false`
  - `live_trading_authorized=false`
  - `countable_forward=false`
  - `official_forward_claimed=false`

---

## 3. 硬范围与代码预算

### 3.1 允许修改

仅允许：

- `scripts/windows_simnow_lab/**`
- 现有 Windows RPC server 的极薄注册/调用 glue
- 一个 M2 侧提交/查询 CLI（确有必要时）
- focused tests
- `AGENTS.md`

### 3.2 禁止修改

未经付哥重新授权，禁止触碰：

- `backend/app/execution/**`
- `backend/app/phase_c/**`
- Custody
- TargetPlan
- preview / authority / completion / successor
- shared audited execution contracts
- market-data journal / projection
- signer / provenance / trust source
- CI framework / branch protection
- production/live/countable-forward lane
- 旧 audited runtime 的交易语义

### 3.3 MVP 硬预算

- 最多 5 个 production files；
- 最多 3 个 test files；
- production code 原则上不超过 1,000 行；
- 最多 2 个 RPC methods；
- 最多 4 张 SQLite 表；
- 不新增第三方依赖；
- 不新增 Docker image；
- 不做“大一统抽象”；
- 不允许顺手重构。

预计超过任一预算时：

```text
STOP
→ 说明为什么最小方案做不到
```

不得自行扩大。

---

## 4. 明确禁止新增的东西

SIMNOW_LAB 阶段禁止：

- signer
- provenance framework
- artifact envelope
- custody receipt
- authority model
- completion archive
- successor K0/K1/K2
- distributed leader/fencing
- portfolio-wide immutable quote proof
- ledger
- WAL framework
- event sourcing
- ORM
- migration framework
- PostgreSQL / QuestDB / Redis
- queue
- scheduler service
- daemon
- dashboard platform
- generalized recovery framework
- generalized security abstraction
- 新 schema framework
- 新 release/CI framework
- 因一个现场 BUG 建立通用层
- 为未来可能需求提前设计
- 写大段设计文档代替实现
- 拆出多个子 Issue 延迟 M1-M3

原则：

> **模型还没持续运行前，不允许再建设平台。**

---

## 5. 最小 target 与执行语义

`simnow_lab_target_v1` 只表达当前希望 SimNow 持有什么：

```text
schema_version
strategy_id = STATIC_CORE_EQUAL
generated_at
target_id
targets[10]:
  product
  vt_symbol
  quantity
```

固定规则：

- 完整 10 品种；
- quantity 为有符号整数；
- canonical JSON + SHA256 只用于输入去重和记录；
- 月度 quantity vector 不手工修改；
- exact contract 继续由当前 target producer / DAILY PIT route 提供；
- 不要求 signer、Custody、receipt、authority、expiry、manifest 或 provenance。

每次 invocation：

```text
fresh positions
+ fresh active orders
+ Windows 本地 fresh tick
+ target
= required delta
```

固定流程：

1. 校验 target；
2. 读取 fresh positions / active orders；
3. portfolio == target：`NOOP`，0 新订单；
4. 否则按产品计算 delta；
5. 使用现有 SHFE/INE close-today / close-yesterday 逻辑；
6. 每个产品/offset bucket 最多一张订单；
7. 禁止按每手拆成几十或上百 child；
8. Windows 本地读取当前 bid1/ask1/price_tick；
9. 写 SQLite order row 后 send；
10. 接收 order/trade callback；
11. 再查 fresh positions；
12. 达到 target：`DONE`；否则 `PARTIAL/FAILED`，下一 invocation 从 fresh positions 继续。

首版价格：

- BUY：当前 ask1 加固定小 tick cushion；
- SELL：当前 bid1 减固定小 tick cushion；
- cushion 是 Lab 本地常量；
- 不做跨主机 5 秒 formal projection gate；
- 不做 creation→start immutable quote contract。

---

## 6. 最小订单状态与 UNKNOWN

只保留：

```text
CREATED
SUBMITTED
FILLED
CANCELLED
REJECTED
UNKNOWN
```

规则：

- HTTP/RPC/CTP 明确拒绝、明确 4xx/409/422、明确 error code、明确 receipt/order 不存在：`REJECTED`；
- 明确拒绝绝不能包装成 `UNKNOWN`；
- 只有网络超时、连接中断、响应无法判断时才进入 `UNKNOWN`；
- UNKNOWN 只按 `client_order_id/order_ref` 查询；
- 查询仍无法确定：当前 run 标记 `FAILED`；
- 下一 invocation 重新读 fresh positions/active orders 再算 delta；
- 不建立 distributed recovery、completion archive、successor 或跨交易日证据框架；
- 禁止 blind resend 的目的仅是避免污染实验数据，不得扩展成生产级恢复工程。

---

## 7. SQLite 范围锁死

只允许标准库 `sqlite3`，最多 4 张表：

```text
runs
orders
trades
snapshots
```

记录：

- target_id / run_id / start-end time / status / error；
- client_order_id / symbol / direction / offset / qty / limit price / broker order id / order status；
- trade id / price / volume / time；
- positions / active orders / balance / equity / available / margin / realized-unrealized PnL；
- target 前后持仓、滑点和收益所需字段。

禁止双写、跨机一致性、数据库服务和迁移框架。

---

## 8. 普通开发 FAST-LANE

默认只允许一个 implementer。

普通开发流程：

```text
当前 blocker / 当前 milestone
→ 最小 diff
→ focused tests
→ Ruff / compile
→ 最小本地或离线 smoke
→ merge/deploy
→ 立即运行
```

明确禁止：

- 等待 full CI；
- 跑全仓测试；
- OCI build；
- 19,519 全量 replay；
- Luna → Terra → Sol → Reviewer 多层 ceremony；
- 多个 Agent 重复调查同一根因；
- style/nit/未来优化 Review；
- 重复 smoke；
- 重复 hash/tree/bundle 认证；
- 未修改组件重新审计。

普通 Review 只看：

```text
P0
P1
是否超 #462 scope
```

不要 review theater。

---

## 9. 开市窗口 LIVE-HOTFIX

开市窗口的第一原则：

> **时间就是金钱。先恢复交易实验运行，后补 GitHub 流程。**

只要未触发本节安全 STOP，任何 PR、CI、Review、merge 等待都不得消耗开市窗口。

满足以下条件时允许现场快速 hotfix：

- 修改只在 #462 允许路径内；
- 根因明确；
- 当前没有无法判定的 broker mutation；
- 不触及真实账户/production lane；
- 不触碰禁止区域和代码预算。

固定流程：

```text
现场最小 patch
→ 1 个 focused reproduction/test
→ Ruff / compile
→ 直接覆盖现场 runtime / exact HEAD 部署一次
→ 立即返回原失败点验证
→ 确认自动运行和页面读回正常
→ 最后再补 PR / CI / Review / merge
```

这里的顺序是硬约束：**恢复运行优先于 GitHub 流程**。HOT 修复不得先开 PR、等待 CI、等待 Review 或等待 merge 后才部署；允许先把已完成 focused 验证的最小 patch 直接覆盖到 SIMNOW_LAB 现场，恢复并完成实测后再补齐提交记录。

开市期间：

- 不要求先创建 PR；
- 不等待 PR CI；
- 不要求 pre-deploy 独立 Reviewer；
- 不等待 PR Review；
- 不等待 full CI；
- 不跑全仓测试；
- 不跑 OCI；
- 不重复 smoke；
- 不重新认证整条系统；
- 不因“审计更漂亮”浪费市场窗口。

真实窗口验证通过后，再补：

```text
PR
→ CI
→ 1 个 P0/P1-only Reviewer
→ merge
```

Review 不得成为下一个市场窗口的前置 blocker。

若 hotfix 超过 100 行，或 30 分钟仍未定位：

```text
STOP 当前尝试
→ 回到最小设计继续删减
```

禁止把现场 BUG 做成 framework。

---

## 10. SIMNOW_LAB 只有三类硬 STOP

运行中只在以下情况 STOP：

1. 有可能误连真实账户、production/live lane；
2. 存在尚未查清的 active/UNKNOWN order，继续会明显污染实验数据；
3. 修复需要触碰 #462 禁止区域或突破硬预算。

其余情况，包括明确本地 BUG、明确 4xx/409/422、明确零订单/零 receipt 的失败：

```text
快速修
→ 快速部署
→ 快速验证
```

不得升级成 lifecycle 工程。

---

## 11. Agent 调度硬约束

- M1-M3 默认一个 implementer 完成；
- 不启动多个子代理并行讨论架构；
- 确需检索时最多使用一个 worker，得到结论后立即停止；
- 不拆子 Issue；
- 不写方案 A/B/C；
- 不为了“看起来严谨”增加 Reviewer 层；
- 实现者可自测；开市 hotfix 先验证，后补独立 P0/P1 Review；
- 不允许 Agent 自行扩大 scope；
- 不允许 Agent 因“长期维护”“未来生产”“更通用”增加代码。

每次开始修改前，只回答四个问题：

1. 是否是当前 #462 milestone/blocker？
2. 是否在允许路径内？
3. 是否在文件/行数/RPC/SQLite 预算内？
4. 修完是否立即回到运行？

任一答案不是“是”，不做。

最终汇报只包含：

- 修改文件；
- production/test 行数预算；
- focused test / smoke；
- M1/M2/M3 实测结果；
- 是否仍阻塞持续运行。

不回传大段原始日志和 Agent 过程。

---

## 12. GitHub 与 CI 规则

GitHub 只记录关键 checkpoint：

- blocker 根因；
- 最小修复；
- 实测结果；
- P0/P1 Review；
- 最终 acceptance。

禁止每个 shell command、每次 hash、每次重复 smoke 都评论。

SIMNOW_LAB：

- required CI 固定为 `Quick checks`、Linux M2/Lab focused、Windows Lab focused 和稳定名称 `CI Gate`；
- 不运行全仓测试、Docker/OCI build、旧 Phase A/B/C、Execution/Custody/TargetPlan 或 Windows fence 全套；
- 旧 audited CI 工具保留为历史代码，不得重新接回自动 PR CI；
- `CI Gate` 继续作为唯一 required check，不修改 branch protection；
- 开市 hotfix 先现场验证，后补 PR/Review；
- docs-only / AGENTS-only 修改也只走上述最小 CI；
- 不因 Review 流程错过开市窗口。

---

## 13. Audited / Production lane 冻结规则

旧执行链：

```text
Strategy target
→ TargetPlan
→ Custody
→ Execution
→ Windows / CTP
→ reconcile / archive
```

当前仅作为 audited execution prototype 保留。

未经付哥明确授权：

- 不继续修 preview/authority/completion/successor/fencing lifecycle；
- 不把旧链 blocker 倒灌到 #462；
- 不把旧链组件导入 SIMNOW_LAB；
- 不删除或削弱旧链；
- 不声称 SIMNOW_LAB 验收等于 production/audited 验收。

旧链中的“Execution 是唯一 send/cancel owner”等规则，只适用于 audited/production lane；不覆盖 #462 的 Windows 本地 Lab executor。

---

## 14. STATIC_CORE_EQUAL 固定语义

策略身份保持：

```text
STATIC_CORE_EQUAL
├─ 50% C_FAST_CROSS_SECTION_NEUTRAL
├─ 50% D_DONCHIAN20_EXIT10_NEUTRAL
├─ COMMODITY_FROZEN_SECTOR_MAP_V1
└─ MONTHLY_RELATIVE_VOL_THERMOSTAT_V1
```

固定经济语义：

```text
economic target / integer quantities = MONTHLY
exact-contract routing / roll = DAILY PIT
```

不存在额外实时 MAP 层。

SIMNOW_LAB 不修改：

- frozen strategy；
- quantity vector；
- C / D；
- thermostat；
- allocator；
- DAILY PIT 路由算法。

---

## 15. 当前主机与运行事实

M2：

```text
fujun@192.168.100.89
/Users/fujun/services/vnpy-web-bridge
Docker context: desktop-linux
```

Windows / CTP / SimNow：

```text
192.168.100.187
ssh wxuser@192.168.100.187
Service: VnpyRpcService
Launcher: C:\quant\run_rpc_server.py
RPC request: 2014
RPC publish: 4102
```

只检查当前决策真正依赖的事实。

未经付哥授权：

- 不扩大 firewall scope；
- 不新增端口；
- 不重启无关服务；
- 不重新审计全系统。

---

## 16. Credential / Secret Rules

永远不要把以下内容写入仓库、Issue、PR 评论或日志 artifact：

- SSH password；
- SimNow credentials；
- account ID；
- private signing key；
- tokens；
- shared secrets。

---

## 17. 最终原则

必须避免：

> 为解决一个真实 blocker，顺手创建三个新问题。

> 为证明一个小修复，重新验收整个系统。

> 为理论完美，继续阻止模型运行。

> 把安全理解成无限增加检查。

正确流程：

```text
当前模型运行 blocker
→ 最小修复
→ focused 验证
→ 立即运行
```

项目当前最终原则：

> **先让模型持续跑；SIMNOW_LAB 极简、限时、禁止扩层。**
