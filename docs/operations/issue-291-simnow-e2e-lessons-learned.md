# Issue 291 SimNow E2E 运维经验

## 1. 目标与适用范围

本文记录后续 LLM/Codex 执行 SimNow 受控演练时的历史经验。它只指导安全的
功能 E2E，不授权下单、部署、重启或生产切换。

验收必须分成两套，不得互相替代：

- **功能 E2E**：在受控 SimNow 范围内，验证 MAP/C_FAST、签名、custody、执行、
  回调、重启后对账、target=0 和归档的闭环。
- **production Windows cutover ceremony**：验证 Windows 侧安装、重启、账户/持仓/
  委托恢复、fence 和 ceremony 证据。这是独立的完整围栏验收。

本文是历史经验索引，不依据 Issue 的实时开闭状态判断任何工作已完成。

## 2. 不可妥协的边界

- `Execution Orchestrator` 是唯一 Linux 侧订单/撤单 mutation 主体；其他服务和
  工具只能产生、签名、保管或读取事实。
- target 必须是已签名的 target，且进入可验证、create-only 的 custody；不得以
  临时 JSON、fixture 或人工参数替代。
- 每次 send/cancel 先持久化 durable intent；结果未知时为 `UNKNOWN`，只能查询和
  对账，绝不 replay。
- 全程保持 `production=false`、`live=false`、`countable_forward=false`；功能 E2E
  不改变这些值。
- 私钥只允许以 FD-only 方式提供给既有离线 signer；不得进入环境变量、命令行、
  容器层、日志、浏览器或普通运行进程。
- 输出只使用脱敏事实、计数、状态和校验结果；不得输出账户明文、secret、私钥、
  key id、地址或 artifact hash。
- [PR #300](https://github.com/folgercn/vnpy-web-bridge/pull/300) 的 observer/
  ceremony 工作不能被写成已完成的 Windows cutover 证据。

## 3. 正确顺序

严格按下列顺序推进；任一步缺事实即停止在只读状态：

```text
read-only discovery
  -> runtime version alignment
  -> fresh facts
  -> MAP / C_FAST
  -> sign / custody
  -> preview / reconcile / leader / start
  -> broker callback
  -> restart / query-only reconcile
  -> target=0
  -> archive
```

要点：

1. discovery 只确认真实主机、服务、镜像、可调用只读面及权限边界，不能靠
   observer placeholder 或 fake seam 证明功能。
2. 对齐运行时源码、镜像与 Windows 服务版本后，重新读取账户、持仓、订单、交易日、
   交易时段和 fresh tick；旧快照不能签新 ceremony。
3. MAP/C_FAST 只生成不可变候选；`scripts/commodity_c_fast_executable_target_adapter.py`
   的 `--reduce-only-close` 路径仅用于受控 target=0 派生，不是通用
   交易入口。
4. 签名和 custody 在事实冻结之后。[PR #300](https://github.com/folgercn/vnpy-web-bridge/pull/300)
   仍有 temporal contract blocker；未来不得预签尚未发生的事实。
5. start 前先 preview、reconcile、取得唯一 leader/fencing，并确认 durable intent
   存储可用；`backend/app/execution/orchestrator.py` 之外不得发单或撤单。
6. 以 broker callback 和后续事实确认结果；重启后对 `SUBMITTED` / `UNKNOWN` intent
   只调用 `query_intent_v1` 与只读 snapshot 对账。
7. target=0 仅在完整对账、fresh tick、允许交易时段和明确授权下执行；归档最后做，
   不得以 archive 替代实时对账。

## 4. 快速决策树

```text
有明确、仍有效的 mutation 授权？
├─ 否 -> 只读 discovery / query-only；停止。
└─ 是 -> 运行时版本与签名 target/custody 都一致？
   ├─ 否 -> 停止，修复一个真实 blocker，重新取 fresh facts。
   └─ 是 -> fresh facts、交易时段和 fresh tick 都成立？
      ├─ 否 -> 停止；不得猜测或复用旧事实。
      └─ 是 -> preview + reconcile + single leader 均通过？
         ├─ 否 -> fail closed，query-only 恢复。
         └─ 是 -> 持久化 intent 后才可 start；超时/重启/状态未知？
            ├─ 是 -> 禁止 replay，只 query/reconcile。
            └─ 否 -> 等 broker callback，完成 target=0 与 archive。
```

## 5. 真实踩坑矩阵

<!-- markdownlint-disable MD013 -->

| 症状 | 根因 | 错误做法 | 正确做法 / 防线 |
| --- | --- | --- | --- |
| observer 有输出但无法证明真实执行 | placeholder、mock 或 fake seam 被当作实机 | 用 fixture 宣称 E2E | 先确认真实主机可提供的只读事实和 callback；假实现只可作单测。 |
| ceremony 要求的未来证据被提前签名 | Event2 时序被倒置 | 先签 Event2、以后补证据 | 事实发生后再 canonicalize、签名和 custody；未来事实缺失即停。 |
| 没有 authoritative facts | 版本、主机或事实源未对齐 | 直接签 target 或继续执行 | 只做 discovery，核实 `peek_current_facts_v1` 的真实数据来源后重取 fresh facts。 |
| blocker 被无限拆分 | 用新 schema/ledger 掩盖一个实机缺口 | 不断加 contract、表或 ledger | 一个真实 blocker 对应一个小 PR；先验证既有路径，不造平行状态。 |
| Event5 审计不能追溯原始字节 | raw custody 丢失或只保留摘要 | 用派生字段替代原始 Event5 | 保留 Event5 raw custody；只读 ceremony facts 见 [PR #301](https://github.com/folgercn/vnpy-web-bridge/pull/301)，raw custody 见 [PR #302](https://github.com/folgercn/vnpy-web-bridge/pull/302)。 |
| M2 读到了不受控数据 | 任意 RPC 被当作只读方法 | 临时调用任意 RPC“看看” | 固定 M2 read-only method 和 allowlist；只用 `peek_current_facts_v1` / `get_execution_snapshot_v1`。 |
| target 无法被原生网关识别 | native symbol 大小写被归一化 | 改成展示名或统一大小写 | 保留 native CTP symbol；参见 [PR #319](https://github.com/folgercn/vnpy-web-bridge/pull/319)。 |
| 新 ceremony 被旧 plan 串扰 | 重用旧 `plan_id` | 为省事复用已归档 plan | 每个尝试有新 plan/intent identity；旧 identity 只读归档。 |
| after 校验在交易前失败 | 交易前要求完整动态 broker row hash，结果不可预测 | 把完整动态 row hash 当作 `expected_after` | 使用既有 `target_position_projection_hash`：包含 `account_scope`、`environment` 和聚合非零 `gateway/symbol/exchange/direction/volume`，排除 `price/pnl/frozen/commission/id`；完整 row 另行 capture/archive。 |
| before 校验无交易也漂移 | 交易前要求完整动态 broker row hash，PnL 等字段会变化 | 复用旧 full-row plan/hash | #321 已改为相同的 current-position projection；动态 PnL 不影响，但 `volume/direction/symbol/exchange/account_scope/environment` 变化必须 fail closed。旧 full-row plan 必须重新生成并重签。 |
| 终态历史订单被再次处理 | 把历史 terminal order 当成待恢复工作 | cancel/replay 旧订单 | 历史 terminal order 只读；仅明确授权的 reduce-only 私有 CLI 可清理实际遗留仓位。 |
| Windows 不识别 close | 旧 artifact-custody image 不认识 `CLOSE` contract | 临时绕过合同或混用镜像 | 先做 runtime version alignment，升级/回退到识别合同的已验证组合，再重新签。 |
| HTTP allowlist 拒绝 custody 写入 | 上层路由未允许该安全路径 | 绕过签名、换成宽写接口 | 只可调用既有底层 verified custody writer，且保持 single writer、create-only；不能绕过签名。 |
| Docker 在非登录 shell 失败 | `PATH` 或 credential helper 与登录 shell 不同 | 把它误判为凭据失效并重配 | 先比较非登录 shell 的 `PATH`、二进制和 helper 可见性；不得输出或重置凭据。 |
| read-only 容器无法 `docker cp` | 容器/挂载只读 | 为拷贝而改为可写 | 用 stdin 流式读取所需文件，不改变容器或挂载权限。 |
| sudo 后突然找不到命令 | sudo session 过期或 secure PATH 不同 | 误判服务/权限故障 | 分别验证 sudo 会话、绝对命令路径和普通 shell PATH。 |
| Windows 重启后短时无账户/持仓/订单 | CTP 登录、订阅和 OMS 恢复有延迟 | 立即重发或判定零状态 | 等恢复窗口并重复只读快照；未恢复即 fail closed。 |
| 重启后 `SUBMITTED` 变 `UNKNOWN` | 回调未持久化或时序中断 | 同 intent 再发一次 | durable intent 不变，只 `query_intent_v1`、读 snapshot、对账到终态。 |
| 开始后被拒绝或无成交 | 非交易时段、无 fresh tick、trading_day 过期 | 用旧 tick、盲目调高价格 | 检查交易时段/trading_day，限价必须 fresh 且可成交；不满足则停止。 |
| PR comment gate 不通过 | 最后 push 后无可审计评论 | 只保留旧评论 | 最后一次 push 后追加含 exact head SHA 的 PR 评论。 |
| 审查表面全绿但不独立 | 同账号不能 Approve | 自己 Approve 或省略审查 | 同账号不 Approve；仍需独立 reviewer 评论并标注 P0/P1/P2。 |
| 盘中风险扩大 | 为解决 blocker 临时扩展架构 | 盘中继续开发新层/新服务 | 停止 mutation；把架构工作拆为盘后小 PR。 |

<!-- markdownlint-enable MD013 -->

## 6. 错误诊断分类

先分类再行动，避免把工具错误改成业务代码：

- **外部状态**：交易时段、trading_day、fresh tick、CTP 登录、broker callback、
  账户/持仓/订单恢复延迟。
- **部署漂移**：源码、镜像、Windows 服务、合同或已安装 artifact 的版本不一致。
- **contract 语义**：签名 target、native symbol、`CLOSE`、hash 范围、事件时序、
  custody create-only 约束不一致。
- **实现 bug**：在可重复的真实输入下，既有合同未被实现或回归；用最小复现和小 PR
  修复。
- **工具环境**：非登录 `PATH`、credential helper、sudo 会话、只读文件系统或容器
  读取方式；先区分 PATH 与权限，不能改安全边界掩盖问题。

## 7. 开盘前与执行后清单

### T-120

- 完成 read-only discovery：真实服务、运行版本、可用只读方法与权限边界。
- 关闭 production/live/countable_forward，确认无未解决 active intent 或未归档 unknown。
- 核对签名 target、custody、schema/contract 和计划的 image/runtime 版本一致。
- 确认 PR/CI 状态；最后 push 后的评论必须带 exact head SHA。

### T-30

- 重新取得 authoritative fresh facts；核对交易日、交易时段、账户/持仓/订单和
  交易网关恢复。
- 生成 MAP/C_FAST 候选，签名并写入 custody；重新生成新 plan 并使用 stable projection。
- 完成 preview/reconcile，确认 single leader、fencing 和 durable intent 存储。

### T-5

- 再取 fresh tick；限价必须可成交且仍属于授权范围。
- 复核 `expected_before` / `expected_after` 的两个 stable projection hash 和 target。
- 单列 capture/archive 的完整 broker rows，不把它们用于预期 position hash。
- 明确本次是 functional E2E；Windows full-fence 另行验收，且不启用 production/live/
  countable_forward。

### 执行后

- 等待 broker callback，记录脱敏的 intent、状态、时间和对账结论。
- 重启或异常时停止 mutation，使用 query-only 恢复并对账；不得 replay unknown intent。
- 以受控 target=0 收敛后，确认仓位/活动订单/intent 的一致终态，再 archive 原始证据。
- 报告只在证据齐备时写 `functional E2E passed`；Windows full-fence 未验收时写
  `Windows full-fence pending`。

## 8. 可复制 preflight checklist

复制后逐项填入本次事实；任一项不是 `true` / `verified` 即停止，不要补猜：

```text
[ ] authorization=verified_and_current
[ ] production=false live=false countable_forward=false
[ ] runtime_version_alignment=verified
[ ] read_only_method_allowlist=verified
[ ] fresh_facts=verified
[ ] trading_day_and_session=verified
[ ] fresh_tick_and_marketable_limit=verified
[ ] map_c_fast_candidate=verified
[ ] signed_target_and_create_only_custody=verified
[ ] plan_id_and_intent_id=new
[ ] expected_before_projection_hash=verified
[ ] expected_after_projection_hash=verified
[ ] full_broker_rows_captured_for_audit=verified
[ ] preview_and_reconcile=passed
[ ] single_leader_and_fencing=passed
[ ] durable_intent_store=passed
[ ] unknown_outcome_replay_disabled=verified
[ ] restart_query_only_reconcile=ready
[ ] target_zero_and_archive_plan=authorized
[ ] pr_comment_after_last_push_contains_exact_head_sha=verified
```

## 9. fail-closed 与 query-only 恢复

立即停止 mutation，转 query-only 的条件包括：缺 authoritative facts、版本/合同/
签名/custody 不一致、无 fresh tick 或非交易时段、leader/fencing 失败、持久化 intent
失败、callback 超时、重启后状态未知、账户/持仓/订单未恢复、allowlist 拒绝、hash 不匹配
或任何私钥/secret 暴露风险。

恢复步骤固定为：保留现场与已有 raw bytes → 停止 runner/避免 start → 用固定只读方法
读取 snapshot 与 `query_intent_v1` → 将 broker/order/position/intent 对账 → 归类为终态
或 `UNKNOWN`。只有在新的 fresh facts、重新签名和新的明确授权齐备后，才可开始新的
attempt；原 unknown intent 永不 replay。

## 10. 证据与报告措辞

最小证据包应包含：版本对齐证明、脱敏 fresh facts、MAP/C_FAST 与签名/custody receipt、
preview/reconcile/leader 结果、durable intent、broker callback、重启后的 query-only
对账、target=0 结果、archive 索引，以及 PR 最后 push 后带 exact head SHA 的评论。

报告边界：

- 证据齐全：`functional E2E passed`。
- Windows 安装/重启/恢复/fence ceremony 未另行完成：`Windows full-fence pending`。
- 不得用功能 E2E、绿色 CI、observer 输出或历史 PR 合并来声称 production Windows
  cutover 完成。

## 11. LLM 行动准则

- 先验证真实机器能提供什么，再设计命令；不要猜接口、状态或 fixture。
- 一个真实 blocker 对应一个小 PR；不要不断造 schema、ledger 或并行架构来规避它。
- 不要重复询问已经明确授权的范围；超出授权才停下请求方向。
- 工具失败先区分 PATH、credential helper、sudo 会话、只读限制和实际权限；不要为了
  “跑通”而放宽安全控制。
- 盘中不临时继续架构开发；先 fail closed，盘后再做隔离的最小改动。
- 所有输出永不包含账户明文、secret、私钥、key id、地址或 artifact hash。
- 任何 contract/CLI 结论必须先用 `rg` 核对当前 `origin/main` 的实现与 tests；不得从
  旧评论或记忆抄写。

## 12. 实现定位与历史 PR 索引

阅读或排障时优先从现有边界入口定位：

- `scripts/windows_rpc_durable_fence_v1.py`：`_WindowsExecutionFactsV1`、
  `peek_current_facts_v1`、`get_execution_snapshot_v1`、`query_intent_v1`；这是受限
  Windows 事实和 unknown 查询面。
- `backend/app/execution/orchestrator.py`、`gateway.py`：执行、回调和对账边界。
- `backend/app/execution/executable_target_adapter.py`、`final_runtime.py`：
  target 投影与运行时装配；native symbol 和动态 row hash 问题先在此验证。

| PR | 历史角色 |
| --- | --- |
| [#300](https://github.com/folgercn/vnpy-web-bridge/pull/300) | Windows host observer 与安全 ceremony runner；不能替代 full-fence 完成证据。 |
| [#301](https://github.com/folgercn/vnpy-web-bridge/pull/301) | 暴露只读 Windows/M2 ceremony facts。 |
| [#302](https://github.com/folgercn/vnpy-web-bridge/pull/302) | 持久化 restart dispatch audit raw / Event5 raw custody。 |
| [#305](https://github.com/folgercn/vnpy-web-bridge/pull/305) | frozen Windows reconciliation-only attach。 |
| [#306](https://github.com/folgercn/vnpy-web-bridge/pull/306) | 将 SimNow environment 绑定到 durable snapshot。 |
| [#307](https://github.com/folgercn/vnpy-web-bridge/pull/307) | 处理有界 snapshot clock skew。 |
| [#309](https://github.com/folgercn/vnpy-web-bridge/pull/309) | 将 C_FAST target 接入 SimNow execution。 |
| [#310](https://github.com/folgercn/vnpy-web-bridge/pull/310) | 从 final validation peek 进行 reconcile。 |
| [#317](https://github.com/folgercn/vnpy-web-bridge/pull/317) | 映射 SimNow Windows fence wire environment。 |
| [#319](https://github.com/folgercn/vnpy-web-bridge/pull/319) | 保留 native CTP target symbol 大小写。 |
| [#320](https://github.com/folgercn/vnpy-web-bridge/pull/320) | 增加 SimNow reduce-only close target。 |
| [#321](https://github.com/folgercn/vnpy-web-bridge/pull/321) | 修复 current-position projection baseline。 |
