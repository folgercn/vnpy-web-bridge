# C_FAST execution-quality durable scorer sidecar 基础

本文档对应 Issue #144 在纯 scorer 之后的离线持久化切片。它提供显式调用的
Research Plane journal 和 restart replay，不接 Settings、startup、API、
worker、行情订阅、QuestDB、SimNow、Gateway 或任何真实执行路径。

## 固定权限边界

每一类 journal payload 和 status 都固定：

```text
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
```

本切片不会修改 `execution_quality_implemented`，不会提供自动启动入口，也不会
读取 collection admission 或 execution permit。它不能把离线 scorer 基础设施
解释为 forward collection、Shadow 激活或 SimNow 验证已开始。

## 输入边界

`register_preverified_intent` 只接收调用方声明已经通过当前 authority 链重放的
`CFastVirtualIntentPlanDTO`。sidecar 会：

- 要求指定 intent 确实存在于 plan；
- 绑定 plan hash、snapshot receipt、intent policy hash、score policy hash
  和 exact-contract spec；
- 先调用纯 scorer 验证完整输入组合；
- 先 create-only 持久化 intent，完成 file + directory fsync 后，才记录
  `durably_created_at_utc` decision anchor。

sidecar 不保存签名私钥，也不独立读取 accepted signed snapshot。持久化 payload
明确保留
`CALLER_REVALIDATION_REQUIRED_SIGNED_SNAPSHOT_PLAN_AND_POLICY`，record type 也只称为
`PREVERIFIED_VIRTUAL_INTENT_INPUT`，不把 caller assertion 伪称为 Bridge 已独立
接受的事实。因此运行接线仍须独立消费和重放签名 authority；journal checksum
不能替代签名。

每条 intent input record 还会持久化同一 plan 的 exact ordered
`expected_plan_intent_ids`。recovery 要求该列表非空、唯一、类型和 ID 格式严格，
包含当前 record 的 intent，并要求同一 `preverified_plan_hash` 的全部 intent record
保存完全相同的 expected 列表。sidecar 本身允许逐 intent create-only 写入产生短暂
missing-tail 中间态；任何 runtime worker 在接收 Tick、封口或报告健康前必须证明
每个 plan 的 actual ordered intent IDs 等于这份 durable expectation，且 anchor 全部
存在。不能只用 `actual intents == anchors` 误判 plan 已完整落盘。

## create-only journal

journal root 必须是调用者预先创建、当前用户拥有且权限严格为 `0700` 的真实绝对
目录。每条 record：

- 使用连续 20 位 sequence、previous-record hash 和 canonical JSON SHA256；
- 先以固定、每个 sequence 唯一的
  `<20-digit-sequence>.reservation` 执行 create-only reservation，再创建同时
  绑定 sequence 与 record hash 的 record 文件；reservation 永久绑定
  operation、previous hash、record hash、record filename 和 exact record bytes
  hash；
- reservation 和 record 都通过 `O_CREAT | O_EXCL | O_NOFOLLOW` 以 `0600`
  创建；因此即使 `.journal.lock` 在两个 writer 之间被轮换，两个锁域也只能有
  一个成功占用同一 sequence；
- 完整写入后依次 fsync 文件和 journal 目录；
- 使用固定、`0600`、regular-file、owner-pinned、inode-pinned 的
  `.journal.lock` 和跨进程 `flock(LOCK_EX)`，在同一锁内执行
  recover + semantic replay + dedupe + append，两个 writer 不会各自创建同
  sequence 的不同文件，也不能以竞态写入冲突的 ingest/event identity；
- reservation 提交前、reservation 提交后和 record 提交后都会重新比较已打开
  lock fd 与当前 `.journal.lock` 的 identity；lock 轮换必须 fail closed；
- 每次操作同时比较已经打开的 root fd 与当前 root path 的
  device/inode/type/owner/mode；目录被 rename 后替换时，即使旧 fd 仍可写，也会
  fail closed，不能向已经脱链的旧目录写完后返回成功；
- operation ID 重试只允许 byte-equivalent payload，冲突 replay fail closed；
- recovery 拒绝 sequence gap、未知文件、symlink、非普通文件、非 canonical
  JSON、缺 reservation、reservation 与 record 不一致、hash-chain 断裂、截断
  写、内容篡改和 authority literal 改写。

目录 fsync 已发生但调用方未收到成功响应时，重启/retry 会恢复同一 operation，
不会追加第二份 evidence。若进程只留下 reservation、尚未完成 record，recovery
明确返回 `JOURNAL_INCOMPLETE_RESERVATION`，不会猜测 payload、删除 marker 或
重用该 sequence；这类 journal 需要独立审计/恢复工具后续处理。当前 root
identity pin 只覆盖 journal 实例生命周期；
跨主机或跨进程重建的强抗回滚仍需外部 WORM/签名 checkpoint，不由 SHA256
自证。

## snapshot 去重与 horizon evidence

`append_preverified_snapshot` 持久保存调用方预验证的 L1-L5 snapshot：

- `ingest_id`；
- `exact_contract + exchange_timestamp + ingest_seq` event key；
- 完整 book snapshot 的 content fingerprint。

同一 identity + 同一 content 幂等返回；identity 被不同 content 复用会 fail
closed。每个 exact contract 的 `received_at_utc` 只允许单调前进，防止 horizon
封口后再补入旧 tick 改写选择结果。

snapshot record type 固定为 `PREVERIFIED_L1_L5_SNAPSHOT_INPUT`；它只验证严格
DTO、content hash、ingest/event identity 和 journal 顺序，不声称独立完成外部
行情签名或 collection admission 验收。

decision 和 `250ms / 1s / 5s / 30s / 60s` 分别只有在已持久化 watermark
严格晚于对应闭区间末端后才封口。每个封口 evidence 保存：

- watermark record hash；
- 完整、不可省略的输入 snapshot record hash 集；
- 纯 scorer 的完整 score 与 score hash；
- `SEALED_SELECTED_EVIDENCE` 或
  `SEALED_MISSING_NOT_IMPUTED`。

restart recovery 会按 journal 的原始 intent、policy、contract spec 和 snapshot
集合重新执行 scorer，并逐字段比较 score。已经存在的 target evidence 不会重复
追加；缺 horizon 也只记录明确 missing，不 carry-forward 或伪造指标。

## 尚未实现

后续必须使用独立 PR 和独立 authority 才能增加：

- collection admission 的 signed release 消费；
- runtime config / startup / subscription / worker；
- QuestDB 或其他外部 repository adapter；
- API、监控或 UI；
- SimNow/真实盘口采集及任何 execution-quality 运行宣称；
- 外部 WORM checkpoint、跨实例单写者租约和 journal anti-rollback。

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py

PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality.py \
  backend/tests/unit/test_commodity_c_fast_execution_policy.py \
  backend/tests/unit/test_commodity_c_fast_execution_policy_v2.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_scorer.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_sidecar.py
```
