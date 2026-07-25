# C_FAST QuestDB 只读 principal L3 部署授权契约

## 结论与边界

本契约只允许一个短时、一次性、人工签名的 L3 变更窗口，用于：

```text
安装 dedicated readonly principal 的 file secret
配置 dedicated PGWire readonly principal
对 exact QuestDB target 做一次 restart
执行被冻结的人工 pre/post 检查与必要回滚
```

它不执行上述动作。本仓库新增的 verifier 只离线验证 exact artifacts，并在固定
custody 中 create-only 消费 release。它不调用 Docker、Compose、QuestDB、
Web Bridge、RPC 或交易接口，也不读取 secret 内容。

release 只把以下三项设为 `true`：

```text
readonly_principal_deployment_authorized=true
readonly_secret_file_installation_authorized=true
questdb_restart_authorized=true
```

同时固定：

```text
secret_content_read_authorized=false
global_pgwire_readonly_allowed=false
instance_readonly_allowed=false
questdb_recreate_authorized=false
questdb_image_change_authorized=false
writer_identity_mutation_authorized=false
writer_secret_mutation_authorized=false
network_mutation_authorized=false
unscoped_deployment_mutation_authorized=false
production_query_authorized=false
readonly_query_authorized=false
collection_authorized=false
write_probe_authorized=false
database_mutation_authorized=false
order_authorized=false
position_mutation_authorized=false
dispatch_authorized=false
trading_authorized=false
strategy_activation_authorized=false
automatic_promotion_authorized=false
web_bridge_deployment_authorized=false
isolated_network_unexpected_members_allowed=false
isolated_network_docker_socket_connectivity_allowed=false
isolated_network_rpc_connectivity_allowed=false
isolated_network_trading_connectivity_allowed=false
```

所以该 release 不能替代后续 T1 one-shot query release，也不能启动
`C_FAST_CROSS_SECTION_NEUTRAL` shadow、SimNow 或任何交易。

## 信任根、唯一性与 replay

release 使用 Ed25519 canonical JSON 签名，专用 key purpose 必须精确为：

```text
readonly_deployment_release_signer
```

keyring 格式固定为：

```json
{
  "schema_version": "commodity_c_fast_readonly_deployment_trusted_keys_v1",
  "keys": [
    {
      "key_id": "c-fast-readonly-deployment-key-a01",
      "purpose": "readonly_deployment_release_signer",
      "public_key_base64": "<32-byte Ed25519 public key base64>"
    }
  ]
}
```

verifier 不信任 release 自己声明的 keyring hash。正式运行只从以下 root-owned、
group/world 不可写文件取得独立 pin：

```text
/run/c-fast-readonly-deployment-pins/trusted-keyring.sha256
/run/c-fast-readonly-deployment-pins/custody.path
```

release 还绑定固定 pin root 的 canonical path SHA256、custody absolute path
SHA256 和 custody identity canonical SHA256。custody 必须是当前 verifier UID
所有的 `0700` 非 symlink 目录，父目录由 root 所有且不可被 group/world 写。
identity 文件固定为：

```json
{
  "schema_version": "commodity_c_fast_readonly_deployment_custody_identity_v1",
  "custody_id": "c-fast-readonly-deployment-custody-a01"
}
```

`attempt_id` 只能是：

```python
import hashlib

attempt_id = "attempt-" + hashlib.sha256(
    release_id.encode("utf-8")
).hexdigest()
```

verifier 在返回 receipt 前先以 `O_EXCL + fsync` 创建 consume marker。已有
consume marker 时固定报
`RELEASE_ALREADY_CONSUMED_REPLAY_FORBIDDEN`；receipt 存在但 consume 不存在
也 fail closed。复制 release 到另一 custody 会因为 root pin、path hash 和
identity hash 不一致而失败。TTL 最长两小时，单次变更时间最多 1,800 秒，只允许
一次 restart。签署、验证和 consume 的运行时 `now` 必须携带明确 timezone；
naive datetime 一律 fail closed，不能隐式套用控制机本地时区。同时强制：

```text
max_deployment_seconds <= expires_at - not_before
rollback_deadline_seconds <= max_deployment_seconds
consume 时 expires_at - now >= max_deployment_seconds
```

因此不能用只剩几十秒的 release 声称仍有完整的部署或回滚预算。

## exact evidence bundle

签名和验证都必须提供以下十二个 JSON object 普通非 symlink 文件，读取采用同一
FD 双读并核对 path/FD identity；重复 key、`NaN`、`Infinity` 或非 object root
全部 fail closed。release 绑定每个文件的 exact raw SHA256 和确定性 bundle
index：

1. QuestDB 外部 image attestation；
2. readonly principal identity attestation；
3. secret-file identity/permission attestation；
4. writer continuity pre evidence；
5. writer continuity post-check evidence contract；
6. health evidence；
7. backlog evidence；
8. rollback plan；
9. root pin identity attestation；
10. custody path identity attestation；
11. isolated network attestation；
12. exact deployment plan。

这十二个 object 不再只做哈希绑定。签署和 consume 都会重新读取原始 bytes，
执行 exact-field validator、目标/source/identity 交叉绑定和时间检查。八个部署
专用合同固定如下：

| 文件 | schema version | 强制语义 |
|---|---|---|
| writer pre | `commodity_c_fast_readonly_writer_continuity_pre_evidence_v1` | 一小时内采集、target/source、writer identity/commit/lag/queue、`HEALTHY` |
| writer post contract | `commodity_c_fast_readonly_writer_continuity_post_contract_v1` | 绑定 writer-pre raw SHA256、同一 writer identity、60 秒 lag、10,000 queue delta 和固定失败条件 |
| health | `commodity_c_fast_readonly_health_pre_evidence_v1` | 一小时内 HTTP health 采集、200/`HEALTHY`、120 秒 post-restart 恢复阈值 |
| backlog | `commodity_c_fast_readonly_backlog_pre_evidence_v1` | 一小时内 writer backlog 采集、无 corrupt spool/drop、post-restart 必须 drain 到 0 |
| rollback | `commodity_c_fast_readonly_rollback_plan_v1` | deadline 等于 release、固定 trigger/steps，不在本 release 中暗授第二次 restart |
| root pin | `commodity_c_fast_readonly_root_pin_identity_attestation_v1` | 固定 pin-root path hash、root:root、0755、directory/non-symlink、`lstat` |
| custody | `commodity_c_fast_readonly_custody_path_identity_attestation_v1` | path/identity hash、verifier owner、0700、directory/non-symlink、`lstat` |
| deployment plan | `commodity_c_fast_readonly_exact_deployment_plan_v1` | 精确 image/target/principal/secret/network、一次 restart、固定步骤/失败条件/禁止能力 |

pre evidence 和各 plan/contract 的 `captured_at` 或 `frozen_at` 必须落在
`issued_at` 前一小时内，避免陈旧准备材料被重新包装进新 release。

所有十二个 object 都必须显式包含
`secret_content_included=false`。validator 还会递归拒绝 PostgreSQL DSN、
password/token 赋值和 private-key marker；extra field 也因 exact-field
合同失败。因此 signer 不会把通用 `{}`、调试 DSN 或凭证明文当成有效 evidence
读取后签入归档。

`writer_continuity_post_evidence` 在授权前冻结的是 post-check 的 exact
接受合同、基线和采集办法，不得伪称已经发生的生产 post outcome。真实 restart
后的 writer continuity、health 和 backlog outcome 仍必须在 L3 变更窗口中另行
create-only 归档；不满足时按已绑定 rollback plan 停止。由于本 release 只允许
一次部署 restart，rollback plan 明确
`rollback_restart_authorized=false` 和
`requires_separate_rollback_restart_release=true`，不得借“回滚”名义隐式执行
第二次 restart。

image attestation 是外部事实的 exact raw bytes；verifier 不把容器内 CLI 参数
比较描述为供应链证明。attestation 使用
`contract_source_commit_sha` 指向本部署契约源码，并与 release 的 exact
`source_commit_sha` 交叉绑定，避免误写成 QuestDB 自身源码版本。release 另外绑定
`questdb_image_digest`、target identity hash 和 QuestDB build string hash。
正式人工主审必须从独立执行器取得这些事实。

secret identity attestation 只能包含 path/inode/UID/GID/mode/file-type 等身份
事实，禁止包含 password、DSN 或 secret 内容。release 固定要求：

```text
owner=65532:65532
mode=0600
regular_file_required=true
symlink_allowed=false
secret_content_read_authorized=false
readonly_password_value_source_required=file
```

principal identity 使用不暴露名称或凭证的外部 attestation raw hash，并另行绑定
opaque salted identity SHA256；release 固定要求 principal 与 admin 不同，并
禁止 `pg.security.readonly=true` 或实例级 readonly 来冒充 dedicated principal
保护。verifier 会严格交叉核对 image attestation 的 source SHA/image
digest/target/build、principal identity attestation 和 secret-file
path/UID/GID/mode/file-type，三类文件禁止 extra fields。

isolated network attestation 必须只有以下 exact fields：

```json
{
  "schema_version": "commodity_c_fast_readonly_isolated_network_attestation_v1",
  "attestation_id": "isolated-network-attestation-a01",
  "isolated_network_identity_sha256": "<exact network identity hash>",
  "driver": "bridge",
  "internal": true,
  "runner_member_identity_sha256": "<exact runner member hash>",
  "questdb_member_identity_sha256": "<exact QuestDB member hash>",
  "member_count": 2,
  "unexpected_member_identity_sha256s": [],
  "docker_socket_connectivity": false,
  "rpc_connectivity": false,
  "trading_connectivity": false,
  "secret_content_included": false
}
```

release 同时签名绑定 network、runner、QuestDB 三个 identity hash，固定两个
不同成员、internal bridge 和空 unexpected-member 集合。Docker socket、Web
Bridge RPC 与交易网络 connectivity 必须均为 false；extra field、成员 hash
不符、runner/QuestDB identity 相同或任一 connectivity 为 true 都 fail closed。
本 release 只验证既有 attestation，`network_mutation_authorized` 固定为 false。

## 离线签署

从
[`c-fast-readonly-deployment-release-v1.template.json`](operations/c-fast-readonly-deployment-release-v1.template.json)
复制 unsigned draft。模板故意使用 `PENDING_` 值且省略 `attempt_id` 和
`signature`；未全部替换时 signer 必须失败。

keyring、私钥和所有 evidence 必须由签署者从独立审核环境提供。签名 CLI 会重新
计算 attempt ID、runtime verifier/schema hashes、十二个 raw evidence hashes、
bundle index、keyring pin，并核对私钥对应的 trusted public key：

```bash
PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_readonly_deployment_sign_release.py \
  --input /secure/c-fast-readonly-deployment.unsigned.json \
  --output /secure/c-fast-readonly-deployment.signed.json \
  --private-key-file /secure/c-fast-readonly-deployment.key \
  --trusted-keyring /secure/c-fast-readonly-deployment-keyring.json \
  --expected-trusted-keyring-sha256 "$KEYRING_SHA256" \
  --source-commit-sha "$SOURCE_SHA" \
  --questdb-image-digest "$QUESTDB_IMAGE_DIGEST" \
  --questdb-image-attestation /evidence/image-attestation.json \
  --readonly-principal-identity-attestation /evidence/principal-identity.json \
  --secret-file-identity-attestation /evidence/secret-file-identity.json \
  --writer-continuity-pre-evidence /evidence/writer-pre.json \
  --writer-continuity-post-evidence /evidence/writer-post-contract.json \
  --health-evidence /evidence/health.json \
  --backlog-evidence /evidence/backlog.json \
  --rollback-plan /evidence/rollback-plan.json \
  --root-pin-identity-attestation /evidence/root-pins.json \
  --custody-path-identity-attestation /evidence/custody-path.json \
  --isolated-network-attestation /evidence/network.json \
  --deployment-plan /evidence/deployment-plan.json
```

私钥和 keyring 必须是当前用户所有的 `0600` 普通文件。signed output 使用
create-only `0600 + fsync`，不会覆盖历史 release。

## 离线 consume 与非权威 receipt

正式人工窗口开始前，在已建立 root pins 和 custody 的隔离控制机上执行：

```bash
PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_readonly_deployment_release.py \
  --release /secure/c-fast-readonly-deployment.signed.json \
  --trusted-keyring /secure/c-fast-readonly-deployment-keyring.json \
  --custody-dir /var/lib/c-fast-readonly-deployment-custody \
  --source-commit-sha "$SOURCE_SHA" \
  --questdb-image-digest "$QUESTDB_IMAGE_DIGEST" \
  --questdb-image-attestation /evidence/image-attestation.json \
  --readonly-principal-identity-attestation /evidence/principal-identity.json \
  --secret-file-identity-attestation /evidence/secret-file-identity.json \
  --writer-continuity-pre-evidence /evidence/writer-pre.json \
  --writer-continuity-post-evidence /evidence/writer-post-contract.json \
  --health-evidence /evidence/health.json \
  --backlog-evidence /evidence/backlog.json \
  --rollback-plan /evidence/rollback-plan.json \
  --root-pin-identity-attestation /evidence/root-pins.json \
  --custody-path-identity-attestation /evidence/custody-path.json \
  --isolated-network-attestation /evidence/network.json \
  --deployment-plan /evidence/deployment-plan.json
```

verifier 只会在 custody 中创建：

```text
<attempt_id>.deployment-consumed.json
<attempt_id>.deployment-receipt.json
```

receipt 固定：

```text
receipt_authority_state=NON_AUTHORITATIVE_OFFLINE_VERIFICATION_RECEIPT
receipt_is_authority=false
authority_granted=false
raw_signed_release_required_for_any_action=true
deployment_executed=false
readonly_principal_deployment_authorized=false
readonly_secret_file_installation_authorized=false
questdb_restart_authorized=false
questdb_recreate_authorized=false
questdb_image_change_authorized=false
writer_identity_mutation_authorized=false
writer_secret_mutation_authorized=false
secret_content_read_authorized=false
deployment_mutation_authorized=false
runtime_activation_authorized=false
dynamic_selection_allowed=false
replacement_authorized=false
production_authorized=false
production_query_authorized=false
collection_authorized=false
order_authorized=false
dispatch_authorized=false
trading_authorized=false
database_mutations=0
orders_sent=0
positions_modified=0
dispatch_changed=false
```

receipt schema 还逐项复制 release 的所有其他 `const=false` 能力，避免非权威
产物遗漏某个 deny 字段后被下游误判。因此 receipt 不能被 API、automation 或
人工单独当成权限。L3 操作仍必须在同一
人工窗口直接核对 raw signed release、consume marker、exact evidence 和真实
运行状态。consume 后进程异常也会烧毁 release，不得删除 marker 重试；必须保留
现场并签发全新 release。

## 尚未包含的执行

本代码切片没有：

- 修改 `deployments/` 或 `.github/workflows/`；
- 创建、读取或安装 secret；
- 执行 `docker compose`、restart/recreate 或 rollback；
- 查询或修改 QuestDB；
- 生成真实生产 evidence；
- 授权 T1 query、P0 acceptance、collection、shadow 或交易。

在未来人工 L3 executor 实现前，本契约只是可审计、不可重放的离线能力封装。
任何实际 executor 都必须重新验证 raw signed release 和固定 pins，不能把
receipt 升格为 authority。
