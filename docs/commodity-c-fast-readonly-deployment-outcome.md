# C_FAST 只读部署 post-outcome 独立签署契约

## 结论与权限边界

本契约用于独立复核并签署一次已经完成的 C_FAST QuestDB readonly principal
部署结果。它补齐 `commodity_c_fast_readonly_deployment_receipt_v1` 明确缺失的
事实层：#130 receipt 只证明 signed release 已离线验签并被一次性消费，
`deployment_executed=false`，不能证明 restart 或 post-check 已发生。

一个有效 outcome 只能表示：

```text
deployment_outcome_state=SUCCEEDED_POSTCHECKS_VERIFIED
deployment_executed=true
restart_executed=true
restart_count=1
writer_continuity_verified=true
post_restart_health_verified=true
backlog_drain_verified=true
readonly_principal_verified=true
secret_file_verified=true
isolated_network_verified=true
```

它不是新的执行 release，也不产生 readiness。签名 outcome 固定：

```text
receipt_is_authority=false
outcome_is_authority=false
readiness_authorized=false
readonly_principal_deployment_authorized=false
readonly_secret_file_installation_authorized=false
questdb_restart_authorized=false
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
runtime_activation_authorized=false
replacement_authorized=false
production_authorized=false
replay_allowed=false
```

同时要求 query、write probe、数据库 mutation、Web Bridge RPC、订单和持仓变更
计数均为 exact integer `0`，`dispatch_changed=false`。因此本契约不能启动 T1、
P0、execution-quality collection、Shadow、SimNow 或交易。

## 独立 Ed25519 信任域

outcome keyring 只能使用：

```json
{
  "schema_version": "commodity_c_fast_readonly_deployment_outcome_trusted_keys_v1",
  "keys": [
    {
      "key_id": "c-fast-readonly-outcome-key-a01",
      "purpose": "readonly_deployment_outcome_signer",
      "public_key_base64": "<32-byte Ed25519 public key base64>"
    }
  ]
}
```

keyring 中出现其他 purpose、重复 key ID 或非 32-byte Ed25519 key 均 fail
closed。outcome signer 的原始 32-byte public key 必须同时不同于：

1. 实际签署 readonly deployment release 的 key；
2. T1 keyring 内所有 `t1_audit_release_signer` key。

只改 key ID、purpose 或 keyring 文件不能构成独立信任域。

`verify_signed_outcome()` 的验证结果同时返回实际 outcome signer 原始
32-byte Ed25519 public key 的 `outcome_signer_public_key_sha256`。后续
readiness verifier 可用它做跨 witness 的原始 key 隔离；该 hash 只是已验签
signer identity，不授予任何 authority。

正式 verifier 不从 CLI 或 outcome 自身接受三项 keyring pin。它只读取固定、
root-owned、group/world 不可写的目录：

```text
/run/c-fast-readonly-deployment-outcome-pins/
  outcome-keyring.sha256
  release-keyring.sha256
  t1-keyring.sha256
```

每个文件只能包含对应 keyring canonical JSON 的 64 位小写 SHA256。Python
函数的 pin 参数只用于离线 signer 和测试注入，不是生产 verifier 的信任入口。

## 被重新验证的 #130 历史链

outcome verifier 不信任 receipt 自述。它重新读取并验证：

1. raw signed deployment release；
2. release trusted keyring；
3. exact consume marker；
4. exact non-authoritative receipt；
5. #130 的十二个 pre evidence 文件。

release 以 `consume.consumed_at` 作为历史验证时点重验 Ed25519 signature、
有效期、exact runtime/schema hashes、十二文件 raw SHA256、bundle index 及全部
部署前合同。consume/receipt 必须：

- 使用 `<attempt_id>.deployment-consumed.json` 和
  `<attempt_id>.deployment-receipt.json` 精确文件名；
- 位于同一个、与 release 的 canonical custody path SHA256 一致的 `0700`
  non-symlink custody；
- 通过 custody identity 验证；
- raw/canonical release hash、attempt、evidence bundle、keyring、source、
  image、custody 完全交叉一致；
- `verified_at == consumed_at`；
- receipt 精确绑定 consume raw bytes；
- 保持 #130 的完整 deny/zero matrix。

receipt 仍必须是 `deployment_executed=false`。真实执行只由新的独立 post
evidence 和 outcome signature 表达。

## 六类 post evidence

所有 post evidence 都是普通 non-symlink JSON object，禁止 duplicate key、
`NaN`、`Infinity`、extra field、secret 内容、DSN、token 或 private-key marker。
六个文件全部绑定同一 raw release、consume、receipt、release ID 和 attempt ID：

| 文件 | 核心事实 |
|---|---|
| execution | exact target、同一 image/container、一次 restart、无 recreate/image change、执行时间链 |
| writer post | 同 writer identity、pre/post contract raw hash、exact pre commit 未变化、lag/queue 阈值 |
| health post | restart 后 HTTP 200/HEALTHY、120 秒内恢复、至少三次连续成功 |
| backlog post | 绑定 pre backlog，pending/corrupt/drop 全为 0 |
| principal + secret post | exact target/principal/path、file source、65532:65532/0600、regular/no symlink、不读取 secret |
| network post | exact internal bridge、两个不同 exact members、无 unexpected member、无 Docker socket/RPC/trading connectivity |

verifier 重新计算每个 raw SHA256 与 deterministic post bundle index。writer
queue delta 必须等于 `post_queue - pre_queue`。由于 #130 的 pre evidence 没有
签名绑定可比较的 numeric commit sequence，本 v1 只接受 `SAME`，并要求 post
commit identity 精确等于 pre commit identity；不接受调用方自述的 `ADVANCED`。

execution evidence 还必须提供 query、write probe、数据库 mutation、Web Bridge
RPC、订单、持仓和 dispatch 的 exact zero/false 事实。outcome 中的相同字段逐项
从 execution evidence 复制，不由 signer 凭空生成。

## 时间链

成功 outcome 强制：

```text
release.not_before
<= consume.consumed_at
<= deployment_started_at
<= secret_installed_at
<= restart_started_at
<= restart_completed_at
<= every post captured_at
<= deployment_ended_at
< release.expires_at
```

部署耗时不能超过 signed `max_deployment_seconds`。health post 必须在 restart
完成后 120 秒内采集。`outcome.issued_at` 必须位于 deployment end 之后、验证
时点之前，签署延迟最多 24 小时。

`outcome_contract_source_commit_assertion` 只是签署者提供的 source revision
assertion，不单独构成代码 provenance。真正被机器绑定的是当前 verifier、
outcome schema 和六个 post schema 的 exact file SHA256。

`rollback_deadline_seconds` 是 #130 对失败路径的 rollback deadline；成功 outcome
不宣称发生 rollback，固定 `rollback_invoked=false`。成功路径的耗时边界只使用
signed `max_deployment_seconds`。

## 签署与验证

从
[`c-fast-readonly-deployment-outcome-v1.template.json`](operations/c-fast-readonly-deployment-outcome-v1.template.json)
复制 unsigned draft。模板故意只有人工字段、含 `PENDING_` 值、缺少所有派生
绑定和 signature，不能直接通过 schema 或 verifier。signer 会从 exact evidence
重算所有非人工字段，拒绝人工覆盖。最终 output 只能以
`<attempt_id>.deployment-outcome.json` 写入 release 绑定的同一 custody，使用
create-only `O_EXCL + fsync`；任意其他目录、文件名或已有 outcome 都失败。

签署命令需要显式的三项独立 pin，并同时传入 #130 十二个 pre evidence 和六个
post evidence：

```bash
PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_readonly_deployment_sign_outcome.py \
  --input /secure/outcome.unsigned.json \
  --output /var/lib/c-fast-readonly-deployment-custody/<attempt_id>.deployment-outcome.json \
  --private-key-file /secure/outcome-ed25519.key \
  --outcome-keyring /secure/outcome-keyring.json \
  --t1-keyring /secure/t1-keyring.json \
  --expected-outcome-keyring-sha256 "$OUTCOME_KEYRING_SHA256" \
  --expected-release-keyring-sha256 "$RELEASE_KEYRING_SHA256" \
  --expected-t1-keyring-sha256 "$T1_KEYRING_SHA256" \
  --expected-outcome-source-commit-sha "$OUTCOME_SOURCE_ASSERTION" \
  --expected-release-source-commit-sha "$RELEASE_SOURCE_SHA" \
  --expected-questdb-image-digest "$QUESTDB_IMAGE_DIGEST" \
  --release /archive/release.json \
  --release-keyring /archive/release-keyring.json \
  --consume-marker /archive/attempt.deployment-consumed.json \
  --receipt /archive/attempt.deployment-receipt.json \
  ...十二个与 #130 相同的 pre evidence 参数... \
  --execution /evidence/execution.json \
  --writer-post /evidence/writer-post.json \
  --health-post /evidence/health-post.json \
  --backlog-post /evidence/backlog-post.json \
  --principal-secret-post /evidence/principal-secret-post.json \
  --network-post /evidence/network-post.json
```

正式验证使用相同 artifacts，但三项 keyring pin 只能来自固定 root pin
目录，因此命令没有 `--expected-*-keyring-sha256` 参数。成功输出仍会明确：

```text
readiness_authorized=false
collection_authorized=false
trading_authorized=false
```

## 尚未包含

本切片不会执行 deployment、restart、rollback、QuestDB query、collection、
Web Bridge RPC 或交易，也不会生成真实 post evidence。失败或不完整部署不能
伪造成成功 outcome：缺少任一 post 文件、任一 post-check 不通过或时间链不完整
时，signer 必须 fail closed，不产生 `SUCCEEDED_POSTCHECKS_VERIFIED`。

后续 readiness v2 必须再次验证 raw release/consume/receipt、此 signed outcome
和 final OCI attestation；即使全部通过，也只能由新的独立 readiness contract
表达下一步门禁，不能把本 outcome 自身升格为 authority。
