# C_FAST query-v5 one-shot lifecycle contract

## 当前结论

本切片只冻结 future query-v5 的 consume、child-started 和 terminal schema，并提供
一个 **verify-only** runner。runner 会完整重放 #231 的 signed release-v5、signed
build/registry provenance、#227 composition 和 create-only pre-DSN receipt，然后固定
返回：

```text
QUERY_V5_PRE_DSN_REPLAY_VERIFIED_RUNTIME_CONTRACT_BLOCKED
runtime_execution_ready=false
fact_scope=THIS_VERIFY_ONLY_RUNNER_PROCESS_ONLY
attempt_state=NOT_INSPECTED
this_runner_release_consumed=false
this_runner_custody_opened=false
this_runner_dsn_secret_read=false
this_runner_network_attempted=false
authority_granted=false
```

它没有 custody、DSN 或 child 参数，也没有 consume/launch 写路径。pre-DSN receipt
仍是 non-authority observation，不能被当作 child capability。当前 release-v5 缺少下列
不可逆边界所需 binding，因此不能进入 M2：

- readiness-v4、L3 outcome 与十品种 exact query manifest 的 raw/canonical SHA256；
- exact runtime pin generation/manifest/identity；
- canonical custody path、custody id、custody identity 和 directory identity；
- 不含 secret bytes 的 DSN file identity attestation、预期 readonly principal 与
  endpoint identity，以及 identity-attestation schema hash；
- query-manifest schema hash、signed connect/statement/max-runtime timeout；
- runner、query child、audit source 以及 consume/child/terminal/readonly-proof schema
  的 exact SHA256。

这不是 release-v5 的兼容扩展。release-v5 schema 是 immutable 且
`additionalProperties=false`；后续必须使用独立、人工复审的新 authority version，不能
修改 v3/v4 或让旧签名冒充新 authority。runner 报告的 `missing_release_bindings` 只用于
证明当前 release-v5 必须 blocked，不是未来 authority 完整性的充分清单或自动生成依据。

## 冻结的状态机要求

后续 executable runtime 必须遵守：

```text
initial full verify
  -> pre-consume full reverify
  -> irreversible O_EXCL consume burn
  -> child claim
  -> exact child final full reverify of pins and TTL
  -> next line opens and reads DSN through one O_NOFOLLOW fd
  -> readonly query
  -> terminal
```

consume 文件一旦 O_EXCL 创建，即使为空、partial、corrupt、write/fsync/reopen 失败，也
代表 release 在协议层已永久 burned；实现不得 unlink 或重试。custody 必须预先存在且使用绝对
规范路径，所有 parent root-owned 且不可 group/world write，0700 leaf 由 writer 拥有；
runtime 全程持有 `O_DIRECTORY|O_NOFOLLOW` dirfd，并只使用 openat/statat。成功 consume
还需 write-all、fd fsync、dir fsync 和 exact reopen。

child claim 后遇到 timeout、signal、非审计 exit、missing/corrupt output 或不完整 proof，
terminal 必须保守记录 `OUTCOME_UNKNOWN`、`production_query_attempted=true`、
`production_query_completed=null`、`database_mutations_observed=null`。只有明确的
pre-child failure 可记录 `NOT_STARTED`。只有完整 pre/post readonly proof、principal、
endpoint 与全部 artifact hash 验证通过，才可记录 completed；缺 L2-L5 不能乐观 PASS。

## secret 与 custody 边界

release、consume、child-started、terminal 和日志都不得包含 DSN 原文、原文 SHA256 或
credential fingerprint。只允许绑定独立 `dsn_file_identity_attestation` 的 raw/canonical
SHA256；attestation 只能描述 canonical path hash、uid/gid/mode、dev/inode 或 deployment
generation、readonly principal 和 endpoint identity，不能包含 secret bytes。真实 DSN
只能在 exact child final gate 后通过单个 `O_NOFOLLOW` fd 做 fstat/double-read，不能进入
argv、日志或持久化 artifact。

create-only 文件只提供本地首次创建完整性，同 UID 仍可能修改、删除或 rename。因此
terminal 固定 `LOCAL_CREATE_ONLY_REQUIRES_EXTERNAL_CUSTODY`，真实 P0 acceptance 仍须
独立外部首次可见性、签名 custody 和全量重放；本 contract 不授权 query、collection、
RPC、订单、仓位、dispatch、交易或 production promotion。

## 离线验证

```bash
PYTHONPATH=scripts python scripts/commodity_c_fast_t1_query_v5_runtime.py \
  --signed-provenance "$SIGNED_PROVENANCE" \
  --provenance-keyring "$PROVENANCE_KEYRING" \
  --composition-attestation "$COMPOSITION_ATTESTATION" \
  --final-oci-layout "$FINAL_OCI_ARCHIVE" \
  --query-v4-external-image-evidence "$QUERY_V4_EXTERNAL_IMAGE_EVIDENCE" \
  --query-v4-source-bundle-archive "$QUERY_V4_SOURCE_BUNDLE" \
  --query-v4-oci-layout-archive "$QUERY_V4_OCI_ARCHIVE" \
  --query-v4-content-attestation "$QUERY_V4_CONTENT_ATTESTATION" \
  --expected-query-v4-source-commit-sha "$QUERY_V4_SOURCE_COMMIT" \
  --external-image-evidence "$QUERY_V5_EXTERNAL_IMAGE_EVIDENCE" \
  --source-bundle-archive "$QUERY_V5_SOURCE_BUNDLE" \
  --signed-release "$SIGNED_RELEASE" \
  --release-keyring "$RELEASE_KEYRING" \
  --expected-provenance-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --expected-release-keyring-sha256 "$RELEASE_KEYRING_SHA256" \
  --expected-source-commit-sha "$SOURCE_COMMIT" \
  --expected-image-digest "$IMAGE_DIGEST" \
  --pre-dsn-receipt "$PRE_DSN_RECEIPT"
```

该命令只验证并报告 blockers，不产生任何 output 文件。
