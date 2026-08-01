# C_FAST T1 query-v5 final-image provenance and pre-DSN gate

## 本切片边界

Parent Issue 为 #114，本切片属于 #216，并强制绑定 #227 产出的
`commodity_c_fast_t1_query_v5_image_attestation_v1` composition attestation。
它只实现以下离线闭环：

```text
#227 composition attestation
  -> exact final OCI archive + external build/registry facts
  -> independent provenance signature
  -> independent human release-v5 signature
  -> final offline pre-DSN verification
  -> create-only receipt and STOP
```

没有实现 release consume、query child、DSN 读取、网络连接或 SQL。receipt 固定：

```text
release_consumed=false
query_child_implemented=false
dsn_read=false
network_attempted=false
production_query_attempted=false
receipt_is_authority=false
```

因此代码、schema、模板和测试本身不授权真实 query。仓库中的两个模板都故意
`PENDING_` 且省略 `signature`，不能直接通过 schema 或运行时 gate。

## 不接受 v3/v4 降级

query-v5 使用独立版本、purpose 和 release key domain：

```text
commodity_c_fast_t1_query_v5_build_registry_provenance_v1
c_fast_t1_query_v5_exact_final_image_build_registry_provenance
commodity_c_fast_t1_one_shot_query_release_v5
c_fast_t1_exact_final_image_readonly_query_authority_v5
t1_exact_readonly_query_v5_release_signer
```

它不接受 query-v4 provenance/release、旧 composition schema、mutable tag 或
只绑定 config digest 的对象。provenance signer 继续使用专用
`t1_build_registry_provenance_signer` domain；release-v5 keyring 与 provenance
keyring 的**全部**公钥材料必须互斥。

## exact final-image 绑定

provenance 同时绑定：

- #227 composition attestation 的 raw/canonical SHA256、schema SHA256、
  `runtime_identity_sha256` 和 attestation-verifier runtime RepoDigest；该 runtime
  与被验证的 final image 是两个独立 identity；
- exact source archive/manifest、Containerfile、runtime bundle index；
- final OCI archive、image manifest digest、config digest、layers/diff IDs；
- immutable registry `repository@sha256:...`、push receipt、builder/registry
  identity 与时间顺序；
- 当前 verifier、signer、provenance/release/receipt schema 的 SHA256。

signer 和 gate 不信任 supplied composition JSON 本身。两者都要求 #227 的完整输入
集合，调用 `verify_query_v5_image_evidence` 重放 query-v4 attestation、query-v4/raw
OCI、query-v5 source bundle、external evidence 和 final OCI，再将 recomputed report 与
supplied composition 做 canonical exact-equal。重放同时保留 #227 runtime identity /
revalidator 边界，并在每次调用前重新核验 launcher、v5/v4 verifier、delegate 和
validator source hash。OCI index/manifest/config/layer blobs 会被真实解析，
manifest/config/layer digest 和未压缩 diff ID 会重新计算并逐项 exact-match。
任意 bytes、损坏 archive、未引用 blob、手拼 schema-valid composition 或只伪造 JSON
binding 都会 fail closed。

`composition_attestation_runtime_repo_digest_verified=true`、build facts 和
registry facts 是独立 provenance signer 作出的外部签名断言。offline gate 会
验证其签名和所有可重算 binding，但不会重连 registry 复查。这不是 registry
custody 的替代品。

## 权限与时间边界

provenance 全部 authority 字段固定为 false。release-v5 不得早于其绑定的 signed
provenance，最长 TTL 为 600 秒；gate 在完整验签后、写 receipt 前会再次按当前时间
检查 TTL 和 `minimum_launch_margin_seconds`。release 只允许四项 query
意图字段为 true；write probe、数据库/网络/部署 mutation、Web Bridge RPC、采集、
策略激活、订单、仓位、dispatch、交易、production promotion、P0 acceptance 和
replay 全部固定为 false。

pre-DSN receipt 不是 consume marker，也不是 capability。它只证明给定 release、
provenance、composition 和 final OCI bytes 在一个时点通过了离线校验；下一个真实
M2 切片仍须重新全量校验并实现 one-shot consume/child/terminal 状态机。

## 离线签署

先复制并人工填写
[`c-fast-t1-query-v5-build-registry-provenance-v1.template.json`](c-fast-t1-query-v5-build-registry-provenance-v1.template.json)。
私钥、keyring 和输出均应位于仓库外的 root custody；keyring/private key 权限必须
为 `0600`。命令中的两个 keyring hash 是 canonical JSON SHA256 的外部 pin：

```bash
PYTHONPATH=scripts python scripts/commodity_c_fast_t1_query_v5_sign.py \
  sign-provenance \
  --input "$PROVENANCE_DRAFT" \
  --private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --output "$SIGNED_PROVENANCE" \
  --provenance-keyring "$PROVENANCE_KEYRING" \
  --expected-provenance-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --composition-attestation "$COMPOSITION_ATTESTATION" \
  --query-v4-external-image-evidence "$QUERY_V4_EXTERNAL_IMAGE_EVIDENCE" \
  --query-v4-source-bundle-archive "$QUERY_V4_SOURCE_BUNDLE" \
  --query-v4-oci-layout-archive "$QUERY_V4_OCI_ARCHIVE" \
  --query-v4-content-attestation "$QUERY_V4_CONTENT_ATTESTATION" \
  --expected-query-v4-source-commit-sha "$QUERY_V4_SOURCE_COMMIT" \
  --external-image-evidence "$QUERY_V5_EXTERNAL_IMAGE_EVIDENCE" \
  --source-bundle-archive "$QUERY_V5_SOURCE_BUNDLE" \
  --final-oci-layout "$FINAL_OCI_ARCHIVE" \
  --expected-source-commit-sha "$SOURCE_COMMIT" \
  --expected-image-digest "$IMAGE_DIGEST"
```

然后复制并人工填写
[`c-fast-t1-query-v5-release-v5.template.json`](c-fast-t1-query-v5-release-v5.template.json)。
`release_id` 必须全新且不可复用；signer 会派生并覆盖匹配的 `attempt_id`，注入所有
runtime/provenance/schema hash，并拒绝 provenance/release key-domain 复用：

```bash
PYTHONPATH=scripts python scripts/commodity_c_fast_t1_query_v5_sign.py \
  sign-release \
  --input "$RELEASE_DRAFT" \
  --private-key-file "$RELEASE_PRIVATE_KEY" \
  --output "$SIGNED_RELEASE" \
  --signed-provenance "$SIGNED_PROVENANCE" \
  --release-keyring "$RELEASE_KEYRING" \
  --expected-release-keyring-sha256 "$RELEASE_KEYRING_SHA256" \
  --provenance-keyring "$PROVENANCE_KEYRING" \
  --expected-provenance-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --composition-attestation "$COMPOSITION_ATTESTATION" \
  --query-v4-external-image-evidence "$QUERY_V4_EXTERNAL_IMAGE_EVIDENCE" \
  --query-v4-source-bundle-archive "$QUERY_V4_SOURCE_BUNDLE" \
  --query-v4-oci-layout-archive "$QUERY_V4_OCI_ARCHIVE" \
  --query-v4-content-attestation "$QUERY_V4_CONTENT_ATTESTATION" \
  --expected-query-v4-source-commit-sha "$QUERY_V4_SOURCE_COMMIT" \
  --external-image-evidence "$QUERY_V5_EXTERNAL_IMAGE_EVIDENCE" \
  --source-bundle-archive "$QUERY_V5_SOURCE_BUNDLE" \
  --final-oci-layout "$FINAL_OCI_ARCHIVE" \
  --expected-source-commit-sha "$SOURCE_COMMIT" \
  --expected-image-digest "$IMAGE_DIGEST"
```

## 最终 pre-DSN STOP gate

输出路径必须为绝对路径且不存在；receipt 以 create-only `0600` 写入。该命令不会
读取任何 DSN，也没有网络/SQL client：

```bash
PYTHONPATH=scripts python scripts/commodity_c_fast_t1_query_v5_release.py \
  --signed-release "$SIGNED_RELEASE" \
  --release-keyring "$RELEASE_KEYRING" \
  --expected-release-keyring-sha256 "$RELEASE_KEYRING_SHA256" \
  --signed-provenance "$SIGNED_PROVENANCE" \
  --provenance-keyring "$PROVENANCE_KEYRING" \
  --expected-provenance-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --composition-attestation "$COMPOSITION_ATTESTATION" \
  --query-v4-external-image-evidence "$QUERY_V4_EXTERNAL_IMAGE_EVIDENCE" \
  --query-v4-source-bundle-archive "$QUERY_V4_SOURCE_BUNDLE" \
  --query-v4-oci-layout-archive "$QUERY_V4_OCI_ARCHIVE" \
  --query-v4-content-attestation "$QUERY_V4_CONTENT_ATTESTATION" \
  --expected-query-v4-source-commit-sha "$QUERY_V4_SOURCE_COMMIT" \
  --external-image-evidence "$QUERY_V5_EXTERNAL_IMAGE_EVIDENCE" \
  --source-bundle-archive "$QUERY_V5_SOURCE_BUNDLE" \
  --final-oci-layout "$FINAL_OCI_ARCHIVE" \
  --expected-source-commit-sha "$SOURCE_COMMIT" \
  --expected-image-digest "$IMAGE_DIGEST" \
  --output "$ABSOLUTE_PRE_DSN_RECEIPT"
```

任何 PENDING 值、版本回退、过期 release、hash splice、final OCI 漂移、key
复用、已有输出、非 regular file、symlink 或权限不合格都会 fail closed。
