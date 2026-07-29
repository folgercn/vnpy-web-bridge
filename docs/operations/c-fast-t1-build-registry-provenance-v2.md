# C_FAST query-v3 build/registry provenance v2

## 结论和边界

本契约对应 Issue #156。它为 Issue #155 产生的 query-v3 source bundle 与 OCI
content attestation 增加独立签名的 builder/registry witness assertion，同时移除
运行时 verifier 对 signer 源码文件的读取依赖。

验证成功只生成：

```text
SIGNED_QUERY_V3_BUILD_REGISTRY_ASSERTIONS_VERIFIED_NO_RUNTIME_AUTHORITY
```

这表示离线 verifier 验证了签名、独立 keyring pin、独立 signer source pin、
query-v3 content identity、build assertion 和 registry digest 之间的一致性。
verifier 不连接 Git、builder 或 registry，不重新执行 signer，也不证明签署时
实际载入的进程内代码，因此 receipt 固定：

```text
signing_tool_source_pin_verified=true
signing_tool_source_bytes_revalidated_at_runtime=false
signing_tool_execution_independently_verified=false
external_facts_independently_reverified=false
authority_granted=false
readiness_authorized=false
production_query_authorized=false
collection_authorized=false
runtime_activation_authorized=false
dispatch_authorized=false
```

该 receipt 不是 Acceptance、Deployment 或 Execution Permit，不能启动 query-v3，
不能读取 DSN、连接 QuestDB、收集数据或交易。

## 与 v1 的隔离

v1 verifier、signer、schema、template 和历史 evidence 均保持原样。v2 使用独立
schema version、purpose、verifier 和 signer；v2 不接受 v1 payload，也没有
auto-upgrade、fallback 或兼容解析。

历史 v1 evidence 只能使用归档的 exact v1 verifier/source bundle 验证。不能把
v1 JSON 改名、补字段或重新包装成 v2。

## signer source identity

签署时，v2 signer 从自身当前普通文件读取 exact bytes，计算 SHA256，并要求其
同时匹配两个由调用方独立提供的 release-side pin：

```text
--expected-signing-tool-source-sha256
--expected-signing-tool-source-commit-sha
```

成功后 signer 才把以下结构签入 provenance：

```json
{
  "path": "scripts/commodity_c_fast_t1_build_registry_provenance_sign_v2.py",
  "source_commit_sha": "<40-char lowercase commit>",
  "sha256": "<64-char lowercase SHA256>",
  "verification_scope": "SIGNED_AND_INDEPENDENTLY_PINNED_SOURCE_IDENTITY_NOT_RUNTIME_BYTES_OR_EXECUTION_ATTESTATION"
}
```

运行时 verifier 只把已签 identity 与 Control Plane 调用方传入的相同独立 pin
比较。它没有 signer import、signer filesystem `Path` 或 signer read；query-v3
runtime image 也必须继续拒绝任何 signer COPY。expected pin 不得从待验证
provenance 自身派生。

## query-v3 content 依赖

本分支是 Issue #155 上的 stacked contract，固定引用：

- `scripts/c_fast_t1/verify_query_v3_image_attestation.py`
- `commodity-c-fast-t1-query-v3-image-attestation-v1.schema.json`
- `commodity-c-fast-t1-query-v3-source-manifest-v1.schema.json`

provenance v2 本地重算上述 verifier/schema、自身 verifier/schema/receipt exact
bytes，并交叉绑定：

- content attestation raw/canonical SHA256；
- runtime source commit；
- source bundle archive raw SHA256；
- source manifest raw/canonical/schema SHA256；
- query-v3 Containerfile、OCI archive、image reference/digest/config；
- runtime bundle canonical index；
- build 输出和 registry immutable digest。

Issue #155 合并并 rebase 前，本分支 focused tests 使用 monkeypatch fixture 代替
尚不存在的文件；不得在本 issue 复制或实现 #155。

## 签署

先复制
[`c-fast-t1-build-registry-provenance-v2.template.json`](c-fast-t1-build-registry-provenance-v2.template.json)
到受控目录并替换所有 `PENDING_` 值。模板故意省略：

- `signing_tool_source_identity`
- `provenance_verifier_sha256`
- `provenance_schema_sha256`
- `receipt_schema_sha256`
- `content_attestation_schema_sha256`
- `content_verifier_sha256`
- `source_manifest_schema_sha256`
- `signature`

这些字段全部由 signer 从当前受控 source closure 生成。

```bash
PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_t1_build_registry_provenance_sign_v2.py \
  --input /secure/provenance-v2.unsigned.json \
  --output /secure/provenance-v2.signed.json \
  --private-key-file /secure/provenance-ed25519-private.pem \
  --trusted-keyring /secure/provenance-keyring.json \
  --expected-trusted-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --content-attestation /archive/query-v3-content-attestation.json \
  --expected-runtime-source-commit-sha "$QUERY_V3_SOURCE_SHA" \
  --expected-image-digest "$QUERY_V3_IMAGE_DIGEST" \
  --expected-signing-tool-source-sha256 "$SIGNER_SOURCE_SHA256" \
  --expected-signing-tool-source-commit-sha "$SIGNER_SOURCE_COMMIT_SHA" \
  --t1-authority-keyring /secure/t1-release-keyring.json \
  --expected-t1-authority-keyring-sha256 "$T1_KEYRING_SHA256" \
  --l3-authority-keyring /secure/l3-release-keyring.json \
  --expected-l3-authority-keyring-sha256 "$L3_KEYRING_SHA256"
```

私钥必须与 dedicated provenance keyring 匹配且不能复用 T1/L3 authority key。
输出采用 create-only、`0600` 和 fsync。

## 运行时离线验证

```bash
PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_t1_build_registry_provenance_v2.py \
  --provenance /archive/provenance-v2.signed.json \
  --trusted-keyring /secure/provenance-keyring.json \
  --expected-trusted-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --content-attestation /archive/query-v3-content-attestation.json \
  --expected-runtime-source-commit-sha "$QUERY_V3_SOURCE_SHA" \
  --expected-image-digest "$QUERY_V3_IMAGE_DIGEST" \
  --expected-signing-tool-source-sha256 "$SIGNER_SOURCE_SHA256" \
  --expected-signing-tool-source-commit-sha "$SIGNER_SOURCE_COMMIT_SHA" \
  --t1-authority-keyring /secure/t1-release-keyring.json \
  --expected-t1-authority-keyring-sha256 "$T1_KEYRING_SHA256" \
  --l3-authority-keyring /secure/l3-release-keyring.json \
  --expected-l3-authority-keyring-sha256 "$L3_KEYRING_SHA256" \
  --json-output /new/archive/provenance-v2-receipt.json
```

错误或 rotated pin、签名失败、key 复用、source/content/build/registry splice、
schema/version downgrade、任一 authority=true、非零 side effect、symlink、
重复 JSON key 或 create-only replay 均 fail closed。

## 后续顺序

1. Issue #155 合并 query-v3 source/content identity；
2. 本分支 rebase 后用真实 #155 schema/verifier 跑完整 trust-chain；
3. 独立 readiness-v3 issue 增加 root-owned signer hash/commit pin；
4. 人工 review 后才可构建 exact merge-SHA OCI；
5. L3 outcome、readiness、人工 query release、one-shot T1、acceptance。

在这些步骤完成前，Issue #139 的 runtime blocker 不能删除。
