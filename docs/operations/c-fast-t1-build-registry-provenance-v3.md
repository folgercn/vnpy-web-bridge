# C_FAST query-v4 build/registry provenance v3

## 结论与边界

本契约对应 Issue #216 的 query-v4 provenance 切片。它把独立签名的
builder/registry assertions 绑定到 query-v4 exact source bundle、OCI content
attestation、RepoDigest 和 runtime bundle。

验证成功只生成：

```text
SIGNED_QUERY_V4_BUILD_REGISTRY_ASSERTIONS_VERIFIED_NO_RUNTIME_AUTHORITY
```

receipt 仅证明签名和各项绑定通过。builder/registry facts 仍是外部签署事实，
offline verifier 不连接 builder 或 registry，因此固定：

```text
external_facts_independently_reverified=false
readiness_authorized=false
production_query_authorized=false
authority_granted=false
```

它不是 readiness、query release、P0 acceptance 或交易权限。

## 与 query-v3 v2 的隔离

v3 使用独立 schema、purpose、signer path、receipt status 和 query-v4 content
contract。v2/v3 payload 不能相互验证或改名升级。为安全复用已审计逻辑，v3
wrapper 显式绑定以下 exact bytes：

- v3 verifier；
- v2 verifier delegate；
- v2 signer delegate；
- v3 provenance/receipt schema；
- query-v4 content/source-manifest schema；
- query-v4 content verifier。

任一 wrapper、delegate、schema 或 verifier 漂移都会 fail closed。query-v3
v2 module 的全局 contract 不会被 v3 import 修改。

## 签署

复制
[`c-fast-t1-build-registry-provenance-v3.template.json`](c-fast-t1-build-registry-provenance-v3.template.json)
到受控目录，替换全部 `PENDING_` 值。generated identity/hash/signature 字段由
signer 生成，不能手填。

```bash
PYTHONPATH=scripts python3 \
  scripts/commodity_c_fast_t1_build_registry_provenance_sign_v3.py \
  --input /secure/query-v4-provenance-v3.unsigned.json \
  --output /secure/query-v4-provenance-v3.signed.json \
  --private-key-file /secure/provenance-ed25519-private.pem \
  --trusted-keyring /secure/provenance-keyring.json \
  --expected-trusted-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --content-attestation /archive/query-v4-content-attestation.json \
  --expected-runtime-source-commit-sha "$QUERY_V4_SOURCE_SHA" \
  --expected-image-digest "$QUERY_V4_IMAGE_DIGEST" \
  --expected-signing-tool-source-sha256 "$SIGNER_V3_SOURCE_SHA256" \
  --expected-signing-tool-source-commit-sha "$SIGNER_SOURCE_COMMIT_SHA" \
  --t1-authority-keyring /secure/t1-release-keyring.json \
  --expected-t1-authority-keyring-sha256 "$T1_KEYRING_SHA256" \
  --l3-authority-keyring /secure/l3-release-keyring.json \
  --expected-l3-authority-keyring-sha256 "$L3_KEYRING_SHA256"
```

private key 必须属于 dedicated provenance key domain，且不得与 T1/L3
authority key 复用。signer source pin 必须来自待签 artifact 之外的独立审查
渠道。

## 离线验证

```bash
PYTHONPATH=scripts python3 \
  scripts/commodity_c_fast_t1_build_registry_provenance_v3.py \
  --provenance /archive/query-v4-provenance-v3.signed.json \
  --trusted-keyring /secure/provenance-keyring.json \
  --expected-trusted-keyring-sha256 "$PROVENANCE_KEYRING_SHA256" \
  --content-attestation /archive/query-v4-content-attestation.json \
  --expected-runtime-source-commit-sha "$QUERY_V4_SOURCE_SHA" \
  --expected-image-digest "$QUERY_V4_IMAGE_DIGEST" \
  --expected-signing-tool-source-sha256 "$SIGNER_V3_SOURCE_SHA256" \
  --expected-signing-tool-source-commit-sha "$SIGNER_SOURCE_COMMIT_SHA" \
  --t1-authority-keyring /secure/t1-release-keyring.json \
  --expected-t1-authority-keyring-sha256 "$T1_KEYRING_SHA256" \
  --l3-authority-keyring /secure/l3-release-keyring.json \
  --expected-l3-authority-keyring-sha256 "$L3_KEYRING_SHA256" \
  --json-output /new/archive/query-v4-provenance-v3-receipt.json
```

signature、pin、key-domain、commit、content、image、build/registry、delegate
bytes、schema namespace、权限矩阵或 create-only 输出任一不一致均 fail
closed。

## 后续边界

下一步由 query-v4 readiness 直接消费 v3 receipt，并用 root-owned pins 固定
provenance keyring 和 signer identity。完成新的短时 readiness 与人工 query
release 前，不得运行真实 QuestDB one-shot。
