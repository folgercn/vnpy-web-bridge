# C_FAST T1/P0 preflight v2

## 当前结论

v2 在 v1 的 query-v4 source/OCI、readiness-v3/L3、packaging 和 readonly DSN
metadata join 上，新增 query-v4 signed build/registry provenance v3 的实时验证。
v2 artifact 同时记录 wrapper 和 v1 delegate verifier 的 exact SHA256，任一实现
漂移都会改变 preflight identity。

成功状态：

```text
QUERY_V4_SOURCE_OCI_PROVENANCE_AND_UPSTREAM_PREFLIGHT_VERIFIED_READINESS_BLOCKED
```

此时 `build_provenance_verified=true`、`registry_provenance_verified=true`，但
builder/registry facts 仍是 signed external assertions，不是 verifier 对外部
系统的重放，因此
`external_build_registry_facts_independently_reverified=false`。

v2 只移除 provenance blocker，仍固定：

```text
blocking_reasons=[
  "QUERY_V4_READINESS_AND_HUMAN_RELEASE_NOT_YET_DERIVED"
]
ready_for_human_query_release_only=false
production_query_attempted=false
p0_verdict=NOT_RUN
authority_granted=false
```

## 输入与 pin

query-v4 provenance 使用现有 root-owned provenance keyring pin，并与 T1/L3
authority key domains 做隔离。v3 signer source SHA256/commit 由调用方从待验
artifact 之外独立提供：

```text
--query-v4-build-registry-provenance
--expected-query-v4-provenance-signing-tool-source-sha256
--expected-query-v4-provenance-signing-tool-source-commit-sha
--expected-query-v4-provenance-signer-dependency-manifest-sha256
--expected-query-v4-provenance-signer-runtime-image-digest
```

其余 query-v4 content、readiness-v3/L3 和 DSN 参数与
[`c-fast-t1-p0-preflight-v1.md`](c-fast-t1-p0-preflight-v1.md) 一致。执行命令
将 v1 的 script 名替换为：

```bash
PYTHONPATH=scripts python3 \
  scripts/commodity_c_fast_t1_p0_preflight_v2.py \
  --query-v4-build-registry-provenance \
    /archive/query-v4-provenance-v3.signed.json \
  --expected-query-v4-provenance-signing-tool-source-sha256 \
    "$SIGNER_V3_SOURCE_SHA256" \
  --expected-query-v4-provenance-signing-tool-source-commit-sha \
    "$SIGNER_SOURCE_COMMIT_SHA" \
  --expected-query-v4-provenance-signer-dependency-manifest-sha256 \
    "$SIGNER_DEPENDENCY_MANIFEST_SHA256" \
  --expected-query-v4-provenance-signer-runtime-image-digest \
    "$SIGNER_RUNTIME_IMAGE_DIGEST" \
  <all-v1-query-v4-readiness-l3-dsn-arguments> \
  --output /new/archive/t1-p0-preflight-v2.json
```

输出为 `0600`、create-only。命令不连接网络，不读取 DSN 内容，不执行 query，
不调用 Web Bridge/RPC，也不产生订单或持仓变化。

## Fail-closed 边界

以下任一情况都会阻断且不产生 authority：

- v2/v3 schema downgrade 或 namespace splice；
- query-v4 content attestation 不是 exact typed rerun 或 canonical storage；
- signed provenance 与 source commit、source bundle、attestation、image
  reference/digest 任一不一致；
- provenance signer key 与 T1/L3 authority key 复用；
- signer source、dependency closure、runtime image 或 keyring independent
  pin 不匹配；
- readiness-v3/L3 过期或无法精确重放；
- DSN metadata 不是当前用户持有的普通 `0600` 文件；
- 输出路径已存在。

## 后续边界

preflight-v2 仍复用 query-v3 readiness-v3 作为 upstream 安全链，不能冒充
query-v4 readiness。下一切片必须建立直接绑定 provenance-v3 的 query-v4
readiness 和人工短时 query release；之后才允许一次真实 M2 readonly
QuestDB query，成功 terminal 后才能独立评估 P0。
