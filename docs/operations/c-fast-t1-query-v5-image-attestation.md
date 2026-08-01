# C_FAST query-v5 final OCI composition attestation

本切片对应 Issue #216 的离线 composition proof。它同时重放 query-v4 content
attestation 与 raw OCI，并把 query-v5 code-only source bundle、final OCI 和 unsigned
external claims 收敛成一份 create-only receipt。它不构建或推送镜像，不访问
registry、网络、QuestDB 或 DSN，不运行 launcher，也不产生签名或任何 query /
production authority。

成功状态固定为：

```text
QUERY_V5_BASE_AND_OVERLAY_OCI_COMPOSITION_VERIFIED_NO_BUILD_OR_REGISTRY_PROVENANCE
```

## 输入与重放边界

[`verify_query_v5_image_attestation.py`](../../scripts/c_fast_t1/verify_query_v5_image_attestation.py)
要求九项 exact 输入：query-v4 external evidence、source bundle、raw OCI、已有
content attestation 与 source commit，以及 query-v5 external evidence、source bundle、
final OCI 与 source commit。

verifier 首先调用 query-v4 verifier 重新计算 content report，再要求 supplied
query-v4 attestation payload 与重放结果完全相等；只给一个历史 JSON digest 不足以
通过。随后它分别解析两份 OCI layout，并检查：

- 都是唯一的 linux/amd64 OCI manifest，所有 descriptor、blob、config、layer 与
  diff-id 从 raw bytes 重算，拒绝 missing/unreferenced blob；
- final 的完整 query-v4 layer descriptor 与 diff-id 序列是 exact prefix；
- 至少有一个 query-v5 overlay layer；overlay 禁止 whiteout、symlink、hardlink、
  device/special entry，禁止覆盖 query-v4 中任何 file 或 directory；
- overlay 只能触碰 `/opt/c-fast-query-v5/**` 与
  `/run/c-fast-t1-query-v5-pins` 固定闭包；最终 runtime path 必须与 source bundle
  byte-for-byte 一致，root-owned 且不可写；
- merged rootfs 的 Python startup/execution closure 重新扫描，其 closure hash 与
  entry count 必须与重放后的 query-v4 attestation 完全相同；
- non-root user、isolated ENTRYPOINT、working directory、环境、完整 labels、base
  immutable reference 与 final immutable reference 全部精确匹配，其他继承的 OCI
  runtime config 字段不得新增或漂移；
- extra runtime path、bytecode、signer/private-key path 或私钥内容 fail closed。

external evidence schema 是严格的 unsigned claim envelope。其 image digest、ID、
export SHA、layer/diff-id、config、overlay touched paths 与 runtime file hashes 都由
verifier 重算，JSON 本身不提供 trust。

## 离线运行

先把模板复制到私有 capture 目录并替换为实际 inspector 输出：

```bash
cp docs/operations/c-fast-t1-query-v5-external-image-evidence.template.json \
  /private/c-fast-query-v5-input/external-image-evidence.json
```

然后只读验证，并写入一个此前不存在的绝对输出路径：

```bash
mkdir -m 700 /private/c-fast-query-v5-attestation

python scripts/c_fast_t1/verify_query_v5_image_attestation.py \
  --query-v4-external-image-evidence /private/query-v4/external-image-evidence.json \
  --query-v4-source-bundle-archive /private/query-v4/source-bundle.tar \
  --query-v4-oci-layout-archive /private/query-v4/runtime.oci.tar \
  --query-v4-content-attestation /private/query-v4/content-attestation.json \
  --expected-query-v4-source-commit-sha <40-hex-query-v4-commit> \
  --external-image-evidence /private/c-fast-query-v5-input/external-image-evidence.json \
  --source-bundle-archive /private/c-fast-query-v5-input/source-bundle.tar \
  --oci-layout-archive /private/c-fast-query-v5-input/final.oci.tar \
  --expected-source-commit-sha <40-hex-query-v5-commit> \
  --output /private/c-fast-query-v5-attestation/composition-attestation.json
```

输出是 create-only、mode `0600`。已有路径、相对路径、symlink output 或变化中的
input 都会 fail closed。

## 明确不证明的事项

receipt 中以下结论固定为 false：

```text
image_built_here=false
build_provenance_verified=false
registry_provenance_verified=false
cryptographic_approval_present=false
authority_granted=false
network_authorized=false
production_query_authorized=false
runtime_activation_authorized=false
trading_authorized=false
production_authorized=false
```

因此通过本 verifier 只代表给定 source/OCI bytes 的离线 composition 一致性，不代表
这些 bytes 来自受信 builder、已 push 到 registry、RepoDigest 已确认、可以连接 DSN
或可以执行 query。下一阶段仍须基于最终 merge commit 完成实际 build/push、registry
capture 与独立签名 provenance，之后才能进入 release-v5 lifecycle；本切片不加入
release signer、parent/child、DSN 或 query path。

## Schema 与测试

- `commodity-c-fast-t1-query-v5-source-manifest-v1.schema.json`
- `commodity-c-fast-t1-query-v5-external-image-evidence-v1.schema.json`
- `commodity-c-fast-t1-query-v5-image-attestation-v1.schema.json`

```bash
PYTHONPATH=backend:scripts python -m pytest -q \
  backend/tests/unit/test_c_fast_t1_query_v5_image_attestation.py

ruff check \
  scripts/c_fast_t1/verify_query_v5_image_attestation.py \
  backend/tests/unit/test_c_fast_t1_query_v5_image_attestation.py
```
