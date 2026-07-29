# C_FAST query-v3 source bundle 与 OCI content attestation

本文对应 Issue #155，仅定义 Research / Control Plane 的离线 Evidence
合同。它不会构建、推送或部署镜像，不会访问 registry、QuestDB、DSN 或 Web
Bridge，也不会授予 query、collection、dispatch、trading 或 production
authority。

当前 `Containerfile.query-v3` 仍处于
`INVALID_BLOCKED_NOT_RUNNABLE_NOT_AUTHORITY`。生成 source bundle 或通过本文的
content verifier，都不能把 blocked packaging 解释为可运行。

## 两阶段边界

### 构建侧 source-bundle producer

[`create_query_v3_source_bundle.py`](../../scripts/c_fast_t1/create_query_v3_source_bundle.py)
只在受控构建侧运行。它需要一个本地 Git repository 和精确的 40 位 commit：

```bash
mkdir -m 700 /private/c-fast-query-v3-source

python scripts/c_fast_t1/create_query_v3_source_bundle.py \
  --source-root /absolute/path/vnpy-web-bridge \
  --source-commit-sha 0123456789abcdef0123456789abcdef01234567 \
  --bundle-output /private/c-fast-query-v3-source/source-bundle.tar \
  --manifest-output /private/c-fast-query-v3-source/source-manifest.json
```

producer：

- 禁用 replace objects、system/global Git config 和可变 pager；
- 要求 commit 精确解析；
- 只读取 `Containerfile.query-v3` 及其 exact `COPY` closure；
- 固定完整 normalized Containerfile instruction sequence；
- 拒绝 `ADD`、第二个 `FROM`、额外 `RUN/ENV/LABEL/USER/WORKDIR/COPY`、
  parser directive、`RUN --mount`、signer/private-key source；
- 生成 USTAR plain tar，manifest 必须是第一个 entry；
- 所有 source entry 按路径排序，并固定 uid/gid、mtime、mode；
- bundle 与单独输出的 manifest 都采用 create-only 私有写入。

`source-manifest.json` 的内容同时内嵌在 tar 的固定路径
`query-v3-source-manifest.json`。manifest 不包含 bundle 自身 SHA，避免循环
自引用；bundle raw SHA 由 external evidence、content attestation 和后续
provenance-v2 逐层绑定。

## 运行侧 content verifier

[`verify_query_v3_image_attestation.py`](../../scripts/c_fast_t1/verify_query_v3_image_attestation.py)
只读取四个 exact artifact：

```bash
mkdir -m 700 /private/c-fast-query-v3-attestation

python scripts/c_fast_t1/verify_query_v3_image_attestation.py \
  --external-image-evidence \
    /private/c-fast-query-v3-input/external-image-evidence.json \
  --source-bundle-archive \
    /private/c-fast-query-v3-source/source-bundle.tar \
  --oci-layout-archive \
    /private/c-fast-query-v3-input/runtime.oci.tar \
  --expected-source-commit-sha \
    0123456789abcdef0123456789abcdef01234567 \
  --output \
    /private/c-fast-query-v3-attestation/content-attestation.json
```

verifier 没有 `--source-root` 参数，不 import `subprocess`，不运行 Git，也不需要
repository mount。它 fail closed 检查：

- source bundle 的 raw SHA、canonical manifest identity、schema 和 exact
  allowlist；
- entry 顺序、path、size、SHA256、mode、uid/gid、mtime；
- duplicate、missing、extra、traversal、link、device、PAX、oversize 和
  replacement；
- 完整 Containerfile instruction identity、base digest、依赖、COPY 和
  isolated query-v3 ENTRYPOINT；
- OCI layout/index/manifest/config/layer descriptor 与 raw digest；
- 最终 layer/diff-id 必须以前述 pinned base 的 linux/amd64 四层为精确前缀，
  post-base 只能修改固定 runtime、十一项完整 dependency closure、固定
  console script 和 custody directory；
- linux/amd64、non-root user、环境、labels、revision、ENTRYPOINT 和 neutral
  runtime hooks；
- 除固定 runtime `.pth` 外拒绝所有额外 `.pth`、`sitecustomize`、
  `usercustomize` 和 `.egg-link`，并把 interpreter、stdlib、site-packages
  的完整路径、内容 hash、权限和 link metadata 收敛成
  `python_execution_closure_sha256`；
- hardlink 按目标 regular-file 内容建模；原路径在后层被 whiteout 后，
  alias 内容仍参加 signer/private-key 扫描；
- 最终 layer filesystem 的 exact runtime bundle 与 source bundle
  byte-for-byte SHA 对应；
- extra runtime path、bytecode、signer/private-key path 或内容。

external evidence 是 unsigned external claim。verifier 会从 source bundle 和 OCI
layers 重新计算事实；修改 JSON 不能伪造 bundle、Containerfile、OCI、image
digest 或 runtime file hash。

成功状态固定为：

```text
QUERY_V3_SOURCE_BUNDLE_AND_OCI_CONTENT_VERIFIED_NO_BUILD_OR_REGISTRY_PROVENANCE
```

输出仍固定：

```text
image_built_here=false
cryptographic_approval_present=false
authority_granted=false
network_authorized=false
production_query_authorized=false
collection_authorized=false
deployment_mutation_authorized=false
runtime_activation_authorized=false
dispatch_authorized=false
trading_authorized=false
production_authorized=false
```

## source commit 语义

运行侧没有 Git object database，因此它证明的是：

1. exact source bundle 与 manifest 一致；
2. OCI runtime bytes 与 source bundle 一致；
3. OCI revision、external evidence 和 supplied source commit assertion 一致。

它不会声称独立从 Git hosting 或 object database 解析过 commit。attestation
明确记录：

```text
source_commit_assertion_bound=true
git_binary_required=false
git_commit_independently_resolved=false
```

commit → source bundle 的外部 lineage 必须由后续 provenance-v2 的独立签名合同
绑定。没有 provenance-v2、query readiness 和人工 query release 时，本报告不具备
任何 authority。

## Schema

- `commodity-c-fast-t1-query-v3-source-manifest-v1.schema.json`
- `commodity-c-fast-t1-query-v3-external-image-evidence-v1.schema.json`
- `commodity-c-fast-t1-query-v3-image-attestation-v1.schema.json`

三个 schema 都使用独立 query-v3 namespace，不复用或修改 legacy one-shot
image-attestation v1 identity。

## 离线验证

```bash
python -m pytest -q \
  backend/tests/unit/test_c_fast_t1_query_v3_image_attestation.py

ruff check \
  scripts/c_fast_t1/create_query_v3_source_bundle.py \
  scripts/c_fast_t1/verify_query_v3_image_attestation.py \
  backend/tests/unit/test_c_fast_t1_query_v3_image_attestation.py

python -m py_compile \
  scripts/c_fast_t1/create_query_v3_source_bundle.py \
  scripts/c_fast_t1/verify_query_v3_image_attestation.py \
  backend/tests/unit/test_c_fast_t1_query_v3_image_attestation.py
```

后续 query-v3 readiness/runtime integration 必须作为独立 issue，把固定 verifier
和 schema 加入最终 runtime closure，并基于最终 merge commit 重新冻结
source-bundle、OCI、RepoDigest 与 provenance。该后续动作不在 Issue #155 范围内。
