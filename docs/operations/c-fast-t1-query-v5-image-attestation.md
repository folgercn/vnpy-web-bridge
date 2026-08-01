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
- 每个 overlay layer raw tar 与每个 bounded regular member 都检查私钥 marker；
  每层只能出现 fixed directory 或 exact source runtime file，且当层 path、type、
  content hash、root uid/gid 与允许的 build/final mode 必须立即匹配；后续 layer
  恢复 exact final file 不能掩盖旧 layer blob 中的 payload 或 type 漂移；
- 每个 overlay layer 必须是其 exact members 的唯一 canonical USTAR 编码；拒绝
  local/global PAX、GNU longname/sparse/extended records、未冻结 header 字段、
  非零 padding、非规范 EOF 和 trailing bytes。layer digest 之外不存在未被
  member contract 解释的隐藏 raw payload；
- base/final OCI config raw bytes 与解析后的所有嵌套 string 都检查敏感内容，不能把
  私钥藏在 `history`、`author` 或其他非-runtime config 字段；
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

### 独立 attestation runtime trust root

正式入口禁止直接运行 verifier、shebang 或依赖 `PYTHONPATH`。独立 release 必须把
launcher、v5/v4 verifier、v4 delegate、v5/v4 validators、全部 schemas 与固定第三方
依赖封装进 root-owned、runtime 不可写的 attestation image，并由独立流程填写：

```text
/run/c-fast-t1-query-v5-image-attestation-pins/pin-set.manifest.json
```

pin-set schema/template 分别是
`commodity-c-fast-t1-query-v5-image-attestation-pin-set-v1.schema.json` 与
`c-fast-t1-query-v5-image-attestation-pin-set.template.json`。不能在目标 runtime 内
从当前文件反推 expected pins。pin-set 固定 immutable runtime image RepoDigest、
launcher/verifier/delegate/validator、解释器、source root、dependency root 与两份完整
closure manifest。

唯一支持的入口使用固定解释器与隔离 flags：

```bash
<PINNED_PYTHON> -I -S -s -E -B \
  /opt/c-fast-query-v5-attestation/release/scripts/commodity_c_fast_t1_query_v5_image_attestation_launcher.py \
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

launcher 在任何本地 verifier/delegate/validator 或第三方 import 前 stable-FD 读取并
验证 pin generation、launcher、解释器、Linux `/proc/self/exe`、完整 source tree 与
dependency tree。它拒绝 symlink/hardlink/special file、group/world write、`.pth`、
`.egg-link`、`sitecustomize`、`usercustomize`；本地 modules 只从首次扫描保留的 exact
bytes 加载。导入前后、receipt create-only 写入前后都会重验 closure。runtime
RepoDigest、launcher/verifier/interpreter、明确的 v4 delegate/validators 与
source/dependency manifests 全部进入 `attestation_runtime` 和
`runtime_identity_sha256`。

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
  scripts/commodity_c_fast_t1_query_v5_image_attestation_launcher.py \
  scripts/c_fast_t1/verify_query_v5_image_attestation.py \
  backend/tests/unit/test_c_fast_t1_query_v5_image_attestation.py
```
