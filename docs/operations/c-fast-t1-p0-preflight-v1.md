# C_FAST 真实 T1/P0 preflight v1

本文对应 Issue #216 的首个可独立合并切片。它补齐 query-v4 的 exact
source bundle、OCI content attestation 和查询前 fail-closed preflight。整个
流程只读本地文件，不连接 M2、QuestDB、Web Bridge、TradeService、CTP 或
SimNow。

## 当前结论

preflight 成功只表示以下输入在同一次短时检查中相互一致：

- query-v4 source bundle 来自一个可精确解析的 40 位 Git commit，bundle
  只包含 `Containerfile.query-v4` 的 exact COPY closure；
- query-v4 OCI layout、RepoDigest、runtime 文件、依赖、入口、标签和 source
  bundle 逐字节一致；
- readiness-v3 仍处于有效期内，并已由既有 verifier 从 source/image、
  provenance-v2、L3 outcome 和 root-owned pins 精确重放；
- query-v4 与 readiness-v3 使用同一个 source commit；
- readonly DSN 是当前用户持有的普通非符号链接文件，权限为 `0600` 或更严。

固定输出：

```text
status=QUERY_V4_SOURCE_OCI_AND_UPSTREAM_PREFLIGHT_VERIFIED_PROVENANCE_BLOCKED
production_query_attempted=false
p0_verdict=NOT_RUN
authority_granted=false
```

preflight 不读取 DSN 内容，只记录路径的 SHA256 和
device/inode/uid/mode/size。输出中不得出现 DSN、用户名、密码或主机地址。

## 为什么仍然 BLOCKED

本切片建立 query-v4 自己的 source/OCI 身份，不能复用 query-v3 attestation
冒充 query-v4。但现有 provenance-v2/readiness-v3 仍绑定 query-v3 content
schema。因此 preflight 固定保留两个 blocker：

```text
QUERY_V4_SIGNED_BUILD_REGISTRY_PROVENANCE_NOT_YET_VERIFIED
QUERY_V4_READINESS_AND_HUMAN_RELEASE_NOT_YET_DERIVED
```

只有后续独立实现并验证 query-v4 signed build/registry provenance、新
readiness 和人工 query release 后，才可进入真实 one-shot。不得手工删除
blocker、把本 artifact 签成 release，或将其解释为 P0 PASS。

## 1. 生成 exact query-v4 source bundle

在已合并且无替换对象的仓库中执行：

```bash
python3 scripts/c_fast_t1/create_query_v4_source_bundle.py \
  --source-root /srv/vnpy-web-bridge \
  --source-commit-sha <exact-40-char-merged-sha> \
  --bundle-output /secure/c-fast/query-v4-source.tar \
  --manifest-output /secure/c-fast/query-v4-source-manifest.json
```

producer 通过 `git --no-replace-objects` 读取指定 commit 的 blob，不从工作树
复制文件。输出使用确定性 USTAR：固定顺序、mtime=0、uid/gid=0、规范 mode；
目标文件必须不存在。

## 2. 构建、导出并准备 external evidence

必须以第 1 步 bundle 作为完整 build context，构建
`linux/amd64` `Containerfile.query-v4`，推送 immutable RepoDigest，并导出
OCI layout。external evidence 必须符合：

```text
docs/schemas/commodity-c-fast-t1-query-v4-external-image-evidence-v1.schema.json
```

external evidence 是 unsigned capture，不是 build/registry provenance，也不
提供任何 authority。

## 3. 独立重算 query-v4 OCI content

```bash
python3 scripts/c_fast_t1/verify_query_v4_image_attestation.py \
  --external-image-evidence /secure/c-fast/query-v4-image-evidence.json \
  --source-bundle-archive /secure/c-fast/query-v4-source.tar \
  --oci-layout-archive /secure/c-fast/query-v4-runtime.oci.tar \
  --expected-source-commit-sha <exact-40-char-merged-sha> \
  --output /secure/c-fast/query-v4-content-attestation.json
```

verifier 不使用 Git 或仓库挂载。它重新计算 source manifest、OCI
manifest/config/layers、base image prefix、Python execution closure、
runtime bundle、依赖版本和敏感文件扫描。任何 symlink、重复 tar entry、
extra blob、额外 runtime 文件、可写代码、signer/private key 或 mutable
image reference 均 fail closed。

## 4. 生成查询前 preflight

先由既有流程部署 root-owned readiness-v3 pins，并把所有 L3/source/post
evidence 作为 exact-file mount。然后执行：

```bash
python3 scripts/commodity_c_fast_t1_p0_preflight.py \
  --query-v4-external-image-evidence /secure/c-fast/query-v4-image-evidence.json \
  --query-v4-source-bundle-archive /secure/c-fast/query-v4-source.tar \
  --query-v4-oci-layout-archive /secure/c-fast/query-v4-runtime.oci.tar \
  --query-v4-content-attestation /secure/c-fast/query-v4-content-attestation.json \
  --expected-query-v4-source-commit-sha <exact-40-char-merged-sha> \
  --expected-query-v4-image-digest sha256:<64-lowercase-hex> \
  --dsn-file /run/secrets/c-fast-t1-query-v4-readonly.dsn \
  --readiness-packet /var/lib/c-fast-t1-readiness/readiness-v3-<sha256>.json \
  --external-image-evidence <readiness-v3-query-v3-image-evidence> \
  --oci-layout-archive <readiness-v3-query-v3-oci-layout> \
  --source-bundle-archive <readiness-v3-query-v3-source-bundle> \
  --content-attestation <readiness-v3-query-v3-content-attestation> \
  --provenance <readiness-v3-signed-provenance-v2> \
  --provenance-keyring <root-pinned-provenance-keyring> \
  --t1-keyring <root-pinned-t1-keyring> \
  --outcome <signed-l3-outcome> \
  --outcome-keyring <root-pinned-outcome-keyring> \
  --expected-t1-runtime-source-commit-sha <same-exact-merged-sha> \
  --expected-t1-runtime-image-digest sha256:<readiness-v3-image-digest> \
  --expected-l3-contract-source-commit-sha <exact-l3-contract-sha> \
  --expected-outcome-contract-source-commit-assertion <exact-outcome-sha> \
  --expected-questdb-image-digest sha256:<questdb-image-digest> \
  --release <signed-l3-release> \
  --release-keyring <root-pinned-l3-keyring> \
  --consume-marker <l3-consume-marker> \
  --receipt <l3-receipt> \
  --questdb-image-attestation <l3-pre-evidence> \
  --readonly-principal-identity-attestation <l3-pre-evidence> \
  --secret-file-identity-attestation <l3-pre-evidence> \
  --writer-continuity-pre-evidence <l3-pre-evidence> \
  --writer-continuity-post-evidence <l3-pre-evidence> \
  --health-evidence <l3-pre-evidence> \
  --backlog-evidence <l3-pre-evidence> \
  --rollback-plan <l3-pre-evidence> \
  --root-pin-identity-attestation <l3-pre-evidence> \
  --custody-path-identity-attestation <l3-pre-evidence> \
  --isolated-network-attestation <l3-pre-evidence> \
  --deployment-plan <l3-pre-evidence> \
  --execution <l3-post-evidence> \
  --writer-post <l3-post-evidence> \
  --health-post <l3-post-evidence> \
  --backlog-post <l3-post-evidence> \
  --principal-secret-post <l3-post-evidence> \
  --network-post <l3-post-evidence> \
  --output /secure/c-fast/t1-p0-preflight.json
```

命令只允许在已授权的本地/M2 文件上下文运行。它不需要也不应获得网络
namespace。输出为 `0600`、create-only，重复路径会失败。

## 失败处理

- 不允许通过修改 JSON、复制旧 artifact、放宽权限或替换 symlink 继续；
- commit、source bundle、OCI 或 readiness 任一不一致时，重新从 exact merged
  SHA 构建全链；
- readiness-v3 或 L3 outcome 过期时，重新生成短时 evidence，不能延长时间戳；
- DSN 权限不合格时由人工修复为 `0600`，不得把 secret 内容复制进日志；
- 本 runbook 不授权 network/query/deploy/mutation/RPC/order/position/trading。

## 后续边界

下一切片需要为 query-v4 建立独立 signed build/registry provenance 和
readiness contract。完成后仍需人工签署短时 query-release-v4，真实 terminal
显示 `production_query_attempted=true` 且完整 create-only custody 验证通过，
才有资格独立评估 P0。P0 acceptance 仍不产生 collection 或交易权限。
