# C_FAST query-v3 独立运行镜像封装边界

本文对应 Issue #139。当前切片只新增 query-v3 的独立 Containerfile、无 shell
ENTRYPOINT、严格 exact-file mount 清单和离线 validator。它没有构建或推送镜像，
没有部署、联网、读取 DSN 或查询 QuestDB。

## 当前结论

离线验证成功状态刻意命名为：

```text
QUERY_V3_CODE_ONLY_PACKAGING_VALID_RUNTIME_BLOCKED
```

它只证明新增的 query-v3 封装文件内部自洽，不表示镜像可执行真实 T1。模板固定：

```text
template_state=INVALID_BLOCKED_NOT_RUNNABLE_NOT_AUTHORITY
runtime_execution_ready=false
image_built=false
image_pushed=false
deployed=false
production_queried=false
authority_granted=false
```

在以下两个 blocker 由独立后续合同闭合前，禁止删除 `INVALID`、禁止构建正式
artifact、禁止签署 readiness/query release，更不能运行 live P0。

## 两个 fail-closed blocker

### 1. provenance verifier 仍要求 signer 源文件

`commodity_c_fast_t1_build_registry_provenance.py` 在验签时会读取并重算
`commodity_c_fast_t1_build_registry_provenance_sign.py` 的 SHA256。把签署工具复制
进 runtime image 违反 signer/runtime 隔离，所以本 Containerfile 明确不复制它。
结果是当前 provenance revalidation 会在读取 DSN 前 fail closed。

后续必须把“签署工具历史身份”改成由独立 attestation/provenance artifact 绑定，
runtime verifier 只验证签名和已签 source identity，不再要求镜像包含 signer
实现。不得通过改文件后缀、base64 包装或只去掉可执行位把 signer bytes 偷渡进
runtime image。

### 2. readiness-v2 仍复用 legacy image attestation

当前 readiness-v2 调用的 content verifier 固定检查：

- `scripts/c_fast_t1/Containerfile.one-shot`；
- legacy `commodity_c_fast_t1_one_shot.py` ENTRYPOINT；
- legacy v1 runtime bundle；
- 一个完整 git checkout，并在运行时执行 `git rev-parse` / `git archive`。

它不能证明新的 query-v3 Containerfile/runtime bundle。把整个 git checkout
宽挂到生产 query 容器也扩大了运行时可读面。本模板因此不挂载 source root，
`--source-root` 固定为不可运行的
`INVALID_PENDING_QUERY_V3_RUNTIME_SOURCE_VERIFIER_REFACTOR`。

后续必须新增独立 query-v3 runtime content verifier：直接验证预先冻结的 source
archive/manifest 与 query-v3 COPY allowlist、ENTRYPOINT、OCI config/layers，
运行时不依赖 git binary，也不挂完整 repository。

## 已封装的 query-v3 依赖

[`Containerfile.query-v3`](../../scripts/c_fast_t1/Containerfile.query-v3)
独立于 legacy `Containerfile.one-shot`，包含：

- query-v3 parent、bootstrap child 和只读 audit；
- readiness-v2、L3 deployment outcome/release、build provenance 的 verifier；
- query-v3/readiness/L3/audit 的固定 schema closure；
- pinned Python dependencies；
- non-root `65532:65532`、只读 `/opt/c-fast-t1`；
- root-owned 且只读的 system `.pth` 固定 sibling module path；
- exec-form `python -I /opt/c-fast-t1/scripts/commodity_c_fast_t1_query_v3.py`。

query-v3 parent 使用 sibling Python modules。镜像构建时把唯一固定路径
`/opt/c-fast-t1/scripts` 写入 root-owned、`0444` 的 system `.pth`；隔离解释器
只读取该 system site 配置，不读取环境 `PYTHONPATH` 或 user site。ENTRYPOINT
直接启动 parent，没有 shell、运行时 `-c` bootstrap 或可变插件路径。child
和 audit 仍各自使用隔离解释器。

## mount 边界

[`c-fast-t1-query-v3-runtime.template.yml`](c-fast-t1-query-v3-runtime.template.yml)
是严格 JSON 格式的无效模板：

- query keyring、manifest、OCI archive、attestation、provenance、L3 pre/post
  evidence 全部逐文件只读 bind，不允许宽挂 input directory；
- L3 consume/receipt/outcome 和 custody identity 逐文件挂到 exact L3 custody
  path，容器不能改写整个 L3 custody；
- query release 和 readiness packet 位于 pinned packet custody，并额外用
  read-only file bind 覆盖；
- packet custody 是唯一可写 bind，用于 create-only consume、launch、attempt
  bundle、artifact 和 terminal；
- DSN 单文件只读挂载；
- 只有预批准的 QuestDB-only external network；
- 无 Docker socket、host network、privileged、device、RPC 或交易挂载。

这些 mount 只是未来运行合同清单，不会绕过上述两个 blocker。

## 离线验证

该命令只读取仓库文件，不构建镜像、不访问网络：

```bash
python scripts/c_fast_t1/validate_query_v3_runtime.py
```

可选 create-only 私有报告：

```bash
mkdir -m 700 /private/query-v3-packaging-review
python scripts/c_fast_t1/validate_query_v3_runtime.py \
  --output /private/query-v3-packaging-review/validation.json
```

validator 固定检查：

- 完整规范化 Containerfile instruction 序列、唯一 base digest、指令顺序和参数；
- Python dependency pin、COPY allowlist/order，并拒绝 `ADD`、第二个 `FROM`、
  `RUN --mount`、任意额外 `RUN` 或改变 Dockerfile 语义的 parser directive；
- runtime 不包含 query release signer、P0 signer、private key 或 secret；
- query-v3 parent/child/schema closure；
- `-I`、固定 system `.pth`、non-root user、只读 runtime；
- command flag 完整性；
- exact-file mounts、唯一可写 packet custody；
- isolated network 和全部 authority=false；
- blocker/INVALID 状态不能被静默改成 ready。

## 后续严格顺序

1. 新增不含 signer、无 broad git source-root 的 query-v3 runtime source verifier；
2. 新增 query-v3 OCI content attestation/provenance identity；
3. 更新 readiness/query historical chain 绑定新的 exact identity；
4. focused、相邻 trust-chain 和实际离线 OCI render/inspect 验证；
5. 人工 review 后才允许构建并归档 exact RepoDigest；
6. 再进入 L3 outcome、readiness、人工 query release、live one-shot P0。

本切片不会改变 legacy Containerfile、legacy validator、已有 image attestation，
也不会赋予 query、collection、runtime、dispatch 或 trading authority。
