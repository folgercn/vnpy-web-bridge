# C_FAST query-release-v4 runtime packaging

本文对应 Issue #139，基线为 `origin/main@90db2c4`。本切片属于 Research
Plane runtime isolation 与 Control Plane 离线合同校验，不进入 Execution
Plane，也不增加交易 Authority。

## 当前结论

离线 validator 的成功状态固定为：

```text
QUERY_V4_CODE_ONLY_PACKAGING_VALID_RUNTIME_BLOCKED
```

它证明 query-v4 Containerfile、runtime template、parent/child/audit 与 schema
closure 自洽；它不证明镜像已经构建、推送、attest、部署或执行。模板保持：

```text
template_state=INVALID_BLOCKED_NOT_RUNNABLE_NOT_AUTHORITY
runtime_execution_ready=false
image_built=false
image_pushed=false
deployed=false
production_queried=false
authority_granted=false
blocking_reasons=[
  QUERY_V4_SOURCE_BUNDLE_CONTENT_IDENTITY_NOT_FROZEN,
  FINAL_MERGED_SHA_OCI_NOT_BUILT_ATTESTED_DEPLOYED_OR_SIGNED
]
```

现有 query-v3 bounded content verifier 是 readiness-v3 的历史输入 verifier，
但它尚未冻结这组新增 v4 source/COPY identity。因此本切片不能把 v3 content
attestation 冒充 v4 OCI identity。本 PR 不 build/push/deploy，不读取 DSN，
不连接 QuestDB，不签 release，也不执行 query。

## v4 依赖闭包

[`Containerfile.query-v4`](../../scripts/c_fast_t1/Containerfile.query-v4)
使用独立 v4 identity，包含：

- `commodity_c_fast_t1_query_v4.py` parent；
- `commodity_c_fast_t1_query_child_v4.py` bootstrap；
- `commodity_c_fast_l1_l5_audit_v4.py` DSN 前最后 gate；
- readiness-v3；
- provenance-v2；
- query-v3 bounded source-bundle/content verifier；
- L3 release/outcome verifier；
- v4 release/consume/child-started/terminal/keyring schemas；
- readiness-v3、provenance-v2、content、L3 与 audit schemas。

明确拒绝进入 runtime：

```text
commodity_c_fast_t1_readiness_v2.py
commodity_c_fast_t1_release_v2_foundation.py
commodity_c_fast_t1_build_registry_provenance.py
scripts/c_fast_t1/verify_image_attestation.py
query release-v3 / consume-v3 / child-started-v3 / terminal-v3
query release signer / private key / writer DSN
```

因此 runtime 不再依赖 readiness-v2、provenance-v1、legacy verifier、broad Git
source root 或 signer source bytes。source input 是 bounded
`--source-bundle-archive`。

## Authority 与 downgrade 边界

release-v4 只接受：

```text
schema_version=commodity_c_fast_t1_one_shot_query_release_v4
purpose=c_fast_t1_exact_readiness_readonly_query_authority_v4
readiness.schema_version=commodity_c_fast_t1_readiness_v3
readiness.status=READY_FOR_QUERY_RELEASE_V4_HUMAN_SIGNATURE_ONLY
```

readiness-v3 还必须明确：

```text
requires_query_release_v4=true
query_release_v3_accepted=false
readiness_v2_accepted=false
```

consume、child-started 与 terminal 全部使用 v4 schema/filename。任何 release-v3、
readiness-v2 或 consume-v3 splice 在 schema/semantic gate 前即 fail closed。

## pin 与 mount 边界

readiness-v3 会绑定 pin-root directory 的 path/device/inode/owner/mode identity。
为保持该 identity，template 只读 bind 整个专用
`/run/c-fast-t1-readiness-v3-pins` 到同一路径，而不是把各 pin 文件拼装到新的
容器目录。该专用目录必须包含 readiness-v3 同一 generation：

```text
pin-set.manifest.json
provenance-keyring.sha256
provenance-signing-tool-source.sha256
provenance-signing-tool-source.commit
t1-authority-keyring.sha256
l3-authority-keyring.sha256
outcome-keyring.sha256
packet-custody.path
```

此外同目录必须有 `query-v4-authority-keyring.sha256`。它是
**generation-external late authority pin**，不属于 readiness-v3
`pin-set.manifest.json` generation；parent、bootstrap child 与 audit 会把它
作为独立 root-owned pin 重读，不能把它表述成与 readiness-v3 同 generation
冻结。

其余 evidence 使用 exact-file read-only bind；不得宽挂 input directory。packet
custody 是唯一 writable bind，用于 create-only consume/launch/attempt/terminal。
DSN 只能作为单文件只读 secret；网络只能是预批准 QuestDB-only external
network。RPC、order、position、dispatch、trading 全部固定 false。

## 离线验证

以下命令只读取代码、schema 与 template：

```bash
python scripts/c_fast_t1/validate_query_v4_runtime.py
```

validator 固定：

- base image digest、完整规范化 instruction sequence 与 dependency pins；
- exact COPY allowlist/order，拒绝 `ADD`、extra `COPY/RUN`、signer/private key；
- `python -I` ENTRYPOINT、root-owned system `.pth`、non-root/read-only runtime；
- v4 command flag 与 exact mount allowlist；
- readiness-v3 dedicated pin-root mount；
- isolated network 与 authority=false；
- template 仍为 code-only blocked state。

focused failure tests覆盖 readiness-v2/release-v3/consume-v3 downgrade、legacy
verifier COPY、RPC escalation 与拆散 readiness-v3 pin-root。

## 后续严格顺序

1. 合并本 v4 code/schema/template/runtime identity；
2. 基于最终 merge SHA 冻结 source bundle/content identity；
3. 在受控环境 build/push immutable RepoDigest；
4. 重新生成 content attestation、provenance-v2 与 L3 outcome；
5. 派生短时 readiness-v3；
6. 人工签署 query-release-v4；
7. 独立人工门禁后才允许未来 one-shot readonly query。

在第 6 步完成前，不存在 query authority；即使未来 query P0 PASS，也不自动产生
Acceptance、Deployment Authority、Execution Permit 或任何交易权限。
