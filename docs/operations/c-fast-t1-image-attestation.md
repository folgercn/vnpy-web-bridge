# C_FAST T1 精确镜像证据校验

## 当前结论

本切片只提供 **外部 OCI 构建证据的离线校验合同**。当前开发机没有 Docker、
Podman、BuildKit、Nerdctl、ORAS、Cosign 或 Skopeo，因此没有在本机生成镜像，也
不能把校验报告解释为镜像已构建、已推送、已部署或已获得 T1 查询权限。

成功报告的固定状态是：

```text
EXTERNAL_BUILD_EVIDENCE_VERIFIED_NOT_IMAGE_BUILT_HERE
```

并固定：

```text
image_built_here=false
authority_granted=false
deployment_mutation_authorized=false
production_query_authorized=false
execution_quality_collection_authorized=false
order_submission_authorized=false
position_mutation_authorized=false
dispatch_authorized=false
database_mutation_authorized=false
dynamic_selection_allowed=false
```

## 外部构建方必须归档的事实

构建必须以即将运行版本的 exact 40 位 commit 为输入，并使用该 commit 的
`git archive --format=tar` 字节流。外部、受控的 OCI 构建/检查环境需要将以下机器
事实写入一份全新的 evidence JSON：

- exact source commit 和 `git archive` SHA256；
- `Containerfile.one-shot` SHA256、固定 base digest 和四个直接依赖版本；
- `repository@sha256:...`、manifest digest、image ID、镜像导出包 SHA256；
- 有序 RootFS layer digests；
- 实际 User、WorkingDir、Entrypoint、相关环境变量和 OCI labels；
- 镜像内两个脚本及七份 schema 的逐文件 SHA256；
- forbidden path、额外 bundle path、signer/private-key path 扫描结果均为空。

模板位于
`docs/operations/c-fast-t1-external-image-evidence.template.json`。模板内所有
digest、commit、时间和 producer 都是假值，禁止直接签署或用于运行。

## 离线核验

在包含 exact commit 对象的仓库中执行：

```bash
python scripts/c_fast_t1/verify_image_attestation.py \
  --evidence /absolute/path/external-image-evidence.json \
  --source-root /absolute/path/vnpy-web-bridge \
  --expected-source-commit-sha '<exact-40-char-merge-sha>' \
  --json-output /new/path/image-attestation.json
```

校验器从 Git 对象库重新读取 Containerfile、两个脚本和七份 schema，并重新计算
exact commit 的 archive SHA，而不是信任当前工作树或 evidence 自报的 source
hash。输出采用 create-only、0600 写入；已有路径、symlink、duplicate JSON key、
NaN/Infinity、可变 tag、revision/user/entrypoint 漂移、bundle 增删或 hash 漂移都
会 fail closed。

## 权限边界与后续顺序

这份 report 没有签名能力，也不恢复任何 authority。它只能作为下一份人工 L3
readonly deployment release 的 raw-byte hash 输入。实际顺序仍为：

1. 外部构建、推送并采集 exact OCI 证据；
2. 本校验器生成无权限 report；
3. 人工复核并签署独立 L3 readonly deployment release；
4. 完成只读 principal、隔离网络、writer continuity、健康和回滚核验；
5. 生成人工签署前 T1 readiness packet；
6. 人工签署 one-shot T1 release 后才可执行一次 T1。

本切片不修改 workflow、deployment、QuestDB、订单、持仓或 dispatch。
