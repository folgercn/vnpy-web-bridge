# C_FAST T1 OCI artifact 内容校验

## 当前结论

本切片只验证一份外部 OCI image-layout tar 的实际内容。它不在本机构建镜像，
也没有可信 builder/registry 签名，因此成功状态固定为：

```text
EXTERNAL_OCI_ARTIFACT_CONTENT_VERIFIED_NO_BUILD_OR_REGISTRY_PROVENANCE
```

这个状态只证明“提供的 OCI archive 内容与 exact source/runtime 合同一致”，不
证明谁构建了它、构建环境是否可信、该 digest 当前存在于哪个 registry，或
registry reference 的 custody。它不能单独让 T1 readiness 进入
`READY_FOR_HUMAN_SIGNATURE_ONLY`；后续必须另有受信 build/registry provenance
或人工 release 明确承担该缺口。

报告固定声明 `build_provenance_verified=false`、
`registry_provenance_verified=false`、`image_built_here=false`，并将 query、
write probe、database/deployment mutation、collection、runtime activation、
order、position、dispatch、replacement、production、dynamic selection 和
automatic promotion 等权限全部固定为 `false`。

## 必需输入

外部环境必须同时归档：

1. exact 40 位 source commit；
2. 由该 source 生成的 `git archive --format=tar` SHA256；
3. plain tar 格式的 OCI image-layout archive；
4. 一份 unsigned capture JSON，记录 producer、预期 source/container pin 和
   OCI 字段。

unsigned JSON 只是待核对的 claim，不是事实源。校验器不再依据空数组或自报
digest 直接出具成功报告。模板位于
`docs/operations/c-fast-t1-external-image-evidence.template.json`，其中所有
digest、commit、时间和 producer 均为假值。

## 校验器实际重算的事实

校验器直接读取 `--oci-layout-archive`，并：

- 拒绝外层 tar 的路径穿越、duplicate path、symlink/hardlink、非普通文件、
  非 OCI layout 路径和超限输入；
- 验证 `oci-layout`、单一 `linux/amd64` index/manifest、descriptor size 和
  所有 blob path/digest，无未引用 blob；
- 从原始字节重算 archive、manifest、config 和有序 compressed layer digest；
- 校验 config `rootfs.diff_ids` 与 plain/gzip layer 的 uncompressed digest；
- 从实际 config 解析 User、WorkingDir、Entrypoint、labels 和 Env，拒绝敏感
  environment；
- 按顺序在内存虚拟文件系统中应用 plain/gzip layers、whiteout 和 opaque
  whiteout，不向宿主文件系统 extract；
- 从最终 layer filesystem 重算两个脚本和七份 schema 的 SHA256；
- 要求 `/opt/c-fast-t1` 最终只能包含这九个普通文件，禁止 `.pyc/.pyo`、
  `__pycache__`、signer、private-key marker 或任何额外 runtime file；
- 从最终 filesystem 的 `*.dist-info/METADATA` 实算
  `cryptography/jsonschema/psycopg/psycopg-binary/referencing` 版本；
- 要求 immutable reference 的 digest 等于实际 manifest digest。
- 要求当前运行的 verifier 与两份 schema 的 SHA256 等于 exact source commit
  中对应 blob，并把三者 hash 写入 report。

`base_image_digest` 只表示 exact Containerfile 中存在固定 base pin；在没有
可信 build provenance 时，它不证明实际 layer 的 base lineage。Containerfile
中的直接依赖 pin 与镜像内实际安装版本分别报告，不能混称。

Git 读取固定禁用 replace objects，并隔离可能改变 object lookup 的环境变量。
Containerfile 在 `py_compile` 自检后必须删除所有 `.pyc/.pyo` 和空
`__pycache__`；runtime packaging validator 冻结了这条指令。

## 离线命令

```bash
python scripts/c_fast_t1/verify_image_attestation.py \
  --evidence /absolute/path/external-image-evidence.json \
  --oci-layout-archive /absolute/path/c-fast-t1.oci.tar \
  --source-root /absolute/path/vnpy-web-bridge \
  --expected-source-commit-sha '<exact-40-char-source-sha>' \
  --json-output /new/path/image-attestation.json
```

输入文件必须是普通非 symlink 文件，并进行 path/fd 双读一致性校验。输出采用
create-only、0600、完整写入和 `fsync`；已有路径不会覆盖。

## 后续顺序

1. 外部受控环境构建并导出 exact OCI layout；
2. 本校验器只生成 content-verified、无 provenance、无 authority 的 report；
3. 独立验证并绑定 build/registry provenance；
4. 人工复核并签署 L3 readonly deployment release；
5. readiness packet 对真实 image report 和 signed L3 release 做验签与
   exact-byte 绑定；
6. 人工签署 one-shot T1 release 后才可执行一次 T1。

本切片不修改 deployment/workflow，不查询 QuestDB，不采集、不发单、不修改
持仓或 dispatch。
