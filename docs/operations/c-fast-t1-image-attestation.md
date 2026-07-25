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
- 从实际 config 同时校验顶层 `os=linux`、`architecture=amd64`，解析
  User、WorkingDir、绝对 Entrypoint、labels 和 Env；Env 必须精确等于 pinned
  官方 Python base 的四个继承项加 Containerfile 冻结的三个项，拒绝
  `LD_PRELOAD` 等任意额外环境注入；
- 要求 image `Cmd` absent/null/empty、Healthcheck absent/null、
  Volumes/OnBuild absent/empty，避免 compose 启动前继承 image 内的命令或
  hook；
- 按顺序在内存虚拟文件系统中应用 plain/gzip layers、whiteout 和 opaque
  whiteout，不向宿主文件系统 extract；每个 entry/whiteout 都拒绝已有的
  non-directory ancestor，link target 会在 image root 内安全规范化并拒绝
  越界 traversal；每层 entry 数和最终 filesystem entry 数都有固定上限，
  whiteout 仅接受 size=0 的 regular entry；
- 从最终 layer filesystem 重算两个脚本和七份 schema 的 SHA256；
- 要求 `/opt/c-fast-t1` 最终只能包含这九个普通文件，禁止 `.pyc/.pyo`、
  `__pycache__`、signer、private-key marker、额外 runtime file 或额外空目录；
  九个文件均按 uid/gid 65532 权限模型检查 read bit；
- 要求 `/opt/c-fast-t1` 及 bundle 的全部父目录按 uid/gid 65532 权限模型
  具有 traverse bit；解释器的 `/usr`、`/usr/local`、`/usr/local/bin` 父目录
  同样必须可 traverse；
- 要求绝对解释器 `/usr/local/bin/python3.12` 是 non-empty、regular 且按
  uid/gid 65532 权限模型具有 execute bit；这只验证路径、类型、长度与权限位，
  不证明解释器代码 bytes 的来源或完整性；
- 从最终 filesystem 的 `*.dist-info/METADATA` 重算其中自报的
  `cryptography/jsonschema/psycopg/psycopg-binary/referencing` 版本字段；
- 要求 immutable reference 的 digest 等于实际 manifest digest。
- 要求当前运行的 verifier 与两份 schema 的 SHA256 等于 exact source commit
  中对应 blob，并把三者 hash 写入 report。

`base_image_digest` 只表示 exact Containerfile 中存在固定 base pin；在没有
可信 build provenance 时，它不证明实际 layer 的 base lineage。Containerfile
中的直接依赖 pin 与镜像内 exact
`/usr/local/lib/python3.12/site-packages/<name>-<version>.dist-info/METADATA`
路径自报的 metadata 版本分别报告，不能
混称。`installed_dependency_metadata_versions_recomputed=true` 不校验 package
payload、module code、transitive dependency pins 或 `RECORD`，因此不证明
这些 package bytes 的完整性；伪造或漂移的 package payload 仍属于 build
provenance gap，报告状态不会因此升格，也不能进入
`READY_FOR_HUMAN_SIGNATURE_ONLY`。

Containerfile 与正式 runtime template 都使用绝对
`/usr/local/bin/python3.12`，并冻结 PATH；template 还显式禁用 healthcheck。
Containerfile 不设置 `CMD`；Docker/BuildKit 在设置 `ENTRYPOINT` 时应把基础
镜像继承的默认参数重置为 absent/null，verifier 也兼容语义等价的空数组。
正式 template 的 frozen `command` 负责提供 one-shot 参数。二者都不授予
authority，也不代表无需 runner 内部的 signed-release 校验。

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
