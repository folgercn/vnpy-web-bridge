# C_FAST query-v5 code-only overlay runtime

本切片属于 Research Plane，不改变 Authority，也不影响生产交易。它只冻结
query-v5 overlay 的 source bundle、Containerfile 和独立启动信任根；没有
query-release-v5、query child、DSN 参数或查询路径。

## 当前结论

离线 validator 唯一成功状态为：

```text
QUERY_V5_CODE_ONLY_OVERLAY_PACKAGING_VALID_RUNTIME_BLOCKED
```

launcher 即使完整验证 root-owned pin generation，也只输出：

```text
QUERY_V5_OVERLAY_RUNTIME_IDENTITY_VERIFIED_CODE_ONLY_BLOCKED
```

随后以非零状态退出。上述状态不代表镜像已构建、attest、push、deploy 或取得
网络/查询权限。所有 authority 字段固定为 false。

## Base 与 overlay 边界

`Containerfile.query-v5` 必须通过 `QUERY_V4_BASE_IMAGE` 接受一个未来由
readiness-v4 绑定的 immutable query-v4 `repository@sha256:...`。当前切片不信任
该 build arg，也不声称完成 OCI composition 证明。下一切片必须同时重放：

1. query-v4 source bundle、OCI content attestation、RepoDigest 与 provenance；
2. final query-v5 source bundle、OCI layout、RepoDigest 与 provenance；
3. base layer digest 与 diff-id 是 final 的 exact prefix；
4. overlay 不含 whiteout、不覆盖任何 base path，并且只新增 allowlist 路径；
5. merged rootfs、Python execution closure 与 launcher/runtime bundle 全部重算。

在这些条件全部实现前，禁止加入 release signer、parent/child、DSN 或 query
authority。

## Launcher 信任根

正式运行只能使用：

```text
/usr/local/bin/python3.12 -I -S -s -E -B \
  /opt/c-fast-query-v5/release/scripts/commodity_c_fast_t1_query_v5_launcher.py
```

launcher 在任何后续导入前验证：Linux `/proc/self/exe` 已加载二进制、
`sys.executable`、pinned interpreter path 的 exact bytes/stat/samefile 三者一致，
以及 launcher exact bytes、source closure、root ownership、不可写性和 root-owned
canonical pin generation。source closure 对目录枚举错误 fail closed，要求每个目录
可读可执行，并以两次完整扫描及扫描前后 identity/entry 集合一致证明没有漏文件。
source-root 的外部 pin identity 仅使用可跨 OCI 部署复现的绝对路径、uid/gid/mode
和 closure hash；device/inode/timestamps 只用于同次运行的抗漂移比较，不写入 pin。

## 离线验证

```bash
python scripts/c_fast_t1/validate_query_v5_runtime.py
```

source bundle producer 只从指定 exact Git commit 读取 Containerfile COPY 闭包：

```bash
python scripts/c_fast_t1/create_query_v5_source_bundle.py \
  --source-root /path/to/vnpy-web-bridge \
  --source-commit-sha <40-hex-merged-sha> \
  --bundle-output /absolute/create-only/query-v5-source.tar \
  --manifest-output /absolute/create-only/query-v5-source-manifest.json
```

## 后续严格顺序

1. 完成 query-v4 base + query-v5 overlay OCI composition verifier；
2. 基于最终 merge SHA build/push immutable RepoDigest 并签 build provenance；
3. 增加完整 release-v5 parent/child/terminal lifecycle；
4. 人工短时 release 后才允许未来 M2 readonly one-shot；
5. terminal/custody 后另建新 P0 acceptance contract。

本切片不修改历史 query-v3/query-v4/readiness-v4 合同。
