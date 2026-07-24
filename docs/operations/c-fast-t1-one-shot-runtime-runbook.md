# C_FAST T1 one-shot 运行镜像与接线合同

## 结论

本切片把已经合并的 one-shot runner 和 packaging 合同集成为一个可复验的
**代码产物**，但不部署、不签署 release，也不授权生产查询：

```text
deployment_mutation_authorized=false
production_query_authorized=false
database_mutations=0
orders_sent=0
positions_modified=0
dispatch_changed=false
```

`Containerfile.one-shot` 包含 one-shot runner、只读审计脚本及它们运行时需要的
七份 schema，并安装固定版本的 `cryptography`。签名工具和私钥能力不会进入运行
镜像。镜像默认入口只能验证并消费人工签名的 T1 release；缺少 release、部署 pin
或私有挂载时会在读取 DSN 和联网前失败。

## 与 preparation-only 包装的关系

以下已有文件保持不变：

- `scripts/c_fast_t1/Containerfile`；
- `docs/operations/c-fast-t1-readonly-override.template.yml`；
- `scripts/c_fast_t1/validate_packaging.py`。

它们继续证明 `/bin/false + network_mode=none` 的离线准备边界。新增的
`Containerfile.one-shot` 和
`c-fast-t1-one-shot-runtime.template.yml` 只用于后续经人工主审的独立运行窗口，
不能用新增文件反推已有 packaging-only 产物已经获得权限。

## 离线校验

在仓库根目录执行：

```bash
python scripts/c_fast_t1/validate_one_shot_runtime.py
```

如需归档校验结果，只能写入全新路径：

```bash
python scripts/c_fast_t1/validate_one_shot_runtime.py \
  --json-output artifacts/c-fast-t1-one-shot-runtime-validation.json
```

validator 会 fail closed 核对：

- 固定 digest 的基础镜像和四个直接 Python 依赖；
- one-shot/audit 两个脚本及七份 schema 的精确 COPY allowlist；
- runtime 镜像不含 signer、宽目录 COPY、下载器、DSN 或密码；
- 非 root、只读 rootfs、drop capabilities 和 no-new-privileges；
- 固定 pins、input、DSN、持久 custody 路径；
- 仅连接预先批准的 QuestDB-only 外部网络；
- 不挂 `.env`、Docker socket、writer DSN、RPC 或交易能力。

这只是静态合同校验，不证明镜像已构建或部署。

## 构建与外部事实

构建必须使用本集成 PR 合并后的 exact source SHA：

```bash
SOURCE_SHA="$(git rev-parse HEAD)"
git archive --format=tar "$SOURCE_SHA" |
  docker build \
    --file scripts/c_fast_t1/Containerfile.one-shot \
    --build-arg "SOURCE_REVISION=$SOURCE_SHA" \
    --tag "vnpy-web-bridge-c-fast-t1-one-shot:$SOURCE_SHA" \
    -
```

模板用同一个 `C_FAST_T1_RUNTIME_IMAGE_DIGEST` 同时构造
`repository@sha256:...` 镜像引用并传入 signed expectation，禁止实际镜像与 CLI
断言来自两个独立值。正式运行还必须由隔离执行器外部核对：

- OCI revision 等于 exact source SHA；
- 实际 RepoDigest 等于 release 的 `runtime_image_digest`；
- runner/audit/schema hashes 等于 release；
- 镜像文件 allowlist 没有额外 signer、secret 或业务代码。

one-shot CLI 的 source SHA 和 image digest 参数只是与 signed expectation 比较，
不能代替以上外部镜像事实。

## 挂载所有权

容器 UID/GID 固定为 `65532:65532`。正式运行前必须在宿主机验证：

| 路径 | 所有权/权限 | 挂载 |
|---|---|---|
| `/run/c-fast-t1-pins` | root-owned，group/world 不可写 | 只读 |
| `trusted-keyring.json` | 65532-owned，0600 | 精确单文件只读 |
| signed release / manifest | 不可变、非 symlink | 各自精确单文件只读 |
| readonly DSN | 65532-owned，0600，非 symlink | 单文件只读 |
| `/var/lib/c-fast-t1-custody` | 65532-owned，0700，父目录 root-owned 且不可写 | 宿主与容器同路径 1:1 持久读写 |
| `custody-identity.json` | 65532-owned，0600 | custody 内 |

Compose 本地 file secret 可能保留 root ownership，不能假设 `uid/gid/mode` 一定被
实现。模板只 bind runner 实际需要的三个 input 文件和一个 DSN 文件，不挂载整个
release 目录，避免把签名私钥或其他审批材料带入运行容器。人工 L3 release 必须在
启动前核对真实 inode、UID 和 mode，不能把权限不符解释为 runner 故障后临时放宽。
custody 禁止把任意宿主目录映射为固定容器别名；宿主 source、容器 target、
`--custody-dir` 和 deployment pin 必须都等于
`/var/lib/c-fast-t1-custody`，否则签名路径 hash 无法保护跨目录重放。

## 网络和部署边界

模板只冻结一个外部网络引用，静态 validator **不能证明网络隔离**。该网络必须由
另一份人工 L3 deployment release 建立并核对 network ID、driver、internal flag、
成员 allowlist 和 QuestDB container identity，才可声称只允许 one-shot runner
到目标 QuestDB PGWire。禁止：

- default、host 或 Web Bridge 业务网络；
- Docker socket；
- writer/admin DSN；
- RPC、TradeService、订单、撤单或持仓接口；
- 自动 CD 修改 QuestDB 配置或重启服务。

dedicated readonly principal、file password、QuestDB restart/recreate、writer
continuity、health、backlog 和 rollback 仍属于独立 L3 变更，不在本 PR 内。

## 中断和一次性消费

正常 child 完成、超时或 Python 可捕获的中断会尽力写 terminal。容器级
`SIGTERM`、`SIGKILL`、OOM、宿主机宕机或磁盘故障可能只留下 consume marker。
这不是可重试状态：

```text
CONSUMED_WITHOUT_TERMINAL_REQUIRES_NEW_RELEASE
```

不得删除 consume、复制 custody 或复用 attempt。必须保留现场、归档已有字节并
签署全新的 release。即使得到 `SUCCEEDED_P0_PASS`，本地 terminal 仍固定
`p0_acceptance_authorized=false`；必须另有外部 WORM/append-only custody 或
独立签名 acceptance，才可进入正式 P0 acceptance。

## 当前下一步

本切片合并后仍保持：

```text
t1_executed=false
p0_pass=false
execution_quality_collection_authorized=false
```

严格顺序是：构建并归档 exact image → 人工 L3 readonly deployment → 冻结十品种
manifest 和短 TTL release → 人工签署 → one-shot T1 → 外部 P0 acceptance。
