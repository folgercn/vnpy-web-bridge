# C_FAST T1 QuestDB 只读运行器准备手册

## 1. 本切片的边界

本手册只冻结 Issue #114 formal T1 的**离线打包边界**，不授权部署或查询：

```text
activation_allowed=false
authority_granted=false
production_query_authorized=false
production_queried=false
database_mutations=0
orders_sent=0
```

本切片没有修改：

- `deployments/docker-compose.prod.yml`；
- 主 `Dockerfile`；
- `.github/workflows/*`；
- Web Bridge、QuestDB 或 SimNow 运行配置；
- 任何生产 secret、DSN、endpoint、订单或持仓路径。

`scripts/c_fast_t1/Containerfile` 的默认入口固定为 `/bin/false`；
`docs/operations/c-fast-t1-readonly-override.template.yml` 中的审计服务固定
`network_mode=none`。二者组合仍然不能查询 QuestDB。后续只有独立、人工签名、
一次性 consume 的 authority runner 才能在核对全部绑定后覆盖入口、挂载输入并加入
受限网络。本切片不复制也不预判该 one-shot release schema。

## 2. 已确认的仓库事实

当前生产 compose 固定 `questdb/questdb:9.4.3`，但没有：

- `QDB_PG_READONLY_USER_ENABLED`；
- `QDB_PG_READONLY_USER`；
- `QDB_PG_READONLY_PASSWORD_FILE`；
- QuestDB readonly password secret mount。

常驻 Web Bridge 的 `QUESTDB_PG_DSN` 是 writer/admin 路径，不能替换为审计
readonly DSN。主运行镜像只复制 `backend`、`shared`、RPC 测试脚本和前端产物，
不包含 `scripts/commodity_c_fast_l1_l5_audit.py` 或相应 evidence schemas。

因此，#121 合并只交付了代码能力；它本身不代表 readonly principal 已部署，
也不代表 T1/P0 已执行或通过。

## 3. QuestDB 配置原则

QuestDB Open Source 提供独立的 PGWire readonly user。模板只使用：

```text
QDB_PG_READONLY_USER_ENABLED=true
QDB_PG_READONLY_USER=<非 admin 的专用 principal>
QDB_PG_READONLY_PASSWORD_FILE=/run/secrets/c_fast_t1_questdb_readonly_password
```

禁止使用：

```text
QDB_PG_READONLY_PASSWORD=<明文>
QDB_PG_SECURITY_READONLY=true
QDB_READONLY=true
```

原因：

- password 必须来自文件 secret，不能进入 compose environment、进程参数、日志或
  repository；
- `QDB_PG_SECURITY_READONLY` 会把整个 PGWire 入口变成只读，不能证明保护来自专用
  principal，也可能影响 writer；
- `QDB_READONLY` 会把实例整体变为只读，同样不能作为 dedicated-user proof。

QuestDB 官方说明：

- [独立 readonly user](https://questdb.com/docs/cookbook/integrations/grafana/read-only-user/)
- [配置与 `_FILE` secrets](https://questdb.com/docs/configuration/overview/#secrets-from-files)
- [`SHOW PARAMETERS`](https://questdb.com/docs/query/sql/show/#show-parameters)

9.4.3 应在启动后通过 `SHOW PARAMETERS` 看到
`pg.readonly.password.value_source=file`。#121 的 companion proof 会在同一连接的
审计前后核对 principal、build 和 allowlisted 参数；不得通过试写来证明禁写。

## 4. 离线验证

在仓库根目录运行：

```bash
python scripts/c_fast_t1/validate_packaging.py
```

如需归档本次 preparation evidence，必须使用全新路径：

```bash
python scripts/c_fast_t1/validate_packaging.py \
  --json-output artifacts/c-fast-t1-runner-packaging-validation.json
```

validator 会 fail closed 检查：

- override 是 strict JSON-compatible YAML，无 duplicate key/NaN/symlink；
- 只增加 dedicated readonly user 和 password file secret；
- 不含 writer DSN、全局 readonly 或实例 readonly 配置；
- 审计 package 默认 `/bin/false`、无网络、只读 rootfs、无 capabilities；
- audit image 必须由调用方提供 immutable digest；
- Containerfile base image pin digest，只复制审计脚本和四个 schemas；
- Containerfile 不允许 `COPY .`、`ADD`、下载器、DSN 或 password 配置。

输出由
`docs/schemas/commodity-c-fast-t1-runner-packaging-validation-v1.schema.json`
约束。`--json-output` 使用 create-only `0600` 文件，重复路径会失败而不会覆盖旧证据。

## 5. 可复现构建准备

构建上下文必须来自待签 release 绑定的 exact Git SHA，不能直接把含本地 `.env` 的
工作目录发送给 Docker daemon。准备阶段可先在非生产环境验证：

```bash
SOURCE_SHA="$(git rev-parse HEAD)"
git archive --format=tar "$SOURCE_SHA" |
  docker build \
    --file scripts/c_fast_t1/Containerfile \
    --build-arg "SOURCE_REVISION=$SOURCE_SHA" \
    --tag "vnpy-web-bridge-c-fast-t1-audit:$SOURCE_SHA" \
    -
```

构建后必须记录内容 digest，而不是只记录可移动 tag：

```bash
docker image inspect \
  --format '{{json .Id}} {{json .RepoDigests}} {{json .Config.Labels}}' \
  "vnpy-web-bridge-c-fast-t1-audit:$SOURCE_SHA"
```

正式 release 至少绑定：

- repository/source SHA；
- audit Containerfile SHA256；
- audit script SHA256；
- 四个 schema SHA256；
- audit image ID/RepoDigest；
- QuestDB 目标实例身份、实际 image digest 和 `build()`；
- signed manifest SHA256；
- readonly DSN 文件身份；
- attempt ID、有效期、最大一次消费；
- 输出目录和 terminal seal 位置。

本 preparation validator 不校验这些运行期字段；它们属于独立 one-shot authority
契约。

## 6. 人工授权边界

### L1/L2：只做离线准备

- review/merge 本切片；
- 在非生产机器构建并检查 audit image；
- 运行离线 validator；
- 冻结 manifest、镜像/代码 hashes、执行窗口和回滚方案；
- 人工生成非默认 readonly principal/password 和 DSN 文件，但不挂载到生产。

### L3：会改变生产 QuestDB

以下动作必须使用独立人工主审的 deployment release：

- 把 readonly password secret 放到生产主机；
- 将 override 应用到生产 compose；
- restart/recreate QuestDB 使配置生效；
- 核对 writer 连续性、spool backlog、health 和回滚；
- 修改 QuestDB 网络或给 one-shot runner 授予生产网络。

现有自动 CD 只允许部署 `web-bridge`，不能用它隐式完成 QuestDB 变更。也不要把
模板直接复制到 `deployments/docker-compose.prod.yml` 后等待普通 main CD；
`docker compose up web-bridge` 没有 `--no-deps`，依赖服务的配置漂移必须作为
显式 L3 变更处理。

### 至少 L2：真实只读 T1

在 readonly deployment 已由 L3 验收后，真实 T1 仍需要另一份人工签名 one-shot
release。该 release 必须显式授权只读网络和指定查询窗口。运行器只能执行 #121
allowlist 的 `SELECT` / `SHOW PARAMETERS`，不能调用 RPC、TradeService、订单、
撤单或持仓接口。

如果 readonly deployment 和 T1 在同一变更窗口执行，整体按 L3 管理。

## 7. 正式运行前的 fail-closed 清单

没有同时满足以下各项时不得覆盖 `/bin/false`：

1. QuestDB 实际 image digest/build 与 release 相符；
2. dedicated readonly user 已启用，principal 非 admin；
3. readonly password `value_source=file`；
4. `pg.security.readonly=false`、实例 `readonly=false`；
5. writer DSN/ILP 配置未替换，写入健康且 backlog 可解释；
6. readonly DSN 是当前 runner UID 所有的 `0600` 普通文件，不是 symlink；
7. manifest、audit image、script/schema hashes 全部匹配；
8. release 未过期、attempt 未消费、网络目标唯一；
9. JSON/CSV/Markdown/readonly proof 使用全新 create-only 路径；
10. terminal seal 路径全新，失败与成功都会消费 attempt。

结束后必须归档 exit code、四产物 SHA256、P0 结论/blockers、readonly companion
proof、consume marker 和 terminal seal。任何异常均保持：

```text
p0_pass=false
execution_quality_collection_authorized=false
dispatch_allowed=false
production_allowed=false
```
