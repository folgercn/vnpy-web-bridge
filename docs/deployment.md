# 部署说明

## Issue #267 legacy 部署冻结

PR 1-guard 已删除 legacy CD workflow。PR 1-pre C1a/C1b/C1c 分别冻结 `PLANNED_RESTART` consumed lineage、fresh `INITIAL_BASELINE` genesis lineage 与 clean legacy v1/v2 migration baseline 的非授权对账合同。C1b 只接受至少已由实际在线 runtime 接管的 pristine fresh-bootstrap chain，不接受 migration/recovery/consumed 模式。C1c 只接受同时提供 exact legacy state raw、exact legacy epoch-anchor raw 和显式 empty inventory manifest 的 clean v1/v2 migration，严格复验 `source raw → migration genesis → current head → current epoch anchor` 以及 domain-separated 两拍 Windows facts。任何 consumption 痕迹、receipt/recheck/consume pointer、epoch gap、部分历史、source raw 缺失或事实漂移都必须拒绝并保持 `RESTARTED_FROZEN`，不得降级为无历史基线。C1a/C1b/C1c 都是 pure contract，不证明 supplied custody 是 actual latest，也不接线运行状态；C2 才能在 `flock` 和唯一 Commodity owner 内读取实时 custody/inventory、捕获并 create-only 持久化证据，D 才能验证 target runtime、释放 Windows fence 和恢复 authority。在此之前全局 reconciliation/authority restore 及所有 production/live/countable 授权均为 false，`scripts/deploy.sh` 继续硬冻结，也禁止直接 stop/start/recreate `web-bridge`。人工确认不能替代该门禁。

C2a 先补齐 custody 基础：未来 legacy 迁移必须在覆盖前 create-only 封存 exact source bytes，并由从 `/` 逐组件 `openat(O_NOFOLLOW)` 锚定的 fd-pinned inventory 证明 actual state、anchor、连续 chain 与全部业务目录；每个 create-only 保留的历史 planned-restart 周期也必须逐组通过 C1a exact closure。已迁移但缺 exact source bytes 时永久 fail closed，不得从 hash 或 DTO 反投影伪造。

C2b 已在代码中接线唯一 Commodity owner，在同一 `flock → Commodity cycle → RPC` 事务中从 actual custody 自动选择 reconciliation mode，冻结 owner/account/runtime/epoch/state identity，以两拍 Windows facts和 create-only intent/marker/head 提交 non-authorizing activation。它只证明 owner capture 与 activation custody 已闭合；不证明卷外 high-water、目标镜像/config/container 身份，不释放 Windows fence，也不恢复 authority。当前 cache replay 的 served proof 仅在 RPC transport 瞬时校验、尚未进入 create-only closure，因此仍是 runtime activation blocker。C2b 代码合并不表示 Windows 扩展或 Linux runtime 已部署。

剩余顺序固定为：先证明旧 owner frozen、交易禁用/authority revoked、pending send outcome 为空和零活动委托，再由紧邻操作的显式 Windows 授权安装并验收 durable fail-closed fence foundation；再由唯一 M2 bootstrap coordinator 用 root-owned journal 执行 exact receipt-bound、双边冻结、immutable digest、单实例的目标启动；C2c 由 Phase 1-pre frozen Web Bridge owner 向卷外 witness 提交 high-water；D1 做 host-observed identity 和短 TTL lease；D2 只创建被最终订单入口拒绝的 Windows `STAGED` token；D3 才用单次 Windows CAS 永久撤销旧 token、激活 staged token并绑定 conditional grant，随后把 activation/post-proofs CAS 推进并 readback external high-water；D4 单独恢复部署门禁。每笔最终 send/cancel 必须同时持有 ACTIVE token 与 exact D3 grant receipt/hash。INITIAL/LEGACY 不恢复旧 authority，只能后续走新的正式签名授权。目标容器不得自证，D2/D3 必须 fresh re-attest 并 CAS consume/renew 同一未过期 lease，RPC timeout 只能查询同一 id。D4 前通用 `scripts/deploy.sh` 和直接 recreate 继续冻结，D4 也不得替换 D1 已绑定 identity；所有 production/live/countable 与 automatic deploy 均为 false。

下文涉及 stop/start/up 的备份和恢复命令在冻结期间只允许用于非生产恢复演练；生产备份、恢复或紧急操作需要独立授权和可验证的 safe-restart receipt。历史 CD 曾把 `APP_ENV`、`JWT_SECRET_KEY`、`MONITOR_ENABLED` 写入最终 `.env`，但该行为已不再启用。

## QuestDB

生产 compose 固定 QuestDB 为 `questdb/questdb:9.4.3`。生产环境不要使用 `latest`，否则 tick schema、WAL 和 dedup 行为不可复现。

QuestDB 使用命名 volume `questdb-data`，挂载到 `/var/lib/questdb`。Tick spool 使用独立命名 volume `tick-spool`，在 Web Bridge 容器内挂载到 `/app/tick-spool`。Web Bridge 会等待 QuestDB PostgreSQL Wire 端口 `8812` 通过 healthcheck 后再启动。

历史行情采用分层保留策略：

- `market_ticks` 只保存结构化 Tick，不再重复保存 `raw_json`
- `QUESTDB_TICK_RETENTION_DAYS` 默认是 `365`，由 QuestDB TTL 按日分区自动清理
- 设置为 `0` 可以禁用 TTL；允许范围为 0～3650 天
- 不因磁盘压力临时缩短 TTL，变更保留期限前先确认研究窗口和备份
- 1 分钟/5 分钟长期聚合表应在首批 Tick 到期前独立上线；当前 K 线仍由结构化 Tick 即时聚合

### schema v2 `raw_json` 迁移

删除 `raw_json` 属于不可逆业务数据删除，应用不会在启动时自动执行。生产迁移必须按以下顺序：

1. 先备份 QuestDB volume，并保留恢复演练记录。
2. 部署 schema v3 应用，保持现有 `raw_json` 列不动。
3. 验证最新 Tick 的 `schema_version=3`、五档字段完整、spool 无积压，且 K 线、查询、CSV 导出和 C_FAST 只读审计正常。
4. 确认不再需要原始报文后，人工执行：

```sql
ALTER TABLE market_ticks DROP COLUMN raw_json;
ALTER TABLE market_ticks SET TTL 365 DAYS;
```

5. 使用 `SHOW COLUMNS FROM market_ticks`、`SHOW PARTITIONS FROM market_ticks` 和磁盘监控确认列已移除、TTL 生效及空间回收完成。

不要先删列再部署旧版应用：schema v2 writer 会继续向 `raw_json` 写入并导致 Tick 持久化失败。当前约 42 天数据不会被 365 天 TTL 删除。

## 备份

以下流程在冻结期间仅用于非生产环境。在 compose 项目目录执行：

```bash
mkdir -p backups
docker compose -f deployments/docker-compose.prod.yml stop web-bridge
docker run --rm \
  -v vnpy_questdb-data:/data:ro \
  -v "$PWD/backups":/backup \
  busybox tar czf /backup/questdb-data-$(date +%Y%m%d-%H%M%S).tgz -C /data .
docker run --rm \
  -v vnpy_tick-spool:/data:ro \
  -v "$PWD/backups":/backup \
  busybox tar czf /backup/tick-spool-$(date +%Y%m%d-%H%M%S).tgz -C /data .
docker compose -f deployments/docker-compose.prod.yml start web-bridge
```

如果 compose project name 不是 `vnpy`，先确认真实 volume 名称：

```bash
docker volume ls | grep -E 'questdb-data|tick-spool'
```

## 恢复演练

正式依赖备份前，应先在非生产主机完成一次恢复演练。不得把以下命令作为绕过生产部署冻结的发布方式。

```bash
docker compose -f deployments/docker-compose.prod.yml stop web-bridge questdb
docker run --rm -v vnpy_questdb-data:/data busybox sh -c 'rm -rf /data/*'
docker run --rm \
  -v vnpy_questdb-data:/data \
  -v "$PWD/backups":/backup \
  busybox tar xzf /backup/questdb-data-YYYYMMDD-HHMMSS.tgz -C /data
docker compose -f deployments/docker-compose.prod.yml up -d questdb
docker compose -f deployments/docker-compose.prod.yml up -d web-bridge
```

恢复后验证：

```bash
curl -fsS http://127.0.0.1:8080/api/health/live
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/market/data/status
```
