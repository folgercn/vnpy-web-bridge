# 部署说明

## Issue #267 legacy 部署冻结

PR 1-guard 已删除 legacy CD workflow。PR 1-pre C1a/C1b 分别冻结 `PLANNED_RESTART` consumed lineage 与 fresh `INITIAL_BASELINE` genesis lineage 的非授权对账合同。C1b 只接受至少已由实际在线 runtime 接管的 pristine fresh-bootstrap chain，并通过可信 expected account hash、内容寻址的 exact Commodity baseline checkpoint raw 和两拍稳定 Windows facts 建立起始事实；它不接受 migration/recovery/consumed 模式，也不声称 pre-bootstrap facts unchanged 或真实 custody inventory 已验证。C1a/C1b 都不接线运行状态；target runtime 尚未验证、Windows fence 尚未释放、全局 reconciliation/authority restore 仍为 false。legacy migration、owner-only 持久激活和 Windows 解锁分别留 C1c/C2/D。所有 production/live/countable 授权仍为 false，`scripts/deploy.sh` 继续硬冻结，也禁止直接 stop/start/recreate `web-bridge`。人工确认不能替代该门禁。

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
