# 部署说明

## QuestDB

生产 compose 固定 QuestDB 为 `questdb/questdb:9.4.3`。生产环境不要使用 `latest`，否则 tick schema、WAL 和 dedup 行为不可复现。

QuestDB 使用命名 volume `questdb-data`，挂载到 `/var/lib/questdb`。Tick spool 使用独立命名 volume `tick-spool`，在 Web Bridge 容器内挂载到 `/app/tick-spool`。Web Bridge 会等待 QuestDB PostgreSQL Wire 端口 `8812` 通过 healthcheck 后再启动。

历史 tick 采用长期保留策略：

- 不配置 QuestDB TTL
- 不自动 drop partition
- 不因磁盘压力自动清理历史数据
- 容量压力只通过 status/monitoring 告警，后续人工处理

## 备份

在 compose 项目目录执行：

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

正式依赖备份前，应先在非生产主机完成一次恢复演练。

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
