# Backend

Phase 1 后端只提供只读能力和 WebSocket 事件流，不开放 Web 下单。

## 启动

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

## 配置

`.env` 中配置 Windows 侧 vn.py RPC：

```bash
VNPY_RPC_REQ_ADDRESS=tcp://127.0.0.1:2014
VNPY_RPC_PUB_ADDRESS=tcp://127.0.0.1:4102
VNPY_GATEWAY_NAME=CTP
VNPY_RPC_TIMEOUT_MS=10000
QUESTDB_PG_DSN=postgresql://admin:quest@127.0.0.1:8812/qdb
QUESTDB_ILP_CONF=http::addr=127.0.0.1:9000;
DATABASE_URL=postgresql://vnpy:vnpy@127.0.0.1:5432/vnpy
```

`QUESTDB_PG_DSN` 为空时不写入时序库。配置后，后端启动会自动创建或升级 `market_ticks` 表，实时 tick 会写入 QuestDB，`GET /api/market/bars` 会优先从 QuestDB 聚合 K 线。`QUESTDB_ILP_CONF` 配置后，tick writer 使用 QuestDB 官方 ILP/HTTP client 批量 flush 写入；未配置时回退到 PGWire。

前端【数据管理】页面可查看 QuestDB 中已保存数据的合约、时间范围和行数，并支持按 `symbol`、`exchange`、`vt_symbol`、起止时间筛选 Tick 数据。CSV 导入/导出字段：

```csv
datetime,received_at,ingest_id,schema_version,vt_symbol,symbol,exchange,gateway_name,name,trading_day,action_day,last_price,last_volume,volume,turnover,open_interest,open_price,high_price,low_price,pre_close,limit_up,limit_down,bid_price_1,bid_price_2,bid_price_3,bid_price_4,bid_price_5,ask_price_1,ask_price_2,ask_price_3,ask_price_4,ask_price_5,bid_volume_1,bid_volume_2,bid_volume_3,bid_volume_4,bid_volume_5,ask_volume_1,ask_volume_2,ask_volume_3,ask_volume_4,ask_volume_5
```

`market_ticks` schema v2 使用 UTC `ts` 作为 QuestDB 时间戳，额外保存 `received_at`、`schema_version` 和事件级 `ingest_id`，并启用 `DEDUP UPSERT KEYS(ts, ingest_id)`，重试同一 tick 时保持幂等。`raw_json` 保留原始 TickData 字段，结构化列覆盖 vn.py `TickData` 的合约名、价格、成交量、成交额、持仓、涨跌停、开高低昨收和买卖 1-5 档；`extra` 保留在 `raw_json` 中。

实时 tick 持久化由后台 writer 完成，RPC callback 只做标准化和有界入队，不直接访问 QuestDB。相关配置：

```env
QUESTDB_TICK_PERSIST_ENABLED=true
QUESTDB_TICK_QUEUE_SIZE=100000
QUESTDB_TICK_BATCH_SIZE=1000
QUESTDB_TICK_FLUSH_INTERVAL_MS=500
QUESTDB_TICK_RETRY_MAX_SECONDS=60
QUESTDB_TICK_SPOOL_DIR=logs/tick-spool
QUESTDB_TICK_SPOOL_MAX_BYTES=10737418240
QUESTDB_TICK_SPOOL_SEGMENT_BYTES=67108864
QUESTDB_TICK_ERROR_LOG_INTERVAL_SECONDS=60
```

每条 tick 入队时由 Web Bridge 生成事件级 `ingest_id` 和 `received_at`，重试、spool 和补写过程中保持不变。当 QuestDB 短暂不可用或内存队列满时，合法 tick 会写入本地 JSONL spool；spool 使用 `ticks.active.jsonl` 追加和 `ticks.replaying.*.jsonl` 原子轮转，后台 writer 恢复后只删除已成功回放的 replaying 文件，避免新追加 tick 被误删。spool 超过上限时会显式计入 dropped 并写 error 日志，不静默丢弃。`GET /api/market/data/status` 可查看 received、valid、invalid、persisted、retry、failed、dropped、worker_alive、队列深度、spool 积压、最旧 pending 时间、持久化延迟、最近错误和 spool 所在磁盘容量。

生产 compose 会将 `QUESTDB_TICK_SPOOL_DIR` 覆盖为 `/app/tick-spool`，并挂载到独立 `tick-spool` volume；QuestDB 数据保存在 `questdb-data` volume。备份和恢复步骤见 `docs/deployment.md`。

可重复执行 tick persistence smoke：

```bash
QUESTDB_PG_DSN=postgresql://admin:quest@127.0.0.1:8812/qdb \
PYTHONPATH=backend .venv/bin/python scripts/tick_persistence_smoke.py --count 10
```

脚本会输出 `received`、`persisted`、`questdb_rows`、`diff`、`dropped`、`lag_seconds` 和 `spool_rows`。

## 接口

- `GET /api/status`
- `GET /api/rpc/status`
- `GET /api/gateway/status`
- `GET /api/trade/config`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/risk/status`
- `GET /api/risk/rules`
- `PATCH /api/risk/rules`
- `POST /api/risk/trade/enable`
- `POST /api/risk/trade/disable`
- `POST /api/risk/emergency-stop`
- `GET /api/strategies`
- `GET /api/strategies/{strategy_name}`
- `GET /api/strategies/{strategy_name}/setting`
- `PATCH /api/strategies/{strategy_name}/setting`
- `GET /api/strategies/{strategy_name}/variables`
- `POST /api/strategies/{strategy_name}/init`
- `POST /api/strategies/{strategy_name}/start`
- `POST /api/strategies/{strategy_name}/stop`
- `GET /api/strategies/{strategy_name}/logs`
- `GET /api/contracts`
- `GET /api/market/watchlist`
- `POST /api/market/watchlist`
- `DELETE /api/market/watchlist/{watch_key}`
- `GET /api/account`
- `GET /api/positions`
- `GET /api/orders`
- `GET /api/trades`
- `POST /api/orders`
- `POST /api/orders/{vt_orderid}/cancel`
- `POST /api/orders/cancel-all`
- `POST /api/market/subscribe`
- `POST /api/market/unsubscribe`
- `GET /api/market/tick/{vt_symbol}`
- `GET /api/market/bars`
- `GET /api/market/data/overview`
- `GET /api/market/data/status`
- `GET /api/market/data/ticks`
- `GET /api/market/data/export`
- `POST /api/market/data/import`
- `GET /ws/events`

交易 API 默认关闭。必须设置 `WEB_TRADE_ENABLED=true`，且在默认 `ORDER_CONFIRM_REQUIRED=true` 时请求体传入 `confirm: true`，才会调用真实交易 RPC。

返回格式统一为：

```json
{"ok": true, "data": {}}
```

错误格式统一为：

```json
{"ok": false, "error": {"code": "RPC_TIMEOUT", "message": "RPC 调用超时", "detail": {}}}
```
