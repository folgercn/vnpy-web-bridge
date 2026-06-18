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
```

`QUESTDB_PG_DSN` 为空时不写入时序库。配置后，后端启动会自动创建 `market_ticks` 表，实时 tick 会写入 QuestDB，`GET /api/market/bars` 会优先从 QuestDB 聚合 K 线。

前端【数据管理】页面可查看 QuestDB 中已保存数据的合约、时间范围和行数，并支持按 `symbol`、`exchange`、`vt_symbol`、起止时间筛选 Tick 数据。CSV 导入/导出字段：

```csv
datetime,vt_symbol,symbol,exchange,gateway_name,last_price,volume,turnover,open_interest,bid_price_1,ask_price_1,bid_volume_1,ask_volume_1
```

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
