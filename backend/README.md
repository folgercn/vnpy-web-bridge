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
```

## 接口

- `GET /api/status`
- `GET /api/rpc/status`
- `GET /api/gateway/status`
- `GET /api/contracts`
- `GET /api/account`
- `GET /api/positions`
- `GET /api/orders`
- `GET /api/trades`
- `POST /api/market/subscribe`
- `GET /api/market/tick/{vt_symbol}`
- `GET /ws/events`

返回格式统一为：

```json
{"ok": true, "data": {}}
```

错误格式统一为：

```json
{"ok": false, "error": {"code": "RPC_TIMEOUT", "message": "RPC 调用超时", "detail": {}}}
```
