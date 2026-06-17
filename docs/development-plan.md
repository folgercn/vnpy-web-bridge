# VnPy Web Bridge 开发草案

本文档是 `vnpy-web-bridge` 的完整开发草案，用于指导后续后端、前端、风控、策略管理和部署工作。

项目当前目标不是重写 vn.py，也不是重新实现交易框架，而是在已有 vn.py / VeighNa 能力之上，建设一层可控、可审计、可扩展的 Web 交易桥接服务。

---

## 1. 项目定位

`vnpy-web-bridge` 是基于 vn.py 的远程 Web 交易桥接层。

核心职责：

- 对接 Windows 侧运行的 vn.py / CTP / RPC 服务。
- 向 Web 前端提供统一 REST API。
- 向 Web 前端提供统一 WebSocket 事件推送。
- 封装 vn.py 原生对象，避免前端直接理解 vn.py 内部结构。
- 提供权限、风控、日志审计、交易开关等 Web 交易安全能力。
- 后续扩展 CTA 策略管理、策略参数配置、策略日志、运行状态监控。

非目标：

- 不重新实现 CTP 网关。
- 不替代 vn.py 的交易引擎、事件引擎和策略引擎。
- 不在第一阶段实现完整图表交易终端。
- 不在第一阶段开放公网交易。
- 不将账号、密码、投资者代码、Broker 配置等敏感信息提交到 GitHub。

---

## 2. 当前已验证基础

当前仓库中已有两份 RPC 测试脚本，作为后续服务化封装的基础参考。

### 2.1 `test_rpc_readonly.py`

用途：验证只读 RPC 能力。

已覆盖：

- RPC REQ 地址连接。
- `get_all_contracts` 查询合约。
- `get_all_accounts` 查询资金。
- `get_all_positions` 查询持仓。
- RPC 超时处理。
- RPC 错误返回处理。

后续演进方向：

- 将硬编码地址迁移到 `.env`。
- 将 `rpc_call` 封装到 `VnpyRpcService`。
- 将 vn.py 原始对象转换为可 JSON 序列化的 DTO。
- 增加统一错误码和日志。

### 2.2 `test_rpc_trade_flow.py`

用途：验证行情订阅、下单、查单、撤单的完整交易链路。

已覆盖：

- `vnpy.rpc.RpcClient` 连接 REQ/PUB 地址。
- 订阅全部 topic。
- 订阅指定合约行情。
- 等待 tick。
- 发送限价开仓委托。
- 查询委托状态。
- 根据委托状态创建撤单请求。
- 监听 order / trade 事件。
- 停止并回收 RPC Client。

后续演进方向：

- 迁移为自动化 smoke test。
- 交易参数配置化，避免硬编码合约、网关、地址。
- 加入 Web 交易开关。
- 加入风控前置检查。
- 加入审计日志。
- API 层不要直接暴露裸 `send_order`。

---

## 3. 总体架构

```text
Browser / Web Frontend
  Vue / React / Next.js
        |
        | REST API
        | WebSocket
        v
Backend API Server
  FastAPI
  Pydantic DTO
  Auth / Risk / Audit
        |
        | vn.py RPC Client
        v
Windows Trading Server
  vn.py / VeighNa
  EventEngine
  MainEngine
  RpcService
  CTP Gateway
        |
        v
CTP / SimNow / 实盘柜台
```

---

## 4. 部署分工

### 4.1 Windows 交易服务器

职责：

- 运行 vn.py / VeighNa。
- 连接 CTP / SimNow / 实盘柜台。
- 启动 RPC 服务。
- 保持交易链路稳定。
- 保留本地 vn.py 日志。

不建议在 Windows 侧做复杂 Web 开发。

### 4.2 Mac 开发机

职责：

- 开发后端 FastAPI。
- 开发前端页面。
- 通过 RPC 连接 Windows 交易服务。
- 本地跑单元测试、接口测试、前端开发服务。
- GitHub 提交代码。

### 4.3 生产部署候选

可选模式：

1. Web 后端和 vn.py 同机部署在 Windows。
2. Web 后端部署在局域网 Linux/Mac mini，远程连接 Windows vn.py RPC。
3. Web 前端静态部署，后端通过 VPN/内网访问。

第一版建议：

```text
Windows 跑 vn.py + RPC
Mac 跑 backend + frontend 开发服务
浏览器访问 Mac backend/frontend
```

---

## 5. 目录规划

```text
vnpy-web-bridge/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   ├── routes_status.py
│   │   │   ├── routes_market.py
│   │   │   ├── routes_account.py
│   │   │   ├── routes_trade.py
│   │   │   ├── routes_risk.py
│   │   │   └── routes_strategy.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   ├── logging.py
│   │   │   ├── security.py
│   │   │   └── errors.py
│   │   ├── services/
│   │   │   ├── vnpy_rpc_service.py
│   │   │   ├── market_service.py
│   │   │   ├── account_service.py
│   │   │   ├── trade_service.py
│   │   │   ├── risk_service.py
│   │   │   ├── strategy_service.py
│   │   │   └── audit_service.py
│   │   ├── schemas/
│   │   │   ├── common.py
│   │   │   ├── market.py
│   │   │   ├── account.py
│   │   │   ├── trade.py
│   │   │   ├── risk.py
│   │   │   └── strategy.py
│   │   ├── stores/
│   │   │   ├── memory_store.py
│   │   │   └── snapshot_store.py
│   │   └── ws/
│   │       ├── manager.py
│   │       ├── events.py
│   │       └── serializers.py
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── smoke/
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
│
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── stores/
│   │   ├── router/
│   │   └── utils/
│   ├── package.json
│   └── README.md
│
├── docs/
│   ├── development-plan.md
│   ├── architecture.md
│   ├── api.md
│   ├── websocket.md
│   ├── risk.md
│   └── deployment.md
│
├── test_rpc_readonly.py
├── test_rpc_trade_flow.py
├── README.md
└── LICENSE
```

---

## 6. 后端技术栈

建议第一版后端使用：

- Python 3.10+
- FastAPI
- Uvicorn
- Pydantic v2
- python-dotenv / pydantic-settings
- vn.py / VeighNa RPC Client
- pytest
- ruff

第一版尽量不引入数据库。状态数据先使用内存快照，避免过早复杂化。

后续需要持久化时再引入：

- SQLite：本地开发和轻量部署。
- PostgreSQL：生产环境、多用户、审计日志和历史数据。

---

## 7. 前端技术栈

推荐候选：

### 7.1 快速开发方案

```text
Vue 3 + Vite + TypeScript + Naive UI / Element Plus
```

优点：

- 国内后台系统开发速度快。
- 表格、表单、弹窗、菜单生态成熟。
- 适合交易终端 MVP。

### 7.2 长期产品化方案

```text
React + Vite / Next.js + TypeScript + Ant Design
```

优点：

- 长期工程化能力强。
- 组件和状态管理生态成熟。
- 适合后续复杂图表和多页面应用。

第一版建议先用 Vue 3 + Vite，降低启动成本。

---

## 8. 配置规范

所有环境差异和敏感配置放入 `.env`，不提交真实配置。

示例：

```env
APP_ENV=development
APP_HOST=0.0.0.0
APP_PORT=8000

VNPY_RPC_REQ_ADDRESS=tcp://127.0.0.1:2014
VNPY_RPC_PUB_ADDRESS=tcp://127.0.0.1:4102
VNPY_GATEWAY_NAME=CTP

JWT_SECRET_KEY=change-me
ACCESS_TOKEN_EXPIRE_MINUTES=720

WEB_TRADE_ENABLED=false
RISK_ENABLED=true
AUDIT_ENABLED=true
```

要求：

- `.env` 必须加入 `.gitignore`。
- 仓库只保留 `.env.example`。
- 测试脚本中的 IP、端口、合约代码应配置化。
- 实盘信息不得写入代码、README、Issue、日志截图。

---

## 9. 后端核心模块设计

### 9.1 `VnpyRpcService`

职责：

- 连接 vn.py RPC REQ/PUB。
- 管理 RpcClient 生命周期。
- 提供统一调用入口。
- 提供连接状态。
- 提供超时、异常、重连逻辑。
- 将 vn.py 事件转发到内部事件队列。

关键方法草案：

```python
class VnpyRpcService:
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def is_connected(self) -> bool: ...
    def call(self, name: str, *args, timeout: int | None = None, **kwargs): ...
    def subscribe_market(self, symbol: str, exchange: str) -> None: ...
    def send_order(self, request: OrderRequestDTO) -> str: ...
    def cancel_order(self, request: CancelRequestDTO) -> None: ...
```

### 9.2 `MarketService`

职责：

- 合约查询。
- 行情订阅。
- 最新 tick 快照缓存。
- tick 事件推送。

### 9.3 `AccountService`

职责：

- 账户资金查询。
- 持仓查询。
- 委托查询。
- 成交查询。
- 数据快照转换。

### 9.4 `TradeService`

职责：

- 接收 Web 下单请求。
- 调用 RiskService 做前置风控。
- 转换为 vn.py OrderRequest。
- 调用 RPC 下单。
- 返回 `vt_orderid`。
- 处理撤单、全撤。
- 写操作日志。

### 9.5 `RiskService`

职责：

- Web 交易总开关。
- 单笔手数检查。
- 单合约持仓检查。
- 价格保护检查。
- 交易时间检查。
- 每日亏损限制。
- 风控拒单原因输出。

### 9.6 `AuditService`

职责：

- 记录登录行为。
- 记录下单行为。
- 记录撤单行为。
- 记录策略启停行为。
- 记录风控拒单。
- 后续支持持久化到 SQLite/PostgreSQL。

### 9.7 `WebSocketManager`

职责：

- 管理前端连接。
- 统一事件推送。
- 心跳检测。
- 断连清理。
- 支持订阅 topic 或直接广播。

---

## 10. REST API 草案

### 10.1 状态

```http
GET /api/status
GET /api/rpc/status
GET /api/gateway/status
```

返回示例：

```json
{
  "ok": true,
  "data": {
    "app": "running",
    "rpc_connected": true,
    "gateway_name": "CTP",
    "web_trade_enabled": false
  }
}
```

### 10.2 行情

```http
GET  /api/contracts
POST /api/market/subscribe
GET  /api/market/tick/{vt_symbol}
```

订阅请求：

```json
{
  "symbol": "rb2610",
  "exchange": "SHFE"
}
```

### 10.3 账户

```http
GET /api/account
GET /api/positions
GET /api/orders
GET /api/trades
```

### 10.4 交易

```http
POST /api/orders
POST /api/orders/{vt_orderid}/cancel
POST /api/orders/cancel-all
```

下单请求：

```json
{
  "symbol": "rb2610",
  "exchange": "SHFE",
  "direction": "long",
  "offset": "open",
  "type": "limit",
  "price": 3000,
  "volume": 1,
  "gateway_name": "CTP",
  "confirm": true
}
```

### 10.5 风控

```http
GET  /api/risk/status
GET  /api/risk/rules
PATCH /api/risk/rules
POST /api/risk/emergency-stop
```

### 10.6 策略

```http
GET  /api/strategies
GET  /api/strategies/{strategy_name}
POST /api/strategies/{strategy_name}/init
POST /api/strategies/{strategy_name}/start
POST /api/strategies/{strategy_name}/stop
PATCH /api/strategies/{strategy_name}/setting
```

---

## 11. WebSocket 事件设计

统一入口：

```http
GET /ws/events
```

统一消息格式：

```json
{
  "type": "order",
  "ts": "2026-06-17T10:00:00.000+08:00",
  "data": {}
}
```

计划事件类型：

| 类型 | 说明 |
|---|---|
| `tick` | 行情 tick |
| `order` | 委托更新 |
| `trade` | 成交更新 |
| `position` | 持仓更新 |
| `account` | 资金更新 |
| `log` | 系统日志 |
| `gateway_status` | 网关状态 |
| `strategy_status` | 策略状态 |
| `risk_alert` | 风控提醒 |

要求：

- 后端负责将 vn.py 原始事件转换为 JSON。
- 前端只处理统一事件 envelope。
- 第一版可以全量广播，后续再做按用户、按合约、按页面订阅。
- 断线重连后，前端应主动重新拉取账户、持仓、委托、成交快照。

---

## 12. 数据模型规范

### 12.1 枚举转换

后端统一把 vn.py 枚举转换为小写字符串。

示例：

| vn.py | API |
|---|---|
| `Direction.LONG` | `long` |
| `Direction.SHORT` | `short` |
| `Offset.OPEN` | `open` |
| `Offset.CLOSE` | `close` |
| `OrderType.LIMIT` | `limit` |
| `Status.NOTTRADED` | `not_traded` |

### 12.2 合约 DTO

```json
{
  "symbol": "rb2610",
  "exchange": "SHFE",
  "vt_symbol": "rb2610.SHFE",
  "name": "螺纹钢2610",
  "product": "futures",
  "size": 10,
  "pricetick": 1,
  "gateway_name": "CTP"
}
```

### 12.3 委托 DTO

```json
{
  "vt_orderid": "CTP.123456",
  "symbol": "rb2610",
  "exchange": "SHFE",
  "direction": "long",
  "offset": "open",
  "type": "limit",
  "price": 3000,
  "volume": 1,
  "traded": 0,
  "status": "not_traded",
  "datetime": "2026-06-17T10:00:00+08:00",
  "gateway_name": "CTP"
}
```

---

## 13. 安全和权限设计

第一版至少支持：

- 登录认证。
- JWT 或 Session。
- 只读权限。
- 交易权限。
- 管理权限。
- Web 交易总开关。
- 操作日志。

角色规划：

| 角色 | 权限 |
|---|---|
| `viewer` | 查看行情、资金、持仓、委托、成交 |
| `trader` | viewer 权限 + 下单、撤单、全撤 |
| `admin` | trader 权限 + 风控配置、策略启停、系统配置 |

默认策略：

- 默认关闭交易能力。
- 未登录不可访问任何交易 API。
- 未开启 `WEB_TRADE_ENABLED` 时，所有下单/撤单 API 返回拒绝。
- 实盘模式下必须开启风控和审计。

---

## 14. 风控设计

第一版规则：

```yaml
web_trade_enabled: false
max_order_volume: 1
max_symbol_position: 5
max_daily_loss: 1000
price_protection_percent: 3
allowed_exchanges:
  - SHFE
  - DCE
  - CZCE
  - CFFEX
  - INE
blocked_symbols: []
allowed_symbols: []
```

下单前检查顺序：

1. 是否登录。
2. 是否具备交易权限。
3. Web 交易总开关是否打开。
4. RPC 是否连接。
5. 网关是否可用。
6. 合约是否合法。
7. 交易所是否允许。
8. 合约是否在黑名单。
9. 如果启用白名单，合约是否在白名单。
10. 单笔手数是否超限。
11. 单合约持仓是否超限。
12. 价格是否超过保护范围。
13. 是否超过每日亏损限制。
14. 生成审计日志。
15. 发送委托。

风控拒绝返回示例：

```json
{
  "ok": false,
  "error": {
    "code": "RISK_MAX_ORDER_VOLUME",
    "message": "单笔委托手数超过限制",
    "detail": {
      "max_order_volume": 1,
      "request_volume": 5
    }
  }
}
```

---

## 15. 测试策略

### 15.1 单元测试

覆盖：

- DTO 序列化。
- 枚举转换。
- 风控规则。
- 权限判断。
- API 参数校验。
- WebSocket 消息 envelope。

### 15.2 集成测试

覆盖：

- RPC 连接状态。
- 合约查询。
- 资金查询。
- 持仓查询。
- 行情订阅。
- 下单流程。
- 撤单流程。

### 15.3 Smoke Test

基于当前两份脚本改造：

```text
test_rpc_readonly.py -> tests/smoke/test_rpc_readonly.py
test_rpc_trade_flow.py -> tests/smoke/test_rpc_trade_flow.py
```

要求：

- 参数从环境变量读取。
- 默认不执行真实下单。
- 明确 `--allow-trade` 后才允许交易测试。
- 下单测试使用极端价格，确保尽量不成交。
- 测试结束必须尝试撤单。

---

## 16. 前端页面设计

第一版页面：

| 页面 | 功能 |
|---|---|
| 登录页 | 用户登录 |
| Dashboard | RPC 状态、网关状态、资金摘要、持仓摘要 |
| 行情页 | 合约搜索、行情订阅、最新 tick |
| 下单面板 | 合约、方向、开平、价格、手数、确认下单 |
| 持仓页 | 持仓列表、按合约筛选 |
| 委托页 | 当前委托、历史委托、撤单、全撤 |
| 成交页 | 成交记录 |
| 资金页 | 账户资金、可用资金、保证金、风险度 |
| 策略页 | 策略列表、初始化、启动、停止 |
| 日志页 | 系统日志、交易日志、风控日志 |

前端状态管理：

- REST 拉取初始快照。
- WebSocket 接收增量事件。
- WebSocket 断线后重连。
- 重连成功后重新拉取快照。

---

## 17. 开发顺序

推荐执行顺序：

1. 创建基础目录结构。
2. 创建后端 FastAPI 应用。
3. 创建 `.env.example` 和配置读取。
4. 封装 `VnpyRpcService`。
5. 把 `test_rpc_readonly.py` 能力迁入只读 API。
6. 把 `test_rpc_trade_flow.py` 能力迁入交易服务。
7. 做 WebSocket 事件推送。
8. 做基础风控。
9. 做最小前端页面。
10. 再扩展 CTA 策略管理。

---

## 18. 分支和提交规范

建议分支：

```text
main
feature/backend-bootstrap
feature/rpc-service
feature/readonly-api
feature/websocket-events
feature/trade-api
feature/risk-service
feature/frontend-terminal
feature/strategy-management
```

提交信息建议：

```text
feat: 初始化 FastAPI 后端
feat: 封装 vn.py RPC 服务
feat: 增加只读查询 API
feat: 增加 WebSocket 事件推送
feat: 增加下单撤单 API
feat: 增加基础风控
fix: 修复 RPC 超时处理
refactor: 调整 DTO 序列化
```

---

## 19. Definition of Done

一个功能完成至少满足：

- API 有明确请求/响应模型。
- 业务逻辑不直接写在 route 中。
- vn.py 原始对象不会直接返回给前端。
- 错误返回格式统一。
- 关键操作有日志。
- 下单、撤单类操作经过权限和风控。
- 有最小测试覆盖。
- README 或 docs 有说明。

---

## 20. 近期最小可用目标

MVP 完成标准：

- 后端能启动。
- 后端能连接 Windows RPC。
- 浏览器能看到 RPC 状态。
- 浏览器能查询合约、资金、持仓、委托、成交。
- 浏览器能订阅行情并收到 tick 推送。
- 浏览器能在开启交易开关后下单。
- 浏览器能撤单。
- 所有交易动作都有审计日志。
- 默认配置下交易能力关闭。

完成 MVP 后，再进入策略管理和前端体验优化。