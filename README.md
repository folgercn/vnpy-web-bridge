# VnPy Web Bridge

基于 **vn.py / VeighNa** 的远程 Web 交易桥接服务。

本项目把本地或远程运行的 vn.py 交易服务，通过统一的 Web API 和 WebSocket 推送能力暴露给浏览器前端，用于行情订阅、账户查询、持仓查询、委托成交、下单撤单、策略管理、风控和行情数据管理。

当前已形成一套可运行的 **FastAPI 后端 + Vue 3 前端 + vn.py RPC 桥接层**。交易能力默认关闭，必须显式开启 Web 交易开关并通过权限、风控和二次确认后才会触发真实交易 RPC。

---

## 当前状态

已验证的底层链路：

```text
Mac / Web Backend
  -> vn.py RPC
  -> Windows vn.py 服务
  -> CTP
  -> SimNow
```

已验证能力：

```text
查合约 OK
查资金 OK
查持仓 OK
订阅行情 OK
下单 OK
撤单 OK
```

当前产品化能力：

- Web 登录、JWT 鉴权、角色权限。
- RPC / Gateway / WebSocket / Web 交易开关状态展示。
- 合约查询、行情订阅、tick 快照、K 线查询、WebSocket tick 推送。
- 行情关注列表、合约搜索、品种别名搜索、交易时段状态和下次开市倒计时。
- 账户、持仓、委托、成交查询。
- 限价下单、撤单、全撤、下单二次确认。
- Web 交易开关、紧急停止、基础风控规则、审计日志。
- 冻结 `STATIC_CORE_EQUAL` 商品组合的 SimNow 专用签名目标、自动两阶段派单、逐阶段持仓对账和真实成交滑点快照。
- CTA 策略列表、参数、变量、初始化、启动、停止、策略日志。
- QuestDB 行情数据概览、查询、CSV 导入导出。
- Vue 3 + Vite + Naive UI 前端交易终端，支持桌面和移动端宽度。
- GitHub Actions CI/CD，部署路径面向 Macmini 自托管 runner。

---

## 目标架构

```text
Web Frontend
  Vue 3 / Vite / Naive UI
        |
        | REST API + WebSocket
        v
Web Backend
  FastAPI / Python
        |
        | vn.py RPC
        v
Windows Trading Server
  vn.py / VeighNa
        |
        | CTP Gateway
        v
CTP / SimNow / 实盘柜台
```

### 核心原则

- 前端不直接理解 vn.py 内部对象。
- 前端不直接连接 CTP 或 vn.py RPC。
- 后端统一封装交易、查询、推送、权限、风控和日志。
- 下单、撤单等交易能力必须经过后端权限、开关、二次确认和风控检查。
- Web 交易能力默认关闭，生产环境必须配置强 JWT secret 和管理员账号。
- 敏感配置只放本地环境变量或部署环境，不提交仓库。

---

## 功能清单

### Phase 1：只读能力

- [x] 服务状态查询
- [x] RPC 连接状态
- [x] RPC probe
- [x] Gateway 状态
- [x] 合约查询
- [x] 行情订阅
- [x] 行情取消订阅
- [x] Tick 快照查询
- [x] Tick WebSocket 推送
- [x] K 线查询
- [x] 账户资金查询
- [x] 持仓查询
- [x] 委托查询
- [x] 成交查询
- [x] 日志推送和日志页面

### Phase 2：基础交易

- [x] 限价单下单
- [x] 撤单
- [x] 全撤
- [x] 买入 / 卖出 / 开仓 / 平仓参数封装
- [x] 下单前二次确认
- [x] Web 交易开关
- [x] 操作日志记录
- [x] 交易 API 默认关闭
- [x] 真实交易 smoke 脚本

### Phase 3：风控

- [x] 单笔最大手数限制
- [x] 单合约最大持仓限制
- [x] 每日最大亏损限制配置
- [x] 交易时间检查开关和配置项
- [x] 价格保护检查
- [x] 允许 / 禁止交易所限制
- [x] 允许 / 禁止合约限制
- [x] 只读用户 / 交易用户 / 管理员权限分离
- [x] 一键关闭交易
- [x] 紧急停止并可选择全撤
- [x] 风控状态 WebSocket 推送
- [ ] 交易日历和法定节假日表

### Phase 4：策略管理

- [x] CTA 策略列表
- [x] 策略详情查看
- [x] 策略参数查看
- [x] 策略参数修改
- [x] 策略变量查看
- [x] 初始化策略
- [x] 启动策略
- [x] 停止策略
- [x] 策略日志查询
- [x] 策略操作审计
- [ ] 策略状态 WebSocket 实时推送

### Phase 5：前端交易终端

- [x] 登录页
- [x] 路由守卫和登录态恢复
- [x] 桌面侧边栏布局
- [x] 移动端抽屉菜单和表格横向滚动
- [x] 顶部状态栏：RPC / WS / Trade / 当前用户
- [x] 亮色 / 暗色 / 跟随系统主题
- [x] Dashboard
- [x] Dashboard 交易时段状态
- [x] 行情页
- [x] 合约搜索和品种别名搜索
- [x] 行情关注列表管理
- [x] 当前合约交易时段和下次开市倒计时
- [x] K 线图
- [x] 最新 tick 表格
- [x] 下单面板
- [x] 持仓页
- [x] 委托页
- [x] 成交页
- [x] 资金页
- [x] 策略管理页
- [x] 数据管理页
- [x] 系统日志页
- [x] 前端构建分包，消除 Vite chunk warning

### Phase 6：行情数据管理

- [x] QuestDB 连接配置
- [x] 行情数据概览
- [x] tick 数据查询
- [x] tick CSV 导出
- [x] tick CSV 导入
- [x] 数据管理前端页面
- [ ] 自动落库所有实时 tick 的完整生产验证
- [x] 历史 Tick 长期保留（不自动清理）

### Phase 7：交付和运维

- [x] Dockerfile
- [x] 生产 docker compose 配置
- [x] 部署脚本
- [x] GitHub Actions CI
- [x] GitHub Actions CD
- [x] Macmini 自托管 runner 部署路径
- [x] 前端 build 验证
- [x] 后端单元测试
- [x] RPC 只读 smoke 脚本
- [x] RPC 真实交易 smoke 脚本
- [ ] 完整生产监控和告警

---

## 目录结构

```text
vnpy-web-bridge/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   ├── routes_auth.py
│   │   │   ├── routes_status.py
│   │   │   ├── routes_market.py
│   │   │   ├── routes_trade.py
│   │   │   ├── routes_account.py
│   │   │   ├── routes_risk.py
│   │   │   ├── routes_strategy.py
│   │   │   └── routes_ws.py
│   │   ├── core/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── stores/
│   │   └── ws/
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── router/
│   │   ├── stores/
│   │   ├── test/
│   │   ├── utils/
│   │   └── ws/
│   ├── package.json
│   └── vite.config.ts
├── deployments/
│   └── docker-compose.prod.yml
├── .github/workflows/
│   ├── ci.yml
│   └── cd.yml
├── test_rpc_readonly.py
├── test_rpc_trade_flow.py
├── Dockerfile
└── README.md
```

---

## API

所有交易、行情、账户、策略和风控 API 除 `/api/status` 外均需要 Bearer token。

### 认证

```http
POST /api/auth/login
POST /api/auth/logout
GET  /api/auth/me
```

### 状态

```http
GET /api/status
GET /api/rpc/status
GET /api/rpc/probe
GET /api/gateway/status
GET /api/trade/config
```

### 行情

```http
GET    /api/contracts
GET    /api/market/watchlist
POST   /api/market/watchlist
DELETE /api/market/watchlist/{watch_key}
POST   /api/market/subscribe
POST   /api/market/unsubscribe
GET    /api/market/tick/{vt_symbol}
GET    /api/market/bars
```

### 行情数据

```http
GET  /api/market/data/overview
GET  /api/market/data/status
GET  /api/market/data/ticks
GET  /api/market/data/export
POST /api/market/data/import
```

### 账户

```http
GET /api/account
GET /api/positions
GET /api/orders
GET /api/trades
```

### 交易

```http
POST /api/orders
POST /api/orders/{vt_orderid}/cancel
POST /api/orders/cancel-all
```

### 风控

```http
GET   /api/risk/status
GET   /api/risk/rules
PATCH /api/risk/rules
POST  /api/risk/trade/enable
POST  /api/risk/trade/disable
POST  /api/risk/emergency-stop
```

### 策略

```http
GET   /api/strategies
GET   /api/strategies/{strategy_name}
GET   /api/strategies/{strategy_name}/setting
PATCH /api/strategies/{strategy_name}/setting
GET   /api/strategies/{strategy_name}/variables
POST  /api/strategies/{strategy_name}/init
POST  /api/strategies/{strategy_name}/start
POST  /api/strategies/{strategy_name}/stop
GET   /api/strategies/{strategy_name}/logs
```

### 商品组合 SimNow

```http
GET  /api/commodity-simnow/status
GET  /api/commodity-simnow/plan
GET  /api/commodity-simnow/events
POST /api/commodity-simnow/enable
POST /api/commodity-simnow/disable
POST /api/commodity-simnow/preview
POST /api/commodity-simnow/execute
POST /api/commodity-simnow/reconcile
POST /api/commodity-simnow/auto-advance
```

该控制器只接受研究侧 Ed25519 签名的冻结月度整数目标。白名单 SimNow 账户显式授权后，后台 worker 自动执行平仓、对账、开仓、对账，并记录真实成交和滑点；生产执行仍被硬关闭。配置、签名与验收步骤见 [STATIC_CORE_EQUAL 商品组合 SimNow 接入](docs/commodity-static-core-simnow.md)。

### WebSocket

```http
GET /ws/events
```

统一事件格式：

```json
{
  "type": "tick",
  "data": {}
}
```

已支持或预留的事件类型：

```text
tick
order
trade
position
account
log
strategy_status
gateway_status
risk_alert
```

---

## 本地开发

### 后端

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

默认 RPC 地址：

```text
VNPY_RPC_REQ_ADDRESS=tcp://127.0.0.1:2014
VNPY_RPC_PUB_ADDRESS=tcp://127.0.0.1:4102
VNPY_GATEWAY_NAME=CTP
```

### 前端

```bash
cd frontend
npm install
npm run dev
```

前端技术栈：

- Vue 3
- Vite
- TypeScript
- Naive UI
- Pinia
- Vue Router
- TradingView Lightweight Charts

### 测试

后端：

```bash
cd backend
pytest
```

前端：

```bash
cd frontend
npm test -- --run
npm run build
```

RPC 只读 smoke：

```bash
.venv/bin/python test_rpc_readonly.py
```

真实交易链路 smoke：

```bash
VNPY_ALLOW_TRADE_TEST=true .venv/bin/python test_rpc_trade_flow.py --allow-trade
```

真实交易 smoke 会订阅行情、等待 tick、发送一笔远离成交价的限价单、查询委托并撤单。必须显式设置 `VNPY_ALLOW_TRADE_TEST=true` 或传 `--allow-trade` 才会执行。

---

## 配置

后端通过 `.env` 或环境变量配置：

```env
APP_ENV=development
LOG_LEVEL=INFO

VNPY_RPC_REQ_ADDRESS=tcp://127.0.0.1:2014
VNPY_RPC_PUB_ADDRESS=tcp://127.0.0.1:4102
VNPY_GATEWAY_NAME=CTP
VNPY_RPC_TIMEOUT_MS=10000

WEB_TRADE_ENABLED=false
DEFAULT_GATEWAY_NAME=CTP
ORDER_CONFIRM_REQUIRED=true
TRADE_REFERENCE_PREFIX=web_bridge

JWT_SECRET_KEY=change-me-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=480
AUTH_USERS_JSON=[]

DATABASE_URL=
QUESTDB_PG_DSN=

RISK_MAX_ORDER_VOLUME=1
RISK_MAX_SYMBOL_POSITION=5
RISK_MAX_DAILY_LOSS=1000
RISK_PRICE_PROTECTION_PERCENT=3
RISK_ALLOWED_EXCHANGES=SHFE,DCE,CZCE,CFFEX,INE,GFEX
RISK_ALLOWED_SYMBOLS=
RISK_BLOCKED_SYMBOLS=
RISK_TRADING_TIME_CHECK_ENABLED=false

COMMODITY_SIMNOW_ENABLED=false
COMMODITY_SIMNOW_GATEWAY_NAME=CTP
COMMODITY_SIMNOW_ACCOUNT_HASHES=
COMMODITY_SIMNOW_TRUSTED_PUBLIC_KEYS_JSON={}
COMMODITY_SIMNOW_STATE_PATH=logs/commodity-simnow/state.json
COMMODITY_SIMNOW_AUTO_DISPATCH_ENABLED=true
COMMODITY_SIMNOW_AUTO_DISPATCH_INTERVAL_SECONDS=1
COMMODITY_SIMNOW_AUTO_DISPATCH_RECONCILE_GRACE_SECONDS=30
```

生产环境要求：

- `APP_ENV=production`
- `JWT_SECRET_KEY` 必须更换，长度至少 32 字符。
- `AUTH_USERS_JSON` 必须配置至少一个 `admin` 用户。
- 敏感配置不得提交到 GitHub。

---

## 安全要求

Web 端具备交易能力后，必须满足：

- [x] 登录认证
- [x] JWT token
- [x] 角色权限分级
- [x] 交易 API 角色限制
- [x] 下单二次确认
- [x] Web 交易总开关
- [x] 后端风控校验
- [x] 操作日志审计
- [x] 一键关闭交易
- [x] 紧急停止
- [x] 生产环境 secret 校验
- [ ] HTTPS 终止配置
- [ ] IP 白名单
- [ ] 完整生产监控告警

默认建议：

```text
公网环境：只读
内网/VPN 环境：允许交易
实盘环境：强制开启风控和日志审计
```

---

## 交付

当前仓库包含：

- `Dockerfile`
- `deployments/docker-compose.prod.yml`
- `docs/deployment.md`
- `scripts/deploy.sh`
- `.github/workflows/ci.yml`
- `.github/workflows/cd.yml`

部署自动化主要面向 Macmini 自托管 runner。生产部署前应确认：

- vn.py RPC 服务可达。
- `.env` 中认证、RPC、交易开关、风控和数据库配置正确。
- 前端构建通过。
- 后端测试通过。
- 如涉及交易链路，先执行 RPC smoke。
- QuestDB 和 tick spool 使用持久化 volume；备份恢复步骤见 `docs/deployment.md`。

---

## 项目定位

本项目不是新的交易框架，而是 vn.py 的 Web 化桥接层。

```text
vn.py 负责交易能力
VnPy Web Bridge 负责 Web API、权限、风控、推送和前端交互
```

---

## 风险提示

本项目涉及自动化交易和远程下单能力。任何实盘使用前，应充分测试，并确认风控、权限、日志、网络隔离和异常处理均已完成。

本项目不构成任何投资建议。
