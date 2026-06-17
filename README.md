# VnPy Web Bridge

基于 **vn.py / VeighNa** 的远程 Web 交易桥接服务。

本项目目标是把本地/远程运行的 vn.py 交易服务，通过统一的 Web API 和 WebSocket 推送能力暴露给前端页面，用于行情订阅、账户查询、持仓查询、委托成交、下单撤单、策略管理和风控扩展。

> 当前项目处于初始开发阶段，优先完成最小可用闭环：行情订阅、账户/持仓/委托查询、下单、撤单、WebSocket 推送。

---

## 项目背景

当前已验证链路：

```text
Mac 开发机
  -> RPC
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

后续开发重点是将这条链路产品化，形成稳定的 Web 交易桥接层。

---

## 目标架构

```text
Web Frontend
  Vue / React / Next.js
        |
        | REST API + WebSocket
        v
Web Backend
  FastAPI / Python
        |
        | RPC
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
- 下单、撤单等交易能力必须经过后端风控检查。
- Web 交易能力默认不暴露公网。

---

## 功能规划

### Phase 1：只读能力

- [ ] 服务状态查询
- [ ] RPC 连接状态
- [ ] 合约查询
- [ ] 行情订阅
- [ ] Tick 推送
- [ ] 账户资金查询
- [ ] 持仓查询
- [ ] 委托查询
- [ ] 成交查询
- [ ] 日志推送

### Phase 2：基础交易

- [ ] 限价单下单
- [ ] 撤单
- [ ] 全撤
- [ ] 买入 / 卖出 / 开仓 / 平仓参数封装
- [ ] 下单前二次确认
- [ ] Web 交易开关
- [ ] 操作日志记录

### Phase 3：风控

- [ ] 单笔最大手数限制
- [ ] 单合约最大持仓限制
- [ ] 每日最大亏损限制
- [ ] 交易时间检查
- [ ] 价格保护检查
- [ ] 只读用户 / 交易用户 / 管理员权限分离
- [ ] 一键关闭交易

### Phase 4：策略管理

- [ ] CTA 策略列表
- [ ] 策略参数查看
- [ ] 策略参数修改
- [ ] 初始化策略
- [ ] 启动策略
- [ ] 停止策略
- [ ] 策略变量推送
- [ ] 策略日志推送

### Phase 5：前端交易终端

- [ ] 登录页
- [ ] Dashboard
- [ ] 行情页
- [ ] 下单面板
- [ ] 持仓页
- [ ] 委托页
- [ ] 成交页
- [ ] 资金页
- [ ] 策略管理页
- [ ] 系统日志页

---

## 目录规划

```text
vnpy-web-bridge/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   ├── routes_status.py
│   │   │   ├── routes_market.py
│   │   │   ├── routes_trade.py
│   │   │   ├── routes_account.py
│   │   │   └── routes_strategy.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   ├── security.py
│   │   │   └── logging.py
│   │   ├── services/
│   │   │   ├── vnpy_rpc_service.py
│   │   │   ├── market_service.py
│   │   │   ├── trade_service.py
│   │   │   ├── account_service.py
│   │   │   ├── risk_service.py
│   │   │   └── strategy_service.py
│   │   ├── schemas/
│   │   │   ├── market.py
│   │   │   ├── trade.py
│   │   │   ├── account.py
│   │   │   └── strategy.py
│   │   └── ws/
│   │       ├── manager.py
│   │       └── events.py
│   ├── tests/
│   ├── requirements.txt
│   └── README.md
│
├── frontend/
│   ├── src/
│   ├── package.json
│   └── README.md
│
├── scripts/
│   ├── test_rpc_readonly.py
│   └── test_rpc_trade_flow.py
│
├── docs/
│   ├── architecture.md
│   ├── api.md
│   ├── risk.md
│   └── deployment.md
│
├── .gitignore
├── README.md
└── LICENSE
```

---

## API 设计草案

### 状态

```http
GET /api/status
GET /api/gateway/status
GET /api/rpc/status
```

### 行情

```http
GET  /api/contracts
POST /api/market/subscribe
GET  /api/market/tick/{vt_symbol}
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

### 策略

```http
GET  /api/strategies
GET  /api/strategies/{strategy_name}
POST /api/strategies/{strategy_name}/init
POST /api/strategies/{strategy_name}/start
POST /api/strategies/{strategy_name}/stop
PATCH /api/strategies/{strategy_name}/setting
```

### WebSocket

```http
GET /ws/events
```

统一事件格式：

```json
{
  "type": "order",
  "data": {}
}
```

计划支持的事件类型：

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

## 开发环境规划

### 后端

计划使用：

- Python 3.10+
- FastAPI
- Uvicorn
- Pydantic
- vn.py / VeighNa RPC Client

启动方式草案：

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Windows 侧运行 vn.py RPC 服务，Mac 侧后端通过 RPC 连接 Windows 交易服务。

### 前端

备选技术栈：

- Vue 3 + Vite + Naive UI / Element Plus
- React + Vite / Next.js + Ant Design
- TradingView Lightweight Charts / KLineCharts / ECharts

启动方式草案：

```bash
cd frontend
npm install
npm run dev
```

---

## 配置文件草案

后端计划使用 `.env` 管理本地配置：

```env
APP_ENV=development
APP_HOST=0.0.0.0
APP_PORT=8000

VNPY_RPC_HOST=127.0.0.1
VNPY_RPC_PORT=2014
VNPY_RPC_PUSH_PORT=2016

JWT_SECRET_KEY=change-me
WEB_TRADE_ENABLED=false
```

敏感配置不得提交到 GitHub。

---

## 安全要求

Web 端具备交易能力后，必须满足以下要求：

- 登录认证
- 权限分级
- HTTPS
- IP 白名单
- 下单二次确认
- Web 交易总开关
- 后端风控校验
- 操作日志审计
- 一键关闭交易
- 敏感配置本地化，不提交仓库

默认建议：

```text
公网环境：只读
内网/VPN 环境：允许交易
实盘环境：强制开启风控和日志审计
```

---

## 开发路线

### 当前优先级

1. 初始化后端 FastAPI 项目。
2. 封装 vn.py RPC Client。
3. 实现只读 API：状态、合约、资金、持仓、委托、成交。
4. 实现行情订阅和 WebSocket 推送。
5. 实现下单、撤单、全撤。
6. 增加基础风控。
7. 再开始做完整前端页面。

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