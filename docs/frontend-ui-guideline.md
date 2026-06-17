# 前端 UI 开发规范草案

本文档用于明确 `vnpy-web-bridge` 前端开发原则：统一现代风格，尽量复用成熟开源中后台模板，不重复造轮子。

---

## 1. 总原则

前端不从零搭后台系统，不自行重复实现以下能力：

- Layout 布局
- 侧边栏菜单
- 顶部导航
- 路由守卫
- 登录页基础结构
- 权限路由
- 主题切换
- 暗色模式
- 表格基础样式
- 表单基础样式
- 弹窗确认
- API 请求封装
- WebSocket 状态提示基础组件

项目应基于成熟开源 Admin 模板搭建，在此基础上只开发交易业务页面和 vn.py 业务适配。

---

## 2. 推荐前端基线

第一候选：

```text
Vue 3 + Vite + TypeScript + Vue Vben Admin
```

采用原因：

- 面向中后台系统，适合交易终端形态。
- 已包含现代后台布局、路由、权限、主题、国际化等基础设施。
- 技术栈符合 Vue 3 / Vite / TypeScript 方向。
- 可以减少大量通用后台页面和组件开发。

备选方案：

```text
React + Ant Design Pro
Vue 3 + Naive UI Admin
React / Vue + Arco Design Pro
```

选择原则：

- 优先选择完整 Admin 模板，而不是只选择 UI 组件库。
- 优先选择有权限、路由、主题、请求封装的模板。
- 优先选择 TypeScript 支持完善的方案。
- 避免同时混用多个 UI 体系。

---

## 3. 不重复造轮子的边界

### 直接复用模板能力

- 登录页结构
- 主布局
- 侧边栏菜单
- Breadcrumb
- Tab / 多页签
- 菜单权限
- 按钮权限
- API client 基础封装
- 主题系统
- 暗色模式
- 表格容器
- 表单容器
- Modal / Drawer
- Toast / Message

### 项目自行开发能力

- vn.py RPC 状态展示
- 交易网关状态展示
- 行情订阅业务逻辑
- tick 数据展示
- 下单面板
- 撤单 / 全撤交互
- 持仓表格字段定义
- 委托表格字段定义
- 成交表格字段定义
- 风控状态展示
- 策略管理业务页面
- WebSocket 事件适配
- 交易审计日志展示

---

## 4. 推荐页面风格

整体定位：

```text
专业交易后台
高密度数据展示
低干扰颜色
明显的风险状态提示
暗色模式优先支持
```

页面特征：

- 左侧菜单：Dashboard、行情、交易、持仓、委托、成交、资金、策略、日志、系统设置。
- 顶部状态栏：RPC 状态、网关状态、WebSocket 状态、Web 交易开关、当前用户。
- 内容区：卡片 + 表格 + 操作面板。
- 交易操作：必须有二次确认弹窗。
- 风险状态：必须使用全局明显提示。
- 错误提示：展示后端 `error.message` 和 `error.code`。

---

## 5. 组件选择规范

统一使用一个 UI 体系，不混搭不同组件库。

### 基础组件

- Button
- Input
- Select
- Radio
- Switch
- Modal
- Drawer
- Tabs
- Table
- Card
- Tag
- Badge
- Tooltip
- Message
- Notification

### 图表组件

建议独立引入：

```text
TradingView Lightweight Charts / KLineCharts：K 线、分时
ECharts：资金曲线、收益曲线、统计图
```

图表组件只用于交易数据展示，不作为后台 UI 体系替代品。

---

## 6. 前端目录建议

基于 Admin 模板后，业务目录建议保留：

```text
frontend/src
├── api/
│   ├── auth.ts
│   ├── status.ts
│   ├── market.ts
│   ├── account.ts
│   ├── trade.ts
│   ├── risk.ts
│   └── strategy.ts
├── pages/
│   ├── dashboard/
│   ├── market/
│   ├── trading/
│   ├── positions/
│   ├── orders/
│   ├── trades/
│   ├── account/
│   ├── strategies/
│   └── logs/
├── components/
│   ├── trading/
│   ├── market/
│   ├── account/
│   ├── risk/
│   └── common/
├── stores/
│   ├── auth.ts
│   ├── status.ts
│   ├── market.ts
│   ├── account.ts
│   ├── trade.ts
│   ├── risk.ts
│   └── strategy.ts
└── ws/
    └── events.ts
```

不要把交易业务逻辑写进模板原有 demo 页面中。应删除或隔离模板示例代码。

---

## 7. 交易终端布局建议

### Dashboard

- RPC 状态卡片
- CTP 网关状态卡片
- WebSocket 状态卡片
- Web 交易开关卡片
- 账户资金摘要
- 持仓摘要
- 当日委托 / 成交统计
- 最新风险提示

### 交易页

建议左右结构：

```text
左侧：行情 /盘口 / 最新 tick
中间：下单面板
右侧：当前持仓 / 当前委托
底部：成交 / 日志
```

### 委托页

- 当前委托
- 历史委托
- 可撤状态过滤
- 单笔撤单
- 全撤按钮

### 风控状态

在所有页面顶部保留全局状态：

```text
RPC: connected / disconnected
Gateway: CTP
WS: connected / reconnecting / disconnected
Trade: enabled / disabled / emergency stopped
```

---

## 8. API 适配原则

前端只依赖后端 DTO，不依赖 vn.py 原始对象。

前端 API 返回统一处理：

```ts
interface ApiResponse<T> {
  ok: boolean
  data?: T
  error?: {
    code: string
    message: string
    detail?: Record<string, unknown>
  }
}
```

所有 API client 必须经过统一请求层，统一处理：

- token
- 超时
- 错误码
- 401 跳登录
- 403 权限提示
- 网络异常
- 后端业务错误

---

## 9. WebSocket 适配原则

WebSocket 只建立一个主连接：

```text
/ws/events
```

消息统一格式：

```ts
interface WsEvent<T = unknown> {
  type: string
  ts: string
  data: T
}
```

事件处理集中放在：

```text
src/ws/events.ts
```

不要在每个页面各自创建 WebSocket 连接。

断线重连后必须重新拉取快照：

- account
- positions
- orders
- trades
- risk status
- strategy status

---

## 10. 颜色和视觉原则

不在业务组件中随意写颜色。

要求：

- 使用模板主题变量。
- 使用 UI 组件库的 Tag / Badge / Alert 表示状态。
- 盈亏颜色、买卖方向颜色统一封装。
- 风险状态使用统一组件。
- 暗色模式下必须可读。

交易状态建议统一封装：

```text
多 / 买：统一方向样式
空 / 卖：统一方向样式
开仓：统一开仓样式
平仓：统一平仓样式
未成交：普通状态
部分成交：警示状态
全部成交：成功状态
已撤销：弱化状态
拒单：错误状态
```

---

## 11. Phase 5 调整

Phase 5 不应从空白 Vite 项目开始，而应改为：

1. 选定 Admin 模板。
2. 初始化模板到 `frontend/`。
3. 删除 demo 页面和无关功能。
4. 保留 Layout、权限、路由、主题、请求封装。
5. 接入后端 API client。
6. 开发 vn.py 交易业务页面。
7. 接入 WebSocket。
8. 做交易风控状态和下单确认。

---

## 12. 验收标准

前端基线完成的验收标准：

- [ ] 使用统一 Admin 模板。
- [ ] 只保留一个 UI 组件体系。
- [ ] 页面整体风格一致。
- [ ] 登录、Layout、菜单、路由守卫可用。
- [ ] API client 统一封装。
- [ ] WebSocket client 全局唯一。
- [ ] Dashboard、行情、交易、持仓、委托、成交、资金、策略、日志页面路径已建立。
- [ ] 删除或隐藏模板 demo 页面。
- [ ] 暗色模式下交易页面可读。
- [ ] 下单、撤单、风控提示遵循统一交互。