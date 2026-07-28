# C_FAST SimNow Shakedown Adapter

本文档对应 Issue #148。该适配器位于 M2 Control Plane，只消费已被
`CommodityCFastShadowService` 接受并再次验证的完整十品种签名快照。
C_FAST Shadow 本身仍无 `TradeService`、下单或撤单能力；Windows 仍只负责
CTP RPC 执行与事实回传。

## 固定安全边界

- `candidate_id=C_FAST_CROSS_SECTION_NEUTRAL`
- `execution_lane=simnow_shakedown`
- `countable_forward=false`
- `production_allowed=false`
- `automatic_promotion_allowed=false`
- C_FAST 专用账户 SHA256 白名单与通用 CommoditySimNow 白名单必须同时命中。
- snapshot、formula binding、exact contract、账户、持仓或活动委托不一致时
  fail closed。
- preview 固化 snapshot hash、execution day、selected products、session nonce
  和 plan hash；start 前用实时 RPC、持仓、合约和盘口重新构建并比对计划。
- send intent 先于 RPC 调用落盘；timeout/未知结果只允许恢复和对账，不得重发。

## 配置

```env
COMMODITY_C_FAST_SHADOW_ENABLED=true
COMMODITY_C_FAST_SIMNOW_SHAKEDOWN_ENABLED=false
COMMODITY_C_FAST_SIMNOW_ACCOUNT_HASHES=<dedicated-simnow-account-sha256>
COMMODITY_C_FAST_SIMNOW_STATE_PATH=logs/commodity-c-fast-shadow/shakedown-session.json
COMMODITY_C_FAST_SIMNOW_AUTO_DISPATCH_ENABLED=false
COMMODITY_C_FAST_SIMNOW_MAX_SELECTED_PRODUCTS=2
```

部署默认必须保持两个 shakedown 开关为 `false`。启用前还必须配置并验证现有
`COMMODITY_SIMNOW_*` 安全项、Web 交易风控和 C_FAST Shadow 公钥/路径。
shakedown state 路径不能与任何 baseline、position-manager 或 C_FAST Shadow
路径重合。

## 数据流

```text
signed C_FAST snapshot
  -> Shadow signature/continuity/exact-contract validation
  -> Control Plane preview (1-2 products initially)
  -> immutable execution mask and session nonce
  -> start-time account/position/order/quote revalidation
  -> existing CommoditySimNow two-phase dispatcher
  -> Windows CTP RPC
  -> order/trade/position reconciliation and SimNow PnL evidence
```

完整十品种 signed previous target 必须与账户持仓完全相同，才能生成预览。
未选择品种保持 signed previous target；所选品种必须原样收敛到
`target_quantity`。执行层只拆分 child orders，不缩放、不重算、不替换目标。
合约切换或反向时先平旧仓，完成持仓与活动委托对账后才开新仓。

当前适配器遇到所选品种今日持仓会拒绝执行，不猜测平今/平昨。只有权威
持仓明细足以安全拆分后，才能另行放宽。

## API

读接口允许 viewer/trader/admin：

```text
GET /api/commodity-simnow/c-fast-shakedown/status
GET /api/commodity-simnow/c-fast-shakedown/events
GET /api/commodity-simnow/c-fast-shakedown/pnl
```

变更接口仅 admin：

```text
POST /api/commodity-simnow/c-fast-shakedown/preview
POST /api/commodity-simnow/c-fast-shakedown/start
POST /api/commodity-simnow/c-fast-shakedown/stop
POST /api/commodity-simnow/c-fast-shakedown/reconcile
```

一次显式 start 后自动推进 close、reconcile、open、final reconcile，不逐笔确认。
同一进程内授权会持续监视新接受的连续 snapshot；当 selected scope 再次出现
target delta 时自动生成新 session，无需逐会话确认。正常 shutdown、disable、
emergency stop、信任校验失败或任何 fail-closed 停机会撤销持续授权，重启后
只有仍在收口的原 session 可以恢复，不会静默获得新的下单权。stop 只按本
session nonce/reference 和已确认 order id 定向撤单；会话空闲时 stop 只撤销
持续授权。

## PnL 证据

终态证据包含订单、成交、持仓、fill ratio、实际成交价、决策价和滑点。
`execution_mark_to_market_pnl_cny` 使用当前 L1 mid 对本 session 成交导致的
库存变化估值。未绑定 broker/customer fee 时固定返回：

```text
fees_state=UNBOUND_NOT_ASSUMED_ZERO
net_pnl_state=UNAVAILABLE_UNTIL_FEES_BOUND
```

不得把未绑定费用当作零，也不得把 shakedown PnL 并入正式 forward PnL。

## 本地验证

```bash
PYTHONPATH=backend python -m pytest -q \
  backend/tests/unit/test_commodity_c_fast_simnow.py \
  backend/tests/unit/test_commodity_c_fast_shadow.py \
  backend/tests/unit/test_commodity_simnow.py \
  backend/tests/unit/test_commodity_simnow_api.py
```

真实 SimNow 验收必须先部署验证镜像并保持交易关闭完成只读 preflight；任何
真实模拟委托前仍需用户当次明确授权。验收后确认活动委托为零、持仓与 masked
target 或停止后的成交事实一致，并归档 deployed SHA、session evidence 和日志。
