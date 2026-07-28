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
shakedown state 及其 `.tmp`、不可变终态归档目录不能与任何 baseline、
共享 active plan、position-manager 或 C_FAST Shadow 路径重合。

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
GET /api/commodity-simnow/c-fast-shakedown/sessions
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
持续授权。授权先在内存中不可逆撤销，再尝试写入 session；即使磁盘写入失败，
safe-halt、定向撤单和只读 reconcile 仍继续。固定十品种内出现无法用
reference/order id 唯一归属的活动委托时，状态保持
`SUBMISSION_OUTCOME_UNKNOWN`，禁止声明无证据、禁止归档或重发。
归属按每个 send intent 独立判定；同阶段其他子单已 ACK 或已有 evidence，
不能掩盖另一个 unresolved timeout 子单。
如果 unresolved intent 期间持仓已经偏离派单前快照，即使 orders/trades
仍没有回报，也必须保持 `UNRESOLVED_SEND_INTENTS`，禁止按目标持仓误判完成。
submitted、halted reconcile 和 terminal finalize 都会重新读取原始账户持仓；
发现固定十品种范围外持仓时撤权并保留 active plan，禁止生成终态归档。
submitted/halted reconcile 的账户、持仓或 RPC 校验异常会立即撤销对应 lane
授权并进入 safe-halt；orders 可用时定向撤单，不可用时持久化
`CANCEL_PENDING` 并由 worker 重试。
目标手数均为零、仅 exact contract 变化的合法 snapshot 会直接生成可重启恢复的
no-op 终态证据，不发送委托，也不占用共享执行槽。
终态 archive 已写而 current pointer 尚未写入时，启动恢复以通过 checksum 和
chain-tail 校验的 archive 为事实源，修复 pointer 并释放 active plan；不会把
原 COMPLETE 终态降级成冲突的 HALTED 终态。submitted reconcile 的任意 RPC、
账户或安全异常都会先撤权并进入定向撤单/`CANCEL_PENDING` 收口。
共享 active-plan 落盘失败同样不得阻断 live RPC 查询和撤单，结果会显式记录
`active_state_persistence_error`；服务 shutdown 使用 finally 保证 worker
一定停止。

每个终态 session 在覆盖当前 session pointer 前，先写入
`<state-stem>.sessions/<session_id>.json` 不可变归档；下一 session 通过
`previous_terminal_checksum` 与上一终态形成证据链。`sessions` 接口用于
重启后按链顺序枚举和校验历史终态；缺失 predecessor、分叉、循环或单文件
checksum 错误会返回 `CHAIN_BROKEN`。archive 成功但 current pointer 写失败时，
终态重试复用原 archive，不重新生成完成时间、PnL 或 checksum。
如果进程在 archive 写成功、current pointer 写入前崩溃，启动恢复会校验该
session 的 plan、execution、terminal checksum 与唯一 chain tail，以 archive
为终态事实源修复 pointer，并删除旧 active plan；不会用旧 active 状态生成冲突
终态。
chain 校验也是 preview、start、每次 READY 派单和 terminal append 的执行信任
条件；pointer 缺失但 archive 非空、predecessor 被删除或链已断裂时禁止新委托，
已提交计划只允许撤单和只读对账，不能删除 active plan。
archive commit 前的最后一道 guard 连续采集两轮 positions/orders，分别要求
hash 稳定，再校验固定范围、精确 expected positions、session 和全账户外部
活动委托均为零；两轮之间发生成交或状态推进时标记
`UNSTABLE_TERMINAL_SNAPSHOT` 并等待重试。guard 的时间、前后快照 hash 和
blocker 会写入终态或 halt evidence。

## PnL 证据

终态证据包含订单、成交、持仓、fill ratio、实际成交价、决策价和滑点。
`execution_mark_to_market_pnl_cny` 使用当前 L1 mid 对本 session 成交导致的
库存变化估值。未绑定 broker/customer fee 时固定返回：

```text
fees_state=UNBOUND_NOT_ASSUMED_ZERO
net_pnl_state=UNAVAILABLE_UNTIL_FEES_BOUND
```

不得把未绑定费用当作零，也不得把 shakedown PnL 并入正式 forward PnL。
如果 orders/trades execution snapshot 不可用，成交现金流、库存估值和
execution PnL 全部返回 `None`，不得把未知成交事实推导为零。
RPC 可用但 `expected_volume > filled_volume` 时同样返回
`trade_evidence_state=INCOMPLETE`，所有金额字段为 `None`；权威持仓可用于
安全收口，但不能把迟到的 trade callback 当作零成交或零 PnL。
终态 `execution_snapshot` 与 PnL 的成交量、成交现金流和滑点来自同一次
orders/trades 采集，并记录相同的 `execution_captured_at_utc`。
成交回报按 gateway 与 trade id 去重，并且逐 child 验证完整性；任一 child
欠成交时为 `INCOMPLETE`，超额或矛盾证据为 `INCONSISTENT`，两者金额字段均为
`None`。
terminal commit 还会最终复验原始持仓、精确 expected positions、session
活动委托、所有范围（包括未知 symbol）的外部活动委托，以及采集前后的实时
账户哈希和 gateway；未知 order status 同样 fail closed。账户前后不一致、
未绑定原 plan 或不在 C_FAST 专用白名单时禁止归档，并把双向账户绑定和快照
hash 写入 `terminal_guard`。成交回报按
gateway/trade id 去重且逐 child 要求完整；任一 child 缺失或超额时，PnL
分别标记 `INCOMPLETE` 或 `INCONSISTENT`，金额字段保持 `None`。
start 会在实时计划重建前后保存稳定的 order/trade watermark。terminal commit
连续采集两组完整的 account/gateway/connection generation、positions、orders
和 trades 快照；两组完整事实 hash 必须相同。watermark 后出现的任何非本
session order/trade fact（包括已完成且净持仓往返为零）都会阻止归档。
实时重建得到的同一份 positions 同时绑定为 active plan 的
`previous_positions`，派单前再次精确比对；不会用后续未绑定读取替换计划基线。
preview、start 和每次 READY 派单前均拒绝未知 order status。列表型 RPC
快照按行内容无序哈希，返回顺序变化不会制造虚假的不稳定 blocker。
session trade 归属除 order id 外还必须绑定 CTP gateway、exact contract、
direction、offset，并在回报提供 reference 时要求 reference 一致；裸 ID
碰撞、语义缺失或多 child 歧义均标记 `INCONSISTENT`。
遗留 `NOOP_FINALIZING` 在启动时遇到 RPC 暂时不可用只记录恢复错误并保持
fail-closed，后端和 worker 仍会启动，RPC 恢复后自动重试 no-op 终态提交。

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
