# MONTHLY_RELATIVE_VOL_THERMOSTAT_V1 SimNow 验收 Runbook

本 Runbook 仅适用于 Issue #111 的独立候选 shakedown 会话。它不是正式
`official_forward`，每次会话必须记录 `execution_lane=simnow_shakedown` 和
`countable_forward=false`。

## 不可跳过的边界

- 只允许已白名单的 SimNow 账户；不得使用生产账户。
- Shadow 始终保持 `mode=shadow_only`、`authority_granted=false`、
  `dispatch_allowed=false`。派单权只来自独立 shakedown 会话。
- 页面只能选择品种；exact contract、目标方向和手数必须来自有效的已签名
  Shadow 快照，不能手改。
- 只允许在预先批准的 SimNow 测试窗口执行；页面点击“启动 SimNow 候选测试”
  即为本次会话的执行确认，不需要逐单或另行等待站外授权。
- 会话开始后，不得修改 selected products、snapshot hash 或 plan hash；主力
  合约变化时停止并完成对账，再重新 preview。

## T1：远端只读预检

部署待验收 SHA 的验证镜像，但保持以下执行开关关闭：

```env
WEB_TRADE_ENABLED=false
COMMODITY_POSITION_MANAGER_SIMNOW_SHAKEDOWN_ENABLED=false
COMMODITY_POSITION_MANAGER_SIMNOW_AUTO_DISPATCH_ENABLED=false
```

确认镜像、Bridge 健康和 RPC/CTP 登录正常后，以只读身份检查：

```text
GET /api/commodity-simnow/status
GET /api/commodity-simnow/position-manager-shadow
GET /api/commodity-simnow/position-manager-shakedown/status
GET /api/commodity-simnow/plan
GET /api/commodity-simnow/events?limit=200
```

预检通过条件：

1. 账户被识别为 SimNow，且账户哈希命中白名单；不记录原始账户号。
2. CTP/RPC 可用；十品种的 exact contract、合约规格和盘口可读。
3. Shadow `configured=true`、`valid=true`，baseline link 为 `active` 或
   `completed`，continuity 为 `genesis` 或 `verified`。
4. baseline 无未完成执行；shakedown 无未收口会话；账户没有冲突持仓或活动委托。
5. 当前部署 SHA、镜像 tag、时间和上述 API 响应已保存到验收记录。

任何一项失败都保持交易关闭，不进行 preview 或启动。

## T2：页面 Preview（不发单）

1. 仅选择一个有非零 `target_delta`、不在交割保护期且行情新鲜的品种。
2. 点击“准备预览”，记录 `session_id`、`source_snapshot_hash`、
   `baseline_batch_hash`、selected products、plan hash、当前持仓、close/open
   阶段、订单数和总手数。
3. 改变选择后重新 preview，确认旧 plan hash 被拒绝且未调用订单接口。
4. 在所有结果正确前，仍保持三个执行开关关闭。

## T3：单品种自动 shakedown

在已批准的 SimNow 测试窗口内，按以下最小范围执行：

1. 启用 SimNow 专用开关、账户白名单和 shakedown 自动派单；不要启用生产账户
   或修改 Shadow 的安全 Literal。
2. 重新执行 T1 和 T2；启动请求必须使用刚生成的 plan hash。
3. 点击一次“启动 SimNow 候选测试”。除观察与紧急停止外，不进行逐笔操作。
4. 观察 `send intent -> order id -> trade -> position`，确认平仓阶段完全对账后
   才进入开仓阶段。
5. 结束时查询 orders、trades 和 positions，确认 selected product 达到记录的最终
   目标、委托全部终态，状态为 `COMPLETE`；若停止或异常，则应为
   `HALTED_RECONCILED`。未选品种不得出现本会话 reference。
6. 立即关闭 shakedown 执行开关，归档证据。

## T4/T5：多品种与恢复专项

T3 通过后才可选择 2--3 个品种。验证每个品种的 close/open 隔离、reference
唯一性和未选品种零委托。恢复专项在独立窗口进行：工作委托时重启 Bridge、模拟
RPC timeout/迟到事件和部分成交；期望行为是停止新单、定向撤单、只读对账，绝不
重复下单。任何异常均使用“停止测试”收口；只处理当前 session 的 references。

## 每次会话的证据

归档以下内容，且不得包含账户号、私钥或 token：

- deployed Git SHA/image、操作人、起止时间和 SimNow 账户哈希匹配结果；
- snapshot/baseline/continuity 状态、source month、input cutoff、执行日和
  vol/scale 审计字段；
- session ID、plan hash、selected products、每品种 baseline/shadow target、
  current position 和 planned delta；
- send intents、references、订单、成交、滑点、撤单、RPC 错误和每轮持仓对账；
- 最终状态及 `countable_forward=false`。

`COMPLETE` 只证明本次 SimNow 子集执行收口成功；它不证明完整十品种候选效果，
也不允许晋级或替换 `STATIC_CORE_EQUAL`。
