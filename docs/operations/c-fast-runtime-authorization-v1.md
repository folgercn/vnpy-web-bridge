# C_FAST 持久 Runtime Authorization 运维手册

本文档对应 Issue #262。Runtime Authorization 只授权已批准的
MAP → C_FAST → signed executable target → CommoditySimNow 链，不改变策略、
分配算法、下单路由或两阶段对账。

## 永久边界

- `execution_lane=simnow_shakedown`
- `signed_snapshots_only=true`
- `continuous=true`
- `production_allowed=false`
- `live_allowed=false`
- `countable_forward=false`
- MAP/C_FAST 不持有 `TradeService`、Gateway 或订单能力。
- Windows 只运行 CTP RPC / SimNow Gateway。
- 每期最终目标仍需签名，并同时绑定 MAP Acceptance 与 C_FAST Allocation
  Acceptance。
- 旧的一次性 Execution Permit verifier、consume receipt 和历史 archive 不删除、
  不改写；它只作为显式例外/兼容模式。

任何配置出现 production/live authority 时必须 fail closed 并撤销 Runtime
Authorization，不允许通过 profile 或 API 切换到生产账户。

## 首次启用

1. 保持 Web 交易和 C_FAST 自动派单关闭。
2. 验证 MAP Strategy Acceptance 的 identity、version/hash、参数、输入合同和风险
   边界。
3. 验证 C_FAST Allocation Policy Acceptance 的 allocator/schema/version/hash、
   产品池、换月语义和组合风险上限。
4. 核对 SimNow account SHA256、allowed products、selected-product 上限、child-order
   上限和产品/板块/gross/net caps。
5. 生成并签署 Runtime Authorization；artifact 与状态目录必须 owner-only，启用和
   revoke 都留下 create-only 审计记录。
6. 使用 admin enable API 显式启用。启动过程不得自动创建或迁移授权。
7. 在交易关闭状态完成账户、持仓、活动委托、RPC、terminal archive chain 和前序
   signed target ownership 只读预检。
8. 仅在上述结果一致后，按既有发布流程启用 SimNow 与自动派单。

## M2 配置

Runtime Authorization 使用以下 7 个环境变量：

```dotenv
COMMODITY_C_FAST_RUNTIME_AUTHORIZATION_ENABLED=false
COMMODITY_C_FAST_MAP_STRATEGY_ACCEPTANCE_PATH=/run/c-fast-simnow/artifacts/map-acceptance.json
COMMODITY_C_FAST_ALLOCATION_ACCEPTANCE_PATH=/run/c-fast-simnow/artifacts/allocation-acceptance.json
COMMODITY_C_FAST_RUNTIME_AUTHORIZATION_PATH=/run/c-fast-simnow/artifacts/runtime-authorization.json
COMMODITY_C_FAST_RUNTIME_AUTHORIZATION_TRUSTED_KEYRING_PATH=/run/c-fast-simnow/keyrings/runtime-authority-keyring.json
COMMODITY_C_FAST_RUNTIME_AUTHORIZATION_EXPECTED_KEYRING_RAW_SHA256=<canonical-keyring-raw-sha256>
COMMODITY_C_FAST_RUNTIME_AUTHORIZATION_STATE_DIR=/run/c-fast-simnow/runtime-authorization-state
```

`backend/.env.example` 提供空路径/default-off 模板；M2 permit Compose overlay
只强制 `COMMODITY_C_FAST_RUNTIME_AUTHORIZATION_ENABLED=false`，不会保存账户、
密钥、签名 artifact 或 keyring pin。私有部署 profile 才能填写绝对路径和 raw
SHA256；启用前须保证 artifact/keyring 只读，state dir owner-only 且可写。

## API

状态读取允许 viewer/trader/admin：

```text
GET /api/commodity-simnow/c-fast-shakedown/runtime-authorization/status
```

启用和撤销仅允许 admin。启用示例：

```http
POST /api/commodity-simnow/c-fast-shakedown/runtime-authorization/enable
Content-Type: application/json

{
  "reason": "approve persistent SimNow runtime",
  "confirm_simnow_only": true,
  "confirm_signed_snapshots_only": true,
  "confirm_continuous": true,
  "confirm_no_production": true,
  "confirm_fail_closed_on_drift": true
}
```

撤销示例：

```http
POST /api/commodity-simnow/c-fast-shakedown/runtime-authorization/revoke
Content-Type: application/json

{
  "reason": "operator revoked persistent runtime authority"
}
```

旧接口 `POST /api/commodity-simnow/c-fast-shakedown/continuous/enable` 只恢复
legacy one-shot Permit 连续会话，不能启用、恢复或替代 Runtime Authorization。
新运行链必须使用上述 runtime-authorization enable/revoke API。

状态接口必须显示 MAP Acceptance、C_FAST Allocation Acceptance、Runtime
Authorization、到期时间/revoke reason、当前 Snapshot、`WAITING_*` 或
`HARD_BLOCKED_*`，并始终显示 `production_allowed=false`。

## 每期 Runtime Snapshot 绑定

使用独立工具把已签 Research snapshot 投影为新 schema，并同时绑定两份
Acceptance 与本期 signal artifact。该工具会重验三份 authority artifact、源
Research 签名和版本 projection，输出 create-only、单 Research 签名的 Runtime
Snapshot；它不会调用 enable API：

```bash
PYTHONPATH=backend python scripts/commodity_c_fast_runtime_snapshot.py \
  --source-snapshot /private/c-fast/research-snapshot.json \
  --map-acceptance /private/c-fast/map-acceptance.json \
  --allocation-acceptance /private/c-fast/allocation-acceptance.json \
  --runtime-authorization /private/c-fast/runtime-authorization.json \
  --trusted-keyring /private/c-fast/runtime-authority-keyring.json \
  --keyring-raw-sha256 '<keyring-raw-sha256>' \
  --private-key /private/c-fast/research-signer.pem \
  --signer-key-id '<research-signer-key-id>' \
  --producer-sha256 '<runtime-producer-code-sha256>' \
  --map-signal-artifact-sha256 '<period-signal-artifact-sha256>' \
  --selected-product ag \
  --output /private/c-fast/runtime-snapshot.json
```

正常 signal、target lots、exact contract 或 execution day 变化不会改变 MAP/C_FAST
版本 projection；公式/producer/input contract、allocator/schema/risk policy 变化会
拒绝生成，必须先签发新 Acceptance。

## 每期运行顺序

1. 先从已接受快照 identity provider 读取 `snapshot_id + sha256`。
2. 若与 COMPLETE terminal pointer 完全相同，直接返回
   `snapshot_already_completed`；此步骤不读取已过期 Acceptance，也不读取或消费
   旧 Permit。
3. 只有 identity/hash 都表明是新快照，才执行完整 Snapshot 验签、MAP/C_FAST
   Acceptance、Runtime Authorization、账户/产品/风险、archive chain 和持仓归属
   校验。
4. Runtime Authorization 覆盖新快照时，不生成、不读取、不消费短时 Permit。
5. 没有 Runtime Authorization 的旧部署可显式选择 legacy Permit fallback；已经
   revoked/expired/hard-blocked 的 Runtime Authorization 不得静默降级为 fallback。
6. preview/start 后继续使用既有 send-intent-first、先平后开、逐 child final guard、
   timeout unknown-outcome no-replay、对账和 create-only terminal archive。

## WAITING（不撤权、不下单）

- RPC 暂时断开、网络抖动或 probe 暂时失败；
- 新快照尚未到 execution day；
- 当前不在允许交易窗口；
- 当前快照已完成，没有新目标；
- 新快照文件暂时不存在，但 COMPLETE pointer 与 archive chain 仍完整；
- 新快照尚未完成 Control Plane 接受。

恢复后必须从头重新验证，不得复用上次 preview 或把 WAITING 当作可派单状态。

## HARD BLOCK / REVOKE

以下情况先在内存撤权，再持久化 revoke 与审计；持久化异常不能恢复下单权：

- Snapshot 签名、identity/hash、连续性或 MAP/C_FAST binding 失败；
- MAP/C_FAST Acceptance 撤销、到期或版本/范围不覆盖；
- account hash、allowed products 或风险范围漂移；
- 持仓不能由上一 signed target 证明，存在范围外持仓或外部活动委托；
- archive/custody/terminal chain 失效；
- Runtime Authorization 到期或人工撤销；
- production/live/countable-forward 边界异常；
- active plan 中存在不能安全解释的 send intent 或未知结果。

撤权后即使网络、RPC 或人工停止状态恢复，也必须由管理员重新完成启用流程。

## 重启

- planned restart：正常 stop 只暂停内存执行状态，保留已签 Runtime
  Authorization；重启后必须完整核对 account/position/orders/RPC/archive/ownership，
  通过后才恢复。
- crash restart：若存在 active plan，先进入 recovery/safe-halt，定向取消、对账并
  解释所有 send intent；不得创建新 plan 或重复下单。
- revoke、expired 或 hard-blocked 状态持久化跨重启，不因服务启动自动恢复。

## 旧会话迁移

迁移必须由管理员显式运行迁移工具，并保持交易关闭。工具只接受：

- COMPLETE terminal pointer；
- checksum 与 predecessor chain 全部有效的 create-only archive；
- 当前 SimNow account hash 与 archive account binding 一致；
- 最终活动委托为零；
- 当前持仓与 terminal reconciliation 的 expected positions 完全一致；
- 显式提供且已验证的新 MAP Acceptance 与 C_FAST Allocation Acceptance。

工具不得修改旧 Snapshot、Acceptance、Permit、consume receipt 或 archive 字节，
不得把旧 C_FAST Acceptance 伪装成 MAP Acceptance，也不得启用 Web 交易或自动
派单。迁移产物仍需独立签署并通过 admin enable 才获得 Runtime Authorization。

交易关闭并导出只读 live facts 后执行 create-only 预检：

```bash
PYTHONPATH=backend python scripts/commodity_c_fast_runtime_migration_preflight.py \
  --terminal-pointer /private/c-fast/shakedown-session.json \
  --archive-dir /private/c-fast/shakedown-session.sessions \
  --live-facts /private/c-fast/migration-live-facts.json \
  --expected-account-sha256 '<simnow-account-sha256>' \
  --output /private/c-fast/migration-preflight.json
```

报告固定 `automatic_enable=false`；`eligible=true` 也只是迁移证据，不会自动
放权。随后仍需签署 Runtime Authorization 并调用 admin enable。

## 回退

1. admin revoke Runtime Authorization，记录 reason。
2. 停止自动派单；若有 active plan，按既有 stop/cancel/reconcile 流程安全收口。
3. 确认活动委托为零、持仓与签名目标一致、terminal archive chain 有效。
4. 如确需一次性验收，另行签发新的短时 Permit；不得删除或复用旧 consume
   receipt。
