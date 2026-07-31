# Research Warehouse 主业务消费边界 v1

Research Warehouse 的 186 个官方交易日是 Research Plane 的历史证据源，
不是 Web Bridge 主业务可以直接查询或挂载的数据目录。主业务只消费经过
独立验证、签名并安装的业务快照；不得获得 M2 custody、raw、receipt、
manifest、DuckDB 或私钥路径。

## 当前状态

| 环节 | 状态 |
| --- | --- |
| M2 186 个官方交易日、10 个产品、exact bytes 与每日 receipt | 已完成 |
| 增量 manifest/commit/root anchor | 已完成 |
| Warehouse → sealed PIT source view 适配器 | 尚未实现，跟踪于 #215 |
| Position-manager Research producer 与签名工具 | 已存在 |
| Web Bridge 签名 Shadow 消费入口 | 已存在 |
| 主业务实际启用本批历史数据 | 尚未启用 |

因此，#213 完成的是可信历史输入，不应被描述为“主业务已经在使用”。在
sealed source view 适配器、独立验证和受控签名完成前，主业务继续使用当前
已验收输入并 fail closed。

后续实现与主业务只读启用由
[#215](https://github.com/folgercn/vnpy-web-bridge/issues/215) 跟踪。

## 固定消费链

```text
M2 Research Warehouse
  -> create-only sealed PIT source view
  -> source receipt/keyring/custody verification
  -> commodity_relative_vol_snapshot_producer.py
  -> independent review
  -> commodity_position_manager_shadow_sign.py
  -> COMMODITY_POSITION_MANAGER_SHADOW_PATH
  -> Web Bridge read-only validation/preview
```

Warehouse 适配器必须按签名官方日历选择 PIT 窗口，绑定 186 日 acquisition
receipt、每日 exact raw SHA-256/byte count、calendar/calendar-anchor、
registry、manifest head/commit head/root state，并生成符合
`commodity-relative-vol-position-manager-source-view-v1.schema.json` 的
create-only canonical JSON。它不得伪造历史 observation/availability 时间，
不得调用交易、账户、持仓、订单、Gateway、CTP、SimNow 或 Windows RPC。

186 日是仓库可用窗口；业务 source view 仍必须严格满足下游 schema
对 official calendar、126 日序列、PIT cutoff、baseline、合约规格和连续性
的约束，不能把“仓库有 186 日”直接等同为一个可签业务快照。

## 主业务调用点

Web Bridge 的唯一接入点是
`COMMODITY_POSITION_MANAGER_SHADOW_PATH=/absolute/path/to/signed-shadow.json`。
消费端继续执行 Ed25519、baseline link、月份连续性、冻结公式、guardband、
整数目标和路径隔离校验。无效、缺失或未关联的 Shadow 只能显示为 invalid /
unlinked，不能覆盖最后一次已接受状态。

可通过只读接口检查消费结果：

```text
GET /api/commodity-simnow/position-manager-shadow
GET /api/commodity-simnow/position-manager-shakedown/status
```

设置路径或通过只读校验不授予 Acceptance、Deployment、Execution、Permit、
Trading 或自动派单权限。SimNow shakedown、auto-dispatch 和 production 开关
继续保持各自独立、默认关闭的授权边界。

## 接入验收

后续接入工作至少必须证明：

1. 同一 Warehouse root pin 重放得到逐字节一致的 sealed source view；
2. 10 个产品的 official-day/PIT/return/contract lineage 完整；
3. producer 输出、evidence、签名 Shadow 和主业务读回 hash 全部一致；
4. 缺日、错日、hash 漂移、非法权限、路径重叠和未关联 baseline 均失败关闭；
5. 主业务进程没有 M2 custody、raw、receipt、manifest 或私钥读权限；
6. 未显式授权时不触发 SimNow、交易、RPC 或订单行为。

相关运行说明见
[`commodity-relative-vol-snapshot-producer-v1.md`](../operations/commodity-relative-vol-snapshot-producer-v1.md)
和
[`commodity-static-core-simnow.md`](../commodity-static-core-simnow.md)。
