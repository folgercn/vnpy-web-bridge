# STATIC_CORE_EQUAL 远端算法与参数完备性审计（2026-07-29）

## 结论

审计基准：`main@50b3674baf5ba4206be4de73b4c5ee6818aab269`。

结论为：

```text
EXECUTION_CONSUMER_COMPLETE_ENOUGH
RESEARCH_ALGORITHM_PRODUCERS_COMPLETE
REAL_SOURCE_REPRODUCTION_PENDING
FROZEN_SECTOR_MAP_PARITY_RESTORED
```

当前 `main` 已能安全消费研究侧签名的 `STATIC_CORE_EQUAL` 整数目标，并完成
SimNow 两阶段派单、换月、对账和执行质量记录。C_FAST、D
Donchian20/exit10、C+D 产品级净额、guardband、整数分配与 relative-vol
thermostat producer 均已在远端；算法与冻结参数不再依赖本地研究机文件。

仍不能只依靠仓库从官方行情完成一次真实再生：真实 PIT full-contract OHLC/OI
和官方日收益不属于代码仓库，且需要 receipt、keyring、custody 与 sealed-export
验证。这里的剩余缺口是“真实输入与受控运行”，不是“策略公式或参数缺失”。

## 逐项审计

| 能力 | 远端 `main` | 判断 |
|---|---|---|
| scheduler 身份、十品种、月频、20m NAV | schema/service 中固定 | 完整 |
| `50%C + 50%D` 权重元数据 | 批次验签后固定校验 | 完整 |
| guardband `12%/27%/80%/0` | 批次和仓位管理均校验 | 参数与冻结 sector map 完整 |
| beam allocator `radius=2/width=2048/net penalty=1` | schema Literal 固定 | 参数完整 |
| beam 整数最优化重算 | Execution 不重算；Research composite producer 重算 | 完整且平面隔离 |
| C_FAST 信号 producer | 独立 pure producer kernel 已存在 | 完整 |
| D Donchian20/exit10 producer | `commodity_static_core_equal_formula_v1.py` | 完整 |
| C+D 单账户产品级净额 | composite producer 以 50/50 产品级合成 | 完整 |
| PIT OI 主力选择 | pure producer 对 typed source view 做 PIT 排名 | 算法完整，真实输入待验收 |
| 换月、两阶段派单、持仓对账 | 控制器完整实现 | 完整 |
| 相对波动 thermostat 公式 | 21/126、0.8–1.2、alpha 0.5 均硬校验 | 参数完整 |
| thermostat 波动率与目标生成 | pure producer 从严格滞后的官方日收益 typed view 重算 | 算法完整，真实输入待验收 |

## 已完整固化的参数

`backend/app/schemas/commodity_simnow.py` 与
`backend/app/services/commodity_simnow.py` 已固定：

- `scheduler_id=STATIC_CORE_EQUAL`
- `source_combination_arm=CORE_EQUAL_TARGET`
- `candidate_weights={C: 0.5, D: 0.5}`
- `virtual_nav_cny=20_000_000`
- `FINITE_NEIGHBOURHOOD_BEAM_V1`
- neighbourhood radius `2`
- beam width `2048`
- net error penalty `1.0`
- 仅月度目标、禁止日内自动重配、换月保持整数手
- source caps `20%/35%/100%/net zero`
- buffer caps `12%/27%/80%/net zero`
- integer hard caps `<15%/<35%/<100%/abs net <10%`
- `simnow_shakedown` 可立即运行但不计入正式 forward
- `official_forward` 从 `2026-08` source month、`2026-09` holding month 开始

仓位管理还固定：

- `position_manager_id=MONTHLY_RELATIVE_VOL_THERMOSTAT_V1`
- lookback `21/126`
- annualization `252`
- `raw_scale=clip(sqrt(vol126/vol21), 0.8, 1.2)`
- `smoothed_scale=0.5*raw+0.5*previous`
- genesis previous scale `1.0`
- 月度连续性、签名、baseline batch 关联和 guardband 复核

## 已上远端的算法链

### D 腿与 roll-safe 价格链

PR [#189](https://github.com/folgercn/vnpy-web-bridge/pull/189) 已合入
`D_DONCHIAN20_EXIT10_NEUTRAL`：前 20 个官方日突破、前 10 个官方日退出，
并以旧主力完成换月日区间、次日切换新主力尺度，避免直接拼接换月跳空。
producer 对每个产品输出状态迁移、PIT 主力排名和 roll anchor 证据。

### C+D 组合与整数分配

`commodity_static_core_equal_pure_producer.py` 已在 Research Plane 重算：

- C_FAST 与 D sleeve；
- `50%C + 50%D` 产品级净额；
- guardband v2；
- 20m CNY NAV 下的有限邻域 beam 整数分配；
- exact contract、合约规格、方向与硬上限。

`CommoditySimNowService` 仍只验签名结果与执行硬上限，不在 Execution Plane
重算策略。这是有意保留的平面隔离，不是算法缺失。

### Relative-vol 仓位管理

PR [#188](https://github.com/folgercn/vnpy-web-bridge/pull/188) 已合入
`commodity_relative_vol_snapshot_producer.py`。它从严格滞后的 typed source
view 生成 21/126 日样本波动、0.8–1.2 raw scale、alpha 0.5 连续平滑，并对
baseline batch 重新执行 guardband 与整数分配。服务端继续独立复核公式与签名
连续性。

上述四份远端实现由 lineage manifest 固定完整源码 SHA256；验证器也会拒绝
manifest 漂移、源码漂移、缺失文件和符号链接替换。

## 已修复：sector map 与本地冻结规则一致

原冻结研究使用：

```text
bu -> energy_chemical
ru -> energy_chemical
sp -> light_industry
```

Issue [#183](https://github.com/folgercn/vnpy-web-bridge/issues/183) 已由
PR [#187](https://github.com/folgercn/vnpy-web-bridge/pull/187) 修复并合入
`main`。主策略、position manager 与 C_FAST runtime 现在都从
`COMMODITY_FROZEN_SECTOR_MAP_V1` 取得同一不可变身份；standalone producer
显式声明相同 `SECTOR_MAP_ID`。

回归覆盖：

1. 三条 runtime lane 和 standalone producer 的十品种 frozen-map parity。
2. `bu + ru` source gross 超过 35% 时 fail closed，恰好 35% 时通过。
3. source、buffer、integer exposure 的十品种 golden parity。
4. 已完成签名目标的 persisted state 在迁移后只读兼容，不被重写。

因此此前可构造的 `bu=+20%`、`ru=+20%` source acceptance gap 已关闭。
外部签名 schema 仍保留 lane-specific 历史 ID，以避免无关 schema 迁移；
内部实际校验统一使用冻结 identity。该修复不改变 auto-dispatch 默认值、
SimNow 白名单、两阶段派单或 `production=false` 边界。

## 远端协作者仍需要什么

本次 lineage 封存合并后，协作者不再需要从本地研究机索取 C_FAST 五份原始
源码。继续完成真实闭环仍需要：

1. 带 receipt、独立 keyring 和 custody 的真实 PIT full-contract source view。
2. 每月 thermostat 所需的官方日收益输入，并纳入相同 receipt/custody 边界。
3. 对真实 sealed-export 运行两个 pure producer，取得可审计 golden 与 PnL。
4. 每月受控签名目标/snapshot；私钥只存在于受控本地环境，不进入仓库。

旧 curve-panel、回测输出或本地事件账本都不能替代第 1 项。

## 建议关键路径

1. 已完成：[#183](https://github.com/folgercn/vnpy-web-bridge/issues/183)
   / [PR #187](https://github.com/folgercn/vnpy-web-bridge/pull/187)
   恢复 sector-map parity。
2. 已完成：[#184](https://github.com/folgercn/vnpy-web-bridge/issues/184)
   / [PR #189](https://github.com/folgercn/vnpy-web-bridge/pull/189)
   补齐 D 与 STATIC_CORE_EQUAL composite pure producer。
3. 已完成：[#185](https://github.com/folgercn/vnpy-web-bridge/issues/185)
   / [PR #188](https://github.com/folgercn/vnpy-web-bridge/pull/188)
   补齐 thermostat snapshot pure producer。
4. 当前 P1：完成 Research Warehouse [#172](https://github.com/folgercn/vnpy-web-bridge/issues/172)
   的真实 M2 激活，并由 [#181](https://github.com/folgercn/vnpy-web-bridge/issues/181)
   受控调用真实 sealed-export。
5. 随后：写入 [#145](https://github.com/folgercn/vnpy-web-bridge/issues/145)
   证据账本，并完成 [#148](https://github.com/folgercn/vnpy-web-bridge/issues/148)
   / [#153](https://github.com/folgercn/vnpy-web-bridge/issues/153) 的真实
   SimNow PnL、成交概率与盘口冲击验收。

这些 producer 永久属于 Research Plane，不得持有 TradeService、RPC 或直接
下单能力。
