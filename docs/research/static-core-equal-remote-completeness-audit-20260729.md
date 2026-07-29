# STATIC_CORE_EQUAL 远端算法与参数完备性审计（2026-07-29）

## 结论

审计基准：`main@4e16dfe69e58b1110c5e8b379f5e7fb26eaaf487`。

结论为：

```text
EXECUTION_CONSUMER_COMPLETE_ENOUGH
RESEARCH_REPRODUCTION_INCOMPLETE
FROZEN_SECTOR_MAP_PARITY_FAILED
```

当前 `main` 已能安全消费研究侧签名的 `STATIC_CORE_EQUAL` 整数目标，并完成
SimNow 两阶段派单、换月、对账和执行质量记录；但不能只依靠远端代码从官方
行情独立再生原主候选。这个区别符合 Execution Plane 不依赖研究实现的架构
原则，但意味着仍需在 Research Plane 补齐 producer，不能把现有控制器描述为
“完整策略算法已上远端”。

## 逐项审计

| 能力 | 远端 `main` | 判断 |
|---|---|---|
| scheduler 身份、十品种、月频、20m NAV | schema/service 中固定 | 完整 |
| `50%C + 50%D` 权重元数据 | 批次验签后固定校验 | 完整 |
| guardband `12%/27%/80%/0` | 批次和仓位管理均校验 | 参数完整，但主策略 sector map 有偏差 |
| beam allocator `radius=2/width=2048/net penalty=1` | schema Literal 固定 | 参数完整 |
| beam 整数最优化重算 | 不重算；消费签名手数并校验硬上限 | 缺失 |
| C_FAST 信号 producer | 独立 pure producer kernel 已存在 | C 腿完整，但未生成主组合 |
| D Donchian20/exit10 producer | 仓库无 `D_DONCHIAN20_EXIT10_NEUTRAL` 实现 | 缺失 |
| C+D 单账户产品级净额 | 只校验组合字段和风险上限 | 缺失 |
| PIT OI 主力选择 | 控制器消费签名 exact contract | Research producer 缺失 |
| 换月、两阶段派单、持仓对账 | 控制器完整实现 | 完整 |
| 相对波动 thermostat 公式 | 21/126、0.8–1.2、alpha 0.5 均硬校验 | 参数完整 |
| thermostat 波动率与目标生成 | 消费签名 snapshot，不从官方日线重算 | 缺失 |

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

## 未上远端的算法链

### D 腿缺失

仓库中不存在 `D_DONCHIAN20_EXIT10_NEUTRAL` 或对应 Donchian20/exit10
producer。`candidate_weights={C:0.5,D:0.5}` 只是已签名批次的身份元数据，
不能证明 D 信号、退出状态或逐品种目标由冻结算法产生。

### 组合与整数分配只验结果

`CommoditySimNowService` 校验：

- 签名；
- 固定权重和 allocator 参数；
- source/buffered weights 上限及净额；
- 目标手数方向、合约规格、绝对手数和整数敞口硬上限。

它不重算 C/D sleeve、不执行产品级净额，也不运行 beam optimizer。这是正确
的 Execution/Control 边界，但对应的 Research producer 当前不在仓库。

### 仓位管理只验 snapshot

服务会根据快照中的 `fast_annual_vol`、`slow_annual_vol` 重算 raw/smoothed
scale，并重算 guardband；但不会从官方日收益生成 21/126 日波动，也不会对
shadow 手数运行冻结整数 optimizer。

## P0：sector map 与本地冻结规则不一致

原冻结研究使用：

```text
bu -> energy_chemical
ru -> energy_chemical
sp -> light_industry
```

仓位管理 shadow 已通过 `POSITION_MANAGER_SECTOR_MAP_V1` 使用上述映射。

主策略批次和实时敞口校验使用的 `PRODUCT_SPECS` 却是：

```text
bu -> energy
ru -> chemicals
sp -> agriculture
```

这会把本应合并计算的 `bu + ru` 板块风险拆开，使三层 sector-cap 身份与
冻结研究不一致。可实际构造的接受差异发生在 source 35% cap：例如
`bu=+20%`、`ru=+20%`，再用两个其他板块各 `-20%` 恢复净额零；当前远端
映射会让每个板块都不超过 20%，原冻结映射则应把 `bu+ru=40%` 判为超限。

buffer 与 integer 层虽然分类身份也不同，但在当前十品种中，`bu/ru` 各自的
12% buffer product cap 和 `<15%` integer product cap 会把两者合计分别限制
在 24% 和 `<30%`，数值上已经低于对应 27%/35% sector cap；因此本次没有把
它误报为可直接放大的成交风险。问题仍会破坏 source target 的冻结算法 parity。

在修复前，不应声称主候选已经实现冻结参数的全链路 parity。修复必须单独开
Issue/PR，并补：

1. 主策略、position manager、C_FAST producer 共用同一个冻结 sector-map 身份。
2. `bu + ru` source weights 联合越过 35% 时 fail closed 的 failure-path 测试。
3. 十品种 source、buffer、integer exposure 的本地冻结 golden parity。
4. 已有签名目标在新映射下的兼容性审计。

该修复会影响 Execution Plane 的批次接受语义，不能在本 Research-only PR
中顺手修改。

## 远端协作者仍需要什么

本次 lineage 封存合并后，协作者不再需要从本地研究机索取 C_FAST 五份原始
源码。继续完成真实闭环仍需要：

1. 带 receipt、独立 keyring 和 custody 的真实 PIT full-contract source view。
2. D Donchian20/exit10 的冻结 Research producer。
3. `C + D -> product-level netting -> guardband -> integer allocator` 的纯
   Research producer 与 golden。
4. thermostat 的官方日收益输入、21/126 波动和整数 snapshot producer。
5. 每月受控签名目标/snapshot；私钥只存在于受控本地环境，不进入仓库。

旧 curve-panel、回测输出或本地事件账本都不能替代第 1 项。

## 建议关键路径

1. P0：[#183](https://github.com/folgercn/vnpy-web-bridge/issues/183)
   单独修复 sector-map parity。
2. P1：[#184](https://github.com/folgercn/vnpy-web-bridge/issues/184)
   补 D 与 STATIC_CORE_EQUAL composite pure producer。
3. P1：[#185](https://github.com/folgercn/vnpy-web-bridge/issues/185)
   补 thermostat snapshot pure producer。
4. P1：用真实 sealed-export 输入完成独立重放和 SimNow PnL/成交验收。

这些 producer 永久属于 Research Plane，不得持有 TradeService、RPC 或直接
下单能力。
