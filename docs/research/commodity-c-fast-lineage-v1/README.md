# C_FAST v1 原始研究 lineage 封存

本目录把本地研究机上与 `C_FAST_CROSS_SECTION_NEUTRAL` 纯 Research
producer kernel 直接绑定的五份原始研究源码、对应测试快照，以及
`commodity_fast_tsmom_forward_freeze_v1` 冻结文件做逐字节封存。

## Architecture Impact

- Plane：Research Plane。
- Authority：无变化，全部显式为 `false`。
- Execution：无影响，不接触 RPC、Gateway、订单或持仓。
- Failure mode：任一文件、哈希、冻结身份或权限字段不一致即 fail closed。

## 用途

- 让协作者不依赖本地研究机即可核对当前 producer kernel 声明的五个源码
  SHA256。
- 保存冻结规则、forward 边界和 result-blind 权限边界的原始证据。
- 为后续独立重放、差异审计和 sealed-export 验收提供稳定 provenance。

同仓库消费者是 `scripts/commodity_c_fast_pure_producer_kernel.py`。本次以
`main@d2ea96b514b0a43f02a211a463487ca4ce41f609` 为审计基准；其中
`LINEAGE` 五个 SHA256 与本目录 `sources/` 五份源码逐项一致。manifest
还固定 consumer 完整源码 SHA256，以及 PR
[#187](https://github.com/folgercn/vnpy-web-bridge/pull/187) 合并后的
`COMMODITY_FROZEN_SECTOR_MAP_V1` 身份和十品种映射哈希；任一漂移都会
fail closed。

SHA256 一致只证明 producer kernel 明确绑定了这些原始研究源码的身份，不
表示两者逐字节相同。producer kernel 是面向严格 typed source view 的独立、
自包含移植，仍须通过自身 golden、sealed-export 和真实数据验收。

## 目录

- `sources/`：producer kernel `LINEAGE` 直接绑定的五份源码快照。
- `tests/`：上述源码在原研究树中的测试快照。
- `freeze/`：C_FAST forward freeze 合同、manifest、隔离 receipt、采集模板和报告。
- `bundle_manifest.json`：文件大小、SHA256、原始相对路径与同仓库 consumer 映射。

离线校验：

```bash
python scripts/commodity_c_fast_lineage_verify.py
```

主候选是否已经能由远端代码独立再生，见
[STATIC_CORE_EQUAL 远端完备性审计](../static-core-equal-remote-completeness-audit-20260729.md)。

## 边界

本包不是可交易策略包，也不是历史回测的完整可执行环境：

- 不包含商品原始行情、旧事件账本、PnL、账户、密钥或签名目标批次。
- 不授予 acquisition、network、shadow、SimNow、dispatch、live 或 production authority。
- `sources/` 和 `tests/` 保持原研究树的 import/path 语义，仅作为审计快照；
  不从此目录直接运行历史测试。
- freeze manifest 中引用但不属于 producer kernel 五项 `LINEAGE` 的历史
  runner、研究面板和结果文件未纳入本次最小封存。完整历史重放仍需按
  freeze manifest 的 SHA256 另行取得这些依赖和相应官方行情。
- 旧 curve-panel CSV 未收录；它不能替代带 receipt/custody 的真实 PIT
  source view。

本目录不能把历史研究输出升级为真实 Research artifact，也不能绕过
Acceptance、人工签署或 Execution Permit。
