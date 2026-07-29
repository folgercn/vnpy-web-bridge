# MONTHLY_RELATIVE_VOL_THERMOSTAT_V1 纯 Research producer

本工具属于 Research Plane，只把一个严格有界的 PIT source view 转换为：

1. 缺少 `signature` 的 `commodity_relative_vol_position_manager_shadow_v2`
   draft；
2. 独立的、全部 Authority=false 的 producer evidence。

它不获取数据、不验证 source receipt/custody、不持有私钥、不签名、不安装
snapshot，也不连接 Trade、RPC、Gateway 或订单接口。真实 sealed daily-return
输入及其 source authority 仍由 #171/#181 边界提供；producer evidence 会明确写
`sealed_source_view_verified_by_producer=false` 和
`daily_return_source_authority_verified_by_producer=false`。

## 输入合同

输入必须通过
[`commodity-relative-vol-position-manager-source-view-v1.schema.json`](../schemas/commodity-relative-vol-position-manager-source-view-v1.schema.json)。
核心约束如下：

- baseline 必须是完整的 `commodity_static_core_equal_target_batch_v2`；
- producer 只重算与现有 verifier 相同的 unsigned canonical payload SHA256，
  并核对 `baseline_batch_hash`，不验证 Ed25519 签名；
- official day 和 baseline daily return 必须逐日一一对应、严格递增且恰好
  126 行；所有日期必须不晚于 source month 截止日并严格早于执行日；
- `cutoff_at` 必须落在 source month 最后一个自然日，
  `generated_at` 必须落在 baseline execution day；
- baseline source target、guardband 和冻结 20m beam allocator 必须可独立
  重放，任一 buffered weight 或整数手数不一致即拒绝；
- 正式 genesis 只允许 `source_month=2026-08`、无 previous snapshot；
- linked 必须携带完整上一期签名 snapshot 和声明 hash。producer 重算
  previous unsigned canonical hash，并核对相邻月份及 previous smoothed scale；
- SimNow shakedown 使用隔离 genesis，不读取或推进正式连续性链。

baseline/previous snapshot 的签名字节只做 base64 及 64-byte 形状检查。输入边界
必须在调用 producer 前完成真实签名、receipt、keyring 和 custody 验证。

## 冻结计算

波动率采用严格滞后收益：

```text
fast_annual_vol = sample_std(last_21_returns, ddof=1) * sqrt(252)
slow_annual_vol = sample_std(last_126_returns, ddof=1) * sqrt(252)
raw_scale = clip(sqrt(slow_annual_vol / fast_annual_vol), 0.8, 1.2)
smoothed_scale = clip(
  0.5 * raw_scale + 0.5 * previous_smoothed_scale,
  0.8,
  1.2
)
```

baseline 与 shadow 都重新执行冻结 guardband：

- 产品 12%；
- 板块 gross 27%；
- 组合 gross 80%；
- shrink-only 净额归零。

之后使用 20m 虚拟 NAV、
`FINITE_NEIGHBOURHOOD_BEAM_V1(radius=2, beam=2048, net_penalty=1.0)`
分别生成 baseline/shadow 整数目标。baseline 重算结果必须与输入签名批次的手数
逐品种一致。

## 运行

```bash
PYTHONPATH=backend python scripts/commodity_relative_vol_snapshot_producer.py \
  --input /path/to/sealed-and-verified-source-view.json \
  --snapshot-output /path/to/unsigned-position-manager-shadow.json \
  --evidence-output /path/to/position-manager-producer-evidence.json
```

输出路径必须不存在，工具拒绝覆盖既有 evidence。上述命令不会签名或安装
snapshot。完成独立 source 审核后，人工受控签名仍使用既有工具：

```bash
PYTHONPATH=backend python scripts/commodity_position_manager_shadow_sign.py \
  --input /path/to/unsigned-position-manager-shadow.json \
  --output /path/to/signed-position-manager-shadow.json \
  --private-key-file /path/to/controlled-ed25519-private-key
```

签名成功仍不授予 Acceptance、Deployment 或 Execution Authority；Web Bridge
消费端继续执行自己的 Ed25519、公式、连续性、baseline link、guardband 与整数
敞口校验。

## Fail-closed 条件

下列任一情况都不会生成输出：

- 未来日、少于或多于 126 行、官方日与收益不对齐；
- 零波动、NaN、Infinity、非法日期或重复 JSON key；
- baseline canonical hash、guardband、合约规格或整数 allocator 不一致；
- linked previous hash、月份或 previous scale 断裂；
- 冻结产品、sector map、NAV、lookback、scale 或 smoothing identity 变化；
- 输入超过 4 MiB、输出路径已存在。

producer evidence 不可作为签名 baseline 已验收的证明：
`baseline_batch_hash_validation` 固定为
`CANONICAL_UNSIGNED_PAYLOAD_HASH_MATCH_ONLY`。
