# STATIC_CORE_EQUAL 纯 Research producer v1

## 1. 完成边界

本模块只补齐 `STATIC_CORE_EQUAL` 的 code-only Research producer：

```text
未经 receipt/keyring/custody 验证的 PIT OHLC typed source view
        |
        +-- C_FAST_CROSS_SECTION_NEUTRAL
        |
        +-- D_DONCHIAN20_EXIT10_NEUTRAL
        |
        v
逐品种 50%C + 50%D contribution 净额
        |
        v
source caps -> guardband v2 -> 20m integer beam
        |
        v
九件 canonical Research Evidence
```

输出状态固定为：

```text
PURE_RESEARCH_PRODUCER_ONLY_NOT_REAL_ARTIFACT
```

合成测试 golden 只证明代码确定性，不是真实 execution-day forward evidence。
真实 sealed source、signed receipt、独立 keyring 和 custody 必须先通过
Issue #181 已提供的边界验证；本 producer 不下载数据，也不能把 typed view 中自报的 receipt SHA256
升级成可信事实。

## 2. Architecture Impact

- Plane：Research Plane。
- Authority：只新增未验真的 Research Evidence 计算能力；不新增
  Acceptance、Deployment Authority 或 Execution Permit。
- Execution impact：无。模块不导入 backend runtime、vn.py、TradeService、
  Gateway、RPC、订单或持仓模块。
- Production impact：无。所有 authority 字段固定为 `false`。

## 3. 文件

- D 与组合冻结公式：
  `scripts/commodity_static_core_equal_formula_v1.py`
- 纯 producer 与独立 verifier：
  `scripts/commodity_static_core_equal_pure_producer.py`
- strict typed source schema：
  `docs/schemas/commodity-static-core-equal-pit-ohlc-source-view-v1.schema.json`
- synthetic golden 与失败路径：
  `backend/tests/unit/test_commodity_static_core_equal_pure_producer.py`

旧的 C_FAST source schema 只有 settlement/OI，不能计算 Donchian 的
previous-high/low。因此新增独立的 OHLC schema，不扩宽或改变既有 C_FAST
schema；producer 会先严格验证 OHLC，再投影出原 C schema 交给已经冻结的
C kernel。

## 4. 严格 PIT 输入

source view 继承 C_FAST pure kernel 的资源与因果边界：

- 固定十品种和冻结 sector map；
- 完成的 source month 最后一交易日只能生成下一 official execution day
  的目标；
- market query 不得越过 source official day；
- 每个品种逐日覆盖完整 official-day warmup；
- 每日每品种至少三个完整曲线合约；
- PIT main 只按当日 `OI desc, delivery asc, exact contract asc` 选择；
- execution reference/spec 必须与 source-day PIT main 为同一 exact contract；
- DTE 必须在 execution day 和 following official day 均至少为 11；
- OHLC 必须正有限，且 `low <= open/settlement <= high`；
- raw bytes、calendar、binding、daily row、contract row 均有硬资源上限。

任何字段缺失、额外字段、未来日、contract splice、非法 OHLC、零波动、
unsafe DTE 或代码身份漂移都会 fail closed。

`ProducerResult.source_view_canonical` 会保留通过严格 schema 归一化后的
canonical source bytes。public verifier 先核对该 bytes 的资源上限和
SHA256，再用同一 source 与已固定的 C/D 代码完整重放九件 artifact 和
projection，并逐字节比较。因此仅协调修改多个 output artifact、重算其
digest，不能伪造另一条自洽证据链。source 本身的签名、receipt、custody
和 sealed-export authority 仍不由此 producer 验证，继续由 #181 边界
提供。

receipt/custody 只证明 bytes 身份，不能替代领域 schema。producer 会在调用
冻结 C kernel normalization 前，拒绝 ID、日期、哈希、OHLC、OI、reference
和 contract-spec 中所有与本页 source schema primitive type 不一致的值；
禁止把字符串或 bool 静默转换为数值。

## 5. D_DONCHIAN20_EXIT10_NEUTRAL

D 的 exact contract 固定为：

1. 用当日 PIT OI main 构造 roll-safe synthetic OHLC；
2. 换主力当天仍用旧 main 关闭当天 interval，新 main 只为下一 official
   day 重置价格尺度；
3. 先执行 exit：多头 settlement 严格低于 previous-10 low 时归零，空头
   settlement 严格高于 previous-10 high 时归零；
4. 再执行 entry：settlement 严格高于 previous-20 high 时为 `+1`，严格
   低于 previous-20 low 时为 `-1`；
5. `vol60` 使用 roll-safe settlement log return、`ddof=1`、年化 252；
6. raw risk score 固定为 `state / max(vol60, 0.05)`；
7. 截面去均值、双腿各 50% gross，再按 product 20%、sector 35%、gross
   100% shrink-only 和 net-zero 约束生成 D source target。

producer 在计算前同时固定校验 C kernel 和 D formula source bytes 的
SHA256。任一算法代码变化都要求显式更新 freeze 与 golden，不能静默沿用
旧身份。

## 6. C/D 产品级净额、guardband 与整数目标

每个 product 明示保留：

```text
C_raw_contribution = 0.5 * C_source_target_weight
D_raw_contribution = 0.5 * D_source_target_weight
raw_combined_weight = C_raw_contribution + D_raw_contribution
```

然后只对单账户产品级净额依次执行：

1. source product 20%、sector gross 35%、portfolio gross 100%；
2. 只缩较大腿恢复 net zero，不重新加杠杆；
3. guardband v2：product 12%、sector gross 27%、gross 80%；
4. 再只缩较大腿恢复 net zero；
5. 按 execution-day official open、冻结 multiplier 和 20,000,000 CNY
   虚拟 NAV 计算单位权重；
6. 使用 `FINITE_NEIGHBOURHOOD_BEAM_V1`，radius 2、beam 2048、
   net penalty 1、absolute lot cap 500；
7. 最终严格约束为 product `<15%`、sector gross `<35%`、gross `<100%`、
   `abs(net)<10%`。

若每个产品的所有非零 lot 都已被严格 product cap 排除，deterministic
结果固定为全零，并写入：

```text
allocation_status=NO_FEASIBLE_PRODUCT_NONZERO_SAFE_ZERO
```

禁止 clip、伪造可成交手数或把 safe-zero 表述成有效非零组合。

## 7. 九件 artifact 与验证

固定生成：

1. `freeze_contract`
2. `research_manifest`
3. `signal_evidence`
4. `target_evidence`
5. `allocation_evidence`
6. `daily_roll_evidence`
7. `reference_price_evidence`
8. `calendar_authority`
9. `contract_spec_evidence`

每件均为无尾随换行的 canonical JSON bytes，绑定完整 OHLC source identity、
派生 C source identity、C/D code identity 和全部 authority-false literals。
`verify_research_artifacts()` 会重新检查 role、canonical bytes、代码身份、
authority、artifact digest、buffered target identity 和 target/allocation
quantity 一致性；缺件、改字节或跨 artifact splice 均拒绝。

## 8. 验证

```bash
PY=/path/to/project/.venv/bin/python

$PY -m pytest -q \
  backend/tests/unit/test_commodity_static_core_equal_pure_producer.py
$PY -m pytest -q \
  backend/tests/unit/test_commodity_c_fast_pure_producer_kernel.py \
  backend/tests/unit/test_commodity_static_core_equal_pure_producer.py
$PY -m ruff check \
  scripts/commodity_static_core_equal_formula_v1.py \
  scripts/commodity_static_core_equal_pure_producer.py \
  backend/tests/unit/test_commodity_static_core_equal_pure_producer.py
$PY -m py_compile \
  scripts/commodity_static_core_equal_formula_v1.py \
  scripts/commodity_static_core_equal_pure_producer.py
git diff --check
```
