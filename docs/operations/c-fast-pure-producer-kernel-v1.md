# C_FAST 纯 Research producer kernel v1

## 1. 定位

本模块属于 **Research Plane**，只实现 Issue #163 的最小纯计算内核：

```text
未经 receipt/keyring/custody 验证的 PIT typed source view
        |
        v
确定性市场公式与整数分配
        |
        +-- 九个 role 的 canonical JSON bytes
        |
        `-- producer_projection_v1 分析摘要
                    |
                    |  不输出 #160 draft
                    v
           #171 独立 sealed-export 验证与重建
                    |
                    v
          production #160 unsigned draft
```

固定状态为：

```text
PURE_PRODUCER_KERNEL_ONLY_NOT_REAL_ARTIFACT
```

这表示代码和合成 golden 已可复核，但输出不自动成为真实 Research
artifact，更不产生 Control、Deployment 或 Execution authority。真实
execution-day 输入仍须由 #171 对 signed sealed-export receipt、exact raw
bytes、独立 keyring 与 custody 做完整验证。#163 不得把 typed view 中的
receipt SHA256 claim 当成已验证事实，也绝不产生 #160 signing input。

## 2. 文件

- 内核：
  `scripts/commodity_c_fast_pure_producer_kernel.py`
- typed source schema：
  `docs/schemas/commodity-c-fast-pit-frozen-source-view-v1.schema.json`
- golden、资源上限、raw-lot cap 与 #160 contract-separation 测试：
  `backend/tests/unit/test_commodity_c_fast_pure_producer_kernel.py`

内核只有一个公开生产入口：

```python
from commodity_c_fast_pure_producer_kernel import (
    produce_research_artifacts,
)

result = produce_research_artifacts(unverified_typed_source_view)
assert result.status == "PURE_PRODUCER_KERNEL_ONLY_NOT_REAL_ARTIFACT"
assert result.producer_projection["projection_type"] == "producer_projection_v1"
assert not hasattr(result, "unsigned_bundle_draft")
```

它只接收内存 mapping 或 bounded JSON bytes，并返回内存对象；不读取或写入
文件，不下载数据，不连接网络、数据库、Web Bridge、RPC 或交易相关服务。
`producer_projection_v1` 只包含 kernel/source identity、artifact roles 与
artifact SHA256 摘要；它不含 #160 schema/purpose/source-class、signer、
validity、authority 或可直接复制的 target contract。

## 3. typed source view

source view 必须符合 strict Draft 2020-12 schema，并满足内核的交叉检查。
`claimed_receipt_sha256` 只是待 #171 验证的 identity claim，不代表 receipt
signature、keyring、raw bytes 或 custody 已验证：

- `status=UNVERIFIED_PIT_TYPED_VIEW`；
- 固定十品种 `ag/al/au/bu/cu/rb/ru/sc/sp/zn`；
- 至少 127 个连续 typed official days 的逐日全合约视图；
- 每个品种、每个 official day 至少三个可用曲线合约；
- 每个来源绑定 source identity、query window、cutoff、generated-at、
  raw SHA256、lineage SHA256 和 claimed receipt SHA256；
- completed source-month 最后 official day 必须紧接下一月 execution day；
- execution day 后还必须有一个 following official day；
- official open 必须在 execution day 已观察，且时间不晚于 source view
  的 `generated_at`；
- reference contract、PIT OI main 和 contract spec 必须是同一 exact
  contract；
- contract multiplier 和 price tick 必须与 #160 冻结表一致；
- execution day 及 following official day 的 DTE 都必须至少为 11。

资源上限在 decode、逐行语义循环和多轮 sort/canonicalize 之前 fail closed：

- raw JSON bytes / canonical mapping 不超过 `16 MiB`；
- `official_days` 不超过 `512`；
- source bindings 不超过 `7`；
- 每个 product 的 daily rows 不超过 `512`；
- 每个 product/day 的 contracts 不超过 `64`；
- 全 source view 的 contract rows 不超过 `40,000`。

raw-byte API 会先检查 byte length 再 UTF-8/JSON decode；mapping API 会先做
浅层 collection-count preflight，再做一次受限 canonicalization。schema 的
`maxItems` 和 `x-vnpy-resource-limits` 与代码常量必须一致。

`MARKET_DAILY` binding 的 query end 不得越过
`research_as_of_official_day`。未来行、缺日、重复日、重复合约、来源
scope/class 不匹配、exact-contract splice、零波动和 unsafe DTE 都 fail
closed。

source schema 只表达未经签名/custody 验证的 typed view，不定义下载器、
官方端点解析器、源数据注册表、receipt verifier 或 custody writer；这些职责
不能塞进本纯内核。

## 4. 冻结计算

### 4.1 PIT OI exact contract

每个 product/day 仅使用当日 source view：

1. delivery month 严格晚于 source month；
2. settlement 与 OI 都为正有限数；
3. 按 `OI desc, delivery_yyyymm asc, exact_contract asc` 排序；
4. 第一名为 `DAILY_PIT_OI_MAIN`。

不允许查看未来 main chain。

### 4.2 roll-safe trend 与 vol60

相邻 official day 的收益使用前一日 PIT main 的同一 exact contract：

```text
r_t = log(settlement_t(old_main) / settlement_t-1(old_main))
```

如果当日 main 发生变化，新 main 只在当日锚定，不能把旧合约 settlement
与新合约 settlement 直接拼成收益。趋势为
`sign(log(I_t / I_t-h))`，`h=21/63/126`；三者等权得到
`source_score`。

`vol60` 使用最近 60 个 roll-safe log returns 的 sample standard
deviation（`ddof=1`）乘 `sqrt(252)`。实际波动率必须先为正有限数，不能
用 5% floor 挽救坏输入。bundle 中：

```text
raw_risk_score = source_score / max(vol60, 0.05)
```

### 4.3 self-financing source target 与 guardband

对固定十品种的 raw risk score：

1. 减去当日十品种算术均值；
2. 正负腿分别归一到 50% gross；
3. 依次施加 product 20%、sector gross 35%、portfolio gross 100%；
4. cap 后只缩较大腿恢复 net zero，不扩大较小腿。

guardband v2 再按 shrink-only 顺序施加 product 12%、sector gross 27%、
portfolio gross 80%，最后只缩较大腿恢复 net zero。

### 4.4 2,000 万 CNY 整数目标

单位权重为：

```text
official_open * multiplier / 20_000_000
```

整数分配固定使用 `FINITE_NEIGHBOURHOOD_BEAM_V1`：

- lot neighbourhood radius `2`；
- beam width `2048`；
- net error penalty `1`；
- 为兼容 #160 bundle schema，目标绝对手数上限为 `500`；
- 严格硬上限：product `<15%`、sector gross `<35%`、
  portfolio gross `<100%`、absolute net `<10%`；
- candidate 与最终 tie-break 均为确定性排序；
- 任一非零经济目标的 raw lot `abs(target_weight / unit_weight) > 500`
  时立即报错；禁止把候选集合裁成只剩 `0`，也禁止 clip 到 `500`；
- 只有 raw lots 全部位于该 frozen 兼容边界内，才允许进入有限邻域搜索；
- 无可行非零路径时只允许退回全零安全组合。

`500` 是现有 #160 `target_quantity` schema 的兼容边界，不是风险优化参数。
若未来 frozen allocator 的真实 raw lot 超过它，必须先独立升级 #160 schema、
freeze 与人工审查，不能由 #163 静默改变经济目标。

## 5. 九件 artifact

`result.artifacts` 的 key 固定为：

1. `freeze_contract`
2. `research_manifest`
3. `signal_evidence`
4. `target_evidence`
5. `allocation_evidence`
6. `daily_roll_evidence`
7. `reference_price_evidence`
8. `calendar_authority`
9. `contract_spec_evidence`

每个 value 都是无尾随换行的 canonical UTF-8 JSON bytes，九份必须非空且
字节互异。每份都绑定 normalized source view 的 canonical SHA256 和
`claimed_receipt_sha256`，但同时明确固定：

```text
research_evidence_only=true
source_receipt_signature_verified=false
source_receipt_keyring_verified=false
source_custody_verified=false
sealed_export_verified=false
control_authorized=false
deployment_authorized=false
execution_authorized=false
network_authorized=false
web_bridge_rpc_authorized=false
order_authorized=false
position_mutation_authorized=false
dispatch_authorized=false
trading_authorized=false
production_authorized=false
```

`research_manifest` 还保留全部 typed source bindings；signal、roll、
reference、calendar 和 spec artifacts 保留各自可复核字段。

## 6. #160 前的强制 #171 contract separation

本内核不返回 `unsigned_bundle_draft`，也不构造任何 #160
schema-shaped/near-complete payload。`producer_projection_v1` 与 #160
契约结构不同；即使调用方给它补上历史上用于降权的三个字段，也仍然没有
#160 schema、signer、validity 或 targets contract。这里依赖的是结构隔离，
不是给 near-complete draft 增加几个布尔/状态字段。

#171 必须从 verified facts 独立完成：

1. 验证 signed sealed-export receipt 的 schema、签名、TTL 与 replay；
2. 从独立 active pin 验证完整 keyring，不信任 typed view 自报 hash；
3. 从受保护 custody 重开 receipt 与九件 exact raw bytes；
4. 让九件 artifact 绑定已验证的 receipt raw/canonical identity、keyring 和
   custody identity；
5. 只从这些 verified receipt/raw/keyring/custody facts 和独立冻结规则重新
   构造 production #160 draft；
6. 把重新构造的 draft 交给 #160 public-check-first signer/verifier。

#171 不能原地修改或“升级” #163 返回的 projection，也不能从 projection
复制 target contract；必须重新读取、验证并解释 exact artifact bytes。本内核
不读取 receipt/keyring/custody，不调用 #160 prepare，不读取私钥，不签名，
也不执行 create-only install。#171 与 #160 的进一步 hardening 仍是独立
blocker。

## 7. Authority 与完成边界

本 PR 不改变 Authority：

- 不修改 Settings、API、adapter 或 runtime；
- 不产生 Acceptance、Deployment Authority 或 Execution Permit；
- 不访问账户、委托、成交或持仓；
- 不宣称 synthetic golden 是 execution-day 真实 evidence；
- 不改变 official-forward 或现有 shadow。

Issue #163 不能因纯内核合并而关闭。只有 #171 在真实 execution day 验证
signed sealed export、exact raw artifacts、独立 keyring 与 custody，并从
这些 verified facts 独立重建 production draft，随后通过 #160
signer/verifier 及后续 Acceptance，才可进入人工 Control review。

## 8. 验证

```bash
PY=/path/to/project/.venv/bin/python

$PY -m pytest -q \
  backend/tests/unit/test_commodity_c_fast_pure_producer_kernel.py
$PY -m pytest -q \
  backend/tests/unit/test_commodity_c_fast_simnow_research_bundle.py \
  backend/tests/unit/test_commodity_c_fast_simnow_research_acceptance.py
$PY -m ruff check \
  scripts/commodity_c_fast_pure_producer_kernel.py \
  backend/tests/unit/test_commodity_c_fast_pure_producer_kernel.py
$PY -m py_compile \
  scripts/commodity_c_fast_pure_producer_kernel.py
git diff --check
```
