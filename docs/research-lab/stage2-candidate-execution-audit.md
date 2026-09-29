# Issue #502 Stage 2: 候选执行与科学映射审计报告

> **权威状态声明**：首轮 20 槽位 Provider 生成/准入完成，但**真实科学验收仍处于 BLOCKED 状态**。
> 本报告仅包含合规的执行元数据，不包含原始 CSV 物理数据行或 Provider 私有明文日志。严禁虚构未保存的 Engine 结果。

逐槽位机器可读结果见 [`stage2-run-audit.json`](stage2-run-audit.json)；其中 `integration_evidence` 区分当前仅存的 Round 1 重建记录与未留存的 Round 2 集成记录。

## 一、快照物理特征与对账基线

- **代码基线**：PR #589 已合并，`main` 合并提交 `3b674d95c0c9b8e6168ac93fce5a2c3cf2bccada`；本报告记录的是其后一次探索性运行，不宣称通过 Stage 2 Gate。
- **快照文件定位**：`.git/issue502-stage2-real-data/rb-hc-2701-pit-screening-20260831-20260924.csv`
- **快照 SHA-256**：`4361c48f79345855457d633b962a3ea6975171242a770518c32d89945942624d`
- **数据规格**：19,489 字节，32 行记录，来源覆盖 19 个交易日（2026-08-31 至 2026-09-24，上期所 RB2701 与 HC2701 日结算数据）；筛选样本为其中 16 个日期 × 2 合约。
- **物理特征提供**：仅含单一收益标量列 `feature_val`（同合约日结算收益率）及时间戳审计列；**未提供** 成交量 (`volume`)、持仓量 (`open_interest`)、日内最高价 (`high`)、最低价 (`low`)、开盘价 (`open`) 或真实波幅 (`ATR`) 等特征。
- **来源与时间语义**：M2 Research Warehouse 的 SHFE/INE 日结算原始回执及 commit-ready manifest，经只读导出生成快照；19 个交易日的原始文件字节数和 SHA-256 与 manifest 对账一致。`feature_val=log(settlement_t/settlement_{t-1})`，`target_val=log(settlement_{t+2}/settlement_{t+1})`，均限于同一合约；每行保留 feature 可得时间、as-of 时间、target 起始时间及原始哈希。导出未独立验证 Warehouse 签名；历史首见时间包含回填，不能由此证明早期每一日实时可得。

## 二、首轮执行漏斗事实与数据库对账

1. **首轮执行（Run 1 / task-3415）标准输出漏斗事实**：
   - Round 1 的 10 个 Provider 槽位在 2026-09-29 12:02:03–12:04:40 CST 完成，Session `disc-session-d66`，受控 Memory A `memview-f7a5d2c7345502ddd`（0 条）；Round 2 的 10 槽在 12:06:23–12:09:27 CST 完成，Session `disc-session-761`，Memory B `memview-66cc3a7444d238423`。这些是桌面任务实际墙钟时间；下文另列脚本写入的错误 Session 时间。
   - **Round 1 Funnel**：Requested: 10 | Attempted: 10 | Admitted: 10 | Exact: 0 | Related: 0 | **Novel: 10** | Provider Failed: 0 | Invalid: 0
   - **Round 2 Funnel**：Requested: 10 | Attempted: 10 | Admitted: 10 | Exact: 0 | **Related: 1** | **Novel: 9** | Provider Failed: 0 | Invalid: 0
   - **记忆归因（Attributions）**：Total Citations: **21** | Conclusive: **0** | Inconclusive: **21** (Conclusive Rate: 0.0%)
2. **本地 ResultStore 真实对账状态**：
   - 首轮 20 槽位的 Provider 生成与准入确已完成；
   - 但在后续执行 Run 2 前，首轮 `artifacts/evidence_run_502_real_m2` 曾被清理重建；
   - 当前磁盘 SQLite 数据库仅依靠缓存重放保留了 **Round 1 的 20 条 memory records（10 假设 × 2 评审结论）与 60 条 run records（10 假设 × 6 筛选方法）**，**无可验的 Round 2 integration 结果**；
   - 此外，Run 2 启动时向 Provider 提交了额外的 Round 1 槽位 1 与 2（`task-e67af...` 与 `task-44b6b...`，后被取消停止），因此**不可声称全流程 replay zero submit**。
3. **PIT 时序合规审查**：
   - 首轮执行脚本中硬编码的会话时间（Round 1: `2026-09-22T05:00:00Z`，Round 2: `2026-09-22T05:30:00Z`）**早于物理快照的可用截至时间（`2026-09-24T10:40:15Z`）**，构成前瞻时间泄漏。
   - **科学验收判定**：**BLOCKED**。

## 三、逐槽位候选元数据与科学映射清单

| 轮次 | 槽位 | 任务 ID (可核完整 ID) | 状态 | 查重口径 | 候选标题 | 所需特征 (`source_features`) | 记忆引用数 | 快照支持状态 |
|---|---|---|---|---|---|---|---|---|
| R1 | 01 | `task-de9dbc43dd09b205dcdf4dafa206b6ae` | TURN_COMPLETE | NOVEL | Normalized Three-Day Price Mean Reversion on Ferrous Futures | `close, high, low` | 0 | **UNVERIFIED** |
| R1 | 02 | `task-61cf00a4169e1c86fb907e4e99c62fef` | TURN_COMPLETE | NOVEL | Daily range-normalized close location value reversal for RB and HC futures | `daily_close, daily_high, daily_low` | 0 | **UNVERIFIED** |
| R1 | 03 | `task-9f101f1cad9d44c1dff195b7fc33a33a` | TURN_COMPLETE | NOVEL | Five-Day Volatility-Normalized Price Reversal in Ferrous Futures | `close, daily_return` | 0 | **UNVERIFIED** |
| R1 | 04 | `task-8a8f5a5f152b0b4737d91035da4afc85` | TURN_COMPLETE | NOVEL | Daily Range-Expansion Short-Term Mean Reversion in Ferrous Futures | `close, open, high, low, average_true_range_20d` | 0 | **UNVERIFIED** |
| R1 | 05 | `task-08ccbac34b51230cf3df65e6b089f892` | TURN_COMPLETE | NOVEL | Volume-Conditioned 3-Day Normalized Price Reversal on Daily RB and HC Futures | `daily_close, daily_volume, ts_std_return_20d, ts_mean_volume_20d` | 0 | **UNVERIFIED** |
| R1 | 06 | `task-ce0b069ffb8af123221b902e86709ae2` | TURN_COMPLETE | NOVEL | Volume-Scaled Range Exhaustion Daily Reversal in Ferrous Futures | `close, high, low, volume` | 0 | **UNVERIFIED** |
| R1 | 07 | `task-f4eb4209539152a4c81c2beab783d633` | TURN_COMPLETE | NOVEL | Volume-Weighted Price Stretch Short-Term Reversal for RB and HC | `close, high, low, volume, open_interest` | 0 | **UNVERIFIED** |
| R1 | 08 | `task-e6434fe7724d4416e93cca43adf48f94` | TURN_COMPLETE | NOVEL | Open interest expansion scaled short-term price reversal for RB and HC | `daily_close, daily_high, daily_low, daily_open_interest, daily_volume` | 0 | **UNVERIFIED** |
| R1 | 09 | `task-ce0fc1d0ceb9e328588e5610cf307d16` | TURN_COMPLETE | NOVEL | Open Interest Weighted Short-Term Trend Momentum on Ferrous Futures | `daily_close, daily_open_interest` | 0 | **UNVERIFIED** |
| R1 | 10 | `task-877319191b17bdd7dde5391d6e1378f2` | TURN_COMPLETE | NOVEL | Volume-Conditioned Multi-Day Price Reversal for Ferrous Futures | `close, volume` | 0 | **UNVERIFIED** |
| R2 | 01 | `task-1dfce125170f4739b5d01b466575feb0` | TURN_COMPLETE | NOVEL | Volatility-Standardized Volume-Weighted 3-Day Short-Term Reversal Factor | `Close, High, Low, Volume` | 3 | **UNVERIFIED** |
| R2 | 02 | `task-80295259ec7753a155fdd853c869760e` | TURN_COMPLETE | NOVEL | Volatility-Normalized Short-Term Return Reversal for Ferrous Futures | `close, high, low, open, volume` | 2 | **UNVERIFIED** |
| R2 | 03 | `task-c69e9bd04ed43249e7fa28e867b49419` | TURN_COMPLETE | NOVEL | Normalized Short-Term Return Reversal with Volatility Scaling for Ferrous Futures | `close, high, low` | 2 | **UNVERIFIED** |
| R2 | 04 | `task-1142da91936432a9564b8d7866e8daa2` | TURN_COMPLETE | NOVEL | Standardized 3-Day Return Reversal with Volume-Expansion Conditioning on RB and HC Futures | `close, volume` | 2 | **UNVERIFIED** |
| R2 | 05 | `task-577e5b1f12b8123a1fa2d7955eec27ac` | TURN_COMPLETE | NOVEL | Volume-Weighted Range-Normalized 5-Day Reversal Factor | `close, high, low, volume` | 2 | **UNVERIFIED** |
| R2 | 06 | `task-6b524a457cd34ec4e33369151c383c0f` | TURN_COMPLETE | RELATED | Volatility-Adjusted Short-Term Mean Reversal with Volume Conditioning on RB and HC | `close, high, low, volume` | 2 | **UNVERIFIED** |
| R2 | 07 | `task-94e0e80acf7063d79ddbceda78fd4f98` | TURN_COMPLETE | NOVEL | Open Interest Conditioned Short-Term Price Deviation Reversal on Ferrous Futures | `close, open_interest, volume` | 2 | **UNVERIFIED** |
| R2 | 08 | `task-62b65faf5696a05056d302e9ed2946e5` | TURN_COMPLETE | NOVEL | Volume-Confirmed Volatility-Scaled 5-Day Momentum | `close, volume` | 2 | **UNVERIFIED** |
| R2 | 09 | `task-3bfab6daf5266b96536ba9ba024f214c` | TURN_COMPLETE | NOVEL | Open Interest Conditioned Residual Price Reversal in RB and HC | `close, high, low, open_interest, volume` | 2 | **UNVERIFIED** |
| R2 | 10 | `task-1e37dde6043a13b2875e0abd1e39cde6` | TURN_COMPLETE | NOVEL | Volatility-Normalized 5-Day Price Reversal on Steel Futures | `daily_close, daily_high, daily_low` | 2 | **UNVERIFIED** |

## 四、科学阻塞核心根因

1. **特征语义脱钩（科学映射断裂）**：
   - 20 个候选的信号定义均要求基于多列特征（如 `Volume`、`Open Interest`、`High/Low` 日内极值或 `ATR` 波动率）进行计算；
   - 当前筛选运行器由于缺乏表达式特征计算算子，仍直接对 CSV 中的单一 `feature_val`（结算收益率）计算相关性与符号一致性；
   - **结果**：计算出的统计数据并不代表模型所提出的经济假设，所有候选对当前快照的支持状态均为 **`UNVERIFIED`（0/20 匹配）**。
2. **Memory 对研究设定有可追溯的文本影响，科学进步尚未证明**：
   - Round 1 的 `agent-alpha-0028152eeb885c6c3064a6eb`（上表 R1/08）在当前 ResultStore 中记录 `REJECT`，缺少 `cost_sensitivity`；Critic 记录方向一致性 `0.3750 < 0.45`、分段稳定性衰减 `0.7580 >= 0.50`。该记录含 6 个 task/spec/run/evidence 引用，但这些筛选结果使用的单列特征与候选信号不匹配，数值不得作为该假设的有效科学证据。
   - Round 2/01 的 Provider 请求携带受控 Memory B；其响应通过 `source_context_refs` 引用该条目的 `rmentry-6101122fd66a54a382df49df`，在 `duplicate_awareness` 中明确提到上述两项阈值失败和成本敏感性缺口。新提案改用 ATR 标准化与成交量条件，并要求五折时间顺序方向一致性、样本内外稳定性及 0.5–1.5 bps 成本敏感性筛选。这证明了**提示上下文到提案与证据需求**的可见传递，不证明候选信号已在物理数据上得到验证。
   - 可核引用样例：R1/08 的一组 `task-plan-supp-agent-alpha-0028152eeb885c6c3064a6eb-rev.1-05614f99a76d-coverage-1c17d0f98981` → 同前缀 `spec-plan-supp-...` → `run-screening-ab485125b36844ac` → `manifest-run-screening-ab485125b36844ac` → `evidence-run-screening-ab485125b36844ac` → Critic `rev-54a092e96589b90d` → Memory B 上述 entry → R2/01 `task-1dfce125170f4739b5d01b466575feb0`。完整原始引用保存在本地私有 ResultStore 与 Provider 缓存，不将其筛选数值当成有效科学证据。
   - 两轮 10 个 Round 2 候选合计引用 21 条前序条目；既有归因字段为 `conclusive=0/21`。不将模型自述、字段差异或当前无效的 R1 统计结果写成科学改进或因果效果。
3. **解除阻塞的前置条件**：
   - 必须挂载具备完整行情列（OHLCV + OI）的宽表，并引入确定性特征计算算子；
   - 必须以 $T \ge 2026-09-24\text{T}10:40:16\text{Z}$ 的合法执行时间戳运行完整两轮集成并存盘；
   - 严格保持 `production=false`、`live_trading_authorized=false`、`countable_forward=false`、`official_forward_claimed=false`。
