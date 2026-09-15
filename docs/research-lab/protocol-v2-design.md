# AI Quant Research Lab 统一研究协议设计草案 (Protocol v2)

> **文档元数据**
> - **关联 Issue**: [#538](https://github.com/folgercn/vnpy-web-bridge/issues/538) (Phase 0: Research Protocol Foundation), [#498](https://github.com/folgercn/vnpy-web-bridge/issues/498) (唯一协议设计入口), [#497](https://github.com/folgercn/vnpy-web-bridge/issues/497)
> - **协议状态**: `DRAFT_UNFROZEN` (语义设计与候选字段走查草案，待主控与人工确认评审后正式冻结)
> - **设计约束**: 本阶段仅完成语义定义与样例走查，消除 Agent 沟通歧义；不等于设计已终审验收，更不宣称关闭 #538 或 #498。禁止提前实现 Worker Runtime、Task Queue、Research Farm、Astra 自动发现或 Sol 调度系统。

本轮四项冻结缺口的精确候选规则见 [Freeze Gap Closure](protocol-v2-freeze-gap-closure.md)：Hash、Evidence/Review、研究阶段和 Revision/Run。保持草案，待 #498 最终审查。

---

## 1. 架构定位与设计背景

### 1.1 背景与设计定位
在量化研究系统（AI Quant Research Lab）演进中，若早期缺乏统一、强约束的研究协议，不同自动化组件容易将“策略回测配置”、“数据清洗任务”与“纯统计推断”混淆，导致系统模型退化为单一的“买入持有回测脚本”。

依据 GitHub Issue [#538](https://github.com/folgercn/vnpy-web-bridge/issues/538) 及 [#498](https://github.com/folgercn/vnpy-web-bridge/issues/498) 的路线图门禁（Roadmap Gate）要求：
1. **#498 是当前唯一协议设计入口**：所有下游规范（#511 Experiment Schema、#523 Agent Prompt Contract、#524 Artifact Standard）必须对齐本协议定义；
2. **先语义设计，经人工确认后才冻结**：当前阶段不进入底层执行层开发，杜绝过度工程化；
3. **三类根研究类型化**：量化研究涵盖数据质量审计（`data_quality`）、因子统计推断（`statistical_factor`）与交易回测（`trading_backtest`）。期货回测仅作为 `trading_backtest` 根大类下的专属 Profile，而非独立根类型。

### 1.2 外部设计输入与原则参考
本设计吸收 GitHub Issue [#497](https://github.com/folgercn/vnpy-web-bridge/issues/497) 讨论中梳理的核心原则作为设计输入，不引入外部系统运行时依赖：
- **逻辑任务、执行实例与数据切片解耦**：参考 [OpenLineage 对象模型规范](https://openlineage.io/docs/spec/object-model/) 关于 Job、Run 与 Dataset 的正交解耦原则；
- **时序验证边界与防泄漏原则**：参考 [Scikit-learn 验证边界说明](https://scikit-learn.org/stable/common_pitfalls.html) 关于防范时序数据穿越与预处理严格隔离在训练集拟合的原则；
- **多重检验与过拟合防范**：参考量化研究关于多重假设检验数据窥探偏差的理论讨论，在协议中客观记录试验探索轨迹，供适用评估方法核验。

---

## 2. 核心对象模型、修订版本与哈希引用链

### 2.1 核心对象职责与版本定义
协议严格解耦两套独立版本体系，消除身份引用歧义：
- **Schema 规范命名空间（`schema_version`）**：定义数据结构模式契约，由代码库统一发布，如 `research_lab.task.v2`、`research_lab.experiment.v2`；
- **实体修订号（`revision`）**：定义具体研究对象在业务演化中的不可变修订版本，由业务实体维护，如 `rev.1`、`rev.2`。
- **不可变原则**：同一 `(id, revision)` 不可篡改任何已有内容。若假设、方法或参数发生任何语义改动，必须发布全新的 `revision`。

#### 核心对象职责对照表

| 核心对象 | 核心问题 | 核心包含内容 | 边界禁止与留空原则 |
| :--- | :--- | :--- | :--- |
| **`ResearchTask`** | 为什么研究？验证什么？ | 科学/业务问题、研究目标（`objective`）、背景来源、预期证据类型、逻辑数据需求声明（标的、周期、字段、时序可得性约束） | **绝不包含物理文件路径**、主机节点、随机种子或物理执行参数；数据审计任务无需硬凑先验假设。 |
| **`ExperimentSpec`** | 准备如何验证？具备何种规格？ | 类型化方法引用、候选判据声明（`candidate_decision_criteria`）、逻辑数据提供者要求、时序验证与防泄漏切分规则、交易成本与撮合模型 | 严格 `extra="forbid"`，拒绝未知输入；纯统计不含回测参数；随机种子作为候选提议（`seed_proposal`）。 |
| **`ExperimentRun`** | 实际执行了什么？在何种环境下？ | 实际加载的数据集快照、已展开生效参数与默认值、执行代码版本与未跟踪源码差异、实际随机种子、运行环境指纹 | **所有计算输入在执行前锁定**；未物理执行或执行失败时，未解析字段严格保留为 `null` 并注明原因；记录客观运行事实，不评价证据优劣。 |
| **`ResultEvidence`** | 产出了什么证据？结果如何？ | 物理计算事实指标（Typed Metrics）、度量元信息（单位、样本量、成本口径）、事实性诊断、工件引用清单 | **真实物理 Evidence 仅绑定终态 Run**；未执行/不可算为 null，合法零值如实记录；**所有评价均在顶层外部 Review 集合追加，严禁覆写计算事实**。 |

### 2.2 逐层强哈希绑定与排除规则
四个核心对象通过实体标识、修订号与终态哈希形成不可变引用链：

```text
       Research Task (task_id, revision)
                     ↓ [Spec 显式引用 task_id, task_revision, task_content_hash]
       Experiment Spec (spec_id, revision)
                     ↓ [Run 显式引用 spec_id, spec_revision, spec_content_hash]
       Experiment Run (run_id, run_status, run_content_hash)
                     ↓ [Evidence 显式引用 run_id, run_status_snapshot, run_content_hash]
       Result Evidence (evidence_id, evidence_content_hash)
```

**哈希计算排除规则**：
- 计算对象的 `content_hash` 时，**仅排除当前记录自身的摘要字段本身**（如计算 Task 哈希仅排除自身 `task_content_hash`）；
- **绝对不可排除上游引用哈希**：上游的 `task_content_hash`、`spec_content_hash` 属于当前对象的不可变输入，必须纳入当前对象的哈希计算；
- 在 Phase 0 草案走查阶段，所有 content hash 字段显式保留为 `null` 并附带未绑定原因说明，绝不编造虚假哈希。

### 2.3 Run 状态机、终态快照与 Evidence 模板定位
1. **Run 生命周期状态**：`NOT_DISPATCHED` -> `PENDING` -> `RUNNING` -> `COMPLETED` / `FAILED`；
2. **终态快照固化**：在运行执行期间（`RUNNING`），中间日志与心跳不构成终态事实。只有当 Run 达到终态（`COMPLETED` 或 `FAILED`）时，实际加载的数据集摘要、生效随机种子、工作区代码差异指纹与执行时间戳完全固化，生成不可变的 `run_content_hash`；
3. **Evidence 模板定位与状态一致性**：
   - 走查样例中的 `ResultEvidence` 仅作为字段与结构展示模板（`template_purpose: candidate_evidence_structure_walkthrough_only`）；
   - `NOT_DISPATCHED` 的 Run **绝对不得被误读为已有真实物理 Evidence 产出**；
   - `run_status_snapshot` 必须与 Run 的 `run_status` 严格保持一致。

### 2.4 独立评审结论追加机制（Append-Only Top-Level Reviews）
所有初始/后续评价均在 Review；版本、判据引用、精确证据绑定与不可变规则见 [Gap Closure §2](protocol-v2-freeze-gap-closure.md#2-evidence-与-review)。
- 评审记录（`review_assessments`）位于与实验对象同级的**顶层外部集合**，避免作为内部字段追加时导致原始 `ResultEvidence` 的 content hash 发生改变；
- 评审记录严格引用 `evidence_id` 与 `evidence_content_hash`；
- 评审人记录审核意见（`recommendation`: `accept` | `improve` | `reject`）、适用市场范围与裁定理由；
- **严禁评审覆写计算事实**：评审动作仅能向外部集合追加独立见解，绝不允许修改原始 `ResultEvidence` 中已记录的度量数值、执行状态或工件哈希。

---

## 3. 多重检验追踪、试验上下文与科学指纹

### 3.1 多重检验追踪、试验上下文与判据边界
为使 Deflated Sharpe Ratio (DSR)、PBO 或 Bonferroni 校正具备真实依据，协议在试验上下文中确立最小归属元数据：
1. **假设族归属（`hypothesis_family_id`）**：声明该试验所属的研究假设族/探索空间（如 `hf-commodity-carry-v1`）；
2. **尝试方式（`trial_kind`）**，与 Spec 的 `research_stage`（exploration / validation / confirmation）分离；阶段和预登记规则见 [Gap Closure §3](protocol-v2-freeze-gap-closure.md#3-research-stage-与搜索方式分离)：
   - `parameter_search`：新参数组合尝试，计入多重检验自由度消耗；
   - `replicate_reseed` / `replicate_refold`：固定参数下的随机种子或折数重复，用于评估方差与稳定性；**若研究者事后仅挑取最佳结果汇报，则同样引入选择偏差，协议中立记录所有轨迹，不替上层武断定性**；
   - `technical_retry`：技术重试，不计入参数探索；
3. **试验序号（`trial_index`）**：未执行时严格为 `null`，严禁在草案期凭空编造虚假试验序号；
4. **候选判据位置**：预先确定的决策判据定义在 `ExperimentSpec.candidate_decision_criteria`，属于预先声明的验收目标；`ExperimentRun` 仅记录实际运行结果，不侵入判据定义；
5. **封存集使用记录（`holdout_usage_state`）**：涉及 holdout 但未实证时必须为 `null` 或 `"unknown"`；无假设且不使用 holdout 的 data_quality 审计明确为 `"not_applicable"`，不得用于规避已有 holdout 检验；Holdout 状态必须绑定底层数据集哈希、时间范围以及**跨 Task/Spec 假设族的使用历史记录**，换了任务或规格 ID 绝不能重置封存集的消耗计数。

### 3.2 技术重试（Technical Retry）的严格边界
- **必要条件**：针对技术失败/中断，必须保持**完全相同的 `(spec_id, spec_revision, spec_content_hash)`** 与**完全相同的科学计算输入指纹**；参数、种子、代码或数据的任何更改，均属于新科学配置，严禁标记为技术重试；
- **引用与幂等要求**：技术重试生成全新的独立 `run_id`，并记录 `retry_of_run_id: "<prior_run_id>"`；重复结果不重复计数，迟到结果不得覆盖另一 run。

### 3.3 按研究类型覆盖科学计算指纹（Scientific Fingerprint）
科学计算指纹核心绑定：
1. **实际执行代码版本 + 源码差异指纹**：Git commit hash 加上包含未跟踪源码差异的 `source_diff_fingerprint`（杜绝未提交或未跟踪源码被偷改）；
2. **依赖环境锁定摘要**：`dependency_lock_hash`；
3. **完整展开的有效算法参数**：包含所有引擎隐式默认值展开后的 `resolved_parameters`；
4. **实际生效的随机数种子**：`random_seed`；
5. **实际数据输入指纹**：
   - **数据质量审计**：**必须绑定未经清洗的原始数据字节哈希（`raw_bytes_sha256`）**，绝不能仅用清洗/排重后的数据，否则乱序、缺失与重复缺陷将被掩盖；
   - **因子统计与回测**：绑定原始数据字节哈希 + 规范化转换规则版本 + 交易日历规则版本 + 合约规格规则版本 + 实际发布可用时刻凭证摘要 + 时序切分配置；
6. **排除与保留原则**：
   - 排除：主机名、Worker 节点标识、工作区绝对路径、执行时间（`created_at`, `scheduled_at`, `started_at`, `completed_at`）；
   - 保留：数据科学时间（`time_range`, PIT 可得时刻, split windows）。

**哈希安全边界与规范化说明**：
- **哈希不等于身份认证**：记录哈希仅提供内容完整性与防意外损坏校验，禁止宣称“仅凭哈希即可实现防篡改或身份认证”（后者依赖签名与权限体系）；
- **规范化候选规则已明确，待冻结审查**：采用 [research-json-v1](protocol-v2-freeze-gap-closure.md#1-hash-canonicalizationresearch-json-v1) 受限 profile 和固定向量，不声称 RFC 8785；协议不承诺跨 CPU 架构或编译器的计算结果 bitwise 绝对一致。

---

## 4. 数据需求声明、实际可用时刻与严禁直接降级

### 4.1 数据需求真实支撑与严禁直接降级
- 实验规格（Spec）中声明的方法必须有充分的数据需求（Data Requirements）支持：
  - 声明 BBO 盘口截断（如 `next_bar_open_with_bbo_clip`），则 `required_fields` 必须显式要求盘口深度字段（`bid_price_1`, `ask_price_1`, `bid_volume_1`, `ask_volume_1`）；
  - **严禁直接降级**：若底层数据不足以支撑声明方法，**Runner 必须前置拒绝执行**，严禁在同一个 Spec 下私自降级撮合假设！必须产生**全新的 Spec 修订（New Spec Revision）**并在获得明确授权后，方可调整方法。

### 4.2 五大时序节点与 PIT 凭证缺口审计
时序因果性必须严格解耦五大时间节点：
1. **事件发生时刻（Event Timestamp）**：市场上该事件（如行情跳动、交易成交）物理发生的客观时刻；
2. **实际可得时刻（Availability Timestamp）**：该数据经交易所发布并被研究系统物理接收到的时刻。**必须具备发布时间戳凭证；若无可得凭证，严禁声称 PIT 通过，但可作为数据审计任务继续执行并显式记录时序凭证缺口（Timing Receipt Gap）**；
3. **信号决策时刻（Decision Timestamp）**：模型特征计算完毕并生成交易或分配决策的时刻（必须严格晚于或等于所有输入特征的实际可得时刻）；
4. **撮合成交时刻（Execution / Fill Timestamp）**：订单进入模拟撮合引擎并确认成交的时刻（必须晚于决策时刻，如次根 Bar 开盘）；
5. **标签成熟时刻（Label Maturity Timestamp）**：前向预测收益窗口走完的时刻（如 20 日收益在 $t+20$ 日收盘后方才成熟，此前不可作为已知目标）。

### 4.3 标的池宇宙（Universe）模式声明与禁止静默降级
- 实验规格必须显式声明标的池的处理模式：是**独立单品种逐一评估**、**多品种截面统计**，还是**多品种投资组合**；具体枚举待 Schema 确认，截面统计不自动等于投资组合；
- **禁止静默降级**：只要执行引擎不支持所声明的标的池模式（包括逐品种、截面统计和投资组合），必须前置拒绝并报告能力缺口。严禁更换模式、缩减标的范围或仅运行 `universe[0]` 后将结果冒充原任务结果。

### 4.4 训练前切分与数据审计有效证据
- **预处理拟合边界**：预处理、标准化或特征拟合参数**必须仅在训练集（Train Split）上 fit**，然后应用到测试集；
- **标签重叠判定**：标签重叠严格根据向前预测区间（Label Horizon）的时间交叉重叠判断，执行 Purging 清除；
- **数据审计有效证据价值**：数据审计若在原始数据中发现坏数据（跳空、倒挂、重复），这**本身就是极具价值的有效审计证据**，绝对不能在审计前私自清洗以掩盖缺陷。

---

## 5. 三层解耦判定体系与负收益客观属性

### 5.1 三层正交解耦模型
1. **第一层：执行状态（`execution_status`）**：`COMPLETED` | `RUNTIME_ERROR` | `TIMEOUT` | `DATA_UNAVAILABLE` | `NOT_EXECUTED`；
2. **第二层：外部 Review 的证据有效性（`evidence_validity`，禁止存入 Evidence）**：`VALID` | `VALID_BUT_UNDERPOWERED`（合规但样本不足）| `INVALID_DATA_LEAKAGE` | `INVALID_EXECUTION_ASSUMPTION` | `NOT_EVALUATED`；
3. **第三层：外部 Review 的研究/审计结论（禁止存入 Evidence）**：
   - 因子与策略回测（`research_conclusion`）：`HYPOTHESIS_SUPPORTED` | `NEGATIVE_EVIDENCE_RECORDED` | `HYPOTHESIS_REJECTED` | `INCONCLUSIVE`；
   - 数据质量审计（`audit_conclusion`）：`OBJECTIVE_SATISFIED` | `AUDIT_GAPS_IDENTIFIED` | `PENDING_EXECUTION`。

### 5.2 负收益的客观属性与评价边界
- **负收益是客观数值事实**：回测获得负收益仅是一个中立数值。是否支持假设取决于先验目标与比较基准（如基准暴跌 40% 时对冲策略录得 -3% 可能支持了下行保护假设）；
- **不自动判定策略失效或全盘拉黑**：严禁在未结合基准与目标的情况下，直接将所有负收益判定为“策略失效”，更不能自动触发因子的永久全局黑名单；系统保留其特定参数、数据时段适用范围与独立复核意见。

---

## 6. 三类类型化研究规格与期货回测 Profile

### 6.1 数据质量研究（`data_quality`）
- **定位**：检验数据真实性、连续性与卫生状况；
- **参考样例**：[`sample-data-quality-audit.json`](sample-data-quality-audit.json)；
- **要点**：仅需 `objective`，`hypothesis` 为 `null`；包含单调时间戳、价格包络线、持仓非负与换月跳空校验项；仅输出质量度量，不包含任何回测字段。

### 6.2 因子统计研究（`statistical_factor`）
- **定位**：纯统计推断，检验因子的预测力与单调性；
- **参考样例**：[`sample-factor-statistical.json`](sample-factor-statistical.json)；
- **要点**：
  - **实现引用声明**：特征与目标引用均为候选符号（如 `candidate.research_lab.factors.v1.annualized_roll_yield`），明确当前尚未在仓内审阅注册；运行层若缺失该能力必须前置拒绝执行；
  - **收敛候选配置**：样例收敛为针对单一 20 日向前对数收益率的截面秩相关（Cross-Sectional Rank IC）走查；
  - 近远月合约选择：基于实际 `contract_maturity_date` 排序确定 Near 与 Far 合约；
  - 标签防泄漏切分：采用 Purged Time-Series Split；Purging 窗口严格按向前预测区间清除重叠标签；
  - 仅输出纯统计度量，严禁塞入夏普比率、最大回撤等回测指标。

### 6.3 期货交易回测 Profile（`trading_backtest` 下的 `futures`）
- **定位**：在逼真模拟撮合、合约规则与成本摩擦下评估交易系统净值；
- **参考样例**：[`sample-futures-backtest.json`](sample-futures-backtest.json)；
- **要点**：
  - **参数定位**：样例中所有合约乘数、保证金率、费率与滑点均为自拟候选参数，绝非现行交易所规则，不可当作 #481 冻结版本；
  - **实现引用声明**：策略引用为候选符号，未注册直接拒绝；
  - **连续序列与成交序列解耦**：连续指数仅用于信号计算，撮合必须绑定具体合约代码；
  - **换月展期两步执行**：换月操作严格声明为“先平旧合约、再开新合约”，严禁跨合约瞬时原子对冲；
  - **成本模型单边细化**：开仓、平昨、平今费率分开定义，明确单边口径与计量单位；真实平今折扣若缺失保留缺口标记（`fee_metadata_gap: true`）；滑点按单边跳数明确计量。

---

## 7. 最小指标元信息、计算口径与缺失处理准则

### 7.1 核心度量指标定义表

| 指标字段 | 度量单位 / 格式 | 符号 / 方向规范 | 年化与计算口径 | 缺失与异常处理 |
| :--- | :--- | :--- | :--- | :--- |
| `total_return` | 小数比例 (decimal) | 正数表示盈利，负数表示亏损 | 全区间累积收益率，按实际权益序列计算 | 未运行或数据缺失为 null；期末净值回到起点或全期恒定均为合法数值 `"0"` |
| `annualized_return`| 小数比例 (decimal) | 正数表示年化盈利，负数表示亏损 | 基于 252 交易日按**复利年化**计算 | 未运行或数据缺失为 null；期末净值等于起点时为合法数值 `"0"` |
| `max_drawdown` | 非负小数比例 (decimal) | 恒为非负数 (如 0.15 表示回撤 15%) | 净值峰谷回撤深度最大值，按实际权益序列计算 | 未运行或数据缺失为 null；净值单调上涨或全期无回撤时为合法数值 `"0"` |
| `sharpe_ratio` | 无量纲年化比率 | 正负均可 | 日频超额收益率年化，乘以 $\sqrt{252}$ | 按实际超额收益序列计算；仅在未运行、数据不足或收益方差为 0 等不可定义时为 null 并注明原因 |
| `calmar_ratio` | 无量纲年化比率 | 正负均可 | `annualized_return / max_drawdown` | 按实际年化收益与最大回撤计算；未运行、数据不足或最大回撤为 0 等不可定义时为 null 并注明原因 |
| `trade_count` | 非负整数 | 计数 | 样本期内有效撮合成交总笔数 | 未运行为 null；已执行确认无交易撮合时，记录为真实有效观测值 0 |
| `ic_pearson_cross_sectional` | 相关系数 `[-1.0, 1.0]` | 正负均可 | 每日截面 Pearson 相关系数均值；样本量为截面交易日数 $T$ | 纯统计指标，未运行为 null |
| `rank_ic_spearman_cross_sectional`| 相关系数 `[-1.0, 1.0]` | 正负均可 | 每日截面 Spearman 秩相关系数均值；样本量为截面交易日数 $T$ | 纯统计指标，未运行为 null |
| `t_statistic_hac_adjusted` | 检验统计量 | 正负均可 | Newey-West HAC 稳健 t 统计量 (Lag = horizon - 1) | 纯统计指标，未运行或重叠区间不足为 null |
| `quantile_five_spread` | 小数差值 (decimal) | 正负均可 | 原始 20 日向前对数收益率 top quantile 减 bottom quantile 均值差 | 原始对数收益差值，不进行未定义的年化；未运行为 null |

### 7.2 指标请求与输出命名一致性
实验规格中的指标请求列表（`statistical_metrics_requested`）与产出证据中的度量字典（`typed_metrics`）必须保持完全一一对应的键名，杜绝未定义标量混用。

---

## 8. Artifact 规范与通用角色交互边界（衔接 #524 / #523）

为防止下游 #524（Artifact 标准）与 #523（Agent 通信契约）各自发散，确立通用系统边界约束（仅语义设计，不绑定具体 Agent 实现）：

### 8.1 Artifact 交付标准与 Manifest 完整性（对接 #524）
每一个由实验产生的工件记录必须满足：
1. **内容寻址摘要（`content_sha256`）**：生成 SHA-256 校验摘要；
2. **标准媒体类型（`media_type`）**：明确 MIME 类型（如 `application/json`、`text/csv`）；
3. **相对定位路径（`relative_path`）**：一律以实验产物输出目录为基准的相对路径，严禁使用 `../` 越界逃逸；
4. **Manifest 发布完整性**：产物发布不仅是单文件原子重命名，必须在整个作业的 **Artifact Manifest** 中所有必需工件均校验完整（文件存在、大小匹配、SHA-256 吻合）后，方可完成发布；任何缺失或损坏（missing/corrupt）的文件必须显式标记为不可消费（unconsumable）；
5. **最低必需工件内容要求与候选文件示例（非冻结文件名）**：
   - **数据质量审计**：
     - 必需内容：逐项检验规则判定结果、异常时间戳/价格明细清单与完整率审计报告；
     - 候选示例：`audit_summary.json`、`anomaly_manifest.json`；
   - **因子统计研究**：
     - 必需内容：**逐样本特征值与前向标签记录（必须包含时间戳、合约代码、特征值、前向对数收益与所归属的时序切分 split 引用）、每日截面 IC/Rank IC 时序序列，以及统计检验汇总**；相关系数矩阵仅作为衍生辅助，**绝不能替代上述逐样本与时序基础证据**；
     - 候选示例：`sample_feature_target_records.csv`、`daily_ic_series.csv`、`factor_statistical_summary.json`；
   - **期货交易回测**：
     - 必需内容：按时间戳排序的逐笔撮合成交流水清单（必须包含成交时刻、合约代码、买卖方向、开平标志、成交价、手续费与滑点扣除）、时序资产权益净值曲线，以及综合绩效指标汇总；
     - 候选示例：`trade_blotter.csv`、`equity_curve.csv`、`backtest_performance.json`。

### 8.2 通用系统角色职责正交性（对接 #523）
协议解耦具体 Agent 名称，定义通用协作角色（具体 Agent 如 Astra / Sol 仅作为实现示例）：
1. **提案者 (Proposer，如 Astra)**：仅具备研究设想与规格提案权（产生 `ResearchTask` 与候选 `ExperimentSpec` 提案）；
2. **规划者 (Planner，如 Sol)**：仅具备调度编排与参数配置权（生成执行计划）；
3. **执行者 (Executor，如 Worker / Runner)**：仅具备物理计算与事实记录权（记录 `ExperimentRun` 与 `ResultEvidence`）；
4. **评审者 (Reviewer)**：仅具备外部审计与评审权（追加 `review_assessments`）；
5. **提案与事实归属分离**：任何上层 Agent 均不能替代物理执行引擎捏造或覆写度量事实；未识别能力显式拒绝，授权与能力分离。

---

## 9. 严格 Schema 约束、版本分发与 v1 真实映射

### 9.1 严格 extra="forbid" 与权威模式来源
- **严格 extra="forbid"**：旧版本读者不自动接受新增可选字段，遇到未知字段或未知类型方法必须拒绝抛错；
- **权威模式来源**：推荐由代码库既有 Pydantic 模型作为唯一结构来源生成标准 JSON Schema（待人工确认），文档与走查样例仅作语义说明，不是另一套并存标准。

### 9.2 兼容性分发矩阵（拟议设计，尚未实现）
必须明确：**只读视图与版本分流是当前 Phase 0 拟议的契约设计，尚未在代码库中实现**。未来新类型必须采用强类型的版本化命名空间扩展（Versioned Typed Extension），严禁使用未经校验的万能字典（禁止滥用 `dict[str, Any]` 作为通配扩展）。

| 读者（Consumer） | 输入数据版本 | 预期处理行为 | 兼容性保证说明 |
| :--- | :--- | :--- | :--- |
| **旧读者 (v1 Reader)** | `v1` 历史实验/结果 | **原生完全支持** | 保持既有单测与分析链路 100% 不受破坏 |
| **旧读者 (v1 Reader)** | `v2` 新协议输入 | **前置显式拒绝** | 因 `extra="forbid"` 或模型不匹配直接报错拒绝，杜绝字段误读 |
| **新读者 (v2 Reader)** | `v1` 历史实验/结果 | **原义只读视图** | 解析为 Legacy 视图，不反向合成伪证据，原指标与缺失标记如实呈现 |
| **新读者 (v2 Reader)** | 未知/未支持版本 | **前置硬拒绝** | 显式抛出版本不受支持异常，杜绝隐式降级处理 |

### 9.3 历史 v1 协议真实字段映射 (v1 -> v2 只读视图)
现有 [`../../research_lab/`](../../research_lab) 中，`research_lab/schemas/result.py` 采用 `result_version: "research_lab.result.v1"`，`status: Literal["completed", "failed"]`（小写）；`experiment.py` 采用 `schema_version: "research_lab.experiment.v1"`。拟议的 Legacy 只读视图映射如下：

| 历史 v1 真实字段 | v2 Legacy 只读视图位置 | 映射与原样保留说明 |
| :--- | :--- | :--- |
| `schema_version` | `schema_version: "research_lab.experiment.v1"` | 保留原始版本标识，与 result_version 区分 |
| `result_version` | `result_version: "research_lab.result.v1"` | 原样保留结果版本标识 |
| `experiment_id` | `legacy_experiment_id` | 作为历史单一标识保留 |
| *(隐式缺失)* | `task_id: UNKNOWN_LEGACY_UNTRACKED` | 诚实标记缺失，不伪造合成 Task |
| `strategy.name` | `legacy_strategy_name` | 仅代表确定性 toy 策略（buy_and_hold / flat） |
| `strategy.parameters`| `legacy_parameters` | 原样保留 |
| `cost_model.bps` | `legacy_cost_bps` | 原样保留无单位基点比例，不标称真实手续费 |
| `dataset.prices`/`path`| `legacy_dataset_input` | 保留原始输入形式，不标记为已锁定物理快照 |
| `status` | `execution_status: "completed" \| "failed"` | 原样保留小写物理执行状态 |
| *(隐式缺失)* | Legacy 视图显示“无历史评审” | 不生成 v2 Evidence 评价字段或伪造 Review |
| `metrics.*` | `legacy_metrics.*` | 原样映射 `total_return`, `sharpe`, `max_drawdown` 等原指标 |

未来拟复用已有 `ExperimentRunner`（位于 [`../../research_lab/runners/runner.py`](../../research_lab/runners/runner.py)），按版本分流，不另建全新 Runner；现有测试（如 [`../../research_lab/tests/test_mvp.py`](../../research_lab/tests/test_mvp.py)）继续保持通过。

---

## 10. 契约测试与兼容测试设计

以下是 #511 的后续验收要求，当前未实现 v2 校验器或对应测试。测试只验证已确认的契约，不新建执行、签名或审计服务。

| 场景 | 必须验证的行为 |
| :--- | :--- |
| 旧新版本读取 | 覆盖 §9.2 矩阵；v1 的版本、状态大小写、指标符号、真实零值与缺失状态保持原义；原文件字节不变。 |
| 类型与能力拒绝 | 未知版本、字段、未注册方法，以及纯统计规格混入撮合参数时明确拒绝；不执行自由文本代码，不静默改方法。 |
| 记录哈希与计算指纹 | 改上游引用哈希必须改变下游记录哈希；只改目标说明而实际计算输入不变，不要求计算指纹改变。修改参数、代码、数据或种子必须改变计算指纹。仅改变同内容文件的本地路径不改变计算指纹。 |
| JSON 规范化与原始数据 | 对象键顺序和空白等价时记录摘要一致；数组顺序不随意排序。对数据审计，原始行情记录乱序或增加重复行必须改变原始数据指纹，不能被清洗后摘要掩盖。覆盖候选算法的数字、Unicode、非有限数边界。 |
| 重试、重复和迟到结果 | 同一准确 Spec 引用与已锁定计算输入的技术重试使用新 run_id，引用旧 run_id；保留失败记录，重复结果不重复计数，迟到结果不覆写其他运行。参数或数据内容变化不能伪装成重试。 |
| 缺失、零值与失败 | 未执行/不可计算指标为 null 并说明原因；零交易保留 trade_count=0，不能推出收益为零。净值回起点可零收益，单调上涨可零回撤；零方差 Sharpe 为 null。执行失败不能否定研究假设。 |
| 工件完整性 | 必需工件缺失、摘要/大小不符、越界路径时不得发布为完整可用证据；保留失败与损坏诊断，不删除审计记录。汇总报告不能替代逐样本或成交明细。 |
| 时间与留出集 | 特征只能使用决策时已可得的信息；训练只能使用拟合时已经成熟的标签，测试标签可在预测后成熟用于评分。按标签区间处理切分重叠。换 Task 不重置相同留出数据的暴露历史；被用于调参后不得再声称未见样本外。 |
| 评审与证据隔离 | 新评审只追加外部记录并引用原证据摘要，不能改变计算事实；审计发现坏数据可形成有效审计报告，但不赋予该数据 PIT 合规或可交易资格。 |

---

## 11. Phase 0 验收决策清单、逐项验收矩阵与后续路线

依据 [#538](https://github.com/folgercn/vnpy-web-bridge/issues/538) 及 [#498](https://github.com/folgercn/vnpy-web-bridge/issues/498)，必须明确：**本设计 PR 仅提交 Phase 0 协议设计草案供主控与付哥 Review，不宣称本 PR 关闭 #538 或 #498**。

### 11.1 真实数据路径前置与冻结顺序
依照 #497 核心要求，正式冻结前必须完成案例走查验证；具体核对标准与未决项详见配套的 [`protocol-v2-freeze-checklist.md`](protocol-v2-freeze-checklist.md)：
- **Phase 0 工具边界**：Phase 0 验证聚焦语义完备性，可用现有本地离线分析工具、测试 Fixture 或手工独立计算走查，**不需要且严禁提前开发新 Runner**；规范状态持续保持草案（`DRAFT_UNFROZEN`）；
- **门禁解耦与真实数据前置**：明确“设计方向认可”与“正式冻结”为两个独立门禁，**PR 合并仅代表设计方向被认可为基线草案，merge 决不等于 freeze**。不能将没有真实数据或能力的案例假称通过。执行节奏如下：
```text
门禁 1: 主控与付哥人工评审并认可协议设计方向 (PR #539 目标，合入仅作为草案基线，保持 DRAFT_UNFROZEN)
   ↓
门禁 2: 基于现有工具完成三类案例表达/拒绝走查，且至少一条贯穿真实数据路径 (#497 核心前置)
   ↓
门禁 3: 必需规则与案例证据齐备后，主控与付哥正式确认协议语义冻结 (#498)
   ↓
后续门禁逐项验收: #524 Artifact 规范, #523 Agent 契约, #511 Schema 实现
   ↓
Phase 0 全量验收通过 (#538 达成) → Phase 1 Runner/Result Loop → Phase 2 完整研究闭环验证 → Phase 3 按有效授权实施 Worker/Queue/自动调度
```

### 11.2 Phase 0 逐项验收矩阵

| 门禁验收项 | 当前 PR 交付状态 | 后续证据需求 / 解锁条件 | 关联 Issue |
| :--- | :--- | :--- | :--- |
| **ResearchTask 语义定义** | `DRAFT_UNFROZEN` (已完成候选规范与走查) | 待主控与付哥人工确认决策 | #498 |
| **ExperimentSpec 语义定义** | `DRAFT_UNFROZEN` (已完成三类规格与走查) | 待主控与付哥人工确认决策 | #498, #511 |
| **ResultEvidence 契约定义** | `DRAFT_UNFROZEN` (已完成三层解耦与元信息定义) | 待主控与付哥人工确认决策 | #498, #511 |
| **三类代表性研究案例验证** | 仅完成语义走查样例，**真实物理执行未完成** | 三类研究各自完成逐项证据产生与能力拒绝走查，且必须包含至少一条贯穿真实数据路径的端到端证据（一条不可替代三类全貌） | #497, #538 |
| **Experiment Artifact 标准** | 已确立顶层边界约束（Manifest/MIME/相对路径） | 待承接 Issue 细化目录拓扑与存储实现 | #524 |
| **Agent 输入输出通信边界** | 已确立角色正交与提案/事实归属分离 | 待承接 Issue 细化 Prompt 契约与序列化协议 | #523 |
| **代码层 Schema 与契约测试** | 尚未实现（严禁提前实现） | 待语义正式冻结后实现 Pydantic 校验与契约测试 | #511 |
| **Worker / Queue / 调度系统** | **严格冻结中，禁止提前实现** | 仅在后续 Phase 3 获得明确新授权后方可实施；即使 #538 门禁通过亦绝不自动推定解锁授权 | #505, #514, #536 |

### 11.3 待主控与人工确认的关键决策清单 (Decision Checklist)
- [ ] **决策 1**：确认 `data_quality`、`statistical_factor`、`trading_backtest` 三类根研究类型划分，以及期货作为 backtest profile 的建模方式；
- [ ] **决策 2**：确认实体 `revision` 与规范 `schema_version` 解耦的命名规则，以及同一 `(id, revision)` 内容不可变的原则；
- [ ] **决策 3**：确认内容哈希排除自身摘要但必须包含上游引用哈希的继承计算规则；
- [ ] **决策 4**：确认 Run 终态快照固化与 Evidence 绑定时点，以及评审以 Append-only 外部记录追加的不可变原则；
- [ ] **决策 5**：确认由 #524 承接 Artifact 规范、由 #523 承接 Agent 交互契约的顶层约束边界；
- [ ] **决策 6**：确认复用现有 `ExperimentRunner` 分流、不新建独立 Runner 的架构路线；
- [ ] **决策 7**：确认先人工认可方向、再完成真实数据路径走查、最后正式冻结 Schema 的准入顺序。

---

## 12. 正式冻结前的未决项

本节列出仍需案例和人工决策解决的缺口，不授权安装依赖、新建引擎或扩大数据范围。三份 JSON 是候选结构模板，不是可直接执行的 Schema 实例；其中解释性字段、数值与方法引用均待正式结构确认。

### 12.1 哈希规范化与身份

本轮已提交 [research-json-v1 精确规则与固定向量](protocol-v2-freeze-gap-closure.md)，包括 UTF-8、ASCII 键排序、Decimal 字符串、时间、null/missing、默认值及摘要排除。待 #498 审查签收；#511 尚未实现正式校验器与跨语言契约测试。指标产生小数时的科学精度规则仍随 §12.2 确认，不能由 Hash 层擅自舍入。

### 12.2 指标和判据

当前 252 日年化、20 日预测窗口、HAC lag=19 和判据数值只服务候选样例，不是所有研究的通用标准。冻结前需确认：

- 权益采样、年化天数、无风险基准、外部现金流处理及非正权益时的定义域。
- 截面最低有效标的数、有效日期数、并列秩与缺失处理；样本量不是独立样本量。
- HAC 所检验的 IC 序列、滞后阶数选择、有限样本限制及 p 值的近似分布。不能仅凭 lag=horizon-1 宣称已消除全部相关性。
- 研究阶段与预登记规则已在 Gap Closure §3 明确；每个具体案例仍须绑定比较基准、主指标、选择规则、fold/seed 方案及实际预登记凭据，不能包装成已完成确认。

### 12.3 三类案例的数据和能力清单

| 候选案例 | 冻结前需要核实的输入与方法 | 当前状态与处置 |
| :--- | :--- | :--- |
| RB/HC 数据审计 | 与样例周期相符的原始行情、交易日历、连续序列/换月映射及审计规则；保留原始异常。 | 未绑定真实快照，方法符号未注册。先确认可读取的数据来源与范围，再用已有离线能力核验。 |
| 六品种期限结构截面统计 | 样例六品种的合约到期日、结算价、持仓量与可得凭证，PIT 合约选择、20 日标签构造、切分及逐样本明细。 | 数据、特征和标签实现均未核实。需要澄清标签使用固定合约还是换月序列，不能跨合约直接拼接价格后当作收益。 |
| RB 期货回测 | 连续信号与具体合约映射、交易日/夜盘日历、带事件时刻的 BBO、候选成本/保证金、撮合与资金规则。 | 无真实 BBO、费用与运行证据。缺少必需数据即阻塞；若决定改用另一撮合假设，必须按 §4.1 新建 Spec 修订后核验，不能原地降级。 |

真实数据可用性尚未核实，不推断仓库之外的数据或执行器能力已经存在。案例应优先使用现有离线工具或独立计算；需要新增能力时另行明确范围。三类逐项走查及至少一条真实数据路径完成前，不宣称协议正式冻结或 #538 验收通过。
