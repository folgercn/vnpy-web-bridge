# AlphaHypothesis Contract 规范与去重边界 (#563)

## 1. 契约定义与定位

### 1.1 它是什么？
`AlphaHypothesis` 是 Alpha Discovery 系统的核心起点契约，定义了：
> **“为什么某个信号可能预测未来收益，以及应该如何被证伪。”**

它记录了一个可验证、可证伪的科学命题及其经济学逻辑、输入特征、预测目标、持有周期、适用标的池、已知风险和明确的证伪条件。

### 1.2 它不是什么？
`AlphaHypothesis` 坚决不是以下概念，严禁混入相关字段：
* **不是 ExperimentSpec / Backtest Spec**：不含运行时参数、执行引擎、数据快照路径、种子（seed）、费用模型、工作目录等。
* **不是 Screening Result / Evidence**：不含任何实验产生的事实（如 Sharpe、IC、胜率、回测收益、曲线等）。
* **不是 Review / Critic Score**：不含对假设好坏的判定、评分、排序或 PROMOTE / REJECT / NEED_MORE_EVIDENCE 等决议。
* **不是 Trading Strategy / Portfolio**：不含头寸管理、资金分配或交易执行逻辑。

---

## 2. 核心架构边界

### 2.1 与 ResearchTask 的边界
* `AlphaHypothesis` 是科学命题层，表达“研究什么”以及“证伪边界”。
* `ResearchTask` 是实验规划与组织层，表达“组织何种类型的研究”（如数据质量检查、统计因子筛选、单合约回测）。
* 一个 `AlphaHypothesis` 后续可由 Planner 派生出一个或多个 `ResearchTask`。本阶段严禁自动生成 `ResearchTask`。

### 2.2 与 ExperimentSpec 的边界
* `ExperimentSpec` 严格绑定到具体代码执行环境与数据切片（`execution_engine`, `snapshot_path`, `environment_lock`, `fee_model` 等）。
* `AlphaHypothesis` 完全解耦于执行环境。假设创建时绝对不知道后续实验结果（Evidence）。

---

## 3. 字段规范 (`research_lab.alpha_hypothesis.v1`)

| 字段名 | 类型 | 必填 | 说明 |
| :--- | :--- | :--- | :--- |
| `schema_version` | string | 是 | 固定 `"research_lab.alpha_hypothesis.v1"` |
| `hash_profile` | string | 是 | 固定 `"research-json-v1"` |
| `hypothesis_id` | string | 是 | 假说唯一标识符，满足 `^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$` |
| `revision` | string | 是 | 版本号，满足 `^rev\.[1-9][0-9]*$`（默认 `"rev.1"`） |
| `hypothesis_content_hash` | string | 是 | 64 位 SHA-256 摘要（排除自身后对完整记录计算，不可为空，错误或缺失均 fail closed） |
| `title` | string | 是 | 简短描述性标题 |
| `economic_rationale` | string | 是 | 经济学因果逻辑说明（严禁混入实现代码或结果宣称） |
| `signal_family` | string | 是 | 信号分类族（如 `"momentum"`, `"mean_reversion"`, `"volatility"` 等） |
| `signal_definition` | string | 是 | 明确的数学/逻辑公式或特征计算定义 |
| `source_features` | list[str] | 是 | 所需输入基础特征列表（非空） |
| `target` | string | 是 | 预测目标标的/收益定义（如 `"forward_return_5d"`） |
| `expected_direction` | string | 是 | 预测方向，`"positive"` 或 `"negative"` |
| `holding_horizon` | string | 是 | 持有周期（如 `"5d"`, `"20d"`） |
| `universe` | string \| dict | 是 | 适用标的池范围（如 `"commodity_active"` 或结构化定义） |
| `frequency` | string | 是 | 采样/调仓频率（如 `"1d"`, `"1h"`） |
| `known_risks` | list[str] | 是 | 已知风险与失效场景列表（非空） |
| `falsification_conditions` | list[str] | 是 | 证伪条件列表（非空，定义何种结果表示假设不成立） |
| `proposed_screening_methods` | list[str] | 是 | 建议的低成本筛选检查方法（非空） |
| `provenance` | object | 是 | 来源溯源信息（含 `origin_type`, `origin_ref`, `created_by`, `created_at`） |
| `parent_hypothesis_ref` | object | 否 | 修订或派生时的父假设引用（含 id, revision, content_hash） |
| `related_hypothesis_refs` | list[object] | 否 | 关联假设引用列表 |
| `duplicate_of` | object | 否 | 精确重复时的目标假设引用 |

---

## 4. 机器可测试规则

### 4.1 双层 Hash 架构与 Canonicalization
为严格解耦“单次修订记录的版本快照”与“科学命题本身的本质身份”，系统明确区分两个层面的 Hash：
1. **Revision Record Content Hash (`compute_hypothesis_content_hash`)**：
   - 针对单个 Revision 记录的完整不可变快照计算 SHA-256（排除自身字段）；
   - 涵盖包括 title, revision, known_risks, falsification_conditions, proposed_screening_methods, provenance 在内的所有字段；
   - 作为该版本的唯一物理指纹，**必填且不可为空，任何字段缺失、空字符串或篡改均 fail closed**。
2. **Scientific Identity Hash (`compute_semantic_hash` / `compute_scientific_identity_hash`)**：
   - 针对科学假设核心命题计算 SHA-256；
   - 严格且仅由 `CORE_SCIENTIFIC_FIELDS` 决定，忽略非核心命题字段（如 title, known_risks, falsification_conditions, provenance 等）；
   - 两个假设若该 Hash 相同，即代表它们描述的是同一个 Alpha Idea。

### 4.2 统一科学身份边界与 Revision 边界
由同一组 `CORE_SCIENTIFIC_FIELDS` 统一决定“是否允许 Revision”以及“是否是同一 Alpha Idea / Exact Semantic Identity”：
* **Revision（修订版）**：
  * 本质科学命题保持不变（`CORE_SCIENTIFIC_FIELDS` 完全一致，Scientific Identity Hash 不变）；
  * 仅允许修正表述、细化 `title`、补充 `known_risks`、澄清/补充 `falsification_conditions` 或调整 `proposed_screening_methods`；
  * 继承原 `hypothesis_id`，递增 `revision`（如 `rev.2`），必须显式包含 `parent_hypothesis_ref`；
  * 修改 `falsification_conditions` 产生的新版本记录，其 Revision Record Content Hash 会改变，但 Scientific Identity Hash 保持一致，依然识别为同一个 Alpha Idea，不会被误判为 New Hypothesis。
* **New Hypothesis（新假设）**：
  * 核心科学命题发生改变（任一 `CORE_SCIENTIFIC_FIELDS` 改变）：
    * `signal_family` 改变
    * `signal_definition` 改变
    * `source_features` 改变
    * `target` 改变
    * `expected_direction` 改变
    * `holding_horizon` 改变
    * `universe` 核心语义改变
    * `frequency` 改变
    * `economic_rationale` 改变
    * `signal_type` 改变（属于 frozen scientific identity，决定是否可合法映射 cost proxy，严禁伪装为 revision）
  * Scientific Identity Hash 改变，必须分配新的 `hypothesis_id`，绝对不允许伪装成原有假设的 Revision。

### 4.3 去重规则 (Dedup)
* **Exact Duplicate（精确重复）**：
  * 基于 `compute_semantic_hash`（即 `compute_scientific_identity_hash`）；
  * 核心科学命题完全相同时判定为 Exact Duplicate，阻止重复 Idea 产生冗余实验。
* **Structured Similarity Key（结构相关键）**：
  * 格式：`family={family}|target={target}|dir={dir}|horizon={horizon}|universe={universe}|freq={freq}`。
  * 相同者仅标记为 `potentially_related`，供研究员/检索系统参考，**绝不自动判定为 Duplicate**。

---

## 5. 延期与后续工作 (DEFERRED)

* **#564 Screening Pipeline**：Screening Planner、自动生成 ExperimentSpec、调度 Runner、计算 IC 与相关性、生成 Evidence。
* **#565 Critic / Promotion Gate**：自动执行证伪条件判定、对 Evidence 进行 Critic 审查、产出 REJECT / NEED_MORE_EVIDENCE / PROMOTE 决议。
* **#566 Research Memory**：Hypothesis Graph 数据库、Embedding / Vector 相似检索、跨周期研究检索。
* **基础设施扩张**：严禁引入 Redis、Celery、Worker Queue 或常驻 daemon 服务。
