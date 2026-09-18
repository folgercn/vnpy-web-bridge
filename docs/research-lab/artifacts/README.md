# #524 Artifact Contract 候选

状态：**PROTOCOL_V2_PHASE0_FROZEN**（详见 [Phase 0 Exit Review](../phase0-exit-review.md)）。本次只定义证据交付/消费契约，未实现存储、Manifest 发布器、validator runtime 或 Runner。冻结本协议不关闭 #524/#498/#538，不授权 Worker/Queue/Agent 调度。

依据：[#524](https://github.com/folgercn/vnpy-web-bridge/issues/524)、[#541 Review](https://github.com/folgercn/vnpy-web-bridge/pull/541)、[#542 PR](https://github.com/folgercn/vnpy-web-bridge/pull/542) 用户本轮反馈、[Protocol v2 §8](../protocol-v2-design.md#8-artifact-规范与通用角色交互边界衔接-524--523)、[ExperimentSpec 候选](../specs/README.md)。#524 原有暂缓评论仍约束执行实现；本次按 Owner 后续指示推进契约设计，不提前固定运行框架。

## 1. 先分清交付的是什么

| 内容 | 责任与权威性 | 缺失的影响 |
| --- | --- | --- |
| Task / Spec | 为什么研究、预期方法；准确 id/revision/内容摘要 | 无法绑定预期，不可当作可消费 v2 证据 |
| Run 终态记录 | 实际输入/实现/生效参数/环境/状态与计算指纹 | 无法绑定执行事实；日志不能替代 Run |
| Artifact Manifest | 本次 Run 产物目录、原始字节完整性承诺与元数据绑定清单 | 无法核验完整交付，不接受“目录存在所以完成” |
| Artifact Payload | 可复核的物理/数据载荷（数据表/明细/快照/日志等原始文件） | 承载可复核事实证据；**严禁混入 Agent 私有推理、研究结论或人工评价** |
| ResultEvidence | 实际观测值、样本覆盖、缺失原因，引用 Manifest 及条目 | 只存事实；报告中的数字不能替代它；与 Review 严格独立 |
| Review | 独立版本化评价，精确引用 Evidence | 无 Review 表示尚未评审；不阻止读取完整事实 |
| report / charts | Evidence 的可选派生展示；评价报告应引用 Review | 缺少不影响事实完整性；禁止反向覆盖指标 |

### 1.1 Artifact 的本质与红线

1. **可复核载荷（Payload）**：Artifact 是物理/数据实体（数据表、成交流水、特征标签序列、不可变快照、环境锁、脱敏日志），其校验仅基于原始文件字节的 SHA-256 内容完整性检查与不可变 Schema 约束。**Hash 仅证明内容未受损与内容比对寻址，不证明其物理来源真实性、业务正确性或操作授权**；来源与授权需另有可核验来源凭证及有效授权；Spec/Run/Review记录本身不能授予权限。
2. **严禁混入三类非事实内容**：
   - **严禁混入 Agent 私有推理**：禁止把 Agent 提示词（Prompts）、内部思维链（Chain-of-Thought / CoT）、内部状态机推理或私有调度过程写入产物载荷；
   - **严禁混入科学研究结论**：禁止在 Artifact 载荷内部自述“策略有效”、“假设成立”等主观结论；研究结论属于下游消费端或独立 Review 基于事实作出的判断，产物本身只承载客观事实载荷；
   - **严禁混入人工评价**：禁止塞入人工审批签章、定性打分或评审意见；评价只能走独立 Review 链路。
3. **Evidence 事实与 Review 评价的独立性**：Evidence 记录客观观测指标与事实状态，与独立版本化的 Review 评价严格解耦；两者通过单向不可变摘要绑定，杜绝循环依赖。

**文件名不是对象类型。** `experiment.yaml`、`result.json`、`metrics.json`、`report.md` 是旧 Issue 的示意文件名，不能成为所有研究的强制形状。按 schema/version/role 解析。v2 Spec 规范输入暂为 JSON；此变更不新增 YAML 转换。v1 `ExperimentResult` 的小写 completed/failed、固定 PerformanceMetrics 与 report 原样保留，不伪造为 v2。

## 2. 摘要引用链与元数据绑定位置

候选依赖顺序（严格单向 DAG，彻底杜绝自引用与循环）：

```
Task → Spec → Run 终态
                 ↓
         Artifact Manifest
                 ↓
          ResultEvidence → Review
```

### 2.1 核心元数据绑定位置与权威来源

| 元数据项 | 绑定位置 | 权威性与语义约束 |
| --- | --- | --- |
| `run_reference` (`run_id` + `run_content_hash`) | **Manifest 根级必填字段**（并在下游 ResultEvidence 显式对齐绑定） | `run_reference` 是根级 `run_id` 与 `run_content_hash` 的统称，不另造嵌套包装字段。准确绑定已存在的物理终态 Run，锚定执行事实；Run 本身不反向包含 Manifest 摘要以避免循环。 |
| `artifact_id` | **Manifest 条目（entry）必填** | Manifest 内稳定的局部逻辑标识（非文件路径）。下游 Evidence 对工件载荷的精确引用**必须完整包含 `manifest_id` + `revision` + `manifest_content_hash` + `artifact_id`**，不能仅用二元 id。 |
| `role`（统称 artifact_type） | **Manifest 条目（entry）必填** | 属于本文 §4 的封闭角色枚举（如 `trade_blotter`、`sample_feature_target` 等）；代表载荷在科学复核中的客观角色。`artifact_type` 仅是 `role` 的统称，不增加并列字段。**是否必须交付由固定 role profile 决定，与用途分类严格正交**。 |
| `classification` | **Manifest 条目（entry）必填** | 用途分类，正式条目仅允许 `required` 或 `supporting`；`debug` 是包外分类不得进入 entries。与交付必需性严格正交（详见 §4.1）。 |
| 原始内容 hash (`content_sha256`) | **Manifest 条目（entry）条件必填** | **仅在 `availability=present` 时必填**。对**原始文件字节**计算 64 位小写 SHA-256，绝不 parse/reformat 后再 hash。未产出（`unavailable`）缺失且不得捏造。提供内容完整性校验，不证明来源或授权。 |
| `producer` | **Manifest 条目（entry）条件必填** | **仅在 `availability=present` 时必填实际组件名+版本/不可变实现引用；unavailable 时缺失**。标明实际生成该产物的物理计算组件身份与版本来源（如 `{"component": "research_lab.backtest_engine", "version": "0.4.1"}` 或不可变实现引用）；Run 终态记录绑定整机实际执行来源。未产出（`unavailable`）时无物理组件产出，不得凭空捏造；**严禁将 Agent 调度编排或推理决策塞入 Artifact**，且 producer **不冒充密码学身份证明或授权签章**。 |
| 内容 schema 版本 (`content_schema_ref`) | **Manifest 条目（entry）必填** | 不可变内容定义的逻辑引用（名称、revision、定义内容摘要、locator）；消费方必须依据此版本安全解析列名、类型与单位，不得凭文件名盲猜。 |

- Manifest 绑定准确 `run_id/run_content_hash`，只列出数据产物（payload）。它**不列自身、Task/Spec/Run/Evidence/Review 文件**，这些控制记录通过各自协议摘要核验。Run 不反向包含 Manifest/Evidence 摘要；否则会形成循环。
- Evidence 引用 `manifest_id/revision/manifest_content_hash` 与相同的 Run。既有设计中内嵌 `artifact_manifest` 的展示形式在此候选拟改为准确引用；这是待 #498 签收的细化，不能默认为既有正式 v2 格式。
- Manifest 内容摘要按 research-json-v1 计算，仅排除根 `manifest_content_hash`。其他摘要、版本和所有条目均保留。Artifact `content_sha256` 则对**原始文件字节**计算，绝不 parse/reformat 后再 hash。
- Task/Spec/Run/Evidence 的“记录摘要”与存放它们的 JSON 文件“原始字节摘要”可能不同，字段名与消费逻辑不能互换。传输包若提供额外文件摘要只是运输校验，不能替代对象摘要。
- 同一 Run 的同一发布记录不可覆写。恢复同一组已锁定字节只算重新传输；科学输入/结果改变必须按 Spec/Run 规则新建。丢文件或损坏是本次读取的验证状态，不回写旧 Manifest。

本次不增加生命周期服务、数据库或第二套调度；上图只是不可变引用关系。为避免变相成功声明，Manifest 本身不放 `published=true`、`verified=true`、`reproducible=true` 或 `good/bad`。

## 3. Manifest 最小字段（候选，尚非运行 Schema）

| 字段 | 类型与约束 |
| --- | --- |
| schema_version | 固定候选 `research_lab.artifact_manifest.v2`，未知版本拒绝 |
| manifest_id / revision | 非空逻辑 id / `rev.[1-9][0-9]*`；发布后同 id/revision 不覆写 |
| hash_profile / manifest_content_hash | `research-json-v1` / 64 位小写 SHA-256；正式交付不允许 null |
| run_id / run_content_hash | 已存在终态 Run 的准确引用（统称 run_reference，不另造包装字段），不能只引用 Spec 或 experiment_id |
| experiment_type | data_quality / statistical_factor / trading_backtest；与 Spec 一致 |
| artifact_profile | `research_lab.artifact_roles.v2.candidate1`；明确必需角色集，变更须版本评审 |
| entries | 下表条目数组；artifact_id 与 relative_path 分别唯一，数组顺序参与摘要 |

| 条目字段 | 规则 |
| --- | --- |
| artifact_id | 本 Manifest 内稳定逻辑标识，非路径；下游精确引用使用 `manifest_id` + `revision` + `manifest_content_hash` + `artifact_id` |
| role | 本文 §4 的封闭角色之一。artifact_type 仅是其统称，不增加并列字段。一个文件只承担一个主角色，不通过起名规避必需角色 |
| classification | `required` 或 `supporting`；正式条目仅允许此两类，debug 是包外分类不得进入 entries；用途分类与交付必需性严格正交（详见 §4.1） |
| producer | present 时必填物理生成组件身份与版本/不可变实现引用（如 `component:version`）；unavailable 时缺失且不捏造；严禁注入 Agent 推理/调度，不冒充签名 |
| content_schema_ref | 不可变内容定义的逻辑引用（名称/revision/定义摘要/locator）；未知/不支持须拒绝该角色消费，不能只看扩展名 |
| availability | `present` 或 `unavailable`，这是发布者对可交付字节的声明，不是消费方校验通过证明 |
| relative_path / media_type / byte_length / content_sha256 | present 时全部必填。byte_length 为非负安全整数；空文件也必须验 schema，不因 size=0 自动合格；unavailable 时物理字段缺失且不得捏造 hash |
| unavailable_reason | unavailable 时必填机器可区分原因（not_produced / source_unavailable / execution_interrupted）；上述四个物理字段缺失，不能用零字节/零摘要伪装文件 |
| coverage | `complete` / `partial` / `none`；present 不能为 none；unavailable 必须为 none（未产出角色不可标为 partial）；partial 仅在有实际产出字节且有明确截止范围与缺失原因时合法 |

`content_schema_ref` 的 locator、revision 和定义摘要属于契约引用，实际可用定义及解析责任见 §7。此版不接受任意附加字段，不能把任意字典或说明性 `_reason` 偷渡为正式字段。模板若有 null 必须置于正式对象之外的展示包装，并明确不可消费。

### 路径与格式

- `relative_path` 相对调用方选定的 bundle 根，使用 `/` 分隔 ASCII 小写安全组件：每段匹配 `[a-z0-9][a-z0-9._-]*`；不接受空段、`.`、`..`、前后 `/`、反斜线、绝对路径、盘符、URL 或百分号转义。规范路径必须唯一。
- 内容文件必须是根目录内的普通文件，不允许任何路径段为 symlink，不解引用外部路径。解压必须先检查成员类型与路径，拒绝 symlink/hardlink/设备文件及越界成员。摘要校验和解析须针对同一稳定字节视图，不能先验旧文件再读被替换内容。
- 缺少 payload 时不得自行联网补齐、更换同名文件或接受 report 的数字。外部 source locator 是受既有授权约束的重算材料定位信息，不能通过 Spec/Manifest 扩大访问权限。
- JSON：UTF-8，重复键拒绝；控制记录用 research-json-v1。CSV/JSONL 等 payload 的编码、列类型、缺失值、行排序/主键、单位/精度必须由 content_schema_ref 定义；hash 总是原始字节。CSV 中缺失与真实零必须可区分。
- 整体压缩包 checksum 不能代替成员 checksum。日志需按原有规则避免凭证/账户信息；不能先泄露后指望 Manifest 修复。

## 4. 必需角色与分类规范

### 4.1 用途分类（Required / Supporting）与交付必需性正交

Manifest 条目显式标注用途分类（`classification`，正式条目仅允许 `required` 与 `supporting`），但**用途分类属性与由角色规范（role profile）锁定的交付必需性严格正交**：

| 分类 | 典型角色内容 | 用途定位 | 是否必须交付 |
| --- | --- | --- | --- |
| **required** | 核心汇总统计、输入数据元数据、不可变环境锁与方法定义等（如 `backtest_summary`、`dataset_metadata`、`environment_lock`、`failure_diagnostics`） | 构成科学复核的核心入口、环境指纹或失败诊断 | **由 role profile 决定**：属 profile 必需角色者在相应终态下强制必填（前四项共同材料为所有 COMPLETED 必需，`failure_diagnostics` 为 FAILED 必需） |
| **supporting** | 底层复核明细载荷（如 `trade_blotter`、`sample_feature_target`、`daily_ic_series`、`equity_curve`、`quality_anomalies`）、可选脱敏日志（`execution_log`）及可选图表报告（`chart`、`presentation_report`） | 供深入复核计算过程与审计下钻的证据载荷，或辅助诊断/展示派生物 | **由 role profile 决定**：`trade_blotter`、`sample_feature_target` 等虽然属于 supporting 分类，但在对应实验类型 profile 中**强制必需交付**，绝不可缺！`execution_log` 归 supporting 且为可选；图表报告等可选派生角色可缺省 |
| *(包外) debug* | 运行期未脱敏 trace、内存 dump、中间 scratch 文件等 | 纯工程临时诊断，**不决定科学结论** | **包外分类，严禁进入正式 entries**；其存在与否、缺失与否绝不影响科学事实的有效性与合法消费 |

**正交性红线与分片条款**：
1. **禁止改分类绕过角色要求**：对于终态 COMPLETED，是否必须交付由对应实验类型的不可变角色规范（role profile）锁定。发布者**绝不能**把 `trade_blotter`、`sample_feature_target` 等角色降级或通过篡改分类试图规避缺件；凡属 role profile 规定的必需角色，在 COMPLETED 时必须完整交付（present 且 complete/合法）；FAILED 运行则按 §4.4 规则处理（允许 unavailable/none 或特定 partial）；
2. **分片完整性条款**：单 role 可拆多文件，但版本化内容定义须规定分片与完整分片集，重复/缺片拒绝完成交付；
3. **纯调试产物不得进入正式 Manifest、不决定科学结论**：纯调试 logs / temp 严禁用于决定、推翻或修改客观科学结论；debug 是包外分类，不得进入正式 Manifest 条目；
4. **诊断日志角色的定位调整**：
   - 通用脱敏执行日志 `execution_log` 归 `supporting` 分类且作为**可选脱敏诊断角色**（若声明 present 但缺失/损坏，只影响当前 Manifest 包的交付完整性，**不改变 Run 的客观状态或科学结论**）；
   - 在技术执行失败的运行中，`failure_diagnostics` 归 `required` 分类，且**仍然是 FAILED 强制必需角色**。

### 4.2 所有类型的共同复算材料

前四项共同材料（`dataset_metadata`、`method_definition`、`environment_lock`、`replay_instructions`）归 `required` 分类，且为**所有终态 COMPLETED 运行的强制必需角色**：

- `dataset_metadata`：实际 snapshot/原始输入字节摘要和长度、逻辑来源、样本区间、字段/单位、日历/规范转换版本与可得性凭证引用。输入字节可以受授权外置，但不能仅靠可变 URL；实际取得后必须核验固定摘要。
- `method_definition`：实际使用方法的不可变定义及代码/源码差异定位与摘要，明确预期 implementation_ref 如何解析；不得仅给一个无法定位的名字。
- `environment_lock`：实际 runtime/依赖锁及摘要、生效参数/seed/实际切分的可读取引用，与 Run 科学指纹一致；主机路径不进入科学指纹。
- `replay_instructions`：输入材料、依赖、计算步骤、输出角色及比较规则。数值容差必须事前版本化；同算法不自动承诺跨平台 bitwise 一致，禁止看到差异后放宽容差。
- `execution_log`（supporting 分类，可选脱敏诊断）：执行阶段、错误或完成事件的脱敏诊断记录；不含研究结论。若登记为 present 却损坏/缺失，只使本次包交付完整性校验失败，不改变已记录的 Run 状态与科学事实。

共同角色用于回答“拿到哪些材料才能复算”；不要求把受限数据或凭证提交 Git。**完整可读证据包 ≠ 自包含可重算包**。重算还需全部源字节和实现/环境可取得且吻合；缺项必须给出不能复算的原因，不能宣称“任意实验已完全复现”。

### 4.3 三类终态 COMPLETED 的事实产物（角色必需，不可缺件）

下表为三类实验终态 COMPLETED 时 role profile 锁定的强制必需角色（即使分类属于 supporting，也必须完整交付）：

| 类型 | 强制必需角色（由 role profile 锁定） | 必须表达 |
| --- | --- | --- |
| data_quality | quality_summary（required 分类）、quality_anomalies（supporting 分类） | 每项规则的观测计数、分母/覆盖；原始源序列行/键定位与异常明细。零异常仍提交按 schema 合法的空明细；不预先清洗再宣称原始数据无重复 |
| statistical_factor | statistical_summary（required 分类）、sample_feature_target（supporting 分类）、daily_ic_series（supporting 分类） | 逐样本时间/具体合约/特征/前向标签/split；每日 IC/有效样本计数与不可定义原因；指标版本、精度、重叠标签与聚合范围。不能仅用相关矩阵或最终均值替代 |
| trading_backtest | backtest_summary（required 分类）、trade_blotter（supporting 分类）、equity_curve（supporting 分类） | 逐 fill 时间/确切合约/方向/开平/数量/价/费用/滑点口径；含初始值的权益序列与货币/现金流；版本化指标、样本数与缺失原因。无交易时合法空 fills，不等于缺账本 |

所有汇总中的指标与 Spec 请求、Evidence 观测逐项对应。可以保留有内容的 null+原因，但不能只因文件存在就放行不可定义、缺关键样本或语义不一致的研究结论。

### 4.4 失败实验、缺失与非成功结果：严格区分与防范成功偏差

必须严格区分**拒绝启动/执行失败**与**预声明允许的观测缺失/数学不可定义**，杜绝通过掩盖错误或过滤失败实验制造成功偏差（Survivorship Bias）：

1. **拒绝启动与技术执行失败（Execution FAILED）**：
   - 凡因**必需输入数据缺失、费用/BBO 缺失、未声明的非法数据缺失、算法异常、内存溢出或执行中断**等导致无法完成时，**必须在执行前拒绝启动，或在执行中标记为 FAILED**（视是否已有 Run），**绝对不得强行改成成功/COMPLETED**；
   - 终态为 FAILED 时，必须生成并保留真实终态 Run/Evidence、Manifest 和 `failure_diagnostics`（错误码、失败阶段、已完成步骤、未完成原因；归 required 分类的强制必需角色，须 present 且 complete；不捏造堆栈或指标）；
   - Manifest 列出全部共同及该类型原定角色，已产出的可用字节保留；未产出角色其 `availability` 必须为 `unavailable`，`coverage` **必须为 `none`**（绝不能标为 partial）；
   - **底线保障**：若连终态控制记录或故障诊断都未完成，只能保存中断日志材料，不能冒充正式 FAILED 归档。最小归档能力不要求凭空恢复尚未解析出的数据或参数；
   - **防范成功偏差**：必须真实归档失败实验，禁止静默丢弃失败运行。此类包允许遵循 §5 作为**故障与错误诊断证据**有限读取，但不允许作为完整研究结果输入 Critic。
2. **预声明允许的观测缺失 / 数学不可定义（COMPLETED）**：
   - **严格限定条件**：仅在 Spec 明确预声明允许（具备合法的 `undefined_policy`）、且**物理计算完整完成**的前提下，客观观测缺失或数学不可计算才可输出 COMPLETED：
     - 例如：特定周期内品种无成交（`trade_count=0`，输出合法空账本；损益须按实际初始持仓/权益及现金流口径计算，无成交本身不能推导零损益）；收益序列方差为零导致 Sharpe 在数学上不可计算（输出 `null` 伴随 `undefined_reason: "zero_variance"`）；
     - 策略负收益、统计 IC 为负、数据查出重复，在技术计算完整时仍为 COMPLETED。`STOP_ECONOMIC_GATE` 属于外部 Review/历史评价背景，不能直接映射为执行 FAILED 或填入纯事实 summary 的评价字段；
   - 严禁将亏损策略或负 IC 实验过滤隐瞒，严禁通过剔除“未出交易”或“指标不可定义”的样本制造策略必定盈利或因子始终有效的假象。

### 4.5 可选派生角色

`presentation_report`、`chart`（属于 supporting 分类）可省略，但**一旦列为 present，交付时仍要检查存在/长度/hash/schema**。损坏/缺失的声明条目使当前完整交付校验失败；可单独读取其他已核验事实作诊断，不能声称整个 Manifest 合格。

事实展示报告只能引用事实。含 recommendation 的评价报告应作为独立 Review 的派生文档，用 Review 绑定 Evidence，不塞进本次事实 Manifest，以免要求不可变事实随评审改写。

## 5. 消费决策与 Agent 边界

下述是验收约束，**尚未实现运行状态机或校验器**。不得将这些名称直接当作现有 API 状态。

| 检查结果 | 允许消费范围 |
| --- | --- |
| 控制记录缺失、版本未知、引用/hash 不匹配、路径不安全、声明 present 却文件缺失/损坏 | 拒绝正式事实消费；保留错误诊断，不更新原记录 |
| COMPLETED，全部必需角色 present/complete，文件与内容语义核验通过 | 允许读取事实；是否支持假设由独立 Review 判定 |
| FAILED，诊断完整，已列字节完整，未产出角色明确 unavailable/none | 允许失败诊断和已完成事实的限定读取；不得当完整统计/交易证据 |
| 文件完整，但原始输入/依赖/实现外置且无法取得 | 可按已通过的事实检查限定读取；明确当前不能重算，不声称已复现 |
| NOT_DISPATCHED/PENDING/RUNNING 或草案/null 摘要 | 仅作为草案/进度查看，不能发布终态研究证据 |

### 5.1 正式研究证据的消费约束（衔接 #523）

本节**仅约束正式科学研究证据的消费行为**，不禁止遵循上表对失败/未完整包进行工程错误诊断，亦不扩展 Agent 通信或调度实现：
1. **正式研究结论与假设判定的消费门槛**：
   - Agent（Proposer、Planner、Critic、Reviewer）在进行策略评价、假设检验或参数决策时，**仅限消费已完全通过校验的 COMPLETED 正式 Manifest** 中的合法 payload；
   - 消费时必须基于 `content_schema_ref` 所指向的不可变定义安全解析，严禁依赖展示报告（`report.md`）中的未经核验文本替代原始数据明细；
   - 严禁将 FAILED 运行或未产出必需角色的工件包作为合格科学研究证据输入。
2. **调试与未受管材料边界**：
   - 严禁绕过 Manifest 直接扫描本地文件系统或读取非正式登记路径；
   - 纯调试 trace、临时 scratch 文件与 dump 属于包外材料，不属于正式 Manifest 事实，不得用于支持科学推断。
3. **通信与调度协议留 #523**：
   - Agent 间的消息格式、任务派发机制、协商会话与状态机流转完全属于 `#523` 契约范围，本文不定义任何通信协议或调度 API。

### 5.2 发布完整性与幂等性

发布前必须验证整份引用链、必需角色、所有声明 present 条目及内容；全部通过后才能向消费者暴露“完整交付”的入口。逐个文件原子写入不等于整包发布成功。具体持久化、事务或目录策略留 #513/后续实现，不在本次新建服务。

出现重复传输：准确 Run/Manifest 内容一致可幂等接受；相同 id/revision 而 hash 不同为冲突，拒绝覆盖。迟到结果只归属自己的 Run，不能替换另一 Run 的 Evidence；同输入技术重试不增加独立样本数。

## 6. 三类走查与反例

本次是**规则走查**，无合成真实 hash、无实际读取新 bundle。实际历史材料参考 [#540 三案例](../phase0-validation/README.md)，它们仍是回溯映射，不能自动升级为本候选格式。

| 输入/情况 | 契约预期 |
| --- | --- |
| 数据质量：共同材料+完整审计摘要+合法空异常表，无策略/收益 | 类型可表达；零异常是事实，须核对日历分母与原始序列 |
| 因子：逐样本、每日 IC、统计汇总，IC 为负、无 PnL | 类型可表达，完整执行不因负 IC 变 FAILED；Review 再判断，不制造成功偏差 |
| 回测：成交/权益/汇总齐全，经济门槛未过 | 类型可表达，门槛评价外置，不混淆技术完成 |
| 只复制 #540 的 Git 小文件，external 逐样本或成交文件缺失 | 不可发布完整证据；历史 README 已明确此限制 |
| trade_blotter 分类为 supporting 但在回测中缺失；发布者称其为 supporting 而不提供 | 拒绝；是否必需由 role profile 锁定，trade_blotter 为回测强制必需角色，改分类不得绕过必需性 |
| 条目 classification 填为 debug | 拒绝；debug 为包外分类，正式条目仅允许 required 或 supporting |
| 单 role 拆多文件但缺少其中分片，或存在重复分片 | 拒绝完成交付；必须符合版本化内容定义规定的完整分片集 |
| 缺少纯调试 trace / temp 文件，但全部 role profile 必需产物完备 | 允许正常正式消费；纯调试产物为包外材料，不入正式 Manifest，不影响科学结果 |
| 缺少必需输入或费用模型导致无法撮合，执行者强行 COMPLETED 并填 0 收益 | 拒绝；输入或核心逻辑缺失须拒绝启动或标记为 FAILED，严禁强改成功 |
| 因子计算遭遇未捕获代码异常，执行者将其记为 COMPLETED 伴随 null IC | 拒绝；算法异常属于执行 FAILED，只有预声明允许且计算完整时的不可定义才可 COMPLETED+null |
| 回测预声明允许无交易，实际无成交（trade_count=0），提交合法空账本，Sharpe 因零方差为 null | 允许 COMPLETED 事实交付；遵循预声明策略，按初始持仓/现金流计算，杜绝成功偏差 |
| 把 Agent 内部思考 Prompt 或调度计划塞入 Artifact 或 producer 字段 | 拒绝；Artifact 仅限客观复核载荷，producer 仅表达物理生成组件及版本，不冒充身份证明 |
| 文件 hash 正确但行数/单位/指标版本与 Evidence 不一致 | 语义核验拒绝；hash 仅保证原始字节未被传输损坏，不代表科学口径正确或具备业务权威 |
| FAILED，未产出角色标记为 availability=unavailable 但 coverage=partial | 拒绝；unavailable 角色 coverage 必须为 none，未产出不可标为 partial |
| FAILED，中断且连终态控制记录或故障诊断都未完成，却声称正式 FAILED 归档 | 拒绝；此时只能作为未受管中断材料暂存，不能冒充正式归档 |
| 正常完成却 metrics 文件空白，报告写“0” | 拒绝，不将文件存在、空文件或报告文本当真实零 |
| Manifest 包含自身或 Evidence 文件摘要；Run 再引用 Manifest | 拒绝循环设计；使用 §2 的单向绑定 |
| 同名 snapshot 已被修正、依赖不可定位、超出范围的 symlink | 分别拒绝重算、报告不能重算、拒绝不安全读取；不能追随 latest |
| 可选 chart 声明 present 但缺失 | 完整交付失败；不静默删条目重算旧 Manifest |
| Report 新增“通过”评价，原 Evidence/Manifest 不变 | 创建独立 Review 及其派生报告；不覆写原事实包 |

这些预期还需在正向 v2 输入驱动案例中验证，不能凭本表认定已通过生产消费或完整复现验收。

## 7. 冻结责任与 implementation_ref 待办

机器化进展：已有 [离线契约校验](../../../research_lab/contracts/README.md) 与
[Manifest Schema](../../schemas/research-artifact-manifest-v2.schema.json)。固定定义目录及本例载荷、引用拒绝已有测试；
未登记的其他内容定义、完整科学准入仍是下表的未完成项，不因部分机器化自动冻结或开放执行。

依据 #541 Review，以下不能只停留在“文档说拒绝”：

| 责任 | 正式冻结/开放执行前必须提供的证据 |
| --- | --- |
| 结构 validator（自动） | 版本/字段/类型/必需角色、非 null 正式摘要、路径语法、present/unavailable 条件和唯一性负例 |
| 引用与文件校验（自动） | 控制记录规范摘要、文件原始摘要/长度、引用一致性、安全解析、完整分片集、重复冲突与缺件阻断测试 |
| 科学语义准入（自动；具体实现尚未授权） | #511 S1–S7：方法解析、参数默认值、实际输入/时间范围、指标定义、跨 Task 暴露约束的机器可检查项；未实现就不能开放执行 |
| 人工 Review（审查责任） | 方法与指标设计是否合理、样本选择是否支持研究问题、可信预登记/数据来源证据是否充分；人工不能豁免缺件/hash 错误 |

`implementation_ref` 的冻结签收必须同时回答三件事，当前不能假装已有注册中心：

1. **存储/定位**：选定唯一的版本化方法定义来源；提供能读取定义内容和对应实现的 locator，明确哪些只是候选名字。Artifact `method_definition` 保留本次实际使用定义，不替代注册/解析规则。
2. **身份**：名称、不可变 revision、定义内容摘要以及实际源码/依赖摘要各自绑定；同名方法变语义不能覆盖旧 revision，不能用 mutable main/latest 代替。
3. **缺失行为**：引用不存在、版本不支持、摘要不符或默认值不能展开必须在执行前拒绝；不得从模型记忆补猜或临时下载替代代码。失败后保留定位失败原因。

Artifact `content_schema_ref` 同样需要确定唯一可解析定义源和版本身份。本次角色表是设计输入，尚未交付每个 payload 的机器 Schema；这项明确列为冻结阻塞，不能让消费者凭文件名猜列类型。

下一步 #523 只定义 Agent 对这些引用、错误和可消费边界的输入输出责任；随后完成正向案例，#498 决定冻结，再逐项验收 #538。本轮不关闭任何门禁 Issue。
