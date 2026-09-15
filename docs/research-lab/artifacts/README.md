# #524 Artifact Contract 候选

状态：**DRAFT_UNFROZEN**。本次只定义证据交付/消费契约，未实现存储、Manifest 发布器、validator runtime 或 Runner。合并不冻结协议、不关闭 #524/#498/#538，不授权 Worker/Queue/Agent 调度。

依据：[#524](https://github.com/folgercn/vnpy-web-bridge/issues/524)、[#541 Review](https://github.com/folgercn/vnpy-web-bridge/pull/541)、[Protocol v2 §8](../protocol-v2-design.md#8-artifact-规范与通用角色交互边界衔接-524--523)、[ExperimentSpec 候选](../specs/README.md)。#524 原有暂缓评论仍约束执行实现；本次按 Owner 后续指示推进契约设计，不提前固定运行框架。

## 1. 先分清交付的是什么

| 内容 | 责任与权威性 | 缺失的影响 |
| --- | --- | --- |
| Task / Spec | 为什么研究、预期方法；准确 id/revision/内容摘要 | 无法绑定预期，不可当作可消费 v2 证据 |
| Run 终态记录 | 实际输入/实现/生效参数/环境/状态与计算指纹 | 无法绑定执行事实；日志不能替代 Run |
| ResultEvidence | 实际观测值、样本覆盖、缺失原因，引用 Manifest | 只存事实；报告中的数字不能替代它 |
| Artifact Manifest | 本次 Run 产物目录及其原始字节完整性承诺 | 无法核验完整交付，不接受“目录存在所以完成” |
| Review | 独立版本化评价，精确引用 Evidence | 无 Review 表示尚未评审；不阻止读取完整事实 |
| report / charts | Evidence 的可选派生展示；评价报告应引用 Review | 缺少不影响事实完整性；禁止反向覆盖指标 |

**文件名不是对象类型。** `experiment.yaml`、`result.json`、`metrics.json`、`report.md` 是旧 Issue 的示意文件名，不能成为所有研究的强制形状。按 schema/version/role 解析。v2 Spec 规范输入暂为 JSON；此变更不新增 YAML 转换。v1 `ExperimentResult` 的小写 completed/failed、固定 PerformanceMetrics 与 report 原样保留，不伪造为 v2。

## 2. 摘要引用链：避免自引用

候选依赖顺序：

```
Task → Spec → Run 终态
                 ↓
         Artifact Manifest
                 ↓
          ResultEvidence → Review
```

- Manifest 绑定准确 `run_id/run_content_hash`，只列出数据产物（payload）。它**不列自身、Task/Spec/Run/Evidence/Review 文件**，这些控制记录通过各自协议摘要核验。Run 不反向包含 Manifest/Evidence 摘要；否则会形成循环。
- Evidence 引用 `manifest_id/manifest_content_hash` 与相同的 Run。既有设计中内嵌 `artifact_manifest` 的展示形式在此候选拟改为准确引用；这是待 #498 签收的细化，不能默认为既有正式 v2 格式。
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
| run_id / run_content_hash | 已存在终态 Run 的准确引用，不能只引用 Spec 或 experiment_id |
| experiment_type | data_quality / statistical_factor / trading_backtest；与 Spec 一致 |
| artifact_profile | `research_lab.artifact_roles.v2.candidate1`；明确必需角色集，变更须版本评审 |
| entries | 下表条目数组；artifact_id 与 relative_path 分别唯一，数组顺序参与摘要 |

| 条目字段 | 规则 |
| --- | --- |
| artifact_id | 本 Manifest 内稳定逻辑标识，非路径；Evidence 明细引用用 Manifest 摘要 + artifact_id |
| role | 本文 §4 的封闭角色之一。一个文件只承担一个主角色，不通过起名规避必需角色 |
| content_schema_ref | 不可变内容定义的逻辑引用（名称/revision/定义摘要）；未知/不支持须拒绝该角色消费，不能只看扩展名 |
| availability | `present` 或 `unavailable`，这是发布者对可交付字节的声明，不是消费方校验通过证明 |
| relative_path / media_type / byte_length / content_sha256 | present 时全部必填。byte_length 为非负安全整数；空文件也必须验 schema，不因 size=0 自动合格 |
| unavailable_reason | unavailable 时必填机器可区分原因（not_produced / source_unavailable / execution_interrupted）；上述四个物理字段缺失，不能用零字节/零摘要伪装文件 |
| coverage | `complete` / `partial` / `none`；present 不能为 none，unavailable 必须为 none；partial 必须有明确样本/阶段截止范围与缺失原因 |

`content_schema_ref` 的 locator、revision 和定义摘要属于契约引用，实际可用定义及解析责任见 §7。此版不接受任意附加字段，不能把任意字典或说明性 `_reason` 偷渡为正式字段。模板若有 null 必须置于正式对象之外的展示包装，并明确不可消费。

### 路径与格式

- `relative_path` 相对调用方选定的 bundle 根，使用 `/` 分隔 ASCII 小写安全组件：每段匹配 `[a-z0-9][a-z0-9._-]*`；不接受空段、`.`、`..`、前后 `/`、反斜线、绝对路径、盘符、URL 或百分号转义。规范路径必须唯一。
- 内容文件必须是根目录内的普通文件，不允许任何路径段为 symlink，不解引用外部路径。解压必须先检查成员类型与路径，拒绝 symlink/hardlink/设备文件及越界成员。摘要校验和解析须针对同一稳定字节视图，不能先验旧文件再读被替换内容。
- 缺少 payload 时不得自行联网补齐、更换同名文件或接受 report 的数字。外部 source locator 是受既有授权约束的重算材料定位信息，不能通过 Spec/Manifest 扩大访问权限。
- JSON：UTF-8，重复键拒绝；控制记录用 research-json-v1。CSV/JSONL 等 payload 的编码、列类型、缺失值、行排序/主键、单位/精度必须由 content_schema_ref 定义；hash 总是原始字节。CSV 中缺失与真实零必须可区分。
- 整体压缩包 checksum 不能代替成员 checksum。日志需按原有规则避免凭证/账户信息；不能先泄露后指望 Manifest 修复。

## 4. 必需角色与内容

角色集由实验类型与终态确定，**发布者不能把必需条目标成 optional 来绕过缺件**。下列每个必需角色都必须在 entries 中出现；即使未产出也显式 unavailable。单角色可拆多文件，但内容定义须规定分片与完整分片集，重复/漏片均不可消费。

### 所有类型的共同复算材料

- `dataset_metadata`：实际 snapshot/原始输入字节摘要和长度、逻辑来源、样本区间、字段/单位、日历/规范转换版本与可得性凭证引用。输入字节可以受授权外置，但不能仅靠可变 URL；实际取得后必须核验固定摘要。
- `method_definition`：实际使用方法的不可变定义及代码/源码差异定位与摘要，明确预期 implementation_ref 如何解析；不得仅给一个无法定位的名字。
- `environment_lock`：实际 runtime/依赖锁及摘要、生效参数/seed/实际切分的可读取引用，与 Run 科学指纹一致；主机路径不进入科学指纹。
- `replay_instructions`：输入材料、依赖、计算步骤、输出角色及比较规则。数值容差必须事前版本化；同算法不自动承诺跨平台 bitwise 一致，禁止看到差异后放宽容差。
- `execution_log`：执行阶段、错误或完成事件的脱敏日志；不含研究结论。完整日志不证明研究成功。

共同角色用于回答“拿到哪些材料才能复算”；不要求把受限数据或凭证提交 Git。**完整可读证据包 ≠ 自包含可重算包**。重算还需全部源字节和实现/环境可取得且吻合；缺项必须给出不能复算的原因，不能宣称“任意实验已完全复现”。

### 三类终态 COMPLETED 的事实产物

| 类型 | 必需角色 | 必须表达 |
| --- | --- | --- |
| data_quality | quality_summary、quality_anomalies | 每项规则的观测计数、分母/覆盖；原始源序列行/键定位与异常明细。零异常仍提交按 schema 合法的空明细；不预先清洗再宣称原始数据无重复 |
| statistical_factor | sample_feature_target、daily_ic_series、statistical_summary | 逐样本时间/具体合约/特征/前向标签/split；每日 IC/有效样本计数与不可定义原因；指标版本、精度、重叠标签与聚合范围。不能仅用相关矩阵或最终均值替代 |
| trading_backtest | trade_blotter、equity_curve、backtest_summary | 逐 fill 时间/确切合约/方向/开平/数量/价/费用/滑点口径；含初始值的权益序列与货币/现金流；版本化指标、样本数与缺失原因。无交易时合法空 fills，不等于缺账本 |

所有汇总中的指标与 Spec 请求、Evidence 观测逐项对应。可以保留有内容的 null+原因，但不能只因文件存在就放行不可定义、缺关键样本或语义不一致的研究结论。

### FAILED 归档与非成功结果

FAILED 仍需要真实终态 Run/Evidence、Manifest 和 `failure_diagnostics`（错误码、失败阶段、已完成步骤、未完成原因；不捏造堆栈或指标）。Manifest 列出全部共同及该类型原定事实角色，已产生的可用字节保留，其余明确 unavailable 或 partial；`failure_diagnostics` 本身须 present/complete。

这类包允许作为**失败诊断记录**消费，但不允许作为完整研究结果输入 Critic 的成功/失败假设判断。若连终态控制记录或故障诊断都未完成，只能保留中断日志材料，不能冒充正式 FAILED 归档。最小归档能力不要求凭空恢复尚未解析出的数据或参数。

策略负收益、统计 IC 为负、数据查出重复，在技术计算完整时仍可为 COMPLETED。`STOP_ECONOMIC_GATE` 属于外部 Review/历史评价背景，不能直接映射为执行 FAILED 或填入纯事实 summary 的评价字段。

### 可选派生角色

`presentation_report`、`chart` 可省略，但**一旦列为 present，交付时仍要检查存在/长度/hash/schema**。损坏/缺失的声明条目使当前完整交付校验失败；可单独读取其他已核验事实作诊断，不能声称整个 Manifest 合格。

事实展示报告只能引用事实。含 recommendation 的评价报告应作为独立 Review 的派生文档，用 Review 绑定 Evidence，不塞进本次事实 Manifest，以免要求不可变事实随评审改写。

## 5. 消费决策与发布完整性

下述是验收约束，**尚未实现运行状态机或校验器**。不得将这些名称直接当作现有 API 状态。

| 检查结果 | 允许消费范围 |
| --- | --- |
| 控制记录缺失、版本未知、引用/hash 不匹配、路径不安全、声明 present 却文件缺失/损坏 | 拒绝正式事实消费；保留错误诊断，不更新原记录 |
| COMPLETED，全部必需角色 present/complete，文件与内容语义核验通过 | 允许读取事实；是否支持假设由独立 Review 判定 |
| FAILED，诊断完整，已列字节完整，未产出角色明确 unavailable/partial | 允许失败诊断和已完成事实的限定读取；不得当完整统计/交易证据 |
| 文件完整，但原始输入/依赖/实现外置且无法取得 | 可按已通过的事实检查限定读取；明确当前不能重算，不声称已复现 |
| NOT_DISPATCHED/PENDING/RUNNING 或草案/null 摘要 | 仅作为草案/进度查看，不能发布终态研究证据 |

发布前必须验证整份引用链、必需角色、所有声明 present 条目及内容；全部通过后才能向消费者暴露“完整交付”的入口。逐个文件原子写入不等于整包发布成功。具体持久化、事务或目录策略留 #513/后续实现，不在本次新建服务。

出现重复传输：准确 Run/Manifest 内容一致可幂等接受；相同 id/revision 而 hash 不同为冲突，拒绝覆盖。迟到结果只归属自己的 Run，不能替换另一 Run 的 Evidence；同输入技术重试不增加独立样本数。

## 6. 三类走查与反例

本次是**规则走查**，无合成真实 hash、无实际读取新 bundle。实际历史材料参考 [#540 三案例](../phase0-validation/README.md)，它们仍是回溯映射，不能自动升级为本候选格式。

| 输入/情况 | 契约预期 |
| --- | --- |
| 数据质量：共同材料+完整审计摘要+合法空异常表，无策略/收益 | 类型可表达；零异常是事实，须核对日历分母与原始序列 |
| 因子：逐样本、每日 IC、统计汇总，IC 为负、无 PnL | 类型可表达，完整执行不因负 IC 变 FAILED；Review 再判断 |
| 回测：成交/权益/汇总齐全，经济门槛未过 | 类型可表达，门槛评价外置，不混淆技术完成 |
| 只复制 #540 的 Git 小文件，external 逐样本或成交文件缺失 | 不可发布完整证据；历史 README 已明确此限制 |
| summary 存在但 trade_blotter 缺失；把该 role 改 optional 或删去 | 完成型交付拒绝；必需集不能由发布者减少 |
| 文件 hash 正确但行数/单位/指标版本与 Evidence 不一致 | 语义核验拒绝；字节完整不代表科学口径正确 |
| FAILED，partial 样本+完整故障诊断+其余缺件原因 | 可归档诊断，不能当完整研究结果 |
| 正常完成却 metrics 文件空白，报告写“0” | 拒绝，不将文件存在、空文件或报告文本当真实零 |
| Manifest 包含自身或 Evidence 文件摘要；Run 再引用 Manifest | 拒绝循环设计；使用 §2 的单向绑定 |
| 同名 snapshot 已被修正、依赖不可定位、超出范围的 symlink | 分别拒绝重算、报告不能重算、拒绝不安全读取；不能追随 latest |
| 可选 chart 声明 present 但缺失 | 完整交付失败；不静默删条目重算旧 Manifest |
| Report 新增“通过”评价，原 Evidence/Manifest 不变 | 创建独立 Review 及其派生报告；不覆写原事实包 |

这些预期还需在正向 v2 输入驱动案例中验证，不能凭本表认定已通过生产消费或完整复现验收。

## 7. 冻结责任与 implementation_ref 待办

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
