# Protocol v2 Freeze Gap Closure

状态：`DRAFT_UNFROZEN`。本修订为 #539 提交四项精确候选规则，供 #498 最终 Freeze Review；不是冻结签字、运行实现或 #538 退出证明。与正文相关旧表述不一致时，以本修订为准。

## 1. Hash canonicalization：`research-json-v1`

这是自定义受限 JSON profile，**不是 RFC 8785**。采用限制输入表示的方式保证跨语言一致，不依赖语言默认的 float 序列化。

### 1.1 接受域与唯一字节表示

| 项目 | 必须遵守的规则 |
| --- | --- |
| 输入 | 严格 JSON，UTF-8，无 BOM；解析前拒绝重复键（包括转义后相同的键）、非法 UTF-8、孤立 surrogate、NaN/Infinity。 |
| 对象键 | 只允许非空 ASCII 可打印字符 U+0020–U+007E；递归按 ASCII 码升序排序，区分大小写。不依赖 locale。 |
| 字符串 | Unicode scalar 序列原样保留，不做 NFC/NFD 归一化。双引号与反斜线分别输出 `\"`、`\\`；所有 U+0000–U+001F 统一输出小写十六进制 `\u00xx`，不使用 `\n` 等短转义；其余字符直接 UTF-8，不转义斜线。 |
| JSON 数字 | 仅接受 `0` 或 `-?[1-9][0-9]*`，范围 ±9007199254740991；拒绝负零、小数点、指数形式及超界值。布尔值不作为整数处理。 |
| Decimal / float | Schema 中的小数、金额、比率用 **Decimal 字符串**；格式为 `0` 或 `-?(0\.[0-9]*[1-9]\|[1-9][0-9]*(\.[0-9]*[1-9])?)`。无正号、负零、前导零、指数、末尾小数零；如 `"0.1"`、`"1"`、`"-0.03"`。数量计数仍是 JSON 整数。拒绝非规范表示，不自动四舍五入。计算产生的二进制 float 必须先按版本化指标/算法的精度规则转成 Decimal；该精度规则不属于序列化器，未定义时不可发布正式证据。 |
| 时间 | Schema 声明为 timestamp 的字段只接受合法公历 UTC `YYYY-MM-DDTHH:mm:ss.ffffffZ`，六位微秒，年份 0001–9999，不接受闰秒。本 profile 校验必须拒绝其他表示，不隐式转时区、补零或截断精度；生产者应在构造记录时提供此唯一格式，不能精确表达的时间需另版 profile 决策。日期字段单独使用合法 `YYYY-MM-DD`，不按机器本地时区解释。普通文本不猜测为时间。 |
| null / missing | 二者不同，`null` 输出为 `null`，缺失键不输出；必填字段缺失拒绝，不补 null 或零。 |
| 默认值 | **Hash 不展开默认值**。Task/Spec 记录校验后的显式内容；默认值必须来自其绑定的版本化方法。Run 在执行前将所有生效默认值展开到 `resolved_parameters` 再锁定计算指纹。未绑定版本或无法展开则拒绝启动。显式默认与缺失可以具有不同记录摘要，但相同生效输入指纹。 |
| 数组 | 保留元素顺序与重复元素，不按集合排序。 |
| 输出 | 对象/数组用 JSON 标点，无任何额外空白、BOM 或末尾换行；`true`、`false`、`null` 小写。 |

流程：校验版本和字段类型 → 对指定根记录排除自身摘要 → canonical bytes → SHA-256 → 64 位小写十六进制。不得直接 hash 整个样例外层展示包装。`hash_profile: "research-json-v1"` 是每个正式记录的必填字段，也进入摘要；profile 变更不能静默重算旧记录。

### 1.2 摘要覆盖范围

| 根记录 | 唯一排除的根级字段 |
| --- | --- |
| ResearchTask | `task_content_hash` |
| ExperimentSpec | `spec_content_hash` |
| ExperimentRun 终态快照 | `run_content_hash` |
| ResultEvidence | `evidence_content_hash` |
| Review | `review_content_hash` |

其余字段全部保留，包括上游摘要、schema_version、revision、时间、备注。**不能递归删除所有 `*_hash`**。草案中的 `_...reason` 等说明不是正式 Schema 字段；正式校验器须拒绝未知字段，不能静默剥离后声称草案已成为正式记录。三个展示模板仍未绑定，摘要仍为 null；这是模板豁免，不是正式记录的合法摘要。

原始数据与 Artifact 摘要为原始文件字节的 SHA-256，不做 JSON 规范化、清洗或换行转换。

科学指纹采用相同 canonical bytes/SHA-256 算法，但输入是独立的版本化计算清单，不是整份 Run。清单必含 `hash_profile`、`fingerprint_schema_version`、代码/源码差异/依赖摘要、完整生效参数、实际 seed、数据原始摘要及规范转换/日历/合约规则版本、科学时间/PIT 凭证、切分与实际计算方法；不含主机、路径、调度时间或研究结论。按正文 §3.3 的类型要求绑定，任何必需项未锁定时指纹为 null，禁止猜测相等。各类型精确清单字段由 #511 对齐这些语义，不能通过省略生效输入制造同指纹。

### 1.3 固定向量

见 [固定测试向量](protocol-v2-hash-vectors.json)。`raw_json` 是待解析文本，`canonical_utf8` 是预期输出文本（无换行），`sha256` 是其 UTF-8 字节摘要。`self_hash_field` 非 null 时仅排除该根级字段。`field_types` 指定向量中的 Decimal/timestamp 类型；未声明的字符串不推断类型。向量中的小对象只是算法测试输入，不是完整协议记录；反例必须在产生摘要前拒绝。

## 2. Evidence 与 Review

`ExperimentRun → ResultEvidence → Review`。Evidence 仅保留执行状态、观测指标、样本、单位、事实性诊断和 Artifact 引用。例如重复行数量与按指定规则触发的检查记录是事实；“证据有效”“样本足够”“支持假设”“审计通过”是评价。

`evidence_validity`、`research_conclusion`、`audit_conclusion`、`recommendation` **仅属于外部 Review**，不得写入 Evidence，即使是初始评价或 `NOT_EVALUATED`。未执行模板不创建假 Review，顶层 `review_assessments` 保持空数组。

每条真实 Review 必填：`schema_version: research_lab.review.v2`、`hash_profile`、`review_id`、`revision`、`review_content_hash`、精确 `evidence_id/evidence_content_hash`、`reviewer`、`reviewed_at`、版本化 `criteria_ref`（包含版本与内容摘要）、`recommendation` 和 `reason`。按类型记录有效性与研究/审计结论；不适用的结论不填。新标准、新评审人或修正意见产生新 Review 修订/记录，保留旧记录；不得更新 Evidence 或旧 Review。Review 引用必须指向已存在且摘要匹配的终态事实。

| 对照情况 | Evidence | Review |
| --- | --- | --- |
| 执行失败 | 错误、已完成的观测与缺失原因 | 不据此断言假设被否定 |
| 数据发现重复 | 原始数据摘要、重复数及明细 | 评价此数据是否适用于具体研究 |
| 负收益 | 实测负数、基准事实、成本口径 | 依据预声明目标判断是否支持假设 |
| 未执行 | 展示模板中的 null 与 NOT_EXECUTED | 无真实 Review |
| 更换判据 | 原证据及摘要不变 | 新版本 Review，明确属于事后评价 |

## 3. Research stage 与搜索方式分离

`ExperimentSpec.research_stage` 必填，Run 的 `trial_context.research_stage` 必须与精确 Spec 引用一致，不能由 Worker 自行改阶段。阶段变化产生新 Spec revision；若 Task 目标改变，同时修订 Task。

| stage | 含义与允许解释 |
| --- | --- |
| `exploration` | 可以探索假设、参数、方向；每次定义变化仍产生新 Spec revision，保留所有尝试。不能宣称独立确认。 |
| `validation` | 按声明的方法做数据检查、诊断或候选稳定性检验；反馈可用于下一候选，因而不自动成为未见数据确认。无假设的数据质量审计可使用此阶段，不要求伪造 Alpha 候选。 |
| `confirmation` | 候选及验收方案事前锁定，只检验其是否成立；不得因结果不佳调参后继续称同一次确认。 |

原 `exploration_kind` 改名为 `trial_kind`：`parameter_search`、`replicate_reseed`、`replicate_refold`、`technical_retry` 或不适用时 null。它描述尝试方式，不替代阶段。confirmation 禁止 parameter_search；重复 seed/fold 仅允许已事前声明的序列及汇总规则，不得事后择优汇报。

confirmation Spec 必须包含 `confirmation_plan`：精确候选来源 `source_spec_ref/source_evidence_ref/source_review_ref`（各自 id/revision 如适用及摘要）、预声明主指标与版本化计算定义、基准与判据、样本选择规则/切分、seed/fold/多次检验方案，以及 `registered_at`。整个 Spec 摘要锁定这些字段，作为预登记引用；**不另存引用自身摘要的循环对象**。无这些凭据的草案不得进入确认执行。

Run 执行前另外锁定实际 snapshot 与计算清单，并记录可核验的预登记凭据和跨 Task 的 holdout 暴露历史引用：底层数据摘要、样本范围、假设族及历史事件，不仅记录一个计数。必须证明预登记发生在访问确认结果之前；仅自报时间或 content hash 不能证明这一点。暴露状态 unknown、缺少历史、已据该样本调参，均不能声称独立未见样本确认。新增 task_id、换文件路径或重新命名 snapshot 不重置暴露；样本重叠也必须检查，不能只比较整文件摘要。前瞻数据可事前锁定选择/截止规则，再在执行前解析确切快照。

本次三模板分别标记 validation、exploration、exploration；均未执行。没有捏造 confirmation 通过样例。后续走查至少覆盖：完整预登记可进入确认；缺来源/未知暴露/事后修改判据/事后择优 seed 均拒绝独立确认声明。记录轨迹不等于完成统计校正。

## 4. Revision / Run 决策表

记录 `(id, revision)` 一经发布不可覆写。技术重试要求相同 `(spec_id, spec_revision, spec_content_hash)`（该 Spec 绑定精确 Task）和相同已锁定科学输入指纹；是针对技术失败/中断的再次执行，不是“相同输入必然属于重试”。新 run_id 必须引用原 run_id，保留原失败记录。

| 变化 | Task / Spec | Snapshot / Run |
| --- | --- | --- |
| 参数、方法、特征、成本、信号逻辑改变 | 新 Spec revision；改变目标/Task 记录还需新 Task revision 并重绑 Spec | 新 Run 与相应新指纹 |
| 同一任务/规格/已锁定数据，机器失败后重跑 | 不改 Task/Spec | 新 run_id，retry_of_run_id 指向原记录；指纹必须相同 |
| 失败前数据或参数尚未解析完成 | 不因失败本身改 Spec | 可新 Run，但不得宣称同指纹技术重试；记录未锁定原因 |
| 固定 2024 snapshot 改为含 2025 的 snapshot | 新 Spec revision；若 Task 时间范围也扩大则同时新 Task revision | 新 snapshot、新 Run、新指纹 |
| Spec 事前明确按固定规则读取“截至运行截止日可得数据”，源新增 2025 数据 | Task 允许此时间范围且选择规则未变时可保留 Spec | 锁定新 snapshot、截止时点、新 Run、新指纹；不是技术重试 |
| 同源同名文件历史行被修正 | 若 Spec 固定内容摘要则新 Spec；若符合原动态选择规则可不改 | 内容改变必须新 snapshot、新 Run、新指纹，保留旧内容引用 |
| 仅同内容文件换路径 | 不修改已有发布记录；新 Run 可记录新定位元数据 | 科学指纹不变，Run 内容摘要可不同；不自动算新的独立统计证据 |
| 方法版本未变但实际代码/依赖/seed 改变 | 若违反 Spec 固定要求则先修订 Spec；若属于其明确允许的实现/重复方案则可保留 | 新 Run、新指纹，不能冒充技术重试 |
| exploration 改 confirmation，或事后改变判据 | 新 Spec revision，保留来源及修改时点 | 不溯及既有 Run；已看过样本不能重新宣称未见 |

默认数据选择模式是固定快照；未声明动态选择规则不得自行跟随 latest。草案尚无真实快照时不能执行。重复、迟到结果只绑定自己的 run_id，不覆盖另一 Run；重试与重复观测不能增加独立样本数量。

## 5. 本轮验收边界

本轮只核验规则文本、固定 Hash 向量与三模板一致性。三类真实数据走查、完整指标定义、#498 人工签字、#511/#523/#524 的后续契约验收仍未完成。保持 #538 打开，不解锁 Worker/Queue/Sol/Astra，不因无 P0/P1 就认定协议已冻结。
