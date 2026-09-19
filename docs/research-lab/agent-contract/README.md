# #523 Agent Prompt / Handoff Contract 候选

生效后的协议状态：**PROTOCOL_V2_PHASE0_FROZEN**（Owner 批准并合并 PR #553 后，本记录即生效；批准合并前为 `PENDING_OWNER_SIGNOFF`，详见 [Phase 0 Exit Review](../phase0-exit-review.md)）。本轮只定义角色输入输出、交接引用、Review 和错误表达。没有实现 Agent、Astra、Sol、Worker、Queue、MCP、消息系统、调度器或 Runtime，冻结本协议不自动关闭 #523/#498/#538。

依据：[Issue #523](https://github.com/folgercn/vnpy-web-bridge/issues/523) 与 Owner 本轮 Phase 0 设计授权、[Protocol v2 修订](../protocol-v2-freeze-gap-closure.md)、[#541 Spec 契约](../specs/README.md)、[#542 Artifact 契约](../artifacts/README.md)。旧 Issue 的暂缓评论继续约束运行实现；本次新授权仅推进协议设计。（注：初版草案基于当时尚未合并的 #542，现 #542 依赖已合入主线）。

## 1. Role Contract

角色表示职责，**不授予操作权限**；不指定模型、进程、服务、消息传输或节点。Research 可归纳为提案职责，Execution 为执行事实职责，Critic 为独立评审职责；不改变既有唯一交易 owner 或任何实盘授权。

| 角色 | 输入 | 输出 | 可新增/修改 | 禁止 |
| --- | --- | --- | --- | --- |
| Research Agent | 人类研究目标/约束；已有 Task；后续可以读取已核验 Evidence、Artifact、Review | Task / ExperimentSpec 提案，或新 revision 提案 | 自己尚未发布的提案；发布后只追加新 revision 并保留来源 | 伪造 Run/Evidence、修改已发布事实、把候选提案当执行授权、按结果改旧 Spec |
| Execution Agent | 精确 Task+Spec、版本化方法/数据/环境要求、单独核验的有效授权 | 实际 Run 终态、Artifact Manifest/载荷、ResultEvidence；或明确阻塞/失败 | 在授权范围内记录本次实际执行及阶段事实；终态按上位协议固化 | 改目标/参数/指标定义、用能力代替授权、补猜缺失数据、替 Critic 写研究结论、覆写其他 Run |
| Critic Agent | 精确 Run/Evidence/Manifest、必需 Artifact、Task/Spec 判据、版本化 Review 标准 | 新的独立 Review；可提出改进要求 | 自己未发布的 Review 草案，或追加新 Review/revision | 修改 Evidence/Artifact/旧结果、重新挑参数后反写结论、把执行失败当假设被否定 |

“禁止修改事实”不等于“禁止引用事实”：Research 必须能引用旧 Review 和证据来提出下一版实验。执行层实际代码、snapshot、依赖和展开参数留 Run；交接不重复定义这些字段。人工原始研究想法尚未成为 Task 时，由 Research 草拟 Task，经对象校验/有效授权后再交接；不能凭空填一条不存在的 Task 引用。

### 最小角色提示词约束（仅内容，不是 Agent 实现）

- Research：读取目标、精确来源和反馈，输出可校验提案；未知字段/默认值报告缺口，不臆补；不得改已发布记录。
- Execution：仅按绑定 Spec 和有效授权执行；必需输入或实现不可取得则停止并报告；真实记录异常、缺失和失败，不为满足目标填零或改规则。
- Critic：先核对可消费范围，再按事先声明的标准评审；输出引用证据的理由，不输出私有思维链；新标准只能产生新评审，不能污染原事实。

## 2. Handoff：请求与响应分开

[agent-handoff.schema.json](agent-handoff.schema.json) 是 Draft 2020-12 **静态形状候选**。它不是运行入口或发送 API。一次交接使用 `message_kind=request`；对方用新的 `handoff_id` 返回 `response` 并通过 `in_reply_to` 关联原请求。无 accepted 字段：发送者不能自己声称接收者已接受，更不能声称执行已授权。

| 字段 | 约束 |
| --- | --- |
| schema_version | `research_lab.agent_handoff.v2`；未知版本不可按当前格式猜测 |
| handoff_id / in_reply_to | 不可变交接标识 / 响应对应的请求标识；相同 id 内容不同是冲突，不覆盖旧交接 |
| sender_role / recipient_role | research / execution / critic 的职责映射；不是身份认证、路由地址或 ACL |
| operation | 仅下表四项设计意图；不是调度命令，不能凭 `execute_spec` 开放运行 |
| context_refs | 已存在对象的精确引用；允许跨角色读取引用，**引用不代表拥有写权限** |
| artifact_requirements | 请求必填；固定 role profile、必需角色集和当前已存在 Artifact 的 exact_refs |
| expected_outputs | 请求必填；输出对象类型与 schema_version 列表；不提前分配伪造结果摘要 |
| status / output_refs / problem | 仅响应使用；成功交接交付真实输出引用，非成功返回明确问题，二者互斥 |
| criteria_ref | 仅 review_evidence 请求必填：判据 id、非零 revision、64 位小写 content_hash；不得从 Spec 或模型默认值猜测 |
| review_scope | 仅 review_evidence 请求/响应必填：research_assessment / failure_diagnosis |

`object_ref` 含 object_type、object_id、content_hash；Task/Spec/Manifest/Review 还必须有非零 revision。Run/Evidence 以不可变 id+hash 引用，**不凭空新增 revision**。正式引用不允许 null 摘要。字段中的 object_type 必须和引用槽位一致，不能把 Review 冒充 Spec。

Artifact 精确引用含 `manifest_id/manifest_revision/manifest_content_hash/artifact_id/role/content_sha256`，同时核对该 Manifest 的 Run 绑定。role profile 定义角色必需性，调用方不得减少必需角色或用 Supporting 标签规避成交明细/逐样本数据。执行前尚不存在的输出只能声明 required_roles，不能预填其 exact_refs。缺件/未产出用 problem 报告，不伪造内容摘要。

| operation | 请求方向 | 必需上下文 | expected_outputs |
| --- | --- | --- | --- |
| prepare_spec | Research → Research | Task；可附已有 Review/证据供参考 | ExperimentSpec 提案 |
| execute_spec | Research → Execution | Task、Spec | Run、Manifest、Evidence |
| review_evidence | Execution → Critic | Task、Spec、Run、Manifest、Evidence，至少一个已存在 Artifact 精确引用 | Review |
| revise_spec | Critic → Research | 上述五对象及 Review | 新 ExperimentSpec 提案，不直接改旧版本 |

响应方向反转。Research → Research 只表示提案职责内交接，不要求两个进程。实际参与者身份/能力与授权需独立核验，不能用角色枚举模拟身份；消息传输、超时调度及自动调用均未定义。

## 3. Review Contract

`review_evidence` 请求根级必须显式携带 `criteria_ref: {id, revision, content_hash}`，选定本次评审标准；它是对上位判据引用的交接表达，不新增注册服务或研究对象类型。接收方须解析并核对对应不可变定义；缺引用/格式错误拒绝，定义不可取得则 blocked，版本不支持则 unsupported，摘要不符拒绝。不得从 Spec、历史 Review 或模型默认规则中隐式选择一版。

响应不再复制 criteria_ref，继续交付精确 Review 引用。消费方必须通过 in_reply_to 找到原请求，读取实际输出 Review，并逐项核对其 criteria_ref 的 id/revision/content_hash 与请求一致；任何差异拒绝作为该请求的有效交付。该跨对象核对属于语义准入，单份 Handoff Schema 无法证明，当前未实现 Runtime。

同一份 Evidence 可以先按 rev.1，再用新 handoff_id 指定 rev.2 重评；请求仅改变判据引用及交接标识，原 Task/Spec/Run/Evidence/Artifact 不变。第二次输出新增 Review 或新 Review revision，保留第一次结果；事后标准不能冒充原 Spec 预登记判据。

Critic 必须先校验 Evidence、Manifest 与 Run 的精确引用、内容摘要/载荷及指标口径，再按 #541/#542 的消费边界评审。

| Review 字段/内容 | 规则 |
| --- | --- |
| schema_version、hash_profile、review_id、revision、review_content_hash | 沿用上位 Review；record hash 只排除自身根摘要，保留证据与判据引用；新 revision 不覆写旧版 |
| evidence_id / evidence_content_hash | 精确绑定已存在的终态事实；经 Evidence 的 Manifest 引用定位载荷，不另建循环摘要 |
| reviewer / reviewed_at | 实际评审组件或人的身份记录、合法 UTC 微秒时间；不是密码学认证或权限许可 |
| criteria_ref | 必须与本次请求 criteria_ref 的 id/revision/content_hash 完全一致；同时对照 Spec 预声明目标。事后变更必须如实标记，不能伪称预登记 |
| recommendation / reason | accept / improve / reject 及可核验理由；引用相关 artifact_id/指标事实，不输出 Agent 私有思维链或覆写事实 |

本轮没有新建第二份 Review 实体 Schema；交接只约束输出类型/版本/引用，Review 内容继续由上位协议及最终唯一 Schema 验证。

- `research_assessment`：只消费 #542 规定完整、可读且语义核验通过的 COMPLETED 科学事实。负 IC、负收益可以是有效事实；是否支持目标由 Critic 按判据判断。
- `failure_diagnosis`：可以消费完整的 FAILED 诊断包及明确范围的部分事实，输出故障/证据缺口方面的 Review；禁止据此声称假设成立或被否定。完全缺终态控制记录的中断材料只能作工程诊断，不能冒充正式 Review 证据输入。
- scope 是评审请求范围，响应必须保持相同范围；它不改变 Run 状态，也不自动给 Review 新增字段。接收方必须将范围绑定回原请求后消费。
- `response.status=completed` 表示约定对象已交付并经相应消费规则核验，**不是 Run.COMPLETED 的别名**。例如执行已 FAILED，但失败归档完整，仍可成功交付 Run/Manifest/Evidence；随后只能申请 failure_diagnosis。
- 无初始持仓/权益与现金流核验，不能从零成交推导零损益；数学不可定义用已声明 null+原因，程序异常或必需输入缺失不能伪装成计算完成。

## 4. Error / Blocked Contract

下面四个 status 是**交接响应状态**，不向既有 Run 状态机添加 BLOCKED/UNSUPPORTED。真实 Run 是否已创建、是否终态、是否失败必须查询实际执行事实。

| status | 含义 / code | 必填信息与恢复条件 |
| --- | --- | --- |
| blocked | 请求本可处理，但外部依赖/授权未满足：dependency_unavailable；执行结果未知：execution_outcome_unknown | reason、affected_items、resume_condition、execution_outcome。取得新事实/授权后重新准入；结果未知时先核对原 Run/动作，禁止盲重发 |
| rejected | 输入结构/引用/规则非法：invalid_input | 指明违反项和修正要求。不能静默补字段/改版本/替换摘要后声称原请求有效 |
| incomplete | 已知交付尚不完整：missing_delivery | 列明缺失对象/角色/分片等；先补真实材料并重验，不把缺件当零值或自动重跑计算 |
| unsupported | 当前消费者不支持所请求能力/版本：capability_unsupported | 明确不支持项；等待明确能力或新提案，不自动降级方法或模型 |

`problem` 必须包含 code、reason、非空 affected_items、resume_condition、execution_outcome（not_started / known / unknown）。unknown 强制 blocked+execution_outcome_unknown，优先于 incomplete；恢复说明只是所需条件，不是重新执行授权。所有原始交接及失败历史保留。

非成功响应不填 output_refs；可在 context_refs 引用真实已存在的部分记录，不能把部分交付伪装为成功输出。非法输入中的引用无法解析时，响应 context_refs 可为空，仅用已核验的 in_reply_to 关联请求；不能生成一个假对象填满结构。若连请求 id、角色/operation 都无法可靠解析，应只留拒绝诊断供人工处理，不猜测这些字段伪造正式响应。

本契约不提供自动重试。重复请求/响应的 id 与内容完全一致只能去重读取，不能因此再次执行；相同 id 不同内容拒绝冲突。迟到响应只关联其原请求，禁止覆写其他 Run 或增加独立样本数。

## 5. 自动结构规则与语义准入边界

| 由本 Schema / 本轮离线检查自动覆盖 | 必须在开放执行前实现并验证，当前仍为冻结阻塞 |
| --- | --- |
| 未知字段、角色/operation 组合、请求响应字段分离 | 参与者实际身份、有效授权和能力；角色名不能授权运行 |
| 引用槽位类型、合法摘要格式、适用 revision、必需输入类型 | 解析真实对象及摘要、Task→Spec→Run→Manifest→Evidence 一致性；Run/证据真实终态 |
| operation 所需输出类型、状态/code 一致、未知结果阻断 | 响应 in_reply_to/operation/方向/scope 与原请求一致、输出确实属于该请求，实际 Review.criteria_ref 与请求逐项一致；重复冲突与幂等处理 |
| review_evidence 至少一个 exact_ref；字段完整性 | 固定 profile 完整必需角色与分片集、实际载荷摘要/schema、#541 S1–S7；至少一个引用不等于完整证据 |
| 正式形状拒绝 null 摘要；非成功原因字段必填 | research-json-v1 原始解析约束及规范记录 hash；输入浮点/重复键/Unicode，不能靠 JSON Schema 单独保证 |
| 输出对象版本与类型对应、评审请求判据引用必填及格式 | 方法/内容 Schema 的不可变定义源及版本解析；不支持时明确报错 |

人工作用是检查目标、科学方法与来源证据的合理性，不是豁免自动拒绝条件。未来准入器尚未完成之前，不得因文档和离线形状通过开放 Runtime。

## 6. 示例与验证

所有 `handoff-*.json` 和 `response-*.json` 外层均写 `SYNTHETIC_SHAPE_ONLY_NOT_EXECUTABLE`。其中零摘要只是固定测试常量，**不是算出的真实对象/文件摘要**；没有真实 Run/Evidence/授权，语义准入必然不通过。Schema 仅校验包装内的 `handoff`。包装不是正式协议的一部分，不能忽略包装后宣称样例已可执行。

- Research → Execution：声明数据质量案例预期输出角色，exact_refs 为空，不伪造尚未执行的输出文件。
- Execution → Critic：演示 Manifest+逐角色引用、显式 criteria_ref 及 research_assessment，不声称存在真实历史绑定。
- Critic → Research：保留 Review 及证据来源，输出新 Spec 提案，绝不修改旧记录。
- 四份 response 演示阻塞/拒绝/缺件/不支持，尤其结果未知时不能自动重试。

在仓库根目录用现有环境运行：

```sh
.venv/bin/python docs/research-lab/agent-contract/verify_contract.py.txt
```

这是离线审计脚本文本，不是接入生产的 validator。判据用例额外覆盖缺 id/revision/hash、非法版本/摘要、非评审请求携带判据和同 Evidence 改用 rev.2；输出 Review 选错版本/摘要必须由上述跨对象语义核对拒绝，不列作已通过的结构校验。反例覆盖缺 Task/Spec、缺 revision/hash、错误引用类型、错误角色/输出、错误响应状态、无原因、未绑定摘要、越权添加执行字段。未做真实 bundle、消息投递或 v2 输入驱动计算。

下一步是极小的正向 v2 案例：从真实绑定 Task/Spec 开始，验证准入、实际 Run、Artifact、Evidence 和独立 Review；不能复用 #540 回溯映射冒充正向执行。#498 决定冻结，再逐项判断 #538 退出。本次不提前增加 Runtime。

## 7. #523 restricted offline handoff admission

`research_lab.contracts.v2.validate_handoff` provides fail-closed offline
admission for four operations under registered profiles: `review_evidence`,
`execute_spec`, `prepare_spec`, and `revise_spec`.

For `prepare_spec`, validation is restricted strictly to the
`data_quality/validation` profile. The Research → Research request requires only
a genuine, verified `research_task`. Request-only validation immediately rejects
any Task whose `research_type` is not `data_quality`. It requires no Spec, Run,
or artifacts, keeps `required_roles` and `exact_refs` strictly empty, and
explicitly rejects any unsupported optional context (such as attaching evidence
or reviews). A `completed` response must use a distinct `handoff_id`, reversed
direction, and correct `in_reply_to`, delivering a genuine `experiment_spec`
that binds the `validation` research stage. That Spec must strictly bind to the
requested Task (`task_id`, `task_revision`, `task_content_hash`), align
scientific time and universe with Task data requirements, and pass all existing
method, parameter, snapshot, and metric specification checks.

For `execute_spec`, `validate_handoff` accepts requests and completed deliveries
only for `data_quality/validation`. The request binds exact Task and Spec
records, the fixed candidate role profile, all six required roles, and declares
Run/Manifest/Evidence outputs with empty `exact_refs`. A `completed` response
consumes the archived #544 chain, requiring reverse direction, `in_reply_to`,
terminal Run, all three real output references, complete role delivery, and raw
payload verification. A FAILED Run is only admitted when accompanied by a real
`failure_diagnostics` payload and `typed_metrics=null`.

For `revise_spec`, `validate_handoff` is pinned to the exact archived #544
source identity (exact Task, old Spec, Run, Manifest, Evidence, and Review
records), not any generic self-consistent completed data_quality chain. It
consumes Task, old Spec, Run, Manifest, Evidence, Review, and the required raw
underlying payloads (via `root` safe_read or unmodified `_VerifiedPayloads` from
`validate_manifest`). Any alternate or mutated source chain (even if internally
resealed with valid hashes and payloads) is rejected by the explicit immutable
#544 source identity anchor. The Critic → Research request must bind the verified
#544 source delivery: it requires the actual completed source roles and exact
artifact refs from the Manifest, cross-checked against Evidence and Manifest.
FAILED Run provenance chains are explicitly unsupported (`run_status` must be
`COMPLETED` and `process_exit_code` must be 0). It rejects cross-Run linkage,
mismatched Evidence/criteria references, missing roles, and unverified payloads.
A `completed` response outputs a new `experiment_spec` proposal under the single
explicit key `revised_experiment_spec`. The old Spec and new Spec must be read
simultaneously as two distinct actual objects; in-place replacement of the old
Spec and fallback aliases are forbidden. The revised Spec must bind to the same
Task, maintain the same `spec_id`, preserve `data_quality/validation` type and
stage, and have a strictly increasing revision number (e.g. `rev.1` to `rev.2`),
demonstrating registered parameter revisions such as `source_order.strict`.
Content tampering under the same revision, revision downgrades, cross-Task
rebinding, and forged review handoff fields (`review_scope`, `criteria_ref`)
are rejected.

Non-completed error envelopes (`blocked`, `rejected`, `incomplete`, `unsupported`)
for `prepare_spec`, `execute_spec`, and `revise_spec` follow the reliable error
reporting boundary: `rejected/invalid_input` and `unsupported/capability_unsupported`
can report valid problem envelopes without reading missing future delivery
objects, allowing empty or partially verified `context_refs` without validating
the original request. `blocked` (including unknown execution outcomes) and
`incomplete` strictly require fully admitted input requests. In all non-completed
error envelopes, the response `handoff_id` is required to differ from the
request `handoff_id`.

`validate_handoff` also consumes three registered Review chains: the archived
#544 `data_quality/validation` chain, the Trend20 `statistical_factor/exploration`
profile, and the Issue481 `trading_backtest/validation` profile. Neither Trend20
nor Issue481 supports `prepare_spec` or `revise_spec` cross-object validation.

After Owner approval and merge of PR #553, this protocol record takes effect as
**PROTOCOL_V2_PHASE0_FROZEN**; before then it awaits Owner signoff. It provides no
execution authorization, runtime implementation, scheduling, or retry mechanism.
