# Protocol v2：#498 冻结签收建议

状态：**PENDING_OWNER_SIGNOFF**（建议目标状态为 `PROTOCOL_V2_PHASE0_FROZEN`）。基线为 `df1019df267b7424bc960dff8b68e01146592665`（包含 #539～#552）。

关联 [#498](https://github.com/folgercn/vnpy-web-bridge/issues/498)、[#538](https://github.com/folgercn/vnpy-web-bridge/issues/538)。完整退出评审见 [Phase 0 Exit Review](phase0-exit-review.md)。

## 1. 结论

**建议签收已有共同协议语义，建议将协议冻结为 PROTOCOL_V2_PHASE0_FROZEN，建议批准 Phase 0 达到退出标准；但不代替人工签收，亦不授权 Phase 1 实施。**

M1–M7 规则不仅完成了文本定义与纸面走查，更通过 #546～#552 在离线机器契约、受控 catalogue、三类受限 profile、跨对象 handoff（prepare_spec, execute_spec, review_evidence, revise_spec）及规范化哈希（`research-json-v1`）中获得了 representative 机器契约测试覆盖（受限契约测试 320 passed，数据质量案例测试 28 passed，离线结构检查 50 passed）。

依据 [#538](https://github.com/folgercn/vnpy-web-bridge/issues/538) 原始定义的五项条件：
1. ResearchTask 语义冻结：建议认可（Task 语义在 Spec/Run/Handoff 跨对象上下文中受控绑定；`catalogue.json` 仅为载荷与方法受控定义目录，非 Task 登记服务）；
2. ExperimentSpec 语义冻结：建议认可（Schema 结构及 S1–S7 拒绝规则明确）；
3. Result Contract 冻结：建议认可（事实与评价解耦，负 IC 与经济门槛停止作为有效事实保留）；
4. Artifact 规范明确：建议认可（Manifest 根级绑定 `run_id/run_content_hash`，Payload 红线锁定）；
5. 三类研究任务验证：建议认可（数据质量端到端正向 input-driven 执行；Trend20 因子与 Issue481 回测真实历史事实保留 + 受控 synthetic structural fixture 机器契约校验）。

协议冻结不代表运行平台或实盘授权，不自动解锁 Phase 3 的 Worker/Queue/Astra/Sol/Dashboard。Phase 1 仅为路线图建议，其实施需另获明确授权。

## 2. 固定证据基线

| PR / 合并提交 | 证据路径 | 能证明什么及关键限制 |
| --- | --- | --- |
| #539 / `0bb19e2` | [设计 §11–12](protocol-v2-design.md)、[缺口收口](protocol-v2-freeze-gap-closure.md)、[Hash 向量](protocol-v2-hash-vectors.json) | 精确候选语义、变更表和向量；确立顶层架构与 M1–M7 规则。 |
| #540 / `2c499fe` | [历史三案例](phase0-validation/README.md)及对应输入、方法、事实记录 | 三类真实历史计算事实（数据质量缺陷、因子负 IC、回测经济门槛停止）回溯映射；事实与评审分离。非原生 v2 驱动执行，大产物外置。 |
| #541 / `85871c9` | [Spec 规范及 S1–S7](specs/README.md)、[Schema](../schemas/research-experiment-spec-v2.schema.json)、[结构审计脚本](specs/verify_contract.py.txt) | 三类强类型结构与强制语义约束；50 项离线结构检查锁定 S1–S7 拒绝边界。不代表具备 Admission 运行时。 |
| #542 / `34e8db9` | [Artifact 契约](artifacts/README.md)、[Manifest Schema](../schemas/research-artifact-manifest-v2.schema.json) | 身份、根级 `run_id/run_content_hash` 绑定、角色/分类正交、失败交付、消费完整性；严禁混入 Agent 私有推理或主观结论。 |
| #543 / `f000e0c` | [Agent 契约](agent-contract/README.md)、[Handoff Schema](agent-contract/agent-handoff.schema.json) | 请求/响应分离、三角色职责边界、精确引用、评审 criteria_ref 跨对象核对、错误信封。 |
| #544 / `f97ef1e` | [验收](../../research/phase0_data_quality/ACCEPTANCE.md)、[独立复核](../../research/phase0_data_quality/INDEPENDENT_REVIEW.md)、[包索引](../../research/phase0_data_quality/ci-bundle-index.json) | 真实 validation 数据质量端到端正向案例与独立消费闭环。输入驱动区间变化（192->60行），复跑同指纹。单一数据质量案例，不外推其他两类正向执行器。 |
| #546 / `cf88ba1` | [受控定义 catalogue](definitions/catalogue.json)、[契约 README](../../research_lab/contracts/README.md)、[v2 契约代码](../../research_lab/contracts/v2.py) | 受控定义目录（载荷定义、方法源码 SHA 与判据）；提供 Spec、Manifest、Review 受控校验入口。catalogue 不是 Task 注册服务。 |
| #547 / `e0ae4fd` | [Hash 契约实现](../../research_lab/contracts/v2.py)、[契约测试](../../research_lab/contracts/test_v2.py) | 在 `v2.py` 与 `test_v2.py` 中机器化验证 `research-json-v1` canonical hash 规则，覆盖键排序、Decimal 规范字符串、时间与排除自身摘要。 |
| #548 / `9092bd6` | [Trend20 控制与载荷定义](definitions/catalogue.json)、[契约测试](../../research_lab/contracts/test_v2.py) | 机器化绑定 Trend20 特征、标签、每日截面 IC、12位 half-even 精度。完整样本与每日明细外置不可读未取得，测试使用受控 synthetic structural fixtures。 |
| #549 / `5a79f45` | [Issue481 回测定义](definitions/catalogue.json)、[回测契约测试](../../research_lab/contracts/test_issue481_backtest.py) | 机器化绑定 Issue481 6 账户权益、603 修正事件、STOP_ECONOMIC_GATE (exit code 3) 事实消费。完整流水外置未取得，测试使用受控 synthetic structural fixtures。 |
| #550 / `99f2fff` | [review_evidence 契约](../../research_lab/contracts/v2.py)、[交接测试](../../research_lab/contracts/test_review_evidence.py) | 机器化核验 criteria_ref 一致性、scope 范围匹配与 payload 绑定。 |
| #551 / `40556e3` | [execute_spec 契约](../../research_lab/contracts/v2.py)、[交接测试](../../research_lab/contracts/test_execute_spec.py) | 机器化核验 Task+Spec 绑定、Run/Manifest/Evidence 交付与保留错误信封。仅限 data_quality/validation。 |
| #552 / `df1019d` | [prepare/revise 契约](../../research_lab/contracts/v2.py)、[交接测试](../../research_lab/contracts/test_prepare_revise_spec.py) | 机器化核验 prepare_spec 提案绑定与 revise_spec 严格来源锚定、payload 消费及 revision 单向递增。仅限 data_quality/validation 且锚定 #544 来源。 |

## 3. M1–M7 冻结矩阵

| 项 | 已满足与 representative 证据 | 延期边界 (DEFERRED_OUT_OF_PHASE0) | 评审建议 |
| --- | --- | --- | --- |
| M1 三类 Task/Spec | #539 对象职责；#541 三类强类型 Schema 及 S1–S7（50 项结构校验通过）；#546, #548, #549 机器化 Spec 校验与受控 profile。 | 完整执行器绑定延期至 Phase 1 Runner。 | **SATISFIED** |
| M2 Hash | #547 机器化验证 `research-json-v1` canonical hash vectors，实现于 `research_lab/contracts/v2.py` 与 `test_v2.py`。 | 协议不承诺跨 CPU 浮点一致（强制规范 Decimal 字符串）。 | **SATISFIED** |
| M3 Revision/Run | #544 真实正向案例复跑同指纹；#551 execute_spec 校验根级 `run_id/run_content_hash` 绑定；#552 revise_spec 严格单向版本递增（rev.1->rev.2）。 | 分布式幂等服务延期至 Phase 3。 | **SATISFIED** |
| M4 复现与证据 | #544 真实 input-driven 正向路径贯穿；#540 固化因子与回测真实历史事实；#548, #549 落实受限机器契约（明确两类外置明细当前不可读未取得，使用 synthetic structural fixtures）。 | 因子与回测的原生正向执行器延期至 Phase 1。 | **SATISFIED** |
| M5 Evidence/Review | #539 事实解耦；#542 Payload 红线；#544 缺陷事实与 FAILED 诊断包；#550 review_evidence 机器化 criteria_ref 核对。 | 自动 Critic 智能体服务延期至 Phase 3。 | **SATISFIED** |
| M6 兼容与扩展 | Schema `additionalProperties: false` 拒绝未知字段与版本；`catalogue.json` 受控解析拒绝未登记定义；v1 保持原义。 | 通用自动迁移适配器延期至 Phase 1+。 | **SATISFIED** |
| M7 指标与选择 | Spec README 指标定义、精度、undefined 处理；Trend20 精度校验；50项 Spec 结构正反例中的代表性确认结构检查；暴露unknown/已暴露/事后择优等为规范拒绝规则，未声称已完成相应runtime核验。 | 真实 confirmation 预登记实验与跨任务暴露服务延期至 Phase 2。 | **SATISFIED** |

## 4. S1–S7 语义契约与 Runtime 边界

Phase 0 聚焦协议语义与拒绝规则的定义与受控测试：
- **Phase 0 完成**：S1 身份、S2 方法/参数、S3 数据 PIT、S4 时间切分、S5 确认/预登记、S6 指标/判据、S7 期货回测约束，已全部在规范与 Schema 中明确，并在 `verify_contract.py.txt` (50 项离线结构检查) 和 `research_lab/contracts/` (320 项受限测试) 中完成 representative 拒绝走查。
- **Phase 1+ 承接**：Runner 执行准入网关（Admission Gate）、真实交易日历/PIT Receipt 核验器、confirmation 运行环境及跨任务暴露追踪服务延期至后续阶段。严禁为提前实现 Admission 而逆向引入 Runner。

## 5. 关联 Issue 收口建议

根据协议冻结与测试证据，建议顺序收口如下（**前提需 Owner 接受 Phase 0 范围及相应 runtime 延期，本 PR 绝不自动关闭任何 Issue**）：
1. **#511**：建议标记 Phase 0 ExperimentSpec Contract 完成（实际执行类验收划归 Phase 1+）；
2. **#524**：建议标记 Phase 0 Artifact Contract 完成（存储实现与发布器划归 Phase 1+）；
3. **#523**：建议标记 Phase 0 Agent Communication Contract 完成（Agent Runtime/Sol 划归 Phase 3）；
4. **#498**：建议正式签收 Protocol v2 Phase 0 Freeze；
5. **#538**：**保持 OPEN**，继续用于跟踪量化实验室后续 Phase 1/2/3 路线图。

## 6. 人工签收选项（待 Owner Review 确认）

- [ ] 批准上述固定基线的共同协议语义及 M1–M7 所列 representative 验证限度；
- [ ] 确认 Trend20 与 Issue481 完整历史明细当前未取得之现状（受控测试使用 synthetic structural fixtures）；
- [ ] 明确已绑定指标定义与未绑定 candidate 方法的边界，不将候选方法视为可运行实现；
- [ ] 对 #511/#524/#523 建议完成状态及 Phase 0 边界逐项核定，并保持 #538 OPEN 跟踪路线图；
- [ ] Phase 0 退出后建议准入 Phase 1，具体实施另获明确授权。
