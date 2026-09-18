# Protocol v2：#498 冻结签收决策

状态：**PROTOCOL_V2_PHASE0_FROZEN**。基线为 `df1019df267b7424bc960dff8b68e01146592665`（包含 #539～#552）。

关联 [#498](https://github.com/folgercn/vnpy-web-bridge/issues/498)、[#538](https://github.com/folgercn/vnpy-web-bridge/issues/538)。完整退出评审见 [Phase 0 Exit Review](phase0-exit-review.md)。

## 1. 结论

**Protocol v2 核心协议语义正式签收并冻结（PROTOCOL_V2_PHASE0_FROZEN）；Phase 0 达到退出标准。**

M1–M7 规则不仅完成了文本定义与纸面走查，更通过 #546～#552 在离线机器契约、受控 catalogue、受限 profile、跨对象 handoff（prepare_spec, execute_spec, review_evidence, revise_spec）及规范化哈希（`research-json-v1`）中获得了完整的代码与自动化测试覆盖（320 项契约测试 + 28 项数据质量案例测试全量通过）。

依据 [#538](https://github.com/folgercn/vnpy-web-bridge/issues/538) 原始定义的五项条件：
1. ResearchTask 语义冻结已完成；
2. ExperimentSpec 语义冻结已完成；
3. Result Contract 冻结已完成；
4. Artifact 规范明确已完成；
5. 三类研究任务验证已满足（数据质量端到端正向 input-driven 执行 + 因子与回测真实历史计算事实保留与受控机器契约）。

协议冻结不代表运行平台或实盘授权，不自动解锁 Phase 3 的 Worker/Queue/Astra/Sol/Dashboard，下一阶段只允许进入 Phase 1（Experiment Runner + Result Loop）。

## 2. 固定证据基线

| PR / 合并提交 | 证据 | 能证明什么及限制 |
| --- | --- | --- |
| #539 / `0bb19e2` | [设计 §11–12](protocol-v2-design.md)、[缺口收口](protocol-v2-freeze-gap-closure.md)、[Hash 向量](protocol-v2-hash-vectors.json) | 精确候选语义、变更表和向量；确立顶层架构与 M1–M7 规则。 |
| #540 / `2c499fe` | [历史三案例](phase0-validation/README.md)及对应输入、方法、事实记录 | 三类真实历史计算事实（数据质量缺陷、因子负 IC、回测经济门槛停止）回溯映射；事实与评审分离。 |
| #541 / `85871c9` | [Spec 规范及 S1–S7](specs/README.md)、[Schema](../schemas/research-experiment-spec-v2.schema.json)、50 项结构审计脚本 | 三类强类型结构与强制语义约束；锁定 S1–S7 拒绝边界。 |
| #542 / `34e8db9` | [Artifact 契约](artifacts/README.md)、Manifest Schema | 身份、Run 绑定、角色/分类正交、失败交付、消费完整性；严禁混入 Agent 私有推理或主观结论。 |
| #543 / `f000e0c` | [Agent 契约](agent-contract/README.md)、Schema、结构审计脚本 | 请求/响应分离、三角色职责边界、精确引用、评审 criteria_ref 跨对象核对、错误信封。 |
| #544 / `f97ef1e` | [验收](../../research/phase0_data_quality/ACCEPTANCE.md)、[独立复核](../../research/phase0_data_quality/INDEPENDENT_REVIEW.md)、[包索引](../../research/phase0_data_quality/ci-bundle-index.json) | 真实 validation 数据质量端到端正向案例与独立消费闭环。输入驱动区间变化（192->60行），复跑同指纹。 |
| #546 / `cf88ba1` | [受控定义 catalogue](definitions/catalogue.json)、[契约 README](../../research_lab/contracts/README.md) | 受控定义目录；提供公共 Spec、Manifest、Review 机器校验入口及 phase0 control/payload schema。 |
| #547 / `e0ae4fd` | [Hash 机器契约](../../research_lab/contracts/canonical_hash.py)、测试向量 | 机器化验证 `research-json-v1` canonical hash 规则，覆盖键排序、Decimal 规范字符串、时间与排除自身摘要。 |
| #548 / `9092bd6` | Trend20 统计因子受限 profile | 机器化绑定 Trend20 特征、标签、每日截面 IC、12位 half-even 精度，消费 #540 负 IC 事实。 |
| #549 / `5a79f45` | Issue481 交易回测受限 profile | 机器化绑定 Issue481 6 账户权益、603 修正事件、STOP_ECONOMIC_GATE (exit code 3) 事实消费与回测 Spec 校验。 |
| #550 / `99f2fff` | `review_evidence` 跨对象契约 | 机器化核验 criteria_ref 一致性、scope 范围匹配与 payload 绑定。 |
| #551 / `40556e3` | `execute_spec` 跨对象契约 | 机器化核验 Task+Spec 绑定、Run/Manifest/Evidence 交付与保留错误信封。 |
| #552 / `df1019d` | `prepare_spec` / `revise_spec` 跨对象契约 | 机器化核验 prepare_spec 提案绑定与 revise_spec 严格来源锚定、payload 消费及 revision 单向递增。 |

## 3. M1–M7 冻结矩阵

| 项 | 已满足与证据 | 延期边界 (DEFERRED_OUT_OF_PHASE0) | 结论 |
| --- | --- | --- | --- |
| M1 三类 Task/Spec | #539 对象职责；#541 三类强类型 Schema 及 S1–S7；#546, #548, #549 机器化 Spec 校验与受控 profile。 | 完整执行器绑定延期至 Phase 1 Runner。 | **SATISFIED** |
| M2 Hash | #547 机器化验证 `research-json-v1` canonical hash vectors，实现于 `v2.py` 与 `test_canonical_hash.py`。 | 协议不承诺跨 CPU 浮点一致（强制规范 Decimal 字符串）。 | **SATISFIED** |
| M3 Revision/Run | #544 真实正向案例复跑同指纹；#551 execute_spec 绑定；#552 revise_spec 严格单向版本递增（rev.1->rev.2）。 | 分布式幂等服务延期至 Phase 3。 | **SATISFIED** |
| M4 复现与证据 | #544 真实 input-driven 正向路径贯穿；#540 固化因子与回测真实历史事实；#548, #549 落实离线机器契约。 | 因子与回测的原生正向执行器延期至 Phase 1。 | **SATISFIED** |
| M5 Evidence/Review | #539 事实解耦；#542 Payload 红线；#544 缺陷事实与 FAILED 诊断包；#550 review_evidence 机器化 criteria_ref 核对。 | 自动 Critic 智能体服务延期至 Phase 3。 | **SATISFIED** |
| M6 兼容与扩展 | Schema `additionalProperties: false` 拒绝未知字段与版本；`catalogue.json` 受控解析；v1 保持原义。 | 通用自动迁移适配器延期至 Phase 1+。 | **SATISFIED** |
| M7 指标与选择 | Spec README 指标定义、精度、undefined 处理；Trend20 精度校验；50 项 confirmation 结构与预登记负例校验。 | 真实 confirmation 预登记实验与跨任务暴露服务延期至 Phase 2。 | **SATISFIED** |

## 4. S1–S7 语义契约与 Runtime 边界

Phase 0 聚焦协议语义与拒绝规则的定义与测试：
- **Phase 0 完成**：S1 身份、S2 方法/参数、S3 数据 PIT、S4 时间切分、S5 确认/预登记、S6 指标/判据、S7 期货回测约束，已全部在规范与 Schema 中明确，并在 `verify_contract.py.txt` (50 项) 和 `test_v2.py` 等测试套件中完成机器化拒绝走查。
- **Phase 1+ 承接**：Runner 执行准入网关（Admission Gate）、真实交易日历/PIT Receipt 核验器、confirmation 运行环境及跨任务暴露追踪服务延期至后续阶段。严禁为提前实现 Admission 而逆向引入 Runner。

## 5. 关联 Issue 收口建议

根据协议冻结与测试证据，建议顺序收口如下（**不自动关闭，等待人工审核**）：
1. **#511**：标记 Phase 0 ExperimentSpec Contract 完成（实际执行类验收划归 Phase 1+）；
2. **#524**：标记 Phase 0 Artifact Contract 完成（存储实现与发布器划归 Phase 1+）；
3. **#523**：标记 Phase 0 Agent Communication Contract 完成（Agent Runtime/Sol 划归 Phase 3）；
4. **#498**：正式签收 Protocol v2 Phase 0 Freeze；
5. **#538**：签收 Phase 0 Exit，解除门禁，准入 Phase 1。

## 6. 核验范围与限制

- 读取并核验了上述全部规范、Schema、受控定义与测试源码；
- 本机环境执行并通过：
  - `research_lab/contracts/` 全量测试套件（320 passed）；
  - `research/phase0_data_quality/test_case.py`（28 passed）；
  - `docs/research-lab/specs/verify_contract.py.txt`（50 structural checks passed）；
  - `backend/tests/unit/test_ci_workflow_contract.py`（9 passed）。
- 本轮未改动任何历史数据包内容，未重跑历史研究计算，未访问 M2，未改动任何实盘或 Audited 配置。
