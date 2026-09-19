# Phase 0 Exit Review & Protocol v2 Freeze Record

生效后的协议状态：**PROTOCOL_V2_PHASE0_FROZEN**（Owner 批准并合并 PR #553 后，本记录即生效；批准合并前为 `PENDING_OWNER_SIGNOFF`）

基线 Commit：`df1019df267b7424bc960dff8b68e01146592665`（PR #552 合并提交）

关联上位门禁：[#538 [Research Lab] Roadmap Gate & Development Order Phase 0 Protocol Foundation](https://github.com/folgercn/vnpy-web-bridge/issues/538)
核心 Issue 集合：
- [#498 Research Task Protocol](https://github.com/folgercn/vnpy-web-bridge/issues/498)
- [#511 Experiment Schema](https://github.com/folgercn/vnpy-web-bridge/issues/511)
- [#523 Agent Prompt Contract](https://github.com/folgercn/vnpy-web-bridge/issues/523)
- [#524 Experiment Artifact Standard](https://github.com/folgercn/vnpy-web-bridge/issues/524)

---

## 1. 评审结论：PASS（建议冻结并退出）

基于 [#538](https://github.com/folgercn/vnpy-web-bridge/issues/538) 原始定义的 Phase 0 五项完成条件，经系统核验 #539～#552 真实代码、机器契约、离线测试及历史验证证据，**本评审建议 Phase 0 Research Protocol Foundation 达到退出标准，Owner 批准并合并 PR #553 后，本记录即生效，协议状态为 PROTOCOL_V2_PHASE0_FROZEN**。

### 核心原则澄清与授权边界（红线）
1. **建议状态不代替人工签收**：本评审由实施者整理提交，最终冻结决策由项目 Owner 审核确认；批准并合并 PR #553 即使本记录生效，无需另一个状态更新提交，亦不授权 Phase 1 实施。
2. **冻结不等于运行授权（Freeze != Runtime Authorization）**：协议冻结仅固化研究语言、对象模式、哈希规范与交接边界；不代表实盘交易授权，不代表生产/Audited 环境授权，亦不代表离线/仿真环境无限制运行授权。
3. **不自动解锁后续基础设施**：本退出建议**严格不自动解锁** Worker Runtime (#505 / #536)、Task Queue (#514)、分布式 Research Farm (#504)、Astra 自动发现 (#502)、Sol 自动调度 (#500) 或 Research Dashboard (#521)。
4. **不可变性约束**：历史归档、bundle、artifact 及历史实验记录保持不可变（保留原有历史标记如 `DRAFT_UNFROZEN`），严禁篡改历史计算事实。
5. **后续阶段路径**：Phase 0 退出后，路线图建议进入 **Phase 1: Experiment Runner + Result Loop**；Phase 1 的具体实施必须另获明确授权。

---

## 2. #538 原始五项完成条件核验矩阵

| 序号 | #538 原始完成条件 | 支撑证据与实现路径 | 评审结论 | 限制与延期说明 (DEFERRED) |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **ResearchTask 语义冻结** | • [#539](https://github.com/folgercn/vnpy-web-bridge/pull/539) 设计正文 §2 对象职责与引用规范；<br>• [#541](https://github.com/folgercn/vnpy-web-bridge/pull/541) Spec 对 Task 的不可变引用绑定；<br>• [#546](https://github.com/folgercn/vnpy-web-bridge/pull/546) [catalogue.json](definitions/catalogue.json) 受控定义与 `Definitions().resolve()`（注：`catalogue.json` 是载荷/方法/判据受控定义目录，非 Task 登记服务）；<br>• [#551](https://github.com/folgercn/vnpy-web-bridge/pull/551), [#552](https://github.com/folgercn/vnpy-web-bridge/pull/552) `validate_handoff` 对 Task 上下文跨对象校验。 | **SATISFIED** | 不提供 Task 运行期调度；后续执行能力另行授权，不阻塞 Phase 0 语义签收。 |
| **2** | **ExperimentSpec 语义冻结** | • [#541](https://github.com/folgercn/vnpy-web-bridge/pull/541) 强类型 JSON Schema (`research-experiment-spec-v2.schema.json`) 与 50 项离线结构检查；<br>• [#546](https://github.com/folgercn/vnpy-web-bridge/pull/546) `validate_spec` 机器化校验入口（位于 `research_lab/contracts/v2.py`）；<br>• [#548](https://github.com/folgercn/vnpy-web-bridge/pull/548) Trend20 统计因子受控 Spec 机器契约；<br>• [#549](https://github.com/folgercn/vnpy-web-bridge/pull/549) Issue481 回测受控 Spec 机器契约；<br>• 明确 S1–S7 强制语义约束与拒绝规则。 | **SATISFIED** | 50 项为静态 Spec 结构检查；运行期动态准入网关（Admission Gate）延期至 Phase 1 Runner，不阻塞协议冻结。 |
| **3** | **Result Contract 冻结** | • [#539](https://github.com/folgercn/vnpy-web-bridge/pull/539) 三层正交解耦模型（执行状态、证据有效性、评审结论）；<br>• [#542](https://github.com/folgercn/vnpy-web-bridge/pull/542) ResultEvidence 事实记录规范；<br>• [#543](https://github.com/folgercn/vnpy-web-bridge/pull/543), [#550](https://github.com/folgercn/vnpy-web-bridge/pull/550) Review 外部独立评审契约与 criteria_ref 跨对象核对；<br>• 事实与评价严格解耦，负事实（负 IC、经济门槛停止）作为有效证据保留。 | **SATISFIED** | 自动 Critic 服务与多重假设检验校正服务延期至 Phase 3。 |
| **4** | **Artifact 规范明确** | • [#542](https://github.com/folgercn/vnpy-web-bridge/pull/542) Artifact 契约与 Manifest Schema (`research-artifact-manifest-v2.schema.json`)；<br>• 明确 Payload 严禁混入 Agent 私有推理、研究结论或人工评价；<br>• Manifest 根级必填字段 `run_id` 与 `run_content_hash`，封闭 role profile；<br>• `classification` (required/supporting) 与交付必需性正交；<br>• `availability` 与 `unavailable_reason` 规范；<br>• [#546](https://github.com/folgercn/vnpy-web-bridge/pull/546) `validate_manifest` 机器化核验原始字节 SHA-256 与 Payload Schema。 | **SATISFIED** | 分布式存储实现与 Manifest 自动发布器延期至 Phase 1+。 |
| **5** | **至少验证三类研究任务**<br>1) 数据质量检查<br>2) 因子/统计研究<br>3) 交易回测研究 | • **数据质量**：[#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 真实 input-driven 端到端 v2 闭环（Task→Spec→Run→Manifest→Evidence→Review），区间驱动行数改变，复跑同指纹，独立消费与审查通过；<br>• **因子统计**：[#540](https://github.com/folgercn/vnpy-web-bridge/pull/540) Trend20 历史计算事实（负 IC 保留） + [#548](https://github.com/folgercn/vnpy-web-bridge/pull/548) Trend20 离线受控契约与 12 位 half-even 精度检验；**明确其完整样本与每日明细外置不可读未取得，测试使用受控 synthetic structural fixtures**；<br>• **交易回测**：[#540](https://github.com/folgercn/vnpy-web-bridge/pull/540) Issue481 回测历史事实（6 账户独立权益、STOP_ECONOMIC_GATE） + [#549](https://github.com/folgercn/vnpy-web-bridge/pull/549) Issue481 离线受控契约核验；**明确其完整成交流水与权益明细外置未取得，测试使用受控 synthetic structural fixtures**。 | **SATISFIED** | 满足 #497/#538“至少一条贯穿真实数据路径 + 三类语义与事实核查”标准。其余两类原生 v2 执行器延期至 Phase 1。 |

---

## 3. M1–M7 最终状态矩阵

| 项 | 规则与定义 | 机器证据与测试覆盖（representative） | 评审建议 | 延期至后续阶段的边界 (DEFERRED) |
| :--- | :--- | :--- | :--- | :--- |
| **M1 三类 Task / Typed Spec** | 数据质量、统计因子、交易回测三类职责与标的池模式清晰，禁止静默降级 | `research-experiment-spec-v2.schema.json`、`specs/verify_contract.py.txt` (50 项结构校验通过)、`test_v2.py`、`test_issue481_backtest.py` | **SATISFIED** | 完整执行器绑定延期至 Phase 1。 |
| **M2 Canonical Hash** | `research-json-v1` 规则：UTF-8、ASCII 键排序、规范 Decimal 字符串、UTC 时间、null/missing、排除自身根哈希 | [#547](https://github.com/folgercn/vnpy-web-bridge/pull/547) 机器化向量：在 `research_lab/contracts/v2.py` 与 `test_v2.py` 中验证，正反例全量通过 | **SATISFIED** | 协议不承诺跨 CPU 浮点绝对一致（强制使用 Decimal 字符串）。 |
| **M3 Revision / Run / 重试** | 区分 Spec 变更与数据变化；确定新 Run 与科学指纹；严禁伪造技术重试 | [#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 真实正向案例复跑验证、[#551](https://github.com/folgercn/vnpy-web-bridge/pull/551) execute_spec 绑定根级 `run_id/run_content_hash`、[#552](https://github.com/folgercn/vnpy-web-bridge/pull/552) revise_spec 版本单向严格递增校验 | **SATISFIED** | 分布式幂等服务延期至 Phase 3。 |
| **M4 复现与证据** | 锁定输入、源码差异、环境依赖、生效参数、种子；至少一条真实端到端路径 | [#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 真实 input-driven 独立消费验证；[#540](https://github.com/folgercn/vnpy-web-bridge/pull/540) 固化另外两类事实；Trend20/Issue481 外置明细当前未取得，测试使用受控 synthetic structural fixtures | **SATISFIED** | 因子与回测的原生正向执行器延期至 Phase 1。 |
| **M5 事实与评审** | Evidence 只存事实（含负事实与缺陷）；Review 为独立追加外部记录 | [#542](https://github.com/folgercn/vnpy-web-bridge/pull/542) Payload 红线、[#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 缺陷事实与诊断包、[#550](https://github.com/folgercn/vnpy-web-bridge/pull/550) review_evidence 机器契约 | **SATISFIED** | 自动 Critic 智能体服务延期至 Phase 3。 |
| **M6 兼容与扩展** | 拒绝未知结构字段、未知版本、未知 role；v1 保持原义，不隐式升级 | Schema `additionalProperties: false`、`catalogue.json` 受控解析、`v2.py` 严格拒绝 | **SATISFIED** | 通用自动迁移适配器延期至 Phase 1+。 |
| **M7 指标与选择过程** | 完整计算公式、单位、样本定义、精度、undefined 处理；确认与预登记语义约束；**保留严格拒绝规则** | Spec README 指标规范、Trend20 (12位 half-even)、Issue481 账户权益；50项 Spec 结构正反例中的代表性确认结构检查；暴露unknown/已暴露/事后择优等为规范拒绝规则，未声称已完成相应runtime核验 | **SATISFIED** | 真实 confirmation 预登记实验与跨任务暴露追踪服务延期至 Phase 2。 |

---

## 4. S1–S7 语义契约与 Runtime 边界裁决

明确区分协议语义定义与执行层 Runtime：

```
+-----------------------------------------------------------------------------------+
| Phase 0 已完成（协议定义与受控离线机器测试）：                                     |
| - S1–S7 语义定义与强制拒绝条件已在规范中严格固化                                   |
| - Typed Spec Schema 已能完整表达所有约束字段                                       |
| - 50 项结构化/语义离线检查与 320 项受限契约测试提供 representative evidence        |
| - 至少一条端到端 input-driven 真实执行路径 (#544)                                  |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
| Phase 1+ 承接（执行层运行时实现）：                                               |
| - Runner 执行准入网关（Admission Gate）动态拦截非法 Spec                           |
| - 真实交易日历与数据物理可得时刻（PIT Receipt）核验器                              |
| - 真实 confirmation 预登记与未见样本执行环境                                       |
| - 跨任务样本暴露追踪注册表与服务                                                   |
| - 全资产/多品种/全指标的通用运行时准入                                             |
+-----------------------------------------------------------------------------------+
```

### S1–S7 逐项边界确认：
- **S1（身份）**：`research-json-v1` 机器化哈希与规范化规则已明确，正式交付拒绝 null 摘要。
- **S2（方法与参数）**：方法必须解析到不可变受控定义，参数类型与单位强校验，默认值显式展开。未登记方法拒绝执行。
- **S3（数据）**：`fixed_snapshot` 必须绑定内容摘要，`point_in_time_rule` 必须有确定规则，无可得凭据严禁声称 PIT 通过。
- **S4（时间）**：UTC 闭开区间 `[start, end)`，严禁区间倒置或时序泄露，purge/embargo 必须覆盖预测窗口。
- **S5（确认）**：预登记凭证、隔离 holdout、禁止事后改阈值或参数搜索的语义已固化；运行时暴露服务延期至 Phase 2。
- **S6（指标与判据）**：公式、单位、样本、精度（如 half-even）与 undefined 处理必须一致，禁止将交易 PnL 塞入统计类型。
- **S7（回测）**：展示候选Spec的单产品CNY约束，不外推为Issue481六账户通用交易准入；参数约束（正资金、正步长、正乘数、保证金在 (0,1]、费用滑点非负），严禁连续价格直接成交，换月先平后开。通用撮合引擎延期至 Phase 1。

---

## 5. 延期至后续阶段清单 (DEFERRED_OUT_OF_PHASE0)

以下事项明确**不属于 Phase 0 阻塞项**，严格延期至后续阶段推进：

1. **FAILED 来源 revise_spec**：延期至 Phase 1+ 异常流与诊断交接演进；
2. **statistical_factor / trading_backtest 的 prepare/revise 跨对象交接**：延期至 Phase 1+ 因子与回测管线建设；
3. **通用任意 data_quality chain revise**：延期至 Phase 1+ 泛化交接机制；
4. **Agent Runtime**：延期至 Phase 3 智能体运行时；
5. **Sol 自动调用 handoff**：延期至 Phase 3 Sol 自动调度编排；
6. **Worker Runtime**：延期至 Phase 3 执行基础设施；
7. **Task Queue**：延期至 Phase 3 调度基础设施；
8. **Astra 自动发现系统**：延期至 Phase 3 策略挖掘系统；
9. **完整 confirmation 真实预登记实验**：延期至 Phase 2 完整研究闭环；
10. **cross-Task exposure runtime/service**：延期至 Phase 2 跨任务暴露追踪服务；
11. **通用完整 S1–S7 Runtime admission gate**：延期至 Phase 1 Experiment Runner 准入网关；
12. **三类 profile 全部重新做原生 v2 正向执行**：延期至 Phase 1 Experiment Runner；
13. **storage runtime / publisher**：延期至 Phase 1+ 产物存储基础设施；
14. **distributed idempotency**：延期至 Phase 3 分布式幂等框架。

---

## 6. 关联 Issue 收口建议

Owner 签收并合并 PR #553 后，按 **#511 → #524 → #523 → #498 → #538** 顺序关闭。后续 Phase 1/2/3 由各自 Issue / milestone 跟踪。具体收口依据如下（**前提需 Owner 接受 Phase 0 范围及相应 runtime 延期；本 PR 绝不自动关闭任何 Issue**）：

1. **[#511 Experiment Schema](https://github.com/folgercn/vnpy-web-bridge/issues/511)**：
   - **建议状态**：Owner 接受 Phase 0 范围及 runtime 延期并合并 PR #553 后，按上述顺序关闭；
   - **依据**：ExperimentSpec Typed Schema、S1–S7 语义定义、50 项结构校验及受控机器契约已在 #541, #546, #548, #549 中全部交付并通过测试；原 Issue 中提及的实际执行类验收已由 #538 顶层规划划归 Phase 1+。
2. **[#524 Experiment Artifact Standard](https://github.com/folgercn/vnpy-web-bridge/issues/524)**：
   - **建议状态**：Owner 接受 Phase 0 范围及 runtime 延期并合并 PR #553 后，按上述顺序关闭；
   - **依据**：Artifact / Manifest 规范、Payload 红线、Manifest Schema 及机器核验已在 #542, #546, #548, #549 中全部交付并通过测试；存储实现与发布器延期至 Phase 1+。
3. **[#523 Agent Prompt Contract](https://github.com/folgercn/vnpy-web-bridge/issues/523)**：
   - **建议状态**：Owner 接受 Phase 0 范围及 runtime 延期并合并 PR #553 后，按上述顺序关闭；
   - **依据**：三角色职责契约、四种交接操作 Schema、criteria_ref 跨对象核对及错误信封已在 #543, #550, #551, #552 中全部交付并通过机器测试；Agent 运行时与自动调用延期至 Phase 3。
4. **[#498 Research Task Protocol](https://github.com/folgercn/vnpy-web-bridge/issues/498)**：
   - **建议状态**：Owner 批准并合并 PR #553 后，签收 Protocol v2 Phase 0 Freeze 并按上述顺序关闭；
   - **依据**：Protocol v2 Phase 0 Freeze 语义与受控机器证据已齐备，M1–M7 均已满足。
5. **[#538 Roadmap Gate Phase 0](https://github.com/folgercn/vnpy-web-bridge/issues/538)**：
   - **建议状态**：Owner 签收并合并 PR #553 后，作为顺序最后一项关闭；
   - **依据**：作为 Phase 0 Gate，在 Phase 0 Exit 后形成明确完成态；Phase 1/2/3 由后续 Issue / milestone 跟踪。

---

## 7. 下一阶段建议：Phase 1 Experiment Runner + Result Loop

依据 #538 路线图，Phase 0 退出后，建议准入的下一阶段为：
**Phase 1: Experiment Runner + Result Loop**（需另获明确授权）

### Phase 1 核心聚焦：
- 落实复用既有运行器路径的轻量级 Experiment Runner；
- 实现基于 S1–S7 的运行时动态准入网关（Admission Gate）；
- 贯通 Spec 输入驱动 → 物理计算执行 → Manifest/Evidence 自动组装的本地结果闭环；
- 严禁在 Phase 1 提前引入 Phase 3 的 Worker/Queue/Astra/Sol 等大型调度架构。
