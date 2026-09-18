# Protocol v2 冻结清单

状态：**PENDING_OWNER_SIGNOFF**（建议目标状态为 `PROTOCOL_V2_PHASE0_FROZEN`）。本清单汇总核验证据，供 [#498](https://github.com/folgercn/vnpy-web-bridge/issues/498) 协议冻结与 [#538](https://github.com/folgercn/vnpy-web-bridge/issues/538) Phase 0 Exit Review 人工审查使用。基线为 `df1019df267b7424bc960dff8b68e01146592665`。完整退出评审见 [Phase 0 Exit Review](phase0-exit-review.md)。

设计正文见 [Protocol v2 设计](protocol-v2-design.md)。规则修订见 [Freeze Gap Closure](protocol-v2-freeze-gap-closure.md)。

---

## 1. 冻结核验状态矩阵（M1–M7）

| ID | 检查项目 | 达成证据与实现 | 延期至后续阶段的边界 (DEFERRED_OUT_OF_PHASE0) | 评审建议 |
| :--- | :--- | :--- | :--- | :--- |
| **M1** | **三类 Task / Typed Spec** | • [#541](https://github.com/folgercn/vnpy-web-bridge/pull/541) 三类 Typed Spec Schema 与 50 项结构校验；<br>• [#546](https://github.com/folgercn/vnpy-web-bridge/pull/546) `validate_spec` 机器校验；<br>• [#548](https://github.com/folgercn/vnpy-web-bridge/pull/548) Trend20 统计因子机器契约；<br>• [#549](https://github.com/folgercn/vnpy-web-bridge/pull/549) Issue481 回测机器契约。 | 完整执行器绑定延期至 Phase 1 Runner。 | **SATISFIED** |
| **M2** | **Canonical Hash** | • [#547](https://github.com/folgercn/vnpy-web-bridge/pull/547) 机器化落实 `research-json-v1` 规则（位于 `research_lab/contracts/v2.py` 与 `test_v2.py`）：UTF-8、ASCII 键排序、规范 Decimal 字符串、UTC 时间、null/missing 处理、排除自身根摘要；正反例测试全量通过。 | 协议不承诺跨 CPU 浮点 bitwise 绝对一致（强制使用 Decimal 字符串）。 | **SATISFIED** |
| **M3** | **Revision / Run / 重试** | • [#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 真实数据质量正向案例驱动 Spec 区间更新（新 revision）及复跑验证（新 run_id，相同科学指纹）；<br>• [#551](https://github.com/folgercn/vnpy-web-bridge/pull/551) execute_spec 绑定 `run_id/run_content_hash` 校验；<br>• [#552](https://github.com/folgercn/vnpy-web-bridge/pull/552) revise_spec 严格单向版本递增（rev.1->rev.2）校验，拒绝篡改旧版或跨 Task。 | 分布式幂等框架延期至 Phase 3。 | **SATISFIED** |
| **M4** | **复现与三类证据** | • [#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 真实 input-driven 端到端 v2 路径（Task→Spec→Run→Manifest→Evidence→Review）与独立消费闭环；<br>• [#540](https://github.com/folgercn/vnpy-web-bridge/pull/540) 固化 Trend20 因子与 Issue481 回测真实历史计算事实；<br>• [#548](https://github.com/folgercn/vnpy-web-bridge/pull/548), [#549](https://github.com/folgercn/vnpy-web-bridge/pull/549) 落实离线受控机器契约（注：Trend20 完整样本明细与 Issue481 完整流水外置不可读未取得，测试使用受控 synthetic structural fixtures；非原生 v2 完整重跑）。 | 因子与回测的原生正向执行器延期至 Phase 1。 | **SATISFIED** |
| **M5** | **事实与评审** | • [#539](https://github.com/folgercn/vnpy-web-bridge/pull/539) 事实与评价解耦架构；<br>• [#542](https://github.com/folgercn/vnpy-web-bridge/pull/542) Payload 红线（严禁混入 Agent 推理、研究结论或人工评价）；<br>• [#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 缺陷事实与 FAILED 诊断包；<br>• [#550](https://github.com/folgercn/vnpy-web-bridge/pull/550) review_evidence 跨对象核对 criteria_ref 一致性与 scope 边界。 | 自动 Critic 智能体服务延期至 Phase 3。 | **SATISFIED** |
| **M6** | **兼容与扩展** | • 静态 Schema `additionalProperties: false` 严格拒绝未知字段；<br>• `catalogue.json` 受控解析拒绝未登记定义；<br>• v1 保留原义，不隐式伪造 v2 字段。 | 通用自动迁移适配器延期至 Phase 1+。 | **SATISFIED** |
| **M7** | **指标与选择过程** | • Spec README 指标定义、单位、样本范围与 undefined 策略；<br>• Trend20 12 位 half-even 精度校验；<br>• Issue481 6 账户权益口径校验；<br>• 50项 Spec 结构正反例中的代表性确认结构检查（50 为 Spec 整体结构正反例总数，非 50 项确认或科学预登记核验）；<br>• **保留严格拒绝规则**：暴露 unknown/已暴露/自报注册时间或 hash 不等登记证据/事后改阈值/从多个 seed 择优等为规范拒绝规则，未声称已完成相应 runtime 核验。 | 真实 confirmation 预登记实验与跨任务暴露服务延期至 Phase 2。 | **SATISFIED** |

---

## 2. 延期至后续阶段事项 (DEFERRED_OUT_OF_PHASE0)

依据 [#538](https://github.com/folgercn/vnpy-web-bridge/issues/538) 顶层规划，以下各项明确分类为 `DEFERRED_OUT_OF_PHASE0`，严格不阻塞 Phase 0 退出：

1. `FAILED 来源 revise_spec`（Phase 1+ 异常流演进）；
2. `statistical_factor / trading_backtest 的 prepare/revise`（Phase 1+ 因子与回测管线）；
3. `通用任意 data_quality chain revise`（Phase 1+ 泛化交接机制）；
4. `Agent Runtime`（Phase 3 智能体运行时）；
5. `Sol 自动调用 handoff`（Phase 3 自动调度系统）；
6. `Worker Runtime`（Phase 3 执行基础设施）；
7. `Task Queue`（Phase 3 调度基础设施）；
8. `Astra 自动发现系统`（Phase 3 策略挖掘系统）；
9. `完整 confirmation 真实预登记实验`（Phase 2 完整研究闭环）；
10. `cross-Task exposure runtime/service`（Phase 2 跨任务暴露追踪服务）；
11. `通用完整 S1–S7 Runtime admission gate`（Phase 1 Experiment Runner 准入网关）；
12. `三类 profile 全部重新做原生 v2 正向执行`（Phase 1 Experiment Runner）；
13. `storage runtime / publisher`（Phase 1+ 产物存储基础设施）；
14. `distributed idempotency`（Phase 3 分布式幂等框架）。

---

## 3. 核心冻结签收确认（待 Owner Review 签署）

以下复选框代表正式人工签收动作，本实施 PR 保持未勾选，由 Owner Review 签收时决定：

- [ ] **批准 M1–M7 共同协议语义及所列 representative 验证限度**：包含 Hash、Revision/Run、事实/评审分离及三类受限机器契约，明确 Trend20/Issue481 完整历史明细当前未取得（使用 synthetic structural fixtures）；
- [ ] **明确已绑定指标定义与未绑定 candidate 方法的边界**：不将候选方法视为可运行实现；
- [ ] **对 #511/#524/#523 建议完成状态及 Phase 0 边界逐项核定**：接受上述 runtime 延期清单，同时 **#538 保持 OPEN** 跟踪后续路线图；
- [ ] **Phase 0 退出后建议准入 Phase 1**：具体实施需另获明确授权，不因本 PR 合并自动解锁任何执行系统。
