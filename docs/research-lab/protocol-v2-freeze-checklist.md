# Protocol v2 冻结清单

状态：**PROTOCOL_V2_PHASE0_FROZEN**。本清单汇总核验证据，用于 [#498](https://github.com/folgercn/vnpy-web-bridge/issues/498) 协议冻结与 [#538](https://github.com/folgercn/vnpy-web-bridge/issues/538) Phase 0 Exit Review。基线为 `df1019df267b7424bc960dff8b68e01146592665`。完整退出评审见 [Phase 0 Exit Review](phase0-exit-review.md)。

设计正文见 [Protocol v2 设计](protocol-v2-design.md)。规则修订见 [Freeze Gap Closure](protocol-v2-freeze-gap-closure.md)。

---

## 1. 冻结核验状态矩阵（M1–M7）

| ID | 检查项目 | 达成证据与实现 | 延期至后续阶段的边界 (DEFERRED_OUT_OF_PHASE0) | 最终状态 |
| :--- | :--- | :--- | :--- | :--- |
| **M1** | **三类 Task / Typed Spec** | • [#541](https://github.com/folgercn/vnpy-web-bridge/pull/541) 三类 Typed Spec Schema 与 50 项结构校验；<br>• [#546](https://github.com/folgercn/vnpy-web-bridge/pull/546) `validate_spec` 机器校验；<br>• [#548](https://github.com/folgercn/vnpy-web-bridge/pull/548) Trend20 统计因子机器契约；<br>• [#549](https://github.com/folgercn/vnpy-web-bridge/pull/549) Issue481 回测机器契约。 | 完整执行器绑定延期至 Phase 1 Runner。 | **SATISFIED** |
| **M2** | **Canonical Hash** | • [#547](https://github.com/folgercn/vnpy-web-bridge/pull/547) 机器化落实 `research-json-v1` 规则：UTF-8、ASCII 键排序、规范 Decimal 字符串、UTC 时间、null/missing 处理、排除自身根摘要；`test_canonical_hash.py` 正反例全量通过。 | 协议不承诺跨 CPU 浮点 bitwise 绝对一致（强制使用 Decimal 字符串）。 | **SATISFIED** |
| **M3** | **Revision / Run / 重试** | • [#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 真实数据质量正向案例驱动 Spec 区间更新（新 revision）及复跑验证（新 run_id，相同科学指纹）；<br>• [#551](https://github.com/folgercn/vnpy-web-bridge/pull/551) execute_spec 绑定校验；<br>• [#552](https://github.com/folgercn/vnpy-web-bridge/pull/552) revise_spec 严格单向版本递增（rev.1->rev.2）校验，拒绝篡改旧版或跨 Task。 | 分布式幂等框架延期至 Phase 3。 | **SATISFIED** |
| **M4** | **复现与三类证据** | • [#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 真实 input-driven 端到端 v2 路径（Task→Spec→Run→Manifest→Evidence→Review）与独立消费闭环；<br>• [#540](https://github.com/folgercn/vnpy-web-bridge/pull/540) 固化 Trend20 因子与 Issue481 回测真实历史计算事实；<br>• [#548](https://github.com/folgercn/vnpy-web-bridge/pull/548), [#549](https://github.com/folgercn/vnpy-web-bridge/pull/549) 落实离线受控机器契约。 | 因子与回测的原生正向执行器延期至 Phase 1。 | **SATISFIED** |
| **M5** | **事实与评审** | • [#539](https://github.com/folgercn/vnpy-web-bridge/pull/539) 事实与评价解耦架构；<br>• [#542](https://github.com/folgercn/vnpy-web-bridge/pull/542) Payload 红线（严禁混入 Agent 推理或研究结论）；<br>• [#544](https://github.com/folgercn/vnpy-web-bridge/pull/544) 缺陷事实与 FAILED 诊断包；<br>• [#550](https://github.com/folgercn/vnpy-web-bridge/pull/550) review_evidence 跨对象核对 criteria_ref 一致性与 scope 边界。 | 自动 Critic 智能体服务延期至 Phase 3。 | **SATISFIED** |
| **M6** | **兼容与扩展** | • 静态 Schema `additionalProperties: false` 严格拒绝未知字段；<br>• `catalogue.json` 受控解析拒绝未登记定义；<br>• v1 保留原义，不隐式伪造 v2 字段。 | 通用自动迁移适配器延期至 Phase 1+。 | **SATISFIED** |
| **M7** | **指标与选择过程** | • Spec README 指标定义、单位、样本范围与 undefined 策略；<br>• Trend20 12 位 half-even 精度校验；<br>• Issue481 6 账户权益口径校验；<br>• 50 项结构校验严格拒绝缺方案、缺预登记、参数搜索等伪确认。 | 真实 confirmation 预登记实验与跨任务暴露服务延期至 Phase 2。 | **SATISFIED** |

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

## 3. 核心冻结签收确认

- [x] **M1–M7 规则与机器证据齐备**：各检查项均已达成，测试套件（320 + 28 + 50 项）全量通过；
- [x] **三类表达与拒绝走查完成**：包含至少一条真实 input-driven 端到端路径 (#544) 以及因子与回测的真实计算事实；
- [x] **S1–S7 协议与 Runtime 边界彻底解耦**：冻结规范语义与拒绝规则，不反向引入 Runner；
- [x] **协议正式进入冻结状态**：标记为 `PROTOCOL_V2_PHASE0_FROZEN`；
- [x] **准入下一阶段**：解除 Phase 0 门禁，下一步进入 Phase 1（Experiment Runner + Result Loop）。
