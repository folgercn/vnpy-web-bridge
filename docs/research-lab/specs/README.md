# #511 ExperimentSpec 契约候选

状态：**PENDING_OWNER_SIGNOFF**（建议目标状态为 `PROTOCOL_V2_PHASE0_FROZEN`，详见 [Phase 0 Exit Review](../phase0-exit-review.md)）。本目录收口 ExperimentSpec 的字段、类型与拒绝规则。三份正例是未绑定、未执行的设计输入，不是 #540 历史案例的执行记录。冻结本协议不关闭 #511/#498/#538，不解锁 Runner、Worker、Queue 或自动调度。

依据：[Issue #511 最新执行边界](https://github.com/folgercn/vnpy-web-bridge/issues/511#issuecomment-5678136839)、[Protocol v2](../protocol-v2-design.md)、[Hash/Revision/确认规则](../protocol-v2-freeze-gap-closure.md)。本目录不改写上位协议；旧展示模板不必逐字段满足此候选 Schema，不能静默转换为正式记录。

## 1. 职责及身份

| Spec：预期定义，进入 spec_content_hash | Run：实际事实，进入科学计算清单或运行记录 | Evidence / Review |
| --- | --- | --- |
| 精确 Task id/revision/hash、研究类型和阶段 | 精确 Spec id/revision/hash、run_id、retry 引用 | Evidence 绑定确切 Run，保存事实 |
| 版本化方法引用、带类型/单位的参数提案 | 实际代码 revision/源码差异、实现版本、完整生效参数及 seed | 样本数、观测值、缺失原因及 Artifact 引用属于 Evidence |
| 逻辑数据标识、范围、字段、可得性与固定摘要要求/动态选择规则 | 实际 snapshot、原始内容摘要、规范转换、日历与时间凭证 | 通过、拒绝、研究结论属于外部 Review |
| 预期验证方式、标签窗口、holdout 访问规则 | 实际切分、预登记凭据、跨 Task 暴露历史与访问事实 | 改评价标准只新增 Review，不能覆写 Evidence |
| 费用/成交/合约模型声明，指标公式和精度 | 实际依赖锁、环境与计算方法，实际定位路径 | 负收益或数据缺陷不等于程序执行失败 |

Spec 不含物理路径、实际 commit、Worker/Agent 名称或结果。`implementation_ref` 是预期方法的版本化标识；不是“实际运行了该实现”的证明。合约乘数/保证金/费用是本次实验的假设声明，Run 必须核对与记录实际适用的版本和时点，不能把示例数字当作交易所事实。

`parameters` 是有名字、类型、单位和值的显式参数提案数组。名字必须唯一，且由 `implementation_ref` 的版本化方法定义认可；遗漏值只能取该版本的已定义默认值。`value_type=decimal` 必须用规范 Decimal 字符串。定义变更、新参数、新默认值须修订方法/Spec；Run 展开所有默认值。数组顺序参与摘要，不自行排序去重。此版仅覆盖标量参数；结构参数须另版契约评审，不能塞 JSON 字符串绕过校验。

## 2. 两层校验，不能混称“可执行”

[静态 JSON Schema](../../schemas/research-experiment-spec-v2.schema.json) 使用 Draft 2020-12。调用者须启用实际可用的时间格式校验（不能只开启缺少可选格式库的 `FormatChecker`）。本目录审计脚本用标准库显式注册公历 UTC 时间校验。它拒绝未知结构字段、研究类型混入、缺指标元数据、错误参数值类型、物理 URI、关闭拒绝策略、confirmation 缺方案等。

**Schema 合格仅是结构合格。** 以下语义是强制契约，未来执行准入必须全部核对，本次没有实现执行准入器，也没有将文字规则伪装成 JSON Schema 已强制执行：

| 编号 | 执行前必须核对 | 拒绝条件 / 本次走查 |
| --- | --- | --- |
| S1 身份 | 按 research-json-v1 严格解析、规范化并验摘要，核对 Task 引用 | null 摘要仅允许本目录展示模板；正式记录、确认执行一律拒绝。重复键、浮点/指数数字、非法 Unicode、非规范 Decimal 不得静默修正。Hash 仅排除根自身摘要，不展开默认值。 |
| S2 方法/参数 | 引用必须能解析到不可变版本定义；参数名字唯一且类型/单位/范围匹配；能展开默认值 | 不存在的实现、未知参数名、重复参数、用字符串隐藏运行事实、越界窗口均拒绝。本目录 candidate 方法尚无可执行注册实现。 |
| S3 数据 | fixed_snapshot 必须绑定非 null 内容摘要；point_in_time_rule 必须有确定选择/截止/时区规则 | 默认不能追随 latest；动态规则变更需新 Spec，规则内新数据产生新 Run/指纹。逻辑标识不可解析、未知可得时间不能声明 PIT 合格。 |
| S4 时间 | 所有区间为 UTC 闭开区间 [start,end)，start < end；切分须在数据范围内，训练标签不能跨入测试/holdout | 格式正确但范围倒置、训练与测试重叠、purge 未覆盖完整标签区间、未来 receipt 均拒绝。训练数据不足不得缩窗口后继续声称同一 Spec。 |
| S5 确认 | 来源 Spec/Evidence/Review id、revision（适用时）、hash 可核验；主指标存在且版本一致；基准/方向/阈值/seed-fold 汇总事前锁定 | `reserved_confirmation` 的范围须与候选训练/调参样本隔离；必须核对跨 Task 样本重叠、假设族和访问历史。unknown、已暴露、事后改阈值或择优 seed 不允许独立确认。注册时间字符串和摘要本身不是预登记证据。 |
| S6 指标/判据 | 名称及版本解析到本文样例内的明确公式；单位、样本、精度和 null 原因语义一致；每项判据映射到实际声明的指标 | 不得同版本换公式、用别名把 PnL 塞入统计类型，或缺基准/现金流口径时发布数字。不能将结构字段存在视为公式正确。 |
| S7 回测 | 合约/费用参数符合约束；资金/价格步长/乘数>0，保证金(0,1]、费用/滑点>=0；货币一致，percent_equity 在(0,1] | 此候选仅支持单产品 CNY 期货与已声明的成交假设；更多资产/多币种另行评审。确切合约不能由连续价格直接成交；换月先平旧后开新。缺费用/BBO/可得凭证拒绝执行，不置零。 |

对于数据质量审计，待检查的缺失/倒序本身是 Evidence；`failure_action=record` 保证不会因“发现缺陷”冒充“执行失败”。无法读取输入、缺少核对所需日历属于审计无法完成，需记录缺失原因。

## 3. 三类表达及指标

| 正例 | 专属结构 | 不需要/禁止混入 |
| --- | --- | --- |
| [数据质量](spec-data-quality-example.json) | quality_checks、扫描方式、完整性/倒序/包络/换月缺口指标 | strategy、收益、Sharpe |
| [因子统计](spec-statistical-factor-example.json) | feature、target、20 日标签、purge/embargo、样本与 IC/HAC/分组标签差 | 交易成交、成本、交易 PnL |
| [期货回测](spec-trading-backtest-example.json) | signal 方法、下一 bar 成交假设、合约、换月、单边费用、OOS 指标 | 真实订单或实际执行记录 |

每个 `metric_specifications` 条目必须给出：名字、计算定义版本、**完整 calculation_definition**、单位、样本范围、精度和 undefined_policy。版本与公式必须一起验。不是仅列举 `sharpe` 或指向尚不存在的代码。

- IC 明确每日截面、平均秩 ties、有效样本下限、等权跨日平均；HAC 给出 Bartlett 权重和 lag=19，不把重叠标签当独立样本。
- 六品种案例使用 top 2 减 bottom 2，而不是不可平均分配的“五分组”。差值是前瞻标签统计，不是可交易收益。
- Sharpe 使用日净权益简单收益、样本标准差 ddof=1、显式年化 A 与有效年无风险利率转换；回撤包括初始净权益，成交数计 fills 而非订单/往返。
- 费用模型 `candidate.additive_bps_fixed_per_side.v1` 每笔 fill 按 `abs(price*multiplier*lots)*对应开/平今/平昨 bps/10000 + abs(lots)*fixed_commission_per_lot_cny` 相加，滑点每侧按 tick 加到买价/减到卖价，已体现在成交价时不可重复扣除。权益计入未实现损益、双边各自费用与滑点；此示例不允许外部出入金，遇到则拒绝该指标 profile，不能将其当收益。
- 非计数指标最终 ROUND_HALF_EVEN 到 8 位小数再输出规范 Decimal；不舍入中间值。不可定义输出 null 与原因，完整账本的真实零可以保留。

样例方法也必须有定义才能实现：质量检查按指标公式扫描原序列；carry 特征拟采用 `log(far_settlement/near_settlement)*365/(far_expiry-near_expiry 的日数)`，先按到期日及 OI 阈值筛近远合约、再按可得性对齐。统计 target 固定同一选定近月合约，从 t+1 开盘到 t+20 收盘的 log 比率，缺到期前价格则排除并报告。回测示例的 breakout/ATR 方法引用是候选接口，尚未定义完整交易算法，不具备执行条件；不得补猜逻辑或声称已跑通。其作用是验证 Spec 能声明交易语义，真实前向案例另验。

## 4. Holdout / Revision 与兼容

这里的 `holdout_policy` 是 Spec 访问意图，不是 Run 的 `holdout_usage_state`。`not_used` 不代表数据未暴露，也不能给统计/回测 Run 写成 `not_applicable`；实际状态和跨 Task 历史仍遵循上位 §3.1。

三正例均不声称独立 confirmation，`not_used` 必须解释原因。回测 OOS 诊断不自动成为密封 holdout。`reserved_confirmation` 须声明样本范围、假设族、访问规则和跨任务暴露历史要求；实际暴露凭据留 Run。confirmation 还需来源和预登记计划，禁止 parameter_search。

方法/参数、stage、费用、逻辑数据范围或固定 snapshot 内容改变：新 Spec revision。相同准确 Spec 和已锁定科学指纹因技术失败重跑：新 Run，引用原 Run，不改 Spec；新 seed/数据/依赖不能冒充技术重试。完整判定沿用上位 Gap Closure §4。

| 数据 | 读取 | 新记录/执行 |
| --- | --- | --- |
| research_lab.*.v1 | 按原版本解释，保留原始引用 | 本次不改已有 v1 行为；不补造 v2 hash、receipt 或 holdout |
| v2 候选模板 | 按本目录 Schema 做结构走查 | null 绑定、candidate 方法不构成可执行记录 |
| 冻结后的 v2 | 精确版本分派，拒绝未知版本/字段 | 需人工签收与执行准入，不因本 PR 合并自动启用 |

本次静态 Schema 是设计候选。上位 §9.1 的 Pydantic 单一结构源方案仍待签收；后续若采用代码模型，应从该唯一来源生成 Schema，不能维护互相独立的两套权威定义。

JSON 是本次规范输入。YAML 仅可在未来明确无歧义转换规则后作为编辑格式，当前不提供 YAML parser 或将 YAML 默认值/时间解析视为协议。

## 5. 可复核检查及后续出口

在仓库根目录用现有环境运行（不新增依赖）：

```sh
.venv/bin/python docs/research-lab/specs/verify_contract.py.txt
.venv/bin/python -m pytest -q backend/tests/unit/test_ci_workflow_contract.py
```

审计脚本仅做离线 Schema 正反例验证，不是 Runner 或生产准入器；未实现 S1–S7 的完整执行验证。保留可重复的反例以及结构正例，包括三种 sizing、动态数据选择、confirmation 结构。结构 confirmation 用合成摘要，明确不是通过科学验证的案例。

#511 提供此份契约候选供 Review；#524 Artifact、#523 Agent 契约、实际 v2 正向案例和 #498 签字仍需完成，再逐项判断 #538 退出。本 PR 不证明 #540 已变成原生 v2 执行链。
