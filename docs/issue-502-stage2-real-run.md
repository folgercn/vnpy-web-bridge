# #502 Stage 2：真实结算数据两轮 Discovery 实测

本次运行基于包含 #589、#590 的 `main` 提交 `8338786afb2118f8157bbe9d73940e1c47324ca5` 和本 PR 的信号绑定改动。完整逐槽位索引见 [issue-502-stage2-real-evidence-index.json](issue-502-stage2-real-evidence-index.json)。原始 M2 数据、Provider 原文、Engine bundle、Critic、Memory 和 SQLite 均保留在本机私有目录 `artifacts/stage2_real_runs/run_20260929_stage2_universal_r1_real_v1/`，未纳入 Git；获授权审查者可按索引中的相对路径逐项读取。旧 #590 失败审计与缓存未清理或重写。

## 数据、计算及时间边界

- 来源：M2 Research Warehouse 已提交的 SHFE 日结算数据；精确合约 RB2701、HC2701，19 个源交易日（2026-08-31 至 2026-09-24），频率 1d。私有来源记录 `.git/issue502-stage2-real-data/snapshot-provenance.json` 的 SHA-256 为 `e3d6b6b74d8b6617455bcccf7d6eeed3e4f5fbfe8eca1216f40ad03006725354`；原 32 行快照 SHA-256 为 `4361c48f79345855457d633b962a3ea6975171242a770518c32d89945942624d`，19,489 字节。
- 仅接纳同合约结算价动量 `log(settlement[t] / settlement[t-k])` 与反转 `-log(settlement[t] / settlement[t-k])`，`k=1..3`；本轮十槽使用下表的十个定义。目标固定为同合约 `log(settlement[t+2] / settlement[t+1])`。派生样本按 k 分别为 16、15、14 行；未补造 warm-up、缺值或合约滚动行。
- 时间与 PIT 状态（纠正为 **BLOCKED**）：经独立核验，M2 Research Warehouse 原始提交记录仅包含入库摄取时间戳（`first_seen_at`、`committed_at`），缺乏可验证的 t+1/t+2 市场交易或结算生效时间戳。按审查契约，管道摄取时间不得冒充市场时间；在来源未提供可验证市场生效时间前，真实数据的 Stage 2 PIT 验证严格保持 **BLOCKED**（fail-closed，不杜撰市场时间，不宣称既有 2×10 PIT 通过）。既有 2×10 槽位的原始产物与 Memory 影响矩阵完整保留，供复核受控 Memory 驱动证据需求变化，但受影响范围明确为：不得将其主张为已通过市场时间因果验证的实盘信号。
- 候选科学字段中的公式、参数、方向、目标窗口须通过确定性解析；不支持定义、错绑、无来源或 PIT 失败在 Critic/Memory 前阻断。派生 CSV 的 SHA、字节数、样本数与源摘要逐槽记录。

## 两轮漏斗与逐槽位结果

两轮使用字节相同的 objective（SHA-256 `00454c65a766a540dc9a188af154b7c85e601f552f4a80716b8a1c8450d3e4e4`）、项目、能力范围、策略和 10 槽预算。两轮各 requested/attempted/generated/admitted/绑定通过/进入 Engine = **10/10/10/10/10/10**，Provider 失败、无效、未尝试、工程阻断、exact duplicate、unverified 均为 0；各轮 novel 4/10、related 6/10；momentum 6/10、reversal 4/10。每槽一个 Provider attempt，两轮 20 个不同 job。Round 1 每槽四种方法，共 40 个完成的 Protocol v2 run，Critic 为 REJECT 3、NEED_MORE_EVIDENCE 7，写入 10 条 MemoryRecord。Round 2 每槽六种方法，共新增 60 个完成的 run，Critic 为 REJECT 5、NEED_MORE_EVIDENCE 5，再写入 10 条 MemoryRecord。各项分母均为本轮 10 槽。

| 槽 | 精确合约与信号 | 行数/轮 | R1 Engine→Critic | R2 Engine→Critic |
|---:|---|---:|---|---|
| 01 | RB2701 动量 k=1 | 16 | 4→REJECT | 6→REJECT |
| 02 | RB2701 动量 k=2 | 15 | 4→REJECT | 6→REJECT |
| 03 | RB2701 动量 k=3 | 14 | 4→NEED_MORE_EVIDENCE | 6→NEED_MORE_EVIDENCE |
| 04 | RB2701 反转 k=1 | 16 | 4→NEED_MORE_EVIDENCE | 6→REJECT |
| 05 | RB2701 反转 k=2 | 15 | 4→NEED_MORE_EVIDENCE | 6→NEED_MORE_EVIDENCE |
| 06 | HC2701 动量 k=1 | 16 | 4→REJECT | 6→REJECT |
| 07 | HC2701 动量 k=2 | 15 | 4→NEED_MORE_EVIDENCE | 6→NEED_MORE_EVIDENCE |
| 08 | HC2701 动量 k=3 | 14 | 4→NEED_MORE_EVIDENCE | 6→NEED_MORE_EVIDENCE |
| 09 | HC2701 反转 k=1 | 16 | 4→NEED_MORE_EVIDENCE | 6→REJECT |
| 10 | HC2701 反转 k=2 | 15 | 4→NEED_MORE_EVIDENCE | 6→NEED_MORE_EVIDENCE |

逐槽 JSON 索引给出 Provider job、task、候选 identity/content hash、预检报告、派生快照 SHA/字节数、每个 Engine run/evidence、Critic decision/hash、MemoryRecord、私有原文路径和 R2 所用 Memory refs。Round 1 SQLite 在 Round 2 前后 SHA-256 均为 `99bdcdfc7fa443456f0f2bcc99d42d1be04fc015014525c6892a85375dfb5489`；Round 2 复制后另行持久化，累计 100 run、20 MemoryRecord。

## 可追踪的 Memory 影响

Round 1 初始 Memory A 为 0 条；真实 Engine/Critic 产出的 Memory B 为 23 条，View ID `memview-248d8e4d90e20fee62ca71f14d5967ed`，内容哈希 `a18be8a2c7a68231749f33ea36e09a173f97095269bb9f4cb7fa7e464aab8401`。其中 10 条 research gap、7 条 NME backlog 均指出缺少 `stability_split`、`outlier_sensitivity`。相同 objective 在 Memory A 空时要求四种基础方法；在 Memory B 存在这些有效缺口时，要求候选引用准确 `rmentry-*` 并增加两种方法。R2 十份 **原始 Provider JSON** 均引用有效缺口，候选自身提出六种方法；Engine 的 60 个新 run 与 method definition 证明新增方法实际执行，并非后期改写候选或仅增加文字引用。

例如槽 04：R1 的 RB2701 反转 k=1 经 16 行物理计算、四个 run 后为 NEED_MORE_EVIDENCE，记录 `rmrec-agent-alpha-f1549c737fed6dcc27bb7552-rev.1-1-5bfb2c79602f`；Memory B 的 `rmentry-169d2f09dff1f71cc4446851` 和 `rmentry-27d7e6c709a90ce410176319` 记录缺失的稳定性与离群点证据，且均出现在 R2 原始候选引用中。R2 为同一公式实际执行六个 run，稳定性分段相关性差 `0.7848 >= 0.50`，Critic 因新增的实测风险从 NEED_MORE_EVIDENCE 转为 REJECT。槽 09 的 HC2701 反转 k=1 经 `rmentry-c211423dcabbb6ab9a384312` / `rmentry-2e5328a9ba4040673219bed9` 发生相同证据需求变化，实测分段差 `0.7768 >= 0.50` 后转为 REJECT。两轮缺失证据由四项降至两项，但 `cost_sensitivity` 与样本不足仍未解决。

此处证明的是**受控 Memory 改变候选提出的证据需求，并且新增方法被实际执行**。条件规则本身写在相同 objective 中，故不能将此归因为模型自发学习，也不声称盈利改善、交易可用或生产验收。本轮没有把自动比较强行标为 `is_conclusive=True`，供人工按原始链路复核。

## 复核入口与停止点

获授权且持有本机私有来源的审查者可读取 `round_1/ROUND1_FULL_EVIDENCE.json`、`round_2_real_v1/ROUND2_FULL_EVIDENCE.json` 及索引指定的逐槽原文、预检、Engine bundle 和 SQLite。实际执行入口为 `scripts/run_stage2_universal_round1_real.py --run-id run_20260929_stage2_universal_r1_real_v1` 与 `scripts/run_stage2_universal_round2_real.py --run-id run_20260929_stage2_universal_r1_real_v1`，objective 定义在 `scripts/precheck_stage2_universal_objective_v8.py`；**审查已有运行只读文件，不重放 Provider submit**。需要新运行时使用新的独立 run ID，并先重新确认 Desktop 身份、额度、项目绑定和旧 job 状态。

本 PR 停在 Stage 2 人工验收 Review；#502 保持 OPEN。19 源交易日只支持探索性筛选，且缺交易成本与足量独立样本；所有候选 `is_tradable=False`，无 PROMOTE，也未执行真实交易。
