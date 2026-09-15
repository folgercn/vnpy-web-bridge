# Phase 0：三个真实历史案例验证（2026-09-15）

基线：PR #539，`0bb19e27a473c5742b3d1a054b9b967a6e041523`。状态仍为 **DRAFT_UNFROZEN**。

## 结论与边界

三个案例均完成真实历史数据计算，并回溯映射 Task → Spec → Run → Evidence → 外部 Review。它们证明三类研究可表达，不等于正式 v2 Schema 验收或 Phase 0 关闭。

- 原始执行起止时间没有被当时的调用捕获，Run 明示 null；`recorded_at` 是此次映射时间，绝不伪装成事前登记。
- confirmation 未执行；样本不是未见 holdout。框架代码、正式 Schema/validator、Worker、Queue、Sol、Astra 均未新增或启动。
- 案例使用派生曲线表及历史模拟撮合输入，不宣称拥有历史 collector received_time，不补造旧数据的 v2 字段。
- 每个案例的 `method`、计算清单字段是本次走查的具体表达，尚未经 #511 正式 Schema 校验。后续冻结审查可据此确定最终映射，不将本目录变成第二套运行协议。

## 三个案例

| 案例 | 输入与实际计算 | 结果 | 验收限度 |
| --- | --- | --- | --- |
| [数据质量](data_quality_example.json) | 归档派生曲线表，2023-01-03—2024-12-31；按所供日历核对六品种覆盖、重复键、时间顺序、结算价和可得日期列 | 35,816 行；484 日 × 6 品种 = 2,904 产品日全部覆盖；上述重复/逆序/无效列值计数均为 0 | 不包含 strategy/PnL；不是交易所原始字节审计、盘中缺口检查或 PIT 认证。日历本身独立真实性未重新审计。 |
| [因子统计](statistical_factor_example.json) | Trend20：同一具体合约 t/t−20 日结算价对数比；标签为同合约 t+1 至 t+6 日结算价对数收益。每品种选 t 日 eligible 且 OI 最大合约，平局按合约名排序 | 478 截面日、2,868 样本；平均每日 Pearson IC `-0.012667903046`；每日 top2−bottom2 前向对数收益均值 `-0.001355555878` | 纯统计，无交易 PnL。每日日截面均值，不是将全部样本混成单一相关系数。标签重叠，未做显著性检验，不宣称独立样本或 Alpha 成立。 |
| [交易回测](trading_backtest_example.json) | 原样执行已有 `scripts/issue481_minimal_causal_replay.py`；六输入摘要匹配 #485，DEV_2023/2024 固定事件路径、合约、换月、单边费用及 BBO 模型 | 607 原事件经既有因果修正为 603；执行 603。成交明细 SHA 与历史完全一致；保留 `STOP_ECONOMIC_GATE` | exit 3 是既有脚本的经济门槛停止，不是执行失败。received_time、涨跌停包络与部分平今手续费是原有模型假设，非真实柜台证明。未调参或改旧结果。 |

因子按年份的事实：

| 区间 | 截面日 | 样本 | 平均 IC | 平均 top2−bottom2 前向对数收益 |
| --- | ---: | ---: | ---: | ---: |
| 2023 | 242 | 1,452 | -0.01770333313 | -0.002017677675 |
| 2024 | 236 | 1,416 | -0.007504453553 | -0.000676600476 |

窗口要求每个具体合约从 t−20 至 t+6 的全部所需日结算价有效，不填补缺失、不拼接换月收益。最后六个交易日没有完整未来标签，排除 36 个产品日。发布值按 12 位小数、half-even 舍入，聚合使用未舍入中间值。

## 输入、隔离及复现差异

输入由 M2 已有 #481 custody 只读复制到本机。来源成员、字节数与摘要见 [input-manifest.json](input-manifest.json)。未修改远端归档，未运行采集、签名、服务或交易命令。

- custody：`/Users/fujun/vnpy-research-upload/issue-481/20260831-local-research-custody/`。
- 只取 gap_resolution、event_bbo、close_today_fee_model 三份已有归档的明确成员；完整原始数据未提交 Git。
- 曲线 CSV 混有范围外行。首次范围预检在计算指标前拒绝，未产生案例结果；随后明确按日期过滤，排除 46,116 条 2024 年后记录，仅对 DEV 和所需 2022 warmup 计算。归档完整字节被复制/校验，不能将这描述为“从未读取过含 holdout 的文件”；没有进行 2025+ 经济分析。
- 数据质量审计对所供 CSV 原始字节绑定摘要，不先去重/排序再计数；过滤研究日期是声明的范围选择。
- 回测 `target-changes.jsonl` SHA：`1a8d0e50e2f96b41e07d875415818021eb04f5683e289706b0488cefd8b294ee`，与 #485 完全相同。
- 回测 summary 与历史仅四项 `directional_pnl_identity_error_cny` 各相差 `1e-10`，见 [差异明细](replay-comparison-differences.json)。不得声明汇总文件字节一致，也不事后改容差掩盖差异。收入/费用/门槛结论没有变化；依然不是跨环境 bitwise 可复现保证。

## 计算指纹与证据

每个 Run 保存：代码 revision、实际案例脚本 SHA、feature/方法版本、输入文件 SHA、有效参数/日期、runtime environment、dependency lock 摘要和计算清单 SHA。运行环境见 [runtime-lock.json](runtime-lock.json)：记录 Python、平台、解释器及使用模块摘要；**不是完整 hermetic 环境镜像**。无外部依赖。

记录哈希遵循 `research-json-v1`，只排除各自根级摘要，保留上游引用。评价只在 `review_assessments`，历史 STOP 决策作为 Review 背景保留，未写成 v2 Evidence 评价字段。旧 #485 summary/comparison 原文件保留本机，不冒充新 v2 纯事实产物。

小型事实与三套协议记录提交本目录。完整逐样本/逐日/成交证据保存在本机 `/tmp/vnpy-phase0-case.Jb6sNB/complete-artifacts/`，以各 Evidence manifest 的 SHA 校验；对应可消费 bundle 位于 `/tmp/vnpy-phase0-case.Jb6sNB/bundle/`，其中 `external/` 具有完整大产物。**仅下载本 Git 目录无法获得全部 Artifact，不可将缺 external 文件的目录发布为完整证据。**

## 复核方法

`*.py.txt` 为原样脚本审计副本。输出 bundle 供读取证据，**不是包含原始输入的可独立重算包**；重算需要 custody 中三份原始 tar 和两个历史基准 JSON。脚本支持 `PHASE0_CASE_ROOT`，在全新根目录运行，不改源码也不覆盖已有证据。记录默认写入该根目录的 `records/`；`PHASE0_RECORD_DIR` 只用于本轮整理 Git 文档。

以下从仓库根目录执行，使用现有 M2 SSH 登录，只读复制原件；不调用远端计算、服务或交易。保留 `compare_replays.py.txt` 的源码摘要于计算指纹，历史 summary 与 paired comparison 两个摘要均纳入 Spec。

```sh
export PHASE0_CASE_ROOT=$(mktemp -d /tmp/vnpy-phase0-case.XXXXXX)
unset PHASE0_RECORD_DIR
mkdir -p "$PHASE0_CASE_ROOT/inputs"
case_docs=docs/research-lab/phase0-validation
for case_script in extract_selected calculate_cases compare_replays build_case_records verify_records; do
  cp "$case_docs/$case_script.py.txt" "$PHASE0_CASE_ROOT/$case_script.py"
done
cp "$case_docs/validation-plan.json" "$PHASE0_CASE_ROOT/"
case_custody=fujun@192.168.100.89:/Users/fujun/vnpy-research-upload/issue-481/20260831-local-research-custody
for case_archive in issue481_gap_resolution_supplement_20260831 issue481_event_bbo_supplement_20260831 issue481_close_today_fee_model_20260831; do
  scp "$case_custody/$case_archive.tar.gz" "$PHASE0_CASE_ROOT/inputs/"
done
for case_baseline in replay-summary.json paired-baseline-comparison.json; do
  scp "$case_custody/20260901-dev-economic-replay-696482d8/$case_baseline" "$PHASE0_CASE_ROOT/inputs/"
done
python3 "$PHASE0_CASE_ROOT/extract_selected.py"
python3 "$PHASE0_CASE_ROOT/calculate_cases.py"
case_replay_rc=0
python3 scripts/issue481_minimal_causal_replay.py \
  --input-root "$PHASE0_CASE_ROOT/selected" \
  --output-dir "$PHASE0_CASE_ROOT/replay" || case_replay_rc=$?
test "$case_replay_rc" -eq 3
python3 "$PHASE0_CASE_ROOT/compare_replays.py"
python3 "$PHASE0_CASE_ROOT/build_case_records.py"
python3 "$PHASE0_CASE_ROOT/verify_records.py"
```

输入 SHA 必须与本目录 input-manifest 及 Spec 中固定摘要对照，变化时不得称为同一实验。提取前强制核对三份归档固定SHA；比较前强制核对两个历史基准固定SHA。脚本仅提取普通文件，不把任意同名归档视为可信原件。首次范围拒绝保留为输入预检失败；新计算不称同指纹技术重试。计划见 [validation-plan.json](validation-plan.json)，不声称外部可信预登记。

本轮已按上述完整命令在 `/tmp/vnpy-phase0-case.Jb6sNB/` 全新根目录实际执行成功，输入三tar和历史两JSON均经过固定SHA核对；记录写入独立records目录，未覆盖旧证据。两次 DQ/因子摘要一致；回放仍为603事件，历史 summary 与 paired comparison 分别仅四项方向残差不同。保留差异，不改容差掩盖。

## 下一步

本轮成果提交 Review；仍需 #498 冻结签收、正式字段/指标定义与 #511/#523/#524 的契约验收。真实案例计算完成不自动关闭 #538，也不打开 #537 或 Worker/Queue/Sol/Astra。
