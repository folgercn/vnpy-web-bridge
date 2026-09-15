# Phase 0：输入驱动的数据质量单案例

**DRAFT_UNFROZEN**。关联 #538 / #498；不关闭协议门禁，不实现通用 Runner、Worker、Queue、Agent 服务或交易系统。

## 检查什么

只对已有本地历史派生表中的 RB 日期键做 `validation` 顺序审计。原表 SHA-256 为
`f9526c90a515f914d9c26fb2824c27869b171aa17ffd4864258968f4df9a6351`，与
[`#540 input-manifest`](../../docs/research-lab/phase0-validation/input-manifest.json) 一致。

在计算前，人工准备操作从原表选取 `2023-01-03 <= source_official_day < 2023-02-01`、`product=rb`，
只投影 `source_official_day/product/exact_contract` 三列。保留源顺序和所有重复，记录原始行号；
重新序列化为 UTF-8/LF CSV，明确为**派生子集的新快照**，不冒充原表字节。
完整子集随包交付，重算不需要原作者目录或原始 14 MB 表。核查投影来源时才需要外置原表及其固定摘要。
未新增远程访问，未修改原始历史输入。

`source_official_day` 是日期标签，使用 UTC 午夜只是闭开区间的规范表达，**不是采集/到达时间**。
不检查日历覆盖、OHLC、分钟线、换月或 PIT，不声称未来行情、未见 holdout 或 Alpha 验证。

## 最小程序与边界

- `prepare.py`：只准备真实子集、Task、合法 Spec、版本化判据及局部方法/内容定义；不计算质量结果。
- `quality.py`：只按 Spec 扫描原始顺序；`strict=true`（绑定默认）计 `date <= previous`，false 计 `<`；另外列出重复键、严格逆序明细。
- `case.py run`：拒绝缺件/未知方法/摘要不符，展开默认值，将源字节、方法源码与运行环境锁定并落盘，之后记录真实起止时间和结果；不能覆盖已存在的输出目录。
- `case.py verify`：只读独立包，验证各层记录与字节摘要、局部封闭字段/内容定义、完整角色和 Handoff；重新扫描包内输入核对事实。`--require-review` 还要求独立 Review 及关联响应，核对请求判据、Evidence 引用和评审时间。

方法绑定是本例允许的单一 `candidate.phase0.source_order.rev1`，不通过字符串执行任意代码。
Spec/Handoff 使用 #541/#543 已合并 Schema 的固定副本及摘要。其他对象按已有字段职责做本例封闭检查；
`payload.schema.json` 只定义本例载荷，不是第二套公共协议标准。正式权威来源和其余类型仍待 #498 签收。
`input-lock.json` 是本例的事前执行材料，非新增协议核心对象。

摘要链：Task → Spec → 终态 Run → payload Manifest → Evidence → 外部 Review。
Run 不反向引用 Manifest/Evidence；Manifest 不收录控制记录。
共同材料与 `quality_summary/quality_anomalies` 全部必需，即使明细为空。
算法抛错时保留 FAILED、`failure_diagnostics` 和明确 unavailable 的质量载荷；不伪装成零缺陷。
若进程被杀或文件系统导致终态无法落盘，残留目录仅是中断材料，`verify` 拒绝正式消费，不声称崩溃安全发布。

## 复现

从仓库根运行，使用已有 `.venv`（Python 3.12，jsonschema 及其依赖；精确实测环境在包内）。

```sh
case_dir=research/phase0_data_quality
case_work=$(mktemp -d)
tar -xzf "$case_dir/prepared-inputs.tar.gz" -C "$case_work"
.venv/bin/python "$case_dir/case.py" run --inputs "$case_work" --bundle "$case_work/new-run"
.venv/bin/python "$case_dir/case.py" verify --bundle "$case_work/new-run"
.venv/bin/python -m pytest -q "$case_dir/test_case.py"
```

验证已交付包：解包到一个全新目录，然后从该目录外调用包内脚本，指定绝对 bundle 路径：

```sh
case_bundle=$(mktemp -d)
tar -xzf research/phase0_data_quality/bundles/validation-rev1.tar.gz -C "$case_bundle"
.venv/bin/python "$case_bundle/materials/case.py" verify --bundle "$case_bundle" --require-review
```

这些是本 PR 生成并核验的可信归档；不要将命令用于来源不明的归档或任意代码。消费者拒绝 payload symlink、越界路径和不完整文件。
包内包含源码、输入、固定 Schema 与全部事实载荷；Python/依赖由调用者提供。
运行环境记录解释器、所用第三方依赖文件摘要及选定 stdlib；**不是 hermetic OS 镜像**。
复算会重新记录实际环境，按事先固定规则精确比较事实计数/明细，不要求新 Run 的时间和整份摘要相同。

若本机已有明确外置原表，可重新准备两版输入（路径由操作者提供）：

```sh
.venv/bin/python research/phase0_data_quality/prepare.py --source /ABSOLUTE/curve_contract_daily.csv --out /NEW/rev1
.venv/bin/python research/phase0_data_quality/prepare.py --source /ABSOLUTE/curve_contract_daily.csv --out /NEW/rev2 --end 2023-01-10 --revision rev.2
```

两版使用相同源码和原始子集字节，第二版 Spec 缩小扫描区间；不修改计算源码。
准备命令和新 Run 均拒绝覆盖旧目录。同 Spec 重跑生成新 Run，保留既有结果；不增加独立统计样本数，不冒充技术失败重试。

## 验收范围

`test_case.py` 覆盖 Spec 日期/strict 参数驱动、重复/逆序完整产出、8 类启动前拒绝、运行中故障归档、
缺件/损坏/链接/事实不一致、错 criteria_ref、干净目录消费和重跑、严格 JSON 及上位固定 hash 正向向量。
测试中的合成缺陷及测试 Reviewer 明确隔离；不进入真实研究包。
现有 CI 未改动，案例 focused tests 本地执行；远端现有 CI Gate 不代表案例测试已被自动纳入流水线。

最终真实包、事实计数、独立 Review 和命令结果见 [验收记录](ACCEPTANCE.md)。
Hash 和本机落盘顺序只证明本例可检查的完整性/动作次序，不提供外部可信预登记、身份认证或防恶意重写证明。
独立 Review 是离线人的/审阅会话的判断；生产者不自行填写“独立通过”。
