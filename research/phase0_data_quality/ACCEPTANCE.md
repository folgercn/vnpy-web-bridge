# #538 单案例验收记录

状态：**DRAFT_UNFROZEN**。本记录不关闭 #498/#538，不开放运行平台。

## 真实执行

实现固定于 `2155b03` 后，运行 `prepare.py` 两次，
分别持久保存 rev.1 与 rev.2 输入；随后运行三个独立输出目录。不是 #540 的事后对象映射。
运行环境为 Python 3.12.14，其他环境/源码/固定定义摘要见包内 `payload/environment_lock.json`、`materials/preparation.json` 和 `input-lock.json`。

| 包 | Run | Spec 区间（UTC 日期标签闭开） | 行数 | 比较次数 | 顺序缺陷 |
| --- | --- | --- | ---: | ---: | ---: |
| `validation-rev1-corrected` | `run-1f1ed5a273c5457586dd774a971f2f19` | 2023-01-03—2023-02-01 | 192 | 179 | 0 |
| `validation-rev2-corrected` | `run-8e0b4021f5954de59747ef540f60ad2d` | 2023-01-03—2023-01-10 | 60 | 48 | 0 |
| `replay-rev1-corrected` | `run-0df06c25259642fea112f7fce44e77d4` | 2023-01-03—2023-02-01 | 192 | 179 | 0 |

三包输入子集原始字节摘要均为 `fa9a07c2cd55dc04e3300b01ef6ae0fabfb9d0c2b8813796758612cec6a8da19`。
三包源码摘要相同。rev.2 只改 Spec 日期终点与 revision，事实计数实际改变。
rev.1 两次科学指纹均为 `e9fd8849a8b2c67bcae83effa6a74d778bee56510cfbdf9489217a1e494f972f`；
rev.2 为 `343cf17ff275be110d889ee7ad34a7808ba79dd3055dcd5a6d5b5fcf559d2d25`。
每次真实开始/结束时间保留在各 `run.json`，其前置锁定时间在 `input-lock.json`，输入准备时间在 `materials/preparation.json`。
这是本机动作顺序证据，不是外部可信确认性预登记。

## 四项验收

1. **Spec 实际驱动**：上述两个合法 Spec 的真实运行计数改变；另有合成反例验证 strict 参数从 true 改为 false 后，同三行数据顺序违例由 2 变成 1。
2. **缺陷与失败分离**：合成重复/逆序得到 COMPLETED、3 行/2 比较/2 违例/1 重复/1 逆序；原始历史数据未修改。8 类非法前置条件不创建 Run 目录；注入计算异常后生成 FAILED、真实测试故障诊断和 unavailable 质量载荷，不填零。
3. **独立消费**：包内包含完整输入、源码、固定结构/内容定义及全部载荷；干净目录调用包内入口验证、重跑成功。Python/已声明依赖由消费者环境提供。外置大原表仅用于溯源复核，不是计数复算依赖。
4. **错误交付拒绝**：缺明细、损坏汇总、symlink、错误事实（即使重算 Evidence 摘要并更新交接引用）、错误 criteria_ref 均拒绝；版本化 Review 与关联响应不可覆盖旧文件。

## 检查分层

- 本地 focused tests：**28 passed**，包括上位 canonical hash 正向固定向量；合成故障与评审 fixture 不混入真实包。
- 现有 CI 契约测试：**9 passed**。
- Ruff、Python 编译和 diff 空白检查：通过。
- 真实执行：上表三次，全部 COMPLETED；输出包计数由实际 Spec 与原始子集计算。
- 独立代码审查与产物 Review：见 [独立复核记录](INDEPENDENT_REVIEW.md) 及包内 `review.json/review-response.json`。
- 远端 CI Gate 在本 PR 上单独报告；不会将本地案例测试称为远端已纳入的检查。

## 交付与未覆盖

三个完整包在 [bundles/](bundles/)，包的 SHA-256、Run/Spec/Evidence/Review 摘要见 [交付索引](corrected-bundle-index.json)。
`prepared-inputs.tar.gz` 是未执行的 rev.1 准备材料，供重跑与测试；不是带 Review 的完整结果包。
仓库提交仅保留最终真实包，`.work/` 开发目录不属于交付。

未覆盖：其他研究类型执行器、交易日历/OHLC/receipt/PIT、confirmation、跨任务暴露登记、通用消息/调度/鉴权、
防恶意修改与崩溃后自动恢复、完整 hermetic 环境。一次日期顺序检查不代表历史数据可直接用于任何金融研究，
更不代表协议已冻结。#498 仍需按既有清单逐项签收。

## 定点整改记录

初版 README 把输出放进输入目录，实际复现导致递归复制。独立复核发现这一 P1 后，
`2155b03` 修正示例为兄弟目录，并在任何写入前拒绝输入目录内部的输出路径；新增回归并实际重跑 README 命令通过。
上表及 `corrected-bundle-index.json` 对应修正版新 Run；源码包装变更导致新科学指纹，不冒充同指纹技术重试。
初版三个归档和 `bundle-index.json` 保持原字节作为历史，不覆盖旧 Run/Evidence/Review；当前复现入口以 `-corrected` 包为准。
