# 独立审阅记录

审阅者：`Codex /root/forward_dq_review independent reviewer`。

审阅范围为 `ae87305` 的最小 data_quality 正向案例，以及三个正式输出包：
`validation-rev1`、`validation-rev2`、`replay-rev1`。未修改 Task、Spec、Run、Manifest、Evidence 或 payload；仅按各包的 `criteria_ref` 写入 `review.json` 和 `review-response.json`。

## 独立核验

在新建的干净目录复制三个包后，分别运行：

```sh
.venv/bin/python "$bundle/materials/case.py" verify --bundle "$bundle"
```

三个包均通过控制记录、hash、输入锁、时序、引用链、payload 重算和 Manifest 校验。删除干净副本中的 `payload/quality_anomalies.json` 后，验证以 `missing file: payload/quality_anomalies.json` 拒绝。

| 包 | Spec | 行数 / 比较数 | 日期顺序违规 | Review |
| --- | --- | --- | --- | --- |
| `validation-rev1` | `rev.1`，2023-01-03 至 2023-02-01 | 192 / 179 | 0 | `accept` |
| `validation-rev2` | `rev.2`，2023-01-03 至 2023-01-10 | 60 / 48 | 0 | `accept` |
| `replay-rev1` | `rev.1`，与首包相同输入和指纹 | 192 / 179 | 0 | `accept` |

三个 Review 均精确引用对应 Evidence 和 `phase0-date-order-criteria@rev.1`。判据要求违规数不大于 0、比较数至少为 1；三包满足该限定范围。Review 明确不评价日历完整性、PIT、交易所原始字节、Alpha 或 Protocol v2 冻结。

## 结论

本次独立核验未发现 P0/P1。已覆盖：预先锁定输入与 Spec 驱动范围、质量缺陷与执行失败分离的实现测试、干净目录消费、损坏交付拒绝、以及 Review 与 `criteria_ref` 的绑定。

未覆盖：真实交易所原始数据、日历/PIT 证据、其他研究类型、通用 Runner/Agent Runtime 和 Protocol Freeze 签收。

## P1 复核与修正后复验

初版结论后，按 README 原样将输出目录置于输入目录内进行复现，触发了递归复制并最终因路径过长失败。这是 P1：文档承诺的复现命令不能完成。

修订 `2155b03` 将 README 调整为输入目录与输出目录同级，并在任何写入前拒绝输出位于输入目录内（含解析后的路径）。原样执行修订后的 README 命令成功生成并验证新 Run；嵌套输出被 `output must be outside inputs` 拒绝。新增回归后 focused tests 为 28 passed。

随后对新建的 `validation-rev1-corrected`、`validation-rev2-corrected` 和 `replay-rev1-corrected` 完整包独立核验并写入新的 Review。三个包分别得到 192 / 179 / 0、60 / 48 / 0、192 / 179 / 0（行数 / 比较数 / 日期顺序违规），均按 `phase0-date-order-criteria@rev.1` 得到 `accept`。P1 修正增量未发现新的 P0/P1。

## CI 兼容修正复核

远端 CI 报告旧 Ruff `E731` 后，`4c4691c` 仅将 `verify` 内的局部 `lambda` 改为同参数、同返回值的具名函数。未改变验证顺序或语义。因源码摘要进入输入锁与科学指纹，实施者重新准备输入并重跑三包；本审阅会话只读核验后，为 `validation-rev1-ci`、`validation-rev2-ci` 和 `replay-rev1-ci` 写入新的 Review 与响应。

三个 CI 对应包的行数 / 比较数 / 日期顺序违规仍为 192 / 179 / 0、60 / 48 / 0、192 / 179 / 0，均按同一 `phase0-date-order-criteria@rev.1` 得到 `accept`，且 `--require-review` 验证通过。该两行等价修正及其新包未发现 P0/P1。
