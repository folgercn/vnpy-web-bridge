# C_FAST 十品种 L1–L5 盘口数据审计

## 范围与安全边界

这是 Issue #114 的 P0 / PR-A，只回答当前 QuestDB `market_ticks` 是否足以支持后续 book-walk、markout 和成交可行性研究。

- 只对显式给定的 C_FAST 十品种 exact contracts 执行参数化 `SELECT`。
- 不调用 RPC、TradeService、订单、撤单、持仓或策略接口。
- 不修改 QuestDB、部署配置、Shadow 状态或 SimNow 会话。
- 输出中不包含 DSN、账户、RPC 地址、token 或原始 `raw_json`。
- `L2–L5` 缺失时结论只能是 `L1_ONLY` 或更差，不能回退成乐观的 L1 成交概率。
- 五档聚合盘口不能识别排队位置和撤单身份，本工具不输出被动成交点概率。

脚本固定候选和品种：

```text
candidate_id=C_FAST_CROSS_SECTION_NEUTRAL
products=ag,al,au,bu,cu,rb,ru,sc,sp,zn
```

## 输入清单

输入清单必须是 `commodity_c_fast_l1_l5_audit_manifest_v2`，且正好包含十个唯一品种。`exact_contract` 可以使用研究侧 `SHFE.ag2609` 格式，也可以使用 vn.py `ag2609.SHFE` 格式；证据统一保留两种规范化表示。

v2 把审计起止、交易日和四个必需时段一起放进被哈希的清单，不再允许只通过命令行临时选择一个能通过的短窗口。清单必须是 UTF-8 普通文件；重复 JSON key、`NaN`/`Infinity`、符号链接、超限文件及读取期间发生变化都会 fail closed。运行时按 Draft 2020-12 schema 校验，而非只依赖文档约定。

```json
{
  "schema_version": "commodity_c_fast_l1_l5_audit_manifest_v2",
  "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
  "snapshot_id": "c-fast-p0-202608-a01",
  "audit_window": {
    "start": "2026-08-31T12:00:00+00:00",
    "end_exclusive": "2026-09-01T08:00:00+00:00",
    "trading_day": "20260901"
  },
  "session_windows": {
    "night_open": {
      "start": "2026-08-31T13:00:00+00:00",
      "end_exclusive": "2026-08-31T13:02:05+00:00"
    },
    "night_session": {
      "start": "2026-08-31T13:10:00+00:00",
      "end_exclusive": "2026-08-31T13:20:00+00:00"
    },
    "day_open": {
      "start": "2026-09-01T01:00:00+00:00",
      "end_exclusive": "2026-09-01T01:02:05+00:00"
    },
    "day_session": {
      "start": "2026-09-01T01:10:00+00:00",
      "end_exclusive": "2026-09-01T01:20:00+00:00"
    }
  },
  "targets": [
    {
      "product": "ag",
      "exact_contract": "SHFE.ag2609",
      "previous_exact_contract": null,
      "roll_expected": false
    }
  ],
  "execution_windows": [
    {
      "window_id": "ag-202609-open-a01",
      "product": "ag",
      "exact_contract": "SHFE.ag2609",
      "execution_time": "2026-09-01T01:01:00+00:00",
      "window_seconds": 60
    }
  ]
}
```

示例只展示一个 target；正式输入必须补齐全部十品种。发生换月时：

- `roll_expected=true`；
- `previous_exact_contract` 必填且必须与 `exact_contract` 不同；
- 旧约、新约均进入审计；
- 应分别声明覆盖旧约平仓和新约开仓的 execution window。

每个品种至少需要一个 execution window，否则 P0 保持 blocker。时间必须带明确 UTC offset，窗口必须完整落在 signed `audit_window` 内。
审计时间跨度最多 36 小时，用一个完整交易日覆盖前一晚夜盘和次日日盘，避免把多周 Tick 全量装入审计进程。换月品种的旧约和新约必须各有 execution window。

四个 session window 使用固定中国时间：

| 名称 | 中国时间 | 日期约束 |
|---|---|---|
| `night_open` | 21:00:00–21:02:05 | signed trading day 之前 1–3 个自然日 |
| `night_session` | 21:10:00–21:20:00 | signed trading day 之前 1–3 个自然日 |
| `day_open` | 09:00:00–09:02:05 | signed trading day 当日 |
| `day_session` | 09:10:00–09:20:00 | signed trading day 当日 |

这四个边界不能缩短、重叠或事后移动；周一交易日允许绑定前一周五夜盘。所有 Tick 的非空 `trading_day` 还必须等于 signed trading day。

## 执行

QuestDB DSN 只通过环境变量注入，不作为命令行参数，避免出现在 shell history 或进程列表：

```bash
PYTHONPATH=backend .venv/bin/python scripts/commodity_c_fast_l1_l5_audit.py \
  --manifest /path/to/c-fast-audit-manifest.json \
  --json-output artifacts/commodity-c-fast-l1-l5-audit.json \
  --csv-output artifacts/commodity-c-fast-l1-l5-audit.csv \
  --markdown-output artifacts/commodity-c-fast-l1-l5-audit.md
```

`--start` / `--end` 仅是可选的一致性断言；传入时必须逐值等于 signed manifest，不能覆盖它。

使用非默认环境变量名时只传变量名：

```bash
... --dsn-env ISSUE114_QUESTDB_PG_DSN
```

脚本退出码：

- `0`：十品种、所需时段和 execution windows 均为 `L5_USABLE`，无 blocker；
- `1`：审计成功并已写出证据，但 P0 未通过；
- `2`：输入、连接或只读查询失败。

## 固定指标与结论

逐合约和逐时段统计：

- L1–L5 价格、数量及价格/数量成对非零覆盖率；
- `night_open / night_session / day_open / day_session`；
- `received_at - ts` 的 P50/P95/P99/最大值；
- `received_at / ingest_id / ingest_seq / trading_day / last_price` 缺失计数；
- Tick 间隔、重复 exchange timestamp、重复 `ingest_id` 和同 timestamp 重复 `ingest_seq`；
- `ingest_seq <= 0`、跨递增 timestamp 的非递增、回退、重复值和疑似进程重启 reset；
- stale、clock skew、crossed、locked、买卖档位倒挂；
- 累计 `volume` 回退、正差分与 `last_volume` 的匹配关系；少于 10 个正差分或匹配率低于 95% 均降级；
- execution window 前后行数、`window.start→首 Tick`、Tick 内部、`末 Tick→window.end` 三段最大间隔。

阈值在脚本和 JSON evidence 中同时固化。核心分类：

| 结论 | 含义 |
|---|---|
| `L5_USABLE` | L1 完整率至少 99.5%、L5 完整率至少 95%，并通过固定异常阈值 |
| `DEGRADED` | 五档覆盖达到阈值，但 stale、clock skew、crossed/locked、档位倒挂、重复身份、样本量或窗口连续性有问题 |
| `L1_ONLY` | L1 可用，但 L5 完整率不足 95% |
| `UNUSABLE` | 无数据、L1 完整率不足 99.5%，或所需日夜盘/开盘时段缺失 |

`cadence_gap_count` 只记录同一时段内 5–300 秒间隔；大于 300 秒记为 session break，不直接伪装为网络 stale。传输 stale 只按 `received_at - ts > 5s` 判断。
每个必需日/夜盘时段至少需要 20 行、起止边界和内部相邻 Tick 间隔均不超过 5 秒；每个 execution window 至少需要 11 行（首行建立累计量基线，至少留下 10 个可验证差分）且执行时点前后均有 Tick。行数、边界或连续性任一不满足时保持 `DEGRADED`/`UNUSABLE`，不能凭集中在几十秒内的完整快照宣称 P0 通过。
execution window 的起止边界和内部相邻 Tick 间隔都必须不超过 5 秒；只在执行时点附近存在少量 Tick 不构成完整 `±window_seconds` 覆盖。`ingest_seq` 是进程内序列，生产进程重启可能导致 reset；由于当前表没有独立的进程 generation ID，审计会把 reset candidate 明确计入 evidence 并降级，不会静默分段后宣称全窗稳定。

## 证据产物

一次运行产生三个同源产物：

1. JSON：完整不可变 evidence，结构由
   `docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json` 定义，并在写文件前运行时校验；
2. CSV：合约/时段和 execution window 的扁平指标；
3. Markdown：中文结论、blockers 和解释边界。

JSON 固定包含：

```text
read_only=true
database_mutations=0
manifest_sha256=<输入清单规范 JSON 的 SHA256>
```

正式 T1 证据还应在 Issue #114 记录：

- PR/部署 SHA 与镜像；
- 审计 UTC 时间窗和对应中国期货交易日；
- 输入清单 SHA256；
- 三个产物的归档位置；
- 十品种分类和全部 blockers。

本 PR 只交付审计器、evidence schema、测试与 runbook；在真实 QuestDB 上运行前不得宣称 P0 已通过。

历史 `commodity_c_fast_l1_l5_audit_v1` schema 保留不变；v2 才包含 signed trading day、逐时段边界覆盖证据和固定阈值契约。
