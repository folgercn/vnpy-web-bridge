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

v2 把审计起止、交易日和四个必需时段一起放进被哈希的清单，不再允许只通过命令行临时选择一个能通过的短窗口。清单必须是 UTF-8 普通文件；重复 JSON key、`NaN`/`Infinity`、符号链接、超限文件及两次同一 FD 读取不一致都会 fail closed。运行时按 Draft 2020-12 schema 校验，而非只依赖文档约定。

strict reader 只依赖普通文件类型、同一设备/inode/size、路径与 FD 身份，以及同一已打开 FD 的两次字节内容完全一致；不依赖不同文件系统可能有差异的 ctime/mtime 更新语义。支持本地文件、容器 bind mount 和 overlayfs 普通文件；NFS 等远程文件系统必须先复制到隔离容器内的只读普通文件后再审计。

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
审计时间跨度最多 96 小时，用一个完整交易日覆盖前一有效夜盘和次日日盘；96 小时只为容纳周五夜盘到周一日盘，不允许扩成多周 Tick 扫描。换月品种的旧约和新约必须各有 execution window。

每个 exact contract 查询在 SQL 层固定 `LIMIT 500001`，应用只接受最多 `500000` 行；第 `500001` 行会立即 fail closed，不写成功 evidence。成功 evidence 显式记录 `scanned_rows`、`max_contract_rows_observed` 和查询硬上限，避免 96 小时时间窗变成无界资源扫描。

四个 session window 使用固定中国时间：

| 名称 | 中国时间 | 日期约束 |
|---|---|---|
| `night_open` | 21:00:00–21:02:05 | signed trading day 之前 1–3 个自然日 |
| `night_session` | 21:10:00–21:20:00 | signed trading day 之前 1–3 个自然日 |
| `day_open` | 09:00:00–09:02:05 | signed trading day 当日 |
| `day_session` | 09:10:00–09:20:00 | signed trading day 当日 |

这四个边界不能缩短、重叠或事后移动；周一交易日允许绑定前一周五夜盘。所有 Tick 的非空 `trading_day` 还必须等于 signed trading day。

## 执行

QuestDB DSN 只从隔离运行器挂载的 `0600` 普通文件读取，不作为命令行值或环境变量注入，避免出现在 shell history、进程参数和常驻 backend 环境中。文件必须由当前用户持有、不是符号链接，并在同一已打开 FD 上双读一致：

```bash
PYTHONPATH=backend .venv/bin/python scripts/commodity_c_fast_l1_l5_audit.py \
  --manifest /path/to/c-fast-audit-manifest.json \
  --dsn-file /run/secrets/c-fast-t1-readonly.dsn \
  --expected-endpoint-identity-sha256 <signed-endpoint-sha256> \
  --expected-manifest-sha256 <signed-manifest-sha256> \
  --json-output artifacts/commodity-c-fast-l1-l5-audit.json \
  --csv-output artifacts/commodity-c-fast-l1-l5-audit.csv \
  --markdown-output artifacts/commodity-c-fast-l1-l5-audit.md \
  --readonly-proof-output artifacts/commodity-c-fast-questdb-readonly-proof.json
```

`--start` / `--end` 仅是可选的一致性断言；传入时必须逐值等于 signed manifest，不能覆盖它。

连接固定 `connect_timeout=10s` 和 PGWire `statement_timeout=60000ms`，DSN 文件中的更宽值不能覆盖这两个上限。正式 T1 必须使用 QuestDB 内建的独立 PGWire readonly principal：

- `pg.readonly.user.enabled=true`；
- 当前 `current_user()` 必须等于 `pg.readonly.user`；
- 当前 principal 必须不同于 `pg.user`；
- `pg.readonly.password` 必须来自 `conf`、`env` 或 `file`，不能使用默认值；
- `pg.security.readonly=false`，证明保护来自独立 readonly principal，而不是会同时影响 writer 的全局 PGWire 禁写。
- QuestDB 实例级 `readonly=false`，避免把实例整体只读误归因于 dedicated principal。

脚本在同一连接上于审计前后各执行一次 `SELECT current_user(), build()` 和固定 allowlist 的 `SHOW PARAMETERS` 查询。principal、QuestDB build 或相关可观测配置发生漂移都会 fail closed。四个输出必须使用全新路径且 create-only；JSON、CSV、Markdown 全部成功并关闭数据库连接后才最后发布 readonly proof，失败或重复运行不会覆盖旧 proof。证明过程不执行 `INSERT`、`UPDATE`、DDL 或“试写后期待失败”的权限探针。

建立 PGWire 连接后，脚本从连接对象读取 `host/port/dbname`，按
`{"dbname":...,"host":...,"port":...}` 的 canonical JSON 计算 SHA256，
并与 signed release 的 endpoint expectation 做常量时间比较。proof 只保存
该 SHA256 和 `endpoint_binding_verified=true`，不保存 DSN 或密码。这里绑定的
是 libpq/psycopg 报告的已建立连接参数，不应被表述为网络层 peer
attestation。

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

evidence v2 另外为每个合约时段和 execution window 输出：

- `depth_quality=L5_USABLE/L1_ONLY/UNUSABLE`：只表达盘口深度覆盖；
- `volume_semantics_quality=VALIDATED/INSUFFICIENT/INCONSISTENT`：只表达累计量与 `last_volume` 语义；
- `combined_classification`：继续作为 P0 gate 的综合结论。

因此历史数据可能因为成交量语义尚未验证而从综合 `L5_USABLE` 降为 `DEGRADED`，但不会被误写成深度本身不可用；分析人员应同时查看两个分量。

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
- JSON/CSV/Markdown 与 readonly proof 四个产物的归档位置；
- 十品种分类和全部 blockers。

readonly companion proof 由
`docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json`
约束，并绑定 `snapshot_id`、manifest SHA256 和实际 JSON audit evidence
文件 SHA256。proof 不保存 principal/readonly/admin 用户名、其无盐哈希、DSN 或密码；固定声明：

```text
proof_method=questdb_builtin_pgwire_readonly_user_configuration
same_connection=true
observable_readonly_metadata_stable=true
requested_statement_timeout_ms=60000
write_probe_attempted=false
database_mutations=0
```

`requested_statement_timeout_ms` 是客户端在 PGWire 连接中请求的查询上限，不伪称为服务器回读值。proof 不保存 principal/admin/readonly 用户名或其可字典反推的无盐哈希，也不读取密码内容；`observable_readonly_metadata_stable` 只表示上述 allowlist 元数据在审计前后稳定，不能证明同一配置来源内部的敏感密码内容没有轮换。

该 companion proof 仍不等于 T1 authority。正式执行还必须有独立 one-shot 人工签名 release、隔离 runner、镜像/代码哈希绑定和不可复用的终态封存。启用 QuestDB readonly 用户属于另一个需要人工主审的部署 release；本脚本不会修改 QuestDB 配置，不会替换现有 writer DSN，也不得要求设置 `QDB_PG_SECURITY_READONLY=true` 或实例级 `QDB_READONLY=true`。
companion proof 会记录并核对命令行给定的 endpoint hash，但单独运行时该
expectation 尚未获得签名授权，也不绑定容器或镜像；这些事实必须由后续
signed one-shot release 绑定并在 terminal seal 中归档。

one-shot authority、consume marker、terminal seal 和人工签署步骤见
[`commodity-c-fast-t1-one-shot.md`](commodity-c-fast-t1-one-shot.md)。

本 PR 只交付审计器、evidence schema、测试与 runbook；在真实 QuestDB 上运行前不得宣称 P0 已通过。

历史 `commodity_c_fast_l1_l5_audit_v1` schema 保留不变；v2 才包含 signed trading day、逐时段边界覆盖证据和固定阈值契约。
v2 使用仓库内 `urn:vnpy-web-bridge:schema:*` 资源 ID，并把保留的 v1 schema 显式注入本地 registry；schema resolver 禁止任何外部 retrieval，因此离线容器不会访问 GitHub 或其他网络地址。
