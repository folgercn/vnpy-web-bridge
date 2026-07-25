# C_FAST T1 release v2 foundation（NO_QUERY）操作边界

## 结论

本切片只冻结未来 T1 release v2 的字段、exact-readiness 绑定和权限下限。
它是 `foundation`，不是可执行 release authority。

当前允许表达的正向字段只有规划事实：

```text
t1_one_shot_child_launch_planned=true
network_query_planned=true
readonly_production_query_planned=true
local_audit_artifact_write_planned=true
```

`planned=true` 只表示未来实现需要覆盖这些能力，不表示当前可以启动 child、
建立网络连接、查询 QuestDB 或写入审计产物。所有实际 authority 必须保持
`false`：

```text
foundation_is_authority=false
packet_is_authority=false
authority_granted=false
readiness_authorized=false
t1_one_shot_child_launch_authorized=false
network_query_authorized=false
readonly_production_query_authorized=false
local_audit_artifact_write_authorized=false
network_authorized=false
production_query_authorized=false
readonly_query_authorized=false
write_probe_authorized=false
database_mutation_authorized=false
deployment_mutation_authorized=false
readonly_principal_deployment_authorized=false
readonly_secret_file_installation_authorized=false
questdb_restart_authorized=false
questdb_recreate_authorized=false
questdb_image_change_authorized=false
writer_identity_mutation_authorized=false
writer_secret_mutation_authorized=false
network_mutation_authorized=false
unscoped_deployment_mutation_authorized=false
web_bridge_deployment_authorized=false
collection_authorized=false
execution_quality_collection_authorized=false
runtime_activation_authorized=false
web_bridge_rpc_authorized=false
order_authorized=false
order_submission_authorized=false
position_mutation_authorized=false
dispatch_authorized=false
trading_authorized=false
strategy_activation_authorized=false
replacement_authorized=false
production_authorized=false
dynamic_selection_allowed=false
automatic_promotion_authorized=false
replay_allowed=false
```

这里的 `local_audit_artifact_write_*` 只指未来 query 产生的 JSON/CSV/Markdown
evidence bundle。foundation 为防 replay 而 create-only 写入的 consume marker 和
`NO_QUERY` harness terminal 是 custody control records，不是查询证据，也不会把
该字段提升为 `true`。

因此，本 foundation 不得用于查询、部署、重启、采集、交易、改仓、dispatch
或自动晋级。

## INVALID/PENDING 模板

[`c-fast-t1-release-v2-foundation.template.json`](c-fast-t1-release-v2-foundation.template.json)
是人工核对字段的清单，明确为：

```text
INVALID
PENDING
NOT_SIGNABLE
NOT_AUTHORITY
NO_QUERY
```

模板包含 `PENDING_` placeholder、把 `max_runtime_seconds` 保留为未决字符串，
并故意省略 required `signature`。因此它不能通过
[`commodity-c-fast-t1-one-shot-release-v2.schema.json`](../schemas/commodity-c-fast-t1-one-shot-release-v2.schema.json)，
不能传给 release consumer，也不能被“补一个签名”后直接投入运行。

当前切片没有 signer，只包含严格先后两次完成全链验证的 `NO_QUERY`
foundation consumer；它只会 create-only 消费 attempt、重验 readiness 和
release/manifest/keyring/runtime 原始绑定并生成 harness terminal，不包含
child/query callback，也没有生产 query runner。任何人都不得
通过手工删除 `PENDING_`、复制 v1 signature、修改 schema 或绕过 validator
把模板转换成 authority。未来如需真实 query，必须在独立 PR 中实现并审查完整的
query authority、one-shot child、timeout/unknown 和 query terminal 状态机。

可用下面的只读命令确认模板当前确实无效：

```bash
PYTHONPATH=scripts .venv/bin/python - <<'PY'
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

root = Path.cwd()
template = json.loads(
    (
        root
        / "docs/operations/c-fast-t1-release-v2-foundation.template.json"
    ).read_text(encoding="utf-8")
)
schema = json.loads(
    (
        root
        / "docs/schemas/commodity-c-fast-t1-one-shot-release-v2.schema.json"
    ).read_text(encoding="utf-8")
)
errors = list(
    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).iter_errors(template)
)
if not errors:
    raise SystemExit("ERROR: PENDING template unexpectedly became schema-valid")
print(f"expected INVALID/PENDING template errors: {len(errors)}")
PY
```

该命令只读取本地文件，不签名、不连接网络、不查询数据库。

## exact-readiness 规划绑定

foundation 规划未来 release 必须绑定同一份短 TTL readiness v2 packet 的：

- packet ID、raw SHA256、canonical SHA256、生成和过期时间；
- content attestation 的 raw/canonical SHA256；
- signed build/registry provenance 的 raw/canonical SHA256 和实际验签 signer
  public-key SHA256；
- signed deployment outcome 的 raw/canonical SHA256 和实际验签 signer
  public-key SHA256；
- T1 runtime、L3 contract、outcome contract、QuestDB image 五个隔离 namespace；
- readiness source bundle index；
- manifest raw/canonical SHA256、snapshot、审计窗口、endpoint 和 QuestDB build；
- release、consume、harness terminal、readiness verifier 和 readiness schema 的
  exact SHA256。

这些字段现在只是待人工核对的冻结形状。它们不会把非权威 readiness packet
提升为 authority。未来任何真实 query 前，runner 仍必须从原始 inputs 重新验证
当前有效的 readiness v2；只比较手填 hash 或非权威 receipt 不足以获得权限。

## harness terminal 不是 P0

当前配套 terminal 是
`commodity_c_fast_t1_harness_terminal_v2`，只允许：

```text
HARNESS_REVALIDATED_NO_QUERY
FAILED_FINAL_READINESS_REVALIDATION_NO_QUERY
```

并固定：

```text
query_execution_state=NOT_STARTED
child_launched=false
production_queried=false
terminal_is_authority=false
p0_acceptance_authorized=false
replay_allowed=false
```

`HARNESS_REVALIDATED_NO_QUERY` 只说明无查询 harness 的合同校验完成，
不是 `SUCCEEDED_P0_PASS`。该 terminal 不得输入现有 P0 acceptance v1，也不得
作为未来 P0 acceptance v2、collection admission 或 runtime activation 的成功
来源。

当前不存在真实 query terminal、P0 pass、P0 acceptance v2 或 collection
admission。缺少其中任一层时必须保持：

```text
t1_executed=false
production_queried=false
p0_pass=false
collection_authorized=false
```

## 后续实现前置条件

未来从 foundation 进入真实 one-shot query 至少需要新的人工主审切片：

1. 可签且短 TTL 的 query authority release，而不是本 PENDING 模板；
2. 最终 query 前重新验证 exact readiness raw inputs；
3. create-only consume，消费后不可 replay；
4. 明确区分 success、P0 blocked、child failure、timeout、interrupt 和
   query outcome unknown 的 terminal；
5. timeout、断连、缺 terminal 或部分产物一律 fail closed；
6. 完整证据/proof exact-byte 绑定和独立外部 custody；
7. 独立签名的 P0 acceptance v2；
8. P0 之后仍需单独的 execution-quality collection admission release。

这些条件未全部实现和审核前，本 foundation 始终是 `NO_QUERY`。
