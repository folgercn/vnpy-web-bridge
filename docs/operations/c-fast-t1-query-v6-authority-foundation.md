# C_FAST query-v6 signed authority foundation

## Architecture

该切片是独立的 query-v6 offline authority foundation，不修改或兼容冒充
query-v3/v4/v5。它在签名前重放 query-v5 build/registry provenance 与 final
OCI composition，并冻结 #236 列出的全部 pre-runtime blocker：readiness-v4、
L3 outcome、十品种 exact-contract manifest、runtime pin generation、custody、
secret-free DSN identity、超时参数，以及 runner/child/audit/lifecycle/readonly
proof 的 exact bytes。

readiness-v4 与 L3 不是按 schema/hash 直接接收。signer 和 verifier 都必须从
固定 `/run/c-fast-t1-readiness-v4-pins` 重读 active root-owned pin generation，
调用官方 `verify_existing_readiness_packet` 做 packet/custody/runtime identity
exact re-derive，并调用官方 `verify_signed_outcome` 重放 L3 release、consume、
receipt、pre/post evidence 和 Ed25519 signature。完成后还会重验 active pins，
因此同路径伪 packet、伪 outcome、keyring/pin rotation 或中途 tamper 都会
fail closed。

签名 payload 使用独立 Ed25519 key domain。query-v6 key material 与
query-v5 provenance keyring 任意重合都会 fail closed。`release_id` 必须全新，
`attempt_id` 只能是 `attempt-<sha256(UTF-8 release_id)>`；TTL 最长 600 秒，
`maximum_uses=1`、`replay_allowed=false`。

## Authority

本 foundation **不是 query authority**。所有 query、network、collection、
runtime、RPC、dispatch、trading、order、position、production 与 P0 authority
均固定为 false。它也不能 consume release、打开 custody、读取 DSN metadata
或 secret、启动 child、连接 QuestDB 或写 evidence。

签名成功只证明人工评审接受了一组完整的离线 pins。后续若实现真实 runtime，
必须使用新的独立 contract，在不可逆动作前重新验证这些 bytes，并独立实现
create-only consume、final revalidation、readonly proof 和 terminal custody。

## Inputs

- signed query-v5 provenance、独立 provenance keyring、composition attestation、
  final OCI layout 及其完整 replay inputs；
- 当前有效的 readiness-v4 与其中绑定的 exact signed L3 outcome；
- readiness-v4 全量 replay inputs：query-v4 image/source/OCI/content、
  provenance-v3 及 keyring、query-v5/T1 keyrings；L3 release keyring、release、
  consume marker、receipt、12 个 pre evidence、6 个 post evidence、outcome
  keyring；以及独立提供的 T1/L3 source commit、T1/QuestDB image digest 和
  outcome contract source assertion；
- `commodity_c_fast_l1_l5_audit_manifest_v2` manifest。`targets` 必须恰好为
  `ag/al/au/bu/cu/rb/ru/sc/sp/zn`，current/roll 每个 exact contract 都必须有
  execution window；
- query-v5 runtime pin manifest，必须保持 `code_only_blocked=true` 和
  `authority_granted=false`；
- secret-free DSN file identity attestation。它只能包含 stat identity、路径
  hash 和 expected principal/endpoint hash；不得包含 DSN、password、secret
  hash 或可供离线猜测的 content hash；
- 独立 query-v6 keyring 和人工填写后的 unsigned release template。

runtime pin manifest、DSN identity attestation、keyring、unsigned/signed release
均应为当前用户所有的普通 `0600` 文件。keyring canonical SHA256 必须通过
独立 root-owned pin 传入，不可只相信 release 内的值。
query-v6 的跨域隔离使用上述 active pins 验证过的完整 keyring materials；不会
相信 readiness packet 自报的 `signer_public_key_sha256`。

## Sign and verify

先填写模板中唯一允许人工决定的字段：`release_id`、三个 UTC 时间、
`signer_key_id`、`reviewer_role`、`human_signature` 和
`custody_absolute_path`。其余 `PENDING_DERIVED_BY_SIGNER` 字段由 signer 从
exact artifacts 计算，禁止人工抄写。

查看完整离线参数：

```bash
python scripts/commodity_c_fast_t1_query_v6_sign.py --help
python scripts/commodity_c_fast_t1_query_v6_authority.py --help
```

signer 只 create-only 写入一个 `0600` signed JSON。verifier 只读输入并打印
`FOUNDATION_ONLY_NO_QUERY_AUTHORITY`；它没有 `--dsn-file`、consume、network
或 launch 参数。`--signed-release` 只属于 verifier；signer 只接收 unsigned
`--input` 和 create-only `--output`，不要求尚未生成的 signed release。任何
PENDING、schema downgrade、raw/canonical splice、
十品种缺失、roll window 缺失、四组 session window 反转/重叠/越过 audit
window/偏离签署 trading day、custody 不一致、endpoint 不一致、runtime pin
rotation、source/schema hash rotation、签名错误、跨域 key reuse、TTL/attempt
错误都会 fail closed。

## Execution impact

- DSN reads: 0
- network attempts: 0
- production queries: 0
- database mutations: 0
- Web Bridge RPC calls: 0
- orders/positions/dispatch changes: 0

因此该切片只消除 signed authority **结构**的 blocker，不构成 #216 的真实
M2 one-shot 验收，也不构成 #114 的 P0 acceptance。
