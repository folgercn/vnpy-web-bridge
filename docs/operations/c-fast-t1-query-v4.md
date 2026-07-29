# C_FAST T1 real readonly query v4

## 当前边界

Parent Issue 为 #114；本次 query-release-v4/runtime integration 对应 #139，
基线为 `origin/main@90db2c4`。本切片只交付 code/schema/template/runbook/tests；
未 build、push、deploy、读取 DSN 或执行 query。

本切片实现可审查的合同和运行时，但没有执行它：

```text
deployed=false
production_queried=false
write_probe_attempted=false
database_mutations=0
web_bridge_rpc_calls=0
orders_sent=0
positions_modified=0
dispatch_changed=false
trading_authorized=false
```

query v4 与以下对象严格分离，不接受版本回退：

- query release-v3、consume-v3、child-started-v3、terminal-v3；
- readiness-v2、provenance-v1 与 legacy image verifier；
- release-v2 `NO_QUERY` foundation；
- consume-v2；
- harness-terminal-v2；
- release/consume/terminal v1；
- P0 acceptance v1。

`HARNESS_REVALIDATED_NO_QUERY` 不是 query authority，也不能输入后续 #136
P0 acceptance v2。

## 文件与权限

人工签署对象是
[`commodity-c-fast-t1-one-shot-query-release-v4.schema.json`](../schemas/commodity-c-fast-t1-one-shot-query-release-v4.schema.json)。
专用 key purpose 固定为：

```text
t1_exact_readonly_query_v4_release_signer
```

query authority 不复用 readiness 的 T1 audit keyring。它使用独立
[`commodity-c-fast-t1-query-v4-trusted-keys-v1.schema.json`](../schemas/commodity-c-fast-t1-query-v4-trusted-keys-v1.schema.json)
和 root-owned 固定 pin：

```text
/run/c-fast-t1-readiness-v3-pins/query-v4-authority-keyring.sha256
```

parent 的 initial/pre-consume/final verify、bootstrap child 和 audit 内部最后
gate 都会重读该 pin；原 `t1-authority-keyring.sha256` 仍作为 upstream
readiness pin 单独重读。这个 query-v4 pin 是
**generation-external late authority pin**：它与 readiness-v3 generation
同目录挂载并独立校验，但不属于 readiness-v3 的
`pin-set.manifest.json` generation，不能描述为由该 generation 冻结。
query-v4 keyring 的全部 key material 还必须与
provenance、T1、L3 release、outcome 四个 pinned upstream keyring 的全部 key
（包括未使用 key）互斥。

readiness 输入只接受
`commodity_c_fast_t1_readiness_v3` 与
`READY_FOR_QUERY_RELEASE_V4_HUMAN_SIGNATURE_ONLY`，并要求 packet 明确记录
`query_release_v3_accepted=false`、`readiness_v2_accepted=false`。parent、
bootstrap 和独立
`commodity_c_fast_l1_l5_audit_v4.py` 还会绑定同一
`pin-set.manifest.json` generation、manifest canonical SHA256、pin-root
directory identity、provenance signing-tool source pin/commit 和 custody
path/id/identity/directory identity，以及 generation 的
`evidence_join_identity_sha256`；同路径替换 custody directory 或混代 pin
snapshot 都在 DSN 读取前拒绝。

release 的 `custody_identity_sha256` 不是 legacy T1 custody identity，也不是
可独立填写的新 identity；它必须逐字等于 readiness-v3 packet 与 active
generation pin 的 `packet_custody_identity_sha256`。parent 与 bootstrap child
都按
`commodity_c_fast_t1_readiness_v3_custody_identity_v1`
重读同一个 `custody-identity.json`。旧
`commodity_c_fast_t1_custody_identity_v1` 即使 hash 自洽也按 downgrade
拒绝。

release 最长 TTL 为十分钟，不能早于 readiness 生成时间，也不能晚于 exact
readiness expiry。它只允许以下四项为 `true`：

```text
t1_one_shot_child_launch_authorized=true
network_query_authorized=true
readonly_production_query_authorized=true
local_query_evidence_write_authorized=true
```

write probe、数据库/部署/网络 mutation、Web Bridge RPC、采集、订单、仓位、
dispatch、交易、替换、production activation、自动 promotion 和 P0 acceptance
全部由 schema const 与运行时 deny matrix 固定为 `false`。

## one-shot 状态机

唯一顺序为：

```text
initial full verify
  -> pre-consume full verify
  -> capture consumed_at
  -> validate TTL at consumed_at
  -> re-read active pins
  -> parent mints a 32-byte one-shot launch capability in memory
  -> create-only + fsync consume
  -> reopen exact consume bytes
  -> create-only frozen bundle/gate/invocations
  -> final full release/readiness revalidation
  -> parent active-pin re-read
  -> parent passes the capability to bootstrap through an inherited pipe FD
  -> bootstrap consumes and closes the parent FD
  -> child bootstrap reopens exact consume through pinned custody dirfd
  -> child atomically creates attempt-level launch claim (O_EXCL + fsync)
     bound to the parent capability, exact child/audit invocations and gate
  -> child rejects existing launch claim or terminal before network
  -> child forwards the same capability only through a new inherited pipe FD
  -> audit internal last gate independently verifies Ed25519 release/keyring
  -> audit revalidates exact readiness-v3, active pins and consume/launch markers
  -> audit consumes and closes the one-time capability FD
  -> read DSN / connect / readonly SELECT
  -> exact output validation
  -> create-only terminal
```

consume 成功后 attempt 永久烧毁。任何失败、timeout、interrupt、
`CONSUMED_WITHOUT_TERMINAL` 或 terminal 写入失败都必须使用全新人工 release；
不能删除 marker、补写成功 terminal 或 replay。

`<attempt_id>.query-child-started-v4.json` 是 child/DSN 边界的唯一 launch
claim。bootstrap 必须从 root-pinned custody 以 `dirfd + O_NOFOLLOW + fstat +
双读`重开 exact consume marker，验证 release/attempt/custody 及 raw/canonical
SHA256 后，才可以 `O_EXCL` 创建 `0600` claim，并对文件和 custody 目录执行
`fsync`。两个并发 child 只有一个能认领；已认领的 staged invocation 即使在
timeout、interrupt、exec failure 或无产物后再次运行，也必须在 DSN/网络之前
拒绝。terminal 已存在同样必须 pre-query 拒绝。

32-byte capability 只能由已经完成 signed release/readiness pre-consume 全量验证和
active-pin 重读的 parent 生成。bootstrap 禁止 mint capability；缺少 FD、错误 FD、
已消费 FD 或 digest 不匹配都必须在创建 launch marker 和执行 audit/DSN 前失败。
capability 原文只存在于 parent/bootstrap/audit 内存和两个一次性匿名 pipe FD，不
进入 argv、持久化环境值、gate、marker、terminal 或日志。

gate 保存 domain-separated `parent_launch_capability_sha256`，launch marker 再保存
domain-separated capability binding，而不是普通 raw SHA256。binding 覆盖 release、
consume、readiness、manifest、custody 身份，以及 exact query-child invocation、
exact audit invocation、pre-connect gate 的 raw/canonical SHA256。marker 还保存不
含 capability 原文的 `launch_marker_identity_sha256`。audit 在最后 gate 中只读取
一次 FD、删除环境中的 FD 编号、关闭 FD，并用重新打开的 exact artifacts 复算完整
identity/binding。因此直接执行持久化的 `query-child-invocation-v4.json`、并发执行
audit，或在 bootstrap 已认领但无产物失败后重放 invocation，都不能取得 capability，
必须在 DSN 读取前失败。

inherited FD 只承担一次性 secret 传输，不作为 parent 身份证明。最终 authority
来自 audit 自己完成的 Ed25519 校验：audit 重开 staged query-v4 keyring，要求其
raw/canonical SHA256 同时匹配 signed release、gate 和 root active pin，验证
`signer_key_id`/purpose/重复 key-material 约束，再对去除 `signature` 的 canonical
release bytes 验签。随后它用已签名的 exact readiness raw/canonical hash 复算完整
readiness binding、source-bundle index、namespace、custody 和 signer domain
separation，并调用冻结且 hash 匹配 release 的 readiness-v3 verifier，使用原始
readiness input paths、原始 custody packet 和当前 active pins 重新执行完整
`verify_existing_readiness_packet`；重新派生的 payload/raw/canonical hash 必须与
signed release 绑定完全相同。攻击者即使自行创建 pipe/FD 并伪造 gate、consume、
launch marker，也无法用未签名、签名不匹配或 readiness 无法重派生的 release 越过
DSN 前 gate。

## 最后的 active-pin 边界

外层 parent 和 bootstrap child 的 pin check 是纵深防御，不是最后事实边界。
最后一次 gate 位于冻结的
`commodity_c_fast_l1_l5_audit.py` 内部：manifest 和 exact runtime bindings
验证完成后、读取 DSN 之前执行。它用单次 `O_NOFOLLOW` fd、`fstat`、双读和
path identity 重验：

- exact audit script；
- gate 绑定的 exact audit invocation core raw/canonical bytes；
- bootstrap 内存中的 gate hash 后缀与 audit 重新打开的完整 invocation；
- exact query release raw/canonical bytes；
- root-pin 匹配的 exact query-v4 trusted keyring 与 Ed25519 release signature；
- exact readiness raw/canonical bytes；
- exact manifest source raw/canonical bytes；
- exact consume marker raw/canonical bytes；
- exact child launch marker、terminal absence、parent capability digest 与
  domain-separated invocation/gate binding；
- provenance/T1/query-v4/L3/outcome 五个 active keyring pins；
- resolved active custody path。

最后 gate 还会用当前 UTC 重新检查 signed release 的
`issued_at <= not_before <= now < expires_at` 和 exact readiness 的
`generated_at <= now < expires_at`。因此 parent 调度或 child 启动暂停导致 TTL
过期时，不会继续读取 DSN。

gate 返回后下一步就是 `_read_secret_text_file()` 和 connect，中间没有 artifact
写入、插件、回调或动态配置读取。任何 pin、custody、script、invocation、
release、readiness、manifest 或 gate late replacement 都会在 DSN 读取和网络连接
之前 fail closed。bootstrap 只是纵深校验层；即使调用者绕过 bootstrap 而直接
执行冻结的 audit invocation，缺少未持久化 capability 也无法越过最后 gate。

consume marker、child launch claim、pre-connect gate、audit invocation 和
query-child invocation 都作为 create-only exact artifacts 保存，并把各自的
raw/canonical SHA256 写入 query terminal，供 #136 离线 acceptance 直接绑定，
而不是依赖路径或隐式传递。terminal 另记录
`query_v4_keyring_raw_sha256`/`query_v4_keyring_canonical_sha256`、
`parent_launch_capability_sha256`、`launch_marker_identity_sha256` 和
`launch_capability_binding_sha256`；capability 原文永不落盘。launch claim 的结构由
[`commodity-c-fast-t1-query-child-started-v4.schema.json`](../schemas/commodity-c-fast-t1-query-child-started-v4.schema.json)
冻结，其 schema hash 也必须包含在人工签署的 query release 中。

## terminal 与 outcome unknown

query terminal 只允许：

```text
BLOCKED_FINAL_REVALIDATION_PRE_CHILD
FAILED_CHILD_LAUNCH_PRE_QUERY
COMPLETED_EVIDENCE_P0_PASS
COMPLETED_EVIDENCE_P0_BLOCKED
FAILED_CHILD
FAILED_OUTPUT_VALIDATION
TIMED_OUT_OUTCOME_UNKNOWN
INTERRUPTED_OUTCOME_UNKNOWN
CORRUPT_CHILD_LAUNCH_MARKER_OUTCOME_UNKNOWN
```

timeout/interrupted/非审计退出/无效输出/损坏的 child launch marker 固定：

```text
query_execution_state=OUTCOME_UNKNOWN
production_query_attempted=true
production_query_completed=null
p0_pass=null
proof_verified=false
database_mutations_observed=null
p0_acceptance_authorized=false
replay_allowed=false
```

默认 executor 使用 `-I` 隔离的 bootstrap 和独立 process group。timeout、
`SIGINT`、`SIGTERM` 或 `SIGHUP` 会先 `SIGTERM`，等待后再 `SIGKILL` 并强制
`wait`/reap，恢复原 signal handler 后才写 unknown terminal；即使 cleanup
本身被第二次中断，也不会先写 terminal 并遗留 child。即使进程已终止，也不从
进程状态推断 SQL 是否完成或数据库 mutation 为零。

只有 child 已持有 exact launch claim、audit 已消费匹配的瞬态 capability、
exit 0/1、四份产物完整且 readonly proof、
endpoint、QuestDB build、manifest、release、readiness、consume、gate 和两层
invocation exact bindings 全部通过，
才可写 `COMPLETED_EVIDENCE_*`。即使该状态为 P0 pass，terminal 仍固定
`p0_acceptance_authorized=false`，外部 acceptance 属于独立 Issue #136。

`started_at <= final_revalidation_at <= ended_at` 必须成立。时钟回拨绝不能被
`max()` 静默夹平后产生 PASS；child 已运行时会降为
`FAILED_OUTPUT_VALIDATION`/`OUTCOME_UNKNOWN`。

## INVALID/PENDING 模板与签署

[`c-fast-t1-query-v4.template.json`](c-fast-t1-query-v4.template.json) 是
`INVALID / PENDING / NOT_SIGNABLE / NOT_AUTHORITY` 清单。它包含 `PENDING_`
placeholder、字符串形式的 `max_runtime_seconds`，并故意没有 `signature`，
不能直接签署或运行。

人工必须复制成新的 unsigned JSON，逐项用 exact artifacts 填完，并使用全新
release ID。离线签署命令为：

```bash
PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_t1_query_v4_sign_release.py \
  --input /secure/query-v4.unsigned.json \
  --trusted-keyring /secure/query-v4-keyring.json \
  --readiness-packet /secure/readiness-v3.json \
  --private-key-file /secure/query-v4-ed25519.pem \
  <与 query runner 相同的完整 readiness-v3 raw/source/post 参数> \
  --output /secure/query-v4.signed.json
```

signer 自动生成或核对
`attempt-<sha256(release_id UTF-8)>`，私钥必须为当前用户所有、`0600`、
非 symlink，输出为 create-only。signer 会先完整重放 readiness-v3 真链、重读
四个 upstream pins 与独立 query-v4 pin，验证 query keyring schema/purpose、
`signer_key_id` 和私钥对应 public bytes，并执行五个 key domain 的全 keyset
互斥检查；schema-only 或伪造 readiness packet 不能进入私钥加载/签署阶段。
完整参数以 `commodity_c_fast_t1_query_v4_sign_release.py --help` 为准。

## 运行门禁

CLI 已提供完整 exact-readiness raw inputs、L3 post-outcome inputs、query release、
keyring、manifest、DSN 和 readiness packet 参数；正式使用前必须由人工主审新的
signed release 和部署事实。可用以下本地命令只查看参数，不读取 DSN、不联网：

```bash
PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_t1_query_v4.py --help
```

本 PR 的执行器测试注入 fake child；另有一个 `-I` 隔离的 audit subprocess
只验证 gate 并在 active-pin 边界停止。测试没有读取凭证、连接 QuestDB、执行
SQL、部署、重启、采集或交易。
