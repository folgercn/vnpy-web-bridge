# C_FAST query-v6 executable one-shot runtime

## Boundary

query-v6 foundation release 只冻结并重放 provenance、readiness-v4、L3 outcome、
exact-contract manifest、runtime pins、custody 和 secret-free DSN identity；它永远
不是 query authority。真实的一次性只读查询还必须具备另一份由独立 Ed25519
key domain 人工签署的 `commodity_c_fast_t1_one_shot_query_executable_release_v6`。
该 release 精确绑定 foundation 的 raw/canonical hash、签署 key、readiness/L3、
十品种 manifest/window、runtime image/source/identity、custody、DSN identity、
expected readonly principal/endpoint，以及 active root-owned executable pin set。

executable release 最长有效五分钟，只允许一次使用，并固定 30 秒 launch margin。
它只授权 exact readonly production query、一次 child launch、网络连接和本地证据
写入。database mutation、collection、Web Bridge RPC、order、position、dispatch、
trading、strategy activation、broad production 和 P0 acceptance 均固定为 false。

## Required deployment inputs

必须由部署方独立建立以下不可伪造输入，仓库模板本身不会产生权限：

- root-owned、不可 group/world 写的 active pin root
  `/run/c-fast-t1-query-v6-executable-pins/pin-set.manifest.json`；
- 与 foundation、provenance、readiness 和 outcome key material 完全隔离的
  executable keyring，并把其 canonical SHA256 写入 active pin set；
- root-owned、不可 group/world 写且 bytes 与 pin set 完全一致的 query-v6
  pre-connect execution adapter；
- QuestDB exact build hash，以及只含 stat/path/principal/endpoint identity、绝不
  含 DSN secret 或 content hash 的 foundation DSN identity attestation；
- 人工填写的全新 `release_id`、UTC `issued_at/not_before/expires_at`、
  `signer_key_id`、真实 `reviewer_role` 和非占位 `human_signature`。

pin set 中 signer、verifier、runner、release/keyring/consume/terminal/audit/readonly
schema、adapter 和 QuestDB build 的 SHA256 都必须来自待部署 exact bytes。任何
source、schema、keyring、pin generation 或 adapter rotation 都要求重新审核并
签署 release。

## Verify, sign, and execute

完整离线参数可通过以下命令查看：

```bash
python scripts/commodity_c_fast_t1_query_v6_executable.py --help
python scripts/commodity_c_fast_t1_query_v6_executable_sign.py --help
python scripts/commodity_c_fast_t1_query_v6_runtime.py --help
```

verifier 只重放 foundation、active pins、独立 key domain 与 executable signature；
不会读取 DSN secret、consume、启动 child 或联网。signer 只 create-only 写入
`0600` signed release。runner 在任何网络动作前依次执行：

1. 校验 adapter custody/hash 与 secret-free DSN metadata；
2. 拒绝既有 consume、terminal 或 partial attempt directory；
3. 完整重放 foundation、pins 与 executable release；
4. create-only 写 consume，并从 custody descriptor 精确重开核验；
5. staging exact adapter，再做一次完整 final revalidation；
6. 使用 `python -I`、最小环境、无 stdin、独立 process session 和固定 timeout
   启动 adapter；
7. 验证 pre/post readonly proof、expected principal/endpoint、audit outputs，并
   create-only 写 terminal。

consume 后、adapter launch 前任一步骤失败都会写
`FAILED_BEFORE_NETWORK`。launch 后 timeout、signal、异常退出或证据无法确认会写
`OUTCOME_UNKNOWN`，绝不自动重试。成功和 P0-blocked 分别写 `COMPLETED_PASS` 与
`COMPLETED_BLOCKED`。任何 terminal/consume/partial state 均永久阻止同 attempt
重放。

## Current runtime blocker

仓库当前没有把 query-v4/v5 child 伪装成 query-v6 adapter。旧 child 的签署
release、readiness 和 active pin root 都属于旧 authority domain，直接复用会造成
authority downgrade。因而 CLI 未显式提供 `--execution-adapter` 时固定返回
`QUERY_V6_PINNED_PRECONNECT_ADAPTER_NOT_DEPLOYED`，并在打开 custody、读取 DSN
secret、consume 或联网前终止。

要解除该 blocker，仍需把一个独立审计、root-pinned 的 query-v6 pre-connect
adapter 作为部署 artifact 交付。该 adapter 必须消费 runner 传入的 exact
foundation/release/consume hashes，在连接前验证 server-enforced readonly
principal 与 endpoint/build identity，并生成现有 audit-v2 与 pre/post readonly
proof。完成该部署输入前，本切片只提供 fail-closed executable contract 和
consume/terminal runner，不构成真实 M2 查询，也不构成 #114 P0 acceptance。

## Execution impact

默认无 adapter 的路径固定为：release consumed = false、DSN secret read = false、
network attempted = false、Web Bridge RPC calls = 0、orders sent = 0、positions
modified = 0。即使存在有效 executable release，也不授权任何交易或广义生产
操作。
