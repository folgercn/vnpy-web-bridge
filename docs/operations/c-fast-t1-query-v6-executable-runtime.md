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
  pre-connect execution adapter package；package manifest、entrypoint、Python
  interpreter、完整 Python dependency closure 及从 package parent 到 filesystem
  root 的 custody chain 都必须由 root 所有且不可 group/world 写，也不得含
  symlink；
- QuestDB exact build hash，以及只含 stat/path/principal/endpoint identity、绝不
  含 DSN secret 或 content hash 的 foundation DSN identity attestation；
- 人工填写的全新 `release_id`、UTC `issued_at/not_before/expires_at`、
  `signer_key_id`、真实 `reviewer_role` 和非占位 `human_signature`。

pin set 中 signer、verifier、runner、release/keyring/consume/terminal/audit/readonly/
launch/package schema、package builder、adapter、package root identity、Python
interpreter/dependencies 和 QuestDB build 的 SHA256 都必须来自待部署 exact bytes。
root installer 只接受 generation/keyring/QuestDB build 三个外部 pin，其余 pin
全部从已安装 exact bytes 自行计算；install 还必须显式接收运维预先批准的
package manifest raw SHA256 与 exact 40 位 source commit，两者任一不匹配都在
staging/pin publish 前失败。任何
source、schema、keyring、pin generation 或 adapter rotation 都要求重新审核并
签署 release。

## Verify, sign, and execute

完整离线参数可通过以下命令查看：

```bash
python scripts/commodity_c_fast_t1_query_v6_executable.py --help
python scripts/commodity_c_fast_t1_query_v6_executable_sign.py --help
python scripts/commodity_c_fast_t1_query_v6_runtime.py --help
python scripts/c_fast_t1/query_v6_preconnect_package.py --help
```

verifier 只重放 foundation、active pins、独立 key domain 与 executable signature；
不会读取 DSN secret、consume、启动 child 或联网。signer 只 create-only 写入
`0600` signed release。runner 在任何网络动作前依次执行：

1. 对 `--manifest` 做稳定重读，要求 raw/canonical hash 与 foundation 已验证的
   query manifest 完全一致，再校验 adapter custody/hash 与 secret-free DSN
   metadata；
2. 拒绝既有 consume、terminal 或 partial attempt directory；
3. 完整重放 foundation、pins 与 executable release；
4. create-only 写 consume，并从 custody descriptor 精确重开核验；
5. 建立 create-only attempt/artifact 目录，再做一次完整 final revalidation；
6. 在紧邻 launch 处再次核验 root-custodied 原 adapter、package/interpreter/
   dependency closure、DSN metadata 和 exact runtime manifest；随后 create-only
   写 `query-child-launched-v6` claim，并将一份 32-byte opaque capability 仅经
   inherited pipe 交给 child。adapter 必须同时验证 consume、launch claim、
   capability 和 invocation binding，缺一即不得读取 DSN 或连接；
7. 直接以 pin set 中 exact Python 与 adapter resolved root-owned path、
   `python -I`、最小环境、无 stdin、独立 process session 和固定 timeout 启动一次；
   timeout、SIGINT/SIGTERM/SIGHUP 或异常会先 SIGTERM 整个 process group，
   bounded wait 后仍存活则 SIGKILL，并确认 fork descendants 已退出；
8. adapter 在连接后、查询前验证真实 connected endpoint、readonly principal、
   QuestDB build，并要求查询前后 readonly facts 完全一致；runner 再验证 outputs
   并
   create-only 写 terminal。

consume 后、adapter launch 前任一步骤失败都会写
`FAILED_BEFORE_NETWORK`。launch 后 timeout、signal、异常退出或证据无法确认会写
`OUTCOME_UNKNOWN`；操作员或系统信号中断会在清理 process group 后写
`INTERRUPTED`，两者都绝不自动重试。成功和 P0-blocked 分别写
`COMPLETED_PASS` 与 `COMPLETED_BLOCKED`。任何 terminal/consume/partial state
均永久阻止同 attempt 重放。

## Current runtime blocker

本切片提供独立 v6-only pre-connect adapter 与确定性 package/installer；adapter
不会校验、消费或调用 query-v3/v4/v5 one-shot authority。旧 v4 audit 文件只作为
冻结的 readonly 计算引擎加载，旧 release/gate/consume/launch 函数均不进入调用链。
CLI 未显式提供 `--execution-adapter` 时仍固定返回
`QUERY_V6_PINNED_PRECONNECT_ADAPTER_NOT_DEPLOYED`，并在打开 custody、读取 DSN
secret、consume 或联网前终止。

解除 blocker 需要在目标机离线 build 后由 root create-only 安装 package 和 active
pin generation，再以该 pin 中 exact adapter path 执行。build/install/preflight
本身不接收 DSN、network release 或签署材料，也不联网。真实 M2 signed release、
真实 SimNow/QuestDB 回调仍是后续外部验收；这里不伪造它们，也不自动复用旧
one-shot authority。正式
`commodity_c_fast_execution_quality_p0_acceptance_v6_v1` 只能在真实查询完成且
外部 custody 已建立后，由独立 keyless bundle builder 绑定 foundation、
executable、active pins、manifest、consume、launch、terminal 和全部证据，再交由
独立人工签署域签名；它不是旧 query-v3 P0 acceptance 的续签或别名。

## Execution impact

默认无 adapter 的路径固定为：release consumed = false、DSN secret read = false、
network attempted = false、Web Bridge RPC calls = 0、orders sent = 0、positions
modified = 0。即使存在有效 executable release，也不授权任何交易或广义生产
操作。
