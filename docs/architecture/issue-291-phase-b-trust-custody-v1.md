# Issue #291 Phase B：Signing/Trust 与 Artifact Custody 基础合同

状态：Phase B implementation baseline，未部署、未启用交易、未包含任何生产或真实私钥。

## 边界

`signing-authority` 是离线/local-agent/HSM 适配层。它只接受一个 canonical
`web-bridge-signing-request-v1`，在显式的 `domain + key_id + key_version`
下产生 Ed25519 签名；它不安装、启用、撤销 artifact，不访问数据库、HTTP、vn.py
或 Windows RPC。普通运行时镜像不得复制 `scripts/signing/**` 或任何私钥。

Trust domain 固定为：

* `research`
* `map_acceptance`
* `c_fast_acceptance`
* `runtime_authorization`
* `execution_permit`

每个 domain 有独立 keyring、key version、active key 和审计链。公钥 keyring 可以
只读分发，但 key id 和 32-byte 公钥材料不得跨 domain 重用；验证必须使用 signed
artifact 指定的 key id，不能尝试所有 key、旧 key 或默认 domain 作为 fallback。

`artifact-custody` 是 artifact 和 install/consume/revoke receipt 的唯一持久 writer。
Artifact 及 receipt 使用 canonical JSON line；artifact 带 canonical/raw SHA-256、
schema ref、producer identity、predecessor、lineage、scope 和 immutable id。发布和
receipt append 都是 create-only：临时文件写满并 fsync，原子发布后 fsync 目录；读取
使用 `O_NOFOLLOW`、fd identity 和 canonical/hash 重校验。期望版本、idempotency key、
fencing token 和上一 receipt hash 防止 replay、TOCTOU、双 writer 和 stale writer。

Custody 不持有私钥，不调用 signer，不拥有订单或交易 RPC。Execution 只能提交带
fencing/idempotency 的 consume/revoke request，并读取 pinned receipt；Control API
只能发 typed request/读 metadata，不能直接写 custody volume。

## 目录与实现

* `shared/trust_contracts/v1.py`：五域 keyring、canonical bytes、signing request、
  signed artifact 验证和 authority-negative flags。
* `shared/artifact_contracts/v1.py`：immutable envelope、publish request、receipt
  identity/hash contracts。
* `scripts/phase_b_offline_signer.py`：离线 signer CLI/HSM/ephemeral-FD adapter；无 public
  web endpoint。
* `shared/artifact_custody/v1.py` + `scripts/phase_b_artifact_custody.py`：filesystem
  custody CLI；0700 custody volume、writer epoch、single writer lock、atomic
  create-only artifact/receipt。
* `docs/schemas/issue-291-phase-b-{trust-keyring,signing-request,signed-artifact,
  custody-record}-v1.schema.json` 与 `docs/schemas/web-bridge-artifact-*-v1.schema.json`：
  跨进程 JSON Schema。
* `deployments/phase-b/Containerfile.{signing-authority,artifact-custody}`：restricted
  images；只复制本合同和对应 CLI，不复制 `backend/app`、`scripts/**`、vn.py 或 key。

Compose 的 batch 交接是单向、只读的命名卷边界：MAP 只写
`phase_b_map_output`，离线 signer 读取它并只写 `phase_b_map_signing_handoff`；C_FAST
只读该 handoff 并只写 `phase_b_cfast_output`；第二次 signer 读取 C_FAST 输出并只写
`phase_b_custody_handoff`，custody 只读最后一个 handoff。每个 batch 卷使用
UID/GID 65532、0700 的 tmpfs driver option，任何卷不在两个服务间共享 RW。生产者的
MAP/C_FAST JSON Schemas 随 custody 镜像注册，并以 `$id`、文件 stem 和 payload
`schema_version` 三种稳定引用键解析。

`shared/artifact_custody/v1.py` 是 compose 使用的 epoch-fenced custody adapter；它通过
CLI 运行，不提供 HTTP/control endpoint，必须与本合同保持同一 canonical/hash/receipt
语义，并且最终部署只能保留一个 custody writer 根和一个 canonical API。

## Fail-closed 验收门禁

1. 公钥域集合缺失、重复 key id/material、非 active key、domain/key version mismatch、
   签名篡改、过期或 predecessor/schema/hash 不符均拒绝；不能 fallback。
2. 普通镜像 SBOM、entrypoint、环境变量、日志和网络扫描不得发现私钥、sign endpoint、
   order/RPC 依赖。
3. Custody 对 symlink、文件替换、非 canonical bytes、部分临时文件、artifact/receipt
   篡改、expected-version 冲突、idempotency replay、receipt chain 断裂、双 writer 和
   revoke 后续写入均拒绝。
4. `version`、`health`、`ready` CLI 输出明确 unit identity，并声明
   `private_key_access=false`、`trade_rpc_access=false`；签名输出只能是 signed bytes，
   custody 输出只能是 immutable receipt。

本合同不改变 Phase A Execution/Windows 的订单权限，也不进行部署、切换、蓝绿/滚动
迁移、双读/双写或任何真实交易动作。
