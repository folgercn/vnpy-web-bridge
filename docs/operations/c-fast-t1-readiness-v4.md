# C_FAST query-v4 readiness-v4 离线门禁

## 结论与权限边界

readiness-v4 对应 Issue #216，属于 Control Plane 的 Evidence 汇合合同。它把
query-v4 source bundle、OCI content attestation、provenance-v3 和既有 L3
deployment outcome 汇合为一份 15 分钟有效的、非权威 packet。

成功状态固定为：

```text
READY_FOR_QUERY_RELEASE_V5_HUMAN_SIGNATURE_ONLY
```

该状态只表示 exact Evidence 可以交给人类审核，并由后续独立
query-release-v5 合同处理。它不是 Acceptance、Deployment Authority 或
Execution Permit，不允许启动 query-v4，也不允许访问 QuestDB、DSN、registry、
Web Bridge RPC、Gateway、订单或持仓。

这里的 `READY_FOR_QUERY_RELEASE_V5_HUMAN_SIGNATURE_ONLY` 只表示 Evidence
与未来 query-v5 authority key domain 已冻结，可以交给下一切片实现 release-v5；
本切片新增的只是 readiness verifier 的隔离 runtime，并没有 query release-v5
schema、signer 或 query runtime，因此不能据此签名或启动 query。

成功 packet 固定：

```text
ready_for_query_release_v5_human_signature_only=true
query_release_v4_accepted=false
readiness_v3_accepted=false
p0_preflight_v2_accepted_as_readiness=false
packet_is_authority=false
authority_granted=false
readiness_authorized=false
network_authorized=false
production_query_authorized=false
collection_authorized=false
runtime_activation_authorized=false
t1_one_shot_child_launch_authorized=false
local_query_evidence_write_authorized=false
web_bridge_rpc_authorized=false
p0_acceptance_authorized=false
dispatch_authorized=false
trading_authorized=false
```

本合同不会修改或兼容升级 readiness-v3、provenance-v2、query release-v4、
query-v4 parent/child、`Containerfile.query-v4` 或 runtime template。后续必须新增
release/runtime-v5，不能把 readiness-v4 回灌到历史 v4 合同。

## 验证链

### 独立 readiness runtime trust root

正式入口不再直接运行 verifier，也不接受 shebang 或 `PYTHONPATH`。唯一受支持
入口是 exact readiness-v4 release 中的 launcher：

```text
<PINNED_PYTHON> -I -S -s -E -B \
  /opt/c-fast-readiness-v4/release/scripts/commodity_c_fast_t1_readiness_v4_launcher.py
```

launcher 在任何 readiness、本地 delegate、jsonschema、referencing 或 crypto
module import 前验证 Python flags，并从 root-owned v2 pin generation 取得固定的
interpreter、source root、site-packages 和 immutable image RepoDigest。随后它：

- stable-FD double-read 并固定 launcher、verifier 和 interpreter bytes；
- 验证 source/site-packages 从 filesystem root 开始的完整父链均 root-owned、
  non-symlink、不可 group/world 写，并且 non-root runtime 没有写权限；
- 连续两次递归扫描完整 source release 和 dependency tree，固定每个目录/文件的
  relative path、owner、mode、size 和 SHA256；
- 拒绝 symlink、hardlink、device/socket、`.pth`、`.egg-link`、
  `sitecustomize` 和 `usercustomize`；
- 只从初次扫描保留的 exact Python source bytes 加载全部本地 module；普通路径
  漂移不会改变已执行 bytes，后续全 closure rescan 又会检测并拒绝漂移；
- 只有 dependency closure 与独立 pin 匹配后，才把唯一 site-packages root 加入
  `sys.path`；`-I -S -s -E -B` 同时排除 cwd、environment、user-site、site hooks
  和 bytecode 写入；
- 在派生前、create-only 写入前和写入后重新核对 pin generation 与完整 execution
  closure。

`scripts/c_fast_t1/Containerfile.readiness-v4` 把全部 `scripts/`、全部 schemas 和
固定版本第三方依赖封装为 root-owned、non-writable release。trusted release
launcher 必须按 immutable RepoDigest 选择该 image，并使用 read-only rootfs、
non-root UID、`--network=none`、只读 pin/evidence mounts；只有 exact pinned
custody mount 可写。不能在目标 container 内现场从当前 bytes 反推 expected pins。

packet 的 `readiness_runtime` 固定 image RepoDigest、launcher/verifier/interpreter、
source/dependency manifests、path/directory identities 和 enforcement booleans；
`runtime_identity_sha256` 进入 packet ID。existing-packet verifier 也必须由同一
launcher 调用，并用当前 retained runtime identity 重派生，不能只检查 packet
自报的 `verifier_sha256`。

readiness-v4 按以下顺序重新验证 raw artifacts：

```text
query-v4 unsigned external evidence
  + exact bounded source-bundle archive
  + exact OCI layout archive
    -> 重新运行 query-v4 content verifier
    -> 要求 supplied content attestation object 完全相等
    -> 重新验证 signed provenance-v3
    -> 重新验证 L3 release/consume/receipt + pre/post evidence + signed outcome
    -> 派生 readiness-v4 packet
```

### query-v4 content

工具调用
`c_fast_t1.verify_query_v4_image_attestation.verify_query_v4_image_evidence()`。
输入只有 exact external evidence、source bundle、OCI archive 和预期 source
commit。没有 `--source-root`，不 import `subprocess`，不运行 Git，也不需要完整
repository mount。

重新生成的 content object 必须与 supplied attestation object 完全相等；随后
再次绑定以下 raw/canonical identity：

- external image evidence raw SHA256；
- source bundle archive raw SHA256；
- source manifest raw/canonical SHA256；
- OCI layout archive raw SHA256；
- content attestation raw/canonical SHA256；
- runtime source commit、immutable image reference/digest/image ID；
- runtime bundle index、content verifier/schema 和 source-manifest schema。

packet 明确保留：

```text
source_commit_assertion_bound=true
git_binary_required=false
source_root_required=false
git_commit_independently_resolved=false
```

commit lineage 由 provenance-v3 的签名 assertion 和独立 root-owned signer-source
pins 约束；readiness-v4 不声称自己连接 Git object database。

### provenance-v3 与 key domain

readiness-v4 只调用
`commodity_c_fast_t1_build_registry_provenance_v3.verify_provenance()`，不接受
provenance-v2 fallback。验证输入包括：

- pinned provenance keyring SHA256；
- pinned provenance signing-tool source SHA256；
- pinned provenance signing-tool source commit；
- pinned signer dependency-manifest SHA256；
- pinned signer runtime image RepoDigest；
- pinned T1/L3 authority keyrings；
- pinned future query-v5 authority keyring；
- exact content attestation、runtime source commit 和 image digest。

provenance-v3 仍明确：

```text
signing_tool_source_pin_verified=true
signer_dependency_manifest_pin_verified=true
signer_runtime_image_digest_pin_verified=true
signer_runtime_execution_independently_verified=false
external_facts_independently_reverified=false
```

readiness-v4 还重新解析 provenance 和 outcome 的完整 keyring，要求每个 entry
都是唯一的 32-byte Ed25519 public key，并要求 provenance、T1、future
query-v5、L3、outcome 五个完整 key domain 两两不交叉。不能只比较当前 signer
而忽略预埋的 rotation key。readiness-v4 会直接重新读取五份真实 keyring，而
不是只信任 provenance receipt 合并后的 authority hash 列表；因此五个 domain
的十种两两 collision 都会 fail closed。future query-v5 keyring 使用独立 schema
和 purpose `t1_exact_readonly_query_v5_release_signer`，并进入同一 pin generation，
不采用 generation-external late pin。

### content/provenance 与 outcome join

独立验签并不足以证明任意一份 query-v4 build 可以与任意一份 deployment
outcome 拼接。root-owned pin-set manifest 还必须固定
`evidence_join_identity_sha256`。它是以下 canonical object 的 SHA256：

- candidate ID；
- T1 runtime source commit、image digest；
- content attestation canonical SHA256；
- signed provenance raw SHA256、canonical SHA256；
- L3/outcome contract source commits、QuestDB image digest；
- signed outcome raw SHA256、canonical SHA256；
- release ID、attempt ID、QuestDB target identity SHA256。

任何 target/release/attempt、build/outcome 换片，或仅通过 whitespace/key
order 改写 signed provenance/outcome raw bytes，都会改变 join identity，并在
packet 派生前 fail closed。

### L3 outcome freshness

既有 signed deployment outcome verifier 会重新验证 raw release、consume、
receipt、全部 pre/post evidence、签名、keyring pin 和 QuestDB namespace。

readiness-v4 保留 readiness-v3 的时间关系：

```text
deployment_ended_at <= outcome.issued_at <= readiness.generated_at
```

packet 固定 15 分钟 TTL；`expires_at` 距 outcome 签发和 deployment completion
都不得超过一小时。因此生成时，二者最多已有 45 分钟。

## active pins 与 custody

生产 CLI 不接受调用方传入 trust-root hash。它只从以下固定目录读取单行 pin：

```text
/run/c-fast-t1-readiness-v4-pins/
  pin-set.manifest.json
  readiness-runtime-image.digest
  readiness-runtime-launcher.sha256
  readiness-runtime-verifier.sha256
  readiness-runtime-python-executable.path
  readiness-runtime-python-executable.sha256
  readiness-runtime-source-root.path
  readiness-runtime-source-root-identity.sha256
  readiness-runtime-source-closure-manifest.sha256
  readiness-runtime-site-packages.path
  readiness-runtime-site-packages-identity.sha256
  readiness-runtime-dependency-manifest.sha256
  provenance-keyring.sha256
  provenance-signing-tool-source.sha256
  provenance-signing-tool-source.commit
  provenance-signer-dependency-manifest.sha256
  provenance-signer-runtime-image.digest
  query-v5-authority-keyring.sha256
  t1-authority-keyring.sha256
  l3-authority-keyring.sha256
  outcome-keyring.sha256
  packet-custody.path
```

pin root 必须 root-owned、non-symlink、不可 group/world 写；每个 pin 文件也必须
root-owned、non-symlink、不可 group/world 写。`pin-set.manifest.json` 是完整
generation 的 root-owned 原子快照，字段固定为：

校验覆盖从 pin root 到 filesystem root 的完整目录链；每一级都必须 root-owned、
non-symlink 且不可 group/world 写，不能只验证最终 pin directory 后忽略可被
rename/swap 的上层目录。

```json
{
  "schema_version": "commodity_c_fast_t1_readiness_v4_pin_set_v2",
  "generation_id": "readiness-v4-pins-UNIQUE_ID",
  "readiness_runtime_image_digest": "sha256:<64 hex>",
  "readiness_runtime_launcher_sha256": "<64 hex>",
  "readiness_runtime_verifier_sha256": "<64 hex>",
  "readiness_runtime_python_executable_path": "/usr/local/bin/python3.12",
  "readiness_runtime_python_executable_sha256": "<64 hex>",
  "readiness_runtime_source_root_path": "/opt/c-fast-readiness-v4/release",
  "readiness_runtime_source_root_identity_sha256": "<64 hex>",
  "readiness_runtime_source_closure_manifest_sha256": "<64 hex>",
  "readiness_runtime_site_packages_path": "/opt/c-fast-readiness-v4/site-packages",
  "readiness_runtime_site_packages_identity_sha256": "<64 hex>",
  "readiness_runtime_dependency_manifest_sha256": "<64 hex>",
  "provenance_keyring_sha256": "<64 hex>",
  "provenance_signing_tool_source_sha256": "<64 hex>",
  "provenance_signing_tool_source_commit_sha": "<40 hex>",
  "provenance_signer_dependency_manifest_sha256": "<64 hex>",
  "provenance_signer_runtime_image_digest": "sha256:<64 hex>",
  "query_v5_authority_keyring_sha256": "<64 hex>",
  "t1_authority_keyring_sha256": "<64 hex>",
  "l3_authority_keyring_sha256": "<64 hex>",
  "outcome_keyring_sha256": "<64 hex>",
  "packet_custody_path": "/absolute/custody/path",
  "packet_custody_id": "readiness-v4-custody-UNIQUE_ID",
  "packet_custody_identity_sha256": "<64 hex>",
  "packet_custody_directory_identity_sha256": "<64 hex>",
  "evidence_join_identity_sha256": "<64 hex>"
}
```

verifier 在逐项读取前后重读 manifest 和 pin-root directory identity，并要求所有
单行 pin 与同一 manifest 完全一致。轮换时应先在临时路径完整准备新一代单行
pin，再逐项原子 rename，最后原子替换 manifest；任何中间态只会拒绝，不会产生
混代 snapshot。

packet custody 必须是 pinned absolute path、当前 verifier UID 所有的 `0700`
non-symlink 目录，其父目录在正式运行时必须 root-owned 且不可 group/world 写。
该要求同样覆盖从 custody 直接父目录到 filesystem root 的完整链。
manifest 还必须独立冻结 custody directory 的 resolved path、device、inode、
owner、mode 与 file type identity SHA256；不能从当前路径动态接受一个新的 inode。
custody 内必须预先存在：

```json
{
  "schema_version": "commodity_c_fast_t1_readiness_v4_custody_identity_v1",
  "custody_id": "readiness-v4-custody-UNIQUE_ID"
}
```

该 object 的 canonical SHA256 和 custody ID 都由 root-owned manifest 固定。
packet 还绑定当前 custody directory 的 device/inode/owner/mode identity。即使
路径和 `custody-identity.json` 被复制到重建目录，旧 packet 或由旧 snapshot
派生的二次写也会因 directory identity 不同而失败。

packet ID 绑定 independently retained readiness execution closure、verifier/schema、
pin-root directory identity、pin generation/
manifest、custody path/object/directory identity、root-pinned evidence join、
source/image namespaces、content、provenance-v3 和 deployment outcome 全部
exact facts：

```text
readiness-v4-<canonical identity SHA256>
```

输出只能位于：

```text
<pinned custody>/<packet_id>.json
```

写入使用 guarded directory FD、`O_EXCL`、file fsync 和 directory fsync。写入前
重新读取全部 active pins，写入后再次重核 generation；若期间轮换，新建 packet
会被移除。`verify_existing_readiness_packet()` 在返回前再次重读 packet 和完整
active pin snapshot。任何 keyring、signer-source、signer dependency/runtime、
join 或 custody pin 轮换都会 fail closed。

existing packet 必须保持 verifier 的 deterministic canonical storage bytes
（sorted keys、2-space indent、单个尾随 newline）。只改 whitespace 的重写也会
失败，不能只依赖解析后的 object 相等。

## PENDING 模板

[`c-fast-t1-readiness-v4.template.json`](c-fast-t1-readiness-v4.template.json)
只是人工准备清单，不是 verifier 输入，也不是 readiness packet。它故意包含
`PENDING_` 和额外模板字段，不能通过 readiness-v4 schema。

不得删除模板的 `template_only_not_accepted_as_packet_input` 后把它冒充 packet。
正式 packet 只能由 verifier 从 raw artifacts 派生。

## 离线命令

以下命令只读取本地 exact artifacts并写入 pinned custody。示例中的 L3 pre/post
参数与既有 deployment outcome runbook 相同：

```bash
/usr/local/bin/python3.12 -I -S -s -E -B \
  /opt/c-fast-readiness-v4/release/scripts/commodity_c_fast_t1_readiness_v4_launcher.py \
  --external-image-evidence /archive/query-v4-external-evidence.json \
  --source-bundle-archive /archive/query-v4-source-bundle.tar \
  --oci-layout-archive /archive/query-v4-runtime.oci.tar \
  --content-attestation /archive/query-v4-content-attestation.json \
  --provenance /archive/query-v4-provenance-v3.signed.json \
  --provenance-keyring /secure/provenance-keyring.json \
  --query-v5-keyring /secure/query-v5-keyring.json \
  --t1-keyring /secure/t1-keyring.json \
  --outcome /var/lib/c-fast-readonly-deployment-custody/<attempt_id>.deployment-outcome.json \
  --outcome-keyring /secure/outcome-keyring.json \
  --expected-t1-runtime-source-commit-sha "$QUERY_V4_RUNTIME_SOURCE_SHA" \
  --expected-t1-runtime-image-digest "$QUERY_V4_IMAGE_DIGEST" \
  --expected-l3-contract-source-commit-sha "$L3_CONTRACT_SOURCE_SHA" \
  --expected-outcome-contract-source-commit-assertion "$OUTCOME_SOURCE_ASSERTION" \
  --expected-questdb-image-digest "$QUESTDB_IMAGE_DIGEST" \
  --release /archive/l3-release.signed.json \
  --release-keyring /secure/l3-release-keyring.json \
  --consume-marker /var/lib/c-fast-readonly-deployment-custody/<attempt_id>.deployment-consumed.json \
  --receipt /var/lib/c-fast-readonly-deployment-custody/<attempt_id>.deployment-receipt.json \
  --questdb-image-attestation /archive/questdb-image.json \
  --readonly-principal-identity-attestation /archive/readonly-principal.json \
  --secret-file-identity-attestation /archive/secret-file.json \
  --writer-continuity-pre-evidence /archive/writer-pre.json \
  --writer-continuity-post-evidence /archive/writer-release-post.json \
  --health-evidence /archive/health-pre.json \
  --backlog-evidence /archive/backlog-pre.json \
  --rollback-plan /archive/rollback-plan.json \
  --root-pin-identity-attestation /archive/root-pin.json \
  --custody-path-identity-attestation /archive/custody-path.json \
  --isolated-network-attestation /archive/isolated-network.json \
  --deployment-plan /archive/deployment-plan.json \
  --execution /archive/execution.json \
  --writer-post /archive/writer-post.json \
  --health-post /archive/health-post.json \
  --backlog-post /archive/backlog-post.json \
  --principal-secret-post /archive/principal-secret-post.json \
  --network-post /archive/network-post.json \
  --output /var/lib/c-fast-t1-readiness/<derived_readiness_v4_packet_id>.json
```

该命令不读取 DSN、不联网、不连接 registry/QuestDB、不执行部署或 query。

## 后续严格顺序

1. readiness-v4 代码和 schema 人工 review、合并；
2. 基于 readiness-v4 的 frozen query-v5 key domain 新增独立
   query-release-v5/runtime-v5 合同；不得修改历史 v4；
3. release-v5 必须消费 exact readiness-v4 packet/raw hashes 与同一 active pin
   generation，并继续保持短时人工签名和一次性 launch；
4. 人工签署 query-release-v5 后，才允许未来 one-shot readonly query。

本切片不 build/push OCI、不部署、不签署 release，也不执行 query。

## 测试

```bash
PYTHONPATH=scripts .venv/bin/python -m pytest -q \
  backend/tests/unit/test_commodity_c_fast_t1_readiness_v4_script.py \
  backend/tests/unit/test_commodity_c_fast_t1_readiness_v4_launcher.py

.venv/bin/ruff check \
  scripts/commodity_c_fast_t1_readiness_v4.py \
  scripts/commodity_c_fast_t1_readiness_v4_launcher.py \
  backend/tests/unit/test_commodity_c_fast_t1_readiness_v4_script.py \
  backend/tests/unit/test_commodity_c_fast_t1_readiness_v4_launcher.py

PYTHONPATH=scripts .venv/bin/python -m py_compile \
  scripts/commodity_c_fast_t1_readiness_v4.py \
  scripts/commodity_c_fast_t1_readiness_v4_launcher.py
```

failure-path 覆盖 exact content 重算、raw artifact splice、provenance-v3 signing
tool/dependency/runtime pins、五 keyring 十对 collision、build/outcome join splice、
non-canonical key encoding、unsafe ancestor、stale outcome、symlink、authority
escalation、真实 readiness-v3 file downgrade、
mixed-generation pin snapshot、write/return 前 pin rotation、同路径 custody 重建、
whitespace rewrite、create-only replay、expired packet、non-isolated direct entry、
startup hooks、`PYTHONPATH` module shadow、symlink escape、post-import path drift、
retained source bytes 和 independently pinned runtime identity。
