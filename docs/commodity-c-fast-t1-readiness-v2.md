# C_FAST T1 readiness v2 派生门禁

## 结论

readiness v2 把 T1 OCI 内容、独立签名的 build/registry witness、L3 release
历史链和独立签名的 deployment post-outcome 汇合成一份短时、非权威 packet。

成功状态只有：

```text
READY_FOR_T1_RELEASE_V2_HUMAN_SIGNATURE_ONLY
```

它只表示 exact inputs 已通过机器校验，可以交给人类审核并签署未来的 T1
release v2。它不允许直接使用现有 T1 release v1，也不授予网络、生产只读查询、
采集、部署、交易或自动 promotion 权限。

```text
requires_t1_release_v2=true
t1_release_v1_accepted=false
packet_is_authority=false
authority_granted=false
readiness_authorized=false
ready_for_human_t1_release_signature_only=false
replay_allowed=false
network_authorized=false
production_query_authorized=false
readonly_query_authorized=false
collection_authorized=false
dispatch_authorized=false
trading_authorized=false
```

本工具没有 caller-authored packet/status 输入。调用方不能提交 `READY`、覆盖
`blocking_reasons` 或修改权限字段；任一验证失败时不生成 packet。

## 验证链

readiness 按以下顺序重新验证原始 artifacts：

```text
raw external image evidence + raw OCI layout + exact source checkout
  -> 重新运行 #129 OCI content verifier
  -> exact supplied content attestation object
  -> #131 signed build/registry witness provenance
  -> #130 raw signed L3 release + consume + non-authoritative receipt
  -> #130 十二份 pre evidence
  -> #132 六份 post evidence + independently signed outcome
  -> derived readiness v2 packet
```

### T1 OCI 内容

工具调用 `verify_image_evidence()`，重新解析 OCI layout、layer、config、入口、
依赖版本和 runtime bundle，并从 exact git commit 重算 source archive。重新生成的
report 必须与输入 content attestation 的 JSON object 完全相等；schema-valid 的
伪造 report 不会被接受。

packet 绑定 content attestation 原始字节和 canonical JSON SHA256、external
evidence 原始 SHA256、OCI archive 原始 SHA256、immutable image reference、
manifest/config digest、runtime bundle index 和 content verifier SHA256。

### Build/registry witness

工具验证 #131 的专用 Ed25519 signature、provenance keyring pin、T1/L3 authority
keyring pin 及 raw public-key 隔离，并要求 provenance 精确绑定同一 content raw
bytes、runtime source commit 和 T1 image digest。

该 witness 明确：

```text
external_facts_independently_reverified=false
```

readiness 不把离线验签夸大为重新联网查询 builder/registry。人类 T1 release v2
签署者仍需对 witness 信任域负责。

readiness 还比较两个已实际验签 signer 的 raw Ed25519 public-key SHA256：build/
registry provenance signer 与 deployment outcome signer 必须不同。不同的 key ID、
keyring schema 或 purpose 不能掩盖复用同一把 32-byte 公钥。

### L3 deployment outcome

工具调用 #132 verifier，后者用 `consume.consumed_at` 重验 #130 raw release、
release keyring、consume、receipt、十二份 pre evidence、六份 post evidence和
独立 outcome signature。consume/receipt 仍必须
`deployment_executed=false`；真实完成事实只来自 signed outcome。

outcome 和真实 deployment completion 必须覆盖 readiness 的完整有效窗口：
`deployment_ended_at <= outcome.issued_at <= readiness.generated_at`，并且
`readiness.expires_at` 距二者都不得超过一小时。packet 固定 15 分钟 TTL，因此
生成时二者最多只能已有 45 分钟。即使 outcome 签署者在 #132 允许的 24 小时窗口
末端才签署，也不能把旧的 QuestDB/principal/network 状态复用为当前 readiness。

## namespace 隔离

readiness 不比较或混用以下不同事实：

| namespace | 含义 |
|---|---|
| `t1_runtime_source_commit_sha` | one-shot runner 源码 commit |
| `l3_contract_source_commit_sha` | readonly deployment release 合同 commit |
| `outcome_contract_source_commit_assertion` | outcome 签署者的合同 revision assertion |
| `t1_runtime_image_digest` | T1 runner OCI manifest digest |
| `questdb_image_digest` | 已部署 QuestDB image digest |

T1 runner digest 与 QuestDB digest 不要求相等，也不得互相替代。三个 source 字段
同样只在自己的验证链内交叉绑定。

## 固定信任根和 custody

生产 CLI 不接受 keyring SHA256 参数。它只从 root-owned、non-symlink、
group/world 不可写目录读取：

```text
/run/c-fast-t1-readiness-v2-pins/
  provenance-keyring.sha256
  t1-authority-keyring.sha256
  l3-authority-keyring.sha256
  outcome-keyring.sha256
  packet-custody.path
```

四个 keyring pin 必须是 canonical JSON 的 64 位小写 SHA256。packet custody
必须是 pinned absolute path、当前 verifier UID 所有的 `0700` non-symlink 目录，
其父目录由 root 所有且不可 group/world 写。

`packet_id` 是生成/过期时间、verifier/schema、pin root/custody、三个 source
namespace、两个 digest namespace 以及全部上游 exact hashes 的 canonical
SHA256。输出只能是：

```text
<pinned custody>/<packet_id>.json
```

写入使用 guarded directory FD、`O_EXCL` 和 file/directory `fsync`。同一次派生
不能通过改变时间或输出路径覆盖 packet；重新派生会得到一个新 ID，后续 release
v2 必须绑定选中的 exact raw bytes。packet validator 会重新计算 ID、15 分钟 TTL、
outcome freshness relation 和当前 verifier/schema hashes；create-only 写入还会再次
检查 `generated_at <= write_time < expires_at`。写入前还会重新读取 root-owned
active pins，并要求四个 keyring pin 和 resolved custody path 与派生时 pins、
packet 内绑定全部一致；验证期间发生 pin 轮换时旧 packet 不会落盘。

## 运行

[`c-fast-t1-readiness-v2.template.json`](operations/c-fast-t1-readiness-v2.template.json)
只是填写清单，带有 `PENDING_` 且不是工具输入。正式命令直接传原始 artifacts：

```bash
PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_t1_readiness_v2.py \
  --external-image-evidence /archive/t1-external-evidence.json \
  --oci-layout-archive /archive/t1-runtime.oci.tar \
  --source-root /archive/exact-source-checkout \
  --content-attestation /archive/t1-content-attestation.json \
  --provenance /archive/t1-build-registry-provenance.signed.json \
  --provenance-keyring /secure/provenance-keyring.json \
  --t1-keyring /secure/t1-keyring.json \
  --outcome /var/lib/c-fast-readonly-deployment-custody/<attempt_id>.deployment-outcome.json \
  --outcome-keyring /secure/outcome-keyring.json \
  --expected-t1-runtime-source-commit-sha "$T1_RUNTIME_SOURCE_SHA" \
  --expected-t1-runtime-image-digest "$T1_RUNTIME_IMAGE_DIGEST" \
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
  --output /var/lib/c-fast-t1-readiness/<derived_packet_id>.json
```

成功输出仍显式包含：

```text
authority_granted=false
production_query_authorized=false
```

## 后续边界

本切片不修改 T1 one-shot release v1 或 runner。后续 T1 release v2 必须：

1. exact raw-byte 绑定 readiness packet；
2. exact raw-byte 绑定 content attestation、signed provenance 和 signed outcome；
3. 保持人工 Ed25519 signature、短 TTL、one-shot consume 和固定 custody；
4. 在最终 query 前由 runner 重新验证 readiness v2；
5. 继续禁止 write probe、数据库 mutation、Web Bridge RPC、订单、持仓和 dispatch。

在 T1 release v2 完成并由人类签署前，readiness packet 不能执行任何生产查询。
