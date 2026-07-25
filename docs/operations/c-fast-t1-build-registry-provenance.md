# C_FAST T1 build/registry 独立签名 provenance

## 结论和边界

本契约给一份已经通过 OCI 内容校验的 T1 one-shot 镜像增加独立签名的
builder/registry witness assertion。它解决的是：

```text
exact OCI content report
  + exact build facts
  + immutable registry digest observation
  + dedicated Ed25519 signer
  + independently supplied keyring pin
```

成功 receipt 固定为：

```text
SIGNED_BUILD_REGISTRY_ASSERTIONS_VERIFIED_NO_RUNTIME_AUTHORITY
```

这只表示离线 verifier 验证了签名、keyring pin、源码/镜像/文件哈希、builder
事实和 registry digest 之间的一致性。verifier 不连接 builder 或 registry，
不会重新查询外部事实，因此固定：

```text
external_facts_independently_reverified=false
```

外部 build log、push receipt 和 registry observation 必须先由人工在受控环境
核对，再由专用 signer 承担这些 assertion。该签名不是透明日志、硬件
attestation、SLSA 或 registry 自身签名的替代品。

本契约和 receipt 均固定：

```text
authority_granted=false
readiness_authorized=false
ready_for_human_t1_release_signature_only=false
network_authorized=false
production_query_authorized=false
deployment_mutation_authorized=false
collection_authorized=false
runtime_activation_authorized=false
order_authorized=false
position_mutation_authorized=false
dispatch_authorized=false
production_authorized=false
t1_executed=false
production_queried=false
```

所以 provenance 验证成功不能独立生成 readiness，不能执行 L3、T1、P0、
execution-quality collection 或交易。

## 信任根和 key 隔离

专用 keyring 格式：

```json
{
  "schema_version": "commodity_c_fast_t1_build_registry_provenance_trusted_keys_v1",
  "keys": [
    {
      "key_id": "c-fast-t1-provenance-key-a01",
      "purpose": "t1_build_registry_provenance_signer",
      "public_key_base64": "<32-byte Ed25519 public key base64>"
    }
  ]
}
```

调用方必须从独立渠道传入 keyring 的 canonical JSON SHA256，不能从待验证
provenance 中读取 expected pin。keyring 和私钥必须是当前用户所有的 `0600`
普通非 symlink 文件。

签署和验证必须同时传入已冻结的 T1/L3 authority keyring 及其独立 pin：

```text
--t1-authority-keyring /secure/t1-release-keyring.json
--expected-t1-authority-keyring-sha256 <canonical SHA256>
--l3-authority-keyring /secure/l3-release-keyring.json
--expected-l3-authority-keyring-sha256 <canonical SHA256>
```

工具要求 T1 keyring/purpose 精确为
`commodity_c_fast_t1_trusted_keys_v1` / `t1_audit_release_signer`，L3
keyring/purpose 精确为
`commodity_c_fast_readonly_deployment_trusted_keys_v1` /
`readonly_deployment_release_signer`。两个 keyring 都必须匹配独立 canonical
pin；两域 public key 集合必须互不相交且合计至少两个不同 key。工具将两个
keyring SHA256 和全部 32-byte public key raw SHA256 签入 provenance，并拒绝
provenance signer 复用任一 key。缺少任一 authority keyring 或 pin 时 CLI
直接失败，不存在合法的空 exclusion 集合。

## 与 OCI content report 的绑定

输入必须是
`commodity_c_fast_t1_image_attestation_v1` 的真实 report。签署和验证都会重新
执行其 Draft 2020-12 schema，并交叉核对：

- report 原始字节 SHA256 和 canonical JSON SHA256；
- runtime source commit、`git archive`、Containerfile 和 OCI archive SHA256；
- immutable image reference、manifest digest 和 config digest；
- content report schema、content verifier exact bytes；
- 九份 runtime file hash map 的 canonical index SHA256；
- build 输出的 OCI archive/manifest/config；
- registry repository、digest reference 和 manifest digest。

`runtime_source_commit_sha` 只表示 T1 runtime 镜像的源码 commit。provenance
contract/verifier 自身不冒用该字段；其 exact 实现由
`provenance_verifier_sha256`、`signing_tool_sha256`、
`provenance_schema_sha256` 和 `receipt_schema_sha256` 单独绑定。

时间顺序固定为 build start < build complete <= push <= registry observation
<= provenance issue，content report capture 必须在 build complete 到 issue
之间。build 最长 6 小时，最后一项 evidence 到签发不得超过 24 小时，未来
时间超过 5 分钟时 fail closed。

`reproducible_build_verified=false` 是有意的：本 v1 绑定一次 exact build，不把
一次成功构建夸大成 reproducible build。

## 填写和签署

复制
[`c-fast-t1-build-registry-provenance-v1.template.json`](c-fast-t1-build-registry-provenance-v1.template.json)
到安全目录。模板故意包含 `PENDING_` 值并省略 signature 和四个工具文件
SHA256；未替换人工字段时 signer 必须失败，四个工具 SHA256 由 signer 从当前
checkout 自动填入。

```bash
KEYRING_SHA256="$(
  PYTHONPATH=scripts .venv/bin/python - <<'PY'
import hashlib
import json
from pathlib import Path

value = json.loads(Path("/secure/provenance-keyring.json").read_text())
raw = json.dumps(
    value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode()
print(hashlib.sha256(raw).hexdigest())
PY
)"

PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_t1_build_registry_provenance_sign.py \
  --input /secure/provenance.unsigned.json \
  --output /secure/provenance.signed.json \
  --private-key-file /secure/provenance-ed25519-private.pem \
  --trusted-keyring /secure/provenance-keyring.json \
  --expected-trusted-keyring-sha256 "$KEYRING_SHA256" \
  --content-attestation /archive/t1-image-content-attestation.json \
  --expected-runtime-source-commit-sha "$RUNTIME_SOURCE_SHA" \
  --expected-image-digest "$IMAGE_DIGEST" \
  --t1-authority-keyring /secure/t1-release-keyring.json \
  --expected-t1-authority-keyring-sha256 "$T1_KEYRING_SHA256" \
  --l3-authority-keyring /secure/l3-release-keyring.json \
  --expected-l3-authority-keyring-sha256 "$L3_KEYRING_SHA256"
```

私钥对应的 public key 必须与 dedicated keyring 匹配。输出采用
create-only `0600 + fsync`，不会覆盖历史 provenance。

## 离线验证

```bash
PYTHONPATH=scripts .venv/bin/python \
  scripts/commodity_c_fast_t1_build_registry_provenance.py \
  --provenance /archive/provenance.signed.json \
  --trusted-keyring /secure/provenance-keyring.json \
  --expected-trusted-keyring-sha256 "$KEYRING_SHA256" \
  --content-attestation /archive/t1-image-content-attestation.json \
  --expected-runtime-source-commit-sha "$RUNTIME_SOURCE_SHA" \
  --expected-image-digest "$IMAGE_DIGEST" \
  --t1-authority-keyring /secure/t1-release-keyring.json \
  --expected-t1-authority-keyring-sha256 "$T1_KEYRING_SHA256" \
  --l3-authority-keyring /secure/l3-release-keyring.json \
  --expected-l3-authority-keyring-sha256 "$L3_KEYRING_SHA256" \
  --json-output /new/archive/provenance-verification-receipt.json
```

verifier 使用 strict JSON parser，拒绝 duplicate key、NaN/Infinity、symlink、
超限输入、读取期间发生的替换、extra fields、错误签名、错误 pin、任一
exact-byte/canonical/digest/time 绑定不一致和任何 authority=true。receipt
同样采用 create-only 写入且没有 authority。receipt 中的
`signer_public_key_sha256` 是本次实际完成 Ed25519 验签的 32-byte raw public
key 的 SHA256；它与 `signer_key_id`、`trusted_keyring_sha256` 一起保留精确的
签名者身份事实，不从 provenance 的声明字段复制。

## 后续顺序

此 provenance 只是 readiness v2 的一个必要输入。完整顺序仍是：

1. exact OCI content report；
2. 本 build/registry signed provenance；
3. 已消费的 L3 raw signed release 和独立签名 post-deployment outcome；
4. readiness v2 只产生 `READY_FOR_HUMAN_SIGNATURE_ONLY`；
5. 冻结十品种 manifest 和短 TTL T1 release，由人工签署；
6. one-shot T1；
7. 外部 signed P0 acceptance；
8. 独立 collection-admission release。

在第 7/8 步之前不得接 repository、worker、QuestDB collection storage 或 PnL
runtime。
