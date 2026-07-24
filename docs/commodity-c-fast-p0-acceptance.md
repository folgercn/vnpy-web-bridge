# C_FAST P0 独立终态接受

本文说明 `C_FAST_CROSS_SECTION_NEUTRAL` 的纯离线 P0 接受流程。该流程只对已经完成的 T1 一次性只读审计结果做独立复核、外部保管绑定和人工签名，不读取 Settings，不调用 API，不访问 repository/worker/QuestDB，也不授予采集、运行、下单、持仓变更、dispatch、替换或生产权限。

## 安全边界

一个可接受的来源终态必须同时满足：

- `terminal_state=SUCCEEDED_P0_PASS`
- `p0_pass=true`
- `proof_verified=true`
- `write_probe_attempted=false`
- `database_mutations=0`
- `orders_sent=0`
- `positions_modified=0`
- `dispatch_changed=false`
- `replay_allowed=false`
- `p0_acceptance_authorized=false`

签署后的 acceptance 固定声明以下权限全部为 `false`：

- `collection_authorized`
- `runtime_activation_authorized`
- `order_authorized`
- `position_mutation_authorized`
- `dispatch_authorized`
- `replacement_authorized`
- `production_authorized`
- `automatic_promotion_authorized`

因此，`p0_accepted=true` 只表示独立人工接受了一个符合约束的历史 P0 证据包，不代表可以进入数据采集、shadow runtime、自动 dispatch、testnet 或 production。后续每个阶段仍需单独的权限、冻结策略和激活流程。

## 被验证的证据

验证器严格读取以下九个 T1 文件的原始字节：

1. T1 release
2. T1 trusted keyring
3. audit manifest
4. consume marker
5. terminal seal
6. audit JSON
7. audit CSV
8. audit Markdown
9. readonly proof

它验证：

- T1 release 的 Ed25519 签名和 `t1_audit_release_signer` key purpose；
- release、manifest、consume、terminal、证据和 proof 的现有严格 schema；
- release、manifest、terminal 的 canonical JSON 绑定；
- consume marker 和四个完成产物的 exact-byte SHA256 绑定；
- 九个源文件的确定性 bundle index；
- snapshot、审计窗口、endpoint、QuestDB build、source commit 和 runtime image 的跨文件绑定；
- 验证期间四个完成产物未发生 TOCTOU 字节变化；
- evidence、proof、consume 和 terminal 的历史时序一致。

`acceptance_id` 固定为：

```text
p0-accept-<terminal seal 原始字节的 64 位小写 SHA256>
```

验证历史证据时不会因为“当前时间已经超过 release TTL”而拒绝。TTL 仍必须不超过 24 小时，且 `consumed_at` 和 terminal 的开始时间必须位于原始 release 窗口内；证据和 proof 的生成时间也必须落在 terminal 的历史执行区间内。

## 独立信任根

验签命令要求调用方从独立渠道显式传入两个 pinned canonical SHA256：

- T1 trusted keyring；
- P0 acceptance trusted keyring。

P0 acceptance keyring 的严格格式如下：

```json
{
  "schema_version": "commodity_c_fast_p0_acceptance_trusted_keys_v1",
  "keys": [
    {
      "key_id": "c-fast-p0-acceptance-key-a01",
      "purpose": "c_fast_p0_acceptance_signer",
      "public_key_base64": "<32-byte Ed25519 public key 的 base64>"
    }
  ]
}
```

key purpose 必须精确为 `c_fast_p0_acceptance_signer`。keyring、私钥、外部保管 identity、acceptance draft 和 signed acceptance 都应是普通文件、禁止符号链接，并设置为 `0600`。

两个 expected keyring SHA256 都是对应 keyring JSON 的 canonical JSON SHA256，不是文件原始字节 SHA256。不要从待验证 acceptance 本身取得 expected 值，否则不构成独立 pin。

## 外部保管 identity

外部保管 identity 的严格格式如下：

```json
{
  "schema_version": "commodity_c_fast_p0_external_custody_identity_v1",
  "custody_id": "c-fast-p0-external-custody-a01",
  "archive_type": "WORM",
  "archive_locator_sha256": "<不暴露真实 locator 的 64 位小写 SHA256>",
  "independent_from_t1_runner": true,
  "immutability_asserted": true
}
```

`archive_type` 只允许 `WORM` 或 `APPEND_ONLY`。acceptance 同时绑定 identity 的 exact-byte SHA256、canonical SHA256、`custody_id`、locator SHA256 和已归档 bundle index。

这个本地 JSON 是经过签名的人工声明和身份绑定，不会主动访问外部归档系统，也不能单独证明外部介质确实不可变。审阅人必须先在独立保管系统中核对 locator、bundle index 和归档时间，再签署 acceptance。

## 签署

unsigned draft 必须符合
[`commodity-c-fast-p0-acceptance-v1.schema.json`](schemas/commodity-c-fast-p0-acceptance-v1.schema.json)
的全部字段，但必须省略 `signature`。所有来源绑定值都必须来自已复核的证据包，不能手工改写以绕过验证。

```bash
python scripts/commodity_c_fast_p0_sign_acceptance.py \
  --input /secure/p0-acceptance-unsigned.json \
  --output /secure/p0-acceptance-signed.json \
  --private-key-file /secure/p0-acceptance-ed25519-private.pem \
  --acceptance-trusted-keyring /secure/p0-acceptance-keyring.json \
  --expected-acceptance-keyring-sha256 "$P0_KEYRING_SHA256" \
  --t1-release /archive/t1-release.json \
  --t1-trusted-keyring /archive/t1-keyring.json \
  --manifest /archive/manifest.json \
  --consume-marker /archive/consume.json \
  --terminal-seal /archive/terminal.json \
  --audit-json /archive/audit.json \
  --audit-csv /archive/audit.csv \
  --audit-markdown /archive/audit.md \
  --readonly-proof /archive/readonly-proof.json \
  --external-custody-identity /secure/external-custody-identity.json \
  --expected-t1-keyring-sha256 "$T1_KEYRING_SHA256"
```

签名器在签名之前会重新验证完整 T1 bundle、draft 绑定、独立 keyring pin、私钥与可信公钥的一致性。输出使用 create-only 语义，不会覆盖既有文件，也不会修改任何来源 T1 产物。

## 验证

```bash
python scripts/commodity_c_fast_p0_acceptance.py \
  --acceptance /secure/p0-acceptance-signed.json \
  --acceptance-trusted-keyring /secure/p0-acceptance-keyring.json \
  --expected-acceptance-keyring-sha256 "$P0_KEYRING_SHA256" \
  --t1-release /archive/t1-release.json \
  --t1-trusted-keyring /archive/t1-keyring.json \
  --manifest /archive/manifest.json \
  --consume-marker /archive/consume.json \
  --terminal-seal /archive/terminal.json \
  --audit-json /archive/audit.json \
  --audit-csv /archive/audit.csv \
  --audit-markdown /archive/audit.md \
  --readonly-proof /archive/readonly-proof.json \
  --external-custody-identity /secure/external-custody-identity.json \
  --expected-t1-keyring-sha256 "$T1_KEYRING_SHA256"
```

成功时退出码为 `0`，并输出 acceptance ID、signed acceptance canonical SHA256，以及两项明确的 `false` 权限提醒。任一 schema、签名、exact-byte、canonical、时序、外部保管或权限绑定不一致时退出码为 `2`。
