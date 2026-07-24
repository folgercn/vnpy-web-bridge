# C_FAST execution-quality policy 离线签名冻结

本文档对应 Issue #114 的 PR-C1。该切片为 PR-C0 的纯虚拟 intent policy
增加独立的人工作业签名冻结，但仍不授予 execution-quality collection、
runtime activation、派单、替换或生产权限。

## 固定边界

签名 envelope 固定为：

```text
schema_version=commodity_c_fast_execution_policy_freeze_v1
candidate_id=C_FAST_CROSS_SECTION_NEUTRAL
policy_scope=EXECUTION_QUALITY_SHADOW_FOUNDATION_ONLY
policy_frozen=true
protected_price_rule_state=DEFERRED_NOT_COLLECTION_READY
p0_pass_required_before_collection=true
foundation_only=true
collection_authorized=false
runtime_activation_authorized=false
authority_granted=false
dispatch_allowed=false
replacement_allowed=false
production_allowed=false
```

`policy_frozen=true` 只表示人工签名已经把 PR-C0 policy 的完整 JSON 和
`policy_hash` 固化。它不等于 sidecar 可启动，也不表示 P0 已通过。当前
`protected_price_rule=DEFERRED_TO_DECISION_SNAPSHOT`，因此该 freeze 明确
保持 `DEFERRED_NOT_COLLECTION_READY`，不能被解释为完整 collection
policy。

本切片没有增加 Settings、环境变量、startup hook、route、repository、
QuestDB、文件状态适配器、worker、行情订阅、RPC 或 TradeService。
`execution_quality_implemented` 继续为 `false`。

## 签名与信任域

freeze envelope 直接嵌入严格的
`CFastVirtualIntentPolicyDTO`，并绑定：

- 唯一 `freeze_id`；
- 完整 policy 及 canonical JSON `policy_hash`；
- 人工 reviewer role 和 UTC 冻结时间；
- candidate、scope、P0 前置条件和全部非激活 Literal；
- 独立 `signer_key_id`。

Ed25519 信任项只能包含：

```json
{
  "public_key_base64": "<32-byte Ed25519 public key>",
  "purpose": "execution_quality_policy_freeze_signer"
}
```

研究 snapshot signer、T1 one-shot release signer 或其他 purpose 不能
跨域使用。验证器对不受信 key、错误 purpose、额外 trust-entry 字段、
非 32-byte key、错误签名和修改后重算 checksum 的 artifact 全部 fail
closed。

签名覆盖除 `signature` 外的完整 canonical JSON。`freeze_sha256` 同样
对该 unsigned payload 取 SHA256，因此更换签名字节不会改变内容身份；
它是 checksum，不是第二个签名。

验证成功只产生
`commodity_c_fast_execution_policy_freeze_receipt_v1` receipt。receipt
继续固定全部运行权限为 `false`。未来如需持久化或启动 sidecar，必须
重新验证原始 signed freeze，不能只信任一个可自行构造的 receipt JSON。

## 严格 JSON 与签名工具

parser 固定：

- 最大 64 KiB；
- UTF-8 JSON object；
- 重复 key、`NaN`、`Infinity`、extra field 全部拒绝；
- `frozen_at_utc` 必须是 UTC；
- policy hash 必须与完整 policy 一致。

签名工具只给已经写全 policy/hash/人工 review 字段的 unsigned JSON
增加 Ed25519 signature，不生成或修改 policy 参数：

```bash
PYTHONPATH=backend python scripts/commodity_c_fast_execution_policy_sign.py \
  --input /secure/c-fast-policy-freeze-unsigned.json \
  --private-key-file /secure/c-fast-policy-freeze.key \
  --output /secure/c-fast-policy-freeze-signed.json
```

私钥必须是 `0600` 或更严格的普通非 symlink 文件。输出使用 `0600`
create-only 写入；目标已存在或是 symlink 时拒绝，不覆盖历史人工
artifact。

## 与 T1/P0 和后续 PR 的关系

本 freeze 可以与 T1 one-shot authority 并行实现，但两者不能互相替代：

- T1 authority 只授权一次只读 QuestDB 审计；
- 本 freeze 只冻结离线 execution-quality foundation policy；
- P0 terminal evidence 尚未通过前，两者都不能启动 P2/T2 collection。

仍被阻塞的范围：

- execution-quality QuestDB table、repository、DDL 和 DSN；
- filesystem/database storage adapter；
- tick/horizon worker、恢复、markout、book-walk、fill bounds 和 PnL；
- config、startup、API、UI；
- C_FAST SimNow shakedown 或任何委托能力。

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_policy.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality.py

python -m compileall -q \
  backend/app/schemas/commodity_c_fast_execution_policy.py \
  backend/app/services/commodity_c_fast_execution_policy.py \
  scripts/commodity_c_fast_execution_policy_sign.py
```
