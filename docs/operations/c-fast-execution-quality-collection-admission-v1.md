# C_FAST execution-quality collection-admission v1 离线合同

本文档对应 Issue #140。该切片只冻结一项人工准入事实：

```text
ADMISSION_VERIFIED_FOR_SEPARATE_RUNTIME_RELEASE_ONLY
```

它不启动 execution-quality sidecar，不创建 QuestDB table，不接 repository、
worker、Settings、startup、API 或页面，也不授予 collection/runtime/数据库/
查询/RPC/订单/持仓/dispatch/交易/production 权限。

## 依赖与 exact source

admission 不接受 P0 receipt、单个 `p0_accepted=true` 或手填 hash 作为事实源。
每次签署、初始验证、consume 前验证和 consume 后最终验证都必须重新执行：

1. raw signed execution-policy freeze v1/v2 ancestry、policy keyring 和独立 pin；
2. raw signed P0 acceptance-v2、acceptance keyring 和独立 pin；
3. acceptance-v2 的完整 query-v3 bundle verifier，包括 release、readiness、
   consume、child launch、terminal、manifest、两层 invocation、pre-connect
   gate、四份 audit/proof artifact、五个上游 keyring 与 bundle index；
4. policy、acceptance、五个上游域和 admission keyring 的全部 active/unused
   Ed25519 public-key material 隔离。

policy v1/v2 bytes 只读取一次后直接交给 raw-chain verifier；source binding 使用
的就是该次验签 bytes。函数返回前还会逐字节重读 v1、v2 和 policy keyring，
任何验签期间的文件替换都会拒绝，不允许把首次 receipt 与二次未验签 bytes 拼接。

因此，raw v1 重排、v2 ancestry 改写、不同 P0 attempt/source 拼接、artifact
改写、keyring pin rotation 或 unused key 复用都会 fail closed。

## Release 时间与身份

release 使用：

```text
schema_version=commodity_c_fast_execution_quality_collection_admission_v1
purpose=c_fast_execution_quality_collection_admission_offline_review
parent_issue_number=114
issue_number=140
```

`release_id` 必须全新且不可复用。`attempt_id` 固定为：

```text
collection-admission-attempt-<sha256(release_id UTF-8)>
```

时间必须满足：

```text
issued_at <= not_before < expires_at
expires_at - issued_at <= 10 minutes
verification_time + 30 seconds < expires_at
P0 acceptance accepted_at <= admission issued_at
```

release 还绑定 verifier、四份 schema、私有 custody 的 resolved path SHA256
和 `custody-identity.json` canonical SHA256、policy v1/v2 raw/canonical hash、
signed acceptance raw/canonical hash 和完整 P0
bundle raw/canonical/artifact/index hash。custody path 与 identity 必须分别由
root-owned、不可组/世界写的单行 pin 文件固定；custody 的父目录也必须
root-owned 且不可组/世界写，防止成功后在同一路径替换整个目录进行重放。

## 权限边界

签名 release、consume 和 terminal 均固定：

```text
collection_authorized=false
execution_quality_collection_authorized=false
runtime_activation_authorized=false
database_mutation_authorized=false
deployment_mutation_authorized=false
network_authorized=false
query_authorized=false
web_bridge_rpc_authorized=false
order_authorized=false
position_mutation_authorized=false
dispatch_authorized=false
trading_authorized=false
production_authorized=false
```

成功只表示：未来独立 runtime/storage/recovery release 可以把这份 raw signed
admission 作为一个必要输入并再次完整重验。当前 artifact 本身不能被 startup
读取后直接激活任何进程；`execution_quality_implemented` 必须继续为 `false`。

## INVALID/PENDING 模板与离线签署

模板：

[`c-fast-execution-quality-collection-admission-v1.template.json`](c-fast-execution-quality-collection-admission-v1.template.json)

模板故意包含 `template_state`、`PENDING_*`，并缺少 signature，不能通过 schema
或 signer。人工应复制模板，删除 `template_state`，使用 verifier 重算的 exact
binding 填满所有字段，并提供独立 admission keyring：

```text
schema_version=commodity_c_fast_execution_quality_collection_admission_trusted_keys_v1
purpose=c_fast_execution_quality_collection_admission_signer
```

签署器严格先完成全部 public evidence、pin、schema、binding 和全 keyset 隔离
检查，最后才读取 private key。私钥必须匹配指定 admission signer；signed output
写入预先存在、当前用户所有、0700 的目录，采用 0600 create-only + fsync。

```bash
PYTHONPATH=backend:scripts .venv/bin/python \
  scripts/commodity_c_fast_execution_quality_sign_collection_admission.py \
  --input /private/review/admission-v1.unsigned.json \
  --output /private/review/admission-v1.signed.json \
  --private-key-file /private/keys/admission-v1.pem \
  --admission-trusted-keyring /private/keys/admission-v1-keyring.json \
  --expected-admission-keyring-sha256 <sha256> \
  --custody-dir /private/custody/c-fast-admission \
  --custody-path-pin /run/c-fast-collection-admission/custody.path \
  --custody-identity-pin /run/c-fast-collection-admission/custody-identity.sha256 \
  --policy-v1 /archive/policy-v1.signed.json \
  --policy-v2 /archive/policy-v2.signed.json \
  --policy-trusted-keyring /private/keys/policy-keyring.json \
  --expected-policy-keyring-sha256 <sha256> \
  --acceptance /archive/p0-acceptance-v2.signed.json \
  --acceptance-trusted-keyring /private/keys/p0-acceptance-keyring.json \
  --expected-acceptance-keyring-sha256 <sha256> \
  <完整 acceptance-v2 exact bundle 与五个独立 keyring pin 参数>
```

## Consume、final revalidation 与 terminal

verifier 的顺序固定为：

```text
initial full verify
  -> pre-consume full verify
  -> create-only consume + fsync + exact reopen
  -> final full verify
  -> create-only terminal
```

consume 后 attempt 永久 burn，不能删除 marker 后复用。final revalidation 期间
任一 raw source、pin、schema、release 或 key material 变化，terminal 必须为：

```text
FAILED_FINAL_REVALIDATION_NO_COLLECTION
```

只有所有 exact bytes 保持一致，terminal 才能为：

```text
ADMISSION_VERIFIED_FOR_SEPARATE_RUNTIME_RELEASE_ONLY
```

两种 terminal 都记录零 database mutation、零 RPC、零订单、零仓位修改和
`dispatch_changed=false`。consume 与 terminal 都重复绑定 custody path/identity；
consume 前、final revalidation 和 terminal 写入前都会重新检查同一目录 identity。

## 验证

```bash
PYTHONPATH=backend:scripts .venv/bin/pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_collection_admission.py

PYTHONPATH=backend:scripts .venv/bin/pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_policy.py \
  backend/tests/unit/test_commodity_c_fast_execution_policy_v2.py \
  backend/tests/unit/test_commodity_c_fast_p0_acceptance_v2.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_collection_admission.py

.venv/bin/ruff check \
  scripts/commodity_c_fast_execution_quality_collection_admission.py \
  scripts/commodity_c_fast_execution_quality_sign_collection_admission.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_collection_admission.py
```
