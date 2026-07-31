# C_FAST execution-quality artifact revalidation adapter

本文档对应 Issue #217 的第二个 code-only 切片。它补齐 runtime foundation 与未来
各类签名 verifier 之间的文件级汇合边界，但仍不接 Tick、QuestDB、API、RPC 或
交易能力。

## 本切片验证的对象

adapter 每次 startup、reload 或 recovery 都要求一次性提供并重验完整七件集合：

```text
signed_p0_acceptance
collection_admission
execution_policy
signed_snapshot
virtual_intent_plan
contract_spec_set
custody_binding
```

每个 role 的密码学签名、schema 和业务语义由独立 verifier callback 重放；callback
必须返回与 adapter 本次稳定读取的 exact raw/canonical SHA256 完全一致的强类型
receipt。缺任一 verifier、role 错配、签名未验证、语义未验证或 authority literal
不为 false 都会失败关闭。

adapter 自身负责：

- 固定完整且唯一的 role/path/verifier 集合，构造后不能热替换；
- 校验 custody root path/identity/owner/mode pin 和完整父目录链；
- 在整个重验窗口保留 `O_DIRECTORY | O_NOFOLLOW` root fd；
- 所有文件只按 retained root dirfd 和 basename 打开，拒绝 symlink、hardlink、
  owner 漂移、group/world writable、非 canonical JSON 和超限文件；
- 按 `fstat().st_size` 循环精确读取、同一 fd 双读，并在所有 verifier 完成后重开
  七份文件；
- 强制 admission、snapshot、plan、spec 和 custody 的跨文件 raw SHA256 join；
- 强制关键 role 的 exact-contract 集非空且完全一致；
- 强制 P0、admission、snapshot、custody 仍在有效期内，并以最早 expiry 作为
  runtime revalidation receipt 的有效期。

## 仍然阻塞的外部事实

本切片不包含、也不伪造 query-v4 P0 acceptance、collection admission、合法签名
snapshot/plan/spec/custody。当前 `main` 的 P0 acceptance 与 collection-admission
仍绑定历史 query-v3 证据；必须等待 #216 的 query-v4 readiness、真实只读 query、
query-v4 P0 acceptance 和后继 admission verifier。生产接线还必须把这些 exact
verifier 以不可热替换方式绑定到本 adapter。

因此本切片完成后仍保持：

```text
runtime_active=false
execution_quality_implemented=false
collection_authorized=false
database_mutation_authorized=false
dispatch_allowed=false
order_authorized=false
position_mutation_authorized=false
production_allowed=false
orders_sent=0
positions_modified=0
```

## 验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_artifact_revalidation.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_runtime.py

ruff check \
  backend/app/schemas/commodity_c_fast_execution_quality_runtime.py \
  backend/app/services/commodity_c_fast_execution_quality_artifact_revalidation.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_artifact_revalidation.py
```
