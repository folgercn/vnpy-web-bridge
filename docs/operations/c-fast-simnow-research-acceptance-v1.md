# C_FAST SimNow Research Acceptance v1

## 1. 范围与权限边界

本流程属于 **Control Plane**，只验收 Issue #157 / PR #160 产生的
`C_FAST_CROSS_SECTION_NEUTRAL` 非 countable SimNow Research Evidence。

唯一成功状态为：

```text
READY_FOR_HUMAN_SIMNOW_EXECUTION_PERMIT_ONLY
```

它只表示：Research Evidence、root-owned custody、人工选定的 1–2 个产品和
预期 SimNow account SHA256 在一个不超过 15 分钟的窗口内一致，可以交给后续
独立 Issue 做人工 Execution Permit 复核。

它不是 Deployment Authority 或 Execution Permit。签名 acceptance、consume
marker 和 receipt 均固定：

- `countable_forward=false`
- `production_allowed=false`
- `deployment_authorized=false`
- `execution_permit_issued=false`
- network/RPC/order/position/dispatch/trading/runtime/production authority 全部
  `false`
- `orders_sent=0`
- `positions_modified=0`
- `web_bridge_rpc_calls=0`

本版本不读取 SimNow 账户、订单、成交或持仓，不连接网络，不 import
Settings/API/RPC/TradeService/adapter，不修改 official-forward Shadow DTO，
也不处理 query-v3 readiness 或 OCI。

## 2. 输入事实

签名前必须已经完成 #160 install，并保留同一次 Research bundle 使用的：

1. root-owned、非 group/world writable 的 custody 目录；
2. 确定性命名的 install claim、signed bundle、install receipt；
3. Research trusted keyring 及其独立 raw SHA256 pin；
4. Research signer source 的独立 raw SHA256 pin；
5. 以下九份 exact raw Research artifacts：

| 参数 | Research artifact |
| --- | --- |
| `--freeze-contract` | freeze contract |
| `--research-manifest` | research manifest |
| `--signal-evidence` | signal evidence |
| `--target-evidence` | target evidence |
| `--allocation-evidence` | allocation evidence |
| `--daily-roll-evidence` | PIT daily-roll evidence |
| `--reference-price-evidence` | official-open reference price |
| `--calendar-authority` | official-day calendar authority |
| `--contract-spec-evidence` | contract specs |

verifier 不信任 install receipt 自报成功。它会从 `research_bundle_id` 唯一
推导三个 #160 文件名，重新执行 #160 bundle verifier，并重验：

- claim/bundle/receipt exact canonical raw bytes；
- bundle signature、formula、target、PIT-main、DTE、时间窗口；
- 九份 artifact 的完整角色集、raw hash、size、regular/non-symlink、不同
  path/inode 和读取期稳定性；
- custody root path/device/inode/uid/mode；
- claim/bundle/receipt 的确定性文件名、device/inode/uid、精确 `0600` mode
  及文件 identity index；
- Research keyring 的完整 key set。

## 3. 独立 Control key

Control acceptance 必须使用独立 Ed25519 keyring：

```json
{
  "schema_version": "commodity_c_fast_simnow_research_acceptance_trusted_keys_v1",
  "purpose": "c_fast_simnow_research_acceptance_signer",
  "keys": [
    {
      "key_id": "c-fast-acceptance-key-a01",
      "purpose": "c_fast_simnow_research_acceptance_signer",
      "public_key_base64": "PENDING_32_BYTE_ED25519_PUBLIC_KEY_BASE64"
    }
  ]
}
```

调用方必须独立提供 keyring raw SHA256。verifier 会读取 Research 和 Control
两个 keyring 的全部 entry；任一 Control public-key material 与任一 Research
key material 相同都会失败，不只比较当前 signer key。

acceptance verifier 不 import、定位或读取 signer 文件。它只比较 acceptance
内的 `acceptance_signer_sha256` 与调用方独立 pin。offline signer 必须先完成
所有 public/custody/artifact/account/target/key-domain 检查，之后才读取私钥。

## 4. 准备 INVALID/PENDING draft

复制模板到预先建立的私有目录：

```bash
install -d -m 0700 /private/c-fast-acceptance
cp \
  docs/operations/c-fast-simnow-research-acceptance-v1.template.json \
  /private/c-fast-acceptance/unsigned-acceptance.json
chmod 0600 /private/c-fast-acceptance/unsigned-acceptance.json
```

模板故意不能签名。人工必须：

1. 删除 `template_state`；
2. 填写 `accepted_at`、`not_before`、`expires_at`；窗口必须为正且不超过
   15 分钟，并完全落在 Research bundle 有效期和 execution day 内；
   `accepted_at` 必须是已经发生的人工接受事实，不能使用未来时刻；
3. 填写 `execution_day`；
4. 填写真实 `reviewer_role` 和非 `PENDING_` 的 `human_signature`；
5. 填写 Control `signer_key_id`；
6. 填写已安装的 `research_bundle_id`；
7. 填写 independently pinned `expected_simnow_account_sha256`；
8. 填写排序后的 `selected_products`，只能选 1–2 个冻结十品种中的产品。

其余 `PENDING_DERIVED_BY_SIGNER` 字段由 signer 从 exact installed chain 推导。
人工不得填写或改写 target quantity。signer 只会从 signed Research bundle
复制 exact contract、previous quantity、target quantity、delta 和完整 target
row SHA256。选中产品的 signed target delta 为零时签名失败。

账户 pin 示例；不要把真实 account ID 写入仓库、报告或 shell history：

```bash
read -r -s SIMNOW_ACCOUNT_ID
SIMNOW_ACCOUNT_SHA256="$(
  printf '%s' "${SIMNOW_ACCOUNT_ID}" | shasum -a 256 | awk '{print $1}'
)"
unset SIMNOW_ACCOUNT_ID
```

## 5. 生成独立 pins

```bash
RESEARCH_KEYRING_SHA256="$(
  shasum -a 256 /private/c-fast/research-keyring.json | awk '{print $1}'
)"
RESEARCH_SIGNER_SHA256="$(
  shasum -a 256 \
    scripts/commodity_c_fast_simnow_sign_research_bundle.py \
    | awk '{print $1}'
)"
ACCEPTANCE_KEYRING_SHA256="$(
  shasum -a 256 /private/c-fast-acceptance/keyring.json | awk '{print $1}'
)"
ACCEPTANCE_SIGNER_SHA256="$(
  shasum -a 256 \
    scripts/commodity_c_fast_simnow_sign_research_acceptance.py \
    | awk '{print $1}'
)"
```

定义 exact Research artifact 参数：

```bash
ARTIFACT_ARGS=(
  --freeze-contract /sealed/c-fast/freeze-contract.raw
  --research-manifest /sealed/c-fast/research-manifest.raw
  --signal-evidence /sealed/c-fast/signal-evidence.raw
  --target-evidence /sealed/c-fast/target-evidence.raw
  --allocation-evidence /sealed/c-fast/allocation-evidence.raw
  --daily-roll-evidence /sealed/c-fast/daily-roll-evidence.raw
  --reference-price-evidence /sealed/c-fast/reference-price-evidence.raw
  --calendar-authority /sealed/c-fast/calendar-authority.raw
  --contract-spec-evidence /sealed/c-fast/contract-spec-evidence.raw
)
```

## 6. Public-check-first 签名

```bash
python scripts/commodity_c_fast_simnow_sign_research_acceptance.py \
  --input /private/c-fast-acceptance/unsigned-acceptance.json \
  --output /private/c-fast-acceptance/signed-acceptance.json \
  --private-key-file /private/c-fast-acceptance/control-private-key \
  --custody-root /var/lib/c-fast-simnow-research-custody \
  --research-trusted-keyring /private/c-fast/research-keyring.json \
  --expected-research-keyring-raw-sha256 \
    "${RESEARCH_KEYRING_SHA256}" \
  --expected-research-signer-sha256 "${RESEARCH_SIGNER_SHA256}" \
  --acceptance-trusted-keyring /private/c-fast-acceptance/keyring.json \
  --expected-acceptance-keyring-raw-sha256 \
    "${ACCEPTANCE_KEYRING_SHA256}" \
  --expected-acceptance-signer-sha256 \
    "${ACCEPTANCE_SIGNER_SHA256}" \
  --expected-simnow-account-sha256 "${SIMNOW_ACCOUNT_SHA256}" \
  "${ARTIFACT_ARGS[@]}"
```

输出文件使用 `O_EXCL` create-only、`0600`，不会覆盖已有文件。任何 public
检查失败时 signer 不读取私钥。signer 不复用进程入口时间：私钥读取前和
真实签名前都会重新取得当前时间并重验完整 public snapshot，输出后再用新的
当前时间验证 signed acceptance。`current == expires_at` 已视为过期，禁止
签名。

## 7. 独立 verify

```bash
python scripts/commodity_c_fast_simnow_research_acceptance.py verify \
  --acceptance /private/c-fast-acceptance/signed-acceptance.json \
  --custody-root /var/lib/c-fast-simnow-research-custody \
  --research-trusted-keyring /private/c-fast/research-keyring.json \
  --expected-research-keyring-raw-sha256 \
    "${RESEARCH_KEYRING_SHA256}" \
  --expected-research-signer-sha256 "${RESEARCH_SIGNER_SHA256}" \
  --acceptance-trusted-keyring /private/c-fast-acceptance/keyring.json \
  --expected-acceptance-keyring-raw-sha256 \
    "${ACCEPTANCE_KEYRING_SHA256}" \
  --expected-acceptance-signer-sha256 \
    "${ACCEPTANCE_SIGNER_SHA256}" \
  --expected-simnow-account-sha256 "${SIMNOW_ACCOUNT_SHA256}" \
  "${ARTIFACT_ARGS[@]}"
```

验证成功只说明 signed acceptance 当前有效；还没有完成 one-shot consume。

## 8. One-shot consume

人工再次核对 bundle ID、execution day、account SHA256 和 1–2 个 selected
products 后执行：

```bash
python scripts/commodity_c_fast_simnow_research_acceptance.py consume \
  --acceptance /private/c-fast-acceptance/signed-acceptance.json \
  --custody-root /var/lib/c-fast-simnow-research-custody \
  --research-trusted-keyring /private/c-fast/research-keyring.json \
  --expected-research-keyring-raw-sha256 \
    "${RESEARCH_KEYRING_SHA256}" \
  --expected-research-signer-sha256 "${RESEARCH_SIGNER_SHA256}" \
  --acceptance-trusted-keyring /private/c-fast-acceptance/keyring.json \
  --expected-acceptance-keyring-raw-sha256 \
    "${ACCEPTANCE_KEYRING_SHA256}" \
  --expected-acceptance-signer-sha256 \
    "${ACCEPTANCE_SIGNER_SHA256}" \
  --expected-simnow-account-sha256 "${SIMNOW_ACCOUNT_SHA256}" \
  "${ARTIFACT_ARGS[@]}"
```

consume marker 以 `research_bundle_id` 唯一命名，而不是以 acceptance ID
命名。因此同一个 Research bundle 即使重新签一份 acceptance，也不能再次
验收。

写入顺序固定：

1. create-only 写 bundle-scoped consume marker；
2. 重新验证 signed acceptance、完整 install chain、九份 artifacts、两个
   keyring 和 custody；
3. 重新读取 acceptance、bundle、claim、install receipt、两个 keyring、
   九份 raw artifacts、custody root 和三个 custody 文件 identity，完成
   final composite snapshot；
4. 记录 `final_revalidated_at`，并使用新取得的当前时间做 freshness 检查；
   `current == expires_at` 失败；
5. 重新打开并核对 exact consume marker；
6. 记录 receipt commit 时刻，要求
   `accepted_at <= consumed_at <= final_revalidated_at <= ready_at <
   expires_at`；
7. create-only 写 acceptance receipt；
8. 写入后再次取得当前时间。若时钟回退或已经到达 `expires_at`，立即删除本次
   尚未提交的 receipt，保留不可逆 consume marker 并 fail closed。

并发消费只有一个进程能写入 marker。marker 一旦存在，任何后续 consume
都失败。入口验证、marker 前、marker 后、final revalidation、receipt commit
前后分别使用新取得或注入的当前时刻；每次观测都不得早于前一次，不会用入口
`now` 穿过整个流程，也不会接受倒退时钟产生的成功 chronology。

## 9. 崩溃与失败处理

如果进程在 marker 写入后、receipt 写入前发生 `SIGKILL`、OOM、磁盘故障或
宿主机重启，custody 会留下 marker 而没有 receipt。此状态永久 fail closed：

- 不得删除、重命名或覆盖 marker；
- 不得重放旧 acceptance；
- 不得为同一个 Research bundle 重新签 acceptance 后再消费；
- 不得把 marker 或 signed acceptance 当作 Execution Permit；
- 必须重新生产新的 Research bundle，并经过新的 install 和 Acceptance。

receipt 存在但 marker 缺失、marker 损坏、任一输出预先存在或 custody 被替换
同样失败。

## 10. 开发验证

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_simnow_research_acceptance.py

PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_simnow_research_bundle.py \
  backend/tests/unit/test_commodity_c_fast_shadow.py \
  backend/tests/unit/test_commodity_c_fast_simnow.py \
  backend/tests/unit/test_commodity_simnow.py

ruff check \
  scripts/commodity_c_fast_simnow_research_acceptance.py \
  scripts/commodity_c_fast_simnow_sign_research_acceptance.py \
  backend/tests/unit/test_commodity_c_fast_simnow_research_acceptance.py

python -m py_compile \
  scripts/commodity_c_fast_simnow_research_acceptance.py \
  scripts/commodity_c_fast_simnow_sign_research_acceptance.py
```

本流程的 receipt 仍不能接入 PR #149 adapter。后续必须由独立 Execution
Permit Issue 绑定实时 gateway/account/positions/orders/quotes 与 exact preview
plan hash，人工签发 Permit 后 Execution Plane 才能考虑消费。
