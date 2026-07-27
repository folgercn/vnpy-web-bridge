# C_FAST query-v3 P0 acceptance-v2 离线验收

本合同只处理 Issue #136 的历史证据验收。它不会连接 QuestDB、不会读取
DSN、不会启动 query child，也不会授予采集、runtime、RPC、下单、持仓、
dispatch、交易或 production 权限。

## 唯一允许的输入身份

验收器只允许以下精确身份，不提供 v1/v2/harness fallback：

- release：`commodity_c_fast_t1_one_shot_query_release_v3` /
  `c_fast_t1_exact_readiness_readonly_query_authority_v3`；
- consume：`commodity_c_fast_t1_query_consume_v3` /
  `c_fast_t1_query_v3_consume_before_final_revalidation`；
- child launch：`commodity_c_fast_t1_query_child_started_v3` /
  `c_fast_t1_one_shot_child_launch_claim_before_network`；
- terminal：`commodity_c_fast_t1_query_terminal_v3` /
  `c_fast_t1_readonly_query_v3_terminal`。

唯一可接受 terminal state 为 `COMPLETED_EVIDENCE_P0_PASS`，并同时要求
exit code 0、query completed、P0/proof true、数据库 mutation/RPC/order/
position 为零、dispatch 未改变。P0 blocked、launch/child/output failure、
timeout、interrupt 和 outcome unknown 一律拒绝。

## 历史验证与 active 状态隔离

acceptance-v2 使用独立 historical verifier。它不会调用 query-v3 的 live
`verify_query_release()`，不会读取 `/run` active pins，也不会用“当前时间”
重新判断已完成 query 的 TTL。历史时序按签名 release window、
`consumed_at`、`final_revalidation_at` 和 `ended_at` 判断。

调用方必须独立提供以下五个 keyring canonical SHA256 pin：

- query-v3 release；
- build/registry provenance；
- legacy T1 authority；
- L3 readonly deployment release；
- readonly deployment outcome。

验收器验证五个 keyring 的全部公钥材料，包括未被当前签名使用的 key。
acceptance-v2 keyring 的全部 key 也必须与这五个域完全隔离。

## 固定 evidence bundle

固定顺序由代码中的 `BUNDLE_FILE_ORDER` 定义，包含：

1. query release、query keyring、readiness packet；
2. content attestation、signed provenance、provenance/T1/L3 keyring、
   signed L3 release、signed deployment outcome、outcome keyring；
3. manifest、consume、child launch marker；
4. audit invocation、pre-connect gate、query invocation、query terminal；
5. audit JSON/CSV/Markdown、readonly proof。

所有 JSON 对象和 invocation JSON array 都重算 raw/canonical SHA256；
CSV/Markdown 只计算 raw SHA256。固定 index 使用
`commodity_c_fast_p0_bundle_index_v2`、固定 role 顺序、每个文件的字节数和
raw SHA256 计算。acceptance 与 external archive 都必须绑定同一个 index。

验收器还会重新运行既有 `validate_completed_outputs(..., exit=0)`，确保
四份 artifact 完整、P0 PASS、readonly proof 绑定 exact audit JSON，
并与 terminal 的四个 raw hash 一致。

## 外部归档边界

query terminal 明确声明
`CREATE_ONLY_LOCAL_RECORD_REQUIRES_EXTERNAL_CUSTODY`。acceptance-v2 要求
独立 custody identity、append-only/WORM 人工断言、archive locator、
archive time 和 exact bundle index。

`HUMAN_ASSERTION_NOT_MACHINE_VERIFIED` 的含义必须保留：仅凭离线选择性文件
无法密码学证明“此前从未出现 outcome-unknown terminal”。因此人工 reviewer
必须在独立 append-only/WORM custody 中核对该 attempt 的 first-seen terminal
和完整 inventory。若 consume 后曾出现缺 terminal、非 PASS terminal 或
outcome unknown，该 attempt 永久 burn；迟到 artifact 或后补 PASS 不得签署。

## 模板与签署顺序

模板：
`docs/operations/c-fast-p0-acceptance-v2.template.json`

模板故意包含 `INVALID_TEMPLATE_DO_NOT_SIGN` / `PENDING_*`，不能直接签名。
人工必须复制模板，删除 `template_state`，填入 verifier 输出对应的所有
hash、时间、身份和 archive 事实，并保持所有 authority 字段为 false。

签署器严格按以下顺序工作：

1. 一次性读取并验证 exact bundle；
2. 校验五个独立 pin、全部上游 keyset 隔离和 acceptance keyring；
3. 校验 draft schema/bindings；
4. 最后才读取 private key；
5. 以 `O_EXCL | O_NOFOLLOW` 在预先存在、当前用户拥有、0700 的目录中创建
   0600 signed output，fsync 后重读 exact bytes。

示例中的路径和 SHA256 都必须替换：

```bash
python scripts/commodity_c_fast_p0_sign_acceptance_v2.py \
  --input /private/review/acceptance-v2.draft.json \
  --output /private/review/acceptance-v2.signed.json \
  --private-key-file /private/keys/acceptance-v2.pem \
  --acceptance-trusted-keyring /private/keys/acceptance-v2-keyring.json \
  --expected-acceptance-keyring-sha256 <sha256> \
  --query-release /archive/query-release.json \
  --query-trusted-keyring /archive/query-keyring.json \
  --readiness-packet /archive/readiness-v2.json \
  --content-attestation /archive/content-attestation.json \
  --provenance /archive/provenance.signed.json \
  --provenance-trusted-keyring /archive/provenance-keyring.json \
  --t1-trusted-keyring /archive/t1-keyring.json \
  --l3-trusted-keyring /archive/l3-keyring.json \
  --l3-release /archive/l3-release.signed.json \
  --outcome /archive/deployment-outcome.signed.json \
  --outcome-trusted-keyring /archive/outcome-keyring.json \
  --manifest /archive/manifest.json \
  --consume-marker /archive/query-consume.json \
  --child-launch-marker /archive/query-child-started.json \
  --audit-child-invocation /archive/audit-invocation.json \
  --pre-connect-gate /archive/pre-connect-gate.json \
  --query-child-invocation /archive/query-invocation.json \
  --terminal-seal /archive/query-terminal.json \
  --audit-json /archive/audit.json \
  --audit-csv /archive/audit.csv \
  --audit-markdown /archive/audit.md \
  --readonly-proof /archive/readonly-proof.json \
  --external-custody-identity /private/review/custody-identity.json \
  --expected-query-keyring-sha256 <sha256> \
  --expected-provenance-keyring-sha256 <sha256> \
  --expected-t1-keyring-sha256 <sha256> \
  --expected-l3-keyring-sha256 <sha256> \
  --expected-outcome-keyring-sha256 <sha256>
```

验签入口使用相同 bundle/pin 参数，并将签署参数替换为：

```text
--acceptance <signed.json>
--acceptance-trusted-keyring <acceptance-keyring.json>
--expected-acceptance-keyring-sha256 <sha256>
```

验签 PASS 只表示
`HISTORICAL_QUERY_V3_EXACT_EVIDENCE_ONLY`。它不是 query、replay、collection、
runtime activation、dispatch、trading 或 promotion authority。
