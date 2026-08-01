# Research Warehouse → C_FAST source view v1

本流程把已验证的 186 日 Research Warehouse custody 转成冻结
`C_FAST_CROSS_SECTION_NEUTRAL` pure producer 所需的
`commodity_c_fast_pit_frozen_source_view_v1`，并逐字节重放九件 Research
artifacts。它补齐 #153 中 Warehouse 与 #160 sealed Research bundle 之间的确定性
数据桥，不授予签名、安装、Acceptance、Permit、RPC、下单或生产权限。

## 时间边界

- `source_month` 必须是已完整结束的前一自然月。
- `research_as_of_official_day` 是该月最后一个官方交易日。
- `execution_day` 是紧随其后的第一个官方交易日。
- 运行前必须已有 execution-day 正常日采集 receipt、SHFE/INE exact raw 与已提交
  manifest；source view 的 `generated_at/cutoff_at` 使用本次生成的真实观察时刻，
  必须晚于 receipt 的 `completed_at` 且仍在同一 execution day，二者都会进入
  provenance，禁止回填成历史时刻。
- 因此 2026-07 source month 的首次合法生成点是在 2026-08-03 当日官方日数据
  收口之后，而不是 2026-08-01 周末。

## 生成

以下全部 SHA256 必须来自 root/operator 冻结台账，不能从当前文件反推：

```bash
PYTHONPATH=scripts python3 scripts/research_warehouse_c_fast_source_view.py \
  --runtime-input /private/runtime-input.json \
  --operator-state /private/operator-state.json \
  --operator-state-sha256 <64-hex> \
  --history-receipt /private/history-backfill-receipt.json \
  --history-receipt-sha256 <64-hex> \
  --manifest-public-key /private/manifest-public-key.pem \
  --manifest-public-key-sha256 <64-hex> \
  --contract-registry /private/static-core-contract-registry.json \
  --contract-registry-sha256 <64-hex> \
  --source-month 2026-07 \
  --output /private/create-only/c-fast-202607
```

输出父目录必须由当前用户持有且权限为 private；输出目录为 create-only，包含：

- `source-view.json`
- `lineage.jsonl`
- `source-evidence.jsonl`
- 九个 `<artifact_role>.json`

独立重放：

```bash
PYTHONPATH=scripts python3 \
  scripts/research_warehouse_c_fast_source_view_verify.py \
  --input /private/create-only/c-fast-202607
```

验证器重新运行 frozen pure producer，要求九件 artifacts exact-byte 一致，同时校验
sealed-export lineage 与 evidence hash binding。任一缺日、month-end 缺失、execution
receipt 未提交、manifest/revision 漂移、contract registry 冲突、旧主合约缺少
execution-day official open、DTE 不安全或字节被修改都会 fail closed。
发布中途失败时保留 create-only 的 partial 目录供审计，不清理或覆盖父目录中的
任何既有对象；operator 必须隔离该目录并换一个全新输出名重跑。

## 后续边界

本输出仍保持全部 `authority=false`。下一步只能通过既有
`research_warehouse_sealed_export.py` 独立签署/验签 sealed export，再进入 #160
Research bundle、#165 Acceptance 与人工选择的 #178 Execution Permit。不得直接把
本目录挂给 CommoditySimNow，也不得把 producer projection 当成 signed snapshot。
