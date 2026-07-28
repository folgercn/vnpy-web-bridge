# C_FAST SimNow Research Snapshot v1

对应 Issue #153。本合同只解决一次性、不可计数的 SimNow shakedown 输入，
不修改 `commodity_c_fast_cross_section_neutral_shadow_v1` 的
official-forward 月界和 `2026-08/2026-09` 语义。

## Plane 与 Authority

- Research Plane：人工确认后的 bundle 和原始 evidence 文件。
- Control Plane：producer、独立 verifier、签名验证、安装 receipt、Shadow
  acceptance 和 PR #149 Execution Permit。
- Execution Plane：仍仅为 Windows CTP RPC。
- `countable_forward=false`、`production_allowed=false`，不能配置为生产。

Research producer 没有 RPC、账户、持仓、委托或 TradeService 能力。它只消费
`commodity_c_fast_simnow_research_bundle_v1`，验证完整十品种、证据文件 SHA256、
冻结公式、权重、整数目标、PIT exact contract 元数据和人工确认声明，再产生：

```text
commodity_c_fast_cross_section_neutral_simnow_shakedown_v1
```

旧 official-forward 快照不能再被 PR #149 shakedown 适配器消费。

## 时间与连续性

- source 必须是 execution day 之前已完成的 official day；
- snapshot 必须在 execution day 创建并接受；
- TTL 最长 24 小时，过期立即 fail closed；
- genesis 要求 `previous_snapshot_hash=null` 且 previous targets 全零；
- 后续 snapshot 必须绑定前序 hash、exact contract 和整数目标；
- shakedown 使用独立 state receipt，不得与 official-forward state 混用。

## Bundle 与 evidence

Bundle 必须包含：

- 固定 candidate/rule 身份；
- `HUMAN_CONFIRMED_RESEARCH_INPUT_FOR_SIMNOW_SHAKEDOWN_ONLY`；
- 完整十品种信号、vol60、source/buffered weight、exact contract、整数目标、
  参考价和 PIT 元数据；
- research manifest、allocation、daily-roll、reference-price 原始 evidence
  的相对路径和 SHA256；
- bundle 自身 canonical checksum。

未知字段、路径逃逸、文件缺失、哈希不符、参考价未绑定 evidence、公式或风险
不一致均拒绝。签名工具不生成信号或目标。

## 离线流程

```bash
PYTHONPATH=backend python scripts/commodity_c_fast_simnow_snapshot.py produce \
  --bundle /custody/research-bundle.json \
  --evidence-root /custody/evidence \
  --output /custody/unsigned-snapshot.json

PYTHONPATH=backend python scripts/commodity_c_fast_shadow_sign.py \
  --input /custody/unsigned-snapshot.json \
  --output /custody/signed-snapshot.json \
  --private-key-file /custody/research-ed25519.key

PYTHONPATH=backend python scripts/commodity_c_fast_simnow_snapshot.py verify \
  --bundle /custody/research-bundle.json \
  --evidence-root /custody/evidence \
  --signed /custody/signed-snapshot.json \
  --trusted-keys /custody/trusted-keys.json \
  --contract-catalog /custody/rpc-contract-catalog.json

PYTHONPATH=backend python scripts/commodity_c_fast_simnow_snapshot.py install \
  --bundle /custody/research-bundle.json \
  --evidence-root /custody/evidence \
  --signed /custody/signed-snapshot.json \
  --trusted-keys /custody/trusted-keys.json \
  --contract-catalog /custody/rpc-contract-catalog.json \
  --output /runtime/c-fast/signed-snapshot.json
```

produce 和 install 均为 create-only、`0600`、fsync；install 额外生成 checksum
receipt。私钥必须为 `0600` 或更严格，禁止进入仓库、镜像、容器文件系统或日志。

`rpc-contract-catalog.json` 是同次只读预检导出的 `get_all_contracts` 原始数组，
或 `{"contracts":[...]}`。

## 部署

初始配置：

```env
WEB_TRADE_ENABLED=false
COMMODITY_SIMNOW_ENABLED=true
COMMODITY_C_FAST_SHADOW_ENABLED=true
COMMODITY_C_FAST_SHADOW_SNAPSHOT_PATH=/runtime/c-fast/signed-snapshot.json
COMMODITY_C_FAST_SHADOW_STATE_PATH=/runtime/c-fast/state.json
COMMODITY_C_FAST_SHADOW_EVIDENCE_PATH=/runtime/c-fast/reload.jsonl
COMMODITY_C_FAST_SIMNOW_SHAKEDOWN_ENABLED=false
COMMODITY_C_FAST_SIMNOW_ENVIRONMENT=simnow
COMMODITY_C_FAST_SIMNOW_AUTO_DISPATCH_ENABLED=false
COMMODITY_C_FAST_SIMNOW_MAX_SELECTED_PRODUCTS=2
RISK_MAX_ORDER_VOLUME=0
COMMODITY_SIMNOW_MAX_CHILD_ORDER_LOTS=0
```

`0` 表示不限制单笔手数且不按手数拆 child；签名整数目标、组合硬上限、账户双
白名单、持仓、价格、交易时段、急停和事实屏障仍然生效。

只读预检必须先完成：镜像 SHA、签名/expiry、bundle/evidence hash、双账户哈希、
gateway/RPC generation、交易日、合约规格、全量持仓/委托/成交、活动计划和急停。
任一不一致不打开交易开关。
