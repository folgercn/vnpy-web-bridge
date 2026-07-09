# MAK v2 远端 Safety Audit Runbook

本文用于 PR-B/T1 远端部署后的只读安全证据采集。该流程只允许调用：

```text
POST /api/mak-v2/testnet-observer/safety-audit
```

禁止调用 `/api/orders`、`/api/mak-v2/testnet-observer/dry-run/signal`、`/api/mak-v2/testnet-observer/flatten-testnet` 或任何真实下单/撤单接口。

## 前置检查

1. 确认远端已部署包含 MAK v2 observer safety-audit endpoint 的版本。
2. 确认远端运行环境使用真实部署 secrets 注入 RPC 与鉴权配置。
3. 不要用 `.env.example`、默认 `127.0.0.1` RPC 地址或本地缺失 `.env` 状态推导 RPC/交易结论。
4. 准备一个 admin 角色 access token，并只通过环境变量传入采集脚本。

## 设置 Token

默认环境变量名是 `VNPY_WEB_BRIDGE_TOKEN`：

```bash
export VNPY_WEB_BRIDGE_TOKEN='粘贴远端 admin access token'
```

不要把 token 放进命令行参数、shell history、文档、CSV 或工单评论。需要换变量名时使用 `--token-env`，但变量值仍必须来自环境变量。

## 采集命令

选择远端 backend base URL 和本次证据目录。`--contract` 可重复传入本次 T1 预期检查的精确 GFEX 合约：

```bash
python scripts/mak_v2_collect_safety_audit.py \
  --base-url https://YOUR-BRIDGE-HOST \
  --output-dir artifacts/mak_v2_safety_audit_$(date -u +%Y%m%dT%H%M%SZ) \
  --probe-rpc \
  --collect-rpc-snapshot \
  --require-rpc-connected \
  --contract GFEX.ps2609 \
  --contract GFEX.lc2609
```

脚本会把 JSON 审计结果输出到 stdout，并在 `--output-dir` 生成：

- `mak_v2_safety_audit.json`
- `mak_v2_safety_audit_checks.csv`
- `mak_v2_safety_audit_accounts.csv`
- `mak_v2_safety_audit_contracts.csv`

脚本只读取 token env，不会打印 token。HTTP/API 失败会非零退出。接口返回成功但 `overall != PASS` 时也会非零退出，同时保留已写出的 artifact。

## 结果解读

`PASS` 表示当前 safety audit 全部通过，可作为继续推进单笔 testnet smoke wiring 的前置证据；它不授权生产交易、自动 promotion 或容量提升。

`WATCH` 表示没有确认失败，但证据不完整，通常是未采集 RPC snapshot 或某些只读证据仍需远端补齐。补齐证据后重新运行。

`FAIL` 表示至少一个安全前置条件失败。不要继续接入真实下单链路；先处理 `checks.csv` 中 status 为 `FAIL` 的项，再重新采集。

重点检查：

- `order_endpoint_untouched` 必须为 `PASS`。
- `observer_dry_run_only` 和 `observer_production_blocked` 必须为 `PASS`。
- `observer_enabled`、`manual_approval_active`、`testnet_mode_active` 必须为 `PASS`。
- `rpc_connected` 在使用 `--require-rpc-connected` 时必须为 `PASS`。
- `testnet_account_identified`、`production_account_absent`、`expected_exact_contracts_available`、`no_active_mak_positions` 需要依赖 `--collect-rpc-snapshot` 的只读证据。

## 安全边界

本 runbook 只做 T1 远端 safety audit 证据采集。不要在同一命令序列中追加真实订单 smoke；若后续需要单笔 testnet 下单验证，必须另走显式审批和独立 runbook。
