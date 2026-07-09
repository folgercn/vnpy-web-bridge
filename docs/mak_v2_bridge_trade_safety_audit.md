# MAK v2 Bridge Trade Safety Audit

This document tracks PR-B/T1 readiness for controlled MAK v2 testnet execution.

## Current Packet

This packet adds a read-only safety audit endpoint:

```text
POST /api/mak-v2/testnet-observer/safety-audit
```

The endpoint does not call `/api/orders`, `trade_service.send_order`, vn.py RPC `send_order`, or any broker adapter order method.

## Default Mode

By default, the audit does not probe RPC and does not collect account/contract/position snapshots. It reports `WATCH` until remote deployment runs it with:

```json
{
  "probe_rpc": true,
  "collect_rpc_snapshot": true,
  "require_rpc_connected": true,
  "expected_exact_contracts": ["GFEX.ps2609", "GFEX.lc2609"]
}
```

Use exact contracts that are actually tradable in the remote SimNow/testnet session.

## Required T1 Evidence

- testnet account identified
- forbidden production account markers absent
- risk status readable
- emergency stop clear
- order confirmation required
- observer remains dry-run only until PR-B order wiring
- `order_endpoint_touched = false`
- GFEX exact contracts available
- no active MAK v2 `lc/ps` positions before smoke

## Boundary

Passing this audit only authorizes moving toward single-order smoke wiring. It does not authorize production trading, runtime promotion, auto selector export, or capacity pass.
