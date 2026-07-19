# MAK v2 Bridge Trade Safety Audit

This document tracks PR-B/T1 readiness for controlled MAK v2 testnet execution.

## Current Packet

Merged work through PR #101 includes the read-only safety audit endpoint:

```text
POST /api/mak-v2/testnet-observer/safety-audit
```

and read-only runtime inspection endpoints:

```text
GET /api/mak-v2/testnet-observer/safety-audit/latest
GET /api/mak-v2/testnet-observer/safety-audits?limit=...
```

These endpoints do not call `/api/orders`, `trade_service.send_order`, vn.py RPC `send_order`, or any broker adapter order method.

Remote collection is handled by:

```text
scripts/mak_v2_collect_safety_audit.py
```

The collector reads the admin token only from an environment variable and writes JSON/CSV evidence artifacts under the selected output directory. It can optionally collect the latest/history read endpoints after the POST audit and archive those responses as separate JSON/CSV artifacts.

The frontend page at `/mak-v2-observer` displays the latest audit and recent history. Latest/history read failures are isolated from the core Observer data, and a history refresh failure after a successful POST does not reclassify the audit execution as failed.

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
- hashed account summary captured in collector artifacts
- forbidden production account markers absent
- risk status readable
- emergency stop clear
- order confirmation required
- observer remains dry-run only until PR-B order wiring
- observer is enabled with manual waiver and testnet mode active
- `order_endpoint_touched = false`
- GFEX exact contracts available
- no active MAK v2 `lc/ps` positions before smoke
- safety-audit latest/history endpoints can inspect the completed remote run
- collector output is archived with the deployed commit/release identifier

## Current Stop Line

The merged work is ready to collect remote read-only safety evidence after CI/CD deploys it. It is not yet a single-order testnet execution implementation.

Do not add order wiring until a separate PR explicitly defines and tests:

- one-lot testnet submit path
- cancel/timeout path
- position reconciliation before and after the smoke
- flatten rollback procedure
- audit trail that links signal, decision, order request, ack, fill/cancel, and reconciliation

## Boundary

Passing this audit only authorizes moving toward single-order smoke wiring. It does not authorize production trading, runtime promotion, auto selector export, or capacity pass.
