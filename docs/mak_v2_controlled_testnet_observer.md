# MAK v2 Controlled Testnet Observer

This document tracks the vnpy-web-bridge implementation boundary for MAK v2 GFEX `lc/ps` controlled observer work.

## Current Scope

Implemented scope is PR-A instrumentation-first:

- REST endpoints under `/api/mak-v2/testnet-observer/*`
- deterministic manual-waiver state
- dry-run signal event recording
- deterministic eligibility/risk-gate decision
- dry-run order intent generation
- guardrail recording
- dashboard page at `/mak-v2-observer`
- WebSocket event types for MAK v2 observer telemetry

No live order path is connected in this packet.

## CI/CD And Environment Boundary

Local `.env`, `backend/.env`, and `frontend/.env` are not required for this PR-A packet. CI validates the no-env contract with:

- backend unit tests under `backend/tests/unit`
- frontend tests
- frontend production build
- production Docker image build

Runtime secrets and RPC endpoints are expected to be supplied by the remote deployment workflow through `DEPLOY_ENV_FILE` / deployment environment secrets, not by files committed in this branch.

Local RPC/SimNow smoke tests are intentionally not required for PR-A because the implementation is dry-run-only and does not call the order endpoint. PR-B controlled testnet execution must add and pass environment-backed RPC/testnet smoke evidence before it can connect to real testnet orders.

## Hard Boundary

Current implementation keeps:

- `capacity_status = L1_CONSTRAINED_WATCH`
- `dry_run_only = true`
- `production_allowed = false`
- `max_order_lots = 1`
- `order_endpoint_touched = false`

The dry-run intent endpoint does not call `trade_service.send_order`, `/api/orders`, vn.py RPC `send_order`, or any broker adapter.

## Next Phase

PR-B may add controlled testnet execution only after:

- manual waiver is approved
- testnet account binding is verified
- production account checks are complete
- read-only RPC smoke is healthy
- explicit trade smoke approval is present
- order lifecycle tracing and position reconciliation are wired

Even after a controlled testnet run passes, the result is not production capacity proof and does not unlock real-money trading.
