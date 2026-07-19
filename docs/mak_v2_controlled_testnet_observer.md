# MAK v2 Controlled Testnet Observer

This document tracks the vnpy-web-bridge implementation boundary for MAK v2 GFEX `lc/ps` controlled observer work.

## Current Scope

Merged scope through PR #101 is instrumentation-first plus read-only PR-B/T1 safety evidence:

- REST endpoints under `/api/mak-v2/testnet-observer/*`
- deterministic manual-waiver state
- dry-run signal event recording
- deterministic eligibility/risk-gate decision
- dry-run order intent generation
- guardrail recording
- dashboard page at `/mak-v2-observer`
- WebSocket event types for MAK v2 observer telemetry
- read-only safety-audit endpoint and dashboard safety panel
- remote safety-audit collector and runbook
- in-memory safety-audit history/latest endpoints
- optional collector artifacts for latest/history inspection
- frontend latest/history display with audit-history error isolation

No live order path is connected in the merged implementation.

## Merged Phase Ledger

| PR | Phase | Result | Boundary |
| --- | --- | --- | --- |
| #94 | PR-A controlled observer | Dry-run observer endpoints, guardrails, dashboard, and telemetry are merged. | Does not call order endpoints or broker adapters. |
| #95 | PR-B/T1 safety audit preflight | Admin-only read-only safety audit is merged. | `overall=PASS` only authorizes moving toward single-order smoke wiring. |
| #96 | Safety audit dashboard | Dashboard can run and inspect the safety audit. | UI action still calls only the safety-audit endpoint. |
| #97 | Remote collector/runbook | Token-env collector writes JSON/CSV evidence artifacts. | Collector does not read `.env` or call order/dry-run/flatten endpoints. |
| #98 | Safety audit history | Latest/history read endpoints are merged for post-run inspection. | History is in-memory runtime evidence, not a durable trading authorization store. |
| #99 | Phase safety-state documentation | Documents the post-merge scope, ledger, evidence requirements, and order-wiring stop line through PR #101. | Docs-only; no runtime or order-path change. |
| #100 | Audit history collector artifacts | Collector can optionally fetch latest/history after POST and archive JSON/CSV evidence. | Optional read-only collection; default collector behavior and order boundary remain unchanged. |
| #101 | Safety audit history UI | Frontend displays latest/history and isolates read failures from core Observer refresh and successful audit execution. | Frontend-only; no backend, RPC, order, dry-run, or flatten path is added. |

## CI/CD And Environment Boundary

Local `.env`, `backend/.env`, and `frontend/.env` are not required for the dry-run and read-only safety-audit packets. CI validates the no-env contract with:

- backend unit tests under `backend/tests/unit`
- frontend tests
- frontend production build
- production Docker image build

Runtime secrets and RPC endpoints are expected to be supplied by the remote deployment workflow through `DEPLOY_ENV_FILE` / deployment environment secrets, not by files committed in this branch.

Local RPC/SimNow smoke tests are intentionally not required for the merged dry-run/read-only packets because they do not call the order endpoint. PR-B controlled testnet execution must add and pass environment-backed RPC/testnet smoke evidence before it can connect to real testnet orders.

## Hard Boundary

Current implementation keeps:

- `capacity_status = L1_CONSTRAINED_WATCH`
- `dry_run_only = true`
- `production_allowed = false`
- `max_order_lots = 1`
- `order_endpoint_touched = false`

The dry-run intent endpoint does not call `trade_service.send_order`, `/api/orders`, vn.py RPC `send_order`, or any broker adapter.

## Next Phase

PR-B may add controlled testnet execution only after all of the following are present in remote deployment evidence:

- manual waiver is approved
- testnet account binding is verified
- production account checks are complete
- read-only RPC smoke is healthy
- safety-audit collector artifacts are archived for the deployed revision
- latest/history safety-audit endpoints show the same remote run
- explicit trade smoke approval is present
- order lifecycle tracing and position reconciliation are wired
- a separate PR defines the exact one-lot testnet order path, cancellation path, and flatten/reconcile rollback

Even after a controlled testnet run passes, the result is not production capacity proof and does not unlock real-money trading.
