# MAK v2 Testnet Execution Waiver

Status: `PENDING_MANUAL_APPROVAL`

Candidate:

- `candidate_id = w900_z1p5_h900_reversal`
- `profile_id = lc50_ps50`
- `universe = GFEX lc, ps`
- `capacity_status = L1_CONSTRAINED_WATCH`

## Waiver Required Answers

| question | required answer |
|---|---|
| Testnet only? | yes |
| Max order lots = 1? | yes |
| Production disabled? | yes |
| Auto selector export disabled? | yes |
| Auto runtime promotion disabled? | yes |
| Testnet result is not capacity pass? | yes |

## Current Implementation State

The current branch implements dry-run observer instrumentation only. It does not submit testnet orders.

To move to controlled testnet execution, a separate PR-B must add account binding checks, order lifecycle tracking, position reconciliation, and an explicitly approved single-order smoke path.
