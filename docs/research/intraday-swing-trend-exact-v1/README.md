# INTRADAY_SWING_TREND_EXACT_V1 P0/P1 freeze

Issue: [#481](https://github.com/folgercn/vnpy-web-bridge/issues/481)

This directory is the docs-only P0/P1 contract for one research candidate. It
does not implement replay, collect data, create an order, or grant shadow,
SimNow, production, or economic authority.

## Frozen identity

- Candidate: `INTRADAY_SWING_TREND_EXACT_V1`.
- Universe: `ag.SHFE`, `au.SHFE`, `cu.SHFE`, `rb.SHFE`, `ru.SHFE`, `sc.INE`.
- Scientific unit: one standalone CNY 1,000,000 account per instrument, with a
  target in `{-1, 0, +1}` lots. A portfolio cannot rescue a failed instrument.
- Slow state: completed-official-day PIT carry agrees with 21/63-day roll-safe
  trend; it becomes visible only at the next official TradingDay's day open.
- Timing layer: one 15-minute day-session close breakout and one 10-bar close
  exit, with no same-day re-entry or reversal and a five-official-day maximum
  holding period.
- Paired control: the same slow state, contract mapping, one-lot risk, roll,
  BBO, fees, and fill model, entered at the next legal day open without the
  intraday timing layer.

The complete normative rules are in `design-contract-v1.json`. The JSON value
is canonicalized as UTF-8 with sorted keys, compact separators, no ASCII
escaping, and no non-finite numbers before SHA-256. `manifest-v1.json` records
that canonical digest and the exact file-byte digests.

The contract becomes frozen only when its exact manifest is merged into
`main`. Any later strategy, universe, sample, cost, or gate change requires a
new candidate identity and Owner approval; it cannot silently replace this
contract.

## Current P1 decision

`data-gap-matrix-v1.json` distinguishes a repository contract from verified
historical coverage. The repository contains useful schemas, validation code,
and tick/BBO fields, but it does not contain or bind coverage receipts for the
required historical exact-contract bars, quotes, PIT curve inputs, calendar,
roll facts, and fee schedules.

Therefore the current repository-evidence-only status is:

```text
BLOCKED_EXECUTION_DATA
```

This is not a request to build a collector or data platform. A later bounded
inventory may clear the block only by binding existing data to the frozen
requirements. Continuous-main prices, synthetic paths, ideal bar fills, zero
fees, or forward-filled gaps cannot clear it.

## Stage boundary

This PR completes only the A-side design/data contract. It does not authorize
PR-B, a historical economic read, holdout access, no-order forward, shadow, or
SimNow integration. The Owner must make the next decision after the independent
minimal replay-feasibility inventory is reported.
