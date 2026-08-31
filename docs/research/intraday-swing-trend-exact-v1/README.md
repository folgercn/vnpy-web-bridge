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

The later bounded M2 custody export now binds the six frozen products across
DEV_2023, DEV_2024, and warmup. It contains complete PIT-mapped day-session
one-minute coverage, official daily curves/calendar/LTD/specs, modeled historical
fees, and real event-time BBO for the frozen target events. The immutable archive
digests and current coverage are recorded in `data-binding-inventory-v1.json`.

The target-only runner in `scripts/issue481_minimal_causal_replay.py` validates
the held exact contract, close-before-open ordering, real BBO qualification,
price impact, and fee provenance. It writes only the three evidence files allowed
by the freeze. It does not calculate PnL or read the sealed holdout.

The current research-only feasibility status is:

```text
MODELED_PASS_RESEARCH_ONLY
```

The observed quote `event_time` and bid/ask remain real. Collector receive time,
the historical limit envelope, and missing explicit close-today fees are clearly
marked research models accepted by the Owner; they are not historical execution
evidence. Two CU same-open slow-exit/roll collisions are corrected causally by
closing the actually held old contract and suppressing the new roll leg. The
corrected 603-event path is SHA-bound in the inventory.

## Stage boundary

This stage authorizes only the minimal target-transition feasibility replay. It
does not authorize historical economic gate evaluation, holdout access, no-order
forward, shadow, SimNow, production, or order integration. The Owner must make
the next decision after this result is independently reviewed.
