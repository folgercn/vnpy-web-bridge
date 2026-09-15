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

The target-transition feasibility status was:

```text
MODELED_PASS_RESEARCH_ONLY
```

The observed quote `event_time` and bid/ask remain real. Collector receive time,
the historical limit envelope, and missing explicit close-today fees are clearly
marked research models accepted by the Owner; they are not historical execution
evidence. Two CU same-open slow-exit/roll collisions are corrected causally by
closing the actually held old contract and suppressing the new roll leg. The
corrected 603-event path is SHA-bound in the inventory.

## DEV economic result

The Owner subsequently authorized one economic read of DEV_2023 and DEV_2024
with the frozen 603-event path. The replay uses independent CNY 1,000,000
accounts per product, Primary and Stress fills, historically bound/modelled fees,
and official end-of-day settlement marks. Positions still open on 2024-12-31
remain open and are marked to that day's official settlement; no terminal fill is
invented.

The preregistered standalone gates fail:

| Product | Primary net PnL CNY | Stress net PnL CNY |
| --- | ---: | ---: |
| ag | -1,620.09 | -2,505.10 |
| au | 0.00 | 0.00 |
| cu | 10,401.60 | 5,151.91 |
| rb | -1,274.17 | -2,527.72 |
| ru | -22,737.50 | -27,534.38 |
| sc | -117,380.00 | -139,650.00 |

Only cu has positive net PnL in both scenarios, but its Primary net-profit to
maximum-drawdown ratio is 0.8382, below the required value greater than 1. au
has no candidate events and therefore cannot meet the strictly positive Primary
return gate. The final status is:

```text
STOP_ECONOMIC_GATE
```

The three create-only evidence files and their SHA-256 values are bound in the
inventory. The maximum accounting-identity error is CNY 4e-10.

## Stage boundary

This candidate stops at the DEV economic gate. Its parameters, universe,
directions, costs, or event path must not be changed after seeing the result.
Holdout access, no-order forward, shadow, SimNow, production, and order
integration remain unauthorized.
