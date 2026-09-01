# COLLECTOR_ORDERED_L1_BBO_CHANGE_IMBALANCE_V1

Issue: [#488](https://github.com/folgercn/vnpy-web-bridge/issues/488)

This directory freezes the repository-side P0 contract and the first offline
P1 kernel for an independent commodity-futures HFT research line. It does not
collect market data, read credentials, calculate an economic result, create an
order, or grant forward, shadow, SimNow, production, or live authority.

## Scientific boundary

The candidate measures signed price/size changes between adjacent qualified
L1 BBO states in the exact order observed by one dedicated collector. The data
source does not currently prove an exchange-native event sequence, so this
candidate is not named or interpreted as standard/exchange-native OFI. It
cannot support claims about add/cancel/trade events, queue priority, passive
fills, market impact, or capacity.

The candidate is independent from existing research issues: it inherits no
parent, sample, product, threshold, freeze hash, PnL, conclusion, milestone, or
runtime authority. Existing research may be used only as a negative-prior and
engineering-pattern inventory.

## Frozen offline slice

`scripts/collector_ordered_l1_bbo_change_v1.py` provides only deterministic,
networkless boundaries:

- a gapless, generation- and clock-epoch-aware collector-order state machine;
- the frozen BBO price/size-change formula;
- a `(t-10s, t]` depth-normalized score with a full 10-second warmup;
- outcome-free nearest-rank per-contract/session Q95 calibration;
- a 250ms source/receive measurement-quality gate;
- first-eligible-BBO entry and exit selection using 500ms primary latency and
  a 30-active-second horizon.

The focused fixtures cover every bid/ask price and size branch, simultaneous
two-sided changes, same-timestamp callbacks, distinct identical BBO callbacks,
explicit duplicates, generation/epoch/reset behavior, sequence gaps, exact
window edges, long-gap edges, Q95, clock quality, and no-lookahead quote
selection.

Run only the focused offline suite:

```bash
python3 -m pytest -q \
  backend/tests/unit/test_issue488_hft_bbo_change_offline.py
```

## Current decision

```text
P0_IDENTITY_AND_OFFLINE_CONTRACT = READY_TO_FREEZE_ON_MERGE
P1_FEATURE_AND_SINGLE_ROUND_TRIP_KERNEL = IMPLEMENTED_OFFLINE
P1_RAW_JOURNAL_AND_PARTITION_CUSTODY = PENDING
P1_SINGLE_POSITION_LEDGER_AND_FEE_PNL = PENDING
P1_5_PROVIDER_CAPABILITY_PROBE = BLOCKED_PENDING_EXPLICIT_DATA_ONLY_AUTHORIZATION
P2_CALIBRATION = NOT_AUTHORIZED
ECONOMIC_RESULT = NOT_COMPUTED
```

The issue originally placed provider capability proof inside offline P0/P1.
That is impossible without touching the provider. The frozen contract inserts
a separate P1.5 data-only capability probe. Its observations are permanently
excluded from calibration, holdout, and forward. P1.5 permission would not
authorize P2 collection or any economic read.

## Important custody correction

Raw quote/control rows contain `partition_id`, `prev_record_hash`, and
`record_hash`. Final `partition_hash`, `previous_partition_hash`, and `seal_id`
exist only in the create-only closed-partition manifest. Putting a final
partition hash into the rows being hashed would be self-referential.

The complete normative contract and current data-gap decision are in
`design-contract-v1.json`. `manifest-v1.json` binds its exact bytes and the
offline kernel. The freeze becomes effective only when the exact manifest is
merged into `main` before any candidate economic result is read.
