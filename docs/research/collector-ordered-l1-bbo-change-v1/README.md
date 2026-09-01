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

`scripts/collector_ordered_l1_bbo_change_accounting_v1.py` is a separate,
standard-library offline accounting component. It freezes PRIMARY
(`500ms/500ms/30s/one lot/0 tick`) and STRESS
(`1s/1s/30s/one lot/1 adverse tick`) scenarios, admission by
`scenario_id × exact_contract`. Both freeze a one-lot execution-side minimum,
30-second horizon, five-second exit grace, and collector callback event order.
It also freezes PIT terms/fee/markup resolution, Decimal fee rounding to
`0.01` with `ROUND_HALF_UP`, one-lot legs, liquidation-side MTM, and fixed
20-day sealed/priced coverage. The pooled best three official days are selected
once and removed from every product. It is not yet wired to a complete
multi-signal raw replay or an end-to-end PnL result.

The focused fixtures cover every bid/ask price and size branch, simultaneous
two-sided changes, same-timestamp callbacks, distinct identical BBO callbacks,
explicit duplicates, generation/epoch/reset behavior, sequence gaps, exact
window edges, long-gap edges, Q95, clock quality, and no-lookahead quote
selection. They also cover custody tamper/resume/seal failures, admission and
PIT accounting, forged-ledger rejection, PRIMARY/STRESS liquidation, daily
coverage reconciliation, and pooled best-three-day removal.

Run only the focused offline suite:

```bash
python3 -m pytest -q \
  backend/tests/unit/test_issue488_hft_bbo_change_offline.py \
  backend/tests/unit/test_issue488_hft_bbo_change_accounting_offline.py
```

## Current decision

```text
P0_IDENTITY_AND_OFFLINE_CONTRACT = READY_TO_FREEZE_ON_MERGE
P1_FEATURE_AND_SINGLE_ROUND_TRIP_KERNEL = IMPLEMENTED_OFFLINE
P1_POSIX_RAW_JOURNAL_AND_PARTITION_CUSTODY = IMPLEMENTED_OFFLINE
P1_ACCOUNTING_COMPONENT = IMPLEMENTED_OFFLINE_NOT_FULLY_INTEGRATED
P1_FULL_MULTI_SIGNAL_RAW_REPLAY_AND_PNL = PARTIAL
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

The custody implementation is POSIX-only and offline. Its integrity claim is
relative to externally saved custody-root pins and an externally supplied
terminal head hash/seal: it does not create an independent trust anchor. One
run may contain multiple collector generations, but a collector generation is
never reusable after its terminal state. Failed roots, tails, seals, or trusted
head checks fail closed. Every previously sealed manifest/data pair is pinned
after full verification and checked around each append. An unsealed partition
left by a crash must be explicitly resumed; a new partition cannot skip it.

## Accounting scope and remaining P1 work

Admission is deterministic in callback order: a same-callback exit transition
may release the `scenario_id × exact_contract` slot before the next candidate
is admitted. Each present PIT binding must match exactly one
contract/official-day/receive-UTC interval. Current candidate round trips stay
inside one lane and one official trading day, so their close is `CLOSE_TODAY`.
The future `CLOSE_YESTERDAY` resolver is retained only as a non-authorizing
identity boundary. Daily aggregation requires exact-one sealed, priced coverage
for both products on every frozen day and reconciles all attempts before a
zero-trade cell is allowed. It selects the pooled best three official days once
and removes those same dates from each product; this does not permit pooled
rescue of a failing product.

Terminal timeout/unpriced exposure handling has not yet been integrated with
the accounting component; nor has an independent raw-to-PnL auditor. Bootstrap
parameters remain explicitly `BLOCKED`, not selected. Therefore full P1 is
still `PARTIAL`; none of this changes P1.5, data, economic-read, forward, or
order permissions.

The complete normative contract and current data-gap decision are in
`design-contract-v1.json`. `manifest-v1.json` binds its exact bytes and the
offline kernels and tests. The freeze becomes effective only when the exact manifest is
merged into `main` before any candidate economic result is read.
