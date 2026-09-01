# COLLECTOR_ORDERED_L1_BBO_CHANGE_IMBALANCE_V1

Issue: [#488](https://github.com/folgercn/vnpy-web-bridge/issues/488)

This directory freezes the repository-side P0 contract and the generic offline
P1 fixture slice for an independent commodity-futures HFT research line. It does not
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
- an externally anchored, read-only sealed-custody reader with recursively
  bound partition manifests; and
- deterministic PRIMARY/STRESS multi-signal replay from raw custody through
  admission, entry, exit, terminal state, PIT accounting, and per-cell coverage.

`scripts/collector_ordered_l1_bbo_change_accounting_v1.py` is a separate,
standard-library offline accounting component. It freezes PRIMARY
(`500ms/500ms/30s/one lot/0 tick`) and STRESS
(`1s/1s/30s/one lot/1 adverse tick`) scenarios, admission by
`scenario_id × exact_contract`. Both freeze a one-lot execution-side minimum,
30-second horizon, five-second exit grace, and collector callback event order.
It also freezes PIT terms/fee/markup resolution, Decimal fee rounding to
`0.01` with `ROUND_HALF_UP`, one-lot legs, liquidation-side MTM, and fixed
20-day sealed/priced coverage. The pooled best three official days are selected
once and removed from every product. It is not wired to a real-data holdout or
an authorized economic result. Fixed-grid aggregation accepts only exact,
revalidated ledger types and requires an independently supplied trusted
raw-hash-to-quote map derived from verified custody; submitted leg quotes cannot
serve as their own trust root.

`scripts/collector_ordered_l1_bbo_change_auditor_v1.py` independently parses
sealed raw bytes and the freeze bundle, recalculates the complete offline
producer bundle using only the standard library, and reports deterministic
`MATCH`, `MISMATCH`, or `INVALID_INPUT`. A producer match does not override a
blocked holdout/data gate.

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
  backend/tests/unit/test_issue488_hft_bbo_change_accounting_offline.py \
  backend/tests/unit/test_issue488_hft_bbo_change_auditor_offline.py
```

## Current decision

```text
P0_IDENTITY_AND_OFFLINE_CONTRACT = READY_TO_FREEZE_ON_MERGE
P1_FEATURE_AND_MULTI_SIGNAL_REPLAY_KERNEL = OFFLINE_FIXTURE_COMPLETE_REAL_BINDINGS_UNBOUND
P1_POSIX_RAW_JOURNAL_AND_PARTITION_CUSTODY = IMPLEMENTED_OFFLINE_POSIX_RELATIVE_TO_EXTERNAL_ANCHORS
P1_ACCOUNTING_COMPONENT = IMPLEMENTED_AND_INTEGRATED_OFFLINE
P1_INDEPENDENT_RAW_TO_PNL_AUDITOR = IMPLEMENTED_OFFLINE
P1_GENERIC_OFFLINE_STATUS = OFFLINE_FIXTURE_COMPLETE_REAL_BINDINGS_UNBOUND
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
`record_hash`. Final `partition_hash`, `previous_partition_hash`,
`previous_partition_seal_id`, and `seal_id` exist only in the create-only
closed-partition manifest. Each terminal seal therefore commits recursively to
prior manifest metadata as well as prior partition bytes. Putting a final
partition hash into the rows being hashed would be self-referential.

The custody implementation is POSIX-only and offline. Its integrity claim is
relative to externally saved custody-root pins and an externally supplied
terminal head hash/seal: it does not create an independent trust anchor. One
run may contain multiple collector generations, but a collector generation is
never reusable after its terminal state. Failed roots, tails, seals, trusted
heads, nonempty writer locks, or unsafe canonical identities fail closed. Every
previously sealed manifest/data pair is pinned
after full verification and checked around each append. An unsealed partition
left by a crash must be explicitly resumed; a new partition cannot skip it.

## Integrated replay scope and remaining real bindings

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

Terminal timeout and unpriced exposure are explicit. Every terminal attempt
records its boundary evidence and `terminal_position_lots`; an unpriced
position remains nonzero, stops replay globally, makes later coverage cells
incomplete, and cannot be misread as flat. Coverage requires exact
admission-to-attempt and closed-attempt-to-trade reconciliation, quotes inside
one unique generation/clock-epoch segment boundary, no in-segment lifecycle
break, and the frozen raw quality denominators (including all invalid and
duplicate QUOTE rows). Crossed/locked rates use every parseable positive raw
price pair even when sizes are invalid or the row is a proven duplicate. The
auditor recomputes these facts without importing either producer module.

A passing cell also requires an authority-bearing eligible coverage plan with
more than 10 days to last trade, every quote receive time inside its frozen
interval, at least one quote with `>= 60_000_000_000ns` remaining before the
segment end, an exact contract/session Q95, proven provider ID semantics, and
one non-overlapping PIT terms/fee/markup binding for the complete interval.
These gates are reported separately before they are combined into
`data_gate_passed`; a reconciled zero-attempt cell cannot bypass them.

Exit selection also enforces a per-attempt accepted source-time high-water:
a callback whose source time regresses is retained in custody but cannot begin
or satisfy the exit. If an exit quote is usable but trusted accounting still
fails, the attempt retains that exit hash, reports an `ACCOUNTING:` terminal
reason and signed residual position, and triggers the same global stop as any
other unpriced exposure.

Custody and replay require canonical CONTROL text/ISO days and positive raw
callback monotonic time. All eight retained provider numeric fields use only
string, integer, or null values (never bool/float), including auxiliary last,
volume, amount, and open-interest fields. Before any economic state exists, a
full-stream preflight rejects every record after a generation terminal control
and validates provider-ID duplicate/conflict relationships even in a suffix
that replay would later stop before processing.

Economic replay rejects every row-level clock defect before opening state and,
once at least 1,000 quotes exist, also enforces the frozen 250ms p99 gate. A
smaller synthetic fixture may exercise deterministic mechanics, but its
insufficient aggregate clock evidence keeps the holdout gate blocked.

The generic offline fixture slice is complete. Actual provider semantics,
fixed exact-contract selection, session schedules, PIT terms/fee/markup
authorities, clock evidence, and the complete sealed 20-day holdout remain
unbound and unauthorized. Bootstrap parameters belong to a later separately
authorized holdout decision and remain `BLOCKED`; none of this changes P1.5,
data, economic-read, forward, or order permissions.

The complete normative contract and current data-gap decision are in
`design-contract-v1.json`. `manifest-v1.json` binds its exact bytes and the
offline kernels and tests. The freeze becomes effective only when the exact manifest is
merged into `main` before any candidate economic result is read.
