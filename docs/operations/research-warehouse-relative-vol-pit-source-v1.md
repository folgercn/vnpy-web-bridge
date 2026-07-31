# Research Warehouse relative-vol sealed PIT source view v1

## Architecture impact

- Plane: Research Plane.
- Authority impact: no new Authority. Receipt and output retain every
  Control, Deployment, Execution, Permit, RPC, account, position, order,
  production and trading capability as `false`.
- Execution impact: none. The adapter imports no Web Bridge application,
  vn.py, network client, RPC, account, position, order or signing-private-key
  code.
- Security boundary: private root-pinned Research Warehouse custody is read
  only by the offline adapter. Web Bridge receives only a separately
  transferred and controlled-signed Shadow through
  `COMMODITY_POSITION_MANAGER_SHADOW_PATH`.

## Data flow

```text
root-pinned operator state
  + signed manifest/commit/anchor ledger
  + 186-day acquisition receipt
  + exact daily SHFE/INE bytes
  + signed official calendar/availability anchor/registry
  + independently signed baseline and optional previous Shadow
        |
        v
create-only canonical source-view.json
        +
receipt-last source-view-receipt.json
        |
        v
independent read-only verifier and exact producer replay
        |
        v
commodity_relative_vol_snapshot_producer.py
        |
        v
controlled commodity_position_manager_shadow_sign.py
        |
        v
COMMODITY_POSITION_MANAGER_SHADOW_PATH (read only)
```

The main process must never mount or read the Warehouse custody root, raw
objects, run/backfill receipts, manifests, commit ledger, DuckDB/catalog,
operator state or signing key.

## Frozen derivation

The adapter binds the exact 186-day receipt even when the selected source month
is an earlier complete historical month or a later source month also needs
root-pinned normal daily receipts. A late historical backfill remains explicit
in the bound receipt lineage; it is not misrepresented as having been acquired
at the historical cutoff. Calculation and `used_daily_sources` admit only
official observations on or before the selected cutoff, while the complete
186-day receipt remains pinned as custody provenance. Every used source day
records exact SHFE/INE raw SHA-256 and byte count.

For each target product/day it admits exact contract rows only. Product summary
rows, TAS rows, totals and other products cannot become contracts. PIT main is
the frozen `OI descending, delivery ascending, exact contract ascending` rule,
with at least three positive-settlement/OI contracts beyond the source month.
Each daily return closes the interval with the previous day's exact PIT main;
a roll changes the main only after that comparable settlement is used.

The scalar baseline series is frozen as:

```text
SIGNED_BASELINE_BUFFERED_WEIGHTED_ROLL_SAFE_LOG_RETURN_V1

daily_return[t] =
  sum_product(
    signed_baseline.buffered_target_weight[product]
    * old_pit_main_log_return[product, t]
  )
```

The source view contains exactly the calendar's latest 126 completed official
days. The adapter verifies the signed baseline, exact source-month PIT main,
frozen multiplier/price tick and optional signed previous Shadow before it
invokes `commodity_relative_vol_snapshot_producer.py`. The final source bytes
must replay to the same source hash, draft hash and evidence hash.

## Create

The output root must already exist as a private `0700`, current-user-owned,
symlink-free directory outside every Warehouse/runtime/input/key/baseline path.
All external pins are mandatory:

```bash
PYTHONPATH=scripts python scripts/research_warehouse_pit_source_view.py \
  --runtime-input /usr/local/libexec/vnpyresearch/runtime-input-v1.json \
  --operator-state /usr/local/libexec/vnpyresearch/operator-state-v1.json \
  --operator-state-sha256 <exact-sha256> \
  --history-receipt <exact-backfill-receipt-path> \
  --history-receipt-sha256 <exact-sha256> \
  --manifest-public-key <manifest-public-key-path> \
  --manifest-public-key-sha256 <exact-key-sha256> \
  --business-public-key <business-public-key-path> \
  --business-public-key-sha256 <exact-key-sha256> \
  --business-signer-key-id <expected-signer-key-id> \
  --baseline-batch <signed-baseline-path> \
  --source-month 2026-08 \
  --output-root <private-transfer-staging-root>
```

For linked continuity also provide:

```text
--previous-snapshot <signed-previous-shadow-path>
```

The deterministic directory ID contains:

```text
source-view.json
source-view-receipt.json
```

The source view is written first and the receipt last. Publication holds stable
root/output directory descriptors, uses `O_EXCL|O_NOFOLLOW`, fsyncs each file
and directory, and refuses overwrite. A partial directory without the valid
receipt is not consumable.

## Independent verification

Keep the receipt SHA-256 outside the export directory:

```bash
PYTHONPATH=scripts python \
  scripts/research_warehouse_pit_source_view_verify.py \
  --input <sealed-source-view-directory> \
  --expected-receipt-sha256 <externally-retained-sha256>
```

The verifier requires the exact two-file set, canonical bytes, receipt ID,
source hash/byte count, all-false authority and byte-identical producer replay.
It has no write, private-key, network, RPC or execution capability.

## Draft, evidence and controlled Shadow

Only after the independent verifier succeeds:

```bash
PYTHONPATH=backend python scripts/commodity_relative_vol_snapshot_producer.py \
  --input <sealed-source-view-directory>/source-view.json \
  --snapshot-output <new-unsigned-shadow-path> \
  --evidence-output <new-producer-evidence-path>
```

Compare the draft/evidence hashes with the sealed receipt. Signing remains a
separate controlled action:

```bash
PYTHONPATH=backend python scripts/commodity_position_manager_shadow_sign.py \
  --input <new-unsigned-shadow-path> \
  --output <new-signed-shadow-path> \
  --private-key-file <controlled-ed25519-private-key>
```

No adapter/producer/verifier success authorizes signing, installation,
Acceptance, Deployment, Execution, Permit, SimNow, CTP, Windows RPC, account,
position, order or trading.

## Fail-closed conditions

Creation or verification rejects:

- missing/wrong official day, calendar gap or post-cutoff data used by the
  calculation;
- daily receipt/raw SHA or byte drift, registry/calendar/anchor mismatch;
- manifest/commit/root/anchor-ledger fork, replay pin change or uncommitted day;
- malformed/duplicate contract, fewer than three PIT-eligible contracts,
  missing old-main comparable settlement or exact-contract splice;
- invalid baseline/previous signature, hash, month, link, multiplier, tick,
  PIT main, guardband or frozen allocator result;
- source/output overlap, symlink, unsafe ownership/mode, overwrite, partial or
  extra output;
- producer normalization/replay mismatch;
- any attempt to add network, RPC, account, position, order, dispatch,
  production or trading capability.

The fixed #214 receipt ends on 2026-07-30. Before the 2026-07-31 official close
is acquired and root pinned it cannot produce a July month-end view, but it can
produce a bounded view for an earlier complete historical month when a valid
signed baseline for that month exists. A historical view records the actual
late-backfill lineage and never consumes post-cutoff observations. Missing a
valid baseline or signing authority remains an expected fail-closed state, not
a reason to synthesize or backdate input.
