# Research Warehouse exact-byte acquisition v1

## Scope and layers

This component acquires and seals official daily source bytes for Research
Data Custody / Evidence only. It does not normalize data, build DuckDB or
Parquet, decide official trading days, export strategy inputs, deploy a
service, or grant execution authority.

```text
CLI
 ├─ transport -> validation
├─ acquisition -> filesystem custody -> append-only observations
│                                   └-> trusted validation -> revision replay
├─ manifests -> manifest validation -> parent seal chain -> external anchors
│            └-> Ed25519 signing
 └─ PIT selector -> verified manifest chain
```

The warehouse root and every custody directory must be owned by the current
user, mode `0700`, non-symlinked, and on one filesystem. Files are mode `0600`,
regular, non-symlinked, and single-link.

## Acquisition lifecycle

1. Render only the audited registry endpoint and enforce the exact HTTPS host
   allowlist on the request and every redirect.
2. Stream the response into `tmp/`, enforce the size limit and content length,
   `fsync` the file, close it, read it twice through a stable file descriptor,
   validate the frozen source schema, and bind the response's authoritative
   `report_date` to the requested trade day.
3. Publish the SHA-256-named raw object with a create-only hard link on the
   same filesystem, `fsync` its parent, remove the temporary link, and verify
   the final bytes and single-link identity.
4. Atomically publish a canonical observation receipt containing HTTP
   metadata, registry binding, custody binding, first/last seen timestamps,
   and revision lineage. Receipt and manifest publication use the same
   temp-file, file-fsync, create-only-link, parent-fsync protocol as raw.

Identical response bytes reuse the raw object but append a new observation.
Consecutive identical responses remain one revision occurrence. If the current
head changed, old bytes appearing again create a new revision occurrence that
references the reused raw object and supersedes the actual current revision.
This preserves sequences such as `A -> B -> A`. Raw acquisition never creates
`READY`.

A partial response, timeout, disk-full error, schema mismatch, or interruption
before publication leaves neither an observation nor a manifest. Interruption
between raw publication and receipt creation may leave an unreferenced raw
object; it is not `READY` and is never selected by PIT.

## Daily seals and PIT

`seal-day` takes all append-only observations for the requested day, derives
the revision state, writes canonical JSON, binds it to the pinned registry
hash and signer public key, and signs it with a separate raw Ed25519 private
key. Every seal names `parent_batch_seal_sha256`, producing one linear,
append-only chain. Only a successfully verified signed manifest has
`ready: true`.

The parent chain alone cannot detect suffix deletion. Every verify/PIT call
therefore requires trusted external genesis and current-head hashes, and every
seal requires the externally retained expected parent hash. `GENESIS` is the
explicit expected parent for the first seal. The full seal hash printed by
`seal-day` must be stored outside the writable manifests directory before the
next operation.

Before signing, the signer treats receipts as untrusted: it reloads the pinned
registry, validates exact source/exchange/schema/URL/HTTP bindings, revalidates
the exact raw schema and response day, and deterministically replays the
revision chain. PIT uses source/day/revision fields already covered by the
verified signature, then strictly rereads and hashes the selected raw bytes.
It uses the latest manifest whose `sealed_at` is at or before the cutoff and
rejects revisions first seen later than that cutoff.

## Commands

```bash
python scripts/research_warehouse_cli.py init-custody --root /private/path

python scripts/research_warehouse_cli.py acquire \
  --root /private/path \
  --registry deployments/research-warehouse/source-registry-v1.json \
  --source-id shfe-daily-market-data-v1 \
  --trade-day 2026-07-28 \
  --collector-version collector-v1

python scripts/research_warehouse_cli.py seal-day \
  --root /private/path \
  --registry deployments/research-warehouse/source-registry-v1.json \
  --trade-day 2026-07-28 \
  --private-key /private/key/path \
  --signer-key-id research-manifest-v1 \
  --expected-parent-seal GENESIS

python scripts/research_warehouse_cli.py verify-chain \
  --root /private/path \
  --registry deployments/research-warehouse/source-registry-v1.json \
  --public-key /trusted/public-key \
  --expected-genesis-seal $TRUSTED_GENESIS_SHA256 \
  --expected-head-seal $TRUSTED_HEAD_SHA256

python scripts/research_warehouse_cli.py select-pit \
  --root /private/path \
  --registry deployments/research-warehouse/source-registry-v1.json \
  --public-key /trusted/public-key \
  --expected-genesis-seal $TRUSTED_GENESIS_SHA256 \
  --expected-head-seal $TRUSTED_HEAD_SHA256 \
  --source-id shfe-daily-market-data-v1 \
  --trade-day 2026-07-28 \
  --cutoff-at 2026-07-28T09:00:00Z
```

Private signing keys must be owned by the current user, mode `0600`, and kept
outside the warehouse and repository. Public verification keys are independent
inputs; a manifest signed by another key fails closed.
