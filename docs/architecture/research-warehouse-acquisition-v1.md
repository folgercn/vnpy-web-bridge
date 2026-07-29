# Research Warehouse exact-byte acquisition v1

## Scope and layers

This component acquires and seals official daily source bytes for Research
Data Custody / Evidence only. It does not normalize data, build DuckDB or
Parquet, decide official trading days, export strategy inputs, deploy a
service, or grant execution authority.

```text
CLI
 ├─ transport -> validation
 ├─ acquisition -> custody paths / file integrity / publication / locks
 │              └-> observations -> trusted validation -> revision replay
 ├─ manifests -> validation / batch+commit parent chain
 │            └-> Ed25519 commit receipts -> external availability anchors
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
key. Every prepared manifest names both `parent_batch_seal_sha256` and
`parent_commit_seal_sha256`, producing one linear, append-only chain, and
carries `ready: false`. After its final parent directory is successfully
fsynced, the signer atomically publishes a second signed commit receipt. The
receipt's exact raw SHA-256 is its commit seal. A later manifest binds its
parent's commit seal, so replacing an earlier receipt breaks the signed chain.

The local chain cannot detect head rollback. Every verify/PIT call therefore
requires trusted external genesis, current batch-head, and current commit-head
hashes. Every seal requires the externally retained expected parent batch and
commit hashes; `GENESIS` is explicit for both on the first seal. `seal-day`
prints both new hashes. They must be stored outside the writable warehouse
before the next operation.

PIT additionally requires a canonical external commit-anchor ledger. Each
entry binds a sequence, batch seal, commit seal, and `available_at` sampled by
the external anchor owner only after `seal-day` has returned successfully and
the receipt has been strictly reread. The ledger file is itself pinned by a
SHA-256 retained outside that file and the warehouse. PIT requires an exact
entry for every local chain node and uses only external `available_at` values;
the receipt's earlier diagnostic `committed_at` is never PIT authority. Thus a
delayed recovery cannot backdate readiness, and deleting/re-signing a receipt
cannot silently rewrite historical PIT visibility.

```json
{"entries":[{"available_at":"2026-07-28T08:15:00.000000Z","batch_seal_sha256":"<64 hex>","commit_seal_sha256":"<64 hex>","sequence":1}],"schema_version":"vnpy_research_commit_anchor_ledger_v1"}
```

If a process exits after committing a manifest but before returning its seal,
retrying the identical request with the old expected parent recognizes the
unique matching child, completes any missing commit receipt, and returns the
same batch seal. This recovery is allowed only while external state still
names the old parent batch and commit. If external state already names the
current child, a missing or changed receipt fails closed.

Before signing, the signer treats receipts as untrusted: it reloads the pinned
registry, validates exact source/exchange/schema/URL/HTTP bindings, revalidates
the exact raw schema and response day, and deterministically replays the
revision chain. PIT uses source/day/revision fields already covered by the
verified signature, then strictly rereads and hashes the selected raw bytes.
It uses the latest manifest whose externally anchored `available_at` is at or
before the cutoff and rejects revisions first seen later than that cutoff.

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
  --expected-parent-seal GENESIS \
  --expected-parent-commit-seal GENESIS

python scripts/research_warehouse_cli.py verify-chain \
  --root /private/path \
  --registry deployments/research-warehouse/source-registry-v1.json \
  --public-key /trusted/public-key \
  --expected-genesis-seal $TRUSTED_GENESIS_SHA256 \
  --expected-head-seal $TRUSTED_HEAD_SHA256 \
  --expected-head-commit-seal $TRUSTED_HEAD_COMMIT_SHA256

python scripts/research_warehouse_cli.py select-pit \
  --root /private/path \
  --registry deployments/research-warehouse/source-registry-v1.json \
  --public-key /trusted/public-key \
  --expected-genesis-seal $TRUSTED_GENESIS_SHA256 \
  --expected-head-seal $TRUSTED_HEAD_SHA256 \
  --expected-head-commit-seal $TRUSTED_HEAD_COMMIT_SHA256 \
  --commit-anchor-ledger /trusted/commit-anchors-v1.json \
  --expected-commit-anchor-ledger-sha256 $TRUSTED_LEDGER_SHA256 \
  --source-id shfe-daily-market-data-v1 \
  --trade-day 2026-07-28 \
  --cutoff-at 2026-07-28T09:00:00Z
```

Private signing keys must be owned by the current user, mode `0600`, and kept
outside the warehouse and repository. Public verification keys are independent
inputs; a manifest signed by another key fails closed.
