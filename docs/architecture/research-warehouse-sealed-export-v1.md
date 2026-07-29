# Research Warehouse sealed source export v1

Issue #171 adds a one-way evidence boundary between Research Warehouse /
the #163 pure producer and downstream #157 bundle preparation. It does not
query the warehouse, run the producer, construct a #157 signing draft, install
a runtime snapshot, or grant Control/Execution authority.

## Layering

- `sealed_export_contracts.py` independently validates the nine canonical
  producer artifacts, their common source identity, ten-product
  cross-artifact contract/target agreement, PIT dates, and all-false authority.
- `sealed_export_crypto.py` loads an externally SHA-pinned independent
  Ed25519 keyring and verifies signer/keyring identity.
- `sealed_export_custody.py` performs stable, symlink-free reads and publishes
  an exact create-only directory with the receipt written last.
- `sealed_export.py` coordinates public checks, signing, publication, and
  read-only consumer verification.
- `sealed_export_cli.py` is argument/output plumbing only.

The consumer imports no DuckDB, SQLAlchemy, Settings, API, RPC, account,
order, trade, position, adapter, or execution service. It needs read access
only to the transferred export directory and independent keyring; it does not
receive the Research root path or any write capability there.

## Exact export

The directory name is the deterministic `export_id` and contains exactly:

```text
freeze_contract.json
research_manifest.json
signal_evidence.json
target_evidence.json
allocation_evidence.json
daily_roll_evidence.json
reference_price_evidence.json
calendar_authority.json
contract_spec_evidence.json
sealed-export-manifest.json
sealed-export-receipt.json
```

Each artifact binding carries filename, byte count, raw SHA-256, common
lineage SHA-256, and PIT cutoff. The manifest binds the frozen source registry,
calendar and calendar anchor, commit-anchor ledger, manifest
genesis/head/head-commit seals, research as-of date, execution date, source
view hash, and all nine exact byte identities. The signed receipt binds the
exact manifest hash, artifact index, lineage hash, signer, and keyring.

All source artifacts must be non-empty canonical #163 producer JSON, use
distinct paths/inodes/bytes, retain the producer's unverified flags, and agree
on source-view identity. The verifier independently checks exact ten-product
sets and target quantity/exact-contract agreement across signal, target,
allocation, daily-roll, reference-price, and contract-spec evidence.

## Publication and replay

The export root and directory are private, current-user-owned, normalized and
symlink-free. The deterministic export directory is created with `mkdir`
create-only semantics. Artifact files and the signed manifest use `O_EXCL`,
file `fsync`, parent `fsync`, and strict readback. The signed receipt is
published last and is the completion marker.

An existing export ID is never overwritten. A failed partial publication has
no valid receipt and cannot be consumed. A later warehouse revision or changed
producer source file cannot rewrite an earlier export: consumer verification
uses only the copied exact bytes, signed manifest, independent keyring pin, and
externally retained expected receipt SHA-256.

`receipt_created_at` is diagnostic signer time, not an availability claim. Export
completion and identity are established only by the receipt being written last
and by the consumer's independently retained expected receipt SHA-256.

## Authority

The manifest and receipt explicitly set every Control, Deployment, Execution,
Execution Permit, network, RPC, account-data, order, position, dispatch,
trading, production, and replacement authority field to `false`. The nine
producer artifacts must retain their own all-false authority contract.

Successful verification means only:

```text
SEALED_SOURCE_EXPORT_VERIFIED_READ_ONLY
```

It is suitable as evidence input for a later independent #157 draft rebuild.
It is not a #157 bundle, Acceptance, runtime snapshot, permit, or order
instruction.

## CLI

```bash
PYTHONPATH=scripts python scripts/research_warehouse_sealed_export_cli.py \
  create --help

PYTHONPATH=scripts python scripts/research_warehouse_sealed_export_cli.py \
  verify --help
```

The private key and externally pinned keyring/receipt hashes remain outside
the repository. Schema files under `deployments/research-warehouse/` define
the manifest, receipt, and keyring machine contracts.
