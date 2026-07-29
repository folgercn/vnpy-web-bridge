# Research Warehouse deterministic catalog v1

Issue #168 adds a rebuildable derived-data plane beside the immutable Research
evidence store. The raw objects, signed manifests, commit receipts, and external
commit anchors remain the evidence of record. DuckDB contains metadata and
lineage only; normalized market rows live in versioned Parquet partitions.

## Layer boundaries

- `derived_paths.py` owns the private derived filesystem layout.
- `catalog_lock.py` enforces one non-blocking writer.
- `normalization_contracts.py` freezes schema, sort, timezone, DuckDB, and
  Parquet writer settings.
- `normalizer.py` validates one signed raw revision and emits one deterministic
  Parquet partition.
- `revision_snapshots.py` validates monotonic snapshot evolution and selects the
  latest signed view while retaining first-batch lineage.
- `normalization_replay.py` independently reconstructs expected partitions from
  signed raw for verification.
- `catalog_builder.py` publishes a metadata-only DuckDB catalog.
- `catalog_validation.py` independently verifies schema, lineage, bindings,
  partition hashes, row counts, physical schema, compression, and row order.
- `rebuild.py` only coordinates offline chain verification, normalization,
  catalog construction, and final validation.

No layer mutates the raw evidence root. The derived root is disposable and must
not be treated as an authority source.

## Deterministic binding

Every normalized row and catalog partition is bound to:

- the raw object and signed revision;
- the trusted source-registry hash;
- the normalizer version and normalized schema;
- the exact tool Git commit and dependency-lock hash;
- DuckDB 1.5.5, UTC, fixed sort keys, and fixed Parquet writer settings.

The machine-readable contract is validated against
`deployments/research-warehouse/normalization-contract-v1.schema.json`.
Changing a bound input creates a different normalization identity and partition
path instead of overwriting an existing artifact.

## Rebuild and verification

`rebuild-catalog` accepts an empty destination only. It verifies the offline
signed manifest chain and external commit-anchor ledger, reconstructs every
unique revision from raw evidence, creates the catalog, and validates the full
result before reporting success.

`verify-catalog` repeats the evidence-chain checks and independently normalizes
signed raw into a disposable replay root. Catalog partition identities, paths,
row counts, and hashes must exactly match that replay, so coordinated edits to
both a Parquet file and the untrusted catalog cannot validate. DuckDB inspects
Parquet through an anonymous verifier-owned descriptor. It opens a private
verified catalog copy before that copy's pathname is unlinked, leaving the
connection bound to a stable inode; the verifier confirms that DuckDB opened a
new process descriptor with the same device and inode as the already verified
descriptor before unlinking. Both published paths are strictly reread after
inspection to detect concurrent replacement. The commands require explicit
genesis, head, head-commit, ledger, tool-commit, and dependency-lock anchors.
Run `python -m research_warehouse.cli <command> --help` for the complete
arguments.

## Failure semantics

The workflow fails closed for an existing derived root, concurrent writer,
unsafe path or permissions, signature or anchor mismatch, schema drift, raw or
Parquet hash mismatch, catalog corruption, lineage disagreement, dependency
drift, and DuckDB version drift. A failed empty-root rebuild may leave a partial
derived root; it is not valid and must be discarded before retrying with a new
empty path. If final-parent durability fails after a hard link is created, the
temporary link is deliberately retained and strict readers reject the resulting
two-link artifact.
