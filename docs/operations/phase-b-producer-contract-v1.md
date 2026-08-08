# Phase B MAP/C_FAST producer contract v1

This document describes the two offline batch boundaries introduced by Issue
#291.  It is an artifact-plane contract, not a deployment or execution grant.

## Identities

| Job | Producer identity | Formal model/policy | Output |
| --- | --- | --- | --- |
| MAP | `map-producer` / `map-producer-v1` | `commodity_fast_tsmom_forward_freeze_v1` | `commodity_map_signal_candidate_v1` |
| C_FAST | `c-fast-producer` / `c-fast-producer-v1` | `C_FAST_CROSS_SECTION_NEUTRAL` | `commodity_c_fast_target_candidate_v1` |

The identities are distinct even when both jobs use the same frozen pure
kernel.  Code identity is a SHA-256 digest in each candidate.  The stable
MAP-to-C_FAST projection contract is the same formal contract used by the
existing acceptance DTOs: product, sector, three trend signs, source score,
volatility, raw risk score and source target weight.  Execution-only fields
are forbidden in that projection.

## Canonical handoff

The only accepted source input is an exact canonical
`commodity_approved_research_source_v1` envelope.  Its approval facts must all
be true and its source hash must match the normalized PIT source.  A producer
does not turn these facts into runtime authority.

```text
approved source envelope
        |
        v
MAP signal candidate (canonical bytes, source hash, lineage)
        |
        v
C_FAST verifies a domain-signed MAP acceptance (public keyring only)
        |
        v
C_FAST target candidate (canonical bytes, MAP raw predecessor hash, lineage)
```

MAP computes the frozen trend and cross-sectional source weights but does not
emit contract quantities.  C_FAST requires a public-key-verified
`map_acceptance` artifact whose payload pins the exact MAP candidate hash and
keeps production/live/countable flags false.  It then consumes the exact MAP
bytes, replays all MAP signals from the same source, and computes buffered
weights, PIT contract selection and deterministic integer allocation.  Its
predecessor record binds the MAP schema, candidate id, source hash and raw
canonical SHA-256.  C_FAST has no signing capability and never reads private
material; signing remains an external authority step.

Both outputs are unsigned, research-only candidates.  All authority booleans
are fixed to `false`; neither job creates an acceptance, installs an artifact,
or changes a runtime state.

Every MAP and C_FAST `--version`, `health`, and `ready` response is canonical
JSON and explicitly reports the following denials: `private_key_access=false`,
`trade_rpc_access=false`, `account_access=false`, `order_access=false`,
`production_allowed=false`, `live_trading_authorized=false`, and
`countable_forward=false`.  A scheduler must treat these declarations as a
boundary assertion, not an authority grant.

## File and replay rules

The CLI accepts explicit source and predecessor file paths.  It rejects
symlinks, directory traversal through a `latest` path component, changed inode
or size during read, non-canonical JSON, duplicate keys, future/invalid PIT
rows, approval failures and extra fields.  C_FAST never resolves a directory
pointer or a moving “latest” file.  A caller-supplied high-water set can reject
already consumed MAP hashes; durable custody remains the owner of that set.

Candidate output uses create-only atomic publication.  Existing paths are
never overwritten.  The output parent is pinned with a non-following directory
descriptor and revalidated around the link, so parent replacement or symlink
races fail closed.  The output directory is fsynced after the canonical bytes
are linked into place; signing and custody are separate later jobs.

C_FAST `produce` also requires `--map-acceptance-keyring-sha256`.  The public
keyring is loaded through the shared `load_keyring` verifier, which accepts
only canonical JSONL and checks the expected raw SHA-256 pin before the
domain/schema/producer/key-role pins are applied.

## CLI probes

```bash
python -m map_producer.producer --version
python -m map_producer.producer health
python -m map_producer.producer ready

python -m c_fast_producer.producer --version
python -m c_fast_producer.producer health
python -m c_fast_producer.producer ready
```

`produce` is a batch action requiring explicit `--source`, `--map-input` (for
C_FAST) and `--output`; it has no listener or HTTP mode.  The image entrypoint
defaults to the `ready` probe so schedulers can run a non-mutating check.

## Compose acceptance

`deployments/docker-compose.phase-b.yml` is a standalone, offline Phase-B
graph.  It has seven units: artifact custody, market-data worker,
execution-quality worker, monitor worker, MAP, C_FAST, and the offline signing
authority.  It does not include Phase A or declare Control, Execution,
Gateway, or database services.  MAP and C_FAST are `batch` profile jobs; the
signing authority is an `offline-signing` profile job.  Their canonical
handoff is MAP (write) -> offline signing (read MAP/write signed MAP) -> C_FAST
(read signed MAP/write C_FAST) -> offline signing (read C_FAST/write signed
C_FAST) -> custody (read-only).

All batch handoff volumes are UID/GID 65532 tmpfs volumes with mode `0700`.
Each producer gets a distinct writable output volume; a volume shared by MAP
and C_FAST is mounted read-only by both, never read-write.  All producer and
signing jobs use `network_mode: none`; custody has an isolated internal
network.

Before any Compose command, set the exact raw SHA-256 pin for the canonical
MAP-acceptance keyring **and an explicit positive custody writer epoch**.
Compose intentionally refuses to render either protected command when either
value is absent; the epoch is a writer fence and must not be silently reset.

```bash
export MAP_ACCEPTANCE_KEYRING_SHA256='<exact 64-character keyring SHA-256>'
export CUSTODY_WRITER_EPOCH='<positive monotonically fenced integer>'
docker compose -f deployments/docker-compose.phase-b.yml config
docker compose -f deployments/docker-compose.phase-b.yml --profile batch run --rm --no-deps map-producer --version
docker compose -f deployments/docker-compose.phase-b.yml --profile batch run --rm --no-deps map-producer ready
docker compose -f deployments/docker-compose.phase-b.yml --profile batch run --rm --no-deps c-fast-producer --version
docker compose -f deployments/docker-compose.phase-b.yml --profile batch run --rm --no-deps c-fast-producer ready
```

Those are non-mutating image/probe acceptance commands.  Running `produce` or
an offline-signing ceremony requires explicitly staged immutable input and
handoff artifacts; it is not part of a health check.

## Image boundary

`Containerfile.map-producer` and `Containerfile.c-fast-producer` copy only the
owned producer code, frozen pure kernel and JSON contracts.  They run as a
numeric non-root user, have no private material, and are intended for
`--network none` local OCI smoke tests.  The C_FAST image additionally copies
the public artifact/trust verifier modules and cryptography dependency; these
are verification-only and do not expose a signing entrypoint.  It copies the
MAP source file only to verify its declared producer digest; it consumes MAP
as bytes, not by importing or discovering a MAP job.
