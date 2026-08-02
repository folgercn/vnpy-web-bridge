# C_FAST execution-quality production artifacts v1

This contract wires Issue #217's default-off, read-only Tick runtime to one
exact seven-role generation. It does not grant collection, database mutation,
RPC, order, position, dispatch, replacement, or production authority.

## Required exact artifacts

All seven files are canonical JSON with exactly one trailing newline, regular
single-link owner-only files directly under the pinned custody root:

1. `signed_p0_acceptance`: short-lived human-signed query-v6 P0 acceptance.
   It embeds the exact query-v6 terminal, readonly proof, and audit JSON raw
   bytes, including the real query-v6 writer's pretty serialization. Embedded
   JSON is duplicate-key/NaN-safe parsed; raw and canonical hashes are checked
   separately. The audit raw hash must equal the terminal's `audit_json` hash
   and the readonly proof's audit hash. Its schema, fresh timestamp, P0 result,
   and all ten current product/contract rows are replayed; the resulting
   snapshot and exact-contract set, rather than signer-reported fields, bind
   custody, snapshot and plan. The verifier also checks the terminal's
   executable/foundation/adapter pins, pre/post readonly hashes, zero database
   mutations, zero RPC, zero orders and zero positions. `preflight` and
   `postflight` must also be structurally identical; a self-reported stable
   flag cannot conceal a changed observation.
2. `collection_admission`: distinct short-lived human-signed v2 admission
   binding the exact P0 and policy raw bytes.
3. `execution_policy`: the existing signed policy-v2 freeze. Verification
   replays the separately pinned exact policy-v1 ancestry with the official
   `verify_execution_policy_freeze_v2_raw_chain` verifier.
4. `signed_snapshot`: the existing official-forward signed C_FAST snapshot.
   Verification uses the existing Shadow verifier with contract metadata from
   the same signed spec set; no RPC or market repository is available.
5. `virtual_intent_plan`: independently signed plan envelope binding policy,
   snapshot and spec raw bytes. The verifier still freshly recompiles the plan
   from the verified snapshot and frozen v1 policy; the signature cannot
   replace derivation replay.
6. `contract_spec_set`: independently signed exact contract-spec envelope.
   Every row is revalidated as `CFastExecutionQualityContractSpecDTO`; the
   canonical sorted row contracts must equal the envelope's exact-contract
   set, so extra hidden specs are rejected.
7. `custody_binding`: independently signed generation/root binding over the
   exact first six raw hashes, exact contracts, snapshot id, expiry, custody
   path hash and custody inode identity.

Every role has a separate exact keyring file and raw SHA256 pin. Complete key
domains include unused keys and must be pairwise disjoint. Policy and snapshot
reuse their existing signer purposes; the other five roles use their dedicated
purposes in the runtime schemas. The five new envelopes sign a role-separated
message (`commodity_c_fast_execution_quality_role_signature_v1`, exact role,
then canonical unsigned payload), so a valid signature cannot be replayed as a
different role. All signed runtime envelopes have a maximum ten-minute
lifetime.

The formal P0 input is the full query-v6 bundle, not a hand-assembled terminal
summary. Build the unsigned draft with:

```bash
PYTHONPATH=backend python \
  scripts/commodity_c_fast_execution_quality_p0_bundle_v6.py \
  --foundation-release /private/query-v6/foundation.json \
  --foundation-keyring /private/query-v6/foundation-keyring.json \
  --executable-release /private/query-v6/executable.json \
  --executable-keyring /private/query-v6/executable-keyring.json \
  --active-pin-set /private/query-v6/pin-set.manifest.json \
  --manifest /private/query-v6/manifest.json \
  --consume-marker /private/query-v6/consume.json \
  --launch-marker /private/query-v6/launch.json \
  --terminal /private/query-v6/terminal.json \
  --audit-json /private/query-v6/audit.json \
  --audit-csv /private/query-v6/audit.csv \
  --audit-markdown /private/query-v6/audit.md \
  --readonly-proof /private/query-v6/readonly-proof.json \
  --external-custody-identity /private/query-v6/external-custody.json \
  --issued-at 2026-08-02T04:00:00Z \
  --valid-until 2026-08-02T04:10:00Z \
  --archived-at 2026-08-02T03:59:00Z \
  --signer-key-id <signed-p0-role-key-id> \
  --reviewer-role '<real human role>' \
  --human-signature '<real review text>' \
  --output /private/query-v6/unsigned-p0-v6.json
```

The builder stable-reads all fourteen distinct files twice, validates the
foundation/executable/keyring/pin/consume/launch/terminal joins, binds the
pretty JSON and rendered CSV/Markdown raw bytes, derives the bundle index,
snapshot, ten exact contracts and lifecycle timeline, then calls the same P0
semantic replay used by the signer. Its output is create-only `0600` pretty
JSON and intentionally omits `signature`. It has no private-key argument,
network client, authority or mutation path. External WORM/append-only custody
is a human assertion bound by exact identity and bundle hashes; it is not
misrepresented as machine-verifiable archive state.

The signed P0 embeds the exact manifest bytes as well as terminal, readonly
proof and audit JSON. The shared audit-v4 semantic core reconstructs the
manifest's exact-contract/vt-symbol mapping and recomputes segment, session,
contract, execution-window, product, blocker, row-count, quality-breakdown and
summary/P0 conclusions. Reported `classification` and summary fields are never
accepted as their own proof.

The five new envelopes are signed offline with the repository signer, which
uses the same role-domain message function and exact canonical-newline writer
as the production verifier contract:

```bash
PYTHONPATH=backend python \
  scripts/commodity_c_fast_execution_quality_sign_runtime_artifact.py \
  --input /private/custody/unsigned.json \
  --output /private/custody/signed.json \
  --private-key-file /private/keys/role.key \
  --role-keyring /private/keyrings/role.json \
  --expected-role-keyring-raw-sha256 <64-lowercase-hex>
```

The signer is deliberately excluded from the production image.
For `signed_p0_acceptance`, the signer replays the embedded terminal, proof,
audit and exact-bundle index semantics before it opens private-key material.
The other envelopes need
external upstream artifacts for their full joins, so the signer validates their
envelope contract and the runtime performs the complete generation join.

## Settings

Set the runtime and admission settings already documented in `.env.example`,
plus:

```text
COMMODITY_C_FAST_EXECUTION_QUALITY_ARTIFACT_CUSTODY_ROOT
COMMODITY_C_FAST_EXECUTION_QUALITY_ARTIFACT_PATHS_JSON
COMMODITY_C_FAST_EXECUTION_QUALITY_ARTIFACT_EXPECTED_ROOT_PATH_SHA256
COMMODITY_C_FAST_EXECUTION_QUALITY_ARTIFACT_EXPECTED_IDENTITY_SHA256
COMMODITY_C_FAST_EXECUTION_QUALITY_ARTIFACT_EXPECTED_OWNER_UID
COMMODITY_C_FAST_EXECUTION_QUALITY_ROLE_KEYRING_PATHS_JSON
COMMODITY_C_FAST_EXECUTION_QUALITY_ROLE_KEYRING_RAW_SHA256_JSON
COMMODITY_C_FAST_EXECUTION_QUALITY_POLICY_V1_PATH
COMMODITY_C_FAST_EXECUTION_QUALITY_POLICY_V1_EXPECTED_RAW_SHA256
```

Both JSON settings must contain exactly the seven role names. Production keeps
the owner UID at `0`. The factory constructs and binds the journal, repository,
export store, worker and Tick fan-out before it publishes the process-global
verifier capability. Any earlier component failure leaves that capability
unbound. Missing or malformed configuration is a component-binding failure,
never a downgrade to hash-only verification.

## Lifecycle and current boundary

Startup, reload and recovery each reopen the pinned root, stable-read all seven
files, reload all exact keyrings/policy ancestry, replay all signatures and
semantics, and return the plan/snapshot receipt/policy/spec tuple from that same
generation. Any expiry, splice, tamper, path/inode drift, key overlap or typed
join failure stops only this sidecar.

The QuestDB evidence adapter and the real M2 zero-order window are still
separate #217 acceptance work. Therefore `runtime_active=false`,
`execution_quality_implemented=false`, all authority flags remain false, and
the code must not be described as completed production acceptance.

## Verification

```bash
PYTHONPATH=backend pytest -q \
  backend/tests/unit/test_commodity_c_fast_execution_quality_production_verifier.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_artifact_revalidation.py \
  backend/tests/unit/test_commodity_c_fast_execution_quality_production_assembly.py

ruff check backend/app backend/tests/unit/test_commodity_c_fast_execution_quality_production_verifier.py
```
