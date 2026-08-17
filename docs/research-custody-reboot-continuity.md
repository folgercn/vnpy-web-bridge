# Research custody reboot continuity

Issue: #355

## Contract

Research observation v1 historically bound durable custody identity to:

```text
root path + st_dev + inode + uid + gid + mode
```

On the production APFS host, a normal reboot changed only `st_dev`. Runtime filesystem safety still needs device checks, but durable evidence identity must not become unverifiable solely because the operating system assigned a different device number after reboot.

The #355 contract therefore separates two concerns:

- Runtime filesystem/TOCTOU checks continue to use the current device identity and same-filesystem requirements.
- New observation v2 durable custody identity binds `root path + inode + uid + gid + mode` under an explicit v2 domain and does not include `st_dev`.
- Existing observation v1 bytes, IDs, hashes, raw payloads, manifests, and receipts are never rewritten.
- A reviewed legacy `st_dev` transition is accepted only through a signed create-only custody transition receipt using the already pinned M2 backup signing trust.

Missing, tampered, replayed, unrelated, or partially matching transitions fail closed.

## Preconditions for a transition receipt

Do not sign a transition unless read-only inspection proves all of the following:

1. The custody root path is unchanged.
2. The root inode is unchanged.
3. UID, GID, and mode are unchanged and satisfy the production policy.
4. Only `st_dev` changed across the reviewed reboot.
5. The historical legacy identity is reproduced exactly from the reviewed old `st_dev`.
6. The current legacy identity is reproduced exactly from the current `st_dev`.
7. There is no evidence of a custody copy, root replacement, ownership change, ACL change, or raw-data mutation.

For the 2026-08-14 incident the reviewed facts are:

```text
source_st_dev=16777229
source_legacy_identity=2ed159e157e3252ae2c665bf92ad7419370b2979f45afbb188bc2c9a2fafae1a

destination_st_dev=16777234
destination_legacy_identity=3d70ba85584aea530e2d75978e151ff55e4bc55f5133c501ccd93c1c6df6066b
```

## One-shot operator procedure

After the #355 release is installed through the existing approved Research release mechanism, first repeat the read-only identity inspection. If any precondition differs from the reviewed facts, stop.

Then, as the existing root-managed M2 operator, create the transition receipt once:

```bash
python -m research_warehouse.m2_custody_transition_cli \
  --source-st-dev 16777229 \
  --expected-source-legacy-identity 2ed159e157e3252ae2c665bf92ad7419370b2979f45afbb188bc2c9a2fafae1a \
  --expected-destination-legacy-identity 3d70ba85584aea530e2d75978e151ff55e4bc55f5133c501ccd93c1c6df6066b
```

The receipt is create-only at:

```text
/usr/local/libexec/vnpyresearch/custody-transition-v1.json
```

The CLI reuses the existing M2 backup private key and verifies that its public key matches the backup public-key SHA already pinned by the root-managed runtime input. It does not add trading, execution, deployment, RPC, or production authority.

Do not replace, edit, re-sign, or manually copy the transition receipt after creation.

## Verification and recovery sequence

After the receipt exists, remain read-only and perform the existing verification path in this order:

1. Load and validate at least one pre-reboot observation bound to the source legacy identity.
2. Load and validate at least one post-reboot observation bound to the destination legacy identity.
3. Run the existing M2 history/manifest/root-pin verification over the required source history.
4. If and only if the existing evidence chain verifies, regenerate the same-month non-fixture paired sources through the existing `static_core_baseline` and PIT source-view paths.
5. Independently verify both generated canonical sources.
6. Return to Issue #353 at read-only preflight only.
7. Stop before Run A or any Execution/Windows/SimNow mutation and obtain the existing mutation authorization.

The #355 repair does **not** require a 186-day historical re-sample merely to bypass the reboot mismatch. If another independent evidence failure appears after continuity is restored, stop and diagnose that failure rather than silently rebuilding history.

## Fail-closed cases

Stop without producing or trusting continuity if any of these occur:

- source or destination legacy hash differs from the reviewed value;
- root path, inode, UID, GID, or mode differs;
- transition signer public-key pin differs;
- receipt signature, schema, canonical JSON, or transition ID fails;
- receipt is replayed against another custody root;
- an observation claims a legacy identity outside the signed source/destination pair;
- a v2 observation does not match the current stable-v2 identity;
- existing manifest/root-pin verification reveals any additional unrelated mismatch.
