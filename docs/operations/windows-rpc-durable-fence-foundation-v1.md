# Windows RPC durable fence foundation v1

This runbook freezes the C2b Windows foundation contract. It does not install
the extension, authorize a Windows service restart, sign a production
manifest, or authorize any order action.

## Delivery order

The foundation is delivered as seven independently reviewed changes:

1. ownership, classifier, schemas, and recovery contract;
2. one atomic durable-core change containing the `FROZEN_NONE` store,
   protected launcher, A2 integration, and final send/cancel deny;
3. reproducible bundle and offline signed install manifest verifier;
4. M2 host-observer plus fresh Windows zero-order preflight;
5. deterministic stage/query installer with a create-only attempt journal;
6. post-restart identity and final-admission attestation;
7. an explicitly authorized operator ceremony against merged exact hashes.

No intermediate merge proves that Windows is installed or fenced.

WF-1 source, contract, schema, and focused test paths select the dedicated
`windows_fence_changed` CI gate. That gate runs read-only offline tests on
Ubuntu and Windows and has only repository read permission. It has no secret,
package-write, deployment, service-control, or restart capability. These exact
paths do not select the unrelated Linux production image; a mixed change that
also modifies ordinary backend runtime code still selects the normal image
build. The release plan remains `infra_manual`, has no deploy or restart unit,
and maps only to the non-deploying Windows foundation bundle build unit.

The WF-1 production entry is `launch_windows_rpc_durable_fence_v1`. Its
public input contains only the store expectation and one immutable runtime
configuration; recovery, Win32 inspection, vn.py engine construction, gateway
connection, A2 attachment, and RPC listener start are fixed reviewed functions
rather than caller-supplied lifecycle callbacks. Before constructing
`MainEngine`, the entry binds the canonical runtime-config hash, gateway, A2
source hash, launcher source hash, and canonical assembly inventory hash to the
recovered genesis state. The generic callback bootstrap remains an offline
test seam and is not the production entry.

The A2 v1 wire response stays byte-compatible with its existing strict Linux
consumer. In the protected assembly, A2 instead retains an immutable
in-process `durable_fence_binding_sha256` over state/store/attempt IDs, state
and inventory hashes, FROZEN/NONE inventories, and stable final-handler
identities. Every A2 capture revalidates that binding and verifies the final
registry still points directly to the no-downstream admission object. This is
an in-process WF-1 binding, not authenticated remote provenance; WF-5 owns the
signed attestation.

The machine-readable cross-artifact contract is
`docs/architecture/windows-rpc-durable-fence-foundation-chain-v1.json`.
WF-2 through WF-5 verifiers must reject every equality, raw-byte digest,
freshness, event-chain, signing-domain, registry-handler, and zero-downstream-
call mismatch listed there. Validating each artifact schema independently is
never sufficient for installation, restart, or foundation closure.

The install-attempt ID is deterministic. Its v1 domain-separated canonical
input binds the operator nonce, exact bundle, service, target store path and
observed volume identity, expected account, and gateway scope. The same input
must produce the same ID; a second ID or nonce reuse with changed immutable
inputs is rejected.

## Foundation state

The only state accepted by the foundation reader is:

```text
admission = FROZEN
token_state = NONE
staged_token = null
active_token = null
active_grant = null
```

`STAGED` and `ACTIVE` belong to D2 and D3. A foundation binary must reject
them rather than infer forward compatibility. Missing, truncated, forked,
unknown-version, rollback, unsafe-ACL, reparse-point, hardlink, or unreadable
state keeps final order admission closed and the service not ready.

Every final WF-1 send/cancel rejection uses the frozen contract code
`WINDOWS_FENCE_ACTIVE_TOKEN_REQUIRED`. The runtime resolves the actual
`NT SERVICE\\<service>` SID through Windows and requires it to be the sole
write principal in the exact protected DACL. Broad, inherited, unparsed-write,
hardlink, reparse, or alternate-stream facts fail closed. Volume identity is
the SHA-256 of the canonical Windows volume GUID identity, independent of the
separately checked volume serial. Root and state inventories are re-read before
ready is returned, so a changed or forked inventory cannot pass recovery.

The durable journal is a create-only hash chain. Directory inventory is the
authority; a `HEAD` pointer is only a reconstructible cache. Local storage
does not prove that its entire volume was not rolled back; C2c supplies the
external high-water witness.

## Installation boundary

Before any installation write, independent evidence must prove all of the
following:

- the old Linux owner is frozen, trading is disabled, and authority is
  revoked;
- a fresh challenge-bound Windows EventEngine snapshot has zero pending send
  outcomes and no active orders;
- the sanitized raw account row and gateway scope match the signed manifest;
- the extension, launcher, assembly, configuration, service, store root, and
  deterministic attempt identity match exact hashes.

The signed install manifest is not restart authorization. A restart requires
a separate short-lived authorization issued immediately before the operation.
That authorization binds the exact signed publish/readback receipt, whose
component bytes, destination, ACL readback, owner, hardlink count, and
reparse-free parent chain must all verify first.
The manifest is signed only after the fresh preflight exists. It fixes the
content-addressed final directory, every component destination, the service
ImagePath/configuration, owner SID, directory/file ACL policy, and the rule
that the installer loses write access after atomic create-only publication.
It also binds the observer-captured preinstall SCM configuration and the exact
preinstall-to-target transition plan. At observer seal time the active SCM
configuration must still equal the preinstall readback; the target ImagePath
must not yet be active. The manifest alone cannot execute that transition.
The independent observer seal is single-use and expires after 30 seconds.
After a fresh restart authorization, install event 3 first durably reserves
and consumes the exact nonce and service operation. Only then may the installer
first apply and read back a manifest-bound safety configuration that retains
the preinstall ImagePath while setting StartType to demand/manual and disabling
recovery/failure auto-start actions. It may then switch to the target ImagePath
while retaining that safe policy, read everything back, and publish event 4
`SERVICE_CONFIG_TRANSITION_VERIFIED`. Restart is forbidden before event 4.
Immediately before restart dispatch, the installer rechecks the exact sealed
paths, bytes, owner, ACL, reparse/hardlink state, transition receipt, and target
service configuration; any drift blocks the call. The observer-signed startup
receipt binds event 5, the independent host-observed SCM ETW/EventLog raw trace,
caller SID/process/session, operation/nonce, SCM call timestamps/result,
PID/start time, boot identity, and target hashes. Event 5 and the receipt must
bind the same single-use audit evidence. Process start must be strictly later
than the audited SCM call start. Preflight, manifest, journal events, publish
seal, restart authorization, transition receipt, SCM evidence, startup receipt,
and attestation use one pinned trusted clock identity; event 5 and startup
observation must both occur before the SCM trace expires.
WF-0 does not authorize restoring auto-start or recovery actions.
If the restart result is unknown, query the same attempt and SCM/service
identity; never issue a second blind restart.

Install event 3 is `RESTART_DISPATCH_RESERVED`. It create-only publishes,
fsyncs, and securely reads back the exact authorization nonce and service
operation ID before any SCM call. That durable event consumes the nonce. If
the process crashes before, during, or after SCM dispatch, a head at or beyond
event 3 is query-only and may never dispatch restart again. A crash before or
during the configuration transition sacrifices liveness and requires an
explicitly authorized compatible successor attempt; it does not permit reuse
of the consumed authorization or an implicit SCM recovery start.

The manifest signer, observer-evidence signer, and restart authorizer use
distinct credential domains. The independent observer also seals the
post-publish readback; the installer cannot self-attest its own writes. The
Windows target and installer hold only the exact public keys needed for their
verifier roles; the restart authorizer cannot install, restart, observe, or
submit orders.

Every signed artifact uses `windows-foundation-canonical-json-v1`: strict JSON
parsing rejects duplicate keys, floats, non-finite values, and non-NFC text,
then RFC 8785 JCS produces UTF-8 bytes. The core hash covers every field except
the artifact ID, core-hash field, and signature; the ID suffix equals that
core hash. Ed25519 signs `domain-separator || 0x00 || canonical-envelope`,
where the envelope contains every field except the signature, including all
authority flags, role, key domain, key ID, and pinned public-key hash. Base64
must decode canonically to exactly 64 bytes; embedded or cross-domain keys are
never trusted.

The same identity/signature profile is a mandatory precondition for every
artifact, completed prefix event, and the terminal `FAILED_FROZEN` event
present at a failure frontier. Failure handling parses each exact raw byte
sequence once, verifies canonical bytes, core/ID derivation, external
role/domain key pin, and Ed25519 signature, and only then evaluates raw-digest,
predecessor, stage, and equality bindings.

Post-restart closure uses a one-way chain: `START_OBSERVED` event, signed
foundation attestation, then terminal `FOUNDATION_VERIFIED` event. The
attestation uses an in-process non-forwarding final-registry probe; live
mutation RPC probing is forbidden. It binds the final send/cancel handler
identities, request/response evidence, and gateway counters proving zero
downstream mutation calls.

Preflight, genesis state, and post-restart evidence must agree on receipt and
manifest IDs, server/fact projection, store ID/path/volume serial plus observed
volume-identity evidence, account row, gateway name/scope, and old service
identity. Account-row and gateway-scope base64 payloads are strict canonical
JSON: their decoded bytes must equal their RFC 8785 re-encoding and their
declared SHA-256. This volume identity binding proves the intended volume was
used; it does not claim whole-volume anti-rollback, which remains C2c scope.

## Roll-forward-only recovery

- Before restart: retain the old frozen runtime and require fresh restart
  authorization.
- After publish with an unknown restart result: query the same attempt,
  service PID/start time, and startup receipt.
- On partial install or unknown version: mark recovery required and keep order
  admission blocked.
- Never start an older launcher or extension that cannot understand the
  durable store. Recovery uses an explicitly signed, compatible successor.

The real operator ceremony may begin only after the required code and bundle
hashes are merged. It always requires fresh read-only preflight and explicit
operator authorization; no GitHub merge or earlier approval substitutes for
that authorization.
