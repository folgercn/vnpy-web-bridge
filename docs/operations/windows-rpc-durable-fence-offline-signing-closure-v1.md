# Windows fence offline signing closure v1

This procedure is offline and non-executing. It never connects to Windows or
M2, starts a container, invokes SCM/RPC, or changes trading behavior.

The signer receives an inherited read-only private-key descriptor through
`--private-key-fd`; it deliberately has no key-file argument, environment
variable, log value, bundle member, or runtime/installer hand-off. Public
keyrings remain the only key material used by installer/runtime verification.

Perform positive FD signing only on a controlled Unix/macOS offline host: it
uses `fcntl(F_GETFL)` to prove that the inherited descriptor is read-only.
Windows intentionally has no portable equivalent and the signer must fail
closed with `SIGNING_PRIVATE_KEY_FD_ACCESS_UNVERIFIABLE`; Windows CI may build
and verify public artifacts, but must not perform positive private-key signing.

Use three independently provisioned Ed25519 keys: manifest, observer evidence,
and restart authorization. The implementation rejects reused public bytes,
key IDs, hashes, roles, or domains. Every artifact and its audit sidecar must
be written to pre-existing private directories with create-only publication,
fsync, and canonical readback.

The observer signer alone consumes the preflight challenge nonce and replay
guard in a create-only offline ledger. Manifest signing consumes its attempt
nonce and immutable install-attempt identity; restart authorization consumes
its dispatch nonce and authorization identity. Each ledger file is itself a
canonical reservation receipt, bound to the target artifact schema, ID, core,
and signature domain without using another key. Supply the six raw receipts to
the closure input directory under the `*_reservation` names; closure includes
their raw SHA-256 values and rejects any replay, token, ID, core, domain, or
raw-artifact splice.

Before manifest or restart work, verify a canonical observer-signed zero-order
preflight that is no more than 30 seconds old and independently reports frozen
runtime, trading disabled, revoked execution authority, zero pending sends and
no active orders. The signing closure validates the fixed sequence:
preflight reservations, zero-preflight, manifest reservations, manifest, event
1, publish, event 2, restart reservations, restart authorization, event 3,
transition, event 4, SCM evidence, event 5, startup, event 6, attestation,
event 7.
The manifest itself has `restart_authorized=false`; it never substitutes for
the separate one-dispatch restart authorization.
