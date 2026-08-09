# Windows fence offline signing closure v1

This procedure is offline and non-executing. It never connects to Windows or
M2, starts a container, invokes SCM/RPC, or changes trading behavior.

The signer receives an inherited read-only private-key descriptor through
`--private-key-fd`; it deliberately has no key-file argument, environment
variable, log value, bundle member, or runtime/installer hand-off. Public
keyrings remain the only key material used by installer/runtime verification.

Use three independently provisioned Ed25519 keys: manifest, observer evidence,
and restart authorization. The implementation rejects reused public bytes,
key IDs, hashes, roles, or domains. Every artifact and its audit sidecar must
be written to pre-existing private directories with create-only publication,
fsync, and canonical readback.

Before manifest or restart work, verify a canonical observer-signed zero-order
preflight that is no more than 30 seconds old and independently reports frozen
runtime, trading disabled, revoked execution authority, zero pending sends and
no active orders. The signing closure validates the fixed sequence:
zero-preflight, manifest, event 1, publish, event 2, restart authorization,
event 3, transition, event 4, SCM evidence, event 5, startup, event 6,
attestation, event 7.
The manifest itself has `restart_authorized=false`; it never substitutes for
the separate one-dispatch restart authorization.
