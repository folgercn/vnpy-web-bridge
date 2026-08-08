"""Issue #291 signing and trust contracts.

The package is intentionally dependency-light.  It is imported by the offline
signer and by custody/verifier processes; it must never import FastAPI, vn.py,
or a trading service.
"""

from .v1 import (
    KEY_DOMAINS,
    SIGNED_ARTIFACT_SCHEMA_VERSION,
    SIGNING_REQUEST_SCHEMA_VERSION,
    TRUST_KEYRING_SCHEMA_VERSION,
    ContractError,
    assert_non_authoritative,
    build_signed_artifact,
    build_signing_request,
    canonical_json,
    canonical_json_line,
    load_keyring,
    sha256_bytes,
    signing_bytes,
    validate_domain_keyrings,
    validate_keyring,
    validate_signing_request,
    verify_signed_artifact,
)

__all__ = [
    "KEY_DOMAINS",
    "SIGNED_ARTIFACT_SCHEMA_VERSION",
    "SIGNING_REQUEST_SCHEMA_VERSION",
    "TRUST_KEYRING_SCHEMA_VERSION",
    "ContractError",
    "assert_non_authoritative",
    "build_signed_artifact",
    "build_signing_request",
    "canonical_json",
    "canonical_json_line",
    "load_keyring",
    "sha256_bytes",
    "signing_bytes",
    "validate_domain_keyrings",
    "validate_keyring",
    "validate_signing_request",
    "verify_signed_artifact",
]
