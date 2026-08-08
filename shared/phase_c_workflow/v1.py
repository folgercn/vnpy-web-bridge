"""Phase C cross-service workflow vocabulary.

This module is deliberately dependency-free: it describes a browser-safe
handoff, but never signs, persists artifacts, or invokes an execution runtime.
Those capabilities remain separate service responsibilities.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from shared.artifact_contracts.v1 import validate_artifact_envelope
from shared.trust_contracts.v1 import ContractError, assert_non_authoritative
from shared.trust_contracts.v1 import build_signing_request as _build_trust_request

WORKFLOW_SCHEMA_VERSION = "web-bridge-phase-c-workflow-v1"
SIGNING_REQUEST_SCHEMA_VERSION = "web-bridge-phase-c-signing-request-v1"
AUTHORIZATION_COMMAND_SCHEMA_VERSION = "web-bridge-phase-c-authorization-command-v1"
PHASE_C_DOMAINS = frozenset({"map_acceptance", "c_fast_acceptance", "runtime_authorization"})
ARTIFACT_POLICY = {
    "map_acceptance": ("map-acceptance", "phase-c-map-acceptance-v1", "phase-c-map-acceptance"),
    "c_fast_acceptance": ("c-fast-acceptance", "phase-c-c-fast-acceptance-v1", "phase-c-c-fast-acceptance"),
    "runtime_authorization": ("runtime-authorization", "phase-c-runtime-authorization-v1", "phase-c-runtime-authorization"),
}
FALSE_AUTHORITY_FLAGS = {
    "production_allowed": False,
    "live_trading_authorized": False,
    "countable_forward": False,
}


class PhaseCWorkflowError(ValueError):
    """Raised for malformed cross-service handoff values."""


_SENSITIVE_KEY = re.compile(r"(?:private|secret|credential|password|account|rpc|gateway|token|key|signature|order|position|trade)", re.IGNORECASE)


def reject_sensitive_fields(value: Any) -> None:
    """Reject sensitive data recursively before it can enter Control/audit/custody."""
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str) or _SENSITIVE_KEY.search(key):
                raise PhaseCWorkflowError("sensitive artifact field is forbidden")
            reject_sensitive_fields(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            reject_sensitive_fields(nested)


def validate_phase_c_artifact(artifact: Mapping[str, Any], *, domain: str) -> dict[str, Any]:
    if domain not in ARTIFACT_POLICY:
        raise PhaseCWorkflowError("unsupported Phase C signing domain")
    try:
        envelope = validate_artifact_envelope(artifact)
        assert_non_authoritative(envelope)
    except ContractError as exc:
        raise PhaseCWorkflowError("artifact envelope is invalid or authoritative") from exc
    artifact_type, schema_ref, _purpose = ARTIFACT_POLICY[domain]
    if (envelope["trust_domain"], envelope["artifact_type"], envelope["schema_ref"]) != (domain, artifact_type, schema_ref):
        raise PhaseCWorkflowError("artifact type/schema/domain is not allowlisted")
    # The envelope's fixed structural names are safe; only producer-controlled
    # scope/payload/lineage values may be recursively inspected.
    reject_sensitive_fields(envelope["scope"])
    reject_sensitive_fields(envelope["payload"])
    return envelope


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PhaseCWorkflowError("workflow value must be canonical JSON") from exc


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def assert_false_authority_flags(value: Mapping[str, Any]) -> None:
    for name, expected in FALSE_AUTHORITY_FLAGS.items():
        if value.get(name) is not expected:
            raise PhaseCWorkflowError(f"{name} must remain false in Phase C")


def build_signing_request(
    *, artifact: Mapping[str, Any], domain: str, request_id: str, key_id: str, key_version: str, requested_at: str, expires_at: str
) -> dict[str, Any]:
    """Build an export-only request.  It contains no private material."""

    envelope = validate_phase_c_artifact(artifact, domain=domain)
    try:
        return _build_trust_request(envelope, domain=domain, key_id=key_id, key_version=key_version, request_id=request_id, requested_at=requested_at, expires_at=expires_at)
    except ContractError as exc:
        raise PhaseCWorkflowError("signing request is invalid") from exc


__all__ = [
    "ARTIFACT_POLICY",
    "AUTHORIZATION_COMMAND_SCHEMA_VERSION",
    "FALSE_AUTHORITY_FLAGS",
    "PHASE_C_DOMAINS",
    "SIGNING_REQUEST_SCHEMA_VERSION",
    "WORKFLOW_SCHEMA_VERSION",
    "PhaseCWorkflowError",
    "assert_false_authority_flags",
    "build_signing_request",
    "canonical_json",
    "reject_sensitive_fields",
    "sha256",
    "validate_phase_c_artifact",
]
