"""Phase C cross-service workflow vocabulary.

This module is deliberately dependency-free: it describes a browser-safe
handoff, but never signs, persists artifacts, or invokes an execution runtime.
Those capabilities remain separate service responsibilities.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

WORKFLOW_SCHEMA_VERSION = "web-bridge-phase-c-workflow-v1"
SIGNING_REQUEST_SCHEMA_VERSION = "web-bridge-phase-c-signing-request-v1"
AUTHORIZATION_COMMAND_SCHEMA_VERSION = "web-bridge-phase-c-authorization-command-v1"
PHASE_C_DOMAINS = frozenset({"map_acceptance", "c_fast_acceptance", "runtime_authorization"})
FALSE_AUTHORITY_FLAGS = {
    "production_allowed": False,
    "live_trading_authorized": False,
    "countable_forward": False,
}


class PhaseCWorkflowError(ValueError):
    """Raised for malformed cross-service handoff values."""


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
    *, artifact: Mapping[str, Any], domain: str, request_id: str, requested_by: str
) -> dict[str, Any]:
    """Build an export-only request.  It contains no private material."""

    if domain not in PHASE_C_DOMAINS:
        raise PhaseCWorkflowError("unsupported Phase C signing domain")
    if not request_id or not requested_by:
        raise PhaseCWorkflowError("request_id and requested_by are required")
    assert_false_authority_flags(artifact.get("payload", artifact))
    return {
        "schema_version": SIGNING_REQUEST_SCHEMA_VERSION,
        "request_id": request_id,
        "domain": domain,
        "requested_by": requested_by,
        "artifact": json.loads(canonical_json(dict(artifact))),
        "artifact_sha256": sha256(dict(artifact)),
        "browser_signing": False,
        "private_key_access": False,
        **FALSE_AUTHORITY_FLAGS,
    }


__all__ = [
    "AUTHORIZATION_COMMAND_SCHEMA_VERSION",
    "FALSE_AUTHORITY_FLAGS",
    "PHASE_C_DOMAINS",
    "SIGNING_REQUEST_SCHEMA_VERSION",
    "WORKFLOW_SCHEMA_VERSION",
    "PhaseCWorkflowError",
    "assert_false_authority_flags",
    "build_signing_request",
    "canonical_json",
    "sha256",
]
