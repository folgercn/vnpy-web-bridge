"""Typed DTOs for Control's Phase C read/command boundary.

No DTO imports custody, signing, TradeService, gateway, or commodity runtime
code.  Control only forwards these values to independently owned adapters.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shared.phase_c_workflow.v1 import (
    AUTHORIZATION_COMMAND_SCHEMA_VERSION,
    FALSE_AUTHORITY_FLAGS,
)


class StrictDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorityNegativeDTO(StrictDTO):
    production_allowed: Literal[False] = False
    live_trading_authorized: Literal[False] = False
    countable_forward: Literal[False] = False


class SigningRequestCreateDTO(StrictDTO):
    request_id: str = Field(
        min_length=4, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    domain: Literal["map_acceptance", "c_fast_acceptance", "runtime_authorization"]
    key_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
    key_version: str = Field(pattern=r"^v[0-9]+$")
    requested_at: str = Field(min_length=20, max_length=64)
    expires_at: str = Field(min_length=20, max_length=64)
    artifact: dict[str, Any]


class SigningRequestDTO(StrictDTO):
    schema_version: Literal["web-bridge-signing-request-v1"] = (
        "web-bridge-signing-request-v1"
    )
    request_id: str
    domain: str
    key_id: str
    key_version: str
    requested_at: str
    expires_at: str
    artifact: dict[str, Any]


class SignedArtifactUploadDTO(StrictDTO):
    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    expected_custody_version: int = Field(ge=0)
    signing_request_id: str = Field(min_length=4, max_length=128)
    correlation_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    signed_artifact: dict[str, Any]


class TrustedKeylessTargetPlanUploadDTO(StrictDTO):
    """The only unsigned custody input: fixed-tuple SIMNOW target plans."""

    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    expected_custody_version: int = Field(ge=0)
    correlation_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    artifact: dict[str, Any]


class CustodyReceiptDTO(AuthorityNegativeDTO):
    receipt_id: str
    receipt_type: Literal["install"]
    artifact_id: str
    artifact_type: Literal["runtime-authorization", "simnow-target-plan"] = (
        "runtime-authorization"
    )
    trust_domain: Literal["runtime_authorization"] = "runtime_authorization"
    schema_ref: Literal[
        "phase-c-runtime-authorization-v1", "web-bridge-simnow-target-plan-v1"
    ] = "phase-c-runtime-authorization-v1"
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signer_key_id: str = "test-only"
    signer_key_version: str = "v1"
    keyring_raw_sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")
    signed_artifact_sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")
    scope: dict[str, Any] = Field(default_factory=dict)
    expires_at: str = "2099-01-01T00:00:00Z"
    custody_version: int = Field(ge=0)
    idempotency_key: str
    verified: Literal[True] = True
    installed: Literal[True] = True
    custody_writer: Literal["artifact-custody"] = "artifact-custody"

    @model_validator(mode="after")
    def _artifact_type_schema_pair_is_supported(self) -> CustodyReceiptDTO:
        if (self.artifact_type, self.schema_ref) not in {
            ("runtime-authorization", "phase-c-runtime-authorization-v1"),
            ("simnow-target-plan", "web-bridge-simnow-target-plan-v1"),
        }:
            raise ValueError("custody receipt artifact type/schema pair is invalid")
        return self


class TrustedKeylessCustodyReceiptDTO(AuthorityNegativeDTO):
    """Strict receipt returned only by the fixed-tuple keyless custody route."""

    receipt_id: str
    receipt_type: Literal["install"]
    artifact_id: str
    artifact_type: Literal["simnow-target-plan"]
    trust_domain: Literal["runtime_authorization"]
    schema_ref: Literal["web-bridge-simnow-keyless-target-plan-v1"]
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: dict[str, Any]
    expires_at: str
    custody_version: int = Field(ge=1)
    idempotency_key: str
    verified: Literal[True]
    installed: Literal[True]
    custody_writer: Literal["artifact-custody"]


class AuthorizationCommandDTO(StrictDTO):
    schema_version: Literal[AUTHORIZATION_COMMAND_SCHEMA_VERSION] = (
        AUTHORIZATION_COMMAND_SCHEMA_VERSION
    )
    command_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    expected_version: int = Field(ge=0)
    action: Literal["enable", "revoke"]
    authorization_artifact_id: str = Field(min_length=4, max_length=256)
    custody_receipt_id: str = Field(min_length=4, max_length=256)
    reason: str = Field(min_length=3, max_length=500)


class AuthorizationStatusDTO(AuthorityNegativeDTO):
    version: int = Field(ge=0)
    requested_state: Literal["DISABLED", "ENABLE_REQUESTED", "REVOKED"]
    effective_state: Literal["DISABLED"] = "DISABLED"
    artifact_id: str | None = None
    receipt_id: str | None = None
    runtime_mutation_allowed: Literal[False] = False


class ExecutionProjectionDTO(AuthorityNegativeDTO):
    status: Literal["OFFLINE", "ARCHIVED"]
    execution_mutation_allowed: Literal[False] = False
    runtime_state_owner: Literal["phase-c-execution"] = "phase-c-execution"
    custody_state_owner: Literal["artifact-custody"] = "artifact-custody"
    audit: list[dict[str, Any]] = Field(default_factory=list)
    archive: list[dict[str, Any]] = Field(default_factory=list)


class WorkflowStatusDTO(AuthorityNegativeDTO):
    map_status: Literal["PENDING", "READY"]
    c_fast_status: Literal["PENDING", "READY"]
    signing: Literal["EXPORT_ONLY"] = "EXPORT_ONLY"
    browser_signing: Literal[False] = False
    custody_writer: Literal["artifact-custody"] = "artifact-custody"
    execution_writer: Literal["phase-c-execution"] = "phase-c-execution"
    execution_mutation_allowed: Literal[False] = False


def as_negative(value: dict[str, Any]) -> dict[str, Any]:
    """Force the authority-negative contract on projections from an adapter."""
    return {**value, **FALSE_AUTHORITY_FLAGS}


__all__ = [name for name in globals() if name.endswith("DTO") or name == "as_negative"]
