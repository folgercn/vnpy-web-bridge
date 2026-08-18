"""Typed DTOs for Control's Phase C read/command boundary.

No DTO imports custody, signing, TradeService, gateway, or commodity runtime
code.  Control only forwards these values to independently owned adapters.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shared.phase_c_workflow.v1 import (
    AUTHORIZATION_COMMAND_SCHEMA_VERSION,
    FALSE_AUTHORITY_FLAGS,
)

TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF = "web-bridge-simnow-keyless-target-plan-v1"
TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF = "web-bridge-simnow-keyless-target-plan-v2"
TRUSTED_KEYLESS_TARGET_PLAN_SCHEMA_REFS = frozenset(
    {
        TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF,
    }
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


class TrustedKeylessTargetPlanInstallContinuationDTO(StrictDTO):
    """Exact install-only retry for one already-published keyless plan."""

    idempotency_key: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    correlation_id: str = Field(
        min_length=8, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    publish_receipt_id: str = Field(
        min_length=8, max_length=192, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$"
    )
    publish_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    publish_expected_custody_version: int = Field(ge=0)
    publish_resulting_custody_version: int = Field(ge=1)
    artifact: dict[str, Any]

    @model_validator(mode="after")
    def _publish_versions_are_adjacent(
        self,
    ) -> TrustedKeylessTargetPlanInstallContinuationDTO:
        if (
            self.publish_resulting_custody_version
            != self.publish_expected_custody_version + 1
        ):
            raise ValueError("publish custody versions are not adjacent")
        return self


class TargetPlanPublicationProjectionDTO(AuthorityNegativeDTO):
    """Read-only Phase-C publication/install evidence for one phase key."""

    schema_version: Literal["phase-c-target-plan-publication-v1"] = (
        "phase-c-target-plan-publication-v1"
    )
    state: Literal["NOT_PUBLISHED", "PUBLISHED_NOT_INSTALLED", "INSTALLED"]
    idempotency_key: str
    install_idempotency_key: str
    observed_custody_version: int = Field(ge=0)
    custody_state_owner: Literal["artifact-custody"] = "artifact-custody"
    publisher_principal: Optional[str] = None
    correlation_id: Optional[str] = None
    artifact_id: Optional[str] = None
    artifact_canonical_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    artifact_raw_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    artifact_schema_ref: Optional[str] = None
    plan_schema_version: Optional[str] = None
    plan_id: Optional[str] = None
    plan_hash: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    plan_phase: Optional[Literal["CLOSE", "OPEN"]] = None
    publish_receipt_id: Optional[str] = None
    publish_receipt_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    publish_expected_custody_version: Optional[int] = Field(default=None, ge=0)
    publish_resulting_custody_version: Optional[int] = Field(default=None, ge=1)
    install_receipt_id: Optional[str] = None
    install_receipt_sha256: Optional[str] = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    install_expected_custody_version: Optional[int] = Field(default=None, ge=1)
    install_resulting_custody_version: Optional[int] = Field(default=None, ge=2)

    @model_validator(mode="after")
    def _state_has_exact_evidence(self) -> TargetPlanPublicationProjectionDTO:
        if self.install_idempotency_key != f"install-{self.idempotency_key}":
            raise ValueError("install idempotency does not bind publication")
        publication = (
            self.publisher_principal,
            self.correlation_id,
            self.artifact_id,
            self.artifact_canonical_sha256,
            self.artifact_raw_sha256,
            self.artifact_schema_ref,
            self.plan_schema_version,
            self.plan_id,
            self.plan_hash,
            self.plan_phase,
            self.publish_receipt_id,
            self.publish_receipt_sha256,
            self.publish_expected_custody_version,
            self.publish_resulting_custody_version,
        )
        installation = (
            self.install_receipt_id,
            self.install_receipt_sha256,
            self.install_expected_custody_version,
            self.install_resulting_custody_version,
        )
        if self.state == "NOT_PUBLISHED":
            if any(value is not None for value in publication + installation):
                raise ValueError("unpublished projection contains custody evidence")
            return self
        if any(value is None for value in publication):
            raise ValueError("published projection lacks custody evidence")
        if (
            self.publish_resulting_custody_version
            != self.publish_expected_custody_version + 1  # type: ignore[operator]
        ):
            raise ValueError("publish custody versions are not adjacent")
        if self.state == "PUBLISHED_NOT_INSTALLED":
            if any(value is not None for value in installation):
                raise ValueError("uninstalled projection contains install evidence")
            return self
        if any(value is None for value in installation):
            raise ValueError("installed projection lacks install evidence")
        if (
            self.install_expected_custody_version
            != self.publish_resulting_custody_version
            or self.install_resulting_custody_version
            != self.install_expected_custody_version + 1  # type: ignore[operator]
        ):
            raise ValueError("install custody versions do not continue publication")
        return self


class CustodyCurrentVersionDTO(AuthorityNegativeDTO):
    """Read-only CAS input projected from the sole custody ledger owner."""

    schema_version: Literal["phase-c-custody-current-version-v1"] = (
        "phase-c-custody-current-version-v1"
    )
    version: int = Field(ge=0)
    custody_state_owner: Literal["artifact-custody"] = "artifact-custody"


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
    schema_ref: Literal[
        TRUSTED_KEYLESS_TARGET_PLAN_V1_SCHEMA_REF,
        TRUSTED_KEYLESS_TARGET_PLAN_V2_SCHEMA_REF,
    ]
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
