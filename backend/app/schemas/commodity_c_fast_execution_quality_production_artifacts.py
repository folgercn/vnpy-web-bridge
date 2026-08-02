from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from app.schemas.commodity_c_fast_execution_quality import CFastVirtualIntentPlanDTO
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    ArtifactRole,
    StrictFalse,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastExecutionQualityContractSpecDTO,
)
from app.schemas.commodity_c_fast_shadow import StrictFiniteModel


class CFastExecutionQualityRoleTrustedKeyDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    purpose: str = Field(pattern=r"^[a-z0-9_]{8,128}$")
    public_key_base64: str = Field(min_length=44, max_length=44)


class CFastExecutionQualityRoleTrustedKeysDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    schema_version: Literal["commodity_c_fast_execution_quality_role_trusted_keys_v1"]
    artifact_role: ArtifactRole
    trusted_keys: tuple[CFastExecutionQualityRoleTrustedKeyDTO, ...] = Field(
        min_length=1,
        max_length=32,
    )

    @model_validator(mode="after")
    def require_unique_domain(self) -> "CFastExecutionQualityRoleTrustedKeysDTO":
        ids = [item.key_id for item in self.trusted_keys]
        materials = [item.public_key_base64 for item in self.trusted_keys]
        if len(set(ids)) != len(ids) or len(set(materials)) != len(materials):
            raise ValueError("role key domain must be unique")
        return self


class _SignedRuntimeRoleBase(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    generation_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    issued_at_utc: datetime
    valid_until_utc: datetime
    exact_contracts: tuple[str, ...] = Field(min_length=1, max_length=100)
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    signature: str = Field(min_length=88, max_length=88)

    collection_authorized: StrictFalse
    runtime_activation_authorized: StrictFalse
    authority_granted: StrictFalse
    dispatch_allowed: StrictFalse
    order_authorized: StrictFalse
    position_mutation_authorized: StrictFalse
    database_mutation_authorized: StrictFalse
    deployment_mutation_authorized: StrictFalse
    replacement_allowed: StrictFalse
    production_allowed: StrictFalse

    @field_validator("issued_at_utc", "valid_until_utc")
    @classmethod
    def require_utc(cls, value: datetime, info) -> datetime:
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise ValueError(f"{info.field_name} must use UTC")
        return value

    @field_validator("exact_contracts")
    @classmethod
    def require_canonical_contracts(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("exact_contracts must be sorted and unique")
        return value

    @model_validator(mode="after")
    def require_active_window(self):
        if self.issued_at_utc >= self.valid_until_utc:
            raise ValueError("role validity window invalid")
        return self


class CFastExecutionQualityP0AcceptanceV6DTO(_SignedRuntimeRoleBase):
    schema_version: Literal["commodity_c_fast_execution_quality_p0_acceptance_v6_v1"]
    artifact_role: Literal["signed_p0_acceptance"]
    purpose: Literal["c_fast_query_v6_exact_terminal_p0_acceptance"]
    terminal_exact_json_base64: str = Field(min_length=16)
    terminal_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    readonly_proof_exact_json_base64: str = Field(min_length=16)
    readonly_proof_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    readonly_proof_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_exact_json_base64: str = Field(min_length=16)
    audit_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable_release_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable_release_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    foundation_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    foundation_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_adapter_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_raw_sha256: "CFastExecutionQualityP0BundleRawDigestsDTO"
    bundle_canonical_sha256: "CFastExecutionQualityP0BundleCanonicalDigestsDTO"
    bundle_size_bytes: "CFastExecutionQualityP0BundleSizesDTO"
    bundle_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    external_archive: "CFastExecutionQualityP0ExternalArchiveDTO"
    consumed_at_utc: datetime
    launch_claimed_at_utc: datetime
    started_at_utc: datetime
    final_revalidation_at_utc: datetime
    ended_at_utc: datetime
    archived_at_utc: datetime
    p0_accepted: Literal[True]
    exact_terminal_replayed: Literal[True]
    exact_readonly_proof_replayed: Literal[True]
    exact_audit_replayed: Literal[True]
    signer_type: Literal["human"]
    reviewer_role: str = Field(min_length=1, max_length=128)
    human_signature: str = Field(min_length=1, max_length=512)

    @field_validator("reviewer_role", "human_signature", mode="before")
    @classmethod
    def require_human_review(cls, value: object) -> object:
        if isinstance(value, str):
            normalized = value.strip()
            if not normalized or normalized.startswith("PENDING_"):
                raise ValueError("P0 human review is pending")
            return normalized
        return value

    @field_validator(
        "consumed_at_utc",
        "launch_claimed_at_utc",
        "started_at_utc",
        "final_revalidation_at_utc",
        "ended_at_utc",
        "archived_at_utc",
    )
    @classmethod
    def require_timeline_utc(cls, value: datetime, info) -> datetime:
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise ValueError(f"{info.field_name} must use UTC")
        return value

    @model_validator(mode="after")
    def require_exact_p0_timeline(self):
        if not (
            self.consumed_at_utc
            == self.started_at_utc
            <= self.final_revalidation_at_utc
            <= self.launch_claimed_at_utc
            <= self.ended_at_utc
            <= self.archived_at_utc
            <= self.issued_at_utc
        ):
            raise ValueError("query-v6 P0 timeline is invalid")
        if self.external_archive.archived_at_utc != self.archived_at_utc:
            raise ValueError("external archive timeline is not exact")
        if self.external_archive.archived_bundle_index_sha256 != self.bundle_index_sha256:
            raise ValueError("external archive bundle index is not exact")
        if self.valid_until_utc - self.issued_at_utc > timedelta(minutes=10):
            raise ValueError("query-v6 P0 validity exceeds ten minutes")
        return self


class CFastExecutionQualityP0BundleRawDigestsDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    foundation_release: str = Field(pattern=r"^[0-9a-f]{64}$")
    foundation_keyring: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable_release: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable_keyring: str = Field(pattern=r"^[0-9a-f]{64}$")
    active_pin_set: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest: str = Field(pattern=r"^[0-9a-f]{64}$")
    consume_marker: str = Field(pattern=r"^[0-9a-f]{64}$")
    launch_marker: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_json: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_csv: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_markdown: str = Field(pattern=r"^[0-9a-f]{64}$")
    readonly_proof: str = Field(pattern=r"^[0-9a-f]{64}$")
    external_custody_identity: str = Field(pattern=r"^[0-9a-f]{64}$")


class CFastExecutionQualityP0BundleCanonicalDigestsDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    foundation_release: str = Field(pattern=r"^[0-9a-f]{64}$")
    foundation_keyring: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable_release: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable_keyring: str = Field(pattern=r"^[0-9a-f]{64}$")
    active_pin_set: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest: str = Field(pattern=r"^[0-9a-f]{64}$")
    consume_marker: str = Field(pattern=r"^[0-9a-f]{64}$")
    launch_marker: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_json: str = Field(pattern=r"^[0-9a-f]{64}$")
    audit_csv: None = None
    audit_markdown: None = None
    readonly_proof: str = Field(pattern=r"^[0-9a-f]{64}$")
    external_custody_identity: str = Field(pattern=r"^[0-9a-f]{64}$")


class CFastExecutionQualityP0BundleSizesDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    foundation_release: int = Field(gt=0, le=64 * 1024 * 1024)
    foundation_keyring: int = Field(gt=0, le=64 * 1024 * 1024)
    executable_release: int = Field(gt=0, le=64 * 1024 * 1024)
    executable_keyring: int = Field(gt=0, le=64 * 1024 * 1024)
    active_pin_set: int = Field(gt=0, le=64 * 1024 * 1024)
    manifest: int = Field(gt=0, le=64 * 1024 * 1024)
    consume_marker: int = Field(gt=0, le=64 * 1024 * 1024)
    launch_marker: int = Field(gt=0, le=64 * 1024 * 1024)
    terminal: int = Field(gt=0, le=64 * 1024 * 1024)
    audit_json: int = Field(gt=0, le=64 * 1024 * 1024)
    audit_csv: int = Field(gt=0, le=64 * 1024 * 1024)
    audit_markdown: int = Field(gt=0, le=64 * 1024 * 1024)
    readonly_proof: int = Field(gt=0, le=64 * 1024 * 1024)
    external_custody_identity: int = Field(gt=0, le=64 * 1024 * 1024)


class CFastExecutionQualityP0ExternalArchiveDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    custody_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    asserted_archive_type: Literal["ASSERTED_WORM", "ASSERTED_APPEND_ONLY"]
    archive_locator_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    custody_identity_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    custody_identity_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    archived_bundle_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    archived_at_utc: datetime
    independent_custody_asserted: Literal[True]
    immutability_asserted: Literal[True]
    verification_state: Literal["HUMAN_ASSERTION_NOT_MACHINE_VERIFIED"]

    @field_validator("archived_at_utc")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise ValueError("archived_at_utc must use UTC")
        return value


class CFastExecutionQualityCollectionAdmissionV2DTO(_SignedRuntimeRoleBase):
    schema_version: Literal[
        "commodity_c_fast_execution_quality_collection_admission_v2"
    ]
    artifact_role: Literal["collection_admission"]
    purpose: Literal["c_fast_execution_quality_query_v6_collection_admission"]
    signed_p0_acceptance_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_policy_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    p0_accepted: Literal[True]
    policy_rules_complete: Literal[True]
    admission_fact_frozen: Literal[True]
    signer_type: Literal["human"]
    reviewer_role: str = Field(min_length=1, max_length=128)
    human_signature: str = Field(min_length=1, max_length=512)

    @field_validator("reviewer_role", "human_signature", mode="before")
    @classmethod
    def require_human_review(cls, value: object) -> object:
        if isinstance(value, str):
            normalized = value.strip()
            if not normalized or normalized.startswith("PENDING_"):
                raise ValueError("collection admission human review is pending")
            return normalized
        return value


class CFastExecutionQualitySignedPlanDTO(_SignedRuntimeRoleBase):
    schema_version: Literal["commodity_c_fast_execution_quality_signed_plan_v1"]
    artifact_role: Literal["virtual_intent_plan"]
    purpose: Literal["c_fast_execution_quality_virtual_plan_freeze"]
    execution_policy_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_snapshot_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_spec_set_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan: CFastVirtualIntentPlanDTO


class CFastExecutionQualitySignedContractSpecSetDTO(_SignedRuntimeRoleBase):
    schema_version: Literal[
        "commodity_c_fast_execution_quality_signed_contract_spec_set_v1"
    ]
    artifact_role: Literal["contract_spec_set"]
    purpose: Literal["c_fast_execution_quality_exact_contract_spec_freeze"]
    specs: tuple[CFastExecutionQualityContractSpecDTO, ...] = Field(
        min_length=1,
        max_length=100,
    )


class CFastExecutionQualityCustodyArtifactDigestsDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    signed_p0_acceptance: str = Field(pattern=r"^[0-9a-f]{64}$")
    collection_admission: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_policy: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_snapshot: str = Field(pattern=r"^[0-9a-f]{64}$")
    virtual_intent_plan: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_spec_set: str = Field(pattern=r"^[0-9a-f]{64}$")


class CFastExecutionQualitySignedCustodyBindingDTO(_SignedRuntimeRoleBase):
    schema_version: Literal[
        "commodity_c_fast_execution_quality_signed_custody_binding_v1"
    ]
    artifact_role: Literal["custody_binding"]
    purpose: Literal["c_fast_execution_quality_exact_generation_custody"]
    custody_root_path_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    custody_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_raw_sha256: CFastExecutionQualityCustodyArtifactDigestsDTO


__all__ = [
    "CFastExecutionQualityCollectionAdmissionV2DTO",
    "CFastExecutionQualityP0AcceptanceV6DTO",
    "CFastExecutionQualityP0BundleCanonicalDigestsDTO",
    "CFastExecutionQualityP0BundleRawDigestsDTO",
    "CFastExecutionQualityP0BundleSizesDTO",
    "CFastExecutionQualityP0ExternalArchiveDTO",
    "CFastExecutionQualityRoleTrustedKeysDTO",
    "CFastExecutionQualitySignedContractSpecSetDTO",
    "CFastExecutionQualitySignedCustodyBindingDTO",
    "CFastExecutionQualitySignedPlanDTO",
]


CFastExecutionQualityP0AcceptanceV6DTO.model_rebuild()
