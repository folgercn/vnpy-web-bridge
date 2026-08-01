from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from app.schemas.commodity_c_fast_execution_quality_runtime import StrictFalse
from app.schemas.commodity_c_fast_shadow import StrictFiniteModel


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _binding_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key not in {"admission_id", "signature"}
    }


def derived_runtime_admission_id(payload: dict[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json(_binding_payload(payload))).hexdigest()
    return f"cfast-execution-quality-runtime-admission-v1-{digest}"


class CFastExecutionQualityRuntimeArtifactDigestsDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    signed_p0_acceptance: str = Field(pattern=r"^[0-9a-f]{64}$")
    collection_admission: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_policy: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_snapshot: str = Field(pattern=r"^[0-9a-f]{64}$")
    virtual_intent_plan: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_spec_set: str = Field(pattern=r"^[0-9a-f]{64}$")
    custody_binding: str = Field(pattern=r"^[0-9a-f]{64}$")


class CFastExecutionQualityRuntimeAdmissionDTO(StrictFiniteModel):
    """Short-lived human-signed permission to assemble a read-only sidecar.

    The admission is deliberately not collection, execution, deployment or
    trading authority. It only allows the process to verify one exact full
    revalidation receipt while constructing the separately guarded sidecar.
    This v1 admission is short-lived but reusable within its validity window;
    it is not an irreversible one-shot consume capability.
    """

    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    schema_version: Literal["commodity_c_fast_execution_quality_runtime_admission_v1"]
    purpose: Literal["c_fast_execution_quality_readonly_sidecar_runtime_admission"]
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    parent_issue_number: Literal[114]
    issue_number: Literal[217]
    admission_id: str = Field(
        pattern=(r"^cfast-execution-quality-runtime-admission-v1-[0-9a-f]{64}$")
    )
    issued_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime
    signer_type: Literal["human"]
    reviewer_role: str = Field(min_length=1, max_length=128)
    human_signature: str = Field(min_length=1, max_length=512)
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    signature: str = Field(min_length=88, max_length=88)

    revalidation_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_contracts: tuple[str, ...] = Field(min_length=1, max_length=100)
    artifact_raw_sha256: CFastExecutionQualityRuntimeArtifactDigestsDTO
    journal_root_path_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    journal_root_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_export_root_path_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_export_root_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tick_input_mode: Literal["LOCAL_COPY_CALLBACK_NO_RPC_CAPABILITY"]
    repository_mode: Literal["CREATE_ONLY_SIDECAR_READ_ONLY_API"]
    questdb_mode: Literal["READ_ONLY_ADAPTER_NOT_CONNECTION_AUTHORITY"]
    full_runtime_build_required: Literal[True]
    admission_is_runtime_capability: Literal[False]

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

    @field_validator("issued_at_utc", "not_before_utc", "expires_at_utc")
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
    def validate_scope(self) -> "CFastExecutionQualityRuntimeAdmissionDTO":
        if (
            self.issued_at_utc > self.not_before_utc
            or self.not_before_utc >= self.expires_at_utc
            or self.reviewer_role.startswith("PENDING_")
            or self.human_signature.startswith("PENDING_")
        ):
            raise ValueError("runtime admission timing or signer scope invalid")
        payload = self.model_dump(mode="json")
        if self.admission_id != derived_runtime_admission_id(payload):
            raise ValueError("runtime admission id mismatch")
        return self


class CFastExecutionQualityRuntimeAdmissionTrustedKeyDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    public_key_base64: str = Field(min_length=44, max_length=44)
    signer_type: Literal["human"]
    reviewer_role: str = Field(min_length=1, max_length=128)


class CFastExecutionQualityRuntimeAdmissionTrustedKeysDTO(StrictFiniteModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    schema_version: Literal[
        "commodity_c_fast_execution_quality_runtime_admission_trusted_keys_v1"
    ]
    purpose: Literal[
        "c_fast_execution_quality_runtime_admission_signature_verification"
    ]
    trusted_keys: tuple[CFastExecutionQualityRuntimeAdmissionTrustedKeyDTO, ...] = (
        Field(min_length=1, max_length=16)
    )

    @model_validator(mode="after")
    def validate_key_domain(
        self,
    ) -> "CFastExecutionQualityRuntimeAdmissionTrustedKeysDTO":
        ids = [key.key_id for key in self.trusted_keys]
        materials = [key.public_key_base64 for key in self.trusted_keys]
        if (
            len(set(ids)) != len(ids)
            or len(set(materials)) != len(materials)
            or any(
                key.reviewer_role.startswith("PENDING_") for key in self.trusted_keys
            )
        ):
            raise ValueError("runtime admission trusted key domain invalid")
        return self


__all__ = [
    "CFastExecutionQualityRuntimeAdmissionDTO",
    "CFastExecutionQualityRuntimeAdmissionTrustedKeyDTO",
    "CFastExecutionQualityRuntimeAdmissionTrustedKeysDTO",
    "derived_runtime_admission_id",
]
