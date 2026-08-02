from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.schemas.commodity_c_fast_shadow import StrictFiniteModel
from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionQualityCollectionPolicyV2DTO,
)
from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentPlanDTO,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastExecutionQualityContractSpecDTO,
)


RevalidationTrigger = Literal["startup", "reload", "recovery"]
ArtifactRole = Literal[
    "signed_p0_acceptance",
    "collection_admission",
    "execution_policy",
    "signed_snapshot",
    "virtual_intent_plan",
    "contract_spec_set",
    "custody_binding",
]


def _strict_false(value: Any) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("authority value must be the boolean literal false")
    return False


StrictFalse = Annotated[Literal[False], BeforeValidator(_strict_false)]


def _sha256_json(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _require_utc(value: datetime, field: str) -> None:
    if (
        value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        raise ValueError(f"{field} must use UTC")


def _require_canonical_digest_domain(
    value: tuple[str, ...],
) -> tuple[str, ...]:
    if tuple(sorted(set(value))) != value or any(
        re.fullmatch(r"[0-9a-f]{64}", digest) is None for digest in value
    ):
        raise ValueError("signer domain must contain sorted unique SHA256 values")
    return value


class CFastExecutionQualityArtifactSignerDomainsDTO(StrictFiniteModel):
    """Complete verified SHA256 domains of raw 32-byte Ed25519 public keys."""

    model_config = ConfigDict(frozen=True, revalidate_instances="always")

    signed_p0_acceptance: tuple[str, ...] = Field(min_length=1, max_length=64)
    collection_admission: tuple[str, ...] = Field(min_length=1, max_length=64)
    execution_policy: tuple[str, ...] = Field(min_length=1, max_length=64)
    signed_snapshot: tuple[str, ...] = Field(min_length=1, max_length=64)
    virtual_intent_plan: tuple[str, ...] = Field(min_length=1, max_length=64)
    contract_spec_set: tuple[str, ...] = Field(min_length=1, max_length=64)
    custody_binding: tuple[str, ...] = Field(min_length=1, max_length=64)

    @field_validator("*")
    @classmethod
    def require_complete_canonical_domains(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_canonical_digest_domain(value)


class CFastExecutionQualityRuntimeRevalidationDTO(StrictFiniteModel):
    """Result returned by the future full signed-authority verifier.

    This DTO is a capability boundary, not a verifier.  The runtime foundation
    accepts it only from a separately bound verifier and keeps all collection,
    persistence and trading authorities false.
    """

    model_config = ConfigDict(
        frozen=True,
        revalidate_instances="always",
    )

    schema_version: Literal[
        "commodity_c_fast_execution_quality_runtime_revalidation_v1"
    ]
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trigger: RevalidationTrigger
    revalidated_at_utc: datetime
    valid_until_utc: datetime
    exact_contracts: tuple[str, ...] = Field(min_length=1, max_length=100)

    signed_p0_acceptance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    collection_admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    virtual_intent_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_spec_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    custody_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_signer_domains: CFastExecutionQualityArtifactSignerDomainsDTO

    p0_acceptance_state: Literal["VERIFIED"]
    collection_admission_state: Literal["VERIFIED"]
    execution_policy_state: Literal["VERIFIED"]
    signed_snapshot_state: Literal["VERIFIED"]
    virtual_intent_plan_state: Literal["VERIFIED"]
    contract_spec_state: Literal["VERIFIED"]
    custody_state: Literal["VERIFIED"]

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

    @field_validator("revalidated_at_utc", "valid_until_utc")
    @classmethod
    def require_utc(cls, value: datetime, info) -> datetime:
        _require_utc(value, info.field_name)
        return value

    @field_validator("exact_contracts")
    @classmethod
    def require_canonical_contract_set(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("exact_contracts must be sorted and unique")
        for exact_contract in value:
            exchange, separator, symbol = exact_contract.partition(".")
            if (
                separator != "."
                or not exchange.isupper()
                or not exchange.isalpha()
                or not symbol[:-4].isalpha()
                or not symbol[-4:].isdigit()
                or not (8 <= len(exact_contract) <= 32)
            ):
                raise ValueError("exact_contract is invalid")
        return value

    @model_validator(mode="after")
    def validate_window_and_hash(
        self,
    ) -> "CFastExecutionQualityRuntimeRevalidationDTO":
        if self.valid_until_utc <= self.revalidated_at_utc:
            raise ValueError("valid_until_utc must follow revalidated_at_utc")
        core = self.model_dump(mode="json", exclude={"receipt_sha256"})
        if self.receipt_sha256 != _sha256_json(core):
            raise ValueError("receipt_sha256 mismatch")
        return self


class CFastExecutionQualityVerifiedRuntimeInputsDTO(StrictFiniteModel):
    """Atomic typed inputs produced by the same exact artifact revalidation.

    This is deliberately stricter than the hash-only receipt.  A production
    lifecycle may register durable virtual intents only from this bundle, so
    the plan, scoring policy and exact contract specifications cannot be read
    again from a weaker or newer filesystem generation after verification.
    """

    model_config = ConfigDict(
        frozen=True,
        revalidate_instances="always",
    )

    schema_version: Literal[
        "commodity_c_fast_execution_quality_verified_runtime_inputs_v1"
    ]
    verified_inputs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    revalidation_receipt: CFastExecutionQualityRuntimeRevalidationDTO
    preverified_plan: CFastVirtualIntentPlanDTO
    source_snapshot_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    score_policy: CFastExecutionQualityCollectionPolicyV2DTO
    score_policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_specs: tuple[CFastExecutionQualityContractSpecDTO, ...] = Field(
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def validate_atomic_typed_join(
        self,
    ) -> "CFastExecutionQualityVerifiedRuntimeInputsDTO":
        if self.source_snapshot_receipt_sha256 != self.preverified_plan.snapshot_hash:
            raise ValueError("source snapshot receipt must match plan snapshot hash")
        expected_score_policy_hash = _sha256_json(
            self.score_policy.model_dump(mode="json")
        )
        if self.score_policy_hash != expected_score_policy_hash:
            raise ValueError("score_policy_hash mismatch")
        if self.score_policy.foundation_policy_hash != self.preverified_plan.policy_hash:
            raise ValueError("score policy foundation binding mismatch")
        plan_contracts = tuple(
            sorted({intent.exact_contract for intent in self.preverified_plan.intents})
        )
        spec_contracts = tuple(spec.exact_contract for spec in self.contract_specs)
        if (
            not self.preverified_plan.intents
            or tuple(sorted(set(spec_contracts))) != spec_contracts
            or plan_contracts != self.revalidation_receipt.exact_contracts
            or spec_contracts != self.revalidation_receipt.exact_contracts
        ):
            raise ValueError("typed exact contract set mismatch")
        core = self.model_dump(mode="json", exclude={"verified_inputs_sha256"})
        if self.verified_inputs_sha256 != _sha256_json(core):
            raise ValueError("verified_inputs_sha256 mismatch")
        return self


class CFastExecutionQualityArtifactVerificationDTO(StrictFiniteModel):
    """One verifier's result for exact bytes read by the runtime adapter."""

    model_config = ConfigDict(
        frozen=True,
        revalidate_instances="always",
    )

    schema_version: Literal[
        "commodity_c_fast_execution_quality_artifact_verification_v1"
    ]
    artifact_role: ArtifactRole
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    valid_until_utc: datetime | None = None
    exact_contracts: tuple[str, ...] = Field(default=(), max_length=100)
    bound_artifact_raw_sha256: dict[ArtifactRole, str] = Field(default_factory=dict)
    verified_signer_domain_public_key_sha256: tuple[str, ...] = Field(
        min_length=1,
        max_length=64,
        description=(
            "Sorted SHA256 values for every raw 32-byte Ed25519 public key in "
            "the complete verified trust domain, including unused keys."
        ),
    )
    signature_verified: Literal[True]
    semantic_contract_verified: Literal[True]

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

    @field_validator("valid_until_utc")
    @classmethod
    def require_optional_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            _require_utc(value, "valid_until_utc")
        return value

    @field_validator("exact_contracts")
    @classmethod
    def require_canonical_optional_contract_set(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("exact_contracts must be sorted and unique")
        for exact_contract in value:
            exchange, separator, symbol = exact_contract.partition(".")
            if (
                separator != "."
                or not exchange.isupper()
                or not exchange.isalpha()
                or not symbol[:-4].isalpha()
                or not symbol[-4:].isdigit()
                or not (8 <= len(exact_contract) <= 32)
            ):
                raise ValueError("exact_contract is invalid")
        return value

    @field_validator("verified_signer_domain_public_key_sha256")
    @classmethod
    def require_complete_canonical_signer_domain(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_canonical_digest_domain(value)
