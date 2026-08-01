from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentDTO,
    StrictFoundationModel,
)
from app.schemas.commodity_c_fast_execution_quality_runtime import StrictFalse
from app.schemas.commodity_c_fast_execution_quality_score import (
    CFastExecutionQualityScoreDTO,
)


TargetKey = Literal["decision", "250", "1000", "5000", "30000", "60000"]
CompletionState = Literal[
    "SEALED_SELECTED_EVIDENCE",
    "SEALED_MISSING_NOT_IMPUTED",
    "PENDING_NOT_SEALED",
]
_TARGET_HORIZONS = {
    "decision": 0,
    "250": 250,
    "1000": 1_000,
    "5000": 5_000,
    "30000": 30_000,
    "60000": 60_000,
}


def _sha256_json(value: object) -> str:
    raw = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class CFastExecutionQualityTargetProjectionDTO(StrictFoundationModel):
    target_key: TargetKey
    horizon_ms: Literal[0, 250, 1_000, 5_000, 30_000, 60_000]
    completion_state: CompletionState
    evidence_record_sequence: int | None = Field(default=None, ge=1)
    evidence_record_hash: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    score_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_target(self) -> "CFastExecutionQualityTargetProjectionDTO":
        if self.horizon_ms != _TARGET_HORIZONS[self.target_key]:
            raise ValueError("target_key and horizon_ms mismatch")
        evidence_identity = (
            self.evidence_record_sequence,
            self.evidence_record_hash,
            self.score_hash,
        )
        if self.completion_state == "PENDING_NOT_SEALED":
            if any(value is not None for value in evidence_identity):
                raise ValueError("pending target must not claim evidence")
        elif any(value is None for value in evidence_identity):
            raise ValueError("sealed target must bind evidence")
        return self


class CFastExecutionQualityIntentProjectionDTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_execution_quality_intent_projection_v1"]
    preverified_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_snapshot_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    intent_record_sequence: int = Field(ge=1)
    intent_record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    anchor_record_sequence: int = Field(ge=1)
    anchor_record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    durably_created_at_utc: datetime
    intent: CFastVirtualIntentDTO
    score_policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_spec_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    targets: tuple[
        CFastExecutionQualityTargetProjectionDTO,
        CFastExecutionQualityTargetProjectionDTO,
        CFastExecutionQualityTargetProjectionDTO,
        CFastExecutionQualityTargetProjectionDTO,
        CFastExecutionQualityTargetProjectionDTO,
        CFastExecutionQualityTargetProjectionDTO,
    ]

    @field_validator("durably_created_at_utc")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise ValueError("durably_created_at_utc must use UTC")
        return value

    @model_validator(mode="after")
    def validate_intent_projection(
        self,
    ) -> "CFastExecutionQualityIntentProjectionDTO":
        if self.anchor_record_sequence <= self.intent_record_sequence:
            raise ValueError("anchor must follow intent record")
        if self.source_snapshot_receipt_sha256 != self.intent.snapshot_hash:
            raise ValueError("source snapshot receipt mismatch")
        if tuple(target.target_key for target in self.targets) != tuple(
            _TARGET_HORIZONS
        ):
            raise ValueError("target schedule must be exact and ordered")
        return self


class CFastExecutionQualityEvidenceProjectionDTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_execution_quality_evidence_projection_v1"]
    evidence_record_sequence: int = Field(ge=1)
    evidence_record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    intent_id: str = Field(pattern=r"^cfast-virtual-intent-v1-[0-9a-f]{64}$")
    target_key: TargetKey
    horizon_ms: Literal[0, 250, 1_000, 5_000, 30_000, 60_000]
    completion_state: Literal[
        "SEALED_SELECTED_EVIDENCE",
        "SEALED_MISSING_NOT_IMPUTED",
    ]
    window_end_utc: datetime
    watermark_snapshot_record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_snapshot_record_hashes: tuple[str, ...] = Field(max_length=10_000)
    score: CFastExecutionQualityScoreDTO
    evidence_state: Literal["CREATE_ONLY_FSYNCED_RESEARCH_EVIDENCE_AUTHORITY_ABSENT"]

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

    @field_validator("window_end_utc")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise ValueError("window_end_utc must use UTC")
        return value

    @field_validator("input_snapshot_record_hashes")
    @classmethod
    def require_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not isinstance(item, str)
            or len(item) != 64
            or any(character not in "0123456789abcdef" for character in item)
            for item in value
        ):
            raise ValueError("input snapshot record hash invalid")
        return value

    @model_validator(mode="after")
    def validate_evidence_projection(
        self,
    ) -> "CFastExecutionQualityEvidenceProjectionDTO":
        if self.horizon_ms != _TARGET_HORIZONS[self.target_key]:
            raise ValueError("target_key and horizon_ms mismatch")
        if self.score.intent.intent_id != self.intent_id:
            raise ValueError("score intent mismatch")
        if self.score.input_snapshot_count != len(self.input_snapshot_record_hashes):
            raise ValueError("score input snapshot count mismatch")
        expected_completion = "SEALED_SELECTED_EVIDENCE"
        if self.target_key == "decision":
            if self.score.decision_selection_state != "SELECTED_EARLIEST_ELIGIBLE":
                expected_completion = "SEALED_MISSING_NOT_IMPUTED"
        else:
            horizon = next(
                row for row in self.score.horizons if row.horizon_ms == self.horizon_ms
            )
            if horizon.selection_state != "SELECTED_EARLIEST_ELIGIBLE":
                expected_completion = "SEALED_MISSING_NOT_IMPUTED"
        if self.completion_state != expected_completion:
            raise ValueError("completion state and score mismatch")
        return self


class CFastExecutionQualityEvidenceExportDTO(StrictFoundationModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        frozen=True,
        revalidate_instances="always",
    )

    schema_version: Literal["commodity_c_fast_execution_quality_evidence_export_v1"]
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    generation_id: str = Field(pattern=r"^cfast-eq-generation-v1-[0-9a-f]{64}$")
    generation_basis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    preverified_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_snapshot_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_journal_root_path_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_journal_root_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_journal_record_count: int = Field(ge=2, le=10_000_000)
    source_journal_tip_record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    ordered_journal_record_hashes_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_contracts: tuple[str, ...] = Field(min_length=1, max_length=100)
    intent_count: int = Field(ge=1, le=10_000)
    snapshot_record_count: int = Field(ge=0, le=10_000_000)
    evidence_record_count: int = Field(ge=0, le=60_000)
    pending_target_count: int = Field(ge=0, le=60_000)
    intents: tuple[CFastExecutionQualityIntentProjectionDTO, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    evidence: tuple[CFastExecutionQualityEvidenceProjectionDTO, ...] = Field(
        max_length=60_000,
    )
    journal_window_state: Literal[
        "PENDING_TARGETS_PRESENT_LOCAL_JOURNAL_ONLY",
        "ALL_TARGETS_SEALED_LOCAL_JOURNAL_ONLY",
    ]
    source_verification_scope: Literal[
        "FRESH_REPLAY_OF_PINNED_LOCAL_CREATE_ONLY_JOURNAL_AT_EXPORT"
    ]
    self_contained_replay_state: Literal[
        "NOT_SELF_CONTAINED_REQUIRES_PINNED_SOURCE_JOURNAL"
    ]
    external_custody_anchor_state: Literal["NOT_PROVIDED_CODE_ONLY_LOCAL_JOURNAL"]
    signed_runtime_revalidation_binding_state: Literal[
        "NOT_INCLUDED_REQUIRES_RUNTIME_ADAPTER"
    ]
    real_tick_source_attestation_state: Literal[
        "NOT_INCLUDED_LOCAL_JOURNAL_CANNOT_PROVE_SOURCE"
    ]
    m2_acceptance_state: Literal["NOT_EVALUATED_REQUIRES_REAL_SIGNED_EXECUTION_WINDOW"]
    artifact_write_semantics: Literal["CREATE_ONLY_0600_FSYNC_NO_OVERWRITE"]
    execution_quality_implemented: StrictFalse
    runtime_active: StrictFalse
    real_execution_window_verified: StrictFalse
    zero_order_t2_evidence_accepted: StrictFalse
    countable_forward: StrictFalse
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
    orders_sent: Literal[0]
    positions_modified: Literal[0]
    export_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("exact_contracts")
    @classmethod
    def require_contract_set(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("exact contracts must be sorted and unique")
        return value

    @model_validator(mode="after")
    def validate_export(self) -> "CFastExecutionQualityEvidenceExportDTO":
        if self.intent_count != len(self.intents):
            raise ValueError("intent count mismatch")
        if self.evidence_record_count != len(self.evidence):
            raise ValueError("evidence count mismatch")
        if self.source_journal_record_count != (
            self.intent_count * 2
            + self.snapshot_record_count
            + self.evidence_record_count
        ):
            raise ValueError("journal record type counts do not reconcile")
        intent_ids = tuple(row.intent.intent_id for row in self.intents)
        if len(set(intent_ids)) != len(intent_ids):
            raise ValueError("duplicate intent projection")
        if any(
            row.preverified_plan_hash != self.preverified_plan_hash
            or row.source_snapshot_receipt_sha256 != self.source_snapshot_receipt_sha256
            for row in self.intents
        ):
            raise ValueError("intent source binding mismatch")
        if tuple(sorted({row.intent.exact_contract for row in self.intents})) != (
            self.exact_contracts
        ):
            raise ValueError("intent exact contract set mismatch")
        evidence_by_key = {
            (row.intent_id, row.target_key): row for row in self.evidence
        }
        if len(evidence_by_key) != len(self.evidence):
            raise ValueError("duplicate evidence projection")
        expected_order: list[tuple[str, str]] = []
        pending = 0
        for intent in self.intents:
            for target in intent.targets:
                key = (intent.intent.intent_id, target.target_key)
                evidence = evidence_by_key.get(key)
                if target.completion_state == "PENDING_NOT_SEALED":
                    pending += 1
                    if evidence is not None:
                        raise ValueError("pending target has evidence")
                else:
                    expected_order.append(key)
                    if (
                        evidence is None
                        or evidence.evidence_record_sequence
                        != target.evidence_record_sequence
                        or evidence.evidence_record_hash != target.evidence_record_hash
                        or evidence.score.score_hash != target.score_hash
                        or evidence.completion_state != target.completion_state
                    ):
                        raise ValueError("target evidence binding mismatch")
        if tuple((row.intent_id, row.target_key) for row in self.evidence) != tuple(
            expected_order
        ):
            raise ValueError("evidence order mismatch")
        if self.pending_target_count != pending:
            raise ValueError("pending target count mismatch")
        expected_window_state = (
            "PENDING_TARGETS_PRESENT_LOCAL_JOURNAL_ONLY"
            if pending
            else "ALL_TARGETS_SEALED_LOCAL_JOURNAL_ONLY"
        )
        if self.journal_window_state != expected_window_state:
            raise ValueError("journal window state mismatch")
        generation_core = {
            "schema_version": (
                "commodity_c_fast_execution_quality_generation_basis_v1"
            ),
            "source_journal_root_path_sha256": (self.source_journal_root_path_sha256),
            "source_journal_root_identity_sha256": (
                self.source_journal_root_identity_sha256
            ),
            "preverified_plan_hash": self.preverified_plan_hash,
            "source_snapshot_receipt_sha256": (self.source_snapshot_receipt_sha256),
            "exact_contracts": list(self.exact_contracts),
            "intent_record_hashes": [row.intent_record_hash for row in self.intents],
            "anchor_record_hashes": [row.anchor_record_hash for row in self.intents],
        }
        expected_generation = _sha256_json(generation_core)
        if (
            self.generation_basis_sha256 != expected_generation
            or self.generation_id != f"cfast-eq-generation-v1-{expected_generation}"
        ):
            raise ValueError("generation binding mismatch")
        expected_hash = _sha256_json(
            self.model_dump(mode="json", exclude={"export_sha256"})
        )
        if self.export_sha256 != expected_hash:
            raise ValueError("export_sha256 mismatch")
        return self
