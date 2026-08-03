from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from app.schemas.commodity_c_fast_execution_quality_runtime import (
    RevalidationTrigger,
    StrictFalse,
)
from app.schemas.commodity_c_fast_shadow import StrictFiniteModel


def _sha256_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class CFastExecutionQualityQuestDBReadonlyEvidenceReceiptDTO(StrictFiniteModel):
    """One lifecycle's exact read-only source and local evidence join."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
    )

    schema_version: Literal[
        "commodity_c_fast_execution_quality_questdb_readonly_receipt_v1"
    ]
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trigger: RevalidationTrigger
    verified_at_utc: datetime
    revalidation_receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_p0_acceptance_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_v6_terminal_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_v6_readonly_proof_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_contracts: tuple[str, ...] = Field(min_length=1, max_length=100)

    endpoint_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    questdb_build_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observable_readonly_metadata_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    export_generation_id: str = Field(pattern=r"^cfast-eq-generation-v1-[0-9a-f]{64}$")
    export_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    export_artifact_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_journal_record_count: int = Field(ge=2, le=10_000_000)
    source_journal_tip_record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    same_connection: Literal[True]
    readonly_principal_verified: Literal[True]
    endpoint_verified: Literal[True]
    observable_readonly_metadata_stable: Literal[True]
    query_v6_terminal_join_verified: Literal[True]
    journal_export_join_verified: Literal[True]
    select_statements_executed: Literal[4]
    write_probe_attempted: StrictFalse
    database_mutations_observed: Literal[0]
    orders_sent: Literal[0]
    positions_modified: Literal[0]

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

    @field_validator("verified_at_utc")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset().total_seconds() != 0
        ):
            raise ValueError("verified_at_utc must use UTC")
        return value

    @field_validator("exact_contracts")
    @classmethod
    def require_canonical_contracts(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value or any(
            re.fullmatch(r"[A-Z]+\.[A-Za-z]+[0-9]{3,4}", item) is None
            for item in value
        ):
            raise ValueError("exact_contracts must be canonical")
        return value

    @model_validator(mode="after")
    def require_receipt_hash(
        self,
    ) -> "CFastExecutionQualityQuestDBReadonlyEvidenceReceiptDTO":
        core = self.model_dump(mode="json", exclude={"receipt_sha256"})
        if self.receipt_sha256 != _sha256_json(core):
            raise ValueError("receipt_sha256 mismatch")
        return self


__all__ = [
    "CFastExecutionQualityQuestDBReadonlyEvidenceReceiptDTO",
]
