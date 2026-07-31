from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, field_validator, model_validator

from app.schemas.commodity_c_fast_shadow import StrictFiniteModel


RevalidationTrigger = Literal["startup", "reload", "recovery"]


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


class CFastExecutionQualityRuntimeRevalidationDTO(StrictFiniteModel):
    """Result returned by the future full signed-authority verifier.

    This DTO is a capability boundary, not a verifier.  The runtime foundation
    accepts it only from a separately bound verifier and keeps all collection,
    persistence and trading authorities false.
    """

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
