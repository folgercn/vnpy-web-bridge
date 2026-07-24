from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentPolicyDTO,
    StrictFoundationModel,
)


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class CFastExecutionPolicyFreezeDTO(StrictFoundationModel):
    schema_version: Literal[
        "commodity_c_fast_execution_policy_freeze_v1"
    ]
    freeze_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    policy_scope: Literal["EXECUTION_QUALITY_SHADOW_FOUNDATION_ONLY"]
    policy: CFastVirtualIntentPolicyDTO
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen_at_utc: datetime
    reviewer_role: Literal["human_execution_policy_reviewer"]
    human_reviewed: Literal[True]
    policy_frozen: Literal[True]
    protected_price_rule_state: Literal[
        "DEFERRED_NOT_COLLECTION_READY"
    ]
    p0_pass_required_before_collection: Literal[True]
    foundation_only: Literal[True]
    collection_authorized: Literal[False]
    runtime_activation_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signature: str = Field(min_length=40, max_length=256)

    @model_validator(mode="after")
    def validate_freeze_semantics(self) -> "CFastExecutionPolicyFreezeDTO":
        if (
            self.frozen_at_utc.tzinfo is None
            or self.frozen_at_utc.utcoffset() is None
            or self.frozen_at_utc.utcoffset().total_seconds() != 0
        ):
            raise ValueError("frozen_at_utc must use UTC")
        expected_policy_hash = _sha256_json(
            self.policy.model_dump(mode="json")
        )
        if self.policy_hash != expected_policy_hash:
            raise ValueError("policy_hash mismatch")
        return self


class CFastExecutionPolicyFreezeReceiptDTO(StrictFoundationModel):
    schema_version: Literal[
        "commodity_c_fast_execution_policy_freeze_receipt_v1"
    ]
    freeze_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    freeze_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    policy_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signer_key_purpose: Literal["execution_quality_policy_freeze_signer"]
    signature_verified: Literal[True]
    policy_frozen: Literal[True]
    protected_price_rule_state: Literal[
        "DEFERRED_NOT_COLLECTION_READY"
    ]
    p0_pass_required_before_collection: Literal[True]
    foundation_only: Literal[True]
    collection_authorized: Literal[False]
    runtime_activation_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]
