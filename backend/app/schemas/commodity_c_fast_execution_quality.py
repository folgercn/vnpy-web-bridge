from __future__ import annotations

import hashlib
import json
from datetime import date
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from app.schemas.commodity_c_fast_shadow import Product, StrictFiniteModel


VirtualDirection = Literal["buy", "sell"]
VirtualPhase = Literal["virtual_close", "virtual_open"]
VirtualPositionEffect = Literal["reduce_previous", "establish_target"]
HorizonScheduleMs = tuple[
    Literal[250],
    Literal[1_000],
    Literal[5_000],
    Literal[30_000],
    Literal[60_000],
]


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class StrictFoundationModel(StrictFiniteModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        frozen=True,
    )


class CFastVirtualIntentPolicyDTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_virtual_intent_policy_v1"]
    policy_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    max_child_order_lots: int = Field(ge=1, le=100)
    horizon_schedule_ms: HorizonScheduleMs
    decision_book_levels: Literal[5]
    protected_price_rule: Literal["DEFERRED_TO_DECISION_SNAPSHOT"]
    passive_fill_mode: Literal["BOUNDS_ONLY_NO_POINT_PROBABILITY"]
    policy_authority_state: Literal[
        "UNSIGNED_FOUNDATION_INPUT_REQUIRES_SEPARATE_FREEZE"
    ]
    foundation_only: Literal[True]
    collection_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]


class CFastVirtualIntentDTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_virtual_intent_v1"]
    intent_id: str = Field(
        pattern=r"^cfast-virtual-intent-v1-[0-9a-f]{64}$"
    )
    leg_id: str = Field(pattern=r"^cfast-virtual-leg-v1-[0-9a-f]{64}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    formula_target_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    product: Product
    phase: VirtualPhase
    position_effect: VirtualPositionEffect
    exact_contract: str = Field(min_length=8, max_length=32)
    direction: VirtualDirection
    leg_sequence: int = Field(ge=1)
    intent_sequence: int = Field(ge=1)
    child_index: int = Field(ge=1)
    child_count: int = Field(ge=1)
    leg_signed_quantity_delta: int
    signed_quantity_delta: int
    lots: int = Field(ge=1)
    decision_timestamp_state: Literal["NOT_CAPTURED_FOUNDATION_ONLY"]
    quote_snapshot_state: Literal["NOT_CAPTURED_FOUNDATION_ONLY"]
    virtual_only: Literal[True]
    collection_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]

    @model_validator(mode="after")
    def validate_virtual_semantics(self) -> "CFastVirtualIntentDTO":
        if self.signed_quantity_delta == 0:
            raise ValueError("signed_quantity_delta must be non-zero")
        if self.leg_signed_quantity_delta == 0:
            raise ValueError("leg_signed_quantity_delta must be non-zero")
        if self.lots != abs(self.signed_quantity_delta):
            raise ValueError("lots must equal abs(signed_quantity_delta)")
        expected_direction = (
            "buy" if self.signed_quantity_delta > 0 else "sell"
        )
        if self.direction != expected_direction:
            raise ValueError("direction must match signed_quantity_delta")
        if self.signed_quantity_delta * self.leg_signed_quantity_delta <= 0:
            raise ValueError("child direction must match leg direction")
        expected_effect = (
            "reduce_previous"
            if self.phase == "virtual_close"
            else "establish_target"
        )
        if self.position_effect != expected_effect:
            raise ValueError("position_effect must match phase")
        if self.child_index > self.child_count:
            raise ValueError("child_index must not exceed child_count")
        leg_payload = {
            "schema_version": "commodity_c_fast_virtual_leg_v1",
            "snapshot_id": self.snapshot_id,
            "snapshot_hash": self.snapshot_hash,
            "formula_target_binding_sha256": (
                self.formula_target_binding_sha256
            ),
            "policy_hash": self.policy_hash,
            "product": self.product,
            "phase": self.phase,
            "position_effect": self.position_effect,
            "exact_contract": self.exact_contract,
            "signed_quantity_delta": self.leg_signed_quantity_delta,
            "leg_sequence": self.leg_sequence,
        }
        expected_leg_id = (
            f"cfast-virtual-leg-v1-{_sha256_json(leg_payload)}"
        )
        if self.leg_id != expected_leg_id:
            raise ValueError("leg_id hash mismatch")
        intent_payload = self.model_dump(mode="json", exclude={"intent_id"})
        expected_intent_id = (
            f"cfast-virtual-intent-v1-{_sha256_json(intent_payload)}"
        )
        if self.intent_id != expected_intent_id:
            raise ValueError("intent_id hash mismatch")
        return self


class CFastVirtualIntentPlanDTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_virtual_intent_plan_v1"]
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    formula_target_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_month: str = Field(pattern=r"^\d{4}-\d{2}$")
    execution_day: date
    policy: CFastVirtualIntentPolicyDTO
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    intents: tuple[CFastVirtualIntentDTO, ...] = Field(max_length=10_000)
    activation_state: Literal["FOUNDATION_ONLY_NOT_ACTIVATABLE"]
    source_validation_scope: Literal[
        "IDENTITY_BINDING_ONLY_CALLER_MUST_REQUIRE_ACCEPTED_SIGNED_SHADOW"
    ]
    p0_pass_required_before_collection: Literal[True]
    collection_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]

    @model_validator(mode="after")
    def validate_plan_semantics(self) -> "CFastVirtualIntentPlanDTO":
        expected_policy_hash = _sha256_json(
            self.policy.model_dump(mode="json")
        )
        if self.policy_hash != expected_policy_hash:
            raise ValueError("policy_hash mismatch")
        if any(
            row.snapshot_id != self.snapshot_id
            or row.snapshot_hash != self.snapshot_hash
            or row.formula_target_binding_sha256
            != self.formula_target_binding_sha256
            or row.policy_hash != self.policy_hash
            for row in self.intents
        ):
            raise ValueError("intent binding must match plan binding")
        sequences = [row.intent_sequence for row in self.intents]
        if sequences != list(range(1, len(self.intents) + 1)):
            raise ValueError("intent_sequence must be contiguous and ordered")
        phases = [row.phase for row in self.intents]
        if "virtual_open" in phases:
            first_open = phases.index("virtual_open")
            if any(phase == "virtual_close" for phase in phases[first_open:]):
                raise ValueError("all virtual_close intents must precede opens")
        if len({row.intent_id for row in self.intents}) != len(self.intents):
            raise ValueError("intent_id must be unique")
        leg_ids = list(dict.fromkeys(row.leg_id for row in self.intents))
        leg_sequences = list(
            dict.fromkeys(row.leg_sequence for row in self.intents)
        )
        if leg_sequences != list(range(1, len(leg_ids) + 1)):
            raise ValueError("leg_sequence must be contiguous and ordered")
        for leg_id in leg_ids:
            children = [row for row in self.intents if row.leg_id == leg_id]
            first = children[0]
            expected_count = first.child_count
            if len(children) != expected_count:
                raise ValueError("leg child_count does not match children")
            if [row.child_index for row in children] != list(
                range(1, expected_count + 1)
            ):
                raise ValueError("leg child_index must be contiguous")
            if any(
                row.product != first.product
                or row.phase != first.phase
                or row.position_effect != first.position_effect
                or row.exact_contract != first.exact_contract
                or row.direction != first.direction
                or row.leg_sequence != first.leg_sequence
                or row.child_count != first.child_count
                or row.leg_signed_quantity_delta
                != first.leg_signed_quantity_delta
                for row in children
            ):
                raise ValueError("children in one leg must share leg binding")
            if any(
                row.lots > self.policy.max_child_order_lots
                for row in children
            ):
                raise ValueError("child lots exceed policy maximum")
            if (
                sum(row.signed_quantity_delta for row in children)
                != first.leg_signed_quantity_delta
            ):
                raise ValueError("child quantities must reconstruct leg")
        plan_payload = self.model_dump(mode="json", exclude={"plan_hash"})
        if self.plan_hash != _sha256_json(plan_payload):
            raise ValueError("plan_hash mismatch")
        return self
