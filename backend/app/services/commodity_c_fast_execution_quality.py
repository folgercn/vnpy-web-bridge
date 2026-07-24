from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentDTO,
    CFastVirtualIntentPlanDTO,
    CFastVirtualIntentPolicyDTO,
    VirtualPhase,
    VirtualPositionEffect,
)
from app.schemas.commodity_c_fast_shadow import CommodityCFastShadowDTO, Product
from app.services.commodity_c_fast_shadow_common import (
    formula_target_binding_sha256,
    sha256_json,
    unsigned_snapshot_payload,
)


MAX_ABS_TARGET_QUANTITY = 500


class CFastExecutionQualityFoundationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _VirtualLeg:
    product: Product
    phase: VirtualPhase
    position_effect: VirtualPositionEffect
    exact_contract: str
    signed_quantity_delta: int


def virtual_intent_policy_hash(
    policy: CFastVirtualIntentPolicyDTO,
) -> str:
    return sha256_json(policy.model_dump(mode="json"))


def virtual_intent_plan_payload(
    plan: CFastVirtualIntentPlanDTO,
) -> dict[str, Any]:
    return plan.model_dump(mode="json", exclude={"plan_hash"})


def virtual_intent_plan_hash(
    plan: CFastVirtualIntentPlanDTO,
) -> str:
    return sha256_json(virtual_intent_plan_payload(plan))


def compile_virtual_intent_plan(
    *,
    snapshot: CommodityCFastShadowDTO,
    snapshot_hash: str,
    policy: CFastVirtualIntentPolicyDTO,
) -> CFastVirtualIntentPlanDTO:
    """Compile deterministic virtual-only intents from one signed snapshot.

    This pure foundation function neither verifies the Ed25519 signature nor
    reads market/runtime state. The caller must provide a snapshot already
    accepted by CommodityCFastShadowService. Identity and formula hashes are
    rechecked here so a receipt cannot be accidentally paired with another
    snapshot.
    """

    expected_snapshot_hash = sha256_json(unsigned_snapshot_payload(snapshot))
    if snapshot_hash != expected_snapshot_hash:
        raise CFastExecutionQualityFoundationError("SNAPSHOT_HASH_MISMATCH")
    expected_formula_hash = formula_target_binding_sha256(snapshot)
    if snapshot.formula_target_binding_sha256 != expected_formula_hash:
        raise CFastExecutionQualityFoundationError(
            "FORMULA_TARGET_BINDING_MISMATCH"
        )
    _verify_quantity_bounds(snapshot)

    policy_hash = virtual_intent_policy_hash(policy)
    legs = _build_legs(snapshot)
    intents = _compile_children(
        snapshot=snapshot,
        snapshot_hash=snapshot_hash,
        policy=policy,
        policy_hash=policy_hash,
        legs=legs,
    )
    core: dict[str, Any] = {
        "schema_version": "commodity_c_fast_virtual_intent_plan_v1",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_hash": snapshot_hash,
        "formula_target_binding_sha256": (
            snapshot.formula_target_binding_sha256
        ),
        "source_month": snapshot.source_month,
        "execution_day": snapshot.execution_day.isoformat(),
        "policy": policy.model_dump(mode="json"),
        "policy_hash": policy_hash,
        "intents": [row.model_dump(mode="json") for row in intents],
        "activation_state": "FOUNDATION_ONLY_NOT_ACTIVATABLE",
        "source_validation_scope": (
            "IDENTITY_BINDING_ONLY_CALLER_MUST_REQUIRE_ACCEPTED_SIGNED_SHADOW"
        ),
        "p0_pass_required_before_collection": True,
        "collection_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "production_allowed": False,
    }
    return CFastVirtualIntentPlanDTO.model_validate(
        {**core, "plan_hash": sha256_json(core)}
    )


def reload_and_verify_virtual_intent_plan(
    payload: Mapping[str, Any],
    *,
    accepted_snapshot: CommodityCFastShadowDTO,
    snapshot_receipt: str,
    frozen_policy: CFastVirtualIntentPolicyDTO,
) -> CFastVirtualIntentPlanDTO:
    """Reload a plan and prove derivation from current accepted inputs.

    DTO hashes only detect accidental or unsynchronised mutation.  A caller
    that can rewrite every checksum can still create a self-consistent plan,
    so persisted plans must also equal a fresh deterministic compilation from
    the accepted signed snapshot receipt and separately frozen policy.
    """

    reloaded = CFastVirtualIntentPlanDTO.model_validate(payload)
    expected = compile_virtual_intent_plan(
        snapshot=accepted_snapshot,
        snapshot_hash=snapshot_receipt,
        policy=frozen_policy,
    )
    if (
        reloaded.plan_hash != expected.plan_hash
        or reloaded.model_dump(mode="json")
        != expected.model_dump(mode="json")
    ):
        raise CFastExecutionQualityFoundationError(
            "PLAN_DERIVATION_MISMATCH"
        )
    return reloaded


def _verify_quantity_bounds(snapshot: CommodityCFastShadowDTO) -> None:
    for row in snapshot.targets:
        if (
            abs(row.previous_target_quantity) > MAX_ABS_TARGET_QUANTITY
            or abs(row.target_quantity) > MAX_ABS_TARGET_QUANTITY
        ):
            raise CFastExecutionQualityFoundationError(
                "TARGET_QUANTITY_LIMIT"
            )


def _build_legs(snapshot: CommodityCFastShadowDTO) -> tuple[_VirtualLeg, ...]:
    close_legs: list[_VirtualLeg] = []
    open_legs: list[_VirtualLeg] = []
    for row in sorted(snapshot.targets, key=lambda item: item.product):
        previous_contract = row.previous_exact_contract
        previous_quantity = row.previous_target_quantity
        target_contract = row.exact_contract
        target_quantity = row.target_quantity
        if previous_quantity and not previous_contract:
            raise CFastExecutionQualityFoundationError(
                "PREVIOUS_CONTRACT_REQUIRED"
            )
        if previous_contract and previous_contract != target_contract:
            if previous_quantity:
                close_legs.append(
                    _leg(
                        row.product,
                        "virtual_close",
                        previous_contract,
                        -previous_quantity,
                    )
                )
            if target_quantity:
                open_legs.append(
                    _leg(
                        row.product,
                        "virtual_open",
                        target_contract,
                        target_quantity,
                    )
                )
            continue

        delta = target_quantity - previous_quantity
        if delta == 0:
            continue
        if (
            previous_quantity
            and target_quantity
            and previous_quantity * target_quantity < 0
        ):
            close_legs.append(
                _leg(
                    row.product,
                    "virtual_close",
                    target_contract,
                    -previous_quantity,
                )
            )
            open_legs.append(
                _leg(
                    row.product,
                    "virtual_open",
                    target_contract,
                    target_quantity,
                )
            )
        elif (
            previous_quantity
            and abs(target_quantity) < abs(previous_quantity)
            and previous_quantity * target_quantity >= 0
        ):
            close_legs.append(
                _leg(
                    row.product,
                    "virtual_close",
                    target_contract,
                    delta,
                )
            )
        else:
            open_legs.append(
                _leg(
                    row.product,
                    "virtual_open",
                    target_contract,
                    delta,
                )
            )
    return tuple(close_legs + open_legs)


def _leg(
    product: Product,
    phase: VirtualPhase,
    exact_contract: str,
    signed_quantity_delta: int,
) -> _VirtualLeg:
    return _VirtualLeg(
        product=product,
        phase=phase,
        position_effect=(
            "reduce_previous"
            if phase == "virtual_close"
            else "establish_target"
        ),
        exact_contract=exact_contract,
        signed_quantity_delta=signed_quantity_delta,
    )


def _compile_children(
    *,
    snapshot: CommodityCFastShadowDTO,
    snapshot_hash: str,
    policy: CFastVirtualIntentPolicyDTO,
    policy_hash: str,
    legs: tuple[_VirtualLeg, ...],
) -> tuple[CFastVirtualIntentDTO, ...]:
    intents: list[CFastVirtualIntentDTO] = []
    for leg_sequence, leg in enumerate(legs, start=1):
        leg_payload = {
            "schema_version": "commodity_c_fast_virtual_leg_v1",
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_hash": snapshot_hash,
            "formula_target_binding_sha256": (
                snapshot.formula_target_binding_sha256
            ),
            "policy_hash": policy_hash,
            "product": leg.product,
            "phase": leg.phase,
            "position_effect": leg.position_effect,
            "exact_contract": leg.exact_contract,
            "signed_quantity_delta": leg.signed_quantity_delta,
            "leg_sequence": leg_sequence,
        }
        leg_id = f"cfast-virtual-leg-v1-{sha256_json(leg_payload)}"
        child_lots = _split_lots(
            abs(leg.signed_quantity_delta),
            policy.max_child_order_lots,
        )
        sign = 1 if leg.signed_quantity_delta > 0 else -1
        for child_index, lots in enumerate(child_lots, start=1):
            intent_sequence = len(intents) + 1
            signed_quantity_delta = sign * lots
            core: dict[str, Any] = {
                "schema_version": "commodity_c_fast_virtual_intent_v1",
                "leg_id": leg_id,
                "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
                "snapshot_id": snapshot.snapshot_id,
                "snapshot_hash": snapshot_hash,
                "formula_target_binding_sha256": (
                    snapshot.formula_target_binding_sha256
                ),
                "policy_hash": policy_hash,
                "product": leg.product,
                "phase": leg.phase,
                "position_effect": leg.position_effect,
                "exact_contract": leg.exact_contract,
                "direction": (
                    "buy" if signed_quantity_delta > 0 else "sell"
                ),
                "leg_sequence": leg_sequence,
                "intent_sequence": intent_sequence,
                "child_index": child_index,
                "child_count": len(child_lots),
                "leg_signed_quantity_delta": leg.signed_quantity_delta,
                "signed_quantity_delta": signed_quantity_delta,
                "lots": lots,
                "decision_timestamp_state": (
                    "NOT_CAPTURED_FOUNDATION_ONLY"
                ),
                "quote_snapshot_state": "NOT_CAPTURED_FOUNDATION_ONLY",
                "virtual_only": True,
                "collection_authorized": False,
                "authority_granted": False,
                "dispatch_allowed": False,
                "replacement_allowed": False,
                "production_allowed": False,
            }
            intents.append(
                CFastVirtualIntentDTO.model_validate(
                    {
                        **core,
                        "intent_id": (
                            "cfast-virtual-intent-v1-"
                            f"{sha256_json(core)}"
                        ),
                    }
                )
            )
    return tuple(intents)


def _split_lots(total_lots: int, maximum_lots: int) -> tuple[int, ...]:
    result: list[int] = []
    remaining = total_lots
    while remaining:
        child = min(remaining, maximum_lots)
        result.append(child)
        remaining -= child
    return tuple(result)
