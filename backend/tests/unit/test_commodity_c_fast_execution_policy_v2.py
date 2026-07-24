from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import app.services.commodity_c_fast_execution_policy as execution_policy_service
from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionPolicyFreezeDTO,
    CFastExecutionPolicyFreezeReceiptV2DTO,
    CFastExecutionPolicyFreezeV2DTO,
)
from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentPolicyDTO,
)
from app.services.commodity_c_fast_execution_policy import (
    CFastExecutionPolicyFreezeError,
    PLACEHOLDER_SIGNATURE,
    execution_policy_freeze_sha256,
    execution_policy_freeze_v2_sha256,
    parse_execution_policy_freeze_v2_json,
    parse_unsigned_execution_policy_freeze_artifact_json,
    unsigned_execution_policy_freeze_payload,
    unsigned_execution_policy_freeze_v2_payload,
    verify_execution_policy_freeze_v2,
    verify_execution_policy_freeze_v2_raw_chain_files,
)
from app.services.commodity_c_fast_shadow_common import (
    canonical_json,
    sha256_json,
)


def _foundation_policy() -> CFastVirtualIntentPolicyDTO:
    return CFastVirtualIntentPolicyDTO(
        schema_version="commodity_c_fast_virtual_intent_policy_v1",
        policy_id="c-fast-execution-quality-policy-v1",
        max_child_order_lots=3,
        horizon_schedule_ms=(250, 1_000, 5_000, 30_000, 60_000),
        decision_book_levels=5,
        protected_price_rule="DEFERRED_TO_DECISION_SNAPSHOT",
        passive_fill_mode="BOUNDS_ONLY_NO_POINT_PROBABILITY",
        policy_authority_state=("UNSIGNED_FOUNDATION_INPUT_REQUIRES_SEPARATE_FREEZE"),
        foundation_only=True,
        collection_authorized=False,
        authority_granted=False,
        dispatch_allowed=False,
        replacement_allowed=False,
        production_allowed=False,
    )


def _unsigned_v1_payload() -> dict:
    policy = _foundation_policy()
    return {
        "schema_version": "commodity_c_fast_execution_policy_freeze_v1",
        "freeze_id": "c-fast-policy-freeze-20260724-v1",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "policy_scope": "EXECUTION_QUALITY_SHADOW_FOUNDATION_ONLY",
        "policy": policy.model_dump(mode="json"),
        "policy_hash": sha256_json(policy.model_dump(mode="json")),
        "frozen_at_utc": "2026-07-24T15:30:00Z",
        "reviewer_role": "human_execution_policy_reviewer",
        "human_reviewed": True,
        "policy_frozen": True,
        "protected_price_rule_state": "DEFERRED_NOT_COLLECTION_READY",
        "p0_pass_required_before_collection": True,
        "foundation_only": True,
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "replacement_allowed": False,
        "production_allowed": False,
        "signer_key_id": "c-fast-policy-freeze-signer-1",
    }


def _sign_v1(
    payload: dict,
    private_key: Ed25519PrivateKey,
) -> CFastExecutionPolicyFreezeDTO:
    draft = CFastExecutionPolicyFreezeDTO.model_validate(
        {**payload, "signature": PLACEHOLDER_SIGNATURE}
    )
    signature = private_key.sign(
        canonical_json(unsigned_execution_policy_freeze_payload(draft))
    )
    return CFastExecutionPolicyFreezeDTO.model_validate(
        {
            **payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    )


def _signed_model_raw(
    freeze: CFastExecutionPolicyFreezeDTO | CFastExecutionPolicyFreezeV2DTO,
) -> bytes:
    return json.dumps(
        freeze.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _collection_policy(parent: CFastExecutionPolicyFreezeDTO) -> dict:
    return {
        "schema_version": ("commodity_c_fast_execution_quality_collection_policy_v2"),
        "policy_id": "c-fast-execution-quality-collection-policy-v2",
        "foundation_policy_hash": parent.policy_hash,
        "decision_book_levels": 5,
        "horizon_schedule_ms": [250, 1_000, 5_000, 30_000, 60_000],
        "protected_price": {
            "schema_version": ("commodity_c_fast_protected_price_counterfactual_v2"),
            "reference_quote": "SAME_TICK_OPPOSITE_BEST_QUOTE",
            "buy_formula": "ASK_PRICE_1_TICKS_PLUS_ONE",
            "sell_formula": "BID_PRICE_1_TICKS_MINUS_ONE",
            "price_tick_source": "SIGNED_SNAPSHOT_CONTRACT_SPEC",
            "numeric_representation": "DECIMAL_STRING_TO_EXACT_INTEGER_TICKS",
            "tick_grid_rule": (
                "DECIMAL_PRICE_DIVIDED_BY_DECIMAL_PRICE_TICK_MUST_BE_AN_INTEGER"
            ),
            "rendering_rule": (
                "SIGNED_INTEGER_TICKS_MULTIPLIED_BY_DECIMAL_PRICE_TICK_NO_BINARY_FLOAT"
            ),
            "missing_required_input_state": (
                "UNUSABLE_MISSING_OPPOSITE_BEST_OR_PRICE_TICK"
            ),
            "off_tick_input_state": "UNUSABLE_INVALID_PRICE_GRID",
            "counterfactual_only": True,
            "order_price_authorized": False,
        },
        "tick_selection": {
            "schema_version": ("commodity_c_fast_decision_horizon_selection_v2"),
            "decision_anchor": "VIRTUAL_INTENT_DURABLY_CREATED_AT_UTC",
            "decision_anchor_field": "virtual_intent.durably_created_at_utc",
            "decision_anchor_source": (
                "CREATE_ONLY_DURABLE_VIRTUAL_INTENT_RECORD_AFTER_FILE_AND_"
                "DIRECTORY_FSYNC"
            ),
            "intent_id_source": "virtual_intent.intent_id",
            "snapshot_id_source": "virtual_intent.snapshot_id",
            "received_at_field_source": "market_tick.received_at_utc",
            "exchange_timestamp_field_source": "market_tick.exchange_timestamp",
            "ingest_seq_field_source": "market_tick.ingest_seq",
            "ingest_id_field_source": "market_tick.ingest_id",
            "decision_tick_selection": (
                "EARLIEST_ELIGIBLE_TICK_WITH_RECEIVED_AT_UTC_AT_OR_AFTER_"
                "DECISION_ANCHOR"
            ),
            "decision_max_lateness_ms": 1_000,
            "decision_window_endpoints": (
                "RECEIVED_AT_UTC_GREATER_THAN_OR_EQUAL_TO_ANCHOR_AND_LESS_THAN_"
                "OR_EQUAL_TO_ANCHOR_PLUS_1000MS"
            ),
            "horizon_target_basis": "DECISION_ANCHOR_PLUS_HORIZON_MS",
            "horizon_tick_selection": (
                "EARLIEST_ELIGIBLE_TICK_AT_OR_AFTER_HORIZON_TARGET"
            ),
            "horizon_max_lateness_ms": 1_000,
            "horizon_window_endpoints": (
                "RECEIVED_AT_UTC_GREATER_THAN_OR_EQUAL_TO_TARGET_AND_LESS_THAN_"
                "OR_EQUAL_TO_TARGET_PLUS_1000MS"
            ),
            "eligible_tick_definition": (
                "POSITIVE_L1_ON_GRID_NOT_STALE_OR_CROSSED_"
                "LOCKED_AND_L1_ONLY_ALLOWED_DEGRADED"
            ),
            "tie_break_fields": [
                "received_at_utc",
                "exchange_timestamp",
                "ingest_seq",
                "ingest_id",
            ],
            "duplicate_ingest_rule": (
                "SAME_INGEST_ID_OR_SAME_CONTRACT_TIMESTAMP_AND_"
                "INGEST_SEQ_IS_ONE_EVENT_FIRST_CANONICAL_ROW_ONLY"
            ),
            "prior_quote_carry_forward_allowed": False,
            "missing_tick_state": "MISSING_HORIZON_NOT_IMPUTED",
        },
        "book_quality": {
            "schema_version": "commodity_c_fast_book_quality_rules_v2",
            "stale_age_basis": ("RECEIVED_AT_UTC_MINUS_EXCHANGE_TIMESTAMP"),
            "stale_after_ms": 2_000,
            "stale_boundary_rule": ("AGE_MS_GREATER_THAN_OR_EQUAL_TO_2000_IS_STALE"),
            "negative_age_state": "UNUSABLE_CLOCK_ORDER_INVALID",
            "stale_state": "UNUSABLE_STALE_NO_PRICE_OR_FILL_METRICS",
            "crossed_definition": ("BID_PRICE_1_GREATER_THAN_ASK_PRICE_1"),
            "crossed_state": "UNUSABLE_CROSSED_BOOK",
            "locked_definition": "BID_PRICE_1_EQUALS_ASK_PRICE_1",
            "locked_state": ("DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS"),
            "l1_usable_definition": (
                "POSITIVE_BID1_ASK1_SIZE1_ON_TICK_GRID_AND_BID1_LESS_THAN_ASK1"
            ),
            "l5_usable_definition": (
                "ALL_L1_TO_L5_PRICES_ON_GRID_ALL_SIZES_POSITIVE_MONOTONIC_AND_UNCROSSED"
            ),
            "all_level_price_grid_required": True,
            "price_grid_numeric_representation": (
                "DECIMAL_STRING_TO_EXACT_INTEGER_TICKS_NO_BINARY_FLOAT"
            ),
            "price_grid_definition": (
                "EACH_L1_TO_L5_PRICE_DIVIDED_BY_SIGNED_DECIMAL_PRICE_TICK_"
                "MUST_BE_AN_INTEGER"
            ),
            "l5_monotonic_rule": (
                "BID1_GT_BID2_GT_BID3_GT_BID4_GT_BID5_"
                "AND_ASK1_LT_ASK2_LT_ASK3_LT_ASK4_LT_ASK5"
            ),
            "quality_precedence": [
                "UNUSABLE_CLOCK_ORDER_INVALID",
                "UNUSABLE_STALE_NO_PRICE_OR_FILL_METRICS",
                "UNUSABLE_CROSSED_BOOK",
                "DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS",
                "UNUSABLE_NO_EXECUTION_METRICS",
                "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO",
                "L5_USABLE",
            ],
            "unusable_metric_mask": "QUALITY_STATE_AND_DIAGNOSTICS_ONLY",
            "locked_metric_mask": "MARKOUT_ONLY",
            "l1_only_metric_mask": (
                "SPREAD_PROTECTED_PRICE_COUNTERFACTUAL_MARKOUT_AND_L1_COVERAGE_ONLY"
            ),
            "l5_usable_metric_mask": (
                "SPREAD_PROTECTED_PRICE_COUNTERFACTUAL_MARKOUT_L1_COVERAGE_"
                "AND_L5_BOOK_WALK"
            ),
            "missing_l1_state": "UNUSABLE_NO_EXECUTION_METRICS",
            "missing_or_invalid_l2_l5_state": (
                "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO"
            ),
            "degraded_horizon_rule": (
                "RECORD_ONLY_STATE_ALLOWED_OBSERVED_METRICS_WITHOUT_IMPUTATION"
            ),
            "absent_level_synthesis_allowed": False,
            "optimistic_l1_to_l5_fallback_allowed": False,
        },
        "passive_fill_bounds": {
            "schema_version": "commodity_c_fast_passive_fill_bounds_v2",
            "output_mode": "LOWER_UPPER_BOUNDS_ONLY",
            "passive_buy_limit": "BID_PRICE_1_AT_DECISION_TICK",
            "passive_sell_limit": "ASK_PRICE_1_AT_DECISION_TICK",
            "buy_at_or_through_direction": (
                "SELL_AGGRESSOR_VOLUME_AT_PRICE_LESS_THAN_OR_EQUAL_TO_BUY_LIMIT"
            ),
            "sell_at_or_through_direction": (
                "BUY_AGGRESSOR_VOLUME_AT_PRICE_GREATER_THAN_OR_EQUAL_TO_SELL_LIMIT"
            ),
            "observation_interval": (
                "DECISION_TICK_EXCLUSIVE_TO_SELECTED_HORIZON_TICK_INCLUSIVE"
            ),
            "volume_unit": "EXCHANGE_CUMULATIVE_VOLUME_DELTA_RAW_UNITS",
            "volume_unit_binding_rule": (
                "SIGNED_CONTRACT_SPEC_MUST_BIND_ONE_RAW_VOLUME_UNIT_TO_CONTRACT_"
                "LOTS_ELSE_UNIDENTIFIED"
            ),
            "lower_bound_rule": (
                "ZERO_WITHOUT_IDENTIFIABLE_ORDER_QUEUE_AND_EXCHANGE_FILL"
            ),
            "upper_bound_rule": (
                "MIN_ONE_ALL_POSITIVE_INTERVAL_VOLUME_DELTA_IN_BOUND_CONTRACT_"
                "LOTS_DIVIDED_BY_ORDER_LOTS"
            ),
            "queue_ahead_assumption": (
                "ALL_DISPLAYED_SAME_SIDE_SIZE_IS_AHEAD_AT_DECISION"
            ),
            "cancellation_treatment": (
                "NO_CANCELLATION_CREDIT_TO_LOWER_FULL_CREDIT_ONLY_TO_UPPER"
            ),
            "aggregate_direction_attribution": (
                "UNAVAILABLE_FROM_SAMPLED_AGGREGATED_CTP_L1_L5"
            ),
            "price_conditioned_bound_state": (
                "UNIDENTIFIED_AGGREGATED_LAST_PRICE_CANNOT_PROVE_AGGRESSOR_"
                "DIRECTION_OR_AT_OR_THROUGH_VOLUME"
            ),
            "ambiguous_or_reset_volume_state": ("UNIDENTIFIED_BOUNDS_NOT_ZERO_OR_FULL"),
            "locked_crossed_stale_or_l1_only_state": (
                "UNIDENTIFIED_NO_PASSIVE_FILL_BOUNDS"
            ),
            "point_probability_output": "FORBIDDEN",
            "bounds_only": True,
            "calibrated_point_probability_allowed": False,
        },
        "policy_authority_state": (
            "SIGNED_RULES_COMPLETE_REQUIRES_SEPARATE_P0_AND_COLLECTION_RELEASE"
        ),
        "policy_rule_completeness": ("COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT"),
        "counterfactual_only": True,
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dynamic_selection_allowed": False,
        "automatic_promotion_authorized": False,
        "database_mutation_authorized": False,
        "deployment_mutation_authorized": False,
        "replacement_allowed": False,
        "production_allowed": False,
    }


def _unsigned_v2_payload(
    parent: CFastExecutionPolicyFreezeDTO,
    *,
    parent_raw: bytes | None = None,
) -> dict:
    policy = _collection_policy(parent)
    parent_raw = parent_raw if parent_raw is not None else _signed_model_raw(parent)
    return {
        "schema_version": "commodity_c_fast_execution_policy_freeze_v2",
        "freeze_id": "c-fast-policy-freeze-20260725-v2",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "policy_scope": ("EXECUTION_QUALITY_COLLECTION_READY_OFFLINE_POLICY_ONLY"),
        "supersedes_schema_version": ("commodity_c_fast_execution_policy_freeze_v1"),
        "supersedes_freeze_id": parent.freeze_id,
        "supersedes_freeze_sha256": execution_policy_freeze_sha256(parent),
        "supersedes_freeze_raw_sha256": hashlib.sha256(parent_raw).hexdigest(),
        "superseded_policy_hash": parent.policy_hash,
        "policy": policy,
        "policy_hash": sha256_json(policy),
        "frozen_at_utc": "2026-07-25T01:30:00Z",
        "reviewer_role": "human_execution_policy_reviewer",
        "human_reviewed": True,
        "policy_frozen": True,
        "policy_rule_completeness": ("COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT"),
        "p0_pass_required_before_collection": True,
        "separate_collection_release_required": True,
        "offline_policy_only": True,
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "dynamic_selection_allowed": False,
        "automatic_promotion_authorized": False,
        "database_mutation_authorized": False,
        "deployment_mutation_authorized": False,
        "replacement_allowed": False,
        "production_allowed": False,
        "signer_key_id": "c-fast-policy-freeze-signer-1",
    }


def _sign_v2(
    payload: dict,
    private_key: Ed25519PrivateKey,
) -> CFastExecutionPolicyFreezeV2DTO:
    draft = CFastExecutionPolicyFreezeV2DTO.model_validate(
        {**payload, "signature": PLACEHOLDER_SIGNATURE}
    )
    signature = private_key.sign(
        canonical_json(unsigned_execution_policy_freeze_v2_payload(draft))
    )
    return CFastExecutionPolicyFreezeV2DTO.model_validate(
        {
            **payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    )


def _trusted_keys(private_key: Ed25519PrivateKey) -> dict:
    encoded = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return {
        "c-fast-policy-freeze-signer-1": {
            "public_key_base64": encoded,
            "purpose": "execution_quality_policy_freeze_signer",
        }
    }


def _trusted_keys_pin(private_key: Ed25519PrivateKey) -> str:
    return sha256_json(_trusted_keys(private_key))


def _verify_chain(
    child: CFastExecutionPolicyFreezeV2DTO,
    parent: CFastExecutionPolicyFreezeDTO,
    private_key: Ed25519PrivateKey,
    *,
    child_raw: bytes | None = None,
    parent_raw: bytes | None = None,
) -> CFastExecutionPolicyFreezeReceiptV2DTO:
    return verify_execution_policy_freeze_v2(
        child_raw if child_raw is not None else _signed_model_raw(child),
        superseded_freeze_raw=(
            parent_raw if parent_raw is not None else _signed_model_raw(parent)
        ),
        trusted_public_keys=_trusted_keys(private_key),
        expected_trusted_public_keys_sha256=_trusted_keys_pin(private_key),
    )


def _signed_chain() -> tuple[
    Ed25519PrivateKey,
    CFastExecutionPolicyFreezeDTO,
    CFastExecutionPolicyFreezeV2DTO,
]:
    private_key = Ed25519PrivateKey.generate()
    parent = _sign_v1(_unsigned_v1_payload(), private_key)
    child = _sign_v2(_unsigned_v2_payload(parent), private_key)
    return private_key, parent, child


def test_v2_verifies_signed_v1_ancestry_and_returns_no_authority() -> None:
    private_key, parent, child = _signed_chain()

    receipt = _verify_chain(child, parent, private_key)

    assert isinstance(receipt, CFastExecutionPolicyFreezeReceiptV2DTO)
    assert receipt.freeze_sha256 == execution_policy_freeze_v2_sha256(child)
    assert (
        receipt.freeze_raw_sha256
        == hashlib.sha256(_signed_model_raw(child)).hexdigest()
    )
    assert receipt.supersedes_freeze_sha256 == (execution_policy_freeze_sha256(parent))
    assert (
        receipt.supersedes_freeze_raw_sha256
        == hashlib.sha256(_signed_model_raw(parent)).hexdigest()
    )
    assert receipt.signature_verified is True
    assert receipt.ancestry_signature_verified is True
    assert receipt.policy_rule_completeness == (
        "COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT"
    )
    assert receipt.receipt_authority_state == (
        "NON_AUTHORITATIVE_REVERIFY_RAW_SIGNED_FREEZES"
    )
    assert receipt.collection_authorized is False
    assert receipt.runtime_activation_authorized is False
    assert receipt.authority_granted is False
    assert receipt.dispatch_allowed is False
    assert receipt.order_authorized is False
    assert receipt.position_mutation_authorized is False
    assert receipt.dynamic_selection_allowed is False
    assert receipt.automatic_promotion_authorized is False
    assert receipt.database_mutation_authorized is False
    assert receipt.deployment_mutation_authorized is False
    assert receipt.replacement_allowed is False
    assert receipt.production_allowed is False


def test_v2_freezes_concrete_counterfactual_and_bounds_rules() -> None:
    _private_key, _parent, child = _signed_chain()
    policy = child.policy

    assert policy.protected_price.numeric_representation == (
        "DECIMAL_STRING_TO_EXACT_INTEGER_TICKS"
    )
    assert policy.tick_selection.decision_anchor == (
        "VIRTUAL_INTENT_DURABLY_CREATED_AT_UTC"
    )
    assert policy.tick_selection.horizon_window_endpoints.endswith(
        "LESS_THAN_OR_EQUAL_TO_TARGET_PLUS_1000MS"
    )
    assert policy.tick_selection.tie_break_fields == (
        "received_at_utc",
        "exchange_timestamp",
        "ingest_seq",
        "ingest_id",
    )
    assert policy.book_quality.crossed_state == "UNUSABLE_CROSSED_BOOK"
    assert policy.book_quality.missing_or_invalid_l2_l5_state == (
        "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO"
    )
    assert policy.book_quality.optimistic_l1_to_l5_fallback_allowed is False
    assert policy.book_quality.all_level_price_grid_required is True
    assert policy.book_quality.stale_boundary_rule == (
        "AGE_MS_GREATER_THAN_OR_EQUAL_TO_2000_IS_STALE"
    )
    assert policy.book_quality.quality_precedence[0] == ("UNUSABLE_CLOCK_ORDER_INVALID")
    assert policy.passive_fill_bounds.output_mode == "LOWER_UPPER_BOUNDS_ONLY"
    assert policy.passive_fill_bounds.passive_buy_limit == (
        "BID_PRICE_1_AT_DECISION_TICK"
    )
    assert policy.passive_fill_bounds.passive_sell_limit == (
        "ASK_PRICE_1_AT_DECISION_TICK"
    )
    assert policy.passive_fill_bounds.price_conditioned_bound_state.startswith(
        "UNIDENTIFIED_"
    )
    assert policy.passive_fill_bounds.point_probability_output == "FORBIDDEN"
    assert policy.passive_fill_bounds.calibrated_point_probability_allowed is False


@pytest.mark.parametrize(
    "field",
    [
        "collection_authorized",
        "runtime_activation_authorized",
        "authority_granted",
        "dispatch_allowed",
        "order_authorized",
        "position_mutation_authorized",
        "dynamic_selection_allowed",
        "automatic_promotion_authorized",
        "database_mutation_authorized",
        "deployment_mutation_authorized",
        "replacement_allowed",
        "production_allowed",
    ],
)
def test_v2_envelope_cannot_enable_any_authority(field: str) -> None:
    _private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    payload[field] = True

    with pytest.raises(ValidationError):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


@pytest.mark.parametrize(
    "field",
    [
        "collection_authorized",
        "runtime_activation_authorized",
        "authority_granted",
        "dispatch_allowed",
        "order_authorized",
        "position_mutation_authorized",
        "dynamic_selection_allowed",
        "automatic_promotion_authorized",
        "database_mutation_authorized",
        "deployment_mutation_authorized",
        "replacement_allowed",
        "production_allowed",
    ],
)
def test_v2_policy_cannot_enable_any_authority(field: str) -> None:
    _private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    payload["policy"][field] = True

    with pytest.raises(ValidationError):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


def test_v2_policy_cannot_enable_point_probability() -> None:
    _private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    payload["policy"]["passive_fill_bounds"]["calibrated_point_probability_allowed"] = (
        True
    )
    with pytest.raises(ValidationError):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


def test_v2_rejects_extra_point_estimate_and_mutable_rule_literals() -> None:
    _private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    payload["policy"]["passive_fill_bounds"]["fill_probability"] = 0.5
    payload["policy_hash"] = sha256_json(payload["policy"])

    with pytest.raises(ValidationError):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )

    payload = _unsigned_v2_payload(parent)
    payload["policy"]["book_quality"]["stale_after_ms"] = 3_000
    payload["policy_hash"] = sha256_json(payload["policy"])
    with pytest.raises(ValidationError):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


def test_v2_rejects_policy_hash_mismatch_and_non_utc_freeze() -> None:
    _private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    payload["policy_hash"] = "0" * 64
    with pytest.raises(ValidationError, match="policy_hash mismatch"):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )

    payload = _unsigned_v2_payload(parent)
    payload["frozen_at_utc"] = "2026-07-25T09:30:00+08:00"
    with pytest.raises(ValidationError, match="must use UTC"):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("policy", "decision_book_levels"), 5.0),
        (("policy", "tick_selection", "decision_max_lateness_ms"), 1_000.0),
        (("policy", "book_quality", "stale_after_ms"), 2_000.0),
        (("policy", "collection_authorized"), 0.0),
    ],
)
def test_v2_before_validators_reject_float_literals(
    path: tuple[str, ...],
    replacement: float,
) -> None:
    _private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    target = payload
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = replacement
    payload["policy_hash"] = sha256_json(payload["policy"])

    with pytest.raises(ValidationError, match="binary float"):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


@pytest.mark.parametrize(
    "schedule",
    [
        [1_000, 250, 5_000, 30_000, 60_000],
        [250, 1_000, 5_000, 30_000],
        [250, 1_000, 5_000, 30_000, 30_000],
        [250.0, 1_000, 5_000, 30_000, 60_000],
    ],
)
def test_v2_before_validator_rejects_non_exact_schedule(schedule: list) -> None:
    _private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    payload["policy"]["horizon_schedule_ms"] = schedule
    payload["policy_hash"] = sha256_json(payload["policy"])

    with pytest.raises(
        ValidationError,
        match="exact ordered integer schedule|binary float",
    ):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


@pytest.mark.parametrize("numeric_timestamp", [0, 1_721_862_600, 1_721_862_600.0])
def test_v2_before_validator_rejects_numeric_timestamp(
    numeric_timestamp: int | float,
) -> None:
    _private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    payload["frozen_at_utc"] = numeric_timestamp

    with pytest.raises(ValidationError, match="must not be a numeric timestamp"):
        CFastExecutionPolicyFreezeV2DTO.model_validate(
            {**payload, "signature": PLACEHOLDER_SIGNATURE}
        )


@pytest.mark.parametrize(
    ("field", "replacement", "error_code"),
    [
        (
            "supersedes_freeze_id",
            "c-fast-policy-freeze-unrelated-v1",
            "SUPERSEDED_FREEZE_ID_MISMATCH",
        ),
        (
            "supersedes_freeze_sha256",
            "0" * 64,
            "SUPERSEDED_FREEZE_HASH_MISMATCH",
        ),
        (
            "supersedes_freeze_raw_sha256",
            "0" * 64,
            "SUPERSEDED_FREEZE_RAW_HASH_MISMATCH",
        ),
    ],
)
def test_v2_wrong_ancestry_fails_closed(
    field: str,
    replacement: str,
    error_code: str,
) -> None:
    private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    payload[field] = replacement
    child = _sign_v2(payload, private_key)

    with pytest.raises(CFastExecutionPolicyFreezeError, match=error_code):
        _verify_chain(child, parent, private_key)


def test_v2_wrong_superseded_policy_hash_fails_closed() -> None:
    private_key, parent, _child = _signed_chain()
    payload = _unsigned_v2_payload(parent)
    payload["superseded_policy_hash"] = "0" * 64
    payload["policy"]["foundation_policy_hash"] = "0" * 64
    payload["policy_hash"] = sha256_json(payload["policy"])
    child = _sign_v2(payload, private_key)

    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="SUPERSEDED_POLICY_HASH_MISMATCH",
    ):
        _verify_chain(child, parent, private_key)


def test_v2_reverifies_parent_signature_and_child_signature() -> None:
    private_key, parent, child = _signed_chain()
    broken_parent = parent.model_copy(
        update={"signature": base64.b64encode(bytes(64)).decode("ascii")}
    )
    with pytest.raises(CFastExecutionPolicyFreezeError, match="SIGNATURE_INVALID"):
        _verify_chain(child, broken_parent, private_key)

    tampered = copy.deepcopy(child.model_dump(mode="json"))
    tampered["policy"]["tick_selection"]["horizon_max_lateness_ms"] = 999
    with pytest.raises(ValidationError):
        CFastExecutionPolicyFreezeV2DTO.model_validate(tampered)

    tampered = copy.deepcopy(child.model_dump(mode="json"))
    tampered["frozen_at_utc"] = "2026-07-25T02:00:00Z"
    self_consistent = CFastExecutionPolicyFreezeV2DTO.model_validate(tampered)
    with pytest.raises(CFastExecutionPolicyFreezeError, match="SIGNATURE_INVALID"):
        _verify_chain(self_consistent, parent, private_key)


def test_v2_raw_chain_rejects_reserialized_parent_even_when_signature_is_valid() -> (
    None
):
    private_key, parent, _child = _signed_chain()
    original_parent_raw = _signed_model_raw(parent)
    payload = _unsigned_v2_payload(parent, parent_raw=original_parent_raw)
    child = _sign_v2(payload, private_key)
    reserialized_parent_raw = json.dumps(
        parent.model_dump(mode="json"),
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")
    assert reserialized_parent_raw != original_parent_raw

    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="SUPERSEDED_FREEZE_RAW_HASH_MISMATCH",
    ):
        _verify_chain(
            child,
            parent,
            private_key,
            parent_raw=reserialized_parent_raw,
        )


def test_v2_raw_chain_requires_exact_bytes_and_pinned_keyring() -> None:
    private_key, parent, child = _signed_chain()

    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="RAW_FREEZE_BYTES_REQUIRED",
    ):
        verify_execution_policy_freeze_v2(
            _signed_model_raw(child).decode("utf-8"),  # type: ignore[arg-type]
            superseded_freeze_raw=_signed_model_raw(parent),
            trusted_public_keys=_trusted_keys(private_key),
            expected_trusted_public_keys_sha256=_trusted_keys_pin(private_key),
        )

    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="TRUSTED_KEYRING_PIN_MISMATCH",
    ):
        verify_execution_policy_freeze_v2(
            _signed_model_raw(child),
            superseded_freeze_raw=_signed_model_raw(parent),
            trusted_public_keys=_trusted_keys(private_key),
            expected_trusted_public_keys_sha256="0" * 64,
        )


def test_v2_raw_chain_file_entry_double_reads_and_pins_keyring(
    tmp_path: Path,
) -> None:
    private_key, parent, child = _signed_chain()
    parent_path = tmp_path / "parent-v1.json"
    child_path = tmp_path / "child-v2.json"
    keyring_path = tmp_path / "trusted-keys.json"
    parent_path.write_bytes(_signed_model_raw(parent))
    child_path.write_bytes(_signed_model_raw(child))
    keyring_path.write_text(
        json.dumps(_trusted_keys(private_key), sort_keys=True),
        encoding="utf-8",
    )
    keyring_path.chmod(0o600)

    receipt = verify_execution_policy_freeze_v2_raw_chain_files(
        child_path,
        superseded_freeze_path=parent_path,
        trusted_public_keys_path=keyring_path,
        expected_trusted_public_keys_sha256=_trusted_keys_pin(private_key),
    )

    assert (
        receipt.freeze_raw_sha256 == hashlib.sha256(child_path.read_bytes()).hexdigest()
    )
    assert (
        receipt.supersedes_freeze_raw_sha256
        == hashlib.sha256(parent_path.read_bytes()).hexdigest()
    )

    symlink = tmp_path / "parent-link.json"
    symlink.symlink_to(parent_path)
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_FILE_INVALID",
    ):
        verify_execution_policy_freeze_v2_raw_chain_files(
            child_path,
            superseded_freeze_path=symlink,
            trusted_public_keys_path=keyring_path,
            expected_trusted_public_keys_sha256=_trusted_keys_pin(private_key),
        )


def test_v2_raw_chain_file_entry_detects_same_fd_content_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "freeze.json"
    target.write_bytes(b"same-length-one")
    calls = 0

    def inconsistent_read(_fd: int, _maximum_bytes: int) -> bytes:
        nonlocal calls
        calls += 1
        return b"same-length-one" if calls == 1 else b"same-length-two"

    monkeypatch.setattr(
        execution_policy_service,
        "_read_fd_bounded",
        inconsistent_read,
    )
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_FILE_CHANGED",
    ):
        execution_policy_service._read_regular_file_strict(
            target,
            maximum_bytes=64,
            require_private=False,
        )


def test_v2_strict_json_rejects_duplicate_nan_and_extra_fields() -> None:
    _private_key, _parent, child = _signed_chain()
    raw = json.dumps(child.model_dump(mode="json"), separators=(",", ":"))
    duplicate = raw.replace(
        '{"schema_version":',
        '{"freeze_id":"duplicate-freeze","schema_version":',
        1,
    )

    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_JSON_INVALID",
    ):
        parse_execution_policy_freeze_v2_json(duplicate)

    non_finite = raw.replace('"stale_after_ms":2000', '"stale_after_ms":NaN')
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_JSON_INVALID",
    ):
        parse_execution_policy_freeze_v2_json(non_finite)

    extra = child.model_dump(mode="json")
    extra["unexpected"] = True
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_V2_SCHEMA_INVALID",
    ):
        parse_execution_policy_freeze_v2_json(json.dumps(extra))


def _load_signing_script():
    script_path = (
        Path(__file__).resolve().parents[3]
        / "scripts"
        / "commodity_c_fast_execution_policy_sign.py"
    )
    spec = importlib.util.spec_from_file_location(
        "commodity_c_fast_execution_policy_sign_v2",
        script_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_private_key(
    path: Path,
    private_key: Ed25519PrivateKey,
) -> None:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_text(
        base64.b64encode(raw).decode("ascii"),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_signing_tool_preserves_v1_and_signs_v2(tmp_path: Path) -> None:
    module = _load_signing_script()
    private_key = Ed25519PrivateKey.generate()
    parent = _sign_v1(_unsigned_v1_payload(), private_key)
    key_path = tmp_path / "policy-freeze.key"
    _write_private_key(key_path, private_key)

    signed_v1, v1_hash = module.sign_policy_freeze(
        json.dumps(_unsigned_v1_payload()),
        module.load_private_key(key_path),
    )
    assert signed_v1["schema_version"].endswith("_v1")
    assert v1_hash == execution_policy_freeze_sha256(
        CFastExecutionPolicyFreezeDTO.model_validate(signed_v1)
    )

    signed_v2, v2_hash = module.sign_policy_freeze(
        json.dumps(_unsigned_v2_payload(parent)),
        module.load_private_key(key_path),
    )
    parsed = parse_execution_policy_freeze_v2_json(json.dumps(signed_v2))
    assert v2_hash == execution_policy_freeze_v2_sha256(parsed)
    receipt = _verify_chain(parsed, parent, private_key)
    assert receipt.collection_authorized is False


def test_generic_unsigned_parser_rejects_unknown_schema() -> None:
    with pytest.raises(
        CFastExecutionPolicyFreezeError,
        match="POLICY_FREEZE_SCHEMA_VERSION_UNSUPPORTED",
    ):
        parse_unsigned_execution_policy_freeze_artifact_json(
            '{"schema_version":"unknown-policy-freeze"}'
        )


def test_signing_input_symlink_and_same_fd_change_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_signing_script()
    target = tmp_path / "unsigned.json"
    target.write_text("x", encoding="utf-8")
    symlink = tmp_path / "unsigned-link.json"
    symlink.symlink_to(target)
    with pytest.raises(ValueError, match="non-symlink"):
        module._read_regular_file(symlink, maximum_bytes=64)

    calls = 0

    def inconsistent_read(_fd: int, _maximum_bytes: int) -> bytes:
        nonlocal calls
        calls += 1
        return b"x" if calls == 1 else b"y"

    monkeypatch.setattr(module, "_read_fd_bounded", inconsistent_read)
    with pytest.raises(ValueError, match="changed while it was read"):
        module._read_regular_file(target, maximum_bytes=64)
