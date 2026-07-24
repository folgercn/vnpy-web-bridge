from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentPolicyDTO,
    HorizonScheduleMs,
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


def _reject_float_literals(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("binary float JSON literals are forbidden")
    if isinstance(value, dict):
        for item in value.values():
            _reject_float_literals(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_float_literals(item)


class CFastExecutionPolicyFreezeDTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_execution_policy_freeze_v1"]
    freeze_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    policy_scope: Literal["EXECUTION_QUALITY_SHADOW_FOUNDATION_ONLY"]
    policy: CFastVirtualIntentPolicyDTO
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen_at_utc: datetime
    reviewer_role: Literal["human_execution_policy_reviewer"]
    human_reviewed: Literal[True]
    policy_frozen: Literal[True]
    protected_price_rule_state: Literal["DEFERRED_NOT_COLLECTION_READY"]
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
        expected_policy_hash = _sha256_json(self.policy.model_dump(mode="json"))
        if self.policy_hash != expected_policy_hash:
            raise ValueError("policy_hash mismatch")
        return self


class CFastExecutionPolicyFreezeReceiptDTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_execution_policy_freeze_receipt_v1"]
    freeze_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    freeze_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    policy_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signer_key_purpose: Literal["execution_quality_policy_freeze_signer"]
    signature_verified: Literal[True]
    policy_frozen: Literal[True]
    protected_price_rule_state: Literal["DEFERRED_NOT_COLLECTION_READY"]
    p0_pass_required_before_collection: Literal[True]
    foundation_only: Literal[True]
    collection_authorized: Literal[False]
    runtime_activation_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]


class CFastProtectedPriceCounterfactualV2DTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_protected_price_counterfactual_v2"]
    reference_quote: Literal["SAME_TICK_OPPOSITE_BEST_QUOTE"]
    buy_formula: Literal["ASK_PRICE_1_TICKS_PLUS_ONE"]
    sell_formula: Literal["BID_PRICE_1_TICKS_MINUS_ONE"]
    price_tick_source: Literal["SIGNED_SNAPSHOT_CONTRACT_SPEC"]
    numeric_representation: Literal["DECIMAL_STRING_TO_EXACT_INTEGER_TICKS"]
    tick_grid_rule: Literal[
        "DECIMAL_PRICE_DIVIDED_BY_DECIMAL_PRICE_TICK_MUST_BE_AN_INTEGER"
    ]
    rendering_rule: Literal[
        "SIGNED_INTEGER_TICKS_MULTIPLIED_BY_DECIMAL_PRICE_TICK_NO_BINARY_FLOAT"
    ]
    missing_required_input_state: Literal[
        "UNUSABLE_MISSING_OPPOSITE_BEST_OR_PRICE_TICK"
    ]
    off_tick_input_state: Literal["UNUSABLE_INVALID_PRICE_GRID"]
    counterfactual_only: Literal[True]
    order_price_authorized: Literal[False]


class CFastDecisionHorizonSelectionV2DTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_decision_horizon_selection_v2"]
    decision_anchor: Literal["VIRTUAL_INTENT_DURABLY_CREATED_AT_UTC"]
    decision_anchor_field: Literal["virtual_intent.durably_created_at_utc"]
    decision_anchor_source: Literal[
        "CREATE_ONLY_DURABLE_VIRTUAL_INTENT_RECORD_AFTER_FILE_AND_DIRECTORY_FSYNC"
    ]
    intent_id_source: Literal["virtual_intent.intent_id"]
    snapshot_id_source: Literal["virtual_intent.snapshot_id"]
    received_at_field_source: Literal["market_tick.received_at_utc"]
    exchange_timestamp_field_source: Literal["market_tick.exchange_timestamp"]
    ingest_seq_field_source: Literal["market_tick.ingest_seq"]
    ingest_id_field_source: Literal["market_tick.ingest_id"]
    decision_tick_selection: Literal[
        "EARLIEST_ELIGIBLE_TICK_WITH_RECEIVED_AT_UTC_AT_OR_AFTER_DECISION_ANCHOR"
    ]
    decision_max_lateness_ms: Literal[1_000]
    decision_window_endpoints: Literal[
        "RECEIVED_AT_UTC_GREATER_THAN_OR_EQUAL_TO_ANCHOR_AND_LESS_THAN_OR_EQUAL_TO_ANCHOR_PLUS_1000MS"
    ]
    horizon_target_basis: Literal["DECISION_ANCHOR_PLUS_HORIZON_MS"]
    horizon_tick_selection: Literal["EARLIEST_ELIGIBLE_TICK_AT_OR_AFTER_HORIZON_TARGET"]
    horizon_max_lateness_ms: Literal[1_000]
    horizon_window_endpoints: Literal[
        "RECEIVED_AT_UTC_GREATER_THAN_OR_EQUAL_TO_TARGET_AND_LESS_THAN_OR_EQUAL_TO_TARGET_PLUS_1000MS"
    ]
    eligible_tick_definition: Literal[
        "POSITIVE_L1_ON_GRID_NOT_STALE_OR_CROSSED_LOCKED_AND_L1_ONLY_ALLOWED_DEGRADED"
    ]
    tie_break_fields: tuple[
        Literal["received_at_utc"],
        Literal["exchange_timestamp"],
        Literal["ingest_seq"],
        Literal["ingest_id"],
    ]
    duplicate_ingest_rule: Literal[
        "SAME_INGEST_ID_OR_SAME_CONTRACT_TIMESTAMP_AND_INGEST_SEQ_IS_ONE_EVENT_FIRST_CANONICAL_ROW_ONLY"
    ]
    prior_quote_carry_forward_allowed: Literal[False]
    missing_tick_state: Literal["MISSING_HORIZON_NOT_IMPUTED"]

    @model_validator(mode="before")
    @classmethod
    def reject_coercive_integer_literals(cls, value: Any) -> Any:
        if isinstance(value, dict):
            for field in ("decision_max_lateness_ms", "horizon_max_lateness_ms"):
                if field in value and type(value[field]) is not int:
                    raise ValueError(f"{field} must be an integer JSON literal")
        return value


class CFastBookQualityRulesV2DTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_book_quality_rules_v2"]
    stale_age_basis: Literal["RECEIVED_AT_UTC_MINUS_EXCHANGE_TIMESTAMP"]
    stale_after_ms: Literal[2_000]
    stale_boundary_rule: Literal["AGE_MS_GREATER_THAN_OR_EQUAL_TO_2000_IS_STALE"]
    negative_age_state: Literal["UNUSABLE_CLOCK_ORDER_INVALID"]
    stale_state: Literal["UNUSABLE_STALE_NO_PRICE_OR_FILL_METRICS"]
    crossed_definition: Literal["BID_PRICE_1_GREATER_THAN_ASK_PRICE_1"]
    crossed_state: Literal["UNUSABLE_CROSSED_BOOK"]
    locked_definition: Literal["BID_PRICE_1_EQUALS_ASK_PRICE_1"]
    locked_state: Literal["DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS"]
    l1_usable_definition: Literal[
        "POSITIVE_BID1_ASK1_SIZE1_ON_TICK_GRID_AND_BID1_LESS_THAN_ASK1"
    ]
    l5_usable_definition: Literal[
        "ALL_L1_TO_L5_PRICES_ON_GRID_ALL_SIZES_POSITIVE_MONOTONIC_AND_UNCROSSED"
    ]
    all_level_price_grid_required: Literal[True]
    price_grid_numeric_representation: Literal[
        "DECIMAL_STRING_TO_EXACT_INTEGER_TICKS_NO_BINARY_FLOAT"
    ]
    price_grid_definition: Literal[
        "EACH_L1_TO_L5_PRICE_DIVIDED_BY_SIGNED_DECIMAL_PRICE_TICK_MUST_BE_AN_INTEGER"
    ]
    l5_monotonic_rule: Literal[
        "BID1_GT_BID2_GT_BID3_GT_BID4_GT_BID5_AND_ASK1_LT_ASK2_LT_ASK3_LT_ASK4_LT_ASK5"
    ]
    quality_precedence: tuple[
        Literal["UNUSABLE_CLOCK_ORDER_INVALID"],
        Literal["UNUSABLE_STALE_NO_PRICE_OR_FILL_METRICS"],
        Literal["UNUSABLE_CROSSED_BOOK"],
        Literal["DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS"],
        Literal["UNUSABLE_NO_EXECUTION_METRICS"],
        Literal["L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO"],
        Literal["L5_USABLE"],
    ]
    unusable_metric_mask: Literal["QUALITY_STATE_AND_DIAGNOSTICS_ONLY"]
    locked_metric_mask: Literal["MARKOUT_ONLY"]
    l1_only_metric_mask: Literal[
        "SPREAD_PROTECTED_PRICE_COUNTERFACTUAL_MARKOUT_AND_L1_COVERAGE_ONLY"
    ]
    l5_usable_metric_mask: Literal[
        "SPREAD_PROTECTED_PRICE_COUNTERFACTUAL_MARKOUT_L1_COVERAGE_AND_L5_BOOK_WALK"
    ]
    missing_l1_state: Literal["UNUSABLE_NO_EXECUTION_METRICS"]
    missing_or_invalid_l2_l5_state: Literal[
        "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO"
    ]
    degraded_horizon_rule: Literal[
        "RECORD_ONLY_STATE_ALLOWED_OBSERVED_METRICS_WITHOUT_IMPUTATION"
    ]
    absent_level_synthesis_allowed: Literal[False]
    optimistic_l1_to_l5_fallback_allowed: Literal[False]

    @model_validator(mode="before")
    @classmethod
    def reject_coercive_integer_literals(cls, value: Any) -> Any:
        if (
            isinstance(value, dict)
            and "stale_after_ms" in value
            and type(value["stale_after_ms"]) is not int
        ):
            raise ValueError("stale_after_ms must be an integer JSON literal")
        return value


class CFastPassiveFillBoundsV2DTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_passive_fill_bounds_v2"]
    output_mode: Literal["LOWER_UPPER_BOUNDS_ONLY"]
    passive_buy_limit: Literal["BID_PRICE_1_AT_DECISION_TICK"]
    passive_sell_limit: Literal["ASK_PRICE_1_AT_DECISION_TICK"]
    buy_at_or_through_direction: Literal[
        "SELL_AGGRESSOR_VOLUME_AT_PRICE_LESS_THAN_OR_EQUAL_TO_BUY_LIMIT"
    ]
    sell_at_or_through_direction: Literal[
        "BUY_AGGRESSOR_VOLUME_AT_PRICE_GREATER_THAN_OR_EQUAL_TO_SELL_LIMIT"
    ]
    observation_interval: Literal[
        "DECISION_TICK_EXCLUSIVE_TO_SELECTED_HORIZON_TICK_INCLUSIVE"
    ]
    volume_unit: Literal["EXCHANGE_CUMULATIVE_VOLUME_DELTA_RAW_UNITS"]
    volume_unit_binding_rule: Literal[
        "SIGNED_CONTRACT_SPEC_MUST_BIND_ONE_RAW_VOLUME_UNIT_TO_CONTRACT_LOTS_ELSE_UNIDENTIFIED"
    ]
    lower_bound_rule: Literal["ZERO_WITHOUT_IDENTIFIABLE_ORDER_QUEUE_AND_EXCHANGE_FILL"]
    upper_bound_rule: Literal[
        "MIN_ONE_ALL_POSITIVE_INTERVAL_VOLUME_DELTA_IN_BOUND_CONTRACT_LOTS_DIVIDED_BY_ORDER_LOTS"
    ]
    queue_ahead_assumption: Literal["ALL_DISPLAYED_SAME_SIDE_SIZE_IS_AHEAD_AT_DECISION"]
    cancellation_treatment: Literal[
        "NO_CANCELLATION_CREDIT_TO_LOWER_FULL_CREDIT_ONLY_TO_UPPER"
    ]
    aggregate_direction_attribution: Literal[
        "UNAVAILABLE_FROM_SAMPLED_AGGREGATED_CTP_L1_L5"
    ]
    price_conditioned_bound_state: Literal[
        "UNIDENTIFIED_AGGREGATED_LAST_PRICE_CANNOT_PROVE_AGGRESSOR_DIRECTION_OR_AT_OR_THROUGH_VOLUME"
    ]
    ambiguous_or_reset_volume_state: Literal["UNIDENTIFIED_BOUNDS_NOT_ZERO_OR_FULL"]
    locked_crossed_stale_or_l1_only_state: Literal[
        "UNIDENTIFIED_NO_PASSIVE_FILL_BOUNDS"
    ]
    point_probability_output: Literal["FORBIDDEN"]
    bounds_only: Literal[True]
    calibrated_point_probability_allowed: Literal[False]


class CFastExecutionQualityCollectionPolicyV2DTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_execution_quality_collection_policy_v2"]
    policy_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    foundation_policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_book_levels: Literal[5]
    horizon_schedule_ms: HorizonScheduleMs
    protected_price: CFastProtectedPriceCounterfactualV2DTO
    tick_selection: CFastDecisionHorizonSelectionV2DTO
    book_quality: CFastBookQualityRulesV2DTO
    passive_fill_bounds: CFastPassiveFillBoundsV2DTO
    policy_authority_state: Literal[
        "SIGNED_RULES_COMPLETE_REQUIRES_SEPARATE_P0_AND_COLLECTION_RELEASE"
    ]
    policy_rule_completeness: Literal["COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT"]
    counterfactual_only: Literal[True]
    collection_authorized: Literal[False]
    runtime_activation_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    order_authorized: Literal[False]
    position_mutation_authorized: Literal[False]
    dynamic_selection_allowed: Literal[False]
    automatic_promotion_authorized: Literal[False]
    database_mutation_authorized: Literal[False]
    deployment_mutation_authorized: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]

    @model_validator(mode="before")
    @classmethod
    def reject_coercive_numeric_policy_literals(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        _reject_float_literals(value)
        if (
            "decision_book_levels" in value
            and type(value["decision_book_levels"]) is not int
        ):
            raise ValueError("decision_book_levels must be an integer JSON literal")
        if "horizon_schedule_ms" in value:
            schedule = value["horizon_schedule_ms"]
            if (
                not isinstance(schedule, (list, tuple))
                or any(type(item) is not int for item in schedule)
                or tuple(schedule) != (250, 1_000, 5_000, 30_000, 60_000)
            ):
                raise ValueError(
                    "horizon_schedule_ms must be the exact ordered integer schedule"
                )
        return value


class CFastExecutionPolicyFreezeV2DTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_execution_policy_freeze_v2"]
    freeze_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    policy_scope: Literal["EXECUTION_QUALITY_COLLECTION_READY_OFFLINE_POLICY_ONLY"]
    supersedes_schema_version: Literal["commodity_c_fast_execution_policy_freeze_v1"]
    supersedes_freeze_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    supersedes_freeze_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    supersedes_freeze_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    superseded_policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy: CFastExecutionQualityCollectionPolicyV2DTO
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen_at_utc: datetime
    reviewer_role: Literal["human_execution_policy_reviewer"]
    human_reviewed: Literal[True]
    policy_frozen: Literal[True]
    policy_rule_completeness: Literal["COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT"]
    p0_pass_required_before_collection: Literal[True]
    separate_collection_release_required: Literal[True]
    offline_policy_only: Literal[True]
    collection_authorized: Literal[False]
    runtime_activation_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    order_authorized: Literal[False]
    position_mutation_authorized: Literal[False]
    dynamic_selection_allowed: Literal[False]
    automatic_promotion_authorized: Literal[False]
    database_mutation_authorized: Literal[False]
    deployment_mutation_authorized: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signature: str = Field(min_length=40, max_length=256)

    @model_validator(mode="before")
    @classmethod
    def reject_numeric_timestamp(cls, value: Any) -> Any:
        if isinstance(value, dict) and isinstance(
            value.get("frozen_at_utc"),
            (int, float),
        ):
            raise ValueError("frozen_at_utc must not be a numeric timestamp")
        _reject_float_literals(value)
        return value

    @model_validator(mode="after")
    def validate_freeze_semantics(self) -> "CFastExecutionPolicyFreezeV2DTO":
        if (
            self.frozen_at_utc.tzinfo is None
            or self.frozen_at_utc.utcoffset() is None
            or self.frozen_at_utc.utcoffset().total_seconds() != 0
        ):
            raise ValueError("frozen_at_utc must use UTC")
        expected_policy_hash = _sha256_json(self.policy.model_dump(mode="json"))
        if self.policy_hash != expected_policy_hash:
            raise ValueError("policy_hash mismatch")
        if self.policy.foundation_policy_hash != self.superseded_policy_hash:
            raise ValueError("foundation_policy_hash must match superseded_policy_hash")
        if self.policy_rule_completeness != (self.policy.policy_rule_completeness):
            raise ValueError("policy_rule_completeness mismatch")
        return self


class CFastExecutionPolicyFreezeReceiptV2DTO(StrictFoundationModel):
    schema_version: Literal["commodity_c_fast_execution_policy_freeze_receipt_v2"]
    freeze_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    freeze_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    freeze_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    supersedes_freeze_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    supersedes_freeze_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    supersedes_freeze_raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    superseded_policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signer_key_purpose: Literal["execution_quality_policy_freeze_signer"]
    signature_verified: Literal[True]
    ancestry_signature_verified: Literal[True]
    policy_frozen: Literal[True]
    policy_rule_completeness: Literal["COLLECTION_RULES_COMPLETE_AUTHORITY_ABSENT"]
    receipt_authority_state: Literal["NON_AUTHORITATIVE_REVERIFY_RAW_SIGNED_FREEZES"]
    p0_pass_required_before_collection: Literal[True]
    separate_collection_release_required: Literal[True]
    offline_policy_only: Literal[True]
    collection_authorized: Literal[False]
    runtime_activation_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    order_authorized: Literal[False]
    position_mutation_authorized: Literal[False]
    dynamic_selection_allowed: Literal[False]
    automatic_promotion_authorized: Literal[False]
    database_mutation_authorized: Literal[False]
    deployment_mutation_authorized: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]
