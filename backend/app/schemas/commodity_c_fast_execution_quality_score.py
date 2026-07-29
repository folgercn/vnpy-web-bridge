from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentDTO,
    StrictFoundationModel,
)


DecimalText = str
FiveDecimalLevels = tuple[
    DecimalText | None,
    DecimalText | None,
    DecimalText | None,
    DecimalText | None,
    DecimalText | None,
]
FiveIntegerLevels = tuple[
    int | None,
    int | None,
    int | None,
    int | None,
    int | None,
]
BookQualityState = Literal[
    "UNUSABLE_CLOCK_ORDER_INVALID",
    "UNUSABLE_STALE_NO_PRICE_OR_FILL_METRICS",
    "UNUSABLE_CROSSED_BOOK",
    "DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS",
    "UNUSABLE_NO_EXECUTION_METRICS",
    "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO",
    "L5_USABLE",
]

_DECIMAL_PATTERN = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_STRICT_BOOLEAN_FIELDS = frozenset(
    {
        "authority_granted",
        "calibrated_point_probability_allowed",
        "collection_authorized",
        "database_mutation_authorized",
        "deployment_mutation_authorized",
        "dispatch_allowed",
        "order_authorized",
        "position_mutation_authorized",
        "production_allowed",
        "replacement_allowed",
        "runtime_activation_authorized",
        "virtual_only",
    }
)


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _reject_binary_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("binary float literals are forbidden")
    if isinstance(value, dict):
        for item in value.values():
            _reject_binary_floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_binary_floats(item)


def _reject_coercive_booleans(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in _STRICT_BOOLEAN_FIELDS and type(item) is not bool:
                raise ValueError(f"{key} must be a JSON boolean literal")
            _reject_coercive_booleans(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_coercive_booleans(item)


def _decimal(value: str, *, positive: bool = False) -> Decimal:
    if (
        not isinstance(value, str)
        or len(value) > 64
        or _DECIMAL_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("decimal values must use plain decimal strings")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:  # pragma: no cover - guarded by regex
        raise ValueError("invalid decimal string") from exc
    if not parsed.is_finite():
        raise ValueError("decimal values must be finite")
    if positive and parsed <= 0:
        raise ValueError("decimal value must be positive")
    return parsed


def _require_utc(value: datetime, field: str) -> None:
    if (
        value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        raise ValueError(f"{field} must use UTC")


class StrictScoreModel(StrictFoundationModel):
    @model_validator(mode="before")
    @classmethod
    def reject_binary_float_literals(cls, value: Any) -> Any:
        _reject_binary_floats(value)
        _reject_coercive_booleans(value)
        return value


class CFastExecutionQualityContractSpecDTO(StrictScoreModel):
    schema_version: Literal[
        "commodity_c_fast_execution_quality_contract_spec_v1"
    ]
    contract_spec_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_contract: str = Field(
        min_length=8,
        max_length=32,
        pattern=r"^[A-Z]+\.[A-Za-z]+[0-9]{3,4}$",
    )
    price_tick: DecimalText
    multiplier: int = Field(ge=1, le=1_000_000)
    volume_lots_per_raw_unit: DecimalText | None
    binding_state: Literal[
        "CALLER_MUST_BIND_TO_ACCEPTED_SIGNED_SNAPSHOT_CONTRACT_SPEC"
    ]

    @field_validator("price_tick")
    @classmethod
    def validate_price_tick(cls, value: str) -> str:
        if _decimal(value, positive=True) > Decimal("1000000000"):
            raise ValueError("price_tick exceeds resource limit")
        return value

    @field_validator("volume_lots_per_raw_unit")
    @classmethod
    def validate_volume_binding(cls, value: str | None) -> str | None:
        if value is not None:
            if _decimal(value, positive=True) > Decimal("1000000"):
                raise ValueError("volume binding exceeds resource limit")
        return value

    @model_validator(mode="before")
    @classmethod
    def reject_coercive_multiplier(cls, value: Any) -> Any:
        if (
            isinstance(value, dict)
            and "multiplier" in value
            and type(value["multiplier"]) is not int
        ):
            raise ValueError("multiplier must be an integer literal")
        return value

    @model_validator(mode="after")
    def validate_hash(self) -> "CFastExecutionQualityContractSpecDTO":
        payload = self.model_dump(
            mode="json",
            exclude={"contract_spec_hash"},
        )
        if self.contract_spec_hash != _sha256_json(payload):
            raise ValueError("contract_spec_hash mismatch")
        return self


class CFastL1L5BookSnapshotDTO(StrictScoreModel):
    schema_version: Literal["commodity_c_fast_l1_l5_book_snapshot_v1"]
    book_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_contract: str = Field(
        min_length=8,
        max_length=32,
        pattern=r"^[A-Z]+\.[A-Za-z]+[0-9]{3,4}$",
    )
    exchange_timestamp: datetime
    received_at_utc: datetime
    ingest_seq: int = Field(ge=1, le=9_223_372_036_854_775_807)
    ingest_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,192}$")
    cumulative_volume: DecimalText | None
    bid_prices: FiveDecimalLevels
    ask_prices: FiveDecimalLevels
    bid_sizes: FiveIntegerLevels
    ask_sizes: FiveIntegerLevels

    @model_validator(mode="before")
    @classmethod
    def reject_numeric_timestamps_and_non_integer_depth(
        cls,
        value: Any,
    ) -> Any:
        if not isinstance(value, dict):
            return value
        for field in ("exchange_timestamp", "received_at_utc"):
            if field in value and isinstance(value[field], (int, float)):
                raise ValueError(f"{field} must not be a numeric timestamp")
        for field in ("bid_sizes", "ask_sizes"):
            levels = value.get(field)
            if isinstance(levels, (list, tuple)) and any(
                item is not None and type(item) is not int for item in levels
            ):
                raise ValueError(f"{field} must contain integer literals")
        if "ingest_seq" in value and type(value["ingest_seq"]) is not int:
            raise ValueError("ingest_seq must be an integer literal")
        return value

    @field_validator("cumulative_volume")
    @classmethod
    def validate_cumulative_volume(
        cls,
        value: str | None,
    ) -> str | None:
        if value is not None:
            parsed = _decimal(value)
            if parsed < 0:
                raise ValueError("cumulative_volume must be non-negative")
        return value

    @field_validator("bid_prices", "ask_prices")
    @classmethod
    def validate_prices(
        cls,
        value: FiveDecimalLevels,
    ) -> FiveDecimalLevels:
        for item in value:
            if item is not None:
                _decimal(item)
        return value

    @model_validator(mode="after")
    def validate_semantics(self) -> "CFastL1L5BookSnapshotDTO":
        _require_utc(self.exchange_timestamp, "exchange_timestamp")
        _require_utc(self.received_at_utc, "received_at_utc")
        if any(
            value is not None and value > 1_000_000_000
            for value in self.bid_sizes + self.ask_sizes
        ):
            raise ValueError("book size exceeds resource limit")
        payload = self.model_dump(
            mode="json",
            exclude={"book_snapshot_hash"},
        )
        if self.book_snapshot_hash != _sha256_json(payload):
            raise ValueError("book_snapshot_hash mismatch")
        return self


class CFastSelectedBookTickDTO(StrictScoreModel):
    book_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    received_at_utc: datetime
    exchange_timestamp: datetime
    ingest_seq: int = Field(ge=1)
    ingest_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,192}$")
    quality_state: BookQualityState

    @model_validator(mode="before")
    @classmethod
    def reject_coercive_identity_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        for field in ("received_at_utc", "exchange_timestamp"):
            if field in value and isinstance(value[field], (int, float)):
                raise ValueError(f"{field} must not be a numeric timestamp")
        if "ingest_seq" in value and type(value["ingest_seq"]) is not int:
            raise ValueError("ingest_seq must be an integer literal")
        return value

    @model_validator(mode="after")
    def validate_utc(self) -> "CFastSelectedBookTickDTO":
        _require_utc(self.received_at_utc, "received_at_utc")
        _require_utc(self.exchange_timestamp, "exchange_timestamp")
        return self


class CFastBookWalkMetricsDTO(StrictScoreModel):
    metric_mask_state: Literal[
        "MARKOUT_ONLY_NO_DECISION_EXECUTION_METRICS",
        "L1_METRICS_ONLY",
        "L5_METRICS",
    ]
    spread_ticks: DecimalText | None
    spread_cny_per_lot: DecimalText | None
    microprice_ticks: DecimalText | None
    depth_imbalance: DecimalText | None
    protected_price: DecimalText | None
    l1_covered_lots: int | None = Field(default=None, ge=0)
    l1_coverage_ratio: DecimalText | None
    l5_covered_lots: int | None = Field(default=None, ge=0)
    l5_coverage_ratio: DecimalText | None
    l5_vwap_price: DecimalText | None
    l5_adverse_ticks: DecimalText | None
    l5_adverse_cny: DecimalText | None
    l5_book_walk_state: Literal[
        "FULL_L5_COVERAGE",
        "PARTIAL_L5_DEPTH_INSUFFICIENT",
        "UNAVAILABLE_QUALITY_MASK",
    ]

    @field_validator(
        "spread_ticks",
        "spread_cny_per_lot",
        "microprice_ticks",
        "depth_imbalance",
        "protected_price",
        "l1_coverage_ratio",
        "l5_coverage_ratio",
        "l5_vwap_price",
        "l5_adverse_ticks",
        "l5_adverse_cny",
    )
    @classmethod
    def validate_decimal_outputs(
        cls,
        value: str | None,
    ) -> str | None:
        if value is not None:
            _decimal(value)
        return value

    @model_validator(mode="after")
    def validate_l5_mask(self) -> "CFastBookWalkMetricsDTO":
        l1_values = (
            self.spread_ticks,
            self.spread_cny_per_lot,
            self.protected_price,
            self.l1_covered_lots,
            self.l1_coverage_ratio,
        )
        l5_diagnostics = (
            self.microprice_ticks,
            self.depth_imbalance,
        )
        l5_values = (
            self.l5_covered_lots,
            self.l5_coverage_ratio,
            self.l5_vwap_price,
            self.l5_adverse_ticks,
            self.l5_adverse_cny,
        )
        if self.metric_mask_state == (
            "MARKOUT_ONLY_NO_DECISION_EXECUTION_METRICS"
        ):
            if any(
                value is not None
                for value in l1_values + l5_diagnostics + l5_values
            ):
                raise ValueError("locked metric mask must hide decision metrics")
            if self.l5_book_walk_state != "UNAVAILABLE_QUALITY_MASK":
                raise ValueError("locked metric mask cannot expose book walk")
            return self
        if any(value is None for value in l1_values):
            raise ValueError("L1 metrics must be complete")
        if self.metric_mask_state == "L1_METRICS_ONLY" and any(
            value is not None for value in l5_diagnostics
        ):
            raise ValueError("L1-only mask cannot expose L5 diagnostics")
        if self.metric_mask_state == "L5_METRICS" and any(
            value is None for value in l5_diagnostics
        ):
            raise ValueError("L5 diagnostics must be complete")
        if self.l5_book_walk_state == "UNAVAILABLE_QUALITY_MASK":
            if any(value is not None for value in l5_values):
                raise ValueError("masked L5 metrics must be absent")
        elif any(value is None for value in l5_values):
            raise ValueError("available L5 metrics must be complete")
        if (
            self.metric_mask_state == "L1_METRICS_ONLY"
            and self.l5_book_walk_state != "UNAVAILABLE_QUALITY_MASK"
        ):
            raise ValueError("L1 metric mask cannot expose L5 metrics")
        if (
            self.metric_mask_state == "L5_METRICS"
            and self.l5_book_walk_state == "UNAVAILABLE_QUALITY_MASK"
        ):
            raise ValueError("L5 metric mask must expose observed book walk")
        return self


class CFastPassiveFillBoundsDTO(StrictScoreModel):
    state: Literal[
        "IDENTIFIED_CONSERVATIVE_BOUNDS",
        "UNIDENTIFIED_VOLUME_UNIT_BINDING",
        "UNIDENTIFIED_BOUNDS_NOT_ZERO_OR_FULL",
        "UNIDENTIFIED_NO_PASSIVE_FILL_BOUNDS",
        "UNIDENTIFIED_MISSING_HORIZON",
    ]
    lower_bound: DecimalText | None
    upper_bound: DecimalText | None
    price_conditioned_bound_state: Literal[
        "UNIDENTIFIED_AGGREGATED_LAST_PRICE_CANNOT_PROVE_AGGRESSOR_DIRECTION_OR_AT_OR_THROUGH_VOLUME"
    ]
    point_probability_output: Literal["FORBIDDEN"]
    calibrated_point_probability_allowed: Literal[False]

    @field_validator("lower_bound", "upper_bound")
    @classmethod
    def validate_bound(cls, value: str | None) -> str | None:
        if value is not None:
            parsed = _decimal(value)
            if parsed < 0 or parsed > 1:
                raise ValueError("fill bound must be between zero and one")
        return value

    @model_validator(mode="after")
    def validate_bounds(self) -> "CFastPassiveFillBoundsDTO":
        if self.state == "IDENTIFIED_CONSERVATIVE_BOUNDS":
            if self.lower_bound is None or self.upper_bound is None:
                raise ValueError("identified bounds must be complete")
            if Decimal(self.lower_bound) > Decimal(self.upper_bound):
                raise ValueError("lower_bound must not exceed upper_bound")
        elif self.lower_bound is not None or self.upper_bound is not None:
            raise ValueError("unidentified bounds must not contain estimates")
        return self


class CFastExecutionQualityHorizonDTO(StrictScoreModel):
    horizon_ms: Literal[250, 1_000, 5_000, 30_000, 60_000]
    selection_state: Literal[
        "SELECTED_EARLIEST_ELIGIBLE",
        "MISSING_HORIZON_NOT_IMPUTED",
        "DECISION_TICK_MISSING",
    ]
    selected_tick: CFastSelectedBookTickDTO | None
    midpoint_markout_ticks: DecimalText | None
    midpoint_markout_cny: DecimalText | None
    passive_fill_bounds: CFastPassiveFillBoundsDTO

    @model_validator(mode="before")
    @classmethod
    def reject_coercive_horizon(cls, value: Any) -> Any:
        if (
            isinstance(value, dict)
            and "horizon_ms" in value
            and type(value["horizon_ms"]) is not int
        ):
            raise ValueError("horizon_ms must be an integer literal")
        return value

    @field_validator("midpoint_markout_ticks", "midpoint_markout_cny")
    @classmethod
    def validate_markout(cls, value: str | None) -> str | None:
        if value is not None:
            _decimal(value)
        return value

    @model_validator(mode="after")
    def validate_selection(self) -> "CFastExecutionQualityHorizonDTO":
        if self.selection_state == "SELECTED_EARLIEST_ELIGIBLE":
            if (
                self.selected_tick is None
                or self.midpoint_markout_ticks is None
                or self.midpoint_markout_cny is None
            ):
                raise ValueError("selected horizon metrics must be complete")
        elif (
            self.selected_tick is not None
            or self.midpoint_markout_ticks is not None
            or self.midpoint_markout_cny is not None
        ):
            raise ValueError("missing horizon must not contain imputed metrics")
        return self


class CFastExecutionQualityScoreDTO(StrictScoreModel):
    schema_version: Literal["commodity_c_fast_execution_quality_score_v1"]
    score_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    intent: CFastVirtualIntentDTO
    durably_created_at_utc: datetime
    policy_id: str = Field(pattern=r"^[A-Za-z0-9._-]{8,128}$")
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_spec: CFastExecutionQualityContractSpecDTO
    input_snapshot_count: int = Field(ge=0, le=10_000)
    canonical_snapshot_count: int = Field(ge=0, le=10_000)
    duplicate_snapshot_count: int = Field(ge=0, le=10_000)
    input_snapshot_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rejection_quality_counts: dict[BookQualityState, int] = Field(
        max_length=7
    )
    decision_selection_state: Literal[
        "SELECTED_EARLIEST_ELIGIBLE",
        "MISSING_DECISION_TICK_NOT_IMPUTED",
    ]
    decision_tick: CFastSelectedBookTickDTO | None
    decision_metrics: CFastBookWalkMetricsDTO | None
    horizons: tuple[
        CFastExecutionQualityHorizonDTO,
        CFastExecutionQualityHorizonDTO,
        CFastExecutionQualityHorizonDTO,
        CFastExecutionQualityHorizonDTO,
        CFastExecutionQualityHorizonDTO,
    ]
    scoring_state: Literal["PURE_RESEARCH_SCORE_AUTHORITY_ABSENT"]
    source_validation_scope: Literal[
        "CALLER_MUST_REVERIFY_ACCEPTED_INTENT_SIGNED_POLICY_AND_CONTRACT_SPEC"
    ]
    collection_authorized: Literal[False]
    runtime_activation_authorized: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    order_authorized: Literal[False]
    position_mutation_authorized: Literal[False]
    database_mutation_authorized: Literal[False]
    deployment_mutation_authorized: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]

    @model_validator(mode="before")
    @classmethod
    def reject_numeric_anchor(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        if isinstance(
            value.get("durably_created_at_utc"),
            (int, float),
        ):
            raise ValueError(
                "durably_created_at_utc must not be a numeric timestamp"
            )
        for field in (
            "input_snapshot_count",
            "canonical_snapshot_count",
            "duplicate_snapshot_count",
        ):
            if field in value and type(value[field]) is not int:
                raise ValueError(f"{field} must be an integer literal")
        return value

    @model_validator(mode="after")
    def validate_score(self) -> "CFastExecutionQualityScoreDTO":
        _require_utc(
            self.durably_created_at_utc,
            "durably_created_at_utc",
        )
        if self.intent.exact_contract != self.contract_spec.exact_contract:
            raise ValueError("intent and contract spec must bind one contract")
        if self.canonical_snapshot_count + self.duplicate_snapshot_count != (
            self.input_snapshot_count
        ):
            raise ValueError("snapshot counts do not reconcile")
        if tuple(row.horizon_ms for row in self.horizons) != (
            250,
            1_000,
            5_000,
            30_000,
            60_000,
        ):
            raise ValueError("horizon schedule must be exact and ordered")
        if self.decision_selection_state == "SELECTED_EARLIEST_ELIGIBLE":
            if self.decision_tick is None or self.decision_metrics is None:
                raise ValueError("selected decision evidence must be complete")
        elif self.decision_tick is not None or self.decision_metrics is not None:
            raise ValueError("missing decision must not contain metrics")
        payload = self.model_dump(mode="json", exclude={"score_hash"})
        if self.score_hash != _sha256_json(payload):
            raise ValueError("score_hash mismatch")
        return self
