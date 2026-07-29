from __future__ import annotations

import hashlib
import json
import math
from datetime import date, datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from app.schemas.commodity_c_fast_shadow import StrictFiniteModel


Money = float
Sha256 = str
MAX_ABS_MONEY_CNY = 1_000_000_000_000.0
MAX_LEDGER_LOTS = 100_000

LayerKind = Literal[
    "THEORETICAL_TARGET_PNL",
    "FEE_ADJUSTED_PNL",
    "EXECUTION_QUALITY_INTERVAL_PNL",
    "ACTUAL_SIMNOW_CALIBRATION_PNL",
]
SourceKind = Literal[
    "SIGNED_EXACT_TARGET_MARKS",
    "FEE_AND_STRESS_ASSUMPTIONS",
    "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS",
    "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION",
]
UnboundFeeComponent = Literal[
    "official_exchange_fee_rate",
    "broker_customer_fee_rate",
    "preregistered_tick_stress",
    "roll_round_trip_cost",
]


def sha256_json(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _money_equal(left: float, right: float) -> bool:
    return math.isclose(left, right, rel_tol=0.0, abs_tol=1e-6)


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    if value.utcoffset().total_seconds() != 0:
        raise ValueError(f"{field} must use UTC")


class StrictLedgerModel(StrictFiniteModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        frozen=True,
    )


class PnlSourceLineageDTO(StrictLedgerModel):
    schema_version: Literal["commodity_c_fast_pnl_source_lineage_v1"]
    source_kind: SourceKind
    source_artifact_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    source_artifact_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_payload_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    derivation_rule_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    derivation_code_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    input_cutoff_at_utc: datetime
    lineage_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_lineage(self) -> "PnlSourceLineageDTO":
        _require_utc(self.input_cutoff_at_utc, "input_cutoff_at_utc")
        payload = self.model_dump(mode="json", exclude={"lineage_hash"})
        if self.lineage_hash != sha256_json(payload):
            raise ValueError("lineage_hash mismatch")
        return self


class TheoreticalTargetPnlLayerDTO(StrictLedgerModel):
    schema_version: Literal[
        "commodity_c_fast_theoretical_target_pnl_layer_v1"
    ]
    layer_kind: Literal["THEORETICAL_TARGET_PNL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    lineage: PnlSourceLineageDTO
    valuation_day: date
    position_basis: Literal[
        "OBSERVED_VIRTUAL_FILL_STATE_NEVER_ASSUME_UNFILLED_TARGET"
    ]
    held_lots: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    pending_virtual_lots: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    realized_pnl_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    unrealized_pnl_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    roll_pnl_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    total_pnl_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    layer_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_theoretical(self) -> "TheoreticalTargetPnlLayerDTO":
        if self.lineage.source_kind != "SIGNED_EXACT_TARGET_MARKS":
            raise ValueError("theoretical lineage source kind mismatch")
        expected = (
            self.realized_pnl_cny
            + self.unrealized_pnl_cny
            + self.roll_pnl_cny
        )
        if not _money_equal(self.total_pnl_cny, expected):
            raise ValueError("theoretical total_pnl_cny mismatch")
        _validate_layer_hash(self)
        return self


class FeeAdjustedPnlLayerDTO(StrictLedgerModel):
    schema_version: Literal[
        "commodity_c_fast_fee_adjusted_pnl_layer_v1"
    ]
    layer_kind: Literal["FEE_ADJUSTED_PNL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    lineage: PnlSourceLineageDTO
    source_theoretical_layer_hash: Sha256 = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    source_theoretical_total_pnl_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    fee_binding_state: Literal[
        "BOUND",
        "UNBOUND_NOT_ASSUMED_ZERO",
    ]
    official_exchange_fee_cny: Money | None = Field(
        default=None,
        ge=0,
        le=MAX_ABS_MONEY_CNY,
    )
    preregistered_tick_stress_cny: Money | None = Field(
        default=None,
        ge=0,
        le=MAX_ABS_MONEY_CNY,
    )
    roll_round_trip_cost_cny: Money | None = Field(
        default=None,
        ge=0,
        le=MAX_ABS_MONEY_CNY,
    )
    broker_customer_fee_cny: Money | None = Field(
        default=None,
        ge=0,
        le=MAX_ABS_MONEY_CNY,
    )
    all_in_cost_cny: Money | None = Field(
        default=None,
        ge=0,
        le=MAX_ABS_MONEY_CNY,
    )
    fee_adjusted_total_pnl_cny: Money | None = Field(
        default=None,
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    fee_schedule_sha256: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    unbound_components: tuple[UnboundFeeComponent, ...] = Field(
        default=(),
        max_length=16,
    )
    layer_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_fee_adjusted(self) -> "FeeAdjustedPnlLayerDTO":
        if (
            self.lineage.source_kind
            != "FEE_AND_STRESS_ASSUMPTIONS"
        ):
            raise ValueError("fee lineage source kind mismatch")
        if len(set(self.unbound_components)) != len(
            self.unbound_components
        ):
            raise ValueError("unbound_components must be unique")
        if self.fee_binding_state == "UNBOUND_NOT_ASSUMED_ZERO":
            if not self.unbound_components:
                raise ValueError("UNBOUND requires named unbound_components")
            prohibited = (
                self.broker_customer_fee_cny,
                self.all_in_cost_cny,
                self.fee_adjusted_total_pnl_cny,
                self.fee_schedule_sha256,
            )
            if any(value is not None for value in prohibited):
                raise ValueError(
                    "UNBOUND must not publish broker/all-in/net values"
                )
        else:
            if self.unbound_components:
                raise ValueError("BOUND must not list unbound components")
            costs = (
                self.official_exchange_fee_cny,
                self.preregistered_tick_stress_cny,
                self.roll_round_trip_cost_cny,
                self.broker_customer_fee_cny,
            )
            if (
                any(value is None for value in costs)
                or self.fee_schedule_sha256 is None
                or self.all_in_cost_cny is None
                or self.fee_adjusted_total_pnl_cny is None
            ):
                raise ValueError("BOUND requires all fee and net fields")
            expected_cost = sum(float(value) for value in costs)
            if not _money_equal(self.all_in_cost_cny, expected_cost):
                raise ValueError("all_in_cost_cny mismatch")
            expected_total = (
                self.source_theoretical_total_pnl_cny
                - self.all_in_cost_cny
            )
            if not _money_equal(
                self.fee_adjusted_total_pnl_cny,
                expected_total,
            ):
                raise ValueError("fee_adjusted_total_pnl_cny mismatch")
        _validate_layer_hash(self)
        return self


class ExecutionQualityIntervalPnlLayerDTO(StrictLedgerModel):
    schema_version: Literal[
        "commodity_c_fast_execution_quality_interval_pnl_layer_v1"
    ]
    layer_kind: Literal["EXECUTION_QUALITY_INTERVAL_PNL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    lineage: PnlSourceLineageDTO
    fill_evidence_state: Literal[
        "FULL",
        "PARTIAL",
        "UNFILLED",
        "UNIDENTIFIED_BOUNDS_ONLY",
    ]
    point_fill_probability_state: Literal[
        "FORBIDDEN_UNCALIBRATED_BOUNDS_ONLY"
    ]
    planned_lots: int = Field(ge=1, le=MAX_LEDGER_LOTS)
    filled_lots_lower: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    filled_lots_upper: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    unfilled_lots_lower: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    unfilled_lots_upper: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    marketable_book_walk_pnl_cny: Money | None = Field(
        default=None,
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    conservative_fill_lower_bound_pnl_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    optimistic_fill_upper_bound_pnl_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    opportunity_cost_lower_bound_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    opportunity_cost_upper_bound_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    layer_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_interval(self) -> "ExecutionQualityIntervalPnlLayerDTO":
        if (
            self.lineage.source_kind
            != "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS"
        ):
            raise ValueError("execution-quality lineage source kind mismatch")
        if not (
            0
            <= self.filled_lots_lower
            <= self.filled_lots_upper
            <= self.planned_lots
        ):
            raise ValueError("filled lot bounds are invalid")
        expected_unfilled_lower = self.planned_lots - self.filled_lots_upper
        expected_unfilled_upper = self.planned_lots - self.filled_lots_lower
        if (
            self.unfilled_lots_lower != expected_unfilled_lower
            or self.unfilled_lots_upper != expected_unfilled_upper
        ):
            raise ValueError("unfilled lots must derive from fill bounds")
        if (
            self.conservative_fill_lower_bound_pnl_cny
            > self.optimistic_fill_upper_bound_pnl_cny
        ):
            raise ValueError("lower PnL bound exceeds upper bound")
        if (
            self.opportunity_cost_lower_bound_cny
            > self.opportunity_cost_upper_bound_cny
        ):
            raise ValueError("opportunity cost lower bound exceeds upper")
        if self.fill_evidence_state == "FULL":
            if (
                self.filled_lots_lower != self.planned_lots
                or self.filled_lots_upper != self.planned_lots
                or self.unfilled_lots_upper != 0
                or not _money_equal(
                    self.opportunity_cost_lower_bound_cny,
                    0.0,
                )
                or not _money_equal(
                    self.opportunity_cost_upper_bound_cny,
                    0.0,
                )
            ):
                raise ValueError("FULL must bind full fills and zero opportunity")
        elif self.fill_evidence_state == "UNFILLED":
            if self.filled_lots_lower != 0 or self.filled_lots_upper != 0:
                raise ValueError("UNFILLED must bind zero filled lots")
        elif self.fill_evidence_state == "PARTIAL":
            if (
                self.filled_lots_upper == 0
                or self.filled_lots_lower >= self.planned_lots
            ):
                raise ValueError("PARTIAL requires filled and unfilled lots")
        elif (
            self.filled_lots_lower == self.filled_lots_upper
            and self.filled_lots_lower in {0, self.planned_lots}
        ):
            raise ValueError(
                "UNIDENTIFIED must preserve a non-point fill interval"
            )
        _validate_layer_hash(self)
        return self


class ActualSimNowFactsDTO(StrictLedgerModel):
    schema_version: Literal["commodity_c_fast_actual_simnow_facts_v1"]
    fact_source: Literal[
        "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION"
    ]
    execution_lane: Literal["simnow_shakedown"]
    session_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    account_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    orders_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    trades_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    positions_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    reconciliation_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    execution_captured_at_utc: datetime
    expected_lots: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    filled_lots: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    order_outcome: Literal[
        "FULL_FILL",
        "PARTIAL_FILL",
        "UNFILLED_CANCELLED",
        "REJECTED",
        "TIMEOUT_OR_RESULT_UNKNOWN",
    ]
    trade_evidence_state: Literal[
        "COMPLETE",
        "INCOMPLETE",
        "INCONSISTENT",
    ]
    reconciliation_complete: bool
    countable_forward: Literal[False]
    production_allowed: Literal[False]

    @model_validator(mode="after")
    def validate_actual_facts(self) -> "ActualSimNowFactsDTO":
        _require_utc(
            self.execution_captured_at_utc,
            "execution_captured_at_utc",
        )
        if self.filled_lots > self.expected_lots:
            raise ValueError("actual filled_lots exceeds expected_lots")
        if self.order_outcome == "FULL_FILL" and (
            self.filled_lots != self.expected_lots
            or not self.reconciliation_complete
        ):
            raise ValueError("FULL_FILL requires reconciled expected fills")
        if self.order_outcome == "PARTIAL_FILL" and not (
            0 < self.filled_lots < self.expected_lots
        ):
            raise ValueError("PARTIAL_FILL quantity mismatch")
        if self.order_outcome in {"UNFILLED_CANCELLED", "REJECTED"} and (
            self.filled_lots != 0
        ):
            raise ValueError("unfilled/rejected outcomes require zero fills")
        if self.trade_evidence_state == "COMPLETE" and (
            not self.reconciliation_complete
            or self.order_outcome == "TIMEOUT_OR_RESULT_UNKNOWN"
        ):
            raise ValueError("COMPLETE facts require resolved reconciliation")
        return self


class ActualSimNowCalibrationPnlLayerDTO(StrictLedgerModel):
    schema_version: Literal[
        "commodity_c_fast_actual_simnow_calibration_pnl_layer_v1"
    ]
    layer_kind: Literal["ACTUAL_SIMNOW_CALIBRATION_PNL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    actual_state: Literal["NOT_PROVIDED", "FACTS_BOUND"]
    lineage: PnlSourceLineageDTO | None = None
    facts: ActualSimNowFactsDTO | None = None
    gross_execution_pnl_cny: Money | None = Field(
        default=None,
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    adverse_slippage_cny: Money | None = Field(
        default=None,
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    fees_state: Literal[
        "NOT_AVAILABLE",
        "UNBOUND_NOT_ASSUMED_ZERO",
        "BOUND",
    ]
    actual_fees_cny: Money | None = Field(
        default=None,
        ge=0,
        le=MAX_ABS_MONEY_CNY,
    )
    net_pnl_state: Literal[
        "NOT_AVAILABLE",
        "UNAVAILABLE_UNTIL_FEES_BOUND",
        "AVAILABLE_FOR_OBSERVED_FILLS",
    ]
    actual_net_pnl_cny: Money | None = Field(
        default=None,
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    countable_forward: Literal[False]
    layer_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_actual(self) -> "ActualSimNowCalibrationPnlLayerDTO":
        if self.actual_state == "NOT_PROVIDED":
            if self.lineage is not None or self.facts is not None:
                raise ValueError("NOT_PROVIDED must not fabricate facts")
            if any(
                value is not None
                for value in (
                    self.gross_execution_pnl_cny,
                    self.adverse_slippage_cny,
                    self.actual_fees_cny,
                    self.actual_net_pnl_cny,
                )
            ):
                raise ValueError("NOT_PROVIDED must not publish actual PnL")
            if (
                self.fees_state != "NOT_AVAILABLE"
                or self.net_pnl_state != "NOT_AVAILABLE"
            ):
                raise ValueError("NOT_PROVIDED states must be unavailable")
        else:
            if self.lineage is None or self.facts is None:
                raise ValueError("FACTS_BOUND requires lineage and facts")
            if (
                self.lineage.source_kind
                != (
                    "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_"
                    "RECONCILIATION"
                )
            ):
                raise ValueError("actual lineage source kind mismatch")
            facts_payload_sha256 = sha256_json(
                self.facts.model_dump(mode="json")
            )
            if (
                self.lineage.source_payload_sha256
                != facts_payload_sha256
            ):
                raise ValueError(
                    "actual lineage must bind the embedded facts payload"
                )
            if (
                self.lineage.input_cutoff_at_utc
                < self.facts.execution_captured_at_utc
            ):
                raise ValueError(
                    "actual lineage cutoff precedes fact capture"
                )
            complete = (
                self.facts.trade_evidence_state == "COMPLETE"
                and self.facts.reconciliation_complete
            )
            if not complete:
                if any(
                    value is not None
                    for value in (
                        self.gross_execution_pnl_cny,
                        self.adverse_slippage_cny,
                        self.actual_fees_cny,
                        self.actual_net_pnl_cny,
                    )
                ):
                    raise ValueError(
                        "incomplete actual facts must not publish PnL"
                    )
                if (
                    self.fees_state != "NOT_AVAILABLE"
                    or self.net_pnl_state != "NOT_AVAILABLE"
                ):
                    raise ValueError(
                        "incomplete actual facts must remain unavailable"
                    )
            elif self.gross_execution_pnl_cny is None:
                raise ValueError("complete actual facts require gross PnL")
            elif self.fees_state == "UNBOUND_NOT_ASSUMED_ZERO":
                if (
                    self.actual_fees_cny is not None
                    or self.actual_net_pnl_cny is not None
                    or self.net_pnl_state
                    != "UNAVAILABLE_UNTIL_FEES_BOUND"
                ):
                    raise ValueError(
                        "unbound actual fees must not publish net PnL"
                    )
            elif self.fees_state == "BOUND":
                if (
                    self.actual_fees_cny is None
                    or self.actual_net_pnl_cny is None
                    or self.net_pnl_state
                    != "AVAILABLE_FOR_OBSERVED_FILLS"
                ):
                    raise ValueError("bound actual fees require net PnL")
                expected = (
                    self.gross_execution_pnl_cny - self.actual_fees_cny
                )
                if not _money_equal(self.actual_net_pnl_cny, expected):
                    raise ValueError("actual_net_pnl_cny mismatch")
            else:
                raise ValueError(
                    "complete actual facts require BOUND or UNBOUND fees"
                )
        _validate_layer_hash(self)
        return self


class PnlLayerHashIndexDTO(StrictLedgerModel):
    theoretical_target_pnl_sha256: Sha256 = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    fee_adjusted_pnl_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    execution_quality_interval_pnl_sha256: Sha256 = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    actual_simnow_calibration_pnl_sha256: Sha256 = Field(
        pattern=r"^[0-9a-f]{64}$"
    )


class CommodityCFastFourLayerPnlLedgerEntryDTO(StrictLedgerModel):
    schema_version: Literal["commodity_c_fast_four_layer_pnl_ledger_v1"]
    ledger_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    entry_id: str = Field(
        pattern=r"^cfast-pnl-entry-v1-[0-9a-f]{64}$"
    )
    entry_sequence: int = Field(ge=1, le=1_000_000)
    previous_entry_hash: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    entry_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    formula_target_binding_sha256: Sha256 = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    valuation_day: date
    created_at_utc: datetime
    virtual_nav_cny: Literal[20_000_000]
    theoretical_target_pnl: TheoreticalTargetPnlLayerDTO
    fee_adjusted_pnl: FeeAdjustedPnlLayerDTO
    execution_quality_interval_pnl: ExecutionQualityIntervalPnlLayerDTO
    actual_simnow_calibration_pnl: ActualSimNowCalibrationPnlLayerDTO
    layer_hashes: PnlLayerHashIndexDTO
    layer_isolation: Literal[
        "FOUR_LAYERS_APPEND_ONLY_NEVER_OVERWRITE_OR_COALESCE"
    ]
    audit_scope: Literal[
        "DETERMINISTIC_OFFLINE_RESEARCH_STRUCTURE_ONLY"
    ]
    countable_forward: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]

    @model_validator(mode="after")
    def validate_entry(
        self,
    ) -> "CommodityCFastFourLayerPnlLedgerEntryDTO":
        _require_utc(self.created_at_utc, "created_at_utc")
        if self.entry_sequence == 1:
            if self.previous_entry_hash is not None:
                raise ValueError("genesis entry must not have predecessor")
        elif self.previous_entry_hash is None:
            raise ValueError("non-genesis entry requires predecessor")
        layers = (
            self.theoretical_target_pnl,
            self.fee_adjusted_pnl,
            self.execution_quality_interval_pnl,
            self.actual_simnow_calibration_pnl,
        )
        if any(
            layer.snapshot_hash != self.snapshot_hash for layer in layers
        ):
            raise ValueError("all layers must bind the envelope snapshot")
        lineages = [
            layer.lineage
            for layer in layers
            if layer.lineage is not None
        ]
        if any(
            lineage.input_cutoff_at_utc > self.created_at_utc
            for lineage in lineages
        ):
            raise ValueError("entry created before a source cutoff")
        if self.theoretical_target_pnl.valuation_day != self.valuation_day:
            raise ValueError("theoretical valuation day mismatch")
        if (
            self.fee_adjusted_pnl.source_theoretical_layer_hash
            != self.theoretical_target_pnl.layer_hash
            or not _money_equal(
                self.fee_adjusted_pnl.source_theoretical_total_pnl_cny,
                self.theoretical_target_pnl.total_pnl_cny,
            )
        ):
            raise ValueError("fee layer theoretical binding mismatch")
        expected_layer_hashes = PnlLayerHashIndexDTO(
            theoretical_target_pnl_sha256=(
                self.theoretical_target_pnl.layer_hash
            ),
            fee_adjusted_pnl_sha256=self.fee_adjusted_pnl.layer_hash,
            execution_quality_interval_pnl_sha256=(
                self.execution_quality_interval_pnl.layer_hash
            ),
            actual_simnow_calibration_pnl_sha256=(
                self.actual_simnow_calibration_pnl.layer_hash
            ),
        )
        if self.layer_hashes != expected_layer_hashes:
            raise ValueError("layer hash index mismatch")
        entry_identity = {
            "ledger_id": self.ledger_id,
            "entry_sequence": self.entry_sequence,
            "snapshot_hash": self.snapshot_hash,
            "formula_target_binding_sha256": (
                self.formula_target_binding_sha256
            ),
            "valuation_day": self.valuation_day.isoformat(),
            "layer_hashes": self.layer_hashes.model_dump(mode="json"),
        }
        expected_entry_id = (
            f"cfast-pnl-entry-v1-{sha256_json(entry_identity)}"
        )
        if self.entry_id != expected_entry_id:
            raise ValueError("entry_id hash mismatch")
        entry_payload = self.model_dump(mode="json", exclude={"entry_hash"})
        if self.entry_hash != sha256_json(entry_payload):
            raise ValueError("entry_hash mismatch")
        return self


class CommodityCFastPnlLedgerAuditDTO(StrictLedgerModel):
    schema_version: Literal["commodity_c_fast_pnl_ledger_audit_v1"]
    ledger_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    entry_count: int = Field(ge=1, le=10_000)
    genesis_entry_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    chain_tip_entry_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    ordered_entry_hashes_sha256: Sha256 = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    audit_state: Literal[
        "PASS_DETERMINISTIC_STRUCTURE_AND_HASH_CHAIN_ONLY"
    ]
    actual_fact_entry_count: int = Field(ge=0, le=10_000)
    countable_forward: Literal[False]
    authority_granted: Literal[False]
    dispatch_allowed: Literal[False]
    replacement_allowed: Literal[False]
    production_allowed: Literal[False]


def _validate_layer_hash(layer: StrictLedgerModel) -> None:
    payload = layer.model_dump(mode="json", exclude={"layer_hash"})
    if getattr(layer, "layer_hash") != sha256_json(payload):
        raise ValueError("layer_hash mismatch")
