from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Context, Decimal, ROUND_HALF_EVEN, localcontext
from typing import Annotated, Any, Literal

from pydantic import (
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    model_validator,
)

from app.schemas.commodity_c_fast_shadow import StrictFiniteModel


Money = float
Sha256 = str
MAX_ABS_MONEY_CNY = 1_000_000_000_000.0
MAX_LEDGER_LOTS = 100_000
MONEY_CONTEXT = Context(prec=34, rounding=ROUND_HALF_EVEN)
MONEY_TOLERANCE = Decimal("0.000001")

SourceKind = Literal[
    "SIGNED_EXACT_TARGET_MARKS",
    "FEE_AND_STRESS_ASSUMPTIONS",
    "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS",
    "ACTUAL_SIMNOW_FACTS_NOT_PROVIDED",
    "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION",
]
FeeComponent = Literal[
    "official_exchange_fee",
    "broker_customer_fee",
    "preregistered_tick_stress",
    "roll_round_trip_cost",
]
FEE_COMPONENT_UNIVERSE = (
    "official_exchange_fee",
    "broker_customer_fee",
    "preregistered_tick_stress",
    "roll_round_trip_cost",
)


def _strict_false(value: Any) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("value must be the boolean literal false")
    return False


StrictFalse = Annotated[Literal[False], BeforeValidator(_strict_false)]


def sha256_json(value: Any) -> str:
    canonical = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _decimal(value: float | int) -> Decimal:
    with localcontext(MONEY_CONTEXT):
        return +Decimal(str(value))


def money_sum(*values: float) -> float:
    with localcontext(MONEY_CONTEXT):
        return float(sum((_decimal(value) for value in values), Decimal(0)))


def money_product(value: float, quantity: int) -> float:
    with localcontext(MONEY_CONTEXT):
        return float(_decimal(value) * Decimal(quantity))


def money_multiply(left: float, right: float) -> float:
    with localcontext(MONEY_CONTEXT):
        return float(_decimal(left) * _decimal(right))


def money_bounds(
    value_per_lot: float,
    quantity_lower: int,
    quantity_upper: int,
) -> tuple[float, float]:
    first = money_product(value_per_lot, quantity_lower)
    second = money_product(value_per_lot, quantity_upper)
    return min(first, second), max(first, second)


def _money_equal(left: float, right: float) -> bool:
    with localcontext(MONEY_CONTEXT):
        return abs(_decimal(left) - _decimal(right)) <= MONEY_TOLERANCE


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    if value.utcoffset().total_seconds() != 0:
        raise ValueError(f"{field} must use UTC")


def canonical_utc_json(value: datetime) -> str:
    _require_utc(value, "timestamp")
    return value.isoformat().replace("+00:00", "Z")


def parse_utc_string(value: str, field: str) -> datetime:
    try:
        normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    _require_utc(parsed, field)
    return parsed


class StrictLedgerModel(StrictFiniteModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        frozen=True,
    )


class PnlSourceFactsBaseDTO(StrictLedgerModel):
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    ledger_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    formula_target_binding_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    plan_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    valuation_day: date
    as_of_at_utc: datetime

    @model_validator(mode="after")
    def validate_source_time(self) -> "PnlSourceFactsBaseDTO":
        _require_utc(self.as_of_at_utc, "as_of_at_utc")
        return self


class TheoreticalTargetPnlSourceFactsDTO(PnlSourceFactsBaseDTO):
    schema_version: Literal[
        "commodity_c_fast_theoretical_target_pnl_source_facts_v1"
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


class FeeAdjustedPnlSourceFactsDTO(PnlSourceFactsBaseDTO):
    schema_version: Literal[
        "commodity_c_fast_fee_adjusted_pnl_source_facts_v2"
    ]
    fee_binding_state: Literal["BOUND", "UNBOUND_NOT_ASSUMED_ZERO"]
    fee_component_universe: tuple[FeeComponent, ...] = Field(
        min_length=4,
        max_length=4,
    )
    official_exchange_fee_rate: float | None = Field(
        default=None,
        ge=0,
        le=1,
    )
    official_exchange_turnover_cny: Money | None = Field(
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
    broker_customer_fee_rate: float | None = Field(
        default=None,
        ge=0,
        le=1,
    )
    broker_customer_turnover_cny: Money | None = Field(
        default=None,
        ge=0,
        le=MAX_ABS_MONEY_CNY,
    )
    fee_schedule_sha256: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    unbound_components: tuple[FeeComponent, ...] = Field(
        default=(),
        max_length=4,
    )

    @model_validator(mode="after")
    def validate_fee_source(self) -> "FeeAdjustedPnlSourceFactsDTO":
        if self.fee_component_universe != FEE_COMPONENT_UNIVERSE:
            raise ValueError(
                "fee component universe must be complete and frozen"
            )
        if len(set(self.unbound_components)) != len(self.unbound_components):
            raise ValueError("unbound_components must be unique")
        component_fields = {
            "official_exchange_fee": (
                self.official_exchange_fee_rate,
                self.official_exchange_turnover_cny,
            ),
            "broker_customer_fee": (
                self.broker_customer_fee_rate,
                self.broker_customer_turnover_cny,
            ),
            "preregistered_tick_stress": (self.preregistered_tick_stress_cny,),
            "roll_round_trip_cost": (self.roll_round_trip_cost_cny,),
        }
        if self.fee_binding_state == "UNBOUND_NOT_ASSUMED_ZERO":
            if not self.unbound_components:
                raise ValueError("UNBOUND requires named components")
            if self.fee_schedule_sha256 is not None:
                raise ValueError("UNBOUND must not claim a complete schedule")
            unbound = set(self.unbound_components)
            for component in self.fee_component_universe:
                values = component_fields[component]
                if component in unbound and any(
                    value is not None for value in values
                ):
                    raise ValueError(
                        f"{component} is UNBOUND and must remain null"
                    )
                if component not in unbound and any(
                    value is None for value in values
                ):
                    raise ValueError(
                        f"{component} is omitted from UNBOUND but incomplete"
                    )
        else:
            if self.unbound_components:
                raise ValueError("BOUND must not list unbound components")
            required = (
                self.official_exchange_fee_rate,
                self.official_exchange_turnover_cny,
                self.preregistered_tick_stress_cny,
                self.roll_round_trip_cost_cny,
                self.broker_customer_fee_rate,
                self.broker_customer_turnover_cny,
                self.fee_schedule_sha256,
            )
            if any(value is None for value in required):
                raise ValueError("BOUND requires every fee input")
        return self


class ExecutionQualityIntervalPnlSourceFactsDTO(PnlSourceFactsBaseDTO):
    schema_version: Literal[
        "commodity_c_fast_execution_quality_interval_pnl_source_facts_v1"
    ]
    fill_evidence_state: Literal[
        "FULL",
        "PARTIAL",
        "UNFILLED",
        "UNIDENTIFIED_BOUNDS_ONLY",
    ]
    planned_lots: int = Field(ge=1, le=MAX_LEDGER_LOTS)
    filled_lots_lower: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    filled_lots_upper: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    filled_lot_pnl_cny: Money = Field(
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
    unfilled_lot_opportunity_cost_cny: Money = Field(
        ge=0,
        le=MAX_ABS_MONEY_CNY,
    )
    marketable_book_walk_pnl_cny: Money | None = Field(
        default=None,
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )

    @model_validator(mode="after")
    def validate_fill_source(
        self,
    ) -> "ExecutionQualityIntervalPnlSourceFactsDTO":
        lower = self.filled_lots_lower
        upper = self.filled_lots_upper
        planned = self.planned_lots
        if not 0 <= lower <= upper <= planned:
            raise ValueError("filled lot bounds are invalid")
        if self.fill_evidence_state == "FULL":
            if lower != planned or upper != planned:
                raise ValueError("FULL requires exact planned fills")
        elif self.fill_evidence_state == "UNFILLED":
            if lower != 0 or upper != 0:
                raise ValueError("UNFILLED requires exact zero fills")
        elif self.fill_evidence_state == "PARTIAL":
            if upper <= 0 or upper >= planned:
                raise ValueError(
                    "PARTIAL requires 0 <= lower <= upper < planned"
                )
        elif lower >= upper:
            raise ValueError("UNIDENTIFIED requires a non-point fill interval")
        return self


class ActualSimNowNotProvidedSourceFactsDTO(PnlSourceFactsBaseDTO):
    schema_version: Literal[
        "commodity_c_fast_actual_simnow_not_provided_source_facts_v1"
    ]
    actual_state: Literal["NOT_PROVIDED"]


class ActualSimNowFactsDTO(PnlSourceFactsBaseDTO):
    schema_version: Literal["commodity_c_fast_actual_simnow_facts_v3"]
    actual_state: Literal["FACTS_BOUND"]
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
    execution_state_checksum: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    execution_state_checksum_verification_state: Literal[
        "ARCHIVE_REFERENCE_ONLY_CORE_NOT_EMBEDDED"
    ]
    terminal_checksum: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_status: Literal[
        "COMPLETE",
        "HALTED_RECONCILED",
        "INCOMPLETE",
        "INCONSISTENT",
    ]
    terminal_reconciliation_complete: StrictBool
    terminal_completed_at_utc: str | None = Field(
        default=None,
        min_length=20,
        max_length=40,
    )
    valuation_at_utc: datetime
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
    actual_amount_verification_state: Literal[
        "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS"
    ]
    countable_forward: StrictFalse
    production_allowed: StrictFalse

    @model_validator(mode="after")
    def validate_actual_facts(self) -> "ActualSimNowFactsDTO":
        _require_utc(self.valuation_at_utc, "valuation_at_utc")
        _require_utc(
            self.execution_captured_at_utc,
            "execution_captured_at_utc",
        )
        terminal_completed_at = (
            parse_utc_string(
                self.terminal_completed_at_utc,
                "terminal_completed_at_utc",
            )
            if self.terminal_completed_at_utc is not None
            else None
        )
        if self.filled_lots > self.expected_lots:
            raise ValueError("filled_lots exceeds expected_lots")
        terminal_payload = {
            "session_id": self.session_id,
            "plan_hash": self.plan_hash,
            "status": self.terminal_status,
            "completed_at_utc": self.terminal_completed_at_utc,
            "execution_state_checksum": self.execution_state_checksum,
        }
        if self.terminal_checksum != sha256_json(terminal_payload):
            raise ValueError("terminal_checksum mismatch")
        fully_reconciled = (
            self.trade_evidence_state == "COMPLETE"
            and self.terminal_status == "COMPLETE"
            and self.terminal_reconciliation_complete
            and terminal_completed_at is not None
            and self.expected_lots > 0
            and self.filled_lots == self.expected_lots
            and self.order_outcome == "FULL_FILL"
        )
        if (
            self.trade_evidence_state != "COMPLETE"
            and self.terminal_status == "COMPLETE"
        ):
            raise ValueError(
                "terminal COMPLETE cannot retain incomplete trade evidence"
            )
        if self.trade_evidence_state == "COMPLETE" and not fully_reconciled:
            raise ValueError(
                "COMPLETE requires full fill and terminal reconciliation"
            )
        if self.valuation_at_utc.date() != self.valuation_day:
            raise ValueError("valuation_at_utc does not match valuation_day")
        if self.execution_captured_at_utc < self.valuation_at_utc:
            raise ValueError("execution capture precedes valuation")
        if (
            terminal_completed_at is not None
            and terminal_completed_at < self.execution_captured_at_utc
        ):
            raise ValueError("terminal completion precedes execution capture")
        if self.as_of_at_utc < self.execution_captured_at_utc:
            raise ValueError("actual as-of precedes execution capture")
        if (
            terminal_completed_at is not None
            and self.as_of_at_utc < terminal_completed_at
        ):
            raise ValueError("actual as-of precedes terminal completion")
        return self


ActualSourceFactsDTO = (
    ActualSimNowNotProvidedSourceFactsDTO | ActualSimNowFactsDTO
)


class PnlSourceLineageDTO(StrictLedgerModel):
    schema_version: Literal["commodity_c_fast_pnl_source_lineage_v2"]
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
    schema_version: Literal["commodity_c_fast_theoretical_target_pnl_layer_v2"]
    layer_kind: Literal["THEORETICAL_TARGET_PNL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_facts: TheoreticalTargetPnlSourceFactsDTO
    lineage: PnlSourceLineageDTO
    valuation_day: date
    position_basis: Literal[
        "OBSERVED_VIRTUAL_FILL_STATE_NEVER_ASSUME_UNFILLED_TARGET"
    ]
    held_lots: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    pending_virtual_lots: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    realized_pnl_cny: Money
    unrealized_pnl_cny: Money
    roll_pnl_cny: Money
    total_pnl_cny: Money
    layer_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_theoretical(self) -> "TheoreticalTargetPnlLayerDTO":
        if self.lineage.source_kind != "SIGNED_EXACT_TARGET_MARKS":
            raise ValueError("theoretical lineage source kind mismatch")
        facts = self.source_facts
        expected = money_sum(
            facts.realized_pnl_cny,
            facts.unrealized_pnl_cny,
            facts.roll_pnl_cny,
        )
        values_match = (
            self.valuation_day == facts.valuation_day
            and self.held_lots == facts.held_lots
            and self.pending_virtual_lots == facts.pending_virtual_lots
            and _money_equal(
                self.realized_pnl_cny,
                facts.realized_pnl_cny,
            )
            and _money_equal(
                self.unrealized_pnl_cny,
                facts.unrealized_pnl_cny,
            )
            and _money_equal(self.roll_pnl_cny, facts.roll_pnl_cny)
            and _money_equal(self.total_pnl_cny, expected)
        )
        if not values_match:
            raise ValueError("theoretical layer is not derived from facts")
        _validate_source_lineage(self.source_facts, self.lineage)
        _validate_layer_hash(self)
        return self


class FeeAdjustedPnlLayerDTO(StrictLedgerModel):
    schema_version: Literal["commodity_c_fast_fee_adjusted_pnl_layer_v2"]
    layer_kind: Literal["FEE_ADJUSTED_PNL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_facts: FeeAdjustedPnlSourceFactsDTO
    lineage: PnlSourceLineageDTO
    source_theoretical_layer_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_theoretical_total_pnl_cny: Money
    fee_binding_state: Literal["BOUND", "UNBOUND_NOT_ASSUMED_ZERO"]
    official_exchange_fee_cny: Money | None = None
    broker_customer_fee_cny: Money | None = None
    preregistered_tick_stress_cny: Money | None = None
    roll_round_trip_cost_cny: Money | None = None
    all_in_cost_cny: Money | None = None
    fee_adjusted_total_pnl_cny: Money | None = None
    layer_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_fee_adjusted(self) -> "FeeAdjustedPnlLayerDTO":
        if self.lineage.source_kind != "FEE_AND_STRESS_ASSUMPTIONS":
            raise ValueError("fee lineage source kind mismatch")
        if self.fee_binding_state != self.source_facts.fee_binding_state:
            raise ValueError("fee state is not derived from facts")
        facts = self.source_facts
        expected_components = (
            None
            if facts.official_exchange_fee_rate is None
            else money_multiply(
                facts.official_exchange_fee_rate,
                float(facts.official_exchange_turnover_cny),
            ),
            None
            if facts.broker_customer_fee_rate is None
            else money_multiply(
                facts.broker_customer_fee_rate,
                float(facts.broker_customer_turnover_cny),
            ),
            facts.preregistered_tick_stress_cny,
            facts.roll_round_trip_cost_cny,
        )
        actual_components = (
            self.official_exchange_fee_cny,
            self.broker_customer_fee_cny,
            self.preregistered_tick_stress_cny,
            self.roll_round_trip_cost_cny,
        )
        if any(
            (expected is None) != (actual is None)
            or (
                expected is not None
                and actual is not None
                and not _money_equal(actual, expected)
            )
            for actual, expected in zip(actual_components, expected_components)
        ):
            raise ValueError("fee components are not derived from facts")
        if self.fee_binding_state == "UNBOUND_NOT_ASSUMED_ZERO":
            if (
                self.all_in_cost_cny is not None
                or self.fee_adjusted_total_pnl_cny is not None
            ):
                raise ValueError("UNBOUND must not publish all-in/net")
        else:
            costs = actual_components
            if any(value is None for value in costs):
                raise ValueError("BOUND facts lost a fee amount")
            expected_cost = money_sum(
                *(float(value) for value in costs if value is not None)
            )
            expected_total = money_sum(
                self.source_theoretical_total_pnl_cny,
                -expected_cost,
            )
            if (
                self.all_in_cost_cny is None
                or self.fee_adjusted_total_pnl_cny is None
                or not _money_equal(self.all_in_cost_cny, expected_cost)
                or not _money_equal(
                    self.fee_adjusted_total_pnl_cny,
                    expected_total,
                )
            ):
                raise ValueError("fee output is not derived from facts")
        _validate_source_lineage(self.source_facts, self.lineage)
        _validate_layer_hash(self)
        return self


class ExecutionQualityIntervalPnlLayerDTO(StrictLedgerModel):
    schema_version: Literal[
        "commodity_c_fast_execution_quality_interval_pnl_layer_v2"
    ]
    layer_kind: Literal["EXECUTION_QUALITY_INTERVAL_PNL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_facts: ExecutionQualityIntervalPnlSourceFactsDTO
    lineage: PnlSourceLineageDTO
    fill_evidence_state: Literal[
        "FULL",
        "PARTIAL",
        "UNFILLED",
        "UNIDENTIFIED_BOUNDS_ONLY",
    ]
    point_fill_probability_state: Literal["FORBIDDEN_UNCALIBRATED_BOUNDS_ONLY"]
    planned_lots: int
    filled_lots_lower: int
    filled_lots_upper: int
    unfilled_lots_lower: int
    unfilled_lots_upper: int
    marketable_book_walk_pnl_cny: Money | None = None
    conservative_fill_lower_bound_pnl_cny: Money
    optimistic_fill_upper_bound_pnl_cny: Money
    opportunity_cost_lower_bound_cny: Money
    opportunity_cost_upper_bound_cny: Money
    layer_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_interval(self) -> "ExecutionQualityIntervalPnlLayerDTO":
        if (
            self.lineage.source_kind
            != "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS"
        ):
            raise ValueError("execution lineage source kind mismatch")
        facts = self.source_facts
        unfilled_lower = facts.planned_lots - facts.filled_lots_upper
        unfilled_upper = facts.planned_lots - facts.filled_lots_lower
        pnl_lower, pnl_upper = money_bounds(
            facts.filled_lot_pnl_cny,
            facts.filled_lots_lower,
            facts.filled_lots_upper,
        )
        opportunity_lower, opportunity_upper = money_bounds(
            facts.unfilled_lot_opportunity_cost_cny,
            unfilled_lower,
            unfilled_upper,
        )
        values_match = (
            self.fill_evidence_state == facts.fill_evidence_state
            and self.planned_lots == facts.planned_lots
            and self.filled_lots_lower == facts.filled_lots_lower
            and self.filled_lots_upper == facts.filled_lots_upper
            and self.unfilled_lots_lower == unfilled_lower
            and self.unfilled_lots_upper == unfilled_upper
            and self.marketable_book_walk_pnl_cny
            == facts.marketable_book_walk_pnl_cny
            and _money_equal(
                self.conservative_fill_lower_bound_pnl_cny,
                pnl_lower,
            )
            and _money_equal(
                self.optimistic_fill_upper_bound_pnl_cny,
                pnl_upper,
            )
            and _money_equal(
                self.opportunity_cost_lower_bound_cny,
                opportunity_lower,
            )
            and _money_equal(
                self.opportunity_cost_upper_bound_cny,
                opportunity_upper,
            )
        )
        if not values_match:
            raise ValueError("execution interval is not derived from facts")
        _validate_source_lineage(self.source_facts, self.lineage)
        _validate_layer_hash(self)
        return self


class ActualSimNowCalibrationPnlLayerDTO(StrictLedgerModel):
    schema_version: Literal[
        "commodity_c_fast_actual_simnow_calibration_pnl_layer_v2"
    ]
    layer_kind: Literal["ACTUAL_SIMNOW_CALIBRATION_PNL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_facts: ActualSourceFactsDTO
    lineage: PnlSourceLineageDTO
    actual_state: Literal["NOT_PROVIDED", "FACTS_BOUND"]
    stable_actual_fact_identity_sha256: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    actual_amount_verification_state: Literal[
        "NOT_PROVIDED",
        "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS",
    ]
    gross_execution_pnl_cny: Literal[None] = None
    adverse_slippage_cny: Literal[None] = None
    fees_state: Literal[
        "NOT_AVAILABLE",
        "UNVERIFIED",
    ]
    actual_fees_cny: Literal[None] = None
    net_pnl_state: Literal[
        "NOT_AVAILABLE",
        "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS",
    ]
    actual_net_pnl_cny: Literal[None] = None
    countable_forward: StrictFalse
    layer_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_actual(self) -> "ActualSimNowCalibrationPnlLayerDTO":
        facts = self.source_facts
        if isinstance(facts, ActualSimNowNotProvidedSourceFactsDTO):
            if self.actual_state != "NOT_PROVIDED":
                raise ValueError("actual state is not derived from facts")
            expected = (
                None,
                "NOT_PROVIDED",
                None,
                None,
                "NOT_AVAILABLE",
                None,
                "NOT_AVAILABLE",
                None,
            )
        else:
            if self.actual_state != "FACTS_BOUND":
                raise ValueError("actual state is not derived from facts")
            stable_identity = sha256_json(
                {
                    "snapshot_hash": facts.snapshot_hash,
                    "plan_hash": facts.plan_hash,
                    "session_id": facts.session_id,
                    "terminal_checksum": facts.terminal_checksum,
                }
            )
            expected = (
                stable_identity,
                facts.actual_amount_verification_state,
                None,
                None,
                "UNVERIFIED",
                None,
                ("UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS"),
                None,
            )
        actual = (
            self.stable_actual_fact_identity_sha256,
            self.actual_amount_verification_state,
            self.gross_execution_pnl_cny,
            self.adverse_slippage_cny,
            self.fees_state,
            self.actual_fees_cny,
            self.net_pnl_state,
            self.actual_net_pnl_cny,
        )
        if actual != expected:
            raise ValueError("actual layer is not derived from facts")
        _validate_source_lineage(self.source_facts, self.lineage)
        _validate_layer_hash(self)
        return self


class PnlLayerHashIndexDTO(StrictLedgerModel):
    theoretical_target_pnl_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fee_adjusted_pnl_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    execution_quality_interval_pnl_sha256: Sha256 = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    actual_simnow_calibration_pnl_sha256: Sha256 = Field(
        pattern=r"^[0-9a-f]{64}$"
    )


class CommodityCFastFourLayerPnlLedgerEntryDTO(StrictLedgerModel):
    schema_version: Literal["commodity_c_fast_four_layer_pnl_ledger_v2"]
    ledger_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    entry_id: str = Field(pattern=r"^cfast-pnl-entry-v2-[0-9a-f]{64}$")
    entry_sequence: int = Field(ge=1, le=1_000_000)
    previous_entry_hash: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    entry_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_id: Literal["C_FAST_CROSS_SECTION_NEUTRAL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    formula_target_binding_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    plan_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
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
    audit_scope: Literal["DETERMINISTIC_OFFLINE_RESEARCH_STRUCTURE_ONLY"]
    countable_forward: StrictFalse
    authority_granted: StrictFalse
    dispatch_allowed: StrictFalse
    replacement_allowed: StrictFalse
    production_allowed: StrictFalse

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
        for layer in layers:
            facts = layer.source_facts
            identity = (
                facts.candidate_id == self.candidate_id
                and facts.ledger_id == self.ledger_id
                and facts.snapshot_hash == self.snapshot_hash
                and facts.formula_target_binding_sha256
                == self.formula_target_binding_sha256
                and facts.plan_hash == self.plan_hash
                and facts.valuation_day == self.valuation_day
                and facts.as_of_at_utc <= self.created_at_utc
                and layer.snapshot_hash == self.snapshot_hash
            )
            if not identity:
                raise ValueError("source facts envelope binding mismatch")
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
            "plan_hash": self.plan_hash,
            "valuation_day": self.valuation_day.isoformat(),
            "layer_hashes": self.layer_hashes.model_dump(mode="json"),
        }
        expected_entry_id = f"cfast-pnl-entry-v2-{sha256_json(entry_identity)}"
        if self.entry_id != expected_entry_id:
            raise ValueError("entry_id hash mismatch")
        entry_payload = self.model_dump(mode="json", exclude={"entry_hash"})
        if self.entry_hash != sha256_json(entry_payload):
            raise ValueError("entry_hash mismatch")
        return self


class CommodityCFastPnlLedgerAuditDTO(StrictLedgerModel):
    schema_version: Literal["commodity_c_fast_pnl_ledger_audit_v2"]
    ledger_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    entry_count: int = Field(ge=1, le=10_000)
    genesis_entry_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    chain_tip_entry_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    ordered_entry_hashes_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    audit_state: Literal["PASS_FRESH_REPLAY_STRUCTURE_AND_HASH_CHAIN_ONLY"]
    actual_fact_entry_count: int = Field(ge=0, le=10_000)
    external_genesis_anchor_state: Literal["NOT_PROVIDED_STRUCTURE_ONLY"]
    external_tip_anchor_state: Literal["NOT_PROVIDED_STRUCTURE_ONLY"]
    countable_forward: StrictFalse
    authority_granted: StrictFalse
    dispatch_allowed: StrictFalse
    replacement_allowed: StrictFalse
    production_allowed: StrictFalse


def _validate_source_lineage(
    source_facts: PnlSourceFactsBaseDTO,
    lineage: PnlSourceLineageDTO,
) -> None:
    source_hash = sha256_json(source_facts.model_dump(mode="json"))
    if (
        lineage.source_artifact_sha256 != source_hash
        or lineage.source_payload_sha256 != source_hash
        or lineage.input_cutoff_at_utc != source_facts.as_of_at_utc
    ):
        raise ValueError("lineage is not bound to embedded source facts")


def _validate_layer_hash(layer: StrictLedgerModel) -> None:
    payload = layer.model_dump(mode="json", exclude={"layer_hash"})
    if getattr(layer, "layer_hash") != sha256_json(payload):
        raise ValueError("layer_hash mismatch")
