from __future__ import annotations

import hashlib
import json
import math
from datetime import date, datetime, time, timedelta, timezone
from decimal import Context, Decimal, ROUND_HALF_EVEN, localcontext
from typing import Annotated, Any, Literal

from pydantic import (
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    model_validator,
)

from app.schemas.commodity_c_fast_fee_statement import (
    CommodityCFastFeeBindingEvidenceDTO,
    verify_fee_statement_and_calculate,
)
from app.schemas.commodity_c_fast_shadow import StrictFiniteModel


Money = float
Sha256 = str
MAX_ABS_MONEY_CNY = 1_000_000_000_000.0
MAX_LEDGER_LOTS = 100_000
MONEY_CONTEXT = Context(prec=34, rounding=ROUND_HALF_EVEN)
MONEY_TOLERANCE = Decimal("0.000001")
CNY_CENT = Decimal("0.01")

SourceKind = Literal[
    "SIGNED_EXACT_TARGET_MARKS",
    "FEE_AND_STRESS_ASSUMPTIONS",
    "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS",
    "ACTUAL_SIMNOW_FACTS_NOT_PROVIDED",
    "SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION",
    "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND",
    "SIMNOW_SETTLED_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND",
    "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEE_STATEMENT_BOUND",
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


def money_cent_sum(*values: float) -> float:
    """Add money in Decimal and publish exactly at CNY-cent precision."""

    with localcontext(MONEY_CONTEXT):
        return float(
            sum((_decimal(value) for value in values), Decimal(0)).quantize(
                CNY_CENT,
                rounding=ROUND_HALF_EVEN,
            )
        )


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


def _valuation_belongs_to_trading_day(
    valuation_day: date,
    valuation_at_utc: datetime,
) -> bool:
    """Accept China day session or a bounded prior night-session lineage."""

    local = valuation_at_utc.astimezone(
        timezone(timedelta(hours=8))
    )
    day_gap = (valuation_day - local.date()).days
    return day_gap == 0 or (
        1 <= day_gap <= 3 and local.time() >= time(20, 0)
    )


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
    schema_version: Literal["commodity_c_fast_theoretical_target_pnl_source_facts_v1"]
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
    schema_version: Literal["commodity_c_fast_fee_adjusted_pnl_source_facts_v2"]
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
            raise ValueError("fee component universe must be complete and frozen")
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
                if component in unbound and any(value is not None for value in values):
                    raise ValueError(f"{component} is UNBOUND and must remain null")
                if component not in unbound and any(value is None for value in values):
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
                raise ValueError("PARTIAL requires 0 <= lower <= upper < planned")
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
    fact_source: Literal["SIMNOW_AUTHORITATIVE_ORDER_TRADE_POSITION_RECONCILIATION"]
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
            raise ValueError("COMPLETE requires full fill and terminal reconciliation")
        if not _valuation_belongs_to_trading_day(
            self.valuation_day,
            self.valuation_at_utc,
        ):
            raise ValueError("valuation_at_utc is outside trading-day session")
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


class ActualSimNowPinnedArchiveReplayFactsDTO(PnlSourceFactsBaseDTO):
    """Unattested local full-fill archive replay; fees stay unbound."""

    schema_version: Literal["commodity_c_fast_actual_simnow_facts_v4"]
    actual_state: Literal["LOCAL_ARCHIVE_REPLAYED_UNATTESTED"]
    fact_source: Literal["SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND"]
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
        "FULL_EMBEDDED_SESSION_ARCHIVE_FRESH_REPLAY"
    ]
    terminal_checksum: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_status: Literal["COMPLETE"]
    terminal_reconciliation_complete: StrictBool
    terminal_completed_at_utc: str = Field(min_length=20, max_length=40)
    valuation_at_utc: datetime
    execution_captured_at_utc: datetime
    expected_lots: int = Field(ge=1, le=MAX_LEDGER_LOTS)
    filled_lots: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    order_outcome: Literal["FULL_FILL"]
    trade_evidence_state: Literal["COMPLETE"]
    mark_source: Literal["CURRENT_L1_MID"]
    fee_binding_state: Literal["UNBOUND_NOT_ASSUMED_ZERO"]
    fee_source_state: Literal["NOT_AVAILABLE_IN_SESSION_ARCHIVE"]
    session_archive_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    session_archive_raw_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    archive_chain_tip_terminal_checksum: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    archive_predecessor_terminal_checksum: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    archive_custody_verification_state: Literal[
        "LOCAL_FILE_AND_LINEAR_CHAIN_CHECKED_NO_EXTERNAL_AUTHORITY"
    ]
    external_fact_authority_state: Literal["NOT_PROVIDED_STRUCTURE_ONLY"]
    session_archive: dict[str, Any]
    actual_amount_verification_state: Literal[
        "GROSS_AND_SLIPPAGE_REPLAYED_FROM_SESSION_ARCHIVE_FEES_UNBOUND"
    ]
    countable_forward: StrictFalse
    production_allowed: StrictFalse

    @model_validator(mode="after")
    def validate_pinned_archive_facts(
        self,
    ) -> "ActualSimNowPinnedArchiveReplayFactsDTO":
        if self.terminal_reconciliation_complete is not True:
            raise ValueError("archive replay requires terminal reconciliation")
        if self.filled_lots != self.expected_lots:
            raise ValueError("v4 archive replay is limited to full fills")
        if self.archive_chain_tip_terminal_checksum != self.terminal_checksum:
            raise ValueError("v4 archive session is not the pinned chain tip")
        _require_utc(self.valuation_at_utc, "valuation_at_utc")
        _require_utc(
            self.execution_captured_at_utc,
            "execution_captured_at_utc",
        )
        terminal_completed_at = parse_utc_string(
            self.terminal_completed_at_utc,
            "terminal_completed_at_utc",
        )
        terminal_payload = {
            "session_id": self.session_id,
            "plan_hash": self.plan_hash,
            "status": self.terminal_status,
            "completed_at_utc": self.terminal_completed_at_utc,
            "execution_state_checksum": self.execution_state_checksum,
        }
        if self.terminal_checksum != sha256_json(terminal_payload):
            raise ValueError("terminal_checksum mismatch")
        if not _valuation_belongs_to_trading_day(
            self.valuation_day,
            self.valuation_at_utc,
        ):
            raise ValueError("valuation_at_utc is outside trading-day session")
        if not (
            self.valuation_at_utc
            <= self.execution_captured_at_utc
            <= terminal_completed_at
            <= self.as_of_at_utc
        ):
            raise ValueError("archive replay time causality is invalid")

        replay = replay_actual_simnow_session_archive(self)
        expected = (
            self.session_id,
            self.account_sha256,
            self.orders_sha256,
            self.trades_sha256,
            self.positions_sha256,
            self.reconciliation_sha256,
            self.execution_state_checksum,
            self.terminal_checksum,
            self.terminal_status,
            self.terminal_completed_at_utc,
            self.valuation_at_utc,
            self.execution_captured_at_utc,
            self.expected_lots,
            self.filled_lots,
            self.order_outcome,
        )
        if replay[:15] != expected:
            raise ValueError("session archive replay summary mismatch")
        return self


class ActualSimNowSettledArchiveReplayFactsDTO(PnlSourceFactsBaseDTO):
    """Terminal-reconciled archive replay, including non-full outcomes."""

    schema_version: Literal["commodity_c_fast_actual_simnow_settled_archive_facts_v1"]
    actual_state: Literal["LOCAL_SETTLED_ARCHIVE_REPLAYED"]
    fact_source: Literal[
        "SIMNOW_SETTLED_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEES_UNBOUND"
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
    terminal_checksum: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_status: Literal["COMPLETE", "HALTED_RECONCILED"]
    terminal_reconciliation_complete: StrictBool
    terminal_completed_at_utc: str = Field(min_length=20, max_length=40)
    valuation_at_utc: datetime
    execution_captured_at_utc: datetime
    expected_lots: int = Field(ge=1, le=MAX_LEDGER_LOTS)
    filled_lots: int = Field(ge=0, le=MAX_LEDGER_LOTS)
    order_outcome: Literal[
        "FULL_FILL",
        "PARTIAL_FILL",
        "UNFILLED_CANCELLED",
        "REJECTED",
        "TIMEOUT_OR_RESULT_UNKNOWN",
    ]
    unknown_outcome_settlement_state: Literal[
        "NOT_APPLICABLE",
        "SETTLED_BY_TERMINAL_RAW_FACTS_AND_POSITION_RECONCILIATION",
    ]
    mark_source: Literal["CURRENT_L1_MID", "NOT_REQUIRED_ZERO_FILL"]
    session_archive_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    session_archive_raw_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    archive_chain_tip_terminal_checksum: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    archive_predecessor_terminal_checksum: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    archive_custody_verification_state: Literal[
        "LOCAL_FILE_AND_LINEAR_CHAIN_CHECKED_NO_EXTERNAL_AUTHORITY"
    ]
    external_fact_authority_state: Literal["NOT_PROVIDED_STRUCTURE_ONLY"]
    session_archive: dict[str, Any]
    actual_amount_verification_state: Literal[
        "GROSS_AND_SLIPPAGE_REPLAYED_FROM_SESSION_ARCHIVE_FEES_UNBOUND"
    ]
    countable_forward: StrictFalse
    production_allowed: StrictFalse

    @model_validator(mode="after")
    def validate_settled_archive(
        self,
    ) -> "ActualSimNowSettledArchiveReplayFactsDTO":
        if self.terminal_reconciliation_complete is not True:
            raise ValueError("settled archive requires terminal reconciliation")
        if (
            self.order_outcome != "FULL_FILL"
            and self.terminal_status != "HALTED_RECONCILED"
        ):
            raise ValueError(
                "non-full settled archive requires HALTED_RECONCILED terminal"
            )
        if self.archive_chain_tip_terminal_checksum != self.terminal_checksum:
            raise ValueError("settled archive session is not the pinned chain tip")
        if (
            self.order_outcome == "TIMEOUT_OR_RESULT_UNKNOWN"
            and self.unknown_outcome_settlement_state
            != "SETTLED_BY_TERMINAL_RAW_FACTS_AND_POSITION_RECONCILIATION"
        ) or (
            self.order_outcome != "TIMEOUT_OR_RESULT_UNKNOWN"
            and self.unknown_outcome_settlement_state != "NOT_APPLICABLE"
        ):
            raise ValueError("unknown outcome settlement state mismatch")
        if self.mark_source != (
            "CURRENT_L1_MID" if self.filled_lots else "NOT_REQUIRED_ZERO_FILL"
        ):
            raise ValueError("settled archive mark source mismatch")
        _require_utc(self.valuation_at_utc, "valuation_at_utc")
        _require_utc(self.execution_captured_at_utc, "execution_captured_at_utc")
        archive_day = str(self.session_archive.get("signed_execution_day") or "")
        if archive_day != self.valuation_day.isoformat() or not (
            _valuation_belongs_to_trading_day(
                self.valuation_day,
                self.valuation_at_utc,
            )
        ):
            raise ValueError("settled archive valuation day is misdated")
        completed = parse_utc_string(
            self.terminal_completed_at_utc,
            "terminal_completed_at_utc",
        )
        if not (
            self.valuation_at_utc
            <= self.execution_captured_at_utc
            <= completed
            <= self.as_of_at_utc
        ):
            raise ValueError("settled archive time causality is invalid")
        replay = replay_settled_actual_simnow_session_archive(self)
        expected = (
            self.session_id,
            self.account_sha256,
            self.orders_sha256,
            self.trades_sha256,
            self.positions_sha256,
            self.reconciliation_sha256,
            self.execution_state_checksum,
            self.terminal_checksum,
            self.terminal_status,
            self.terminal_completed_at_utc,
            self.valuation_at_utc,
            self.execution_captured_at_utc,
            self.expected_lots,
            self.filled_lots,
            self.order_outcome,
        )
        if replay[:15] != expected:
            raise ValueError("settled session archive replay summary mismatch")
        return self


class ActualSimNowFeeBoundArchiveReplayFactsDTO(PnlSourceFactsBaseDTO):
    """Exact archive replay plus a separately signed fee statement."""

    schema_version: Literal["commodity_c_fast_actual_simnow_facts_v5"]
    actual_state: Literal["LOCAL_ARCHIVE_REPLAYED_FEE_BOUND"]
    fact_source: Literal[
        "SIMNOW_SESSION_ARCHIVE_RAW_TRADE_MARK_REPLAY_FEE_STATEMENT_BOUND"
    ]
    execution_lane: Literal["simnow_shakedown"]
    session_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    account_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    archive_replay: ActualSimNowSettledArchiveReplayFactsDTO
    fee_binding: CommodityCFastFeeBindingEvidenceDTO
    actual_amount_verification_state: Literal[
        "GROSS_SLIPPAGE_FEES_AND_NET_REPLAYED_FROM_EXACT_BOUND_SOURCES"
    ]
    archive_fact_authority_state: Literal[
        "LOCAL_FILE_AND_LINEAR_CHAIN_CHECKED_NO_EXTERNAL_AUTHORITY"
    ]
    fee_fact_authority_state: Literal["SIGNED_FEE_STATEMENT_VERIFIED_SEPARATE_DOMAIN"]
    countable_forward: StrictFalse
    authority_granted: StrictFalse
    dispatch_allowed: StrictFalse
    production_allowed: StrictFalse

    @model_validator(mode="after")
    def validate_fee_bound_archive(
        self,
    ) -> "ActualSimNowFeeBoundArchiveReplayFactsDTO":
        archive = self.archive_replay
        common = (
            self.candidate_id,
            self.ledger_id,
            self.snapshot_hash,
            self.formula_target_binding_sha256,
            self.plan_hash,
            self.valuation_day,
            self.as_of_at_utc,
        )
        archive_common = (
            archive.candidate_id,
            archive.ledger_id,
            archive.snapshot_hash,
            archive.formula_target_binding_sha256,
            archive.plan_hash,
            archive.valuation_day,
            archive.as_of_at_utc,
        )
        if common != archive_common:
            raise ValueError("fee-bound facts splice a different archive identity")
        if (
            self.session_id != archive.session_id
            or self.account_sha256 != archive.account_sha256
        ):
            raise ValueError("fee-bound session/account identity mismatch")
        if self.fee_binding.statement.trading_day != archive.valuation_day:
            raise ValueError("fee statement trading day mismatches archive valuation")
        if (
            parse_utc_string(
                self.fee_binding.verified_at_utc,
                "fee_binding.verified_at_utc",
            )
            > self.as_of_at_utc
        ):
            raise ValueError("fee verification occurs after actual as-of")
        replayed = verify_fee_statement_and_calculate(
            statement=self.fee_binding.statement,
            trusted_keyring=self.fee_binding.trusted_keyring,
            statement_raw_sha256=self.fee_binding.statement_raw_sha256,
            trusted_keyring_raw_sha256=(self.fee_binding.trusted_keyring_raw_sha256),
            excluded_authority_keyring_raw_sha256s=(
                self.fee_binding.excluded_authority_keyring_raw_sha256s
            ),
            excluded_authority_public_key_sha256s=(
                self.fee_binding.excluded_authority_public_key_sha256s
            ),
            verified_at_utc=self.fee_binding.verified_at_utc,
            archive_facts=archive.model_dump(mode="json"),
        )
        if replayed != self.fee_binding:
            raise ValueError("fee binding does not fresh-replay from archive")
        return self


ActualSourceFactsDTO = (
    ActualSimNowNotProvidedSourceFactsDTO
    | ActualSimNowFactsDTO
    | ActualSimNowPinnedArchiveReplayFactsDTO
    | ActualSimNowSettledArchiveReplayFactsDTO
    | ActualSimNowFeeBoundArchiveReplayFactsDTO
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
    position_basis: Literal["OBSERVED_VIRTUAL_FILL_STATE_NEVER_ASSUME_UNFILLED_TARGET"]
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
    schema_version: Literal["commodity_c_fast_execution_quality_interval_pnl_layer_v2"]
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
        if self.lineage.source_kind != "EXECUTION_QUALITY_BOOK_WALK_FILL_BOUNDS":
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
            and self.marketable_book_walk_pnl_cny == facts.marketable_book_walk_pnl_cny
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
        "commodity_c_fast_actual_simnow_calibration_pnl_layer_v2",
        "commodity_c_fast_actual_simnow_calibration_pnl_layer_v3",
        "commodity_c_fast_actual_simnow_calibration_pnl_layer_v4",
        "commodity_c_fast_actual_simnow_calibration_pnl_layer_v5",
    ]
    layer_kind: Literal["ACTUAL_SIMNOW_CALIBRATION_PNL"]
    snapshot_hash: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    source_facts: ActualSourceFactsDTO
    lineage: PnlSourceLineageDTO
    actual_state: Literal[
        "NOT_PROVIDED",
        "FACTS_BOUND",
        "LOCAL_ARCHIVE_REPLAYED_UNATTESTED",
        "LOCAL_SETTLED_ARCHIVE_REPLAYED_FEES_UNBOUND",
        "LOCAL_ARCHIVE_REPLAYED_FEE_BOUND",
    ]
    stable_actual_fact_identity_sha256: Sha256 | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    actual_amount_verification_state: Literal[
        "NOT_PROVIDED",
        "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS",
        "GROSS_AND_SLIPPAGE_REPLAYED_FROM_SESSION_ARCHIVE_FEES_UNBOUND",
        "GROSS_SLIPPAGE_FEES_AND_NET_REPLAYED_FROM_EXACT_BOUND_SOURCES",
    ]
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
    official_exchange_fee_cny: Money | None = Field(
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
    fees_state: Literal[
        "NOT_AVAILABLE",
        "UNVERIFIED",
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
        "UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS",
        "UNAVAILABLE_UNTIL_AUTHORITATIVE_FEES_BOUND",
        "BOUND_AUTHORITATIVE_FEE_STATEMENT",
    ]
    actual_net_pnl_cny: Money | None = Field(
        default=None,
        ge=-MAX_ABS_MONEY_CNY,
        le=MAX_ABS_MONEY_CNY,
    )
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
                None,
                None,
                None,
                "NOT_AVAILABLE",
                None,
                "NOT_AVAILABLE",
                None,
            )
        elif isinstance(facts, ActualSimNowFactsDTO):
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
                None,
                None,
                None,
                "UNVERIFIED",
                None,
                ("UNVERIFIED_REQUIRES_RAW_FILL_PRICE_MULTIPLIER_FEE_FACTS"),
                None,
            )
        elif isinstance(facts, ActualSimNowPinnedArchiveReplayFactsDTO):
            if self.actual_state != "LOCAL_ARCHIVE_REPLAYED_UNATTESTED":
                raise ValueError("actual state is not derived from facts")
            stable_identity = sha256_json(
                {
                    "snapshot_hash": facts.snapshot_hash,
                    "plan_hash": facts.plan_hash,
                    "session_id": facts.session_id,
                    "terminal_checksum": facts.terminal_checksum,
                }
            )
            replay = replay_actual_simnow_session_archive(facts)
            gross, slippage = replay[15:17]
            expected = (
                stable_identity,
                facts.actual_amount_verification_state,
                gross,
                slippage,
                None,
                None,
                None,
                "UNBOUND_NOT_ASSUMED_ZERO",
                None,
                "UNAVAILABLE_UNTIL_AUTHORITATIVE_FEES_BOUND",
                None,
            )
        elif isinstance(facts, ActualSimNowSettledArchiveReplayFactsDTO):
            if self.actual_state != "LOCAL_SETTLED_ARCHIVE_REPLAYED_FEES_UNBOUND":
                raise ValueError("actual state is not derived from facts")
            stable_identity = sha256_json(
                {
                    "snapshot_hash": facts.snapshot_hash,
                    "plan_hash": facts.plan_hash,
                    "session_id": facts.session_id,
                    "terminal_checksum": facts.terminal_checksum,
                }
            )
            replay = replay_settled_actual_simnow_session_archive(facts)
            gross, slippage = replay[15:17]
            expected = (
                stable_identity,
                facts.actual_amount_verification_state,
                gross,
                slippage,
                None,
                None,
                None,
                "UNBOUND_NOT_ASSUMED_ZERO",
                None,
                "UNAVAILABLE_UNTIL_AUTHORITATIVE_FEES_BOUND",
                None,
            )
        elif isinstance(facts, ActualSimNowFeeBoundArchiveReplayFactsDTO):
            if self.actual_state != "LOCAL_ARCHIVE_REPLAYED_FEE_BOUND":
                raise ValueError("actual state is not derived from facts")
            archive = facts.archive_replay
            stable_identity = sha256_json(
                {
                    "snapshot_hash": facts.snapshot_hash,
                    "plan_hash": facts.plan_hash,
                    "session_id": facts.session_id,
                    "terminal_checksum": archive.terminal_checksum,
                }
            )
            replay = replay_settled_actual_simnow_session_archive(archive)
            gross, slippage = replay[15:17]
            official = float(facts.fee_binding.official_exchange_fee_cny)
            broker = float(facts.fee_binding.broker_customer_fee_cny)
            all_in = float(facts.fee_binding.all_in_cost_cny)
            expected = (
                stable_identity,
                facts.actual_amount_verification_state,
                gross,
                slippage,
                official,
                broker,
                all_in,
                "BOUND",
                all_in,
                "BOUND_AUTHORITATIVE_FEE_STATEMENT",
                money_cent_sum(gross, -all_in),
            )
        else:  # pragma: no cover - closed source-facts union
            raise ValueError("actual source facts type is unsupported")
        actual = (
            self.stable_actual_fact_identity_sha256,
            self.actual_amount_verification_state,
            self.gross_execution_pnl_cny,
            self.adverse_slippage_cny,
            self.official_exchange_fee_cny,
            self.broker_customer_fee_cny,
            self.all_in_cost_cny,
            self.fees_state,
            self.actual_fees_cny,
            self.net_pnl_state,
            self.actual_net_pnl_cny,
        )
        if actual != expected:
            raise ValueError("actual layer is not derived from facts")
        expected_schema = (
            "commodity_c_fast_actual_simnow_calibration_pnl_layer_v5"
            if isinstance(facts, ActualSimNowSettledArchiveReplayFactsDTO)
            else "commodity_c_fast_actual_simnow_calibration_pnl_layer_v4"
            if isinstance(facts, ActualSimNowFeeBoundArchiveReplayFactsDTO)
            else "commodity_c_fast_actual_simnow_calibration_pnl_layer_v3"
            if isinstance(facts, ActualSimNowPinnedArchiveReplayFactsDTO)
            else "commodity_c_fast_actual_simnow_calibration_pnl_layer_v2"
        )
        if self.schema_version != expected_schema:
            raise ValueError("actual layer schema version mismatch")
        _validate_source_lineage(self.source_facts, self.lineage)
        _validate_layer_hash(self)
        return self


class PnlLayerHashIndexDTO(StrictLedgerModel):
    theoretical_target_pnl_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fee_adjusted_pnl_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    execution_quality_interval_pnl_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    actual_simnow_calibration_pnl_sha256: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")


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
    economic_counting_state: Literal[
        "PRIMARY",
        "NON_COUNTING_FEE_BINDING_CORRECTION",
    ]
    supersedes_entry_hash: Sha256 | None = Field(
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
    layer_isolation: Literal["FOUR_LAYERS_APPEND_ONLY_NEVER_OVERWRITE_OR_COALESCE"]
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
        if self.economic_counting_state == "PRIMARY":
            if self.supersedes_entry_hash is not None:
                raise ValueError("primary entry must not supersede an entry")
        elif self.supersedes_entry_hash is None or not isinstance(
            self.actual_simnow_calibration_pnl.source_facts,
            ActualSimNowFeeBoundArchiveReplayFactsDTO,
        ):
            raise ValueError("fee correction requires a superseded entry and v5 facts")
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
            theoretical_target_pnl_sha256=(self.theoretical_target_pnl.layer_hash),
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
            "formula_target_binding_sha256": (self.formula_target_binding_sha256),
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
    schema_version: Literal["commodity_c_fast_pnl_ledger_audit_v3"]
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
    actual_gross_replayed_entry_count: int = Field(ge=0, le=10_000)
    actual_net_fee_bound_entry_count: int = Field(ge=0, le=10_000)
    external_genesis_anchor_state: Literal["NOT_PROVIDED_STRUCTURE_ONLY"]
    external_tip_anchor_state: Literal["NOT_PROVIDED_STRUCTURE_ONLY"]
    countable_forward: StrictFalse
    authority_granted: StrictFalse
    dispatch_allowed: StrictFalse
    replacement_allowed: StrictFalse
    production_allowed: StrictFalse

    @model_validator(mode="after")
    def validate_actual_counts(self) -> "CommodityCFastPnlLedgerAuditDTO":
        if self.actual_gross_replayed_entry_count > self.entry_count:
            raise ValueError("replayed actual count exceeds ledger entries")
        if self.actual_net_fee_bound_entry_count > (
            self.actual_gross_replayed_entry_count
        ):
            raise ValueError("fee-bound actual count exceeds replayed actual count")
        return self


def replay_actual_simnow_session_archive(
    facts: ActualSimNowPinnedArchiveReplayFactsDTO,
) -> tuple[Any, ...]:
    """Replay gross/slippage from one embedded terminal session archive.

    The replay intentionally does not derive fees or net PnL: the current
    session archive has no authoritative fee statement source.
    """

    return _replay_actual_simnow_session_archive(
        facts,
        require_full_fill=True,
    )


def replay_settled_actual_simnow_session_archive(
    facts: ActualSimNowSettledArchiveReplayFactsDTO,
) -> tuple[Any, ...]:
    """Replay exact trades for a terminal-reconciled settled outcome."""

    return _replay_actual_simnow_session_archive(
        facts,
        require_full_fill=False,
    )


def _replay_actual_simnow_session_archive(
    facts: (
        ActualSimNowPinnedArchiveReplayFactsDTO
        | ActualSimNowSettledArchiveReplayFactsDTO
    ),
    *,
    require_full_fill: bool,
) -> tuple[Any, ...]:
    archive = facts.session_archive
    if facts.session_archive_sha256 != sha256_json(archive):
        raise ValueError("session_archive_sha256 mismatch")

    def contains_sensitive_key(value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                any(
                    marker in str(key).lower()
                    for marker in (
                        "account_original",
                        "password",
                        "secret",
                        "token",
                        "credential",
                    )
                )
                or contains_sensitive_key(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(contains_sensitive_key(child) for child in value)
        return False

    if contains_sensitive_key(archive):
        raise ValueError("session archive contains a sensitive field")
    if (
        archive.get("schema_version") != "commodity_c_fast_simnow_shakedown_session_v1"
        or archive.get("candidate_id") != "C_FAST_CROSS_SECTION_NEUTRAL"
        or archive.get("execution_lane") != "simnow_shakedown"
        or archive.get("countable_forward") is not False
        or archive.get("production_allowed") is not False
        or archive.get("source_snapshot_hash") != facts.snapshot_hash
        or archive.get("formula_target_binding_sha256")
        != facts.formula_target_binding_sha256
        or archive.get("plan_hash") != facts.plan_hash
        or archive.get("previous_terminal_checksum")
        != facts.archive_predecessor_terminal_checksum
    ):
        raise ValueError("session archive identity mismatch")

    plan_core = {
        key: value
        for key, value in archive.items()
        if key
        not in {
            "schema_version",
            "plan_hash",
            "status",
            "started_by",
            "previewed_at_utc",
            "completed_at_utc",
            "execution",
            "terminal_checksum",
            "continuous_authorized",
        }
    }
    if sha256_json(plan_core) != facts.plan_hash:
        raise ValueError("session archive plan hash mismatch")

    execution = archive.get("execution")
    if not isinstance(execution, dict):
        raise ValueError("session archive execution is missing")
    execution_core = {
        key: value for key, value in execution.items() if key != "state_checksum"
    }
    execution_checksum = execution.get("state_checksum")
    if execution_checksum != sha256_json(execution_core):
        raise ValueError("session archive execution checksum mismatch")
    terminal_payload = {
        "session_id": archive.get("session_id"),
        "plan_hash": archive.get("plan_hash"),
        "status": archive.get("status"),
        "completed_at_utc": archive.get("completed_at_utc"),
        "execution_state_checksum": execution_checksum,
    }
    terminal_checksum = sha256_json(terminal_payload)
    if archive.get("terminal_checksum") != terminal_checksum:
        raise ValueError("session archive terminal checksum mismatch")

    raw = execution.get("terminal_raw_facts")
    guard = execution.get("terminal_guard")
    snapshot = execution.get("execution_snapshot")
    pnl = execution.get("pnl")
    reconciliation = execution.get("reconciliation")
    submitted = execution.get("submitted")
    if not all(
        isinstance(value, dict)
        for value in (raw, guard, snapshot, pnl, reconciliation, submitted)
    ):
        raise ValueError("session archive replay inputs are incomplete")
    if (
        raw.get("schema_version") != "commodity_c_fast_terminal_raw_facts_v3"
        or raw.get("scope") != "C_FAST_SESSION_PLUS_FINAL_POSITIONS"
        or raw.get("account_sha256") != archive.get("account_hash")
        or guard.get("state") != "VALID"
        or guard.get("observed_account_hash") != raw.get("account_sha256")
        or guard.get("final_positions") != reconciliation.get("observed_positions")
        or reconciliation.get("expected_positions")
        != reconciliation.get("observed_positions")
    ):
        raise ValueError("session archive reconciliation join mismatch")
    settlement = execution.get("settlement")
    terminal_settled = isinstance(settlement, dict) and (
        settlement.get("schema_version") == "commodity_c_fast_terminal_settlement_v1"
        and settlement.get("state") == "SETTLED_COMPLETE"
        and settlement.get("basis")
        == (
            "STABLE_TERMINAL_RAW_FACTS_POSITION_RECONCILIATION_"
            "NO_ACTIVE_ORDER_OR_UNRESOLVED_INTENT"
        )
        and settlement.get("terminal_status") == archive.get("status")
    )
    if not require_full_fill and facts.order_outcome != "FULL_FILL":
        guard_blocker_fields = (
            "active_plan_orders",
            "external_active_orders",
            "unknown_status_orders",
            "unresolved_intent_order_facts",
            "unresolved_intent_trade_facts",
            "inconsistent_trade_rows",
            "unmatched_plan_scope_trade_facts",
        )
        if (
            not terminal_settled
            or guard.get("facts_stable") is not True
            or any(guard.get(field) for field in guard_blocker_fields)
            or guard.get("blockers")
            or snapshot.get("settlement_state") != "SETTLED_COMPLETE"
            or pnl.get("trade_evidence_state") != "SETTLED_COMPLETE"
        ):
            raise ValueError("non-full archive lacks settled terminal evidence")

    orders = raw.get("orders")
    trades = raw.get("trades")
    positions = raw.get("positions")
    contract_specs = raw.get("contract_specs")
    if (
        not isinstance(orders, list)
        or not isinstance(trades, list)
        or not isinstance(positions, list)
        or not isinstance(contract_specs, dict)
        or not all(isinstance(row, dict) for row in (*orders, *trades, *positions))
    ):
        raise ValueError("terminal raw fact rows are invalid")

    def row_hash(rows: list[dict[str, Any]]) -> str:
        return sha256_json(sorted(sha256_json(row) for row in rows))

    orders_hash = row_hash(orders)
    trades_hash = row_hash(trades)
    positions_hash = row_hash(positions)
    if (
        raw.get("orders_sha256") != orders_hash
        or raw.get("trades_sha256") != trades_hash
        or raw.get("positions_sha256") != positions_hash
        or raw.get("all_orders_sha256")
        != guard.get("second_snapshot", {}).get("orders_hash")
        or raw.get("all_trades_sha256")
        != guard.get("second_snapshot", {}).get("trades_hash")
        or raw.get("all_positions_sha256")
        != guard.get("second_snapshot", {}).get("positions_hash")
    ):
        raise ValueError("terminal raw fact hash mismatch")

    order_fields = {
        "vt_orderid",
        "gateway_name",
        "reference",
        "vt_symbol",
        "direction",
        "offset",
        "volume",
        "status",
    }
    trade_fields = {
        "vt_tradeid",
        "vt_orderid",
        "gateway_name",
        "reference",
        "vt_symbol",
        "direction",
        "offset",
        "volume",
        "price",
        "trade_at_utc",
    }
    position_fields = {"vt_symbol", "direction", "volume"}
    if (
        any(set(row) != order_fields for row in orders)
        or any(set(row) != trade_fields for row in trades)
        or any(set(row) != position_fields for row in positions)
    ):
        raise ValueError("terminal facts are not canonical safe projections")

    replayed_positions: dict[str, int] = {}
    position_directions: dict[str, str] = {}
    for position in positions:
        vt_symbol = str(position.get("vt_symbol") or "")
        direction = _normalize_ledger_direction(position.get("direction"))
        volume = _strict_nonnegative_int(position.get("volume"), "position volume")
        if not vt_symbol:
            raise ValueError("position contract is missing")
        if (
            vt_symbol in position_directions
            and position_directions[vt_symbol] != direction
        ):
            raise ValueError("same contract has opposing position rows")
        position_directions[vt_symbol] = direction
        signed = volume if direction == "long" else -volume
        replayed_positions[vt_symbol] = replayed_positions.get(vt_symbol, 0) + signed
    replayed_positions = dict(
        sorted(
            (symbol, volume) for symbol, volume in replayed_positions.items() if volume
        )
    )
    if (
        replayed_positions != reconciliation.get("observed_positions")
        or replayed_positions != reconciliation.get("expected_positions")
        or replayed_positions != guard.get("final_positions")
        or replayed_positions != execution.get("final_positions")
    ):
        raise ValueError("canonical positions do not replay reconciliation")

    child_rows_with_phase = [
        (phase, row)
        for phase in ("close", "open")
        for row in submitted.get(phase, [])
        if isinstance(row, dict)
    ]
    child_rows = [row for _, row in child_rows_with_phase]
    if not child_rows or len(child_rows) != sum(
        len(submitted.get(phase, []))
        for phase in ("close", "open")
        if isinstance(submitted.get(phase), list)
    ):
        raise ValueError("submitted child rows are invalid")
    submitted_fields = {
        "product",
        "vt_symbol",
        "direction",
        "offset",
        "volume",
        "price",
        "decision_price",
        "reference",
        "vt_orderid",
    }
    if any(set(row) != submitted_fields for row in child_rows):
        raise ValueError("submitted rows are not canonical safe projections")
    snapshot_orders = snapshot.get("orders")
    if (
        snapshot.get("available") is not True
        or not isinstance(snapshot_orders, list)
        or len(snapshot_orders) != len(child_rows)
        or not all(isinstance(row, dict) for row in snapshot_orders)
    ):
        raise ValueError("execution snapshot is unavailable or incomplete")

    def identity(row: dict[str, Any], prefix: str) -> str:
        value = str(
            row.get(f"vt_{prefix}id") or row.get(f"{prefix}id") or ""
        )
        gateway = str(row.get("gateway_name") or "")
        if value and gateway and not value.startswith(f"{gateway}."):
            return f"{gateway}.{value}"
        return value

    order_ids = [identity(row, "order") for row in orders]
    trade_ids = [identity(row, "trade") for row in trades]
    if (
        any(not value for value in (*order_ids, *trade_ids))
        or len(set(order_ids)) != len(order_ids)
        or len(set(trade_ids)) != len(trade_ids)
    ):
        raise ValueError("terminal raw fact identities are missing or duplicated")
    resolved_gateway = str(guard.get("gateway_before") or "")
    if (
        not resolved_gateway
        or str(guard.get("gateway_after") or "") != resolved_gateway
        or any(
            str(row.get("gateway_name") or "") != resolved_gateway
            for row in orders
        )
        or any(
            str(row.get("gateway_name") or "") != resolved_gateway
            for row in trades
        )
    ):
        raise ValueError("terminal raw facts gateway binding is invalid")

    marks = pnl.get("mark_evidence")
    if not isinstance(marks, dict):
        raise ValueError("session archive mark evidence is missing")
    child_symbols = {str(row.get("vt_symbol") or "") for row in child_rows}
    filled_symbols = {str(row.get("vt_symbol") or "") for row in trades}
    expected_mark_source = "CURRENT_L1_MID" if trades else "NOT_REQUIRED_ZERO_FILL"
    if (
        set(contract_specs) != child_symbols
        or set(marks) != filled_symbols
        or pnl.get("mark_source") != expected_mark_source
        or (terminal_settled and trades and pnl.get("mark_state") != "AVAILABLE")
        or (
            terminal_settled
            and not trades
            and pnl.get("mark_state") != "NOT_REQUIRED_ZERO_FILL"
        )
    ):
        raise ValueError("contract specs or marks do not match submitted symbols")
    if (
        pnl.get("execution_snapshot_available") is not True
        or (require_full_fill and pnl.get("trade_evidence_state") != "COMPLETE")
        or pnl.get("fees_state") != "UNBOUND_NOT_ASSUMED_ZERO"
        or pnl.get("fees_cny") is not None
        or pnl.get("net_pnl_state") != "UNAVAILABLE_UNTIL_FEES_BOUND"
        or pnl.get("net_pnl_cny") is not None
    ):
        raise ValueError("archive PnL availability or fee state is invalid")
    pnl_captured = parse_utc_string(
        str(pnl.get("captured_at_utc") or ""),
        "pnl.captured_at_utc",
    )

    expected_lots = 0
    filled_lots = 0
    gross_components: list[float] = []
    slippage_components: list[float] = []
    mark_times: list[datetime] = []
    used_trade_ids: set[str] = set()
    for child_index, (child_phase, child) in enumerate(child_rows_with_phase):
        child_order_id = str(child.get("vt_orderid") or "")
        child_reference = str(child.get("reference") or "")
        child_symbol = str(child.get("vt_symbol") or "")
        if not child_order_id or not child_reference or not child_symbol:
            raise ValueError("submitted child identity is incomplete")
        child_direction = _normalize_ledger_direction(child.get("direction"))
        child_volume = _strict_positive_int(child.get("volume"), "child volume")
        decision_price = _strict_positive_number(
            child.get("decision_price", child.get("price")),
            "decision price",
        )
        expected_lots += child_volume
        matching_orders = [
            row
            for row in orders
            if identity(row, "order") == child_order_id
            and str(row.get("reference") or "") in {"", child_reference}
        ]
        if len(matching_orders) != 1:
            raise ValueError("submitted child does not join one archived order")
        order = matching_orders[0]
        if (
            str(order.get("vt_symbol") or "") != child_symbol
            or _normalize_ledger_direction(order.get("direction")) != child_direction
            or _normalize_ledger_offset(order.get("offset"))
            != _normalize_ledger_offset(child.get("offset"))
            or _strict_positive_int(order.get("volume"), "order volume") != child_volume
        ):
            raise ValueError("archived order fields do not match submitted child")
        order_status = _normalize_ledger_order_status(order.get("status"))
        if require_full_fill and order_status != "all_traded":
            raise ValueError("v4 archive replay requires all-traded orders")

        matching_trades = [
            row
            for row in trades
            if identity(row, "order") == child_order_id
            and str(row.get("reference") or "") in {"", child_reference}
        ]
        child_filled_lots = sum(
            _strict_positive_int(trade.get("volume"), "trade volume")
            for trade in matching_trades
        )
        if child_filled_lots > child_volume:
            raise ValueError("archived child fills exceed child volume")
        if require_full_fill and child_filled_lots != child_volume:
            raise ValueError("v4 archive replay requires every child full fill")

        spec = contract_specs.get(child_symbol)
        if not isinstance(spec, dict):
            raise ValueError("child contract spec is missing")
        if set(spec) != {"product", "multiplier", "price_tick"}:
            raise ValueError("contract spec is not a canonical safe projection")
        multiplier = _strict_positive_int(spec.get("multiplier"), "multiplier")
        if spec.get("product") != child.get("product"):
            raise ValueError("contract spec product mismatch")
        mark_price: float | None = None
        mark_at: datetime | None = None
        if matching_trades:
            mark = marks.get(child_symbol)
            if not isinstance(mark, dict) or set(mark) != {
                "raw_quote",
                "raw_quote_sha256",
                "received_at_utc",
                "mark_price",
            }:
                raise ValueError("filled child mark is missing or non-canonical")
            raw_quote = mark.get("raw_quote")
            if not isinstance(raw_quote, dict):
                raise ValueError("mark raw quote is missing")
            if set(raw_quote) != {
                "bid_price_1",
                "ask_price_1",
                "bid_volume_1",
                "ask_volume_1",
                "received_at",
                "spread_ticks",
            }:
                raise ValueError("mark quote is not a canonical safe projection")
            if mark.get("raw_quote_sha256") != sha256_json(raw_quote):
                raise ValueError("mark raw quote hash mismatch")
            bid = _strict_positive_number(raw_quote.get("bid_price_1"), "mark bid")
            ask = _strict_positive_number(raw_quote.get("ask_price_1"), "mark ask")
            mark_price = money_multiply(money_sum(bid, ask), 0.5)
            archived_mark = _strict_positive_number(
                mark.get("mark_price"), "mark price"
            )
            if not _money_equal(mark_price, archived_mark):
                raise ValueError("mark price is not derived from raw quote")
            mark_at = parse_utc_string(
                str(mark.get("received_at_utc") or ""),
                "mark.received_at_utc",
            )
            if raw_quote.get("received_at") != mark.get("received_at_utc"):
                raise ValueError("mark timestamp is not bound to raw quote")
            if mark_at > pnl_captured:
                raise ValueError("mark occurs after PnL capture")
            mark_times.append(mark_at)

        fill_notional = money_sum(
            *[
                money_multiply(
                    _strict_positive_number(trade.get("price"), "fill price"),
                    _strict_positive_int(trade.get("volume"), "trade volume"),
                )
                for trade in matching_trades
            ]
        )
        average_fill_price = (
            money_multiply(fill_notional, 1.0 / child_filled_lots)
            if child_filled_lots
            else None
        )
        direction_factor = 1 if child_direction == "long" else -1
        child_slippage = (
            money_product(
                money_multiply(
                    money_sum(average_fill_price, -decision_price),
                    float(multiplier),
                ),
                direction_factor * child_filled_lots,
            )
            if average_fill_price is not None
            else 0.0
        )
        snapshot_child = snapshot_orders[child_index]
        exact_snapshot_fields = (
            ("phase", snapshot_child.get("phase"), child_phase),
            ("vt_orderid", snapshot_child.get("vt_orderid"), child_order_id),
            ("product", snapshot_child.get("product"), child.get("product")),
            ("vt_symbol", snapshot_child.get("vt_symbol"), child_symbol),
            ("direction", snapshot_child.get("direction"), child_direction),
            ("offset", snapshot_child.get("offset"), child.get("offset")),
            (
                "expected_volume",
                snapshot_child.get("expected_volume"),
                child_volume,
            ),
            (
                "trade_evidence_state",
                snapshot_child.get("trade_evidence_state"),
                (
                    "COMPLETE"
                    if require_full_fill or child_filled_lots == child_volume
                    else "SETTLED_COMPLETE"
                    if terminal_settled
                    else snapshot_child.get("trade_evidence_state")
                ),
            ),
            (
                "trade_count",
                snapshot_child.get("trade_count"),
                len(matching_trades),
            ),
            (
                "order_status",
                snapshot_child.get("order_status"),
                order_status,
            ),
        )
        if any(observed != expected for _, observed, expected in exact_snapshot_fields):
            raise ValueError("execution snapshot child identity/state mismatch")
        if (
            not _money_equal(
                _strict_finite_number(
                    snapshot_child.get("filled_volume"),
                    "snapshot filled volume",
                ),
                float(child_filled_lots),
            )
            or (
                average_fill_price is not None
                and not _money_equal(
                    _strict_positive_number(
                        snapshot_child.get("average_fill_price"),
                        "snapshot average fill price",
                    ),
                    average_fill_price,
                )
            )
            or (
                average_fill_price is None
                and snapshot_child.get("average_fill_price") is not None
            )
            or not _money_equal(
                _strict_finite_number(
                    snapshot_child.get("decision_price"),
                    "snapshot decision price",
                ),
                decision_price,
            )
            or (
                snapshot_child.get("slippage_cny") is not None
                and not _money_equal(
                    _strict_finite_number(
                        snapshot_child.get("slippage_cny"),
                        "snapshot child slippage",
                    ),
                    child_slippage,
                )
            )
            or (child_filled_lots > 0 and snapshot_child.get("slippage_cny") is None)
        ):
            raise ValueError("execution snapshot child amount mismatch")
        for trade in matching_trades:
            if mark_at is None or mark_price is None:
                raise ValueError("filled trade has no replayable mark")
            trade_id = identity(trade, "trade")
            if trade_id in used_trade_ids:
                raise ValueError("one archived trade joins multiple children")
            used_trade_ids.add(trade_id)
            if (
                str(trade.get("gateway_name") or "")
                != str(order.get("gateway_name") or "")
                or str(trade.get("vt_symbol") or "") != child_symbol
                or _normalize_ledger_direction(trade.get("direction"))
                != child_direction
                or _normalize_ledger_offset(trade.get("offset"))
                != _normalize_ledger_offset(child.get("offset"))
            ):
                raise ValueError("archived trade fields do not match child")
            volume = _strict_positive_int(trade.get("volume"), "trade volume")
            fill_price = _strict_positive_number(trade.get("price"), "fill price")
            trade_at = parse_utc_string(
                str(trade.get("trade_at_utc") or trade.get("datetime") or ""),
                "trade_at_utc",
            )
            if trade_at > mark_at:
                raise ValueError("trade occurs after valuation mark")
            filled_lots += volume
            signed_volume = volume if child_direction == "long" else -volume
            gross_components.append(
                money_product(
                    money_multiply(
                        money_sum(mark_price, -fill_price),
                        float(multiplier),
                    ),
                    signed_volume,
                )
            )
            slippage_components.append(
                money_product(
                    money_multiply(
                        money_sum(fill_price, -decision_price),
                        float(multiplier),
                    ),
                    signed_volume,
                )
            )
    if used_trade_ids != set(trade_ids):
        raise ValueError("archived trade does not join the submitted plan")
    if require_full_fill and (
        filled_lots != expected_lots or archive.get("status") != "COMPLETE"
    ):
        raise ValueError("v4 archive replay requires full-fill COMPLETE terminal")
    if filled_lots == expected_lots and all(
        _normalize_ledger_order_status(row.get("status")) == "all_traded"
        for row in orders
    ):
        raw_outcome = "FULL_FILL"
    elif filled_lots > 0:
        raw_outcome = "PARTIAL_FILL"
    elif any(
        _normalize_ledger_order_status(row.get("status")) == "rejected"
        for row in orders
    ):
        raw_outcome = "REJECTED"
    elif any(
        _normalize_ledger_order_status(row.get("status"))
        in {"submitting", "submitting_order", "not_traded"}
        for row in orders
    ):
        raw_outcome = "TIMEOUT_OR_RESULT_UNKNOWN"
    else:
        raw_outcome = "UNFILLED_CANCELLED"

    outcome = raw_outcome
    if terminal_settled:
        if not isinstance(settlement, dict):
            raise ValueError("terminal settlement evidence is missing")
        if set(settlement) != {
            "schema_version",
            "state",
            "basis",
            "terminal_status",
            "order_outcome",
            "unknown_outcome_settlement_state",
            "expected_volume",
            "filled_volume",
            "actual_trade_count",
            "pre_trade_positions",
        }:
            raise ValueError("terminal settlement fields are not canonical")
        historical_unknown = bool(
            (execution.get("halt") or {}).get("submission_outcome_unknown_observed")
            or any(
                intent.get("intent_status") == "EVIDENCE_RECOVERED"
                for phase in ("close", "open")
                for intent in execution.get("send_intents", {}).get(phase, [])
                if isinstance(intent, dict)
            )
        )
        settlement_outcome = settlement.get("order_outcome")
        if (
            settlement_outcome != "FULL_FILL"
            and settlement.get("terminal_status") != "HALTED_RECONCILED"
        ):
            raise ValueError("non-full settlement requires HALTED_RECONCILED terminal")
        if settlement_outcome == "TIMEOUT_OR_RESULT_UNKNOWN":
            if not historical_unknown or filled_lots or raw_outcome == "REJECTED":
                raise ValueError("unknown outcome settlement provenance is invalid")
            outcome = "TIMEOUT_OR_RESULT_UNKNOWN"
        elif settlement_outcome != raw_outcome:
            raise ValueError("terminal settlement outcome mismatch")
        if (
            settlement.get("expected_volume") != expected_lots
            or settlement.get("filled_volume") != filled_lots
            or settlement.get("actual_trade_count") != len(trades)
            or settlement.get("unknown_outcome_settlement_state")
            != (
                "SETTLED_BY_TERMINAL_RAW_FACTS_AND_POSITION_RECONCILIATION"
                if outcome == "TIMEOUT_OR_RESULT_UNKNOWN"
                else "NOT_APPLICABLE"
            )
        ):
            raise ValueError("terminal settlement amount/state mismatch")

    if terminal_settled:
        previous_positions = settlement.get("pre_trade_positions")
        if not isinstance(previous_positions, dict) or any(
            not isinstance(symbol, str) or type(volume) is not int
            for symbol, volume in previous_positions.items()
        ):
            raise ValueError("previous positions are not replayable")
        trade_replayed_positions = dict(previous_positions)
        for trade in trades:
            symbol = str(trade.get("vt_symbol") or "")
            volume = _strict_positive_int(trade.get("volume"), "trade volume")
            direction = _normalize_ledger_direction(trade.get("direction"))
            trade_replayed_positions[symbol] = trade_replayed_positions.get(
                symbol, 0
            ) + (volume if direction == "long" else -volume)
            if trade_replayed_positions[symbol] == 0:
                trade_replayed_positions.pop(symbol)
        if dict(sorted(trade_replayed_positions.items())) != replayed_positions:
            raise ValueError("final positions do not replay exact joined trades")
        if any(
            _normalize_ledger_order_status(row.get("status"))
            in {"submitting", "submitting_order", "not_traded", "part_traded"}
            for row in orders
        ):
            raise ValueError("settled archive still contains an active order")

    replayed_gross = money_sum(*gross_components)
    replayed_slippage = money_sum(*slippage_components)
    if (
        int(snapshot.get("expected_volume", -1)) != expected_lots
        or not _money_equal(
            _strict_finite_number(
                snapshot.get("filled_volume"), "snapshot filled volume"
            ),
            filled_lots,
        )
        or not _money_equal(
            _strict_finite_number(snapshot.get("slippage_cny"), "snapshot slippage"),
            replayed_slippage,
        )
        or int(pnl.get("expected_volume", -1)) != expected_lots
        or not _money_equal(
            _strict_finite_number(pnl.get("filled_volume"), "PnL filled volume"),
            filled_lots,
        )
        or not _money_equal(
            _strict_finite_number(
                pnl.get("execution_mark_to_market_pnl_cny"),
                "PnL gross amount",
            ),
            replayed_gross,
        )
        or not _money_equal(
            _strict_finite_number(pnl.get("adverse_slippage_cny"), "PnL slippage"),
            replayed_slippage,
        )
    ):
        raise ValueError("execution snapshot or archive PnL replay mismatch")

    valuation_at = max(mark_times) if mark_times else pnl_captured
    if not (
        valuation_at
        <= pnl_captured
        <= parse_utc_string(
            str(archive.get("completed_at_utc") or ""),
            "completed_at_utc",
        )
        <= facts.as_of_at_utc
    ):
        raise ValueError("archive valuation/capture/terminal time causality is invalid")
    reconciliation_hash = sha256_json(reconciliation)
    return (
        archive.get("session_id"),
        raw.get("account_sha256"),
        orders_hash,
        trades_hash,
        positions_hash,
        reconciliation_hash,
        execution_checksum,
        terminal_checksum,
        archive.get("status"),
        archive.get("completed_at_utc"),
        valuation_at,
        pnl_captured,
        expected_lots,
        filled_lots,
        outcome,
        replayed_gross,
        replayed_slippage,
    )


def _normalize_ledger_direction(value: Any) -> str:
    raw = str(value).strip().lower()
    normalized = {"多": "long", "空": "short"}.get(raw, raw)
    if normalized not in {"long", "short"}:
        raise ValueError("direction is invalid")
    return normalized


def _normalize_ledger_offset(value: Any) -> str:
    raw = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    normalized = {
        "开": "open",
        "平": "close",
        "平今": "closetoday",
        "平昨": "closeyesterday",
    }.get(raw, raw)
    if normalized not in {"open", "close", "closetoday", "closeyesterday"}:
        raise ValueError("offset is invalid")
    return normalized


def _normalize_ledger_order_status(value: Any) -> str:
    raw = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    normalized = {
        "全部成交": "all_traded",
        "filled": "all_traded",
        "alltraded": "all_traded",
    }.get(raw, raw)
    if normalized not in {
        "all_traded",
        "cancelled",
        "rejected",
        "part_traded",
        "not_traded",
        "submitting",
        "submitting_order",
    }:
        raise ValueError("order status is invalid")
    return normalized


def _strict_positive_int(value: Any, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive integer literal")
    return value


def _strict_nonnegative_int(value: Any, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a nonnegative integer literal")
    return value


def _strict_finite_number(value: Any, field: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise ValueError(f"{field} must be a finite number literal")
    return float(value)


def _strict_positive_number(value: Any, field: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)) or value <= 0:
        raise ValueError(f"{field} must be a positive number literal")
    return float(value)


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
