"""Fail-closed, pure offline accounting for Issue #488 research."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext
from typing import Iterable, Mapping, Sequence


class AccountingContractError(ValueError):
    """Raised when a research accounting prerequisite is not exact and usable."""


NANOSECONDS_PER_SECOND = 1_000_000_000
FEE_ROUNDING_QUANTUM = Decimal("0.01")
FEE_ROUNDING_MODE = ROUND_HALF_UP
PRIMARY_SCENARIO_ID = "PRIMARY"
STRESS_SCENARIO_ID = "STRESS"
POSITION_SCOPE = "scenario_id×exact_contract"
EVENT_ORDER_VERSION = "collector-callback-order-v1"


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
    ):
        raise AccountingContractError(f"{name} must be non-empty canonical text")
    return value


def _int(value: object, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AccountingContractError(f"{name} must be an integer >= {minimum}")
    return value


def _decimal(value: object, name: str) -> Decimal:
    if isinstance(value, bool):
        raise AccountingContractError(f"{name} must be a finite Decimal")
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise AccountingContractError(f"{name} must be a finite Decimal") from exc
    if not result.is_finite():
        raise AccountingContractError(f"{name} must be a finite Decimal")
    return result


def _positive(value: object, name: str) -> Decimal:
    result = _decimal(value, name)
    if result <= 0:
        raise AccountingContractError(f"{name} must be positive")
    return result


def _nonnegative(value: object, name: str) -> Decimal:
    result = _decimal(value, name)
    if result < 0:
        raise AccountingContractError(f"{name} must be non-negative")
    return result


def _day(value: object, name: str) -> date:
    if not isinstance(value, date):
        raise AccountingContractError(f"{name} must be a date")
    return value


def _sha256(value: object, name: str) -> str:
    result = _text(value, name)
    if len(result) != 64 or any(char not in "0123456789abcdef" for char in result):
        raise AccountingContractError(f"{name} must be a lowercase SHA-256 hex digest")
    return result


def _offset(value: object) -> str:
    result = _text(value, "offset")
    if result not in {"OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY"}:
        raise AccountingContractError("unsupported offset")
    return result


@dataclass(frozen=True)
class ExecutionScenarioSpec:
    scenario_id: str
    entry_delay_ns: int
    exit_delay_ns: int
    adverse_ticks: int
    horizon_ns: int
    lots: int
    min_side_size: Decimal
    exit_grace_ns: int
    position_scope: str
    event_order_version: str

    def __post_init__(self) -> None:
        _text(self.scenario_id, "scenario_id")
        for name in ("entry_delay_ns", "exit_delay_ns", "adverse_ticks"):
            _int(getattr(self, name), name)
        if self.horizon_ns != 30 * NANOSECONDS_PER_SECOND:
            raise AccountingContractError("horizon_ns is frozen at 30 seconds")
        if self.lots != 1:
            raise AccountingContractError("lots is frozen at one")
        if _decimal(self.min_side_size, "min_side_size") != Decimal(1):
            raise AccountingContractError("min_side_size is frozen at one")
        if self.exit_grace_ns != 5 * NANOSECONDS_PER_SECOND:
            raise AccountingContractError("exit_grace_ns is frozen at 5 seconds")
        if (
            self.position_scope != POSITION_SCOPE
            or self.event_order_version != EVENT_ORDER_VERSION
        ):
            raise AccountingContractError("scenario identity fields are frozen")


PRIMARY = ExecutionScenarioSpec(
    PRIMARY_SCENARIO_ID,
    500_000_000,
    500_000_000,
    0,
    30 * NANOSECONDS_PER_SECOND,
    1,
    Decimal(1),
    5 * NANOSECONDS_PER_SECOND,
    POSITION_SCOPE,
    EVENT_ORDER_VERSION,
)
STRESS = ExecutionScenarioSpec(
    STRESS_SCENARIO_ID,
    1_000_000_000,
    1_000_000_000,
    1,
    30 * NANOSECONDS_PER_SECOND,
    1,
    Decimal(1),
    5 * NANOSECONDS_PER_SECOND,
    POSITION_SCOPE,
    EVENT_ORDER_VERSION,
)
_SCENARIOS = {PRIMARY_SCENARIO_ID: PRIMARY, STRESS_SCENARIO_ID: STRESS}


def frozen_scenario(scenario_id: str) -> ExecutionScenarioSpec:
    try:
        return _SCENARIOS[_text(scenario_id, "scenario_id")]
    except KeyError as exc:
        raise AccountingContractError("unsupported execution scenario") from exc


def require_frozen_scenario(spec: ExecutionScenarioSpec) -> ExecutionScenarioSpec:
    if not isinstance(spec, ExecutionScenarioSpec) or spec != frozen_scenario(
        spec.scenario_id
    ):
        raise AccountingContractError("execution scenario parameters are frozen")
    return frozen_scenario(spec.scenario_id)


@dataclass(frozen=True)
class AdmissionCandidate:
    run_id: str
    collector_generation: str
    clock_epoch: str
    segment_id: str
    official_day: date
    exact_contract: str
    scenario_id: str
    direction: str
    eligibility: str
    callback_seq: int
    threshold_crossing_id: str
    proposed_trade_id: str

    def __post_init__(self) -> None:
        for name in (
            "run_id",
            "collector_generation",
            "clock_epoch",
            "segment_id",
            "exact_contract",
            "threshold_crossing_id",
            "proposed_trade_id",
        ):
            _text(getattr(self, name), name)
        _day(self.official_day, "official_day")
        frozen_scenario(self.scenario_id)
        if self.direction not in {"LONG", "SHORT"} or self.eligibility not in {
            "ELIGIBLE",
            "INELIGIBLE",
        }:
            raise AccountingContractError("invalid direction or eligibility")
        _int(self.callback_seq, "callback_seq", minimum=1)


@dataclass(frozen=True)
class AdmissionLedgerRow:
    run_id: str
    collector_generation: str
    clock_epoch: str
    segment_id: str
    official_day: date
    exact_contract: str
    scenario_id: str
    direction: str
    threshold_crossing_id: str
    proposed_trade_id: str
    callback_seq: int
    decision: str
    state_before: str
    state_after: str
    accepted_trade_id: str | None
    blocker: str | None
    blocking_trade_id: str | None

    def __post_init__(self) -> None:
        states = {"IDLE", "ENTRY_PENDING", "OPEN", "EXIT_PENDING"}
        if self.decision not in {"ADMITTED", "INELIGIBLE", "SUPPRESSED"}:
            raise AccountingContractError("unsupported admission decision")
        if self.state_before not in states or self.state_after not in states:
            raise AccountingContractError("unsupported admission state")
        if self.decision == "ADMITTED" and (
            self.state_before != "IDLE"
            or self.state_after != "ENTRY_PENDING"
            or self.accepted_trade_id != self.proposed_trade_id
            or self.blocker is not None
            or self.blocking_trade_id is not None
        ):
            raise AccountingContractError("invalid admitted admission row")
        if self.decision == "INELIGIBLE" and (
            self.accepted_trade_id is not None or self.blocking_trade_id is not None
        ):
            raise AccountingContractError("ineligible row cannot name accepted trade")
        if self.decision == "SUPPRESSED" and (
            self.accepted_trade_id is not None
            or not self.blocker
            or not self.blocking_trade_id
            or self.state_before != self.state_after
        ):
            raise AccountingContractError("invalid suppressed admission row")


@dataclass(frozen=True)
class _AdmissionState:
    status: str
    accepted_trade_id: str
    lane: tuple[str, str, str, str, date]


@dataclass
class ScenarioAdmissionLedger:
    """One position slot per frozen ``scenario_id×exact_contract`` scope."""

    _states: dict[tuple[str, str], _AdmissionState] = field(default_factory=dict)
    _last_callback_seq: int = 0
    _stream: tuple[str, str] | None = None
    _admitted_trade_ids: set[str] = field(default_factory=set)
    _admitted_threshold_crossing_ids: set[tuple[str, str]] = field(
        default_factory=set
    )
    rows: list[AdmissionLedgerRow] = field(default_factory=list)

    def admit(self, candidate: AdmissionCandidate) -> AdmissionLedgerRow:
        stream = (candidate.run_id, candidate.collector_generation)
        if self._stream is None:
            self._stream = stream
        elif self._stream != stream:
            raise AccountingContractError("admission ledger is fixed to one run/generation stream")
        if candidate.callback_seq < self._last_callback_seq:
            raise AccountingContractError("callback sequence must not regress")
        self._last_callback_seq = candidate.callback_seq
        key = (candidate.scenario_id, candidate.exact_contract)
        current = self._states.get(key)
        before = current.status if current else "IDLE"
        base = (
            candidate.run_id,
            candidate.collector_generation,
            candidate.clock_epoch,
            candidate.segment_id,
            candidate.official_day,
            candidate.exact_contract,
            candidate.scenario_id,
            candidate.direction,
            candidate.threshold_crossing_id,
            candidate.proposed_trade_id,
            candidate.callback_seq,
        )
        if candidate.eligibility == "INELIGIBLE":
            row = AdmissionLedgerRow(
                *base,
                "INELIGIBLE",
                before,
                before,
                None,
                "SIGNAL_INELIGIBLE",
                None,
            )
        elif current:
            row = AdmissionLedgerRow(
                *base,
                "SUPPRESSED",
                before,
                before,
                None,
                f"OCCUPIED_{before}",
                current.accepted_trade_id,
            )
        else:
            if candidate.proposed_trade_id in self._admitted_trade_ids:
                raise AccountingContractError("admitted trade_id cannot be reused")
            crossing_key = (
                candidate.scenario_id,
                candidate.threshold_crossing_id,
            )
            if crossing_key in self._admitted_threshold_crossing_ids:
                raise AccountingContractError("admitted threshold_crossing_id cannot be reused")
            lane = (
                candidate.run_id,
                candidate.collector_generation,
                candidate.clock_epoch,
                candidate.segment_id,
                candidate.official_day,
            )
            self._states[key] = _AdmissionState(
                "ENTRY_PENDING", candidate.proposed_trade_id, lane
            )
            self._admitted_trade_ids.add(candidate.proposed_trade_id)
            self._admitted_threshold_crossing_ids.add(crossing_key)
            row = AdmissionLedgerRow(
                *base,
                "ADMITTED",
                "IDLE",
                "ENTRY_PENDING",
                candidate.proposed_trade_id,
                None,
                None,
            )
        self.rows.append(row)
        return row

    def admit_ordered(
        self, candidates: Sequence[AdmissionCandidate]
    ) -> tuple[AdmissionLedgerRow, ...]:
        if any(
            candidates[i].callback_seq > candidates[i + 1].callback_seq
            for i in range(len(candidates) - 1)
        ):
            raise AccountingContractError(
                "ordered admission input must be callback ordered"
            )
        return tuple(self.admit(candidate) for candidate in candidates)

    def transition(
        self,
        scenario_id: str,
        exact_contract: str,
        state: str,
        callback_seq: int,
        trade_id: str,
        *,
        run_id: str,
        collector_generation: str,
        clock_epoch: str,
        segment_id: str,
        official_day: date,
    ) -> None:
        _int(callback_seq, "callback_seq", minimum=1)
        if callback_seq < self._last_callback_seq:
            raise AccountingContractError("callback sequence must not regress")
        key = (
            frozen_scenario(scenario_id).scenario_id,
            _text(exact_contract, "exact_contract"),
        )
        current = self._states.get(key)
        lane = (
            _text(run_id, "run_id"),
            _text(collector_generation, "collector_generation"),
            _text(clock_epoch, "clock_epoch"),
            _text(segment_id, "segment_id"),
            _day(official_day, "official_day"),
        )
        if not current or current.accepted_trade_id != _text(trade_id, "trade_id"):
            raise AccountingContractError(
                "transition trade_id does not own admitted position"
            )
        if current.lane != lane:
            raise AccountingContractError(
                "transition must remain in the admitted lane and official day"
            )
        allowed = {
            ("ENTRY_PENDING", "OPEN"),
            ("OPEN", "EXIT_PENDING"),
            ("OPEN", "IDLE"),
            ("EXIT_PENDING", "IDLE"),
            ("ENTRY_PENDING", "IDLE"),
        }
        if (current.status, state) not in allowed:
            raise AccountingContractError("invalid admission transition")
        self._last_callback_seq = callback_seq
        if state == "IDLE":
            self._states.pop(key)
        else:
            self._states[key] = _AdmissionState(
                state, current.accepted_trade_id, current.lane
            )


def _binding_common(
    binding_id: object,
    exact_contract: object,
    official_day: object,
    valid_from: object,
    valid_until: object,
    authority: object,
    source: object,
    version: object,
    source_sha256: object,
) -> None:
    for name, value in (
        ("binding_id", binding_id),
        ("exact_contract", exact_contract),
        ("authority", authority),
        ("source", source),
        ("version", version),
    ):
        _text(value, name)
    _day(official_day, "official_day")
    if _int(valid_until, "valid_until_utc_ns", minimum=1) <= _int(
        valid_from, "valid_from_utc_ns"
    ):
        raise AccountingContractError(
            "valid_until_utc_ns must be after valid_from_utc_ns"
        )
    _sha256(source_sha256, "source_sha256")


@dataclass(frozen=True)
class InstrumentTermsBinding:
    binding_id: str
    exact_contract: str
    official_day: date
    valid_from_utc_ns: int
    valid_until_utc_ns: int
    tick_size: Decimal
    multiplier: Decimal
    authority: str
    source: str
    version: str
    source_sha256: str

    def __post_init__(self) -> None:
        _binding_common(
            self.binding_id,
            self.exact_contract,
            self.official_day,
            self.valid_from_utc_ns,
            self.valid_until_utc_ns,
            self.authority,
            self.source,
            self.version,
            self.source_sha256,
        )
        _positive(self.tick_size, "tick_size")
        _positive(self.multiplier, "multiplier")


@dataclass(frozen=True)
class FeeScheduleBinding:
    binding_id: str
    exact_contract: str
    official_day: date
    valid_from_utc_ns: int
    valid_until_utc_ns: int
    offset: str
    fixed_cny: Decimal
    ratio_per_mille: Decimal
    authority: str
    source: str
    version: str
    source_sha256: str

    def __post_init__(self) -> None:
        _binding_common(
            self.binding_id,
            self.exact_contract,
            self.official_day,
            self.valid_from_utc_ns,
            self.valid_until_utc_ns,
            self.authority,
            self.source,
            self.version,
            self.source_sha256,
        )
        _offset(self.offset)
        _nonnegative(self.fixed_cny, "fixed_cny")
        _nonnegative(self.ratio_per_mille, "ratio_per_mille")


@dataclass(frozen=True)
class BrokerMarkupBinding:
    binding_id: str
    exact_contract: str
    official_day: date
    valid_from_utc_ns: int
    valid_until_utc_ns: int
    offset: str
    fixed_cny: Decimal
    ratio_per_mille: Decimal
    authority: str
    source: str
    version: str
    source_sha256: str

    def __post_init__(self) -> None:
        _binding_common(
            self.binding_id,
            self.exact_contract,
            self.official_day,
            self.valid_from_utc_ns,
            self.valid_until_utc_ns,
            self.authority,
            self.source,
            self.version,
            self.source_sha256,
        )
        _offset(self.offset)
        _nonnegative(self.fixed_cny, "fixed_cny")
        _nonnegative(self.ratio_per_mille, "ratio_per_mille")


def _resolve_exact_one(
    bindings: Iterable[object],
    expected_type: type[object],
    exact_contract: str,
    official_day: date,
    utc_ns: int,
    *,
    offset: str | None = None,
) -> object:
    contract = _text(exact_contract, "exact_contract")
    day = _day(official_day, "official_day")
    moment = _int(utc_ns, "utc_ns", minimum=1)
    validated: list[object] = []
    for binding in bindings:
        if type(binding) is not expected_type:
            raise AccountingContractError(
                f"trusted binding must be exact {expected_type.__name__}"
            )
        binding.__post_init__()  # type: ignore[attr-defined]
        validated.append(binding)
    found = [
        b
        for b in validated
        if getattr(b, "exact_contract", None) == contract
        and getattr(b, "official_day", None) == day
        and getattr(b, "valid_from_utc_ns", 0)
        <= moment
        < getattr(b, "valid_until_utc_ns", 0)
        and (offset is None or getattr(b, "offset", None) == offset)
    ]
    if len(found) != 1:
        raise AccountingContractError(
            f"exactly one binding is required; got {len(found)}"
        )
    return found[0]


def resolve_instrument_terms(
    bindings: Iterable[InstrumentTermsBinding],
    exact_contract: str,
    official_day: date,
    utc_ns: int,
) -> InstrumentTermsBinding:
    result = _resolve_exact_one(
        bindings,
        InstrumentTermsBinding,
        exact_contract,
        official_day,
        utc_ns,
    )
    return result  # type: ignore[return-value]


def resolve_fee_schedule(
    bindings: Iterable[FeeScheduleBinding],
    exact_contract: str,
    official_day: date,
    utc_ns: int,
    offset: str,
) -> FeeScheduleBinding:
    result = _resolve_exact_one(
        bindings,
        FeeScheduleBinding,
        exact_contract,
        official_day,
        utc_ns,
        offset=_offset(offset),
    )
    return result  # type: ignore[return-value]


def resolve_broker_markup(
    bindings: Iterable[BrokerMarkupBinding],
    exact_contract: str,
    official_day: date,
    utc_ns: int,
    offset: str,
) -> BrokerMarkupBinding:
    result = _resolve_exact_one(
        bindings,
        BrokerMarkupBinding,
        exact_contract,
        official_day,
        utc_ns,
        offset=_offset(offset),
    )
    return result  # type: ignore[return-value]


def _on_grid(price: Decimal, terms: InstrumentTermsBinding) -> Decimal:
    if (
        price <= 0
        or price / terms.tick_size != (price / terms.tick_size).to_integral_value()
    ):
        raise AccountingContractError("price is invalid or off tick grid")
    return price


def calculate_fee(
    price: object,
    terms: InstrumentTermsBinding,
    exchange: FeeScheduleBinding,
    broker: BrokerMarkupBinding,
    *,
    exact_contract: str,
    official_day: date,
    offset: str,
) -> tuple[Decimal, Decimal]:
    for binding, expected_type, name in (
        (terms, InstrumentTermsBinding, "terms"),
        (exchange, FeeScheduleBinding, "exchange fee"),
        (broker, BrokerMarkupBinding, "broker markup"),
    ):
        if type(binding) is not expected_type:
            raise AccountingContractError(
                f"{name} must be exact {expected_type.__name__}"
            )
        binding.__post_init__()
    contract, day, expected_offset = (
        _text(exact_contract, "exact_contract"),
        _day(official_day, "official_day"),
        _offset(offset),
    )
    if (
        any(
            b.exact_contract != contract or b.official_day != day
            for b in (terms, exchange, broker)
        )
        or exchange.offset != expected_offset
        or broker.offset != expected_offset
    ):
        raise AccountingContractError("terms, fee, markup contract/day/offset mismatch")
    fill = _on_grid(_decimal(price, "price"), terms)
    with localcontext() as context:
        context.prec = 50
        base = fill * terms.multiplier / Decimal(1000)
        exchange_unrounded = exchange.fixed_cny + base * exchange.ratio_per_mille
        broker_unrounded = broker.fixed_cny + base * broker.ratio_per_mille
    return (
        exchange_unrounded.quantize(FEE_ROUNDING_QUANTUM, rounding=FEE_ROUNDING_MODE),
        broker_unrounded.quantize(FEE_ROUNDING_QUANTUM, rounding=FEE_ROUNDING_MODE),
    )


@dataclass(frozen=True)
class ExecutionQuote:
    exact_contract: str
    raw_record_hash: str
    collector_generation: str
    clock_epoch: str
    segment_id: str
    collector_seq: int
    provider_update_id: str | None
    source_event_utc_ns: int
    receive_utc_ns: int
    receive_monotonic_ns: int
    active_time_ns: int
    official_day: date
    bid: Decimal
    bid_size: Decimal
    ask: Decimal
    ask_size: Decimal
    clock_sync_state: str
    reset_reason: str | None
    explicit_duplicate: bool

    def __post_init__(self) -> None:
        for name in (
            "exact_contract",
            "collector_generation",
            "clock_epoch",
            "segment_id",
            "clock_sync_state",
        ):
            _text(getattr(self, name), name)
        _sha256(self.raw_record_hash, "raw_record_hash")
        if self.provider_update_id is not None:
            _text(self.provider_update_id, "provider_update_id")
        for name in (
            "collector_seq",
            "source_event_utc_ns",
            "receive_utc_ns",
            "receive_monotonic_ns",
            "active_time_ns",
        ):
            _int(getattr(self, name), name, minimum=1)
        _day(self.official_day, "official_day")
        _positive(self.bid, "bid")
        _positive(self.ask, "ask")
        _nonnegative(self.bid_size, "bid_size")
        _nonnegative(self.ask_size, "ask_size")
        if self.reset_reason is not None:
            _text(self.reset_reason, "reset_reason")
        if not isinstance(self.explicit_duplicate, bool):
            raise AccountingContractError("explicit_duplicate must be bool")

    def qualified(self) -> bool:
        return (
            self.bid < self.ask
            and self.bid_size > 0
            and self.ask_size > 0
            and self.clock_sync_state == "SYNCED"
            and self.reset_reason is None
            and not self.explicit_duplicate
        )

    def execution_usable(self, side: str, min_side_size: Decimal = Decimal(1)) -> bool:
        minimum = _positive(min_side_size, "min_side_size")
        if side not in {"BUY", "SELL"}:
            raise AccountingContractError("execution side must be BUY or SELL")
        side_size = self.ask_size if side == "BUY" else self.bid_size
        return self.qualified() and side_size >= minimum


def resolve_close_offset(entry_official_day: date, exit_official_day: date) -> str:
    """Official day, not calendar date, determines the future close offset."""
    return (
        "CLOSE_TODAY"
        if _day(entry_official_day, "entry_official_day")
        == _day(exit_official_day, "exit_official_day")
        else "CLOSE_YESTERDAY"
    )


@dataclass(frozen=True)
class ExactExecutionLegRow:
    exact_contract: str
    scenario_id: str
    direction: str
    leg: str
    side: str
    offset: str
    signed_lots: int
    abs_lots: int
    position_before: int
    position_after: int
    quote: ExecutionQuote
    observed_aggressive_price: Decimal
    execution_price: Decimal
    adverse_ticks: int
    tick_size: Decimal
    multiplier: Decimal
    instrument_terms_binding_id: str
    fee_schedule_binding_id: str
    broker_markup_binding_id: str
    fee_rounding_quantum: Decimal
    fee_rounding_mode: str
    exchange_fee_cny: Decimal
    broker_fee_cny: Decimal

    def __post_init__(self) -> None:
        if type(self.quote) is not ExecutionQuote:
            raise AccountingContractError("execution quote must be exact ExecutionQuote")
        self.quote.__post_init__()
        _text(self.exact_contract, "exact_contract")
        scenario = frozen_scenario(self.scenario_id)
        if self.direction not in {"LONG", "SHORT"} or self.leg not in {"OPEN", "CLOSE"}:
            raise AccountingContractError("invalid execution direction or leg")
        expected_buy = (self.direction == "LONG" and self.leg == "OPEN") or (
            self.direction == "SHORT" and self.leg == "CLOSE"
        )
        expected_side = "BUY" if expected_buy else "SELL"
        expected_offset = "OPEN" if self.leg == "OPEN" else "CLOSE_TODAY"
        expected_position = (
            ((0, 1) if self.leg == "OPEN" else (1, 0))
            if self.direction == "LONG"
            else ((0, -1) if self.leg == "OPEN" else (-1, 0))
        )
        if (
            self.side != expected_side
            or self.offset != expected_offset
            or self.signed_lots != (1 if expected_buy else -1)
            or self.abs_lots != scenario.lots
            or (self.position_before, self.position_after) != expected_position
            or self.adverse_ticks != scenario.adverse_ticks
        ):
            raise AccountingContractError("execution leg scenario/position fields mismatch")
        if self.quote.exact_contract != self.exact_contract:
            raise AccountingContractError("execution leg quote contract mismatch")
        if not self.quote.execution_usable(expected_side, scenario.min_side_size):
            raise AccountingContractError("execution leg quote is not usable")
        observed = self.quote.ask if expected_buy else self.quote.bid
        if self.observed_aggressive_price != observed:
            raise AccountingContractError("execution leg observed price mismatch")
        execution = _positive(self.execution_price, "execution_price")
        tick_size = _positive(self.tick_size, "tick_size")
        expected_execution = (
            observed + tick_size * scenario.adverse_ticks
            if expected_buy
            else observed - tick_size * scenario.adverse_ticks
        )
        if execution != expected_execution:
            raise AccountingContractError("execution price does not match frozen adverse ticks")
        _positive(self.multiplier, "multiplier")
        for name in (
            "instrument_terms_binding_id",
            "fee_schedule_binding_id",
            "broker_markup_binding_id",
        ):
            _text(getattr(self, name), name)
        if (
            self.fee_rounding_quantum != FEE_ROUNDING_QUANTUM
            or self.fee_rounding_mode != FEE_ROUNDING_MODE
        ):
            raise AccountingContractError("execution leg fee rounding fields mismatch")
        _nonnegative(self.exchange_fee_cny, "exchange_fee_cny")
        _nonnegative(self.broker_fee_cny, "broker_fee_cny")

    @property
    def total_fee_cny(self) -> Decimal:
        return self.exchange_fee_cny + self.broker_fee_cny


@dataclass(frozen=True)
class TradeLedgerRow:
    attempt_id: str
    exact_contract: str
    scenario_id: str
    direction: str
    status: str
    failure_reason: str | None
    entry: ExactExecutionLegRow | None
    exit: ExactExecutionLegRow | None
    gross_ticks: Decimal | None
    gross_cny: Decimal | None
    exchange_fee_cny: Decimal | None
    broker_fee_cny: Decimal | None
    net_cny: Decimal | None

    def _validate_leg(
        self,
        value: ExactExecutionLegRow,
        expected_leg: str,
    ) -> None:
        if type(value) is not ExactExecutionLegRow:
            raise AccountingContractError("trade leg has an invalid type")
        value.__post_init__()
        if (
            value.exact_contract != self.exact_contract
            or value.scenario_id != self.scenario_id
            or value.direction != self.direction
            or value.leg != expected_leg
        ):
            kind = "closed" if self.status == "CLOSED" else "failed"
            raise AccountingContractError(
                f"{kind} trade legs are not self-consistent"
            )

    @staticmethod
    def _validate_leg_pair(
        entry: ExactExecutionLegRow,
        exit_leg: ExactExecutionLegRow,
        *,
        require_equal_terms: bool,
    ) -> None:
        if (
            entry.position_before != 0
            or exit_leg.position_after != 0
            or entry.position_after != exit_leg.position_before
            or entry.quote.official_day != exit_leg.quote.official_day
            or (
                entry.quote.collector_generation,
                entry.quote.clock_epoch,
                entry.quote.segment_id,
            )
            != (
                exit_leg.quote.collector_generation,
                exit_leg.quote.clock_epoch,
                exit_leg.quote.segment_id,
            )
            or exit_leg.quote.collector_seq <= entry.quote.collector_seq
            or exit_leg.quote.receive_utc_ns <= entry.quote.receive_utc_ns
            or exit_leg.quote.receive_monotonic_ns
            <= entry.quote.receive_monotonic_ns
            or exit_leg.quote.active_time_ns <= entry.quote.active_time_ns
            or exit_leg.quote.source_event_utc_ns
            < entry.quote.source_event_utc_ns
            or (
                require_equal_terms
                and (entry.tick_size, entry.multiplier)
                != (exit_leg.tick_size, exit_leg.multiplier)
            )
        ):
            kind = "closed" if require_equal_terms else "failed"
            raise AccountingContractError(
                f"{kind} trade legs are not self-consistent"
            )

    def __post_init__(self) -> None:
        _text(self.attempt_id, "attempt_id")
        _text(self.exact_contract, "exact_contract")
        frozen_scenario(self.scenario_id)
        if self.direction not in {"LONG", "SHORT"} or self.status not in {"CLOSED", "FAILED"}:
            raise AccountingContractError("invalid trade direction or status")
        economics = (
            self.gross_ticks,
            self.gross_cny,
            self.exchange_fee_cny,
            self.broker_fee_cny,
            self.net_cny,
        )
        entry, exit_leg = self.entry, self.exit
        if exit_leg is not None and entry is None:
            raise AccountingContractError("trade exit leg requires an entry leg")
        if entry is not None:
            self._validate_leg(entry, "OPEN")
        if exit_leg is not None:
            self._validate_leg(exit_leg, "CLOSE")
        if entry is not None and exit_leg is not None:
            self._validate_leg_pair(
                entry,
                exit_leg,
                require_equal_terms=self.status == "CLOSED",
            )
        if self.status == "FAILED":
            if self.failure_reason is None or any(value is not None for value in economics):
                raise AccountingContractError("failed trade must retain reason and no economics")
            _text(self.failure_reason, "failure_reason")
            return
        if self.failure_reason is not None or self.entry is None or self.exit is None:
            raise AccountingContractError("closed trade requires both legs and no failure")
        if any(value is None for value in economics):
            raise AccountingContractError("closed trade requires complete economics")
        assert entry is not None and exit_leg is not None
        gross_ticks = _decimal(self.gross_ticks, "gross_ticks")
        gross_cny = _decimal(self.gross_cny, "gross_cny")
        exchange_fee = _nonnegative(self.exchange_fee_cny, "exchange_fee_cny")
        broker_fee = _nonnegative(self.broker_fee_cny, "broker_fee_cny")
        net = _decimal(self.net_cny, "net_cny")
        expected_ticks = (
            (exit_leg.execution_price - entry.execution_price)
            if self.direction == "LONG"
            else (entry.execution_price - exit_leg.execution_price)
        ) / entry.tick_size
        expected_gross = expected_ticks * entry.tick_size * entry.multiplier * entry.abs_lots
        if (
            gross_ticks != expected_ticks
            or gross_cny != expected_gross
            or exchange_fee != entry.exchange_fee_cny + exit_leg.exchange_fee_cny
            or broker_fee != entry.broker_fee_cny + exit_leg.broker_fee_cny
            or net != gross_cny - exchange_fee - broker_fee
        ):
            raise AccountingContractError("closed trade economics are not self-consistent")


def make_execution_leg(
    contract: str,
    spec: ExecutionScenarioSpec,
    direction: str,
    leg: str,
    quote: ExecutionQuote,
    terms_rows: Iterable[InstrumentTermsBinding],
    fees: Iterable[FeeScheduleBinding],
    markups: Iterable[BrokerMarkupBinding],
) -> ExactExecutionLegRow:
    """Build one frozen, PIT-bound aggressive execution leg."""

    offset = "OPEN" if leg == "OPEN" else "CLOSE_TODAY"
    buy = (direction == "LONG" and leg == "OPEN") or (
        direction == "SHORT" and leg == "CLOSE"
    )
    side = "BUY" if buy else "SELL"
    if not quote.execution_usable(side, spec.min_side_size):
        raise AccountingContractError("quote is not execution-usable for actual side")
    terms = resolve_instrument_terms(
        terms_rows, contract, quote.official_day, quote.receive_utc_ns
    )
    exchange = resolve_fee_schedule(
        fees, contract, quote.official_day, quote.receive_utc_ns, offset
    )
    broker = resolve_broker_markup(
        markups, contract, quote.official_day, quote.receive_utc_ns, offset
    )
    observed = quote.ask if buy else quote.bid
    execution = _on_grid(
        observed + terms.tick_size * spec.adverse_ticks
        if buy
        else observed - terms.tick_size * spec.adverse_ticks,
        terms,
    )
    before, after = (
        ((0, 1) if leg == "OPEN" else (1, 0))
        if direction == "LONG"
        else ((0, -1) if leg == "OPEN" else (-1, 0))
    )
    exchange_fee, broker_fee = calculate_fee(
        execution,
        terms,
        exchange,
        broker,
        exact_contract=contract,
        official_day=quote.official_day,
        offset=offset,
    )
    return ExactExecutionLegRow(
        contract,
        spec.scenario_id,
        direction,
        leg,
        side,
        offset,
        1 if buy else -1,
        spec.lots,
        before,
        after,
        quote,
        observed,
        execution,
        spec.adverse_ticks,
        terms.tick_size,
        terms.multiplier,
        terms.binding_id,
        exchange.binding_id,
        broker.binding_id,
        FEE_ROUNDING_QUANTUM,
        FEE_ROUNDING_MODE,
        exchange_fee,
        broker_fee,
    )


_make_leg = make_execution_leg


def attempt_round_trip(
    attempt_id: str,
    exact_contract: str,
    scenario: ExecutionScenarioSpec,
    direction: str,
    entry_quote: ExecutionQuote,
    exit_quote: ExecutionQuote,
    terms_bindings: Iterable[InstrumentTermsBinding],
    fees: Iterable[FeeScheduleBinding],
    markups: Iterable[BrokerMarkupBinding],
) -> TradeLedgerRow:
    attempt, contract, spec = (
        _text(attempt_id, "attempt_id"),
        _text(exact_contract, "exact_contract"),
        require_frozen_scenario(scenario),
    )
    if direction not in {"LONG", "SHORT"}:
        raise AccountingContractError("direction must be LONG or SHORT")
    try:
        if (
            entry_quote.exact_contract != contract
            or exit_quote.exact_contract != contract
        ):
            raise AccountingContractError("quotes must match exact contract")
        if (
            entry_quote.collector_generation,
            entry_quote.clock_epoch,
            entry_quote.segment_id,
        ) != (
            exit_quote.collector_generation,
            exit_quote.clock_epoch,
            exit_quote.segment_id,
        ):
            raise AccountingContractError(
                "entry and exit must remain in one generation/epoch/segment lane"
            )
        if (
            exit_quote.collector_seq <= entry_quote.collector_seq
            or exit_quote.source_event_utc_ns < entry_quote.source_event_utc_ns
            or exit_quote.receive_utc_ns <= entry_quote.receive_utc_ns
            or exit_quote.receive_monotonic_ns <= entry_quote.receive_monotonic_ns
            or exit_quote.active_time_ns <= entry_quote.active_time_ns
        ):
            raise AccountingContractError(
                "entry and exit sequence and times must strictly increase"
            )
        if (
            resolve_close_offset(entry_quote.official_day, exit_quote.official_day)
            != "CLOSE_TODAY"
        ):
            raise AccountingContractError(
                "current P1 candidates cannot cross official trading day"
            )
        terms_rows, fee_rows, markup_rows = (
            tuple(terms_bindings),
            tuple(fees),
            tuple(markups),
        )
        entry: ExactExecutionLegRow | None = None
        exit: ExactExecutionLegRow | None = None
        entry = make_execution_leg(
            contract,
            spec,
            direction,
            "OPEN",
            entry_quote,
            terms_rows,
            fee_rows,
            markup_rows,
        )
        exit = make_execution_leg(
            contract,
            spec,
            direction,
            "CLOSE",
            exit_quote,
            terms_rows,
            fee_rows,
            markup_rows,
        )
        first = resolve_instrument_terms(
            terms_rows,
            contract,
            entry_quote.official_day,
            entry_quote.receive_utc_ns,
        )
        last = resolve_instrument_terms(
            terms_rows,
            contract,
            exit_quote.official_day,
            exit_quote.receive_utc_ns,
        )
        if (first.tick_size, first.multiplier) != (last.tick_size, last.multiplier):
            raise AccountingContractError(
                "entry and exit PIT terms must have equal tick size and multiplier"
            )
        gross_ticks = (
            (exit.execution_price - entry.execution_price)
            if direction == "LONG"
            else (entry.execution_price - exit.execution_price)
        ) / first.tick_size
        gross_cny = gross_ticks * first.tick_size * first.multiplier * spec.lots
        exchange_fee, broker_fee = (
            entry.exchange_fee_cny + exit.exchange_fee_cny,
            entry.broker_fee_cny + exit.broker_fee_cny,
        )
        return TradeLedgerRow(
            attempt,
            contract,
            spec.scenario_id,
            direction,
            "CLOSED",
            None,
            entry,
            exit,
            gross_ticks,
            gross_cny,
            exchange_fee,
            broker_fee,
            gross_cny - exchange_fee - broker_fee,
        )
    except AccountingContractError as exc:
        return TradeLedgerRow(
            attempt,
            contract,
            spec.scenario_id,
            direction,
            "FAILED",
            str(exc),
            entry if "entry" in locals() else None,
            exit if "exit" in locals() else None,
            None,
            None,
            None,
            None,
            None,
        )


@dataclass(frozen=True)
class LiquidationMtmRow:
    exact_contract: str
    direction: str
    liquidation_price: Decimal
    gross_cny: Decimal
    entry_paid_fee_cny: Decimal
    assumed_exit_fee_cny: Decimal
    net_cny: Decimal


def liquidation_side_mtm(
    exact_contract: str,
    scenario: ExecutionScenarioSpec,
    direction: str,
    entry_price: object,
    entry_official_day: date,
    entry_receive_utc_ns: int,
    entry_paid_fee_cny: object,
    quote: ExecutionQuote,
    terms_bindings: Iterable[InstrumentTermsBinding],
    fees: Iterable[FeeScheduleBinding],
    markups: Iterable[BrokerMarkupBinding],
) -> LiquidationMtmRow:
    contract = _text(exact_contract, "exact_contract")
    spec = require_frozen_scenario(scenario)
    if (
        direction not in {"LONG", "SHORT"}
        or quote.exact_contract != contract
        or not quote.execution_usable("SELL" if direction == "LONG" else "BUY")
    ):
        raise AccountingContractError(
            "liquidation inputs must be usable and contract-exact"
        )
    terms_rows, fee_rows, markup_rows = (
        tuple(terms_bindings),
        tuple(fees),
        tuple(markups),
    )
    entry_day = _day(entry_official_day, "entry_official_day")
    entry_terms = resolve_instrument_terms(
        terms_rows,
        contract,
        entry_day,
        _int(entry_receive_utc_ns, "entry_receive_utc_ns", minimum=1),
    )
    terms = resolve_instrument_terms(
        terms_rows, contract, quote.official_day, quote.receive_utc_ns
    )
    if (entry_terms.tick_size, entry_terms.multiplier) != (
        terms.tick_size,
        terms.multiplier,
    ):
        raise AccountingContractError("entry and liquidation PIT terms must match")
    entry = _on_grid(_decimal(entry_price, "entry_price"), entry_terms)
    observed_exit = quote.bid if direction == "LONG" else quote.ask
    exit_price = _on_grid(
        observed_exit - terms.tick_size * spec.adverse_ticks
        if direction == "LONG"
        else observed_exit + terms.tick_size * spec.adverse_ticks,
        terms,
    )
    offset = resolve_close_offset(
        entry_day, quote.official_day
    )
    exchange = resolve_fee_schedule(
        fee_rows, contract, quote.official_day, quote.receive_utc_ns, offset
    )
    broker = resolve_broker_markup(
        markup_rows, contract, quote.official_day, quote.receive_utc_ns, offset
    )
    exit_exchange, exit_broker = calculate_fee(
        exit_price,
        terms,
        exchange,
        broker,
        exact_contract=contract,
        official_day=quote.official_day,
        offset=offset,
    )
    gross = (
        (exit_price - entry) if direction == "LONG" else (entry - exit_price)
    ) * terms.multiplier * spec.lots
    entry_fee = _nonnegative(entry_paid_fee_cny, "entry_paid_fee_cny")
    return LiquidationMtmRow(
        contract,
        direction,
        exit_price,
        gross,
        entry_fee,
        exit_exchange + exit_broker,
        gross - entry_fee - exit_exchange - exit_broker,
    )


@dataclass(frozen=True)
class DailyAggregateRow:
    product: str
    scenario_id: str
    official_day: date
    trade_count: int
    net_cny: Decimal
    priced: bool

    def __post_init__(self) -> None:
        _text(self.product, "product")
        if self.scenario_id != PRIMARY_SCENARIO_ID:
            raise AccountingContractError("daily aggregation is PRIMARY-only")
        _day(self.official_day, "official_day")
        _int(self.trade_count, "trade_count")
        net = _decimal(self.net_cny, "net_cny")
        if self.trade_count == 0 and net != 0:
            raise AccountingContractError("zero-trade daily row must have zero net_cny")
        if not isinstance(self.priced, bool):
            raise AccountingContractError("priced must be bool")


@dataclass(frozen=True)
class ProductBest3Result:
    product: str
    removed_days: tuple[date, ...]
    retained_net_cny: Decimal
    total_net_cny: Decimal


@dataclass(frozen=True)
class DailyCoverageEvidence:
    """One sealed/priced accounting-attempt coverage record for one daily cell."""

    product: str
    exact_contract: str
    scenario_id: str
    official_day: date
    sealed: bool
    priced: bool
    attempt_count: int

    def __post_init__(self) -> None:
        _text(self.product, "product")
        _text(self.exact_contract, "exact_contract")
        if self.scenario_id != PRIMARY_SCENARIO_ID:
            raise AccountingContractError("daily coverage is PRIMARY-only")
        _day(self.official_day, "official_day")
        if not isinstance(self.sealed, bool) or not isinstance(self.priced, bool):
            raise AccountingContractError("daily coverage sealed/priced must be bool")
        _int(self.attempt_count, "attempt_count")


def aggregate_fixed_20_day_grid(
    trades: Iterable[TradeLedgerRow],
    product_by_contract: dict[str, str],
    grid: Sequence[date],
    coverage: Iterable[DailyCoverageEvidence],
    scenario: ExecutionScenarioSpec = PRIMARY,
    *,
    terms_bindings: Iterable[InstrumentTermsBinding],
    fees: Iterable[FeeScheduleBinding],
    markups: Iterable[BrokerMarkupBinding],
    trusted_quotes_by_raw_record_hash: Mapping[str, ExecutionQuote],
) -> tuple[DailyAggregateRow, ...]:
    if require_frozen_scenario(scenario).scenario_id != PRIMARY_SCENARIO_ID:
        raise AccountingContractError("fixed 20-day aggregation is PRIMARY-only")
    if len(grid) != 20 or len(set(grid)) != 20 or tuple(sorted(grid)) != tuple(grid):
        raise AccountingContractError("grid must be 20 unique ascending official days")
    known = {
        _text(contract, "exact_contract"): _text(product, "product")
        for contract, product in product_by_contract.items()
    }
    if len(set(known.values())) != len(known):
        raise AccountingContractError(
            "product mapping must contain one exact contract per product"
        )
    if len(known) != 2:
        raise AccountingContractError("full holdout grid requires exactly two products")
    expected_coverage = {
        (product, contract, day)
        for contract, product in known.items()
        for day in grid
    }
    trusted_terms = tuple(terms_bindings)
    trusted_fees = tuple(fees)
    trusted_markups = tuple(markups)
    for values, expected_type, name in (
        (trusted_terms, InstrumentTermsBinding, "instrument terms"),
        (trusted_fees, FeeScheduleBinding, "fee schedule"),
        (trusted_markups, BrokerMarkupBinding, "broker markup"),
    ):
        for binding in values:
            if type(binding) is not expected_type:
                raise AccountingContractError(
                    f"trusted {name} must be exact {expected_type.__name__}"
                )
            binding.__post_init__()
    if type(trusted_quotes_by_raw_record_hash) is not dict:
        raise AccountingContractError("trusted raw quote map must be an exact dict")
    trusted_quotes: dict[str, ExecutionQuote] = {}
    for supplied_hash, quote in trusted_quotes_by_raw_record_hash.items():
        record_hash = _sha256(supplied_hash, "trusted raw_record_hash")
        if type(quote) is not ExecutionQuote:
            raise AccountingContractError(
                "trusted raw quote must be exact ExecutionQuote"
            )
        quote.__post_init__()
        if quote.raw_record_hash != record_hash:
            raise AccountingContractError("trusted raw quote map key mismatch")
        trusted_quotes[record_hash] = quote
    evidence_by_cell: dict[tuple[str, str, date], DailyCoverageEvidence] = {}
    for evidence in coverage:
        if type(evidence) is not DailyCoverageEvidence:
            raise AccountingContractError(
                "daily coverage must be exact DailyCoverageEvidence"
            )
        evidence.__post_init__()
        key = (evidence.product, evidence.exact_contract, evidence.official_day)
        if key in evidence_by_cell:
            raise AccountingContractError("duplicate daily coverage evidence")
        if known.get(evidence.exact_contract) != evidence.product:
            raise AccountingContractError("daily coverage product/contract mismatch")
        if not evidence.sealed or not evidence.priced:
            raise AccountingContractError("daily coverage must be sealed and priced")
        evidence_by_cell[key] = evidence
    if set(evidence_by_cell) != expected_coverage:
        raise AccountingContractError("daily coverage must be complete and exact")
    all_trades = tuple(trades)
    attempt_counts: dict[tuple[str, str, date], int] = {
        key: 0 for key in expected_coverage
    }
    seen_attempt_ids: set[str] = set()
    for trade in all_trades:
        if type(trade) is not TradeLedgerRow:
            raise AccountingContractError("trade must be exact TradeLedgerRow")
        trade.__post_init__()
        trade_scenario = frozen_scenario(trade.scenario_id)
        for leg_name, leg in (("OPEN", trade.entry), ("CLOSE", trade.exit)):
            if leg is None:
                continue
            if type(leg) is not ExactExecutionLegRow:
                raise AccountingContractError(
                    "trade leg must be exact ExactExecutionLegRow"
                )
            if type(leg.quote) is not ExecutionQuote:
                raise AccountingContractError(
                    "trade quote must be exact ExecutionQuote"
                )
            leg.quote.__post_init__()
            trusted_quote = trusted_quotes.get(leg.quote.raw_record_hash)
            if trusted_quote is None or leg.quote != trusted_quote:
                raise AccountingContractError(
                    "trade leg does not match trusted raw quote"
                )
            expected_leg = make_execution_leg(
                trade.exact_contract,
                trade_scenario,
                trade.direction,
                leg_name,
                leg.quote,
                trusted_terms,
                trusted_fees,
                trusted_markups,
            )
            if leg != expected_leg:
                raise AccountingContractError(
                    "trade leg does not match trusted PIT bindings"
                )
        if trade.attempt_id in seen_attempt_ids:
            raise AccountingContractError("trade attempt_id must be globally unique")
        seen_attempt_ids.add(trade.attempt_id)
        if trade.exact_contract not in known:
            raise AccountingContractError("product mapping missing for exact contract")
        attempt_leg = trade.entry or trade.exit
        if attempt_leg is None:
            raise AccountingContractError("trade attempt cannot be attributed to a coverage day")
        key = (
            known[trade.exact_contract],
            trade.exact_contract,
            attempt_leg.quote.official_day,
        )
        if key not in attempt_counts:
            raise AccountingContractError("trade attempt day is outside fixed coverage")
        attempt_counts[key] += 1
    for key, evidence in evidence_by_cell.items():
        if evidence.attempt_count != attempt_counts[key]:
            raise AccountingContractError("daily coverage attempt_count does not reconcile")
    sums: dict[tuple[str, date], Decimal] = {}
    counts: dict[tuple[str, date], int] = {}
    for trade in all_trades:
        trade.__post_init__()
        if trade.scenario_id != PRIMARY_SCENARIO_ID:
            raise AccountingContractError(
                "non-PRIMARY trade blocks PRIMARY aggregation"
            )
        if trade.status != "CLOSED" or trade.net_cny is None or trade.exit is None:
            raise AccountingContractError(
                "bad or unpriced PRIMARY day blocks aggregation"
            )
        if trade.exact_contract not in known:
            raise AccountingContractError("product mapping missing for exact contract")
        key = (known[trade.exact_contract], trade.exit.quote.official_day)
        if key[1] not in grid:
            raise AccountingContractError("trade official day is outside fixed grid")
        sums[key] = sums.get(key, Decimal(0)) + trade.net_cny
        counts[key] = counts.get(key, 0) + 1
    return tuple(
        DailyAggregateRow(
            product,
            PRIMARY_SCENARIO_ID,
            day,
            counts.get((product, day), 0),
            sums.get((product, day), Decimal(0)),
            True,
        )
        for product in sorted(known.values())
        for day in grid
    )


def primary_best3_removal(
    rows: Iterable[DailyAggregateRow], grid: Sequence[date]
) -> tuple[ProductBest3Result, ...]:
    if (
        len(grid) != 20
        or len(set(grid)) != 20
        or tuple(sorted(grid)) != tuple(grid)
    ):
        raise AccountingContractError("best-3 removal requires the fixed 20-day grid")
    grouped: dict[str, list[DailyAggregateRow]] = {}
    for row in rows:
        if type(row) is not DailyAggregateRow:
            raise AccountingContractError(
                "best-3 input must be exact DailyAggregateRow"
            )
        row.__post_init__()
        if row.scenario_id != PRIMARY_SCENARIO_ID or not row.priced:
            raise AccountingContractError(
                "unpriced/non-PRIMARY row blocks best-3 removal"
            )
        grouped.setdefault(row.product, []).append(row)
    if len(grouped) != 2:
        raise AccountingContractError("pooled best-3 requires exactly two products")
    pooled_by_day: dict[date, Decimal] = {day: Decimal(0) for day in grid}
    for product, values in sorted(grouped.items()):
        if len(values) != 20 or {row.official_day for row in values} != set(grid):
            raise AccountingContractError(
                "each product must independently have all 20 daily rows"
            )
        for row in values:
            pooled_by_day[row.official_day] += row.net_cny
    removed_days = tuple(
        day
        for day, _ in sorted(
            pooled_by_day.items(), key=lambda item: (-item[1], item[0])
        )[:3]
    )
    result = []
    for product, values in sorted(grouped.items()):
        total = sum((row.net_cny for row in values), Decimal(0))
        removed = sum(
            (row.net_cny for row in values if row.official_day in removed_days),
            Decimal(0),
        )
        result.append(
            ProductBest3Result(
                product,
                removed_days,
                total - removed,
                total,
            )
        )
    return tuple(result)


@dataclass(frozen=True)
class BootstrapGateResult:
    status: str
    reason: str


def bootstrap_parameters_gate() -> BootstrapGateResult:
    return BootstrapGateResult(
        "BLOCKED", "bootstrap parameters are not frozen by Issue #488 P1"
    )
