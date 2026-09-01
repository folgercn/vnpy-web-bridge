"""Offline kernel for the issue #488 collector-observed L1 research line.

The module deliberately models ordered *observations* from one dedicated
collector.  It does not claim exchange-native order-flow events, queue state,
passive fills, capacity, or permission to collect data or place orders.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
from typing import Iterable, Mapping, Sequence


RESEARCH_LINE_ID = "CN_COMMODITY_HFT_BBO_CHANGE_LAB_V1"
CANDIDATE_ID = "COLLECTOR_ORDERED_L1_BBO_CHANGE_IMBALANCE_V1"
DATA_CONTRACT_ID = "CN_FUTURES_CONTINUOUS_EXACT_L1_OBSERVED_UPDATE_V1"

FEATURE_WINDOW_NS = 10_000_000_000
HOLDING_HORIZON_NS = 30_000_000_000
PRIMARY_LATENCY_NS = 500_000_000
MAX_SOURCE_RECEIVE_P99_NS = 250_000_000
MAX_SOURCE_TIME_PRECISION_NS = 1_000_000
MAX_CLOCK_UNCERTAINTY_NS = 25_000_000
MAX_ABS_CLOCK_OFFSET_NS = 100_000_000
MINIMUM_CALIBRATION_SCORES = 1_000

_SYNCED = "SYNCED"
_LONG = "LONG"
_SHORT = "SHORT"
_CONTROL_EVENTS = {
    "COLLECTOR_START",
    "DISCONNECT",
    "RECONNECT",
    "CLOCK_EPOCH_CHANGE",
    "SESSION_SEGMENT_START",
    "SESSION_SEGMENT_END",
    "BACKPRESSURE_ABORT",
    "SINK_FAILURE_ABORT",
    "COLLECTOR_STOP",
}


class BBOChangeContractError(ValueError):
    """Raised when the collector contract cannot be interpreted safely."""


def _require_int(value: object, field_name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise BBOChangeContractError(
            f"{field_name} must be an integer >= {minimum}"
        )
    return value


def _require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BBOChangeContractError(f"{field_name} must be non-empty text")
    return value.strip()


def _decimal(value: object, field_name: str) -> Decimal:
    if isinstance(value, bool):
        raise BBOChangeContractError(f"{field_name} must be finite")
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise BBOChangeContractError(f"{field_name} must be finite") from exc
    if not result.is_finite():
        raise BBOChangeContractError(f"{field_name} must be finite")
    return result


@dataclass(frozen=True)
class ObservedBBO:
    """One callback observed by a dedicated collector.

    ``collector_seq`` is local to ``collector_generation`` and must be gapless.
    ``receive_monotonic_ns`` and ``active_time_ns`` are comparable only inside
    the same ``clock_epoch`` and continuous ``segment_id``.
    """

    collector_generation: str
    clock_epoch: str
    exact_contract: str
    session_family: str
    segment_id: str
    collector_seq: int
    source_event_ns: int
    receive_utc_ns: int
    receive_monotonic_ns: int
    active_time_ns: int
    bid_price: object
    bid_size: object
    ask_price: object
    ask_size: object
    provider_update_id: str | None = None
    explicit_duplicate: bool = False
    reset_reason: str | None = None
    clock_sync_state: str = _SYNCED
    clock_offset_ns: int = 0
    clock_uncertainty_ns: int = 0
    source_time_precision_ns: int = 1


@dataclass(frozen=True)
class CollectorControl:
    """One lifecycle record sharing the run-global collector sequence."""

    collector_generation: str
    clock_epoch: str
    collector_seq: int
    receive_utc_ns: int
    receive_monotonic_ns: int
    event_type: str
    reason: str


@dataclass(frozen=True)
class ControlPoint:
    collector_generation: str
    clock_epoch: str
    collector_seq: int
    receive_monotonic_ns: int
    event_type: str
    status: str


@dataclass(frozen=True)
class _QualifiedBBO:
    raw: ObservedBBO
    bid_price: Decimal
    bid_size: Decimal
    ask_price: Decimal
    ask_size: Decimal

    @property
    def depth(self) -> Decimal:
        return (self.bid_size + self.ask_size) / Decimal(2)


@dataclass(frozen=True)
class FeaturePoint:
    exact_contract: str
    session_family: str
    segment_id: str
    collector_generation: str
    clock_epoch: str
    collector_seq: int
    source_event_ns: int
    receive_monotonic_ns: int
    active_time_ns: int
    status: str
    contribution: Decimal | None = None
    raw_imbalance: Decimal | None = None
    depth_scale: Decimal | None = None
    score: Decimal | None = None
    window_terms: int = 0
    reset_reason: str | None = None


@dataclass(frozen=True)
class FrozenThreshold:
    exact_contract: str
    session_family: str
    quantile: Decimal
    sample_count: int
    threshold: Decimal


@dataclass(frozen=True)
class SignalDecision:
    exact_contract: str
    session_family: str
    segment_id: str
    collector_generation: str
    clock_epoch: str
    collector_seq: int
    source_event_ns: int
    receive_monotonic_ns: int
    active_time_ns: int
    direction: str
    score: Decimal
    threshold: Decimal


@dataclass(frozen=True)
class AggressiveFill:
    collector_seq: int
    receive_monotonic_ns: int
    active_time_ns: int
    side: str
    price: Decimal


@dataclass(frozen=True)
class RoundTripReplay:
    status: str
    signal: SignalDecision
    entry: AggressiveFill | None = None
    exit: AggressiveFill | None = None


@dataclass(frozen=True)
class ClockGateResult:
    passed: bool
    sample_count: int
    p99_lag_ns: int | None
    reason: str


@dataclass(frozen=True)
class _WindowTerm:
    active_time_ns: int
    contribution: Decimal
    depth: Decimal


@dataclass
class _BookState:
    previous: _QualifiedBBO | None = None
    baseline_active_ns: int | None = None
    terms: deque[_WindowTerm] = field(default_factory=deque)


def _metadata(obs: ObservedBBO) -> None:
    _require_text(obs.collector_generation, "collector_generation")
    _require_text(obs.clock_epoch, "clock_epoch")
    _require_text(obs.exact_contract, "exact_contract")
    _require_text(obs.session_family, "session_family")
    _require_text(obs.segment_id, "segment_id")
    _require_int(obs.collector_seq, "collector_seq", minimum=1)
    _require_int(obs.source_event_ns, "source_event_ns")
    _require_int(obs.receive_utc_ns, "receive_utc_ns")
    _require_int(obs.receive_monotonic_ns, "receive_monotonic_ns")
    _require_int(obs.active_time_ns, "active_time_ns")
    _require_int(obs.clock_offset_ns, "clock_offset_ns", minimum=-10**18)
    _require_int(obs.clock_uncertainty_ns, "clock_uncertainty_ns")
    _require_int(
        obs.source_time_precision_ns,
        "source_time_precision_ns",
        minimum=1,
    )
    if obs.provider_update_id is not None:
        _require_text(obs.provider_update_id, "provider_update_id")
    if obs.reset_reason is not None:
        _require_text(obs.reset_reason, "reset_reason")


def _control_metadata(control: CollectorControl) -> None:
    _require_text(control.collector_generation, "collector_generation")
    _require_text(control.clock_epoch, "clock_epoch")
    _require_int(control.collector_seq, "collector_seq", minimum=1)
    _require_int(control.receive_utc_ns, "receive_utc_ns")
    _require_int(control.receive_monotonic_ns, "receive_monotonic_ns")
    event_type = _require_text(control.event_type, "event_type")
    _require_text(control.reason, "reason")
    if event_type not in _CONTROL_EVENTS:
        raise BBOChangeContractError("unsupported collector control event")


def _qualified(obs: ObservedBBO) -> _QualifiedBBO | None:
    try:
        bid_price = _decimal(obs.bid_price, "bid_price")
        bid_size = _decimal(obs.bid_size, "bid_size")
        ask_price = _decimal(obs.ask_price, "ask_price")
        ask_size = _decimal(obs.ask_size, "ask_size")
    except BBOChangeContractError:
        return None
    if (
        bid_price <= 0
        or ask_price <= 0
        or bid_size <= 0
        or ask_size <= 0
        or bid_price >= ask_price
    ):
        return None
    return _QualifiedBBO(
        raw=obs,
        bid_price=bid_price,
        bid_size=bid_size,
        ask_price=ask_price,
        ask_size=ask_size,
    )


def bbo_change_contribution(previous: ObservedBBO, current: ObservedBBO) -> Decimal:
    """Return the frozen signed price/size change contribution."""

    previous_bbo = _qualified(previous)
    current_bbo = _qualified(current)
    if previous_bbo is None or current_bbo is None:
        raise BBOChangeContractError("both BBO observations must be qualified")
    value = Decimal(0)
    if current_bbo.bid_price >= previous_bbo.bid_price:
        value += current_bbo.bid_size
    if current_bbo.bid_price <= previous_bbo.bid_price:
        value -= previous_bbo.bid_size
    if current_bbo.ask_price <= previous_bbo.ask_price:
        value -= current_bbo.ask_size
    if current_bbo.ask_price >= previous_bbo.ask_price:
        value += previous_bbo.ask_size
    return value


def _raw_fingerprint(obs: ObservedBBO) -> tuple[object, ...]:
    return (
        obs.collector_generation,
        obs.clock_epoch,
        obs.exact_contract,
        obs.session_family,
        obs.segment_id,
        obs.source_event_ns,
        (type(obs.bid_price).__qualname__, repr(obs.bid_price)),
        (type(obs.bid_size).__qualname__, repr(obs.bid_size)),
        (type(obs.ask_price).__qualname__, repr(obs.ask_price)),
        (type(obs.ask_size).__qualname__, repr(obs.ask_size)),
        obs.provider_update_id,
    )


class BBOChangeEngine:
    """Gapless collector-order state machine for the frozen 10-second score."""

    def __init__(self) -> None:
        self._generation: str | None = None
        self._clock_epoch: str | None = None
        self._last_collector_seq: int | None = None
        self._last_receive_monotonic_ns: int | None = None
        self._last_raw_fingerprint: tuple[object, ...] | None = None
        self._last_provider_update_id: str | None = None
        self._aborted_generation: str | None = None
        self._states: dict[tuple[str, str, str], _BookState] = {}

    def _point(
        self,
        obs: ObservedBBO,
        status: str,
        **values: object,
    ) -> FeaturePoint:
        return FeaturePoint(
            exact_contract=obs.exact_contract,
            session_family=obs.session_family,
            segment_id=obs.segment_id,
            collector_generation=obs.collector_generation,
            clock_epoch=obs.clock_epoch,
            collector_seq=obs.collector_seq,
            source_event_ns=obs.source_event_ns,
            receive_monotonic_ns=obs.receive_monotonic_ns,
            active_time_ns=obs.active_time_ns,
            status=status,
            **values,
        )

    def _accept_ordering(
        self,
        *,
        collector_generation: str,
        clock_epoch: str,
        collector_seq: int,
        receive_monotonic_ns: int,
    ) -> tuple[bool, bool]:
        generation_changed = self._generation != collector_generation
        epoch_changed = self._clock_epoch != clock_epoch
        if generation_changed:
            if collector_seq != 1:
                self._aborted_generation = collector_generation
                raise BBOChangeContractError(
                    "a collector generation must begin at collector_seq=1"
                )
            self._states.clear()
            self._last_collector_seq = None
            self._last_receive_monotonic_ns = None
            self._last_raw_fingerprint = None
            self._last_provider_update_id = None
            self._aborted_generation = None
            self._generation = collector_generation
            self._clock_epoch = clock_epoch
        elif self._aborted_generation == collector_generation:
            raise BBOChangeContractError(
                "collector generation is aborted; start a new generation"
            )
        elif epoch_changed:
            self._states.clear()
            self._last_receive_monotonic_ns = None
            self._last_raw_fingerprint = None
            self._last_provider_update_id = None
            self._clock_epoch = clock_epoch

        if self._last_collector_seq is not None:
            expected = self._last_collector_seq + 1
            if collector_seq != expected:
                self._aborted_generation = collector_generation
                raise BBOChangeContractError(
                    f"collector_seq must be gapless: expected {expected}"
                )
        if (
            self._last_receive_monotonic_ns is not None
            and receive_monotonic_ns < self._last_receive_monotonic_ns
        ):
            self._aborted_generation = collector_generation
            raise BBOChangeContractError("receive_monotonic_ns regressed")
        self._last_collector_seq = collector_seq
        self._last_receive_monotonic_ns = receive_monotonic_ns
        return generation_changed, epoch_changed

    def process_control(self, control: CollectorControl) -> ControlPoint:
        """Consume one lifecycle record without creating a sequence gap."""

        _control_metadata(control)
        generation_changed, epoch_changed = self._accept_ordering(
            collector_generation=control.collector_generation,
            clock_epoch=control.clock_epoch,
            collector_seq=control.collector_seq,
            receive_monotonic_ns=control.receive_monotonic_ns,
        )
        if control.event_type == "COLLECTOR_START" and not generation_changed:
            self._aborted_generation = control.collector_generation
            raise BBOChangeContractError(
                "COLLECTOR_START requires a new collector generation"
            )
        if control.event_type == "CLOCK_EPOCH_CHANGE" and not epoch_changed:
            self._aborted_generation = control.collector_generation
            raise BBOChangeContractError(
                "CLOCK_EPOCH_CHANGE requires a new clock epoch"
            )
        self._states.clear()
        self._last_raw_fingerprint = None
        self._last_provider_update_id = None
        aborting = control.event_type in {
            "BACKPRESSURE_ABORT",
            "SINK_FAILURE_ABORT",
            "COLLECTOR_STOP",
        }
        if aborting:
            self._aborted_generation = control.collector_generation
        return ControlPoint(
            collector_generation=control.collector_generation,
            clock_epoch=control.clock_epoch,
            collector_seq=control.collector_seq,
            receive_monotonic_ns=control.receive_monotonic_ns,
            event_type=control.event_type,
            status="GENERATION_ABORTED" if aborting else "STATE_RESET",
        )

    def process(self, obs: ObservedBBO) -> FeaturePoint:
        _metadata(obs)
        generation_changed, epoch_changed = self._accept_ordering(
            collector_generation=obs.collector_generation,
            clock_epoch=obs.clock_epoch,
            collector_seq=obs.collector_seq,
            receive_monotonic_ns=obs.receive_monotonic_ns,
        )

        raw_fingerprint = _raw_fingerprint(obs)
        if obs.explicit_duplicate:
            if (
                obs.provider_update_id is None
                or obs.provider_update_id != self._last_provider_update_id
                or raw_fingerprint != self._last_raw_fingerprint
                or obs.reset_reason is not None
            ):
                self._aborted_generation = obs.collector_generation
                raise BBOChangeContractError(
                    "explicit duplicate must exactly match the preceding "
                    "provider update"
                )
            return self._point(obs, "EXPLICIT_DUPLICATE_SKIPPED")
        if (
            obs.provider_update_id is not None
            and obs.provider_update_id == self._last_provider_update_id
        ):
            self._aborted_generation = obs.collector_generation
            raise BBOChangeContractError(
                "repeated provider_update_id must be marked explicit_duplicate"
            )

        self._last_raw_fingerprint = raw_fingerprint
        self._last_provider_update_id = obs.provider_update_id

        key = (obs.exact_contract, obs.session_family, obs.segment_id)
        state = self._states.setdefault(key, _BookState())
        current = _qualified(obs)
        if current is None:
            self._states[key] = _BookState()
            return self._point(obs, "INVALID_BBO_RESET", reset_reason="INVALID_BBO")
        if generation_changed or epoch_changed:
            self._states[key] = _BookState(
                previous=current,
                baseline_active_ns=obs.active_time_ns,
            )
            reason = "COLLECTOR_GENERATION" if generation_changed else "CLOCK_EPOCH"
            return self._point(obs, "BASELINE_RESET", reset_reason=reason)
        if obs.reset_reason is not None:
            self._states[key] = _BookState(
                previous=current,
                baseline_active_ns=obs.active_time_ns,
            )
            return self._point(
                obs,
                "BASELINE_RESET",
                reset_reason=obs.reset_reason,
            )
        if state.previous is None or state.baseline_active_ns is None:
            state.previous = current
            state.baseline_active_ns = obs.active_time_ns
            state.terms.clear()
            return self._point(obs, "BASELINE_ONLY")

        previous = state.previous
        previous_obs = previous.raw
        if obs.source_event_ns < previous_obs.source_event_ns:
            self._states[key] = _BookState(
                previous=current,
                baseline_active_ns=obs.active_time_ns,
            )
            return self._point(
                obs,
                "SOURCE_TIME_REGRESSION_RESET",
                reset_reason="SOURCE_TIME_REGRESSION",
            )
        if obs.active_time_ns < previous_obs.active_time_ns:
            self._states[key] = _BookState(
                previous=current,
                baseline_active_ns=obs.active_time_ns,
            )
            return self._point(
                obs,
                "ACTIVE_TIME_REGRESSION_RESET",
                reset_reason="ACTIVE_TIME_REGRESSION",
            )
        active_delta = obs.active_time_ns - previous_obs.active_time_ns
        monotonic_delta = (
            obs.receive_monotonic_ns - previous_obs.receive_monotonic_ns
        )
        if active_delta != monotonic_delta:
            self._aborted_generation = obs.collector_generation
            raise BBOChangeContractError(
                "active_time_ns must advance with receive_monotonic_ns inside a segment"
            )
        if active_delta >= FEATURE_WINDOW_NS:
            self._states[key] = _BookState(
                previous=current,
                baseline_active_ns=obs.active_time_ns,
            )
            return self._point(
                obs,
                "LONG_GAP_RESET",
                reset_reason="LONG_GAP",
            )

        contribution = bbo_change_contribution(previous_obs, obs)
        state.previous = current
        state.terms.append(
            _WindowTerm(
                active_time_ns=obs.active_time_ns,
                contribution=contribution,
                depth=current.depth,
            )
        )
        lower_bound = obs.active_time_ns - FEATURE_WINDOW_NS
        while state.terms and state.terms[0].active_time_ns <= lower_bound:
            state.terms.popleft()

        if obs.active_time_ns - state.baseline_active_ns < FEATURE_WINDOW_NS:
            return self._point(
                obs,
                "WARMING_UP",
                contribution=contribution,
                window_terms=len(state.terms),
            )
        if not state.terms:
            return self._point(obs, "EMPTY_WINDOW")
        raw_imbalance = sum(
            (term.contribution for term in state.terms),
            start=Decimal(0),
        )
        depth_scale = sum(
            (term.depth for term in state.terms),
            start=Decimal(0),
        ) / Decimal(len(state.terms))
        if depth_scale <= 0:
            return self._point(obs, "INVALID_DEPTH_SCALE")
        with localcontext() as context:
            context.prec = 50
            context.rounding = ROUND_HALF_EVEN
            score = raw_imbalance / depth_scale
        return self._point(
            obs,
            "SCORE_READY",
            contribution=contribution,
            raw_imbalance=raw_imbalance,
            depth_scale=depth_scale,
            score=score,
            window_terms=len(state.terms),
        )


def _nearest_rank(values: Sequence[Decimal], quantile: Decimal) -> Decimal:
    if not values:
        raise BBOChangeContractError("quantile requires at least one value")
    if quantile != Decimal("0.95"):
        raise BBOChangeContractError("only the frozen nearest-rank Q95 is allowed")
    ordered = sorted(values)
    rank = (95 * len(ordered) + 99) // 100
    return ordered[max(0, rank - 1)]


def freeze_feature_only_thresholds(
    points: Iterable[FeaturePoint],
) -> dict[tuple[str, str], FrozenThreshold]:
    """Freeze per-contract/session Q95 without accepting any outcome input."""

    grouped: dict[tuple[str, str], list[Decimal]] = defaultdict(list)
    for point in points:
        if point.status == "SCORE_READY" and point.score is not None:
            grouped[(point.exact_contract, point.session_family)].append(
                abs(point.score)
            )
    if not grouped:
        raise BBOChangeContractError("no eligible feature-only scores")
    frozen: dict[tuple[str, str], FrozenThreshold] = {}
    for key in sorted(grouped):
        values = grouped[key]
        if len(values) < MINIMUM_CALIBRATION_SCORES:
            raise BBOChangeContractError(
                f"insufficient feature-only scores for {key}: {len(values)}"
            )
        threshold = _nearest_rank(values, Decimal("0.95"))
        if threshold <= 0:
            raise BBOChangeContractError(
                f"non-positive Q95 threshold for {key} is degenerate"
            )
        frozen[key] = FrozenThreshold(
            exact_contract=key[0],
            session_family=key[1],
            quantile=Decimal("0.95"),
            sample_count=len(values),
            threshold=threshold,
        )
    return frozen


def signal_from_threshold(
    point: FeaturePoint,
    thresholds: Mapping[tuple[str, str], FrozenThreshold],
) -> SignalDecision | None:
    if point.status != "SCORE_READY" or point.score is None:
        return None
    if not point.score.is_finite():
        raise BBOChangeContractError("feature score must be finite")
    frozen = thresholds.get((point.exact_contract, point.session_family))
    if frozen is None:
        return None
    if (
        frozen.quantile != Decimal("0.95")
        or frozen.sample_count < MINIMUM_CALIBRATION_SCORES
        or frozen.threshold <= 0
        or not frozen.threshold.is_finite()
    ):
        raise BBOChangeContractError("threshold is not a frozen candidate Q95")
    if abs(point.score) < frozen.threshold or point.score == 0:
        return None
    direction = _LONG if point.score > 0 else _SHORT
    return SignalDecision(
        exact_contract=point.exact_contract,
        session_family=point.session_family,
        segment_id=point.segment_id,
        collector_generation=point.collector_generation,
        clock_epoch=point.clock_epoch,
        collector_seq=point.collector_seq,
        source_event_ns=point.source_event_ns,
        receive_monotonic_ns=point.receive_monotonic_ns,
        active_time_ns=point.active_time_ns,
        direction=direction,
        score=point.score,
        threshold=frozen.threshold,
    )


def evaluate_clock_gate(
    observations: Iterable[ObservedBBO],
) -> ClockGateResult:
    """Evaluate whether source-to-receive latency is measurable at 250 ms."""

    lags: list[int] = []
    for obs in observations:
        _metadata(obs)
        if obs.clock_sync_state != _SYNCED:
            return ClockGateResult(False, len(lags), None, "CLOCK_NOT_SYNCED")
        if abs(obs.clock_offset_ns) > MAX_ABS_CLOCK_OFFSET_NS:
            return ClockGateResult(False, len(lags), None, "CLOCK_OFFSET_TOO_LARGE")
        if obs.clock_uncertainty_ns > MAX_CLOCK_UNCERTAINTY_NS:
            return ClockGateResult(
                False,
                len(lags),
                None,
                "CLOCK_UNCERTAINTY_TOO_LARGE",
            )
        if obs.source_time_precision_ns > MAX_SOURCE_TIME_PRECISION_NS:
            return ClockGateResult(False, len(lags), None, "SOURCE_TIME_TOO_COARSE")
        corrected_receive = obs.receive_utc_ns + obs.clock_offset_ns
        lag = corrected_receive - obs.source_event_ns
        if lag < 0:
            return ClockGateResult(False, len(lags), None, "NEGATIVE_CORRECTED_LAG")
        lags.append(lag)
    if len(lags) < MINIMUM_CALIBRATION_SCORES:
        return ClockGateResult(False, len(lags), None, "INSUFFICIENT_SAMPLES")
    ordered = sorted(lags)
    rank = max(0, (99 * len(ordered) + 99) // 100 - 1)
    p99 = ordered[rank]
    return ClockGateResult(
        passed=p99 <= MAX_SOURCE_RECEIVE_P99_NS,
        sample_count=len(lags),
        p99_lag_ns=p99,
        reason="PASS" if p99 <= MAX_SOURCE_RECEIVE_P99_NS else "P99_LAG_TOO_LARGE",
    )


def _same_lane(signal: SignalDecision, obs: ObservedBBO) -> bool:
    return (
        obs.collector_generation == signal.collector_generation
        and obs.clock_epoch == signal.clock_epoch
        and obs.exact_contract == signal.exact_contract
        and obs.session_family == signal.session_family
        and obs.segment_id == signal.segment_id
    )


def _fill(obs: ObservedBBO, side: str) -> AggressiveFill:
    qualified = _qualified(obs)
    if qualified is None or not _execution_qualified(obs, side):
        raise BBOChangeContractError("cannot fill from an unqualified BBO")
    price = qualified.ask_price if side == "BUY" else qualified.bid_price
    return AggressiveFill(
        collector_seq=obs.collector_seq,
        receive_monotonic_ns=obs.receive_monotonic_ns,
        active_time_ns=obs.active_time_ns,
        side=side,
        price=price,
    )


def _execution_qualified(obs: ObservedBBO, side: str) -> bool:
    qualified = _qualified(obs)
    if (
        qualified is None
        or obs.explicit_duplicate
        or obs.reset_reason is not None
        or obs.clock_sync_state != _SYNCED
    ):
        return False
    if side == "BUY":
        return qualified.ask_size >= 1
    if side == "SELL":
        return qualified.bid_size >= 1
    raise BBOChangeContractError("execution side must be BUY or SELL")


def _breaks_execution_lane(obs: ObservedBBO) -> bool:
    return (
        obs.reset_reason is not None
        or obs.clock_sync_state != _SYNCED
        or _qualified(obs) is None
    )


def replay_primary_round_trip(
    signal: SignalDecision,
    future_records: Iterable[ObservedBBO | CollectorControl],
) -> RoundTripReplay:
    """Replay one signal over a complete gapless run-global record stream."""

    if signal.direction not in {_LONG, _SHORT}:
        raise BBOChangeContractError("signal direction must be LONG or SHORT")
    if (
        not signal.score.is_finite()
        or not signal.threshold.is_finite()
        or signal.threshold <= 0
        or abs(signal.score) < signal.threshold
        or (signal.direction == _LONG and signal.score <= 0)
        or (signal.direction == _SHORT and signal.score >= 0)
    ):
        raise BBOChangeContractError("signal does not match the frozen trigger")
    expected_seq = signal.collector_seq + 1
    previous_receive = signal.receive_monotonic_ns
    previous_lane_active = signal.active_time_ns
    previous_lane_receive = signal.receive_monotonic_ns
    previous_lane_source = signal.source_event_ns
    entry_side = "BUY" if signal.direction == _LONG else "SELL"
    exit_side = "SELL" if signal.direction == _LONG else "BUY"
    entry_cutoff = signal.receive_monotonic_ns + PRIMARY_LATENCY_NS
    entry: AggressiveFill | None = None
    active_horizon: int | None = None
    exit_cutoff: int | None = None

    for record in future_records:
        if isinstance(record, CollectorControl):
            _control_metadata(record)
            generation = record.collector_generation
            epoch = record.clock_epoch
            collector_seq = record.collector_seq
            receive_monotonic_ns = record.receive_monotonic_ns
        else:
            _metadata(record)
            generation = record.collector_generation
            epoch = record.clock_epoch
            collector_seq = record.collector_seq
            receive_monotonic_ns = record.receive_monotonic_ns
        if (
            generation != signal.collector_generation
            or epoch != signal.clock_epoch
        ):
            break
        if collector_seq != expected_seq:
            raise BBOChangeContractError(
                f"future collector_seq must be gapless: expected {expected_seq}"
            )
        if receive_monotonic_ns < previous_receive:
            raise BBOChangeContractError("future receive_monotonic_ns regressed")
        expected_seq += 1
        previous_receive = receive_monotonic_ns
        if isinstance(record, CollectorControl):
            status = "NO_ENTRY" if entry is None else "NO_EXIT"
            return RoundTripReplay(status, signal, entry=entry)

        obs = record
        if not _same_lane(signal, obs) or obs.explicit_duplicate:
            continue
        if obs.active_time_ns < previous_lane_active:
            raise BBOChangeContractError("future active_time_ns regressed")
        active_delta = obs.active_time_ns - previous_lane_active
        monotonic_delta = obs.receive_monotonic_ns - previous_lane_receive
        if active_delta != monotonic_delta:
            raise BBOChangeContractError(
                "future active time is not aligned with monotonic time"
            )
        reset = (
            active_delta >= FEATURE_WINDOW_NS
            or obs.source_event_ns < previous_lane_source
        )
        previous_lane_active = obs.active_time_ns
        previous_lane_receive = obs.receive_monotonic_ns
        previous_lane_source = obs.source_event_ns
        if reset or _breaks_execution_lane(obs):
            status = "NO_ENTRY" if entry is None else "NO_EXIT"
            return RoundTripReplay(status, signal, entry=entry)

        if entry is None:
            if obs.receive_monotonic_ns < entry_cutoff:
                continue
            if not _execution_qualified(obs, entry_side):
                return RoundTripReplay("NO_ENTRY", signal)
            entry = _fill(obs, entry_side)
            active_horizon = entry.active_time_ns + HOLDING_HORIZON_NS
            continue

        if exit_cutoff is None:
            if active_horizon is None or obs.active_time_ns < active_horizon:
                continue
            exit_cutoff = obs.receive_monotonic_ns + PRIMARY_LATENCY_NS
            continue
        if obs.receive_monotonic_ns < exit_cutoff:
            continue
        if not _execution_qualified(obs, exit_side):
            return RoundTripReplay("NO_EXIT", signal, entry=entry)
        return RoundTripReplay(
            "COMPLETE",
            signal,
            entry=entry,
            exit=_fill(obs, exit_side),
        )
    status = "NO_ENTRY" if entry is None else "NO_EXIT"
    return RoundTripReplay(status, signal, entry=entry)
