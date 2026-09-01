"""Offline kernel for the issue #488 collector-observed L1 research line.

The module deliberately models ordered *observations* from one dedicated
collector.  It does not claim exchange-native order-flow events, queue state,
passive fills, capacity, or permission to collect data or place orders.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
import hashlib
import json
import os
from pathlib import Path
from stat import S_ISREG
from typing import Any, Iterable, Mapping, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by import-only platforms
    fcntl = None  # type: ignore[assignment]


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

_CUSTODY_COMMON_FIELDS = frozenset(
    {
        "research_line_id", "data_contract_id", "run_id", "partition_id",
        "record_type", "collector_generation", "clock_epoch", "segment_id",
        "collector_seq", "provider_delivery_semantics", "provider_batch_id",
        "within_batch_rank", "provider_update_id", "provider_update_id_semantics",
        "source_event_time_raw", "source_event_utc_ns", "source_time_precision_ns",
        "callback_entry_receive_utc_ns", "callback_entry_receive_monotonic_ns",
        "clock_sample_id", "clock_sync_state", "clock_offset_ns",
        "clock_uncertainty_ns", "product", "exact_contract", "exchange",
        "official_trading_day", "session_family", "prev_record_hash", "record_hash",
    }
)
_CUSTODY_QUOTE_FIELDS = frozenset(
    {
        "bid_price1_raw", "bid_size1_raw", "ask_price1_raw", "ask_size1_raw",
        "last_price_raw", "cumulative_volume_raw", "cumulative_amount_raw",
        "open_interest_raw", "parse_status", "duplicate_status", "source_status",
    }
)
_CUSTODY_SCHEMA_VERSION = "issue488-custody-v1"
_CUSTODY_WRITER_FIELDS = frozenset(
    {
        "research_line_id", "data_contract_id", "run_id", "partition_id",
        "prev_record_hash", "record_hash",
    }
)
_CUSTODY_MANIFEST_ONLY_FIELDS = frozenset(
    {
        "partition_hash", "previous_partition_hash", "seal_id", "closed_at_utc",
        "exact_bytes", "record_count", "first_collector_seq", "last_collector_seq",
        "first_record_hash", "last_record_hash", "path", "schema_version", "code_sha",
    }
)
_UNSET = object()


class BBOChangeContractError(ValueError):
    """Raised when the collector contract cannot be interpreted safely."""


def _require_posix_custody() -> None:
    required_os = ("O_DIRECTORY", "O_NOFOLLOW", "geteuid", "pread")
    required_dir_fd = (os.open, os.stat, os.mkdir)
    if (
        os.name != "posix"
        or fcntl is None
        or any(not hasattr(os, name) for name in required_os)
        or any(function not in os.supports_dir_fd for function in required_dir_fd)
    ):
        raise BBOChangeContractError("custody journal requires explicit POSIX capabilities")


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


def _require_code_sha(value: object) -> str:
    code_sha = _require_text(value, "code_sha")
    if (
        len(code_sha) not in {40, 64}
        or any(char not in "0123456789abcdef" for char in code_sha)
    ):
        raise BBOChangeContractError("code_sha must be a lowercase Git or SHA-256 digest")
    return code_sha


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


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Encode custody records canonically, without platform-dependent bytes."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BBOChangeContractError("custody record is not canonical JSON") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(value: object, field_name: str) -> str:
    text = _require_text(value, field_name)
    if (
        len(text) > 128
        or text in {".", ".."}
        or any(not (char.isascii() and (char.isalnum() or char in "._-")) for char in text)
    ):
        raise BBOChangeContractError(f"{field_name} is not a safe custody name")
    return text


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise BBOChangeContractError("durable custody write did not advance")
        view = view[written:]


@dataclass(frozen=True)
class ClosedPartition:
    run_id: str
    collector_generation: str
    partition_id: str
    path: str
    exact_bytes: int
    record_count: int
    first_collector_seq: int
    last_collector_seq: int
    first_record_hash: str
    last_record_hash: str
    partition_hash: str
    previous_partition_hash: str | None
    seal_id: str
    closed_at_utc: str
    schema_version: str
    code_sha: str


@dataclass(frozen=True)
class CustodyRootPins:
    """Out-of-root identity pins required to safely reopen a custody root."""

    path_sha256: str
    identity_sha256: str
    parent_identity_sha256: str


def pin_custody_root(root: str | Path) -> CustodyRootPins:
    _require_posix_custody()
    raw_path = os.fspath(root)
    if not os.path.isabs(raw_path) or raw_path != os.path.normpath(raw_path):
        raise BBOChangeContractError("custody root must be absolute and normalized")
    path = Path(raw_path)
    try:
        stat = os.lstat(path)
        parent = os.lstat(path.parent)
    except OSError as exc:
        raise BBOChangeContractError("cannot pin a missing custody root") from exc
    if (
        os.path.islink(path)
        or not os.path.isdir(path)
        or stat.st_uid != os.geteuid()
        or (stat.st_mode & 0o777) != 0o700
        or os.path.islink(path.parent)
        or not os.path.isdir(path.parent)
        or parent.st_uid != os.geteuid()
    ):
        raise BBOChangeContractError("cannot pin an unsafe custody root")
    canonical_path = os.path.abspath(os.fspath(path)).encode("utf-8")
    identity = f"{stat.st_dev}:{stat.st_ino}:{stat.st_uid}:{stat.st_mode & 0o777}".encode()
    parent_identity = (
        f"{parent.st_dev}:{parent.st_ino}:{parent.st_uid}:"
        f"{parent.st_mode & 0o777}"
    ).encode()
    return CustodyRootPins(
        _sha256(canonical_path), _sha256(identity), _sha256(parent_identity)
    )


class CustodyJournal:
    """Local, append-only custody for one run-global generation partition.

    This deliberately has no runtime integration: callers pass already-captured
    raw QUOTE/CONTROL mappings.  Every open/resume verifies the old prefix;
    malformed trailing bytes quarantine the generation instead of repairing it.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        run_id: str,
        partition_id: str,
        collector_generation: str,
        code_sha: str,
        schema_version: str = _CUSTODY_SCHEMA_VERSION,
        mode: str = "create",
        expected_previous_partition_hash: str | None = None,
        expected_head_hash: str | None | object = _UNSET,
        expected_head_partition_hash: str | None | object = _UNSET,
        expected_head_seal_id: str | None | object = _UNSET,
        expected_root_pins: CustodyRootPins | None = None,
    ) -> None:
        _require_posix_custody()
        raw_root = os.fspath(root)
        if not os.path.isabs(raw_root) or raw_root != os.path.normpath(raw_root):
            raise BBOChangeContractError("custody root must be absolute and normalized")
        self.root = Path(raw_root)
        self.run_id = _safe_name(run_id, "run_id")
        self.partition_id = _safe_name(partition_id, "partition_id")
        self.collector_generation = _safe_name(
            collector_generation, "collector_generation"
        )
        self.schema_version = _require_text(schema_version, "schema_version")
        self.code_sha = _require_code_sha(code_sha)
        if mode not in {"create", "resume"}:
            raise BBOChangeContractError("custody mode must be create or resume")
        self._mode = mode
        self._expected_previous_partition_hash = expected_previous_partition_hash
        if (
            expected_head_hash is not _UNSET
            and expected_head_partition_hash is not _UNSET
            and expected_head_hash != expected_head_partition_hash
        ):
            raise BBOChangeContractError("conflicting trusted custody head hashes")
        self._expected_head_hash = (
            expected_head_partition_hash
            if expected_head_partition_hash is not _UNSET
            else expected_head_hash
        )
        self._expected_root_pins = expected_root_pins
        self._expected_head_seal_id = expected_head_seal_id
        for value, field_name in (
            (expected_previous_partition_hash, "expected_previous_partition_hash"),
            (self._expected_head_hash, "expected_head_hash"),
            (expected_head_seal_id, "expected_head_seal_id"),
        ):
            if value is not _UNSET and value is not None and (
                not isinstance(value, str)
                or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise BBOChangeContractError(
                    f"{field_name} must be a SHA-256 hex digest"
                )
        self._root_fd: int | None = None
        self._lock_fd: int | None = None
        self._lock_identity: tuple[int, int] | None = None
        self._data_fd: int | None = None
        self._data_identity: tuple[int, ...] | None = None
        self._data_created = False
        self._root_version: tuple[int, ...] | None = None
        self._terminal_manifest_name: str | None = None
        self._terminal_manifest_identity: tuple[int, ...] | None = None
        self._terminal_data_name: str | None = None
        self._terminal_data_identity: tuple[int, ...] | None = None
        self._closed_chain_pins: dict[str, tuple[int, ...]] = {}
        self._root_identity: tuple[int, int] | None = None
        self._last_seq = 0
        self._last_record_hash: str | None = None
        self._partition_start_seq = 1
        self._partition_start_hash: str | None = None
        self._previous_partition_hash: str | None = None
        self._record_count = 0
        self._first_record_hash: str | None = None
        self._closed = False
        self._poisoned = False
        self._open_root()
        try:
            if self._root_preexisted and expected_root_pins is None:
                raise BBOChangeContractError(
                    "existing custody root requires externally stored root pins"
                )
            if expected_root_pins is not None and expected_root_pins != pin_custody_root(self.root):
                raise BBOChangeContractError("trusted custody root pins mismatch")
            self._lock()
            self._refresh_root_version()
            self._ensure_not_quarantined()
            manifests = self._verify_closed_manifests()
            terminal = self._terminal_manifest(manifests)
            if (
                terminal is not None
                and terminal.collector_generation != self.collector_generation
                and any(
                    manifest.collector_generation == self.collector_generation
                    for manifest in manifests
                )
            ):
                raise BBOChangeContractError(
                    "collector generation cannot reappear after a transition"
                )
            if terminal is not None:
                self._partition_start_seq = (
                    terminal.last_collector_seq + 1
                    if terminal.collector_generation == self.collector_generation
                    else 1
                )
                self._partition_start_hash = terminal.last_record_hash
                self._previous_partition_hash = terminal.partition_hash
            if (
                self._expected_previous_partition_hash is not None
                and self._expected_previous_partition_hash != self._previous_partition_hash
            ):
                raise BBOChangeContractError("trusted previous partition hash mismatch")
            self._verify_trusted_head(terminal)
            self._pin_closed_chain(manifests)
            self._pin_terminal(terminal)
            self._reject_orphan_partitions(manifests)
            if self._exists(self._manifest_name):
                self._closed = True
                raise BBOChangeContractError("partition is sealed; append is forbidden")
            existing_partition = self._exists(self._data_name)
            if mode == "resume" and not existing_partition:
                raise BBOChangeContractError("custody resume requires an existing partition")
            if mode == "create" and existing_partition:
                raise BBOChangeContractError("custody create refuses an existing partition")
            self._load_existing_partition()
        except Exception:
            self.close()
            raise

    @property
    def _data_name(self) -> str:
        return f"{self.partition_id}.jsonl"

    @property
    def _manifest_name(self) -> str:
        return f"{self.partition_id}.closed.json"

    @property
    def _quarantine_name(self) -> str:
        return f".quarantine-{self.collector_generation}.json"

    def close(self) -> None:
        if self._data_fd is not None:
            os.close(self._data_fd)
            self._data_fd = None
        if self._lock_fd is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def __enter__(self) -> "CustodyJournal":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _open_root(self) -> None:
        try:
            self._root_preexisted = self.root.exists()
            if not self._root_preexisted:
                if self._mode == "resume":
                    raise BBOChangeContractError("custody resume does not create a root")
                parent = self.root.parent
                parent_stat = os.lstat(parent)
                if (
                    os.path.islink(parent)
                    or not os.path.isdir(parent)
                    or parent_stat.st_uid != os.geteuid()
                ):
                    raise BBOChangeContractError("custody parent is unsafe")
                parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    opened_parent = os.fstat(parent_fd)
                    if (opened_parent.st_dev, opened_parent.st_ino) != (
                        parent_stat.st_dev, parent_stat.st_ino
                    ):
                        raise BBOChangeContractError("custody parent was replaced")
                    os.mkdir(self.root.name, mode=0o700, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            stat = os.lstat(self.root)
            if (
                os.path.islink(self.root)
                or not os.path.isdir(self.root)
                or stat.st_uid != os.geteuid()
                or (stat.st_mode & 0o777) != 0o700
            ):
                raise BBOChangeContractError("custody root must be a real directory")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            self._root_fd = os.open(self.root, flags)
            opened = os.fstat(self._root_fd)
            if (opened.st_dev, opened.st_ino) != (stat.st_dev, stat.st_ino):
                raise BBOChangeContractError("custody root was replaced during open")
            self._root_identity = (opened.st_dev, opened.st_ino)
        except OSError as exc:
            raise BBOChangeContractError("cannot safely open custody root") from exc

    def _check_root(self) -> int:
        if self._root_fd is None or self._root_identity is None:
            raise BBOChangeContractError("custody journal is closed")
        try:
            current = os.lstat(self.root)
        except OSError as exc:
            raise BBOChangeContractError("custody root disappeared") from exc
        if (
            os.path.islink(self.root)
            or not os.path.isdir(self.root)
            or current.st_uid != os.geteuid()
            or (current.st_mode & 0o777) != 0o700
            or (current.st_dev, current.st_ino) != self._root_identity
        ):
            raise BBOChangeContractError("custody root was replaced")
        return self._root_fd

    def _verify_trusted_head(self, terminal: ClosedPartition | None) -> None:
        if terminal is None:
            if (
                self._expected_head_hash not in {_UNSET, None}
                or self._expected_head_seal_id not in {_UNSET, None}
            ):
                raise BBOChangeContractError("genesis custody root cannot have a head anchor")
            if self._root_preexisted and (
                self._expected_head_hash is _UNSET or self._expected_head_seal_id is _UNSET
            ):
                raise BBOChangeContractError(
                    "existing custody root requires explicit genesis anchors"
                )
            return
        if self._expected_head_hash is _UNSET or self._expected_head_seal_id is _UNSET:
            raise BBOChangeContractError("sealed custody chain requires both trusted head anchors")
        if (
            terminal.partition_hash != self._expected_head_hash
            or terminal.seal_id != self._expected_head_seal_id
        ):
            raise BBOChangeContractError("trusted custody head anchor mismatch")

    def _lock(self) -> None:
        fd = self._open_file(".custody.lock", os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise BBOChangeContractError("custody journal is already locked") from exc
        self._lock_fd = fd
        locked = os.fstat(fd)
        self._lock_identity = (locked.st_dev, locked.st_ino)

    def _check_lock(self) -> None:
        if self._lock_fd is None or self._lock_identity is None:
            raise BBOChangeContractError("custody writer lock is unavailable")
        try:
            named = os.stat(".custody.lock", dir_fd=self._check_root(), follow_symlinks=False)
            opened = os.fstat(self._lock_fd)
        except OSError as exc:
            raise BBOChangeContractError("custody writer lock was replaced") from exc
        if (
            (named.st_dev, named.st_ino) != self._lock_identity
            or (opened.st_dev, opened.st_ino) != self._lock_identity
            or not S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or (opened.st_mode & 0o777) != 0o600
            or opened.st_nlink != 1
        ):
            raise BBOChangeContractError("custody writer lock was replaced")

    @staticmethod
    def _identity(stat: os.stat_result) -> tuple[int, ...]:
        return (
            stat.st_dev,
            stat.st_ino,
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
            stat.st_nlink,
            stat.st_uid,
            stat.st_mode & 0o777,
        )

    def _refresh_root_version(self) -> None:
        self._root_version = self._identity(os.fstat(self._check_root()))

    def _check_root_version(self) -> None:
        if self._root_version is None:
            raise BBOChangeContractError("custody root version is unavailable")
        if self._identity(os.fstat(self._check_root())) != self._root_version:
            raise BBOChangeContractError("custody root directory changed externally")

    def _file_identity(self, name: str) -> tuple[int, ...]:
        fd = self._open_file(name, os.O_RDONLY)
        try:
            return self._identity(os.fstat(fd))
        finally:
            os.close(fd)

    def _pin_terminal(self, terminal: ClosedPartition | None) -> None:
        if terminal is None:
            self._terminal_manifest_name = None
            self._terminal_manifest_identity = None
            self._terminal_data_name = None
            self._terminal_data_identity = None
            return
        self._terminal_manifest_name = f"{terminal.partition_id}.closed.json"
        self._terminal_manifest_identity = self._file_identity(
            self._terminal_manifest_name
        )
        self._terminal_data_name = terminal.path
        self._terminal_data_identity = self._file_identity(terminal.path)

    def _pin_closed_chain(self, manifests: Iterable[ClosedPartition]) -> None:
        pins: dict[str, tuple[int, ...]] = {}
        for manifest in manifests:
            manifest_name = f"{manifest.partition_id}.closed.json"
            for name in (manifest_name, manifest.path):
                if name in pins:
                    raise BBOChangeContractError("closed custody chain has duplicate path")
                pins[name] = self._file_identity(name)
        self._closed_chain_pins = pins

    def _check_closed_chain_pins(self) -> None:
        for name, expected in self._closed_chain_pins.items():
            if self._file_identity(name) != expected:
                raise BBOChangeContractError("sealed custody chain changed externally")

    def _reject_orphan_partitions(
        self, manifests: Iterable[ClosedPartition]
    ) -> None:
        closed_data = {manifest.path for manifest in manifests}
        for name in os.listdir(self._check_root()):
            if not name.endswith(".jsonl"):
                continue
            if name not in closed_data and name != self._data_name:
                self._quarantine("ORPHAN_UNSEALED_PARTITION")
                raise BBOChangeContractError(
                    "unsealed custody partition must be explicitly resumed"
                )

    def _check_terminal_pin(self) -> None:
        if self._terminal_manifest_name is None:
            return
        if (
            self._terminal_manifest_identity is None
            or self._terminal_data_name is None
            or self._terminal_data_identity is None
            or self._file_identity(self._terminal_manifest_name)
            != self._terminal_manifest_identity
            or self._file_identity(self._terminal_data_name)
            != self._terminal_data_identity
        ):
            raise BBOChangeContractError("trusted terminal partition changed externally")

    def _pin_current_data(self, fd: int) -> None:
        self._data_fd = fd
        self._data_identity = self._identity(os.fstat(fd))
        self._data_created = True

    def _check_current_data(self) -> None:
        if self._data_fd is None or self._data_identity is None:
            if self._data_created:
                raise BBOChangeContractError("current custody partition disappeared")
            return
        opened = self._identity(os.fstat(self._data_fd))
        named = self._file_identity(self._data_name)
        if opened != self._data_identity or named != self._data_identity:
            raise BBOChangeContractError("current custody partition changed externally")

    def _assert_append_state(self) -> None:
        try:
            self._check_lock()
            self._check_root_version()
            self._check_closed_chain_pins()
            self._check_terminal_pin()
            self._check_current_data()
        except (OSError, BBOChangeContractError):
            self._poison()
            raise

    def _open_new_data_for_append(self) -> None:
        if self._data_created or self._exists(self._data_name):
            raise BBOChangeContractError("current custody partition cannot be recreated")
        fd = self._open_file(
            self._data_name,
            os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL,
        )
        self._pin_current_data(fd)
        self._refresh_root_version()

    def _healthy(self) -> None:
        if self._poisoned:
            raise BBOChangeContractError("custody journal is poisoned after durable I/O failure")

    def _poison(self) -> None:
        if self._poisoned:
            return
        self._poisoned = True
        try:
            self._quarantine("DURABLE_IO_FAILURE")
        except (OSError, BBOChangeContractError):
            pass

    def _exists(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self._check_root(), follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def _open_file(self, name: str, flags: int, *, mode: int = 0o600) -> int:
        if (
            not isinstance(name, str)
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or "\x00" in name
        ):
            raise BBOChangeContractError("custody file name is not a safe basename")
        try:
            fd = os.open(
                name,
                flags | os.O_NOFOLLOW,
                mode,
                dir_fd=self._check_root(),
            )
        except OSError as exc:
            raise BBOChangeContractError(f"cannot safely open custody file {name}") from exc
        try:
            opened = os.fstat(fd)
            named = os.stat(name, dir_fd=self._check_root(), follow_symlinks=False)
            if (
                not S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or (opened.st_mode & 0o777) != 0o600
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise BBOChangeContractError("custody file identity or permissions are unsafe")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _read_file(self, name: str) -> bytes:
        fd = self._open_file(name, os.O_RDONLY)
        try:
            stat = os.fstat(fd)
            if not S_ISREG(stat.st_mode):
                raise BBOChangeContractError("custody path must be a regular file")
            data = _read_all(fd)
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=self._check_root(), follow_symlinks=False)
            stable = (
                stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns,
                stat.st_ctime_ns, stat.st_nlink, stat.st_uid, stat.st_mode & 0o777,
            )
            after_stable = (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                after.st_ctime_ns, after.st_nlink, after.st_uid, after.st_mode & 0o777,
            )
            named_stable = (
                named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns,
                named.st_ctime_ns, named.st_nlink, named.st_uid, named.st_mode & 0o777,
            )
            if stable != after_stable or stable != named_stable or len(data) != stat.st_size:
                raise BBOChangeContractError("custody file changed during read")
            return data
        finally:
            os.close(fd)

    def _write_exclusive(self, name: str, data: bytes) -> None:
        fd = self._open_file(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            _write_all(fd, data)
            os.fsync(fd)
        except (OSError, BBOChangeContractError):
            self._poison()
            raise
        finally:
            os.close(fd)
        try:
            os.fsync(self._check_root())
        except OSError:
            self._poison()
            raise

    def _ensure_not_quarantined(self) -> None:
        if self._exists(self._quarantine_name):
            raise BBOChangeContractError("collector generation is quarantined")

    def _quarantine(self, reason: str) -> None:
        payload = _canonical_json_bytes(
            {"collector_generation": self.collector_generation, "reason": reason}
        ) + b"\n"
        try:
            self._write_exclusive(self._quarantine_name, payload)
        except BBOChangeContractError:
            if not self._exists(self._quarantine_name):
                raise

    def _decode_records(self, data: bytes) -> list[dict[str, Any]]:
        if data and not data.endswith(b"\n"):
            self._quarantine("PARTIAL_TRAILING_WRITE")
            raise BBOChangeContractError("partial trailing write quarantined generation")
        records: list[dict[str, Any]] = []
        for line in data.splitlines():
            try:
                row = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._quarantine("INVALID_JOURNAL_JSON")
                raise BBOChangeContractError("invalid journal JSON quarantined generation") from exc
            if not isinstance(row, dict) or _canonical_json_bytes(row) != line:
                self._quarantine("NONCANONICAL_JOURNAL")
                raise BBOChangeContractError("noncanonical journal quarantined generation")
            records.append(row)
        return records

    def _validate_row(
        self,
        row: Mapping[str, Any],
        previous: str | None,
        expected_seq: int,
        *,
        expected_partition_id: str | None = None,
        expected_generation: str | None = None,
        expected_run_id: str | None = None,
    ) -> str:
        record_type = row.get("record_type")
        required = _CUSTODY_COMMON_FIELDS | (
            _CUSTODY_QUOTE_FIELDS if record_type == "QUOTE" else frozenset()
        )
        if record_type not in {"QUOTE", "CONTROL"} or not required.issubset(row):
            raise BBOChangeContractError("journal row does not match QUOTE/CONTROL schema")
        if record_type == "CONTROL" and (
            row.get("event_type") not in _CONTROL_EVENTS
            or not isinstance(row.get("reason"), str)
            or not row["reason"].strip()
        ):
            raise BBOChangeContractError("journal CONTROL row is incomplete")
        if (
            row.get("research_line_id") != RESEARCH_LINE_ID
            or row.get("data_contract_id") != DATA_CONTRACT_ID
            or row.get("run_id") != (expected_run_id or self.run_id)
            or row.get("partition_id") != (expected_partition_id or self.partition_id)
            or row.get("collector_generation") != (expected_generation or self.collector_generation)
            or row.get("prev_record_hash") != previous
            or row.get("collector_seq") != expected_seq
        ):
            raise BBOChangeContractError("journal row violates run-global custody order")
        _require_int(row.get("collector_seq"), "collector_seq", minimum=1)
        without_hash = dict(row)
        actual_hash = without_hash.pop("record_hash", None)
        expected_hash = _sha256(_canonical_json_bytes(without_hash))
        if not isinstance(actual_hash, str) or actual_hash != expected_hash:
            raise BBOChangeContractError("journal record hash chain verification failed")
        return actual_hash

    def _load_existing_partition(self) -> None:
        if not self._exists(self._data_name):
            if self._record_count:
                self._quarantine("MISSING_CURRENT_PARTITION")
                raise BBOChangeContractError("current custody partition disappeared")
            self._record_count = 0
            self._first_record_hash = None
            self._last_seq = self._partition_start_seq - 1
            self._last_record_hash = self._partition_start_hash
            return
        try:
            records = self._decode_records(self._read_file(self._data_name))
            previous: str | None = self._partition_start_hash
            for seq, row in enumerate(records, self._partition_start_seq):
                previous = self._validate_row(row, previous, seq)
        except BBOChangeContractError:
            self._quarantine("JOURNAL_VERIFICATION_FAILURE")
            raise
        self._record_count = len(records)
        self._first_record_hash = records[0]["record_hash"] if records else None
        self._last_seq = (
            self._partition_start_seq + len(records) - 1
            if records
            else self._partition_start_seq - 1
        )
        self._last_record_hash = previous if records else self._partition_start_hash
        if self._data_fd is not None:
            os.close(self._data_fd)
            self._data_fd = None
        append_fd = self._open_file(self._data_name, os.O_RDWR | os.O_APPEND)
        self._pin_current_data(append_fd)

    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Durably append one caller-captured raw QUOTE or CONTROL row."""

        self._healthy()
        self._assert_append_state()
        self._ensure_not_quarantined()
        if self._closed or self._exists(self._manifest_name):
            self._closed = True
            raise BBOChangeContractError("partition is sealed; append is forbidden")
        row = dict(record)
        if _CUSTODY_WRITER_FIELDS & row.keys():
            raise BBOChangeContractError("caller may not provide writer-owned custody fields")
        if _CUSTODY_MANIFEST_ONLY_FIELDS & row.keys():
            raise BBOChangeContractError("final partition fields are forbidden in raw rows")
        expected_seq = self._last_seq + 1
        for field_name, expected_value in {
            "collector_generation": self.collector_generation,
            "collector_seq": expected_seq,
        }.items():
            if field_name not in row:
                raise BBOChangeContractError(
                    f"journal append requires callback-entry {field_name}"
                )
            if field_name == "collector_seq":
                _require_int(row[field_name], field_name, minimum=1)
            if row[field_name] != expected_value:
                raise BBOChangeContractError(
                    f"journal append has inconsistent {field_name}"
                )
        row["research_line_id"] = RESEARCH_LINE_ID
        row["data_contract_id"] = DATA_CONTRACT_ID
        row["run_id"] = self.run_id
        row["partition_id"] = self.partition_id
        row["prev_record_hash"] = self._last_record_hash
        row.pop("record_hash", None)
        required = _CUSTODY_COMMON_FIELDS - {"record_hash"}
        if row.get("record_type") == "QUOTE":
            required |= _CUSTODY_QUOTE_FIELDS
        if row.get("record_type") not in {"QUOTE", "CONTROL"} or not required.issubset(row):
            raise BBOChangeContractError("journal append requires complete QUOTE/CONTROL fields")
        if row["record_type"] == "CONTROL" and (
            row.get("event_type") not in _CONTROL_EVENTS
            or not isinstance(row.get("reason"), str)
            or not row["reason"].strip()
        ):
            raise BBOChangeContractError("journal CONTROL append is incomplete")
        row["record_hash"] = _sha256(_canonical_json_bytes(row))
        data = _canonical_json_bytes(row) + b"\n"
        if self._data_fd is None:
            try:
                self._open_new_data_for_append()
            except (OSError, BBOChangeContractError):
                self._poison()
                raise
        fd = self._data_fd
        if fd is None:
            self._poison()
            raise BBOChangeContractError("current custody append descriptor is unavailable")
        try:
            self._assert_append_state()
            pre_size = os.fstat(fd).st_size
        except (OSError, BBOChangeContractError):
            self._poison()
            raise
        try:
            _write_all(fd, data)
            os.fsync(fd)
        except (OSError, BBOChangeContractError):
            self._poison()
            raise
        try:
            os.fsync(self._check_root())
        except OSError:
            self._poison()
            raise
        try:
            post_stat = os.fstat(fd)
            if post_stat.st_size != pre_size + len(data):
                raise BBOChangeContractError("custody append size changed unexpectedly")
            if os.pread(fd, len(data), pre_size) != data:
                raise BBOChangeContractError("custody append bytes changed unexpectedly")
            self._data_identity = self._identity(post_stat)
            self._check_lock()
            self._check_root_version()
            self._check_closed_chain_pins()
            self._check_terminal_pin()
            self._check_current_data()
        except (OSError, BBOChangeContractError):
            self._poison()
            raise
        if self._record_count == 0:
            self._first_record_hash = row["record_hash"]
        self._record_count += 1
        self._last_seq += 1
        self._last_record_hash = row["record_hash"]
        return dict(row)

    def verify(self) -> None:
        """Fail closed unless the current journal and every sealed partition verify."""

        self._healthy()
        self._assert_append_state()
        self._ensure_not_quarantined()
        manifests = self._verify_closed_manifests()
        self._verify_trusted_head(self._terminal_manifest(manifests))
        self._pin_closed_chain(manifests)
        self._load_existing_partition()
        self._check_lock()

    @staticmethod
    def _require_hash(value: object, field_name: str, *, nullable: bool = False) -> None:
        if value is None and nullable:
            return
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise BBOChangeContractError(f"{field_name} must be a SHA-256 hex digest")

    def _validate_manifest(self, name: str, decoded: Mapping[str, Any]) -> ClosedPartition:
        if set(decoded) != set(ClosedPartition.__dataclass_fields__):
            raise BBOChangeContractError("closed manifest fields are not exact")
        manifest = ClosedPartition(**decoded)
        if name != f"{manifest.partition_id}.closed.json":
            raise BBOChangeContractError("closed manifest filename is not canonical")
        _safe_name(manifest.partition_id, "manifest partition_id")
        if manifest.path != f"{manifest.partition_id}.jsonl":
            raise BBOChangeContractError("closed manifest path is not canonical")
        _safe_name(manifest.run_id, "manifest run_id")
        _safe_name(manifest.collector_generation, "manifest collector_generation")
        _require_text(manifest.schema_version, "manifest schema_version")
        _require_code_sha(manifest.code_sha)
        _require_text(manifest.closed_at_utc, "manifest closed_at_utc")
        for value, field_name, minimum in (
            (manifest.exact_bytes, "exact_bytes", 1),
            (manifest.record_count, "record_count", 1),
            (manifest.first_collector_seq, "first_collector_seq", 1),
            (manifest.last_collector_seq, "last_collector_seq", 1),
        ):
            _require_int(value, field_name, minimum=minimum)
        if manifest.last_collector_seq < manifest.first_collector_seq:
            raise BBOChangeContractError("closed manifest collector sequence is invalid")
        for value, field_name, nullable in (
            (manifest.first_record_hash, "first_record_hash", False),
            (manifest.last_record_hash, "last_record_hash", False),
            (manifest.partition_hash, "partition_hash", False),
            (manifest.previous_partition_hash, "previous_partition_hash", True),
            (manifest.seal_id, "seal_id", False),
        ):
            self._require_hash(value, field_name, nullable=nullable)
        return manifest

    def _verify_closed_manifests(self) -> list[ClosedPartition]:
        root_fd = self._check_root()
        names = sorted(
            name for name in os.listdir(root_fd) if name.endswith(".closed.json")
        )
        manifests: list[ClosedPartition] = []
        for name in names:
            try:
                raw = self._read_file(name)
                decoded = json.loads(raw)
                if not isinstance(decoded, dict) or _canonical_json_bytes(decoded) + b"\n" != raw:
                    raise BBOChangeContractError("closed manifest is noncanonical")
                manifest_seal_id = decoded.get("seal_id")
                manifest_core = dict(decoded)
                manifest_core.pop("seal_id", None)
                if (
                    not isinstance(manifest_seal_id, str)
                    or manifest_seal_id != _sha256(_canonical_json_bytes(manifest_core))
                ):
                    raise BBOChangeContractError("closed manifest seal binding failed")
                manifest = self._validate_manifest(name, decoded)
                if (
                    manifest.schema_version != self.schema_version
                    or manifest.run_id != self.run_id
                    or manifest.code_sha != self.code_sha
                ):
                    raise BBOChangeContractError("closed manifest schema mismatch")
                data = self._read_file(manifest.path)
                rows = self._decode_records(data)
                if (
                    manifest.exact_bytes != len(data)
                    or manifest.partition_hash != _sha256(data)
                    or manifest.record_count != len(rows)
                    or not rows
                    or manifest.first_record_hash != rows[0]["record_hash"]
                ):
                    raise BBOChangeContractError("closed partition manifest verification failed")
                manifests.append(manifest)
            except (TypeError, ValueError, BBOChangeContractError) as exc:
                raise BBOChangeContractError(
                    "closed partition custody verification failed"
                ) from exc
        by_hash = {item.partition_hash: item for item in manifests}
        if len(by_hash) != len(manifests):
            raise BBOChangeContractError("duplicate closed partition hash")
        for item in manifests:
            if (
                item.previous_partition_hash is not None
                and item.previous_partition_hash not in by_hash
            ):
                raise BBOChangeContractError("missing previous partition hash")
        if manifests:
            if sum(item.previous_partition_hash is None for item in manifests) != 1:
                raise BBOChangeContractError("closed partitions must have one chain root")
            children: dict[str, ClosedPartition] = {}
            for item in manifests:
                if item.previous_partition_hash is not None:
                    if item.previous_partition_hash in children:
                        raise BBOChangeContractError("closed partitions fork")
                    children[item.previous_partition_hash] = item
            root = next(item for item in manifests if item.previous_partition_hash is None)
            ordered = [root]
            while ordered[-1].partition_hash in children:
                ordered.append(children[ordered[-1].partition_hash])
            if len(ordered) != len(manifests):
                raise BBOChangeContractError("closed partition chain is disconnected")
            previous_hash: str | None = None
            expected_seq = 1
            previous_generation: str | None = None
            seen_generations: set[str] = set()
            for manifest in ordered:
                if (
                    previous_generation is not None
                    and manifest.collector_generation != previous_generation
                ):
                    seen_generations.add(previous_generation)
                    if manifest.collector_generation in seen_generations:
                        raise BBOChangeContractError(
                            "collector generation cannot reappear after a transition"
                        )
                    expected_seq = 1
                rows = self._decode_records(self._read_file(manifest.path))
                previous = previous_hash
                for seq, row in enumerate(rows, expected_seq):
                    previous = self._validate_closed_row(row, manifest, previous, seq)
                if (
                    manifest.previous_partition_hash != (
                        ordered[ordered.index(manifest) - 1].partition_hash
                        if ordered.index(manifest) else None
                    )
                    or manifest.first_collector_seq != expected_seq
                    or manifest.last_collector_seq != expected_seq + len(rows) - 1
                    or manifest.last_record_hash != previous
                ):
                    raise BBOChangeContractError("closed partition sequence verification failed")
                expected_seq = manifest.last_collector_seq + 1
                previous_hash = manifest.last_record_hash
                previous_generation = manifest.collector_generation
        return manifests

    @staticmethod
    def _terminal_manifest(manifests: Sequence[ClosedPartition]) -> ClosedPartition | None:
        if not manifests:
            return None
        previous_hashes = {item.previous_partition_hash for item in manifests}
        terminals = [item for item in manifests if item.partition_hash not in previous_hashes]
        if len(terminals) != 1:
            raise BBOChangeContractError("closed partition chain has no unique terminal")
        return terminals[0]

    def _validate_closed_row(
        self, row: Mapping[str, Any], manifest: ClosedPartition, previous: str | None, expected: int
    ) -> str:
        if (
            row.get("partition_id") != manifest.partition_id
            or row.get("collector_generation") != manifest.collector_generation
        ):
            raise BBOChangeContractError("closed partition row identity mismatch")
        return self._validate_row(
            row,
            previous,
            expected,
            expected_partition_id=manifest.partition_id,
            expected_generation=manifest.collector_generation,
            expected_run_id=manifest.run_id,
        )

    def seal(self, *, closed_at_utc: str) -> ClosedPartition:
        """Create the immutable closed-partition manifest after byte-exact hashing."""

        self._healthy()
        self._assert_append_state()
        self._ensure_not_quarantined()
        if self._closed or self._exists(self._manifest_name):
            self._closed = True
            raise BBOChangeContractError("partition is already sealed")
        if self._record_count == 0:
            raise BBOChangeContractError("cannot seal an empty partition")
        manifests = self._verify_closed_manifests()
        self._load_existing_partition()
        if self._record_count == 0 or self._first_record_hash is None:
            raise BBOChangeContractError("cannot seal an empty partition")
        terminal = self._terminal_manifest(manifests)
        self._verify_trusted_head(terminal)
        data = self._read_file(self._data_name)
        manifest_core = {
            "run_id": self.run_id,
            "collector_generation": self.collector_generation,
            "partition_id": self.partition_id,
            "path": self._data_name,
            "exact_bytes": len(data),
            "record_count": self._record_count,
            "first_collector_seq": self._partition_start_seq,
            "last_collector_seq": self._last_seq,
            "first_record_hash": self._first_record_hash or "",
            "last_record_hash": self._last_record_hash or "",
            "partition_hash": _sha256(data),
            "previous_partition_hash": terminal.partition_hash if terminal else None,
            "closed_at_utc": _require_text(closed_at_utc, "closed_at_utc"),
            "schema_version": self.schema_version,
            "code_sha": self.code_sha,
        }
        manifest = ClosedPartition(
            seal_id=_sha256(_canonical_json_bytes(manifest_core)),
            **manifest_core,
        )
        try:
            self._assert_append_state()
        except (OSError, BBOChangeContractError):
            self._poison()
            raise
        self._write_exclusive(
            self._manifest_name,
            _canonical_json_bytes(manifest.__dict__) + b"\n",
        )
        try:
            self._check_closed_chain_pins()
            self._check_terminal_pin()
            self._check_current_data()
            self._refresh_root_version()
            published = self._verify_closed_manifests()
            published_manifest = next(
                (item for item in published if item.partition_hash == manifest.partition_hash),
                None,
            )
            if published_manifest != manifest:
                raise BBOChangeContractError("published custody manifest changed unexpectedly")
            self._pin_closed_chain(published)
            self._pin_terminal(published_manifest)
            self._check_lock()
        except (OSError, BBOChangeContractError):
            self._poison()
            raise
        self._closed = True
        return manifest
