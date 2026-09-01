"""Offline kernel for the issue #488 collector-observed L1 research line.

The module deliberately models ordered *observations* from one dedicated
collector.  It does not claim exchange-native order-flow events, queue state,
passive fills, capacity, or permission to collect data or place orders.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
import hashlib
import json
import os
from pathlib import Path
from stat import S_ISREG
from typing import Any, Iterable, Mapping, Sequence
from types import MappingProxyType

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
_GENERATION_GLOBAL_CONTROL_EVENTS = frozenset(
    {
        "COLLECTOR_START",
        "COLLECTOR_STOP",
        "BACKPRESSURE_ABORT",
        "SINK_FAILURE_ABORT",
        "DISCONNECT",
        "RECONNECT",
        "CLOCK_EPOCH_CHANGE",
    }
)
_EXACT_CONTRACT_SEGMENT_CONTROL_EVENTS = frozenset(
    {"SESSION_SEGMENT_START", "SESSION_SEGMENT_END"}
)
_TERMINAL_GENERATION_CONTROL_EVENTS = frozenset(
    {"COLLECTOR_STOP", "BACKPRESSURE_ABORT", "SINK_FAILURE_ABORT"}
)

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
_CUSTODY_CONTROL_FIELDS = frozenset({"event_type", "reason", "scope"})
_RAW_RETAINED_SCALAR_FIELDS = (
    "bid_price1_raw",
    "bid_size1_raw",
    "ask_price1_raw",
    "ask_size1_raw",
    "last_price_raw",
    "cumulative_volume_raw",
    "cumulative_amount_raw",
    "open_interest_raw",
)
_CUSTODY_SCHEMA_VERSION = "issue488-custody-v1"
_MAX_CUSTODY_MANIFEST_BYTES = 1024 * 1024
_CUSTODY_WRITER_FIELDS = frozenset(
    {
        "research_line_id", "data_contract_id", "run_id", "partition_id",
        "prev_record_hash", "record_hash",
    }
)
_CUSTODY_MANIFEST_ONLY_FIELDS = frozenset(
    {
        "partition_hash", "previous_partition_hash", "previous_partition_seal_id", "seal_id", "closed_at_utc",
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


def _require_canonical_text(value: object, field_name: str) -> str:
    text = _require_text(value, field_name)
    if text != value:
        raise BBOChangeContractError(f"{field_name} must be canonical text")
    return text


def _require_iso_day_text(value: object, field_name: str) -> str:
    text = _require_canonical_text(value, field_name)
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise BBOChangeContractError(f"{field_name} must be an ISO official day") from exc
    if parsed.isoformat() != text:
        raise BBOChangeContractError(f"{field_name} must be an ISO official day")
    return text


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
    scope: str = "GENERATION_GLOBAL"
    exact_contract: str | None = None
    session_family: str | None = None
    segment_id: str | None = None
    official_trading_day: str | None = None


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
    _require_canonical_text(control.collector_generation, "collector_generation")
    _require_canonical_text(control.clock_epoch, "clock_epoch")
    _require_int(control.collector_seq, "collector_seq", minimum=1)
    _require_int(control.receive_utc_ns, "receive_utc_ns")
    _require_int(control.receive_monotonic_ns, "receive_monotonic_ns")
    event_type = _require_canonical_text(control.event_type, "event_type")
    _require_canonical_text(control.reason, "reason")
    if event_type not in _CONTROL_EVENTS:
        raise BBOChangeContractError("unsupported collector control event")
    if control.scope not in {"GENERATION_GLOBAL", "EXACT_CONTRACT_SEGMENT"}:
        raise BBOChangeContractError("unsupported collector control scope")
    if event_type in _GENERATION_GLOBAL_CONTROL_EVENTS:
        if control.scope != "GENERATION_GLOBAL" or any(
            value is not None
            for value in (
                control.exact_contract,
                control.session_family,
                control.segment_id,
                control.official_trading_day,
            )
        ):
            raise BBOChangeContractError("generation-global control has lane fields")
    elif event_type in _EXACT_CONTRACT_SEGMENT_CONTROL_EVENTS:
        if control.scope != "EXACT_CONTRACT_SEGMENT":
            raise BBOChangeContractError("segment control must have exact-contract scope")
        for name in (
            "exact_contract",
            "session_family",
            "segment_id",
            "official_trading_day",
        ):
            if name == "official_trading_day":
                _require_iso_day_text(getattr(control, name), name)
            else:
                _require_canonical_text(getattr(control, name), name)


def _raw_control_scope(row: Mapping[str, object]) -> None:
    """Validate the explicit raw scope independently of contextual common fields."""

    event_type = row.get("event_type")
    scope = row.get("scope")
    if event_type in _GENERATION_GLOBAL_CONTROL_EVENTS:
        if scope != "GENERATION_GLOBAL":
            raise BBOChangeContractError(
                "generation-global raw control has an invalid scope"
            )
        return
    if event_type in _EXACT_CONTRACT_SEGMENT_CONTROL_EVENTS:
        if scope != "EXACT_CONTRACT_SEGMENT":
            raise BBOChangeContractError(
                "segment raw control has an invalid scope"
            )
        for name in (
            "exact_contract",
            "session_family",
            "segment_id",
            "official_trading_day",
        ):
            if name == "official_trading_day":
                _require_iso_day_text(row.get(name), name)
            else:
                _require_canonical_text(row.get(name), name)
        return
    raise BBOChangeContractError("unsupported raw control event")


def _require_raw_control_semantics(row: Mapping[str, object]) -> None:
    """Reject CONTROL schema smuggling before custody or replay state exists."""

    for name in (
        "record_type",
        "collector_generation",
        "clock_epoch",
        "segment_id",
        "provider_delivery_semantics",
        "provider_update_id_semantics",
        "source_event_time_raw",
        "clock_sample_id",
        "clock_sync_state",
        "product",
        "exact_contract",
        "exchange",
        "session_family",
        "event_type",
        "reason",
        "scope",
    ):
        _require_canonical_text(row.get(name), f"CONTROL {name}")
    _require_iso_day_text(
        row.get("official_trading_day"), "CONTROL official_trading_day"
    )
    for name in ("provider_batch_id", "provider_update_id"):
        value = row.get(name)
        if value is not None:
            _require_canonical_text(value, f"CONTROL {name}")
    _require_int(row.get("collector_seq"), "CONTROL collector_seq", minimum=1)
    _require_int(row.get("within_batch_rank"), "CONTROL within_batch_rank", minimum=1)
    _require_int(
        row.get("source_event_utc_ns"), "CONTROL source_event_utc_ns", minimum=1
    )
    _require_int(
        row.get("source_time_precision_ns"),
        "CONTROL source_time_precision_ns",
        minimum=1,
    )
    _require_int(
        row.get("callback_entry_receive_utc_ns"),
        "CONTROL callback_entry_receive_utc_ns",
        minimum=1,
    )
    _require_int(
        row.get("callback_entry_receive_monotonic_ns"),
        "CONTROL callback_entry_receive_monotonic_ns",
        minimum=1,
    )
    _require_int(
        row.get("clock_offset_ns"), "CONTROL clock_offset_ns", minimum=-10**18
    )
    _require_int(
        row.get("clock_uncertainty_ns"), "CONTROL clock_uncertainty_ns"
    )
    if row.get("event_type") not in _CONTROL_EVENTS:
        raise BBOChangeContractError("unsupported raw control event")
    _raw_control_scope(row)


def _require_raw_quote_scalar_types(row: Mapping[str, object]) -> None:
    """Keep every retained provider numeric as exact text/int/null, never float."""

    for name in _RAW_RETAINED_SCALAR_FIELDS:
        value = row.get(name)
        if isinstance(value, bool) or not isinstance(value, (str, int, type(None))):
            raise BBOChangeContractError(
                f"{name} must retain string, integer, or null raw value"
            )


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
        if control.scope == "GENERATION_GLOBAL":
            self._states.clear()
            self._last_raw_fingerprint = None
            self._last_provider_update_id = None
        else:
            lane = (
                control.exact_contract,
                control.session_family,
                control.segment_id,
            )
            self._states.pop(lane, None)
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
            status=(
                "GENERATION_ABORTED"
                if aborting
                else "STATE_RESET"
                if control.scope == "GENERATION_GLOBAL"
                else "LANE_RESET"
            ),
        )

    def process_replay_duplicate(self, obs: ObservedBBO) -> FeaturePoint:
        """Advance replay ordering for an externally proven exact duplicate.

        Provider semantics can prove a duplicate after intervening callbacks;
        the original collector API intentionally only accepts adjacent caller
        duplicates.  Replay must still advance its run-global sequence without
        turning such an anchored duplicate into feature input.
        """

        _metadata(obs)
        self._accept_ordering(
            collector_generation=obs.collector_generation,
            clock_epoch=obs.clock_epoch,
            collector_seq=obs.collector_seq,
            receive_monotonic_ns=obs.receive_monotonic_ns,
        )
        return self._point(obs, "EXPLICIT_DUPLICATE_SKIPPED")

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


def _read_bounded(fd: int, maximum_bytes: int) -> bytes:
    limit = _require_int(maximum_bytes, "maximum_bytes", minimum=0)
    chunks: list[bytes] = []
    consumed = 0
    while consumed <= limit:
        chunk = os.read(fd, min(1024 * 1024, limit + 1 - consumed))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        consumed += len(chunk)
    raise BBOChangeContractError("sealed custody file exceeds its read bound")


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
    previous_partition_seal_id: str | None
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
        self._previous_partition_seal_id: str | None = None
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
                self._previous_partition_seal_id = terminal.seal_id
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
            _CUSTODY_QUOTE_FIELDS if record_type == "QUOTE" else _CUSTODY_CONTROL_FIELDS
        )
        if record_type not in {"QUOTE", "CONTROL"} or set(row) != set(required):
            raise BBOChangeContractError("journal row does not match QUOTE/CONTROL schema")
        if record_type == "CONTROL":
            _require_raw_control_semantics(row)
        else:
            _require_raw_quote_scalar_types(row)
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
        elif row.get("record_type") == "CONTROL":
            required |= _CUSTODY_CONTROL_FIELDS
        if row.get("record_type") not in {"QUOTE", "CONTROL"} or set(row) != set(required):
            raise BBOChangeContractError("journal append requires complete QUOTE/CONTROL fields")
        if row["record_type"] == "CONTROL":
            _require_raw_control_semantics(row)
        else:
            _require_raw_quote_scalar_types(row)
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
        if _safe_name(manifest.partition_id, "manifest partition_id") != manifest.partition_id:
            raise BBOChangeContractError("manifest partition_id is not canonical")
        if manifest.path != f"{manifest.partition_id}.jsonl":
            raise BBOChangeContractError("closed manifest path is not canonical")
        if _safe_name(manifest.run_id, "manifest run_id") != manifest.run_id:
            raise BBOChangeContractError("manifest run_id is not canonical")
        if (
            _safe_name(
                manifest.collector_generation, "manifest collector_generation"
            )
            != manifest.collector_generation
        ):
            raise BBOChangeContractError(
                "manifest collector_generation is not canonical"
            )
        _require_canonical_text(manifest.schema_version, "manifest schema_version")
        if _require_code_sha(manifest.code_sha) != manifest.code_sha:
            raise BBOChangeContractError("manifest code_sha is not canonical")
        _require_canonical_text(
            manifest.closed_at_utc, "manifest closed_at_utc"
        )
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
            (manifest.previous_partition_seal_id, "previous_partition_seal_id", True),
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
                    or manifest.previous_partition_seal_id != (
                        ordered[ordered.index(manifest) - 1].seal_id
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
            "previous_partition_seal_id": terminal.seal_id if terminal else None,
            "closed_at_utc": _require_canonical_text(
                closed_at_utc, "closed_at_utc"
            ),
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


@dataclass(frozen=True)
class VerifiedCustodyStream:
    """A sealed custody chain verified without acquiring or writing a lock.

    The integrity statement is deliberately limited to the caller-supplied root
    pins and terminal partition/seal anchors.  This reader never repairs or
    quarantines a root: any unexpected file, incomplete tail, or bad chain is a
    hard error before replay can see a row.
    """

    root_pins: CustodyRootPins
    terminal_partition_hash: str
    terminal_seal_id: str
    partitions: tuple[Mapping[str, Any], ...]
    rows: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        def freeze(value: object) -> object:
            if isinstance(value, Mapping):
                return MappingProxyType({str(key): freeze(item) for key, item in value.items()})
            if isinstance(value, list):
                return tuple(freeze(item) for item in value)
            if isinstance(value, tuple):
                return tuple(freeze(item) for item in value)
            return value
        object.__setattr__(self, "partitions", tuple(freeze(item) for item in self.partitions))
        object.__setattr__(self, "rows", tuple(freeze(item) for item in self.rows))

    def to_bundle(self) -> dict[str, object]:
        return {
            "root_pins": dict(self.root_pins.__dict__),
            "terminal_partition_hash": self.terminal_partition_hash,
            "terminal_seal_id": self.terminal_seal_id,
            "partitions": [dict(item) for item in self.partitions],
            "rows": [dict(item) for item in self.rows],
        }


def _read_only_custody_file(
    root_fd: int,
    name: str,
    *,
    expected_size: int | None = None,
    maximum_size: int | None = None,
) -> bytes:
    """Read one safe basename and reject replacement while it is read."""

    if not isinstance(name, str) or not name or "/" in name or "\\" in name:
        raise BBOChangeContractError("unsafe read-only custody basename")
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=root_fd
        )
    except OSError as exc:
        raise BBOChangeContractError("cannot read sealed custody file") from exc
    try:
        before = os.fstat(fd)
        if (
            not S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or (before.st_mode & 0o777) != 0o600
            or before.st_nlink != 1
        ):
            raise BBOChangeContractError("sealed custody file is unsafe")
        if expected_size is not None and before.st_size != expected_size:
            raise BBOChangeContractError("sealed custody file size is invalid")
        if maximum_size is not None and before.st_size > maximum_size:
            raise BBOChangeContractError("sealed custody file exceeds its read bound")
        read_bound = expected_size if expected_size is not None else maximum_size
        data = (
            _read_bounded(fd, read_bound)
            if read_bound is not None else _read_all(fd)
        )
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        def identity(stat_result: os.stat_result) -> tuple[int, ...]:
            return (
                stat_result.st_dev,
                stat_result.st_ino,
                stat_result.st_size,
                stat_result.st_mtime_ns,
                stat_result.st_ctime_ns,
                stat_result.st_nlink,
                stat_result.st_uid,
                stat_result.st_mode & 0o777,
            )

        if identity(before) != identity(after) or identity(before) != identity(named):
            raise BBOChangeContractError("sealed custody file changed during read")
        if len(data) != before.st_size:
            raise BBOChangeContractError("sealed custody file length changed during read")
        return data
    finally:
        os.close(fd)


def _decode_read_only_custody_rows(data: bytes) -> list[dict[str, Any]]:
    if not data or not data.endswith(b"\n"):
        raise BBOChangeContractError("sealed custody JSONL is empty or incomplete")
    rows: list[dict[str, Any]] = []
    for line in data.splitlines():
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BBOChangeContractError("sealed custody JSONL is invalid") from exc
        if not isinstance(value, dict) or _canonical_json_bytes(value) != line:
            raise BBOChangeContractError("sealed custody JSONL is noncanonical")
        rows.append(value)
    return rows


def _validate_sealed_manifest_v1(manifest: ClosedPartition) -> None:
    if manifest.path != f"{manifest.partition_id}.jsonl":
        raise BBOChangeContractError("sealed manifest path is not canonical")
    for value, name in (
        (manifest.run_id, "manifest run_id"),
        (manifest.collector_generation, "manifest generation"),
        (manifest.partition_id, "manifest partition"),
    ):
        if _safe_name(value, name) != value:
            raise BBOChangeContractError(f"{name} is not canonical")
    _require_text(manifest.schema_version, "manifest schema_version")
    if manifest.schema_version != _CUSTODY_SCHEMA_VERSION:
        raise BBOChangeContractError("sealed manifest schema version is unsupported")
    _require_canonical_text(manifest.closed_at_utc, "manifest closed_at_utc")
    if _require_code_sha(manifest.code_sha) != manifest.code_sha:
        raise BBOChangeContractError("manifest code_sha is not canonical")
    for value, name in (
        (manifest.exact_bytes, "manifest exact_bytes"),
        (manifest.record_count, "manifest record_count"),
        (manifest.first_collector_seq, "manifest first_collector_seq"),
        (manifest.last_collector_seq, "manifest last_collector_seq"),
    ):
        _require_int(value, name, minimum=1)
    if manifest.last_collector_seq < manifest.first_collector_seq:
        raise BBOChangeContractError("sealed manifest sequence bounds are invalid")
    for value, name, nullable in (
        (manifest.first_record_hash, "manifest first_record_hash", False),
        (manifest.last_record_hash, "manifest last_record_hash", False),
        (manifest.partition_hash, "manifest partition_hash", False),
        (manifest.previous_partition_hash, "manifest previous_partition_hash", True),
        (manifest.previous_partition_seal_id, "manifest previous_partition_seal_id", True),
        (manifest.seal_id, "manifest seal_id", False),
    ):
        if value is None and nullable:
            continue
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise BBOChangeContractError(f"{name} is not a SHA-256 digest")


def read_verified_custody_stream_v1(
    root: str | Path,
    *,
    expected_root_pins: CustodyRootPins,
    trusted_head_partition_hash: str,
    trusted_head_seal_id: str,
) -> VerifiedCustodyStream:
    """Read an anchored, fully sealed custody chain without mutating ``root``.

    The terminal partition hash and seal id are external trust inputs.  A
    caller cannot substitute a self-consistent re-sealed chain without also
    replacing those anchors.
    """

    _require_posix_custody()
    if not isinstance(expected_root_pins, CustodyRootPins):
        raise BBOChangeContractError("read-only custody requires external root pins")
    if pin_custody_root(root) != expected_root_pins:
        raise BBOChangeContractError("read-only custody root pins do not match")
    for value, name in (
        (trusted_head_partition_hash, "trusted_head_partition_hash"),
        (trusted_head_seal_id, "trusted_head_seal_id"),
    ):
        if not isinstance(value, str) or len(value) != 64 or any(
            char not in "0123456789abcdef" for char in value
        ):
            raise BBOChangeContractError(f"{name} must be a SHA-256 hex digest")
    raw_root = os.fspath(root)
    root_fd = os.open(raw_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened_root = os.fstat(root_fd)
        opened_identity = _sha256(
            f"{opened_root.st_dev}:{opened_root.st_ino}:{opened_root.st_uid}:"
            f"{opened_root.st_mode & 0o777}".encode()
        )
        if (
            opened_identity != expected_root_pins.identity_sha256
            or pin_custody_root(root) != expected_root_pins
        ):
            raise BBOChangeContractError("read-only custody root changed during open")
        names = sorted(os.listdir(root_fd))
        root_snapshot = os.fstat(root_fd)
        if any(name.startswith(".quarantine-") and name.endswith(".json") for name in names):
            raise BBOChangeContractError("quarantined custody root cannot be replayed")
        manifest_names = [name for name in names if name.endswith(".closed.json")]
        if not manifest_names:
            raise BBOChangeContractError("read-only replay requires a sealed custody chain")
        manifests: list[tuple[ClosedPartition, dict[str, Any]]] = []
        manifest_raw_by_hash: dict[str, str] = {}
        for name in manifest_names:
            raw = _read_only_custody_file(
                root_fd, name, maximum_size=_MAX_CUSTODY_MANIFEST_BYTES
            )
            try:
                decoded = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BBOChangeContractError("sealed manifest is invalid") from exc
            if not isinstance(decoded, dict) or _canonical_json_bytes(decoded) + b"\n" != raw:
                raise BBOChangeContractError("sealed manifest is noncanonical")
            if set(decoded) != set(ClosedPartition.__dataclass_fields__):
                raise BBOChangeContractError("sealed manifest fields are not exact")
            core = dict(decoded)
            seal_id = core.pop("seal_id", None)
            if not isinstance(seal_id, str) or seal_id != _sha256(_canonical_json_bytes(core)):
                raise BBOChangeContractError("sealed manifest seal binding failed")
            try:
                manifest = ClosedPartition(**decoded)
            except TypeError as exc:
                raise BBOChangeContractError("sealed manifest shape is invalid") from exc
            _validate_sealed_manifest_v1(manifest)
            if name != f"{manifest.partition_id}.closed.json" or manifest.path != f"{manifest.partition_id}.jsonl":
                raise BBOChangeContractError("sealed manifest names are not canonical")
            _safe_name(manifest.run_id, "manifest run_id")
            _safe_name(manifest.collector_generation, "manifest generation")
            _safe_name(manifest.partition_id, "manifest partition")
            _require_code_sha(manifest.code_sha)
            manifests.append((manifest, decoded))
            manifest_raw_by_hash[manifest.partition_hash] = raw.decode("utf-8")
        hashes = {manifest.partition_hash: (manifest, decoded) for manifest, decoded in manifests}
        if len(hashes) != len(manifests):
            raise BBOChangeContractError("sealed custody partition hashes collide")
        roots = [item for item in hashes.values() if item[0].previous_partition_hash is None]
        if len(roots) != 1:
            raise BBOChangeContractError("sealed custody chain needs exactly one root")
        children: dict[str, tuple[ClosedPartition, dict[str, Any]]] = {}
        for manifest, decoded in manifests:
            previous = manifest.previous_partition_hash
            if previous is not None:
                if previous not in hashes or previous in children:
                    raise BBOChangeContractError("sealed custody chain is missing or forked")
                children[previous] = (manifest, decoded)
        ordered = [roots[0]]
        while ordered[-1][0].partition_hash in children:
            ordered.append(children[ordered[-1][0].partition_hash])
        if len(ordered) != len(manifests):
            raise BBOChangeContractError("sealed custody chain is disconnected")
        terminal = ordered[-1][0]
        if (
            terminal.partition_hash != trusted_head_partition_hash
            or terminal.seal_id != trusted_head_seal_id
        ):
            raise BBOChangeContractError("sealed custody terminal anchor mismatch")
        allowed = {".custody.lock"}
        allowed.update(f"{manifest.partition_id}.closed.json" for manifest, _ in ordered)
        allowed.update(manifest.path for manifest, _ in ordered)
        if any(name not in allowed for name in names):
            raise BBOChangeContractError("custody root contains an orphan or unsealed tail")
        if ".custody.lock" in names:
            _read_only_custody_file(root_fd, ".custody.lock", expected_size=0)
        expected_seq = 1
        previous_record_hash: str | None = None
        previous_partition_hash: str | None = None
        previous_partition_seal_id: str | None = None
        prior_generation: str | None = None
        seen_generations: set[str] = set()
        run_id: str | None = None
        chain_schema: str | None = None
        chain_code_sha: str | None = None
        rows: list[Mapping[str, Any]] = []
        bundles: list[Mapping[str, Any]] = []
        for manifest, decoded in ordered:
            if run_id is None:
                run_id = manifest.run_id
            if manifest.run_id != run_id:
                raise BBOChangeContractError("sealed custody chain mixes run ids")
            if chain_schema is None:
                chain_schema, chain_code_sha = manifest.schema_version, manifest.code_sha
            elif (manifest.schema_version, manifest.code_sha) != (chain_schema, chain_code_sha):
                raise BBOChangeContractError("sealed custody chain mixes schema or code")
            if prior_generation is not None and manifest.collector_generation != prior_generation:
                seen_generations.add(prior_generation)
                if manifest.collector_generation in seen_generations:
                    raise BBOChangeContractError("sealed custody generation reappears")
                expected_seq = 1
            data = _read_only_custody_file(
                root_fd, manifest.path, expected_size=manifest.exact_bytes
            )
            decoded_rows = _decode_read_only_custody_rows(data)
            if (
                len(data) != manifest.exact_bytes
                or len(decoded_rows) != manifest.record_count
                or _sha256(data) != manifest.partition_hash
                or manifest.previous_partition_hash != previous_partition_hash
                or manifest.previous_partition_seal_id != previous_partition_seal_id
                or not decoded_rows
            ):
                raise BBOChangeContractError("sealed custody partition commitment mismatch")
            first_hash: str | None = None
            last_hash: str | None = None
            for row in decoded_rows:
                record_type = row.get("record_type")
                required = _CUSTODY_COMMON_FIELDS | (
                    _CUSTODY_QUOTE_FIELDS if record_type == "QUOTE" else frozenset()
                )
                control_fields = {"event_type", "reason", "scope"} if record_type == "CONTROL" else set()
                if (
                    record_type not in {"QUOTE", "CONTROL"}
                    or set(row) != set(required | control_fields)
                ):
                    raise BBOChangeContractError("sealed custody row schema is invalid")
                _require_int(row.get("collector_seq"), "collector_seq", minimum=1)
                if (
                    row.get("research_line_id") != RESEARCH_LINE_ID
                    or row.get("data_contract_id") != DATA_CONTRACT_ID
                    or row.get("run_id") != manifest.run_id
                    or row.get("partition_id") != manifest.partition_id
                    or row.get("collector_generation") != manifest.collector_generation
                    or row.get("collector_seq") != expected_seq
                    or row.get("prev_record_hash") != previous_record_hash
                ):
                    raise BBOChangeContractError("sealed custody row order is invalid")
                if record_type == "CONTROL":
                    _require_raw_control_semantics(row)
                else:
                    _require_raw_quote_scalar_types(row)
                core = dict(row)
                record_hash = core.pop("record_hash", None)
                if not isinstance(record_hash, str) or record_hash != _sha256(_canonical_json_bytes(core)):
                    raise BBOChangeContractError("sealed custody row hash is invalid")
                first_hash = first_hash or record_hash
                last_hash = record_hash
                previous_record_hash = record_hash
                expected_seq += 1
                rows.append(dict(row))
            if (
                manifest.first_collector_seq != expected_seq - len(decoded_rows)
                or manifest.last_collector_seq != expected_seq - 1
                or manifest.first_record_hash != first_hash
                or manifest.last_record_hash != last_hash
            ):
                raise BBOChangeContractError("sealed custody manifest row bounds are invalid")
            bundles.append(
                {
                    "manifest_json_utf8": manifest_raw_by_hash[manifest.partition_hash],
                    "raw_jsonl_utf8": data.decode("utf-8"),
                }
            )
            previous_partition_hash = manifest.partition_hash
            previous_partition_seal_id = manifest.seal_id
            prior_generation = manifest.collector_generation
        root_after = os.fstat(root_fd)
        def root_version(stat_result: os.stat_result) -> tuple[int, ...]:
            return (
                stat_result.st_dev,
                stat_result.st_ino,
                stat_result.st_mtime_ns,
                stat_result.st_ctime_ns,
                stat_result.st_nlink,
                stat_result.st_uid,
                stat_result.st_mode & 0o777,
            )

        if (
            root_version(root_snapshot) != root_version(root_after)
            or sorted(os.listdir(root_fd)) != names
            or pin_custody_root(root) != expected_root_pins
        ):
            raise BBOChangeContractError("custody root changed during read-only verification")
        return VerifiedCustodyStream(
            expected_root_pins,
            terminal.partition_hash,
            terminal.seal_id,
            tuple(bundles),
            tuple(rows),
        )
    finally:
        os.close(root_fd)


_REPLAY_SCHEMA_VERSION = "issue488-raw-replay-v1"
_RAW_PARSE_STATUS = "RAW_RETAINED"
_RAW_SOURCE_STATUS = "OBSERVED"
_PROVIDER_ID_STATUSES = frozenset(
    {"UNVERIFIED", "PROVEN_NO_USABLE_ID", "PROVEN_UNIQUE"}
)


@dataclass(frozen=True)
class _ReplayAttempt:
    attempt_id: str
    signal_id: str
    run_id: str
    collector_generation: str
    clock_epoch: str
    segment_id: str
    session_family: str
    official_day: date
    exact_contract: str
    scenario_id: str
    direction: str
    signal_raw_record_hash: str
    entry_cutoff_receive_monotonic_ns: int
    state: str = "ENTRY_PENDING"
    entry_quote: object | None = None
    entry_raw_record_hash: str | None = None
    horizon_active_time_ns: int | None = None
    exit_cutoff_receive_monotonic_ns: int | None = None
    exit_raw_record_hash: str | None = None
    last_source_event_utc_ns: int | None = None


@dataclass(frozen=True)
class MultiSignalReplayResult:
    """Pure JSON producer result for the independent raw-to-PnL auditor."""

    bundle: Mapping[str, object]

    def to_bundle(self) -> dict[str, object]:
        return dict(self.bundle)


def _json_primitive(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise BBOChangeContractError("freeze bundle cannot contain float")
    if isinstance(value, (list, tuple)):
        return [_json_primitive(item) for item in value]
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise BBOChangeContractError("freeze bundle keys must be text")
        return {key: _json_primitive(item) for key, item in value.items()}
    raise BBOChangeContractError("freeze bundle must contain canonical JSON primitives")


def _as_json(value: object) -> object:
    """Convert only frozen result values to canonical JSON-compatible values."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _as_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_as_json(item) for item in value]
    if is_dataclass(value):
        return {item.name: _as_json(getattr(value, item.name)) for item in fields(value)}
    raise BBOChangeContractError("producer result contains a non-JSON value")


def _reverify_stream_for_replay(
    stream: VerifiedCustodyStream,
    *,
    expected_root_pins: CustodyRootPins,
    trusted_head_partition_hash: str,
    trusted_head_seal_id: str,
) -> None:
    """Recheck supplied bundle bytes before trusting a public stream instance.

    ``VerifiedCustodyStream`` is intentionally serializable for audit, so
    callers can construct one themselves.  Replay therefore does not treat
    its type as authority: it rebuilds the complete sealed chain from exact
    manifest/JSONL bytes and compares the canonical rows/head commitments.
    """

    if (
        not isinstance(expected_root_pins, CustodyRootPins)
        or stream.root_pins != expected_root_pins
        or not stream.partitions
    ):
        raise BBOChangeContractError("replay stream lacks verified custody provenance")
    for value, name in (
        (trusted_head_partition_hash, "trusted_head_partition_hash"),
        (trusted_head_seal_id, "trusted_head_seal_id"),
    ):
        if not isinstance(value, str) or len(value) != 64 or any(
            char not in "0123456789abcdef" for char in value
        ):
            raise BBOChangeContractError(f"{name} must be a SHA-256 hex digest")
    parsed: list[tuple[ClosedPartition, list[dict[str, Any]]]] = []
    for item in stream.partitions:
        if not isinstance(item, Mapping) or set(item) != {"manifest_json_utf8", "raw_jsonl_utf8"}:
            raise BBOChangeContractError("replay custody partition bundle is not exact")
        manifest_text, raw_text = item["manifest_json_utf8"], item["raw_jsonl_utf8"]
        if not isinstance(manifest_text, str) or not isinstance(raw_text, str):
            raise BBOChangeContractError("replay custody partition bytes must be UTF-8 text")
        raw_manifest = manifest_text.encode("utf-8")
        raw_jsonl = raw_text.encode("utf-8")
        if len(raw_manifest) > _MAX_CUSTODY_MANIFEST_BYTES:
            raise BBOChangeContractError("replay custody manifest is too large")
        try:
            decoded = json.loads(raw_manifest)
        except json.JSONDecodeError as exc:
            raise BBOChangeContractError("replay custody manifest is invalid") from exc
        if (
            not isinstance(decoded, dict)
            or _canonical_json_bytes(decoded) + b"\n" != raw_manifest
            or set(decoded) != set(ClosedPartition.__dataclass_fields__)
        ):
            raise BBOChangeContractError("replay custody manifest is noncanonical")
        core = dict(decoded)
        seal_id = core.pop("seal_id", None)
        if not isinstance(seal_id, str) or seal_id != _sha256(_canonical_json_bytes(core)):
            raise BBOChangeContractError("replay custody manifest seal is invalid")
        try:
            manifest = ClosedPartition(**decoded)
        except TypeError as exc:
            raise BBOChangeContractError("replay custody manifest shape is invalid") from exc
        _validate_sealed_manifest_v1(manifest)
        if manifest.path != f"{manifest.partition_id}.jsonl" or _sha256(raw_jsonl) != manifest.partition_hash:
            raise BBOChangeContractError("replay custody partition hash is invalid")
        rows = _decode_read_only_custody_rows(raw_jsonl)
        if len(rows) != manifest.record_count or len(raw_jsonl) != manifest.exact_bytes:
            raise BBOChangeContractError("replay custody partition count is invalid")
        parsed.append((manifest, rows))
    by_hash = {manifest.partition_hash: (manifest, rows) for manifest, rows in parsed}
    if len(by_hash) != len(parsed):
        raise BBOChangeContractError("replay custody chain has duplicate partition hashes")
    roots = [item for item in by_hash.values() if item[0].previous_partition_hash is None]
    if len(roots) != 1:
        raise BBOChangeContractError("replay custody chain has no unique root")
    children: dict[str, tuple[ClosedPartition, list[dict[str, Any]]]] = {}
    for manifest, rows in parsed:
        if manifest.previous_partition_hash is not None:
            if manifest.previous_partition_hash not in by_hash or manifest.previous_partition_hash in children:
                raise BBOChangeContractError("replay custody chain is missing or forked")
            children[manifest.previous_partition_hash] = (manifest, rows)
    ordered = [roots[0]]
    while ordered[-1][0].partition_hash in children:
        ordered.append(children[ordered[-1][0].partition_hash])
    if len(ordered) != len(parsed):
        raise BBOChangeContractError("replay custody chain is disconnected")
    expected_rows: list[dict[str, Any]] = []
    expected_seq, previous_hash, previous_partition, previous_partition_seal = 1, None, None, None
    previous_generation: str | None = None
    seen_generations: set[str] = set()
    run_id: str | None = None
    chain_schema: str | None = None
    chain_code_sha: str | None = None
    for manifest, rows in ordered:
        if run_id is None:
            run_id = manifest.run_id
        if (
            manifest.run_id != run_id
            or manifest.previous_partition_hash != previous_partition
            or manifest.previous_partition_seal_id != previous_partition_seal
        ):
            raise BBOChangeContractError("replay custody partition identity is invalid")
        if chain_schema is None:
            chain_schema, chain_code_sha = manifest.schema_version, manifest.code_sha
        elif (manifest.schema_version, manifest.code_sha) != (chain_schema, chain_code_sha):
            raise BBOChangeContractError("replay custody chain mixes schema or code")
        if previous_generation is not None and manifest.collector_generation != previous_generation:
            seen_generations.add(previous_generation)
            if manifest.collector_generation in seen_generations:
                raise BBOChangeContractError("replay custody generation reappears")
            expected_seq = 1
        first_hash: str | None = None
        for row in rows:
            record_type = row.get("record_type")
            required = _CUSTODY_COMMON_FIELDS | (
                _CUSTODY_QUOTE_FIELDS if record_type == "QUOTE" else frozenset()
            )
            control = {"event_type", "reason", "scope"} if record_type == "CONTROL" else set()
            if (
                record_type not in {"QUOTE", "CONTROL"}
                or set(row) != set(required | control)
                or row.get("research_line_id") != RESEARCH_LINE_ID
                or row.get("data_contract_id") != DATA_CONTRACT_ID
                or row.get("run_id") != manifest.run_id
                or row.get("partition_id") != manifest.partition_id
                or row.get("collector_generation") != manifest.collector_generation
                or row.get("collector_seq") != expected_seq
                or row.get("prev_record_hash") != previous_hash
            ):
                raise BBOChangeContractError("replay custody row identity is invalid")
            _require_int(row.get("collector_seq"), "collector_seq", minimum=1)
            if record_type == "CONTROL":
                _require_raw_control_semantics(row)
            else:
                _require_raw_quote_scalar_types(row)
            core = dict(row)
            record_hash = core.pop("record_hash", None)
            if not isinstance(record_hash, str) or record_hash != _sha256(_canonical_json_bytes(core)):
                raise BBOChangeContractError("replay custody row hash is invalid")
            first_hash = first_hash or record_hash
            previous_hash = record_hash
            expected_seq += 1
            expected_rows.append(row)
        if (
            not rows
            or manifest.first_collector_seq != expected_seq - len(rows)
            or manifest.last_collector_seq != expected_seq - 1
            or manifest.first_record_hash != first_hash
            or manifest.last_record_hash != previous_hash
        ):
            raise BBOChangeContractError("replay custody partition bounds are invalid")
        previous_partition = manifest.partition_hash
        previous_partition_seal = manifest.seal_id
        previous_generation = manifest.collector_generation
    if (
        previous_partition != trusted_head_partition_hash
        or ordered[-1][0].seal_id != trusted_head_seal_id
        or stream.terminal_partition_hash != trusted_head_partition_hash
        or stream.terminal_seal_id != trusted_head_seal_id
        or [dict(row) for row in stream.rows] != expected_rows
    ):
        raise BBOChangeContractError("replay stream rows or terminal anchors were forged")


def _require_freeze_bundle(
    freeze_bundle: Mapping[str, object], trusted_freeze_sha256: str
) -> dict[str, object]:
    if not isinstance(freeze_bundle, Mapping):
        raise BBOChangeContractError("freeze bundle must be a mapping")
    primitive = _json_primitive(freeze_bundle)
    if not isinstance(primitive, dict):  # defensive, Mapping is handled above
        raise BBOChangeContractError("freeze bundle must be an object")
    if _sha256(_canonical_json_bytes(primitive)) != trusted_freeze_sha256:
        raise BBOChangeContractError("external freeze SHA-256 anchor mismatch")
    required = {
        "schema_version",
        "research_line_id",
        "candidate_id",
        "data_contract_id",
        "thresholds",
        "scenarios",
        "instrument_terms",
        "fee_schedules",
        "broker_markups",
        "coverage_plan",
        "provider_semantics",
    }
    if set(primitive) != required:
        raise BBOChangeContractError("freeze bundle fields are not exact")
    if (
        primitive["schema_version"] != _REPLAY_SCHEMA_VERSION
        or primitive["research_line_id"] != RESEARCH_LINE_ID
        or primitive["candidate_id"] != CANDIDATE_ID
        or primitive["data_contract_id"] != DATA_CONTRACT_ID
        or not isinstance(primitive["schema_version"], str)
    ):
        raise BBOChangeContractError("freeze bundle identity mismatch")
    return primitive


def _freeze_day(value: object, field_name: str) -> date:
    if not isinstance(value, str):
        raise BBOChangeContractError(f"{field_name} must be ISO official day text")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise BBOChangeContractError(f"{field_name} must be ISO official day text") from exc


def _freeze_text(value: object, field_name: str) -> str:
    return _require_canonical_text(value, field_name)


def _freeze_decimal(value: object, field_name: str) -> Decimal:
    if not isinstance(value, str):
        raise BBOChangeContractError(f"{field_name} must be decimal text")
    return _decimal(value, field_name)


def _freeze_sha256(value: object, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise BBOChangeContractError(f"{field_name} must be lowercase SHA-256")
    return value


def _freeze_thresholds(bundle: Mapping[str, object]) -> dict[tuple[str, str], FrozenThreshold]:
    rows = bundle["thresholds"]
    if not isinstance(rows, list):
        raise BBOChangeContractError("freeze thresholds must be a list")
    result: dict[tuple[str, str], FrozenThreshold] = {}
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {
            "exact_contract", "session_family", "quantile", "sample_count", "threshold"
        }:
            raise BBOChangeContractError("freeze threshold row is not exact")
        frozen = FrozenThreshold(
            _freeze_text(row["exact_contract"], "threshold exact_contract"),
            _freeze_text(row["session_family"], "threshold session_family"),
            _freeze_decimal(row["quantile"], "threshold quantile"),
            _require_int(row["sample_count"], "threshold sample_count", minimum=1),
            _freeze_decimal(row["threshold"], "threshold value"),
        )
        if (
            frozen.quantile != Decimal("0.95")
            or frozen.sample_count < MINIMUM_CALIBRATION_SCORES
            or frozen.threshold <= 0
            or not frozen.threshold.is_finite()
        ):
            raise BBOChangeContractError("threshold is not a frozen candidate Q95")
        key = (frozen.exact_contract, frozen.session_family)
        if key in result:
            raise BBOChangeContractError("duplicate frozen threshold")
        result[key] = frozen
    if not result:
        raise BBOChangeContractError("freeze thresholds cannot be empty")
    return result


def _freeze_bindings(bundle: Mapping[str, object]) -> tuple[tuple[object, ...], tuple[object, ...], tuple[object, ...]]:
    """Construct accounting bindings solely from externally hashed primitives."""

    from scripts import collector_ordered_l1_bbo_change_accounting_v1 as accounting

    def make_rows(name: str, cls: object) -> tuple[object, ...]:
        raw_rows = bundle[name]
        if not isinstance(raw_rows, list):
            raise BBOChangeContractError(f"freeze {name} must be a list")
        made: list[object] = []
        for raw in raw_rows:
            if not isinstance(raw, Mapping):
                raise BBOChangeContractError(f"freeze {name} row must be an object")
            values = dict(raw)
            common = {
                "binding_id", "exact_contract", "official_day",
                "valid_from_utc_ns", "valid_until_utc_ns", "authority",
                "source", "version", "source_sha256",
            }
            expected = common | (
                {"tick_size", "multiplier"}
                if name == "instrument_terms"
                else {"offset", "fixed_cny", "ratio_per_mille"}
            )
            if set(values) != expected:
                raise BBOChangeContractError(
                    f"freeze {name} accounting binding fields are not exact"
                )
            if "official_day" not in values:
                raise BBOChangeContractError(f"freeze {name} row lacks official_day")
            values["official_day"] = _freeze_day(values["official_day"], "official_day")
            for text_name in (
                "binding_id", "exact_contract", "authority", "source", "version"
            ):
                values[text_name] = _freeze_text(values[text_name], text_name)
            _require_int(values["valid_from_utc_ns"], "valid_from_utc_ns", minimum=1)
            _require_int(values["valid_until_utc_ns"], "valid_until_utc_ns", minimum=1)
            values["source_sha256"] = _freeze_sha256(
                values["source_sha256"], "source_sha256"
            )
            if "offset" in values:
                values["offset"] = _freeze_text(values["offset"], "offset")
            for decimal_name in ("tick_size", "multiplier", "fixed_cny", "ratio_per_mille"):
                if decimal_name in values:
                    values[decimal_name] = _freeze_decimal(
                        values[decimal_name], decimal_name
                    )
            try:
                made.append(cls(**values))  # type: ignore[operator]
            except (TypeError, ValueError) as exc:
                raise BBOChangeContractError(f"freeze {name} accounting binding is invalid") from exc
        return tuple(made)

    return (
        make_rows("instrument_terms", accounting.InstrumentTermsBinding),
        make_rows("fee_schedules", accounting.FeeScheduleBinding),
        make_rows("broker_markups", accounting.BrokerMarkupBinding),
    )


def _freeze_coverage_plan(
    bundle: Mapping[str, object],
) -> tuple[dict[str, object], ...]:
    rows = bundle["coverage_plan"]
    if not isinstance(rows, list):
        raise BBOChangeContractError("coverage_plan must be a list")
    required = {
        "exact_contract", "official_day", "session_family", "segment_id",
        "start_utc_ns", "end_utc_ns", "days_to_ltd", "eligible", "source",
        "authority", "version", "source_sha256",
    }
    result: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for raw in rows:
        if not isinstance(raw, Mapping) or set(raw) != required:
            raise BBOChangeContractError("coverage plan row is not exact")
        row = dict(raw)
        contract = _freeze_text(row["exact_contract"], "coverage exact_contract")
        day = _freeze_day(row["official_day"], "coverage official_day").isoformat()
        session = _freeze_text(row["session_family"], "coverage session_family")
        segment = _freeze_text(row["segment_id"], "coverage segment_id")
        start = _require_int(row["start_utc_ns"], "coverage start_utc_ns", minimum=1)
        end = _require_int(row["end_utc_ns"], "coverage end_utc_ns", minimum=1)
        if end <= start:
            raise BBOChangeContractError("coverage plan segment interval is invalid")
        _require_int(row["days_to_ltd"], "coverage days_to_ltd", minimum=0)
        if not isinstance(row["eligible"], bool):
            raise BBOChangeContractError("coverage eligible must be bool")
        _freeze_text(row["source"], "coverage source")
        _freeze_text(row["authority"], "coverage authority")
        _freeze_text(row["version"], "coverage version")
        _freeze_sha256(row["source_sha256"], "coverage source_sha256")
        cell = (contract, day, session, segment)
        if cell in seen:
            raise BBOChangeContractError("duplicate frozen coverage cell")
        seen.add(cell)
        result.append(row)
    return tuple(result)


def _freeze_provider_semantics(
    bundle: Mapping[str, object],
) -> dict[tuple[str, str], str]:
    rows = bundle["provider_semantics"]
    if not isinstance(rows, list):
        raise BBOChangeContractError("freeze provider_semantics must be a list")
    required = {
        "provider_delivery_semantics", "provider_update_id_semantics", "status"
    }
    result: dict[tuple[str, str], str] = {}
    for raw in rows:
        if not isinstance(raw, Mapping) or set(raw) != required:
            raise BBOChangeContractError("provider semantics row is not exact")
        delivery = _freeze_text(
            raw["provider_delivery_semantics"], "provider delivery semantics"
        )
        identity = _freeze_text(
            raw["provider_update_id_semantics"], "provider id semantics"
        )
        status = _freeze_text(raw["status"], "provider semantics status")
        if status not in _PROVIDER_ID_STATUSES:
            raise BBOChangeContractError("provider semantics status is invalid")
        key = (delivery, identity)
        if key in result:
            raise BBOChangeContractError("duplicate provider semantics cell")
        result[key] = status
    return result


def _provider_status(bundle: Mapping[str, object], row: Mapping[str, object]) -> str:
    rows = bundle["provider_semantics"]
    if not isinstance(rows, list):
        raise BBOChangeContractError("freeze provider_semantics must be a list")
    provider = row.get("provider_delivery_semantics")
    id_semantics = row.get("provider_update_id_semantics")
    matches = [
        item for item in rows
        if isinstance(item, Mapping)
        and item.get("provider_delivery_semantics") == provider
        and item.get("provider_update_id_semantics") == id_semantics
    ]
    if len(matches) != 1 or set(matches[0]) != {
        "provider_delivery_semantics", "provider_update_id_semantics", "status"
    }:
        raise BBOChangeContractError("provider semantics are not uniquely frozen")
    status = matches[0]["status"]
    if not isinstance(status, str) or status not in _PROVIDER_ID_STATUSES:
        raise BBOChangeContractError("provider semantics status is invalid")
    return status


def _provider_payload_digest(row: Mapping[str, object]) -> str:
    # The entire provider payload, rather than a convenient BBO subset, binds
    # a PROVEN_UNIQUE ID.  Collector sequence/hash remain outside that payload.
    names = (
        "provider_delivery_semantics", "provider_batch_id", "within_batch_rank",
        "provider_update_id", "provider_update_id_semantics", "source_event_time_raw",
        "source_event_utc_ns", "source_time_precision_ns", "product", "exact_contract",
        "exchange", "official_trading_day", "session_family", "bid_price1_raw",
        "bid_size1_raw", "ask_price1_raw", "ask_size1_raw", "last_price_raw",
        "cumulative_volume_raw", "cumulative_amount_raw", "open_interest_raw",
        "parse_status", "source_status",
    )
    if any(name not in row for name in names):
        raise BBOChangeContractError("raw provider payload is incomplete")
    return _sha256(_canonical_json_bytes({name: row[name] for name in names}))


def _raw_quote_to_observed(row: Mapping[str, object]) -> ObservedBBO:
    if row.get("parse_status") != _RAW_PARSE_STATUS or row.get("source_status") != _RAW_SOURCE_STATUS:
        raise BBOChangeContractError("raw quote parse/source status is not retained/observed")
    return ObservedBBO(
        collector_generation=_require_text(row.get("collector_generation"), "collector_generation"),
        clock_epoch=_require_text(row.get("clock_epoch"), "clock_epoch"),
        exact_contract=_require_text(row.get("exact_contract"), "exact_contract"),
        session_family=_require_text(row.get("session_family"), "session_family"),
        segment_id=_require_text(row.get("segment_id"), "segment_id"),
        collector_seq=_require_int(row.get("collector_seq"), "collector_seq", minimum=1),
        source_event_ns=_require_int(
            row.get("source_event_utc_ns"), "source_event_utc_ns", minimum=1
        ),
        receive_utc_ns=_require_int(
            row.get("callback_entry_receive_utc_ns"),
            "receive_utc_ns",
            minimum=1,
        ),
        receive_monotonic_ns=_require_int(
            row.get("callback_entry_receive_monotonic_ns"),
            "receive_monotonic_ns",
            minimum=1,
        ),
        active_time_ns=_require_int(
            row.get("callback_entry_receive_monotonic_ns"),
            "active_time_ns",
            minimum=1,
        ),
        bid_price=row.get("bid_price1_raw"), bid_size=row.get("bid_size1_raw"),
        ask_price=row.get("ask_price1_raw"), ask_size=row.get("ask_size1_raw"),
        provider_update_id=None, explicit_duplicate=False,
        clock_sync_state=_require_text(row.get("clock_sync_state"), "clock_sync_state"),
        clock_offset_ns=_require_int(row.get("clock_offset_ns"), "clock_offset_ns", minimum=-10**18),
        clock_uncertainty_ns=_require_int(row.get("clock_uncertainty_ns"), "clock_uncertainty_ns"),
        source_time_precision_ns=_require_int(row.get("source_time_precision_ns"), "source_time_precision_ns", minimum=1),
    )


def _execution_quote(row: Mapping[str, object], *, provider_update_id: str | None) -> object | None:
    """Return a typed execution quote only when raw BBO numerics are representable."""

    from scripts import collector_ordered_l1_bbo_change_accounting_v1 as accounting

    try:
        return accounting.ExecutionQuote(
            exact_contract=_require_text(row.get("exact_contract"), "exact_contract"),
            raw_record_hash=_require_text(row.get("record_hash"), "record_hash"),
            collector_generation=_require_text(row.get("collector_generation"), "collector_generation"),
            clock_epoch=_require_text(row.get("clock_epoch"), "clock_epoch"),
            segment_id=_require_text(row.get("segment_id"), "segment_id"),
            collector_seq=_require_int(row.get("collector_seq"), "collector_seq", minimum=1),
            provider_update_id=provider_update_id,
            source_event_utc_ns=_require_int(row.get("source_event_utc_ns"), "source_event_utc_ns", minimum=1),
            receive_utc_ns=_require_int(row.get("callback_entry_receive_utc_ns"), "receive_utc_ns", minimum=1),
            receive_monotonic_ns=_require_int(row.get("callback_entry_receive_monotonic_ns"), "receive_monotonic_ns", minimum=1),
            active_time_ns=_require_int(row.get("callback_entry_receive_monotonic_ns"), "active_time_ns", minimum=1),
            official_day=_freeze_day(row.get("official_trading_day"), "official_trading_day"),
            bid=_decimal(row.get("bid_price1_raw"), "bid_price1_raw"),
            bid_size=_decimal(row.get("bid_size1_raw"), "bid_size1_raw"),
            ask=_decimal(row.get("ask_price1_raw"), "ask_price1_raw"),
            ask_size=_decimal(row.get("ask_size1_raw"), "ask_size1_raw"),
            clock_sync_state=_require_text(row.get("clock_sync_state"), "clock_sync_state"),
            reset_reason=None,
            explicit_duplicate=False,
        )
    except (ValueError, BBOChangeContractError):
        return None


def _signal_id(row: Mapping[str, object], signal: SignalDecision) -> str:
    return _sha256(_canonical_json_bytes({
        "kind": "threshold-crossing-v1", "candidate_id": CANDIDATE_ID,
        "run_id": row["run_id"], "collector_generation": row["collector_generation"],
        "collector_seq": row["collector_seq"], "raw_record_hash": row["record_hash"],
        "exact_contract": signal.exact_contract, "session_family": signal.session_family,
        "direction": signal.direction, "threshold": format(signal.threshold, "f"),
    }))


def _attempt_id(signal_id: str, scenario_id: str) -> str:
    return _sha256(_canonical_json_bytes({
        "kind": "attempt-v1", "signal_id": signal_id, "scenario_id": scenario_id,
    }))


def _eligibility_reason(
    bundle: Mapping[str, object], row: Mapping[str, object]
) -> str | None:
    """Return None only for the one frozen PIT segment that permits a signal."""

    plans = bundle["coverage_plan"]
    if not isinstance(plans, list):
        raise BBOChangeContractError("coverage_plan must be a list")
    keys = {
        "exact_contract": row.get("exact_contract"),
        "official_day": row.get("official_trading_day"),
        "session_family": row.get("session_family"),
        "segment_id": row.get("segment_id"),
    }
    matches = [item for item in plans if isinstance(item, Mapping) and all(item.get(k) == v for k, v in keys.items())]
    if len(matches) != 1:
        return "PIT_SEGMENT_NOT_UNIQUE"
    plan = matches[0]
    required = {
        "exact_contract", "official_day", "session_family", "segment_id",
        "start_utc_ns", "end_utc_ns", "days_to_ltd", "eligible", "source",
        "authority", "version", "source_sha256",
    }
    if set(plan) != required:
        raise BBOChangeContractError("coverage plan row is not exact")
    start = _require_int(plan["start_utc_ns"], "segment start", minimum=1)
    end = _require_int(plan["end_utc_ns"], "segment end", minimum=1)
    if end <= start:
        raise BBOChangeContractError("coverage plan segment interval is invalid")
    received = _require_int(row.get("callback_entry_receive_utc_ns"), "receive UTC", minimum=1)
    if not start <= received < end:
        return "PIT_SEGMENT_OUTSIDE_INTERVAL"
    if end - received < 60_000_000_000:
        return "PIT_SEGMENT_REMAINING_TOO_SHORT"
    if _require_int(plan["days_to_ltd"], "days_to_ltd", minimum=0) <= 10:
        return "PIT_DAYS_TO_LTD_TOO_SHORT"
    _require_text(plan["source"], "coverage source")
    _require_text(plan["authority"], "coverage authority")
    _require_text(plan["version"], "coverage version")
    value = plan["source_sha256"]
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise BBOChangeContractError("coverage source SHA is invalid")
    return None if plan["eligible"] is True else "PIT_SEGMENT_INELIGIBLE"


def _require_replay_clock_quality(rows: Iterable[Mapping[str, object]]) -> None:
    """Reject row-level clock defects before economic state is created.

    A small synthetic fixture may contain fewer than the 1,000 observations
    needed to prove the aggregate p99 gate; that remains a separate holdout
    blocker.  At 1,000 or more quotes, replay also enforces the frozen p99.
    """

    lags: list[int] = []
    for row in rows:
        if row.get("record_type") != "QUOTE":
            continue
        if _freeze_text(row.get("clock_sync_state"), "clock_sync_state") != _SYNCED:
            raise BBOChangeContractError("economic replay requires a synced clock")
        offset = _require_int(
            row.get("clock_offset_ns"), "clock_offset_ns", minimum=-10**18
        )
        uncertainty = _require_int(
            row.get("clock_uncertainty_ns"), "clock_uncertainty_ns"
        )
        precision = _require_int(
            row.get("source_time_precision_ns"),
            "source_time_precision_ns",
            minimum=1,
        )
        if abs(offset) > MAX_ABS_CLOCK_OFFSET_NS:
            raise BBOChangeContractError("economic replay clock offset is too large")
        if uncertainty > MAX_CLOCK_UNCERTAINTY_NS:
            raise BBOChangeContractError(
                "economic replay clock uncertainty is too large"
            )
        if precision > MAX_SOURCE_TIME_PRECISION_NS:
            raise BBOChangeContractError("economic replay source time is too coarse")
        corrected_lag = (
            _require_int(
                row.get("callback_entry_receive_utc_ns"),
                "callback_entry_receive_utc_ns",
                minimum=1,
            )
            + offset
            - _require_int(
                row.get("source_event_utc_ns"),
                "source_event_utc_ns",
                minimum=1,
            )
        )
        if corrected_lag < 0:
            raise BBOChangeContractError("economic replay corrected lag is negative")
        lags.append(corrected_lag)
    if len(lags) >= MINIMUM_CALIBRATION_SCORES:
        ordered = sorted(lags)
        rank = max(0, (99 * len(ordered) + 99) // 100 - 1)
        if ordered[rank] > MAX_SOURCE_RECEIVE_P99_NS:
            raise BBOChangeContractError("economic replay p99 lag exceeds 250ms")


def _require_raw_quote_semantics(
    rows: Iterable[Mapping[str, object]],
    bundle: Mapping[str, object],
) -> None:
    """Eagerly validate every raw QUOTE, including an unprocessed STOP suffix."""

    canonical_text_fields = (
        "collector_generation", "clock_epoch", "segment_id",
        "provider_delivery_semantics", "provider_update_id_semantics",
        "source_event_time_raw", "clock_sample_id", "clock_sync_state",
        "product", "exact_contract", "exchange", "official_trading_day",
        "session_family", "parse_status", "duplicate_status", "source_status",
    )
    for row in rows:
        if row.get("record_type") != "QUOTE":
            continue
        for name in canonical_text_fields:
            _freeze_text(row.get(name), name)
        _freeze_day(row.get("official_trading_day"), "official_trading_day")
        if row.get("parse_status") != _RAW_PARSE_STATUS:
            raise BBOChangeContractError("raw quote parse status is not frozen")
        if row.get("source_status") != _RAW_SOURCE_STATUS:
            raise BBOChangeContractError("raw quote source status is not frozen")
        if row.get("duplicate_status") not in {
            "NOT_CLASSIFIED", "PROVEN_ADJACENT_EXACT_DUPLICATE"
        }:
            raise BBOChangeContractError("raw quote duplicate status is invalid")
        provider_batch_id = row.get("provider_batch_id")
        if provider_batch_id is not None:
            _freeze_text(provider_batch_id, "provider_batch_id")
        provider_update_id = row.get("provider_update_id")
        if provider_update_id is not None:
            _freeze_text(provider_update_id, "provider_update_id")
        _require_int(row.get("within_batch_rank"), "within_batch_rank", minimum=1)
        status = _provider_status(bundle, row)
        if status == "PROVEN_UNIQUE" and provider_update_id is None:
            raise BBOChangeContractError("PROVEN_UNIQUE quote lacks provider id")
        _require_raw_quote_scalar_types(row)
        _raw_quote_to_observed(row)


def _require_complete_stream_preflight(
    rows: Sequence[Mapping[str, object]],
    bundle: Mapping[str, object],
) -> None:
    """Validate suffix lifecycle/provider facts before any economic state."""

    terminal_generations: set[str] = set()
    provider_ids: dict[tuple[str, str], str] = {}
    for row in rows:
        generation = _freeze_text(
            row.get("collector_generation"), "preflight collector_generation"
        )
        if generation in terminal_generations:
            raise BBOChangeContractError(
                "record exists after terminal generation control"
            )
        if row.get("record_type") == "CONTROL":
            if row.get("event_type") in _TERMINAL_GENERATION_CONTROL_EVENTS:
                terminal_generations.add(generation)
            continue
        status = _provider_status(bundle, row)
        explicit_marker = (
            row.get("duplicate_status")
            == "PROVEN_ADJACENT_EXACT_DUPLICATE"
        )
        raw_id = row.get("provider_update_id")
        if status != "PROVEN_UNIQUE":
            if explicit_marker:
                raise BBOChangeContractError(
                    "explicit duplicate requires PROVEN_UNIQUE provider semantics"
                )
            continue
        if not isinstance(raw_id, str) or not raw_id:
            raise BBOChangeContractError("PROVEN_UNIQUE quote lacks provider id")
        key = (
            f"{row.get('provider_delivery_semantics')}|"
            f"{row.get('provider_update_id_semantics')}",
            raw_id,
        )
        digest = _provider_payload_digest(row)
        prior = provider_ids.get(key)
        if prior is not None and prior != digest:
            raise BBOChangeContractError(
                "PROVEN_UNIQUE provider id has conflicting payload"
            )
        duplicate = prior == digest
        if explicit_marker and not duplicate:
            raise BBOChangeContractError(
                "explicit duplicate marker lacks exact prior payload"
            )
        provider_ids[key] = digest


def _coverage_quality_metrics(
    rows: Sequence[Mapping[str, object]],
    duplicate_record_hashes: set[str],
) -> dict[str, object]:
    """Recompute the frozen raw non-degeneracy denominators for one cell."""

    legal_count = 0
    crossed_or_locked_count = 0
    mirrored_size_count = 0
    state_changing_count = 0
    mid_change_count = 0
    bid_sizes: set[Decimal] = set()
    ask_sizes: set[Decimal] = set()
    previous: dict[
        tuple[str, str, str, str, str],
        tuple[Decimal, Decimal, Decimal, Decimal],
    ] = {}
    for row in rows:
        lane = (
            _require_text(row.get("collector_generation"), "quality generation"),
            _require_text(row.get("clock_epoch"), "quality clock_epoch"),
            _require_text(row.get("exact_contract"), "quality exact_contract"),
            _require_text(row.get("session_family"), "quality session_family"),
            _require_text(row.get("segment_id"), "quality segment_id"),
        )
        record_hash = _require_text(row.get("record_hash"), "quality record_hash")
        try:
            bid = _decimal(row.get("bid_price1_raw"), "quality bid")
            ask = _decimal(row.get("ask_price1_raw"), "quality ask")
        except BBOChangeContractError:
            if record_hash not in duplicate_record_hashes:
                previous.pop(lane, None)
            continue
        if bid > 0 and ask > 0 and bid >= ask:
            crossed_or_locked_count += 1
        if record_hash in duplicate_record_hashes:
            continue
        try:
            bid_size = _decimal(row.get("bid_size1_raw"), "quality bid_size")
            ask_size = _decimal(row.get("ask_size1_raw"), "quality ask_size")
        except BBOChangeContractError:
            previous.pop(lane, None)
            continue
        legal = (
            row.get("parse_status") == _RAW_PARSE_STATUS
            and row.get("source_status") == _RAW_SOURCE_STATUS
            and bid > 0
            and ask > 0
            and bid_size > 0
            and ask_size > 0
            and bid < ask
        )
        if not legal:
            previous.pop(lane, None)
            continue
        legal_count += 1
        bid_sizes.add(bid_size)
        ask_sizes.add(ask_size)
        if bid_size == ask_size:
            mirrored_size_count += 1
        current = (bid, bid_size, ask, ask_size)
        prior = previous.get(lane)
        if prior is not None:
            if current != prior:
                state_changing_count += 1
            if bid + ask != prior[0] + prior[2]:
                mid_change_count += 1
        previous[lane] = current

    denominator = len(rows)

    def ratio_text(numerator: int, divisor: int) -> str:
        if divisor == 0:
            return "0"
        with localcontext() as context:
            context.prec = 50
            return format(Decimal(numerator) / Decimal(divisor), "f")

    quality_gate = (
        denominator > 0
        and legal_count * 100 >= denominator * 99
        and len(bid_sizes) >= 20
        and len(ask_sizes) >= 20
        and mirrored_size_count * 100 <= legal_count * 95
        and crossed_or_locked_count * 1000 <= denominator
        and state_changing_count >= 5000
        and mid_change_count >= 500
    )
    return {
        "legal_bbo_count": legal_count,
        "legal_bbo_rate": ratio_text(legal_count, denominator),
        "distinct_positive_bid_sizes": len(bid_sizes),
        "distinct_positive_ask_sizes": len(ask_sizes),
        "mirrored_size_count": mirrored_size_count,
        "mirrored_size_ratio": ratio_text(mirrored_size_count, legal_count),
        "crossed_or_locked_count": crossed_or_locked_count,
        "crossed_or_locked_rate": ratio_text(
            crossed_or_locked_count, denominator
        ),
        "state_changing_observation_count": state_changing_count,
        "mid_change_count": mid_change_count,
        "quality_gate_passed": quality_gate,
    }


def _attempt_trace(
    attempt: _ReplayAttempt,
    *,
    status: str,
    terminal_reason: str | None,
    terminal_boundary_kind: str,
    terminal_callback_seq: int | None,
    terminal_raw_record_hash: str | None,
) -> dict[str, object]:
    return {
        "attempt_id": attempt.attempt_id,
        "signal_id": attempt.signal_id,
        "run_id": attempt.run_id,
        "collector_generation": attempt.collector_generation,
        "clock_epoch": attempt.clock_epoch,
        "segment_id": attempt.segment_id,
        "session_family": attempt.session_family,
        "official_day": attempt.official_day.isoformat(),
        "exact_contract": attempt.exact_contract,
        "scenario_id": attempt.scenario_id,
        "direction": attempt.direction,
        "signal_raw_record_hash": attempt.signal_raw_record_hash,
        "entry_raw_record_hash": attempt.entry_raw_record_hash,
        "exit_raw_record_hash": attempt.exit_raw_record_hash,
        "entry_cutoff_receive_monotonic_ns": attempt.entry_cutoff_receive_monotonic_ns,
        "horizon_active_time_ns": attempt.horizon_active_time_ns,
        "exit_cutoff_receive_monotonic_ns": attempt.exit_cutoff_receive_monotonic_ns,
        "grace_active_time_ns": (
            attempt.horizon_active_time_ns + 5_000_000_000
            if attempt.horizon_active_time_ns is not None else None
        ),
        "status": status,
        "terminal_reason": terminal_reason,
        "terminal_boundary_kind": terminal_boundary_kind,
        "terminal_callback_seq": terminal_callback_seq,
        "terminal_raw_record_hash": terminal_raw_record_hash,
        "terminal_position_lots": (
            1 if status == "UNPRICED_TERMINAL" and attempt.direction == _LONG
            else -1 if status == "UNPRICED_TERMINAL"
            else 0
        ),
    }


def replay_multi_signal_raw_v1(
    stream: VerifiedCustodyStream,
    freeze_bundle: Mapping[str, object],
    *,
    expected_root_pins: CustodyRootPins,
    trusted_head_partition_hash: str,
    trusted_head_seal_id: str,
    trusted_freeze_sha256: str,
) -> MultiSignalReplayResult:
    """Recompute feature, admission and accounting from anchored raw custody.

    No output from a prior producer is accepted as an input.  A failure of any
    raw, freeze, provider-semantics, or PIT binding prerequisite raises before
    an economic result is emitted.
    """

    from scripts import collector_ordered_l1_bbo_change_accounting_v1 as accounting

    if not isinstance(stream, VerifiedCustodyStream) or not stream.rows:
        raise BBOChangeContractError("replay requires a non-empty verified sealed stream")
    _reverify_stream_for_replay(
        stream,
        expected_root_pins=expected_root_pins,
        trusted_head_partition_hash=trusted_head_partition_hash,
        trusted_head_seal_id=trusted_head_seal_id,
    )
    bundle = _require_freeze_bundle(freeze_bundle, trusted_freeze_sha256)
    thresholds = _freeze_thresholds(bundle)
    terms, fees, markups = _freeze_bindings(bundle)
    frozen_coverage_plan = _freeze_coverage_plan(bundle)
    _freeze_provider_semantics(bundle)
    # The accounting module hard-validates these constants.  Requiring a
    # canonical freeze declaration prevents silently replaying another scenario.
    scenarios = bundle["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != 2:
        raise BBOChangeContractError("freeze must declare exactly PRIMARY and STRESS")
    scenario_specs = (accounting.PRIMARY, accounting.STRESS)
    expected_scenarios = {
        spec.scenario_id: _as_json(spec) for spec in scenario_specs
    }
    actual_scenarios = {
        item.get("scenario_id"): dict(item)
        for item in scenarios if isinstance(item, Mapping)
    }
    if actual_scenarios != expected_scenarios:
        raise BBOChangeContractError("freeze scenarios are not exact frozen constants")
    _require_raw_quote_semantics(stream.rows, bundle)
    _require_complete_stream_preflight(stream.rows, bundle)
    _require_replay_clock_quality(stream.rows)

    engine = BBOChangeEngine()
    admission_ledgers: dict[str, Any] = {}
    callback_trace: list[dict[str, object]] = []
    admitted_rows: list[object] = []
    admission_cells: dict[str, tuple[str, str, str, str]] = {}
    attempt_rows: list[dict[str, object]] = []
    trades: list[object] = []
    open_attempts: dict[tuple[str, str], _ReplayAttempt] = {}
    provider_ids: dict[tuple[str, str], str] = {}
    lane_last_active: dict[tuple[str, str, str, str, str], int] = {}
    lane_last_source: dict[tuple[str, str, str, str, str], int] = {}
    stopped = False
    expected_seq_by_generation: dict[str, int] = {}
    terminal_generation: set[str] = set()
    active_generation: str | None = None
    processed_record_hashes: set[str] = set()
    duplicate_record_hashes: set[str] = set()
    current_record_hash: str | None = None

    def transition(attempt: _ReplayAttempt, state: str, callback_seq: int) -> None:
        ledger = admission_ledgers.get(attempt.collector_generation)
        if ledger is None:
            raise BBOChangeContractError("attempt has no generation admission ledger")
        ledger.transition(
            attempt.scenario_id, attempt.exact_contract, state, callback_seq,
            attempt.attempt_id, run_id=attempt.run_id,
            collector_generation=attempt.collector_generation,
            clock_epoch=attempt.clock_epoch, segment_id=attempt.segment_id,
            official_day=attempt.official_day,
        )

    def finish_no_entry(
        attempt: _ReplayAttempt,
        callback_seq: int,
        reason: str,
        *,
        boundary_kind: str = "CALLBACK",
        boundary_callback_seq: int | None = None,
        boundary_raw_record_hash: str | None = None,
    ) -> None:
        transition(attempt, "IDLE", callback_seq)
        attempt_rows.append(_attempt_trace(
            attempt,
            status="FAILED_NO_ENTRY",
            terminal_reason=reason,
            terminal_boundary_kind=boundary_kind,
            terminal_callback_seq=(
                callback_seq if boundary_kind == "CALLBACK"
                else boundary_callback_seq
            ),
            terminal_raw_record_hash=(
                current_record_hash if boundary_kind == "CALLBACK"
                else boundary_raw_record_hash
            ),
        ))
        open_attempts.pop((attempt.scenario_id, attempt.exact_contract), None)

    def finish_unpriced(
        attempt: _ReplayAttempt,
        callback_seq: int,
        reason: str,
        *,
        boundary_kind: str = "CALLBACK",
        boundary_callback_seq: int | None = None,
        boundary_raw_record_hash: str | None = None,
    ) -> None:
        transition(attempt, "IDLE", callback_seq)
        attempt_rows.append(_attempt_trace(
            attempt,
            status="UNPRICED_TERMINAL",
            terminal_reason=reason,
            terminal_boundary_kind=boundary_kind,
            terminal_callback_seq=(
                callback_seq if boundary_kind == "CALLBACK"
                else boundary_callback_seq
            ),
            terminal_raw_record_hash=(
                current_record_hash if boundary_kind == "CALLBACK"
                else boundary_raw_record_hash
            ),
        ))
        open_attempts.pop((attempt.scenario_id, attempt.exact_contract), None)

    def finish_closed(
        attempt: _ReplayAttempt,
        quote: object,
        callback_seq: int,
        timeout: bool,
    ) -> bool:
        assert attempt.entry_quote is not None
        attempt = _ReplayAttempt(
            **{**attempt.__dict__, "exit_raw_record_hash": quote.raw_record_hash}
        )
        result = accounting.attempt_round_trip(
            attempt.attempt_id, attempt.exact_contract,
            accounting.frozen_scenario(attempt.scenario_id), attempt.direction,
            attempt.entry_quote, quote, terms, fees, markups,
        )
        if result.status != "CLOSED":
            transition(attempt, "IDLE", callback_seq)
            attempt_rows.append(_attempt_trace(
                attempt,
                status="UNPRICED_TERMINAL",
                terminal_reason=f"ACCOUNTING:{result.failure_reason}",
                terminal_boundary_kind="QUOTE",
                terminal_callback_seq=quote.collector_seq,
                terminal_raw_record_hash=quote.raw_record_hash,
            ))
            open_attempts.pop((attempt.scenario_id, attempt.exact_contract), None)
            return False
        transition(attempt, "IDLE", callback_seq)
        attempt_rows.append(_attempt_trace(
            attempt,
            status="CLOSED_TERMINAL_TIMEOUT" if timeout else "CLOSED_NORMAL",
            terminal_reason="EXIT_GRACE_EXCEEDED" if timeout else None,
            terminal_boundary_kind="QUOTE",
            terminal_callback_seq=quote.collector_seq,
            terminal_raw_record_hash=quote.raw_record_hash,
        ))
        trades.append(result)
        open_attempts.pop((attempt.scenario_id, attempt.exact_contract), None)
        return True

    for raw_value in stream.rows:
        row = dict(raw_value)
        generation = _require_text(row.get("collector_generation"), "collector_generation")
        seq = _require_int(row.get("collector_seq"), "collector_seq", minimum=1)
        current_record_hash = _require_text(row.get("record_hash"), "record_hash")
        expected = expected_seq_by_generation.setdefault(generation, 1)
        if seq != expected:
            raise BBOChangeContractError("verified stream generation sequence is not gapless")
        expected_seq_by_generation[generation] = expected + 1
        if generation in terminal_generation:
            raise BBOChangeContractError("records after terminal generation control are forbidden")
        actions: list[str] = []
        if active_generation is not None and generation != active_generation:
            old_callback_seq = expected_seq_by_generation[active_generation] - 1
            for attempt in tuple(open_attempts.values()):
                if attempt.collector_generation != active_generation:
                    continue
                if attempt.state == "ENTRY_PENDING":
                    finish_no_entry(
                        attempt, old_callback_seq, "COLLECTOR_GENERATION_CHANGE",
                        boundary_kind="COLLECTOR_GENERATION_CHANGE",
                        boundary_callback_seq=seq,
                        boundary_raw_record_hash=current_record_hash,
                    )
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                else:
                    finish_unpriced(
                        attempt, old_callback_seq, "COLLECTOR_GENERATION_CHANGE",
                        boundary_kind="COLLECTOR_GENERATION_CHANGE",
                        boundary_callback_seq=seq,
                        boundary_raw_record_hash=current_record_hash,
                    )
                    actions.append(f"UNPRICED:{attempt.attempt_id}")
                    stopped = True
                    break
            active_generation = generation
            if stopped:
                for attempt in tuple(open_attempts.values()):
                    if attempt.state == "ENTRY_PENDING":
                        finish_no_entry(
                            attempt, old_callback_seq,
                            "GLOBAL_STOP_AFTER_UNPRICED",
                            boundary_kind="COLLECTOR_GENERATION_CHANGE",
                            boundary_callback_seq=seq,
                            boundary_raw_record_hash=current_record_hash,
                        )
                        actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                    else:
                        finish_unpriced(
                            attempt, old_callback_seq,
                            "GLOBAL_STOP_AFTER_UNPRICED",
                            boundary_kind="COLLECTOR_GENERATION_CHANGE",
                            boundary_callback_seq=seq,
                            boundary_raw_record_hash=current_record_hash,
                        )
                        actions.append(f"UNPRICED:{attempt.attempt_id}")
                callback_trace.append({
                    "callback_seq": seq,
                    "raw_record_hash": row["record_hash"],
                    "record_type": row.get("record_type"),
                    "event_type": row.get("event_type"),
                    "feature_status": "TERMINAL_STOP",
                    "feature_reset_reason": "COLLECTOR_GENERATION_CHANGE",
                    "signal_ids": [],
                    "actions": actions,
                })
                break
        elif active_generation is None:
            active_generation = generation
        ledger = admission_ledgers.setdefault(
            generation, accounting.ScenarioAdmissionLedger()
        )
        if stopped:
            raise BBOChangeContractError("replay cannot continue after terminal unpriced exposure")
        record_type = row.get("record_type")
        if record_type == "CONTROL":
            scope = _require_text(row.get("scope"), "scope")
            lane_fields = (
                (row.get("exact_contract"), row.get("session_family"),
                 row.get("segment_id"), row.get("official_trading_day"))
                if scope == "EXACT_CONTRACT_SEGMENT" else (None, None, None, None)
            )
            control = CollectorControl(
                generation, _require_text(row.get("clock_epoch"), "clock_epoch"), seq,
                _require_int(row.get("callback_entry_receive_utc_ns"), "receive utc"),
                _require_int(row.get("callback_entry_receive_monotonic_ns"), "receive monotonic"),
                _require_text(row.get("event_type"), "event_type"), _require_text(row.get("reason"), "reason"),
                scope, *lane_fields,
            )
            _control_metadata(control)
            control_day = (
                _freeze_day(control.official_trading_day, "official_trading_day")
                if control.scope == "EXACT_CONTRACT_SEGMENT" else None
            )
            affected = [
                attempt for attempt in open_attempts.values()
                if control.scope == "GENERATION_GLOBAL" or (
                    attempt.exact_contract == control.exact_contract
                    and attempt.session_family == control.session_family
                    and attempt.segment_id == control.segment_id
                    and attempt.collector_generation == control.collector_generation
                    and attempt.clock_epoch == control.clock_epoch
                    and attempt.official_day == control_day
                )
            ]
            for attempt in tuple(affected):
                if attempt.state == "ENTRY_PENDING":
                    finish_no_entry(attempt, seq, "CONTROL_LANE_END")
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                else:
                    finish_unpriced(attempt, seq, "CONTROL_LANE_END")
                    actions.append(f"UNPRICED:{attempt.attempt_id}")
                    stopped = True
                    break
            if stopped:
                for attempt in tuple(open_attempts.values()):
                    if attempt.state == "ENTRY_PENDING":
                        finish_no_entry(
                            attempt, seq, "GLOBAL_STOP_AFTER_UNPRICED"
                        )
                        actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                    else:
                        finish_unpriced(
                            attempt, seq, "GLOBAL_STOP_AFTER_UNPRICED"
                        )
                        actions.append(f"UNPRICED:{attempt.attempt_id}")
            engine.process_control(control)
            if control.event_type in {"COLLECTOR_STOP", "BACKPRESSURE_ABORT", "SINK_FAILURE_ABORT"}:
                terminal_generation.add(generation)
            callback_trace.append({
                "callback_seq": seq, "raw_record_hash": row["record_hash"], "record_type": "CONTROL",
                "event_type": control.event_type, "feature_status": None, "feature_reset_reason": None,
                "signal_ids": [], "actions": actions or ["CONTROL"],
            })
            processed_record_hashes.add(_require_text(row.get("record_hash"), "record_hash"))
            if stopped:
                break
            continue
        if record_type != "QUOTE":
            raise BBOChangeContractError("verified stream has unsupported record type")
        status = _provider_status(bundle, row)
        raw_id = row.get("provider_update_id")
        if raw_id is not None and not isinstance(raw_id, str):
            raise BBOChangeContractError("raw provider id is invalid")
        explicit_marker = row.get("duplicate_status") == "PROVEN_ADJACENT_EXACT_DUPLICATE"
        duplicate = False
        if status == "PROVEN_UNIQUE":
            if not raw_id:
                raise BBOChangeContractError("PROVEN_UNIQUE quote lacks provider id")
            key = (f"{row.get('provider_delivery_semantics')}|{row.get('provider_update_id_semantics')}", raw_id)
            digest = _provider_payload_digest(row)
            prior = provider_ids.get(key)
            if prior is not None and prior != digest:
                raise BBOChangeContractError("PROVEN_UNIQUE provider id has conflicting payload")
            duplicate = prior == digest
            provider_ids[key] = digest
            if duplicate:
                duplicate_record_hashes.add(current_record_hash)
            if explicit_marker and not duplicate:
                raise BBOChangeContractError("explicit duplicate marker lacks exact prior payload")
        elif explicit_marker:
            raise BBOChangeContractError("explicit duplicate requires PROVEN_UNIQUE provider semantics")
        observed = _raw_quote_to_observed(row)
        lane = (
            observed.collector_generation,
            observed.clock_epoch,
            observed.exact_contract,
            observed.session_family,
            observed.segment_id,
        )
        prior_active = lane_last_active.get(lane)
        prior_source = lane_last_source.get(lane)
        qualified_observed = _qualified(observed)
        feature_break = (
            observed.reset_reason is not None
            or qualified_observed is None
            or (
                prior_active is not None
                and (
                    observed.active_time_ns < prior_active
                    or observed.active_time_ns - prior_active >= FEATURE_WINDOW_NS
                )
            )
            or (
                prior_source is not None
                and observed.source_event_ns < prior_source
            )
        )
        # These mirrors represent the feature engine's last accepted BBO, not
        # merely the last raw callback.  A proven nonadjacent duplicate advances
        # collector ordering but cannot roll back source/active high-water or
        # hide a long gap.  An invalid BBO clears the feature lane.
        if not duplicate:
            if qualified_observed is None:
                lane_last_active.pop(lane, None)
                lane_last_source.pop(lane, None)
            else:
                lane_last_active[lane] = observed.active_time_ns
                lane_last_source[lane] = observed.source_event_ns
        quote = _execution_quote(row, provider_update_id=raw_id)
        # A quote for the same exact contract that changes its bound lane/day
        # is a hard terminal boundary; an interleaved other contract is not.
        quote_day = _freeze_day(row.get("official_trading_day"), "official_trading_day")
        for attempt in tuple(open_attempts.values()):
            if attempt.exact_contract != observed.exact_contract:
                continue
            if (
                attempt.collector_generation != observed.collector_generation
                or attempt.clock_epoch != observed.clock_epoch
                or attempt.segment_id != observed.segment_id
                or attempt.session_family != observed.session_family
                or attempt.official_day != quote_day
            ):
                if attempt.state == "ENTRY_PENDING":
                    finish_no_entry(attempt, seq, "EXACT_CONTRACT_LANE_CHANGE")
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                else:
                    finish_unpriced(attempt, seq, "EXACT_CONTRACT_LANE_CHANGE")
                    actions.append(f"UNPRICED:{attempt.attempt_id}")
                    stopped = True
                    break
        if stopped:
            for attempt in tuple(open_attempts.values()):
                if attempt.state == "ENTRY_PENDING":
                    finish_no_entry(
                        attempt, seq, "GLOBAL_STOP_AFTER_UNPRICED"
                    )
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                else:
                    finish_unpriced(
                        attempt, seq, "GLOBAL_STOP_AFTER_UNPRICED"
                    )
                    actions.append(f"UNPRICED:{attempt.attempt_id}")
            callback_trace.append({
                "callback_seq": seq, "raw_record_hash": row["record_hash"],
                "record_type": "QUOTE", "event_type": None,
                "feature_status": "TERMINAL_STOP", "feature_reset_reason": None,
                "signal_ids": [], "actions": actions,
            })
            break
        # Existing positions get the callback before feature/reset/signal work.
        for scenario in scenario_specs:
            key = (scenario.scenario_id, observed.exact_contract)
            attempt = open_attempts.get(key)
            if attempt is None:
                continue
            same_lane = (
                attempt.collector_generation == observed.collector_generation
                and attempt.clock_epoch == observed.clock_epoch and attempt.segment_id == observed.segment_id
                and attempt.session_family == observed.session_family
                and attempt.official_day == quote_day
            )
            if not same_lane or duplicate:
                continue
            entry_side = "BUY" if attempt.direction == _LONG else "SELL"
            exit_side = "SELL" if attempt.direction == _LONG else "BUY"
            if attempt.state == "ENTRY_PENDING":
                if feature_break:
                    finish_no_entry(attempt, seq, "FEATURE_RESET")
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                elif quote is not None and quote.execution_usable(entry_side, scenario.min_side_size) and quote.receive_monotonic_ns >= attempt.entry_cutoff_receive_monotonic_ns:
                    attempt = _ReplayAttempt(**{
                        **attempt.__dict__,
                        "state": "OPEN",
                        "entry_quote": quote,
                        "entry_raw_record_hash": quote.raw_record_hash,
                        "horizon_active_time_ns": quote.active_time_ns + scenario.horizon_ns,
                        "last_source_event_utc_ns": quote.source_event_utc_ns,
                    })
                    transition(attempt, "OPEN", seq)
                    open_attempts[key] = attempt
                    actions.append(f"ENTRY_FILLED:{attempt.attempt_id}")
                continue
            if quote is None or not quote.qualified():
                continue
            if (
                attempt.last_source_event_utc_ns is not None
                and quote.source_event_utc_ns < attempt.last_source_event_utc_ns
            ):
                continue
            attempt = _ReplayAttempt(**{
                **attempt.__dict__,
                "last_source_event_utc_ns": quote.source_event_utc_ns,
            })
            open_attempts[key] = attempt
            grace = attempt.horizon_active_time_ns + scenario.exit_grace_ns
            if attempt.state == "OPEN":
                if quote.active_time_ns < attempt.horizon_active_time_ns:
                    continue
                if quote.active_time_ns > grace:
                    if not quote.execution_usable(
                        exit_side, scenario.min_side_size
                    ):
                        continue
                    if finish_closed(attempt, quote, seq, True):
                        actions.append(f"EXIT_TERMINAL:{attempt.attempt_id}")
                    else:
                        actions.append(f"UNPRICED:{attempt.attempt_id}")
                        stopped = True
                        break
                else:
                    attempt = _ReplayAttempt(**{**attempt.__dict__, "state": "EXIT_PENDING", "exit_cutoff_receive_monotonic_ns": quote.receive_monotonic_ns + scenario.exit_delay_ns})
                    transition(attempt, "EXIT_PENDING", seq)
                    open_attempts[key] = attempt
                    actions.append(f"EXIT_PENDING:{attempt.attempt_id}")
            elif attempt.state == "EXIT_PENDING":
                if not quote.execution_usable(exit_side, scenario.min_side_size):
                    continue
                if quote.active_time_ns > grace:
                    if finish_closed(attempt, quote, seq, True):
                        actions.append(f"EXIT_TERMINAL:{attempt.attempt_id}")
                    else:
                        actions.append(f"UNPRICED:{attempt.attempt_id}")
                        stopped = True
                        break
                elif quote.receive_monotonic_ns >= attempt.exit_cutoff_receive_monotonic_ns:
                    if finish_closed(attempt, quote, seq, False):
                        actions.append(f"EXIT_NORMAL:{attempt.attempt_id}")
                    else:
                        actions.append(f"UNPRICED:{attempt.attempt_id}")
                        stopped = True
                        break
        if stopped:
            for attempt in tuple(open_attempts.values()):
                if attempt.state == "ENTRY_PENDING":
                    finish_no_entry(
                        attempt, seq, "GLOBAL_STOP_AFTER_UNPRICED"
                    )
                    actions.append(f"FAILED_NO_ENTRY:{attempt.attempt_id}")
                else:
                    finish_unpriced(
                        attempt, seq, "GLOBAL_STOP_AFTER_UNPRICED"
                    )
                    actions.append(f"UNPRICED:{attempt.attempt_id}")
            callback_trace.append({
                "callback_seq": seq, "raw_record_hash": row["record_hash"], "record_type": "QUOTE",
                "event_type": None, "feature_status": "TERMINAL_STOP", "feature_reset_reason": None,
                "signal_ids": [], "actions": actions,
            })
            break
        if duplicate:
            engine.process_replay_duplicate(observed)
            callback_trace.append({
                "callback_seq": seq, "raw_record_hash": row["record_hash"], "record_type": "QUOTE",
                "event_type": None, "feature_status": "EXPLICIT_DUPLICATE_SKIPPED", "feature_reset_reason": None,
                "signal_ids": [], "actions": actions + ["DUPLICATE_SKIPPED"],
            })
            processed_record_hashes.add(_require_text(row.get("record_hash"), "record_hash"))
            continue
        feature = engine.process(observed)
        signal = signal_from_threshold(feature, thresholds)
        signal_ids: list[str] = []
        if signal is not None:
            signal_id = _signal_id(row, signal)
            signal_ids.append(signal_id)
            actions.append(f"SIGNAL:{signal_id}")
            reason = _eligibility_reason(bundle, row)
            day = _freeze_day(row.get("official_trading_day"), "official_trading_day")
            for scenario in scenario_specs:
                attempt_id = _attempt_id(signal_id, scenario.scenario_id)
                candidate = accounting.AdmissionCandidate(
                    _require_text(row.get("run_id"), "run_id"), observed.collector_generation,
                    observed.clock_epoch, observed.segment_id, day, observed.exact_contract,
                    scenario.scenario_id, signal.direction,
                    "ELIGIBLE" if reason is None else "INELIGIBLE", seq, signal_id, attempt_id,
                )
                admitted = ledger.admit(candidate)
                admitted_rows.append(admitted)
                admission_cells[candidate.proposed_trade_id] = (
                    candidate.exact_contract,
                    candidate.official_day.isoformat(),
                    observed.session_family,
                    candidate.segment_id,
                )
                if admitted.decision == "ADMITTED":
                    open_attempts[(scenario.scenario_id, observed.exact_contract)] = _ReplayAttempt(
                        attempt_id, signal_id, candidate.run_id, candidate.collector_generation,
                        candidate.clock_epoch, candidate.segment_id,
                        observed.session_family, candidate.official_day,
                        candidate.exact_contract, candidate.scenario_id, candidate.direction,
                        row["record_hash"], observed.receive_monotonic_ns + scenario.entry_delay_ns,
                    )
                    actions.append(f"ADMITTED:{attempt_id}:{scenario.scenario_id}")
                else:
                    actions.append(f"{admitted.decision}:{signal_id}:{scenario.scenario_id}")
        callback_trace.append({
            "callback_seq": seq, "raw_record_hash": row["record_hash"], "record_type": "QUOTE",
            "event_type": None, "feature_status": feature.status, "feature_reset_reason": feature.reset_reason,
            "signal_ids": signal_ids, "actions": actions,
        })
        processed_record_hashes.add(_require_text(row.get("record_hash"), "record_hash"))
    # A verified sealed end terminalizes each still-owned lane.  An open
    # exposure stops the entire replay; a merely pending entry is a no-entry.
    for attempt in tuple(open_attempts.values()):
        final_seq = expected_seq_by_generation[attempt.collector_generation] - 1
        if attempt.state == "ENTRY_PENDING":
            finish_no_entry(
                attempt,
                final_seq,
                "SEALED_STREAM_END",
                boundary_kind="SEALED_STREAM_END",
            )
        else:
            finish_unpriced(
                attempt,
                final_seq,
                "SEALED_STREAM_END",
                boundary_kind="SEALED_STREAM_END",
            )
            stopped = True
    admissions_json = [_as_json(item) for item in admitted_rows]
    trades_json = [_as_json(item) for item in trades]
    attempts_json = [_as_json(item) for item in attempt_rows]
    run_id = _require_text(stream.rows[0].get("run_id"), "coverage run_id")
    coverage: list[dict[str, object]] = []
    plans = frozen_coverage_plan
    plan_by_cell: dict[tuple[str, str, str, str], Mapping[str, object]] = {}
    for plan in plans:
        key = (
            _require_text(plan["exact_contract"], "coverage exact_contract"),
            _require_text(plan["official_day"], "coverage official_day"),
            _require_text(plan["session_family"], "coverage session_family"),
            _require_text(plan["segment_id"], "coverage segment_id"),
        )
        if key in plan_by_cell:
            raise BBOChangeContractError("duplicate frozen coverage cell")
        plan_by_cell[key] = plan
    quote_counts: dict[tuple[str, str, str, str], int] = defaultdict(int)
    quote_records: dict[
        tuple[str, str, str, str], list[tuple[str, int, str]]
    ] = defaultdict(list)
    quality_rows: dict[
        tuple[str, str, str, str], list[Mapping[str, object]]
    ] = defaultdict(list)
    segment_events: dict[
        tuple[str, str, str, str], list[tuple[str, str, int, str]]
    ] = defaultdict(list)
    generations: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    clock_epochs: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    global_events: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for row in stream.rows:
        item = dict(row)
        generation = _require_text(item.get("collector_generation"), "coverage generation")
        record_hash = _require_text(item.get("record_hash"), "coverage record_hash")
        callback_seq = _require_int(item.get("collector_seq"), "coverage seq", minimum=1)
        if item.get("record_type") == "QUOTE":
            cell = (
                _require_text(item.get("exact_contract"), "coverage contract"),
                _require_text(item.get("official_trading_day"), "coverage day"),
                _require_text(item.get("session_family"), "coverage session"),
                _require_text(item.get("segment_id"), "coverage segment"),
            )
            if cell in plan_by_cell:
                quote_counts[cell] += 1
                quote_records[cell].append((generation, callback_seq, record_hash))
                quality_rows[cell].append(item)
                generations[cell].add(generation)
                clock_epochs[cell].add(
                    _require_text(item.get("clock_epoch"), "coverage clock_epoch")
                )
        elif item.get("record_type") == "CONTROL":
            event = item.get("event_type")
            if item.get("scope") == "GENERATION_GLOBAL":
                global_events[generation].append(
                    (str(event), callback_seq, record_hash)
                )
            if item.get("scope") == "EXACT_CONTRACT_SEGMENT" and event in {
                "SESSION_SEGMENT_START", "SESSION_SEGMENT_END"
            }:
                cell = (
                    _require_text(item.get("exact_contract"), "coverage contract"),
                    _require_text(item.get("official_trading_day"), "coverage day"),
                    _require_text(item.get("session_family"), "coverage session"),
                    _require_text(item.get("segment_id"), "coverage segment"),
                )
                if cell in plan_by_cell:
                    segment_events[cell].append(
                        (str(event), generation, callback_seq, record_hash)
                    )
                    generations[cell].add(generation)
                    clock_epochs[cell].add(
                        _require_text(
                            item.get("clock_epoch"), "coverage clock_epoch"
                        )
                    )
    for cell in sorted(plan_by_cell):
        contract, official_day, session_family, segment_id = cell
        events = segment_events[cell]
        starts = [seq for event, _, seq, _ in events if event == "SESSION_SEGMENT_START"]
        ends = [seq for event, _, seq, _ in events if event == "SESSION_SEGMENT_END"]
        generation_values = generations[cell]
        generation = next(iter(generation_values)) if len(generation_values) == 1 else None
        epoch_values = clock_epochs[cell]
        clock_epoch = next(iter(epoch_values)) if len(epoch_values) == 1 else None
        items = [
            item for item in attempts_json
            if isinstance(item, dict)
            and item["exact_contract"] == contract
            and item["official_day"] == official_day
            and item["session_family"] == session_family
            and item["segment_id"] == segment_id
        ]
        admissions_for_cell = [
            item for item in admissions_json
            if isinstance(item, dict)
            and admission_cells.get(item["proposed_trade_id"]) == cell
        ]
        item_ids = {item["attempt_id"] for item in items}
        matching_trades = [
            trade for trade in trades_json
            if isinstance(trade, dict) and trade.get("attempt_id") in item_ids
        ]
        plan_sha256 = _sha256(_canonical_json_bytes(dict(plan_by_cell[cell])))
        closure_ok = (
            len(starts) == 1 and len(ends) == 1 and starts[0] < ends[0]
            and generation is not None and clock_epoch is not None
        )
        quotes_bounded = (
            closure_ok
            and all(
                quote_generation == generation and starts[0] < quote_seq < ends[0]
                for quote_generation, quote_seq, _ in quote_records[cell]
            )
        )
        cell_record_hashes = [record_hash for _, _, _, record_hash in events]
        cell_record_hashes.extend(
            record_hash for _, _, record_hash in quote_records[cell]
        )
        replay_complete = (
            closure_ok
            and all(
                record_hash in processed_record_hashes
                for record_hash in cell_record_hashes
            )
        )
        quality_metrics = _coverage_quality_metrics(
            quality_rows[cell], duplicate_record_hashes
        )
        plan = plan_by_cell[cell]
        plan_start = _require_int(
            plan["start_utc_ns"], "coverage start_utc_ns", minimum=1
        )
        plan_end = _require_int(
            plan["end_utc_ns"], "coverage end_utc_ns", minimum=1
        )
        days_to_ltd = _require_int(
            plan["days_to_ltd"], "coverage days_to_ltd", minimum=0
        )
        coverage_plan_ok = plan["eligible"] is True and days_to_ltd > 10
        threshold_gate_ok = (contract, session_family) in thresholds
        official_day_value = _freeze_day(official_day, "coverage official_day")

        def binding_matches_cell(binding: object, offset: str | None) -> bool:
            return (
                getattr(binding, "exact_contract", None) == contract
                and getattr(binding, "official_day", None) == official_day_value
                and (
                    offset is None
                    or getattr(binding, "offset", None) == offset
                )
            )

        def exact_nonoverlapping_binding(
            bindings: Iterable[object], offset: str | None = None
        ) -> bool:
            overlapping = [
                binding
                for binding in bindings
                if binding_matches_cell(binding, offset)
                and getattr(binding, "valid_from_utc_ns", plan_end) < plan_end
                and getattr(binding, "valid_until_utc_ns", plan_start) > plan_start
            ]
            return (
                len(overlapping) == 1
                and getattr(overlapping[0], "valid_from_utc_ns", plan_start + 1)
                <= plan_start
                and getattr(overlapping[0], "valid_until_utc_ns", plan_end - 1)
                >= plan_end
            )

        accounting_binding_ok = exact_nonoverlapping_binding(terms) and all(
            exact_nonoverlapping_binding(fees, offset)
            and exact_nonoverlapping_binding(markups, offset)
            for offset in ("OPEN", "CLOSE_TODAY", "CLOSE_YESTERDAY")
        )
        provider_semantics_ok = bool(quality_rows[cell]) and all(
            _provider_status(bundle, row)
            in {"PROVEN_NO_USABLE_ID", "PROVEN_UNIQUE"}
            for row in quality_rows[cell]
        )
        quote_receive_times = [
            _require_int(
                row.get("callback_entry_receive_utc_ns"),
                "coverage quote receive UTC",
                minimum=1,
            )
            for row in quality_rows[cell]
        ]
        quote_interval_ok = all(
            plan_start <= receive_utc_ns < plan_end
            for receive_utc_ns in quote_receive_times
        )
        entry_window_ok = any(
            plan_start <= receive_utc_ns < plan_end
            and plan_end - receive_utc_ns >= 60_000_000_000
            for receive_utc_ns in quote_receive_times
        )
        lifecycle_ok = False
        if generation is not None:
            lifecycle = global_events[generation]
            starts_global = [
                seq for event, seq, _ in lifecycle if event == "COLLECTOR_START"
            ]
            stops_global = [
                seq for event, seq, _ in lifecycle if event == "COLLECTOR_STOP"
            ]
            lifecycle_ok = len(starts_global) == len(stops_global) == 1
            if lifecycle_ok and len(starts) == 1 and len(ends) == 1:
                disruptive_inside_segment = any(
                    starts[0] < event_seq < ends[0]
                    and event in {
                        "DISCONNECT", "RECONNECT", "CLOCK_EPOCH_CHANGE",
                        "BACKPRESSURE_ABORT", "SINK_FAILURE_ABORT",
                    }
                    for event, event_seq, _ in lifecycle
                )
                lifecycle_ok = (
                    starts_global[0] < starts[0] < ends[0] < stops_global[0]
                    and not disruptive_inside_segment
                    and quotes_bounded
                )
        for scenario in scenario_specs:
            scenario_items = [item for item in items if item["scenario_id"] == scenario.scenario_id]
            scenario_admissions = [item for item in admissions_for_cell if item["scenario_id"] == scenario.scenario_id]
            scenario_terminal_counts = defaultdict(int)
            for item in scenario_items:
                scenario_terminal_counts[str(item["status"])] += 1
            scenario_attempt_hash = _sha256(_canonical_json_bytes({"attempts": scenario_items}))
            scenario_attempt_ids = [item["attempt_id"] for item in scenario_items]
            scenario_trades = [
                trade for trade in matching_trades
                if trade.get("attempt_id") in set(scenario_attempt_ids)
            ]
            scenario_trade_hash = _sha256(
                _canonical_json_bytes({"trades": scenario_trades})
            )
            resolved = len(scenario_items)
            admitted_ids = [
                item["accepted_trade_id"]
                for item in scenario_admissions
                if item["decision"] == "ADMITTED"
            ]
            admitted_count = len(admitted_ids)
            closed_ids = [
                item["attempt_id"] for item in scenario_items
                if item["status"] in {
                    "CLOSED_NORMAL", "CLOSED_TERMINAL_TIMEOUT"
                }
            ]
            trade_ids = [trade["attempt_id"] for trade in scenario_trades]
            all_resolved = (
                len(set(admitted_ids)) == len(admitted_ids)
                and len(set(scenario_attempt_ids)) == len(scenario_attempt_ids)
                and set(admitted_ids) == set(scenario_attempt_ids)
                and len(set(trade_ids)) == len(trade_ids)
                and set(closed_ids) == set(trade_ids)
            )
            scenario_all_priced = all(
                item["status"] in {"CLOSED_NORMAL", "CLOSED_TERMINAL_TIMEOUT", "FAILED_NO_ENTRY"}
                for item in scenario_items
            )
            scenario_data_gate = replay_complete and lifecycle_ok and bool(
                quality_metrics["quality_gate_passed"]
            ) and coverage_plan_ok and threshold_gate_ok and accounting_binding_ok and provider_semantics_ok and quote_interval_ok and entry_window_ok and all_resolved and all(
                item["status"] in {"CLOSED_NORMAL", "FAILED_NO_ENTRY"}
                for item in scenario_items
            )
            coverage.append({
                "run_id": run_id or "", "collector_generation": generation,
                "exact_contract": contract, "official_day": official_day,
                "session_family": session_family, "segment_id": segment_id,
                "scenario_id": scenario.scenario_id,
                "raw_segment_started": len(starts) == 1,
                "raw_segment_ended": len(ends) == 1,
                "raw_quote_count": quote_counts[cell],
                "replay_complete": replay_complete,
                "lifecycle_gate_passed": lifecycle_ok,
                "clock_epoch_gate_passed": clock_epoch is not None,
                "coverage_plan_gate_passed": coverage_plan_ok,
                "threshold_gate_passed": threshold_gate_ok,
                "accounting_binding_gate_passed": accounting_binding_ok,
                "provider_semantics_gate_passed": provider_semantics_ok,
                "quote_interval_gate_passed": quote_interval_ok,
                "entry_window_gate_passed": entry_window_ok,
                **quality_metrics,
                "admitted_count": admitted_count,
                "suppressed_count": sum(item["decision"] == "SUPPRESSED" for item in scenario_admissions),
                "ineligible_count": sum(item["decision"] == "INELIGIBLE" for item in scenario_admissions),
                "terminal_counts": dict(sorted(scenario_terminal_counts.items())),
                "resolved_attempt_count": resolved,
                "all_attempts_resolved": all_resolved,
                "terminal_partition_hash": stream.terminal_partition_hash,
                "terminal_seal_id": stream.terminal_seal_id,
                "coverage_plan_sha256": plan_sha256,
                "attempt_sha256": scenario_attempt_hash, "trade_sha256": scenario_trade_hash,
                "all_attempts_priced": scenario_all_priced,
                "data_gate_passed": scenario_data_gate,
            })
    return MultiSignalReplayResult({
        "schema_version": _REPLAY_SCHEMA_VERSION,
        "callback_trace": callback_trace,
        "admissions": admissions_json,
        "attempts": attempts_json,
        "trades": trades_json,
        "coverage": coverage,
        "daily": [],
        "best3": [],
    })
