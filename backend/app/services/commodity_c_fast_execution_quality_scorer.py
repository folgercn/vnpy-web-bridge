from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Mapping, Sequence

from app.schemas.commodity_c_fast_execution_policy import (
    CFastExecutionQualityCollectionPolicyV2DTO,
)
from app.schemas.commodity_c_fast_execution_quality import (
    CFastVirtualIntentDTO,
)
from app.schemas.commodity_c_fast_execution_quality_score import (
    BookQualityState,
    CFastBookWalkMetricsDTO,
    CFastExecutionQualityContractSpecDTO,
    CFastExecutionQualityHorizonDTO,
    CFastExecutionQualityScoreDTO,
    CFastL1L5BookSnapshotDTO,
    CFastPassiveFillBoundsDTO,
    CFastSelectedBookTickDTO,
)
from app.services.commodity_c_fast_shadow_common import sha256_json


MAX_BOOK_SNAPSHOTS_PER_SCORE = 10_000
MAX_VIRTUAL_INTENT_LOTS = 100
QUALITY_STATES: tuple[BookQualityState, ...] = (
    "UNUSABLE_CLOCK_ORDER_INVALID",
    "UNUSABLE_STALE_NO_PRICE_OR_FILL_METRICS",
    "UNUSABLE_CROSSED_BOOK",
    "DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS",
    "UNUSABLE_NO_EXECUTION_METRICS",
    "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO",
    "L5_USABLE",
)
ELIGIBLE_QUALITY_STATES = frozenset(
    {
        "DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS",
        "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO",
        "L5_USABLE",
    }
)
HORIZONS_MS = (250, 1_000, 5_000, 30_000, 60_000)


class CFastExecutionQualityScorerError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _ClassifiedTick:
    snapshot: CFastL1L5BookSnapshotDTO
    quality_state: BookQualityState
    bid_ticks: tuple[int | None, ...]
    ask_ticks: tuple[int | None, ...]


def execution_quality_contract_spec_hash(
    spec: CFastExecutionQualityContractSpecDTO,
) -> str:
    return sha256_json(
        spec.model_dump(mode="json", exclude={"contract_spec_hash"})
    )


def l1_l5_book_snapshot_hash(
    snapshot: CFastL1L5BookSnapshotDTO,
) -> str:
    return sha256_json(
        snapshot.model_dump(mode="json", exclude={"book_snapshot_hash"})
    )


def execution_quality_score_hash(
    score: CFastExecutionQualityScoreDTO,
) -> str:
    return sha256_json(score.model_dump(mode="json", exclude={"score_hash"}))


def score_execution_quality(
    *,
    intent: CFastVirtualIntentDTO,
    durably_created_at_utc: datetime,
    policy: CFastExecutionQualityCollectionPolicyV2DTO,
    policy_hash: str,
    contract_spec: CFastExecutionQualityContractSpecDTO,
    snapshots: Sequence[CFastL1L5BookSnapshotDTO],
) -> CFastExecutionQualityScoreDTO:
    """Score one virtual intent without any runtime or execution capability."""

    _verify_inputs(
        intent=intent,
        durably_created_at_utc=durably_created_at_utc,
        policy=policy,
        policy_hash=policy_hash,
        contract_spec=contract_spec,
        snapshots=snapshots,
    )
    canonical, duplicate_count = _canonicalize_snapshots(snapshots)
    tick_size = Decimal(contract_spec.price_tick)
    classified = tuple(
        _classify_snapshot(row, tick_size=tick_size) for row in canonical
    )
    quality_counts = Counter(row.quality_state for row in classified)
    eligible = tuple(
        row for row in classified if _is_eligible(row)
    )
    decision = _select_tick(
        eligible,
        start=durably_created_at_utc,
        end=durably_created_at_utc
        + timedelta(milliseconds=policy.tick_selection.decision_max_lateness_ms),
    )

    decision_tick: CFastSelectedBookTickDTO | None = None
    decision_metrics: CFastBookWalkMetricsDTO | None = None
    if decision is not None:
        decision_tick = _selected_tick(decision)
        decision_metrics = _decision_metrics(
            decision,
            intent=intent,
            contract_spec=contract_spec,
        )

    horizons = tuple(
        _score_horizon(
            horizon_ms=horizon_ms,
            decision=decision,
            eligible=eligible,
            canonical=classified,
            anchor=durably_created_at_utc,
            intent=intent,
            contract_spec=contract_spec,
            maximum_lateness_ms=(
                policy.tick_selection.horizon_max_lateness_ms
            ),
        )
        for horizon_ms in HORIZONS_MS
    )
    input_hash = sha256_json(
        {
            "schema_version": (
                "commodity_c_fast_execution_quality_input_snapshot_set_v1"
            ),
            "book_snapshot_hashes": sorted(
                row.book_snapshot_hash for row in snapshots
            ),
        }
    )
    core: dict[str, Any] = {
        "schema_version": "commodity_c_fast_execution_quality_score_v1",
        "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
        "intent": intent.model_dump(mode="json"),
        "durably_created_at_utc": _utc_json(durably_created_at_utc),
        "policy_id": policy.policy_id,
        "policy_hash": policy_hash,
        "contract_spec": contract_spec.model_dump(mode="json"),
        "input_snapshot_count": len(snapshots),
        "canonical_snapshot_count": len(canonical),
        "duplicate_snapshot_count": duplicate_count,
        "input_snapshot_set_sha256": input_hash,
        "rejection_quality_counts": {
            state: quality_counts.get(state, 0) for state in QUALITY_STATES
        },
        "decision_selection_state": (
            "SELECTED_EARLIEST_ELIGIBLE"
            if decision is not None
            else "MISSING_DECISION_TICK_NOT_IMPUTED"
        ),
        "decision_tick": (
            decision_tick.model_dump(mode="json")
            if decision_tick is not None
            else None
        ),
        "decision_metrics": (
            decision_metrics.model_dump(mode="json")
            if decision_metrics is not None
            else None
        ),
        "horizons": [row.model_dump(mode="json") for row in horizons],
        "scoring_state": "PURE_RESEARCH_SCORE_AUTHORITY_ABSENT",
        "source_validation_scope": (
            "CALLER_MUST_REVERIFY_ACCEPTED_INTENT_SIGNED_POLICY_AND_CONTRACT_SPEC"
        ),
        "collection_authorized": False,
        "runtime_activation_authorized": False,
        "authority_granted": False,
        "dispatch_allowed": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "database_mutation_authorized": False,
        "deployment_mutation_authorized": False,
        "replacement_allowed": False,
        "production_allowed": False,
    }
    return CFastExecutionQualityScoreDTO.model_validate(
        {**core, "score_hash": sha256_json(core)}
    )


def reload_and_verify_execution_quality_score(
    payload: Mapping[str, Any],
    *,
    intent: CFastVirtualIntentDTO,
    durably_created_at_utc: datetime,
    policy: CFastExecutionQualityCollectionPolicyV2DTO,
    policy_hash: str,
    contract_spec: CFastExecutionQualityContractSpecDTO,
    snapshots: Sequence[CFastL1L5BookSnapshotDTO],
) -> CFastExecutionQualityScoreDTO:
    reloaded = CFastExecutionQualityScoreDTO.model_validate(payload)
    expected = score_execution_quality(
        intent=intent,
        durably_created_at_utc=durably_created_at_utc,
        policy=policy,
        policy_hash=policy_hash,
        contract_spec=contract_spec,
        snapshots=snapshots,
    )
    if (
        reloaded.score_hash != expected.score_hash
        or reloaded.model_dump(mode="json")
        != expected.model_dump(mode="json")
    ):
        raise CFastExecutionQualityScorerError(
            "SCORE_DERIVATION_MISMATCH"
        )
    return reloaded


def _verify_inputs(
    *,
    intent: CFastVirtualIntentDTO,
    durably_created_at_utc: datetime,
    policy: CFastExecutionQualityCollectionPolicyV2DTO,
    policy_hash: str,
    contract_spec: CFastExecutionQualityContractSpecDTO,
    snapshots: Sequence[CFastL1L5BookSnapshotDTO],
) -> None:
    if (
        durably_created_at_utc.tzinfo is None
        or durably_created_at_utc.utcoffset() is None
        or durably_created_at_utc.utcoffset().total_seconds() != 0
    ):
        raise CFastExecutionQualityScorerError(
            "DECISION_ANCHOR_MUST_USE_UTC"
        )
    if sha256_json(policy.model_dump(mode="json")) != policy_hash:
        raise CFastExecutionQualityScorerError("POLICY_HASH_MISMATCH")
    if tuple(policy.horizon_schedule_ms) != HORIZONS_MS:
        raise CFastExecutionQualityScorerError(
            "POLICY_HORIZON_SCHEDULE_MISMATCH"
        )
    if intent.policy_hash != policy.foundation_policy_hash:
        raise CFastExecutionQualityScorerError(
            "INTENT_FOUNDATION_POLICY_MISMATCH"
        )
    if intent.lots > MAX_VIRTUAL_INTENT_LOTS:
        raise CFastExecutionQualityScorerError(
            "VIRTUAL_INTENT_LOT_LIMIT"
        )
    if intent.exact_contract != contract_spec.exact_contract:
        raise CFastExecutionQualityScorerError("CONTRACT_SPEC_MISMATCH")
    if len(snapshots) > MAX_BOOK_SNAPSHOTS_PER_SCORE:
        raise CFastExecutionQualityScorerError(
            "BOOK_SNAPSHOT_RESOURCE_LIMIT"
        )
    if any(
        row.exact_contract != intent.exact_contract for row in snapshots
    ):
        raise CFastExecutionQualityScorerError("BOOK_CONTRACT_MISMATCH")


def _canonicalize_snapshots(
    snapshots: Sequence[CFastL1L5BookSnapshotDTO],
) -> tuple[tuple[CFastL1L5BookSnapshotDTO, ...], int]:
    ordered = sorted(
        snapshots,
        key=lambda row: (
            row.received_at_utc,
            row.exchange_timestamp,
            row.ingest_seq,
            row.ingest_id,
        ),
    )
    seen_ingest_ids: dict[str, str] = {}
    seen_exchange_events: dict[tuple[str, datetime, int], str] = {}
    canonical: list[CFastL1L5BookSnapshotDTO] = []
    for row in ordered:
        event_key = (
            row.exact_contract,
            row.exchange_timestamp,
            row.ingest_seq,
        )
        ingest_hash = row.book_snapshot_hash
        event_hash = sha256_json(
            row.model_dump(
                mode="json",
                exclude={"book_snapshot_hash", "ingest_id"},
            )
        )
        previous_hash = seen_ingest_ids.get(row.ingest_id)
        if (
            previous_hash is not None
            and previous_hash != ingest_hash
        ):
            raise CFastExecutionQualityScorerError(
                "BOOK_DUPLICATE_IDENTITY_CONFLICT"
            )
        previous_event_hash = seen_exchange_events.get(event_key)
        if (
            previous_event_hash is not None
            and previous_event_hash != event_hash
        ):
            raise CFastExecutionQualityScorerError(
                "BOOK_DUPLICATE_EVENT_CONFLICT"
            )
        is_duplicate = (
            previous_hash is not None or previous_event_hash is not None
        )
        seen_ingest_ids.setdefault(row.ingest_id, ingest_hash)
        seen_exchange_events.setdefault(event_key, event_hash)
        if is_duplicate:
            continue
        canonical.append(row)
    return tuple(canonical), len(snapshots) - len(canonical)


def _classify_snapshot(
    snapshot: CFastL1L5BookSnapshotDTO,
    *,
    tick_size: Decimal,
) -> _ClassifiedTick:
    bid_ticks = tuple(
        _integer_ticks(value, tick_size) for value in snapshot.bid_prices
    )
    ask_ticks = tuple(
        _integer_ticks(value, tick_size) for value in snapshot.ask_prices
    )
    age = snapshot.received_at_utc - snapshot.exchange_timestamp
    bid1 = (
        Decimal(snapshot.bid_prices[0])
        if snapshot.bid_prices[0] is not None
        else None
    )
    ask1 = (
        Decimal(snapshot.ask_prices[0])
        if snapshot.ask_prices[0] is not None
        else None
    )
    if age < timedelta(0):
        quality: BookQualityState = "UNUSABLE_CLOCK_ORDER_INVALID"
    elif age >= timedelta(milliseconds=2_000):
        quality = "UNUSABLE_STALE_NO_PRICE_OR_FILL_METRICS"
    elif bid1 is not None and ask1 is not None and bid1 > ask1:
        quality = "UNUSABLE_CROSSED_BOOK"
    elif bid1 is not None and ask1 is not None and bid1 == ask1:
        quality = "DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS"
    elif (
        bid_ticks[0] is None
        or ask_ticks[0] is None
        or bid_ticks[0] <= 0
        or ask_ticks[0] <= 0
        or snapshot.bid_sizes[0] is None
        or snapshot.ask_sizes[0] is None
        or snapshot.bid_sizes[0] <= 0
        or snapshot.ask_sizes[0] <= 0
    ):
        quality = "UNUSABLE_NO_EXECUTION_METRICS"
    elif _l5_is_usable(snapshot, bid_ticks=bid_ticks, ask_ticks=ask_ticks):
        quality = "L5_USABLE"
    else:
        quality = (
            "L1_ONLY_L1_COVERAGE_ALLOWED_NO_L5_BOOK_WALK_OR_L5_FILL_RATIO"
        )
    return _ClassifiedTick(
        snapshot=snapshot,
        quality_state=quality,
        bid_ticks=bid_ticks,
        ask_ticks=ask_ticks,
    )


def _integer_ticks(value: str | None, tick_size: Decimal) -> int | None:
    if value is None:
        return None
    price_coefficient, price_exponent = _decimal_components(
        Decimal(value)
    )
    tick_coefficient, tick_exponent = _decimal_components(tick_size)
    common_exponent = min(price_exponent, tick_exponent)
    scaled_price = price_coefficient * (
        10 ** (price_exponent - common_exponent)
    )
    scaled_tick = tick_coefficient * (
        10 ** (tick_exponent - common_exponent)
    )
    quotient, remainder = divmod(scaled_price, scaled_tick)
    if remainder:
        return None
    return quotient


def _decimal_components(value: Decimal) -> tuple[int, int]:
    parts = value.as_tuple()
    coefficient = 0
    for digit in parts.digits:
        coefficient = coefficient * 10 + digit
    if parts.sign:
        coefficient = -coefficient
    return coefficient, parts.exponent


def _l5_is_usable(
    snapshot: CFastL1L5BookSnapshotDTO,
    *,
    bid_ticks: tuple[int | None, ...],
    ask_ticks: tuple[int | None, ...],
) -> bool:
    if (
        any(value is None for value in bid_ticks + ask_ticks)
        or any(
            value is not None and value <= 0
            for value in bid_ticks + ask_ticks
        )
        or any(
            value is None or value <= 0
            for value in snapshot.bid_sizes + snapshot.ask_sizes
        )
    ):
        return False
    bids = tuple(value for value in bid_ticks if value is not None)
    asks = tuple(value for value in ask_ticks if value is not None)
    return all(
        left > right for left, right in zip(bids, bids[1:])
    ) and all(left < right for left, right in zip(asks, asks[1:]))


def _is_eligible(row: _ClassifiedTick) -> bool:
    return (
        row.quality_state in ELIGIBLE_QUALITY_STATES
        and row.bid_ticks[0] is not None
        and row.ask_ticks[0] is not None
        and row.bid_ticks[0] > 0
        and row.ask_ticks[0] > 0
        and row.snapshot.bid_sizes[0] is not None
        and row.snapshot.ask_sizes[0] is not None
        and row.snapshot.bid_sizes[0] > 0
        and row.snapshot.ask_sizes[0] > 0
    )


def _select_tick(
    rows: Sequence[_ClassifiedTick],
    *,
    start: datetime,
    end: datetime,
) -> _ClassifiedTick | None:
    return next(
        (
            row
            for row in rows
            if start <= row.snapshot.received_at_utc <= end
        ),
        None,
    )


def _selected_tick(row: _ClassifiedTick) -> CFastSelectedBookTickDTO:
    return CFastSelectedBookTickDTO(
        book_snapshot_hash=row.snapshot.book_snapshot_hash,
        received_at_utc=row.snapshot.received_at_utc,
        exchange_timestamp=row.snapshot.exchange_timestamp,
        ingest_seq=row.snapshot.ingest_seq,
        ingest_id=row.snapshot.ingest_id,
        quality_state=row.quality_state,
    )


def _decision_metrics(
    decision: _ClassifiedTick,
    *,
    intent: CFastVirtualIntentDTO,
    contract_spec: CFastExecutionQualityContractSpecDTO,
) -> CFastBookWalkMetricsDTO:
    if decision.quality_state == (
        "DEGRADED_MARKOUT_ONLY_NO_BOOK_WALK_OR_FILL_BOUNDS"
    ):
        return CFastBookWalkMetricsDTO(
            metric_mask_state="MARKOUT_ONLY_NO_DECISION_EXECUTION_METRICS",
            spread_ticks=None,
            spread_cny_per_lot=None,
            microprice_ticks=None,
            depth_imbalance=None,
            protected_price=None,
            l1_covered_lots=None,
            l1_coverage_ratio=None,
            l5_covered_lots=None,
            l5_coverage_ratio=None,
            l5_vwap_price=None,
            l5_adverse_ticks=None,
            l5_adverse_cny=None,
            l5_book_walk_state="UNAVAILABLE_QUALITY_MASK",
        )
    bid1_ticks = _required_int(decision.bid_ticks[0])
    ask1_ticks = _required_int(decision.ask_ticks[0])
    bid1_size = _required_int(decision.snapshot.bid_sizes[0])
    ask1_size = _required_int(decision.snapshot.ask_sizes[0])
    tick_size = Decimal(contract_spec.price_tick)
    spread_ticks = Decimal(ask1_ticks - bid1_ticks)
    depth_total = Decimal(bid1_size + ask1_size)
    microprice_ticks = (
        Decimal(ask1_ticks * bid1_size + bid1_ticks * ask1_size)
        / depth_total
    )
    imbalance = Decimal(bid1_size - ask1_size) / depth_total
    protected_ticks = (
        ask1_ticks + 1 if intent.direction == "buy" else bid1_ticks - 1
    )
    opposite_l1 = (
        ask1_size if intent.direction == "buy" else bid1_size
    )
    l1_covered = min(intent.lots, opposite_l1)
    common: dict[str, Any] = {
        "spread_ticks": _decimal_text(spread_ticks),
        "spread_cny_per_lot": _decimal_text(
            spread_ticks * tick_size * contract_spec.multiplier
        ),
        "protected_price": _decimal_text(
            Decimal(protected_ticks) * tick_size
        ),
        "l1_covered_lots": l1_covered,
        "l1_coverage_ratio": _decimal_text(
            Decimal(l1_covered) / Decimal(intent.lots)
        ),
    }
    if decision.quality_state != "L5_USABLE":
        return CFastBookWalkMetricsDTO(
            metric_mask_state="L1_METRICS_ONLY",
            **common,
            microprice_ticks=None,
            depth_imbalance=None,
            l5_covered_lots=None,
            l5_coverage_ratio=None,
            l5_vwap_price=None,
            l5_adverse_ticks=None,
            l5_adverse_cny=None,
            l5_book_walk_state="UNAVAILABLE_QUALITY_MASK",
        )

    price_ticks = (
        decision.ask_ticks
        if intent.direction == "buy"
        else decision.bid_ticks
    )
    sizes = (
        decision.snapshot.ask_sizes
        if intent.direction == "buy"
        else decision.snapshot.bid_sizes
    )
    remaining = intent.lots
    covered = 0
    price_tick_lot_sum = Decimal(0)
    for ticks, size in zip(price_ticks, sizes):
        available = _required_int(size)
        take = min(remaining, available)
        if take:
            covered += take
            remaining -= take
            price_tick_lot_sum += Decimal(_required_int(ticks) * take)
        if remaining == 0:
            break
    vwap_ticks = price_tick_lot_sum / Decimal(covered)
    best_ticks = ask1_ticks if intent.direction == "buy" else bid1_ticks
    adverse_ticks = (
        vwap_ticks - Decimal(best_ticks)
        if intent.direction == "buy"
        else Decimal(best_ticks) - vwap_ticks
    )
    return CFastBookWalkMetricsDTO(
        metric_mask_state="L5_METRICS",
        **common,
        microprice_ticks=_decimal_text(microprice_ticks),
        depth_imbalance=_decimal_text(imbalance),
        l5_covered_lots=covered,
        l5_coverage_ratio=_decimal_text(
            Decimal(covered) / Decimal(intent.lots)
        ),
        l5_vwap_price=_decimal_text(vwap_ticks * tick_size),
        l5_adverse_ticks=_decimal_text(adverse_ticks),
        l5_adverse_cny=_decimal_text(
            adverse_ticks
            * tick_size
            * contract_spec.multiplier
            * covered
        ),
        l5_book_walk_state=(
            "FULL_L5_COVERAGE"
            if covered == intent.lots
            else "PARTIAL_L5_DEPTH_INSUFFICIENT"
        ),
    )


def _score_horizon(
    *,
    horizon_ms: int,
    decision: _ClassifiedTick | None,
    eligible: Sequence[_ClassifiedTick],
    canonical: Sequence[_ClassifiedTick],
    anchor: datetime,
    intent: CFastVirtualIntentDTO,
    contract_spec: CFastExecutionQualityContractSpecDTO,
    maximum_lateness_ms: int,
) -> CFastExecutionQualityHorizonDTO:
    if decision is None:
        return CFastExecutionQualityHorizonDTO(
            horizon_ms=horizon_ms,
            selection_state="DECISION_TICK_MISSING",
            selected_tick=None,
            midpoint_markout_ticks=None,
            midpoint_markout_cny=None,
            passive_fill_bounds=_unidentified_fill(
                "UNIDENTIFIED_MISSING_HORIZON"
            ),
        )
    target = anchor + timedelta(milliseconds=horizon_ms)
    selected = _select_tick(
        eligible,
        start=target,
        end=target + timedelta(milliseconds=maximum_lateness_ms),
    )
    if selected is None:
        return CFastExecutionQualityHorizonDTO(
            horizon_ms=horizon_ms,
            selection_state="MISSING_HORIZON_NOT_IMPUTED",
            selected_tick=None,
            midpoint_markout_ticks=None,
            midpoint_markout_cny=None,
            passive_fill_bounds=_unidentified_fill(
                "UNIDENTIFIED_MISSING_HORIZON"
            ),
        )
    markout_ticks = _midpoint_markout_ticks(
        decision,
        selected,
        direction=intent.direction,
    )
    fill_bounds = _passive_fill_bounds(
        decision=decision,
        horizon=selected,
        canonical=canonical,
        intent=intent,
        contract_spec=contract_spec,
    )
    return CFastExecutionQualityHorizonDTO(
        horizon_ms=horizon_ms,
        selection_state="SELECTED_EARLIEST_ELIGIBLE",
        selected_tick=_selected_tick(selected),
        midpoint_markout_ticks=_decimal_text(markout_ticks),
        midpoint_markout_cny=_decimal_text(
            markout_ticks
            * Decimal(contract_spec.price_tick)
            * contract_spec.multiplier
            * intent.lots
        ),
        passive_fill_bounds=fill_bounds,
    )


def _midpoint_markout_ticks(
    decision: _ClassifiedTick,
    horizon: _ClassifiedTick,
    *,
    direction: str,
) -> Decimal:
    decision_mid = Decimal(
        _required_int(decision.bid_ticks[0])
        + _required_int(decision.ask_ticks[0])
    ) / Decimal(2)
    horizon_mid = Decimal(
        _required_int(horizon.bid_ticks[0])
        + _required_int(horizon.ask_ticks[0])
    ) / Decimal(2)
    sign = Decimal(1) if direction == "buy" else Decimal(-1)
    return sign * (horizon_mid - decision_mid)


def _passive_fill_bounds(
    *,
    decision: _ClassifiedTick,
    horizon: _ClassifiedTick,
    canonical: Sequence[_ClassifiedTick],
    intent: CFastVirtualIntentDTO,
    contract_spec: CFastExecutionQualityContractSpecDTO,
) -> CFastPassiveFillBoundsDTO:
    if (
        decision.quality_state != "L5_USABLE"
        or horizon.quality_state != "L5_USABLE"
    ):
        return _unidentified_fill(
            "UNIDENTIFIED_NO_PASSIVE_FILL_BOUNDS"
        )
    if contract_spec.volume_lots_per_raw_unit is None:
        return _unidentified_fill("UNIDENTIFIED_VOLUME_UNIT_BINDING")
    decision_index = _canonical_position(canonical, decision)
    horizon_index = _canonical_position(canonical, horizon)
    if horizon_index < decision_index:
        return _unidentified_fill(
            "UNIDENTIFIED_BOUNDS_NOT_ZERO_OR_FULL"
        )
    interval = [
        row.snapshot
        for row in canonical[decision_index : horizon_index + 1]
    ]
    if not interval or any(
        row.cumulative_volume is None for row in interval
    ):
        return _unidentified_fill(
            "UNIDENTIFIED_BOUNDS_NOT_ZERO_OR_FULL"
        )
    volumes = [
        Decimal(row.cumulative_volume or "0") for row in interval
    ]
    if any(
        current < previous
        for previous, current in zip(volumes, volumes[1:])
    ):
        return _unidentified_fill(
            "UNIDENTIFIED_BOUNDS_NOT_ZERO_OR_FULL"
        )
    raw_delta = volumes[-1] - volumes[0]
    volume_lots = raw_delta * Decimal(
        contract_spec.volume_lots_per_raw_unit
    )
    upper = min(Decimal(1), volume_lots / Decimal(intent.lots))
    return CFastPassiveFillBoundsDTO(
        state="IDENTIFIED_CONSERVATIVE_BOUNDS",
        lower_bound="0",
        upper_bound=_decimal_text(upper),
        price_conditioned_bound_state=(
            "UNIDENTIFIED_AGGREGATED_LAST_PRICE_CANNOT_PROVE_AGGRESSOR_"
            "DIRECTION_OR_AT_OR_THROUGH_VOLUME"
        ),
        point_probability_output="FORBIDDEN",
        calibrated_point_probability_allowed=False,
    )


def _unidentified_fill(state: str) -> CFastPassiveFillBoundsDTO:
    return CFastPassiveFillBoundsDTO(
        state=state,
        lower_bound=None,
        upper_bound=None,
        price_conditioned_bound_state=(
            "UNIDENTIFIED_AGGREGATED_LAST_PRICE_CANNOT_PROVE_AGGRESSOR_"
            "DIRECTION_OR_AT_OR_THROUGH_VOLUME"
        ),
        point_probability_output="FORBIDDEN",
        calibrated_point_probability_allowed=False,
    )


def _canonical_position(
    canonical: Sequence[_ClassifiedTick],
    selected: _ClassifiedTick,
) -> int:
    for index, row in enumerate(canonical):
        if row is selected:
            return index
    raise CFastExecutionQualityScorerError(
        "SELECTED_TICK_NOT_IN_CANONICAL_ORDER"
    )


def _required_int(value: int | None) -> int:
    if value is None:  # pragma: no cover - guarded by quality classification
        raise CFastExecutionQualityScorerError(
            "INTERNAL_REQUIRED_DEPTH_MISSING"
        )
    return value


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        raise CFastExecutionQualityScorerError(
            "NON_FINITE_METRIC_FORBIDDEN"
        )
    if value == 0:
        return "0"
    rendered = format(value.normalize(), "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _utc_json(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
