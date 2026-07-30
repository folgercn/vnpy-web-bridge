#!/usr/bin/env python3
"""Frozen market-only formulas for STATIC_CORE_EQUAL Research evidence.

This module deliberately contains only deterministic calculations.  It has no
filesystem, network, RPC, broker, gateway, order, position or signing
capability.  The producer pins this module's exact source SHA256 before using
it.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Mapping

import commodity_c_fast_pure_producer_kernel as cfast


D_CANDIDATE_ID = "D_DONCHIAN20_EXIT10_NEUTRAL"
D_ALGORITHM_ID = "DONCHIAN20_EXIT10_ROLL_SAFE_NEUTRAL_V1"
D_ENTRY_LOOKBACK = 20
D_EXIT_LOOKBACK = 10
CANDIDATE_WEIGHTS = {"C": 0.5, "D": 0.5}


@dataclass(frozen=True)
class CompositeAllocation:
    allocation: cfast.Allocation
    allocation_status: str
    nonzero_product_candidate_available: bool


def _ohlc(
    lookup: Mapping[tuple[str, str, str], Mapping[str, float]],
    *,
    product: str,
    official_day: str,
    exact_contract: str,
) -> Mapping[str, float]:
    key = (product, official_day, exact_contract)
    row = lookup.get(key)
    if row is None:
        raise cfast.ProducerKernelError(
            f"{product} {official_day} lacks old-main comparable OHLC"
        )
    return row


def build_d_signal(
    product_view: cfast.ProductSourceView,
    ohlc_lookup: Mapping[tuple[str, str, str], Mapping[str, float]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the exact previous-20 breakout / previous-10 exit state.

    The series is roll-jump-free.  On a PIT-main switch day the old main closes
    the interval and contributes that day's synthetic OHLC; the new main only
    resets the scale for the following official day.
    """

    product = product_view["product"]
    scale = 1.0
    previous_main: cfast.ContractObservation | None = None
    previous_close: float | None = None
    highs: list[float] = []
    lows: list[float] = []
    returns: list[float] = []
    state = 0
    state_rows: list[dict[str, Any]] = []

    for daily in product_view["daily"]:
        official_day = cfast._parse_date(
            daily["official_day"],
            "daily official_day",
        )
        main, ranked = cfast._pit_main(product, official_day, daily["contracts"])
        comparable_exact = (
            str(previous_main["exact_contract"])
            if previous_main is not None
            else str(main["exact_contract"])
        )
        raw_ohlc = _ohlc(
            ohlc_lookup,
            product=product,
            official_day=official_day.isoformat(),
            exact_contract=comparable_exact,
        )
        synthetic_open = float(raw_ohlc["open"]) * scale
        synthetic_high = float(raw_ohlc["high"]) * scale
        synthetic_low = float(raw_ohlc["low"]) * scale
        synthetic_close = float(raw_ohlc["settlement"]) * scale
        if not (
            0 < synthetic_low
            <= min(synthetic_open, synthetic_close)
            <= max(synthetic_open, synthetic_close)
            <= synthetic_high
        ):
            raise cfast.ProducerKernelError(
                f"{product} {official_day} synthetic OHLC is invalid"
            )

        daily_log_return: float | None = None
        if previous_close is not None:
            daily_log_return = math.log(synthetic_close / previous_close)
            if not math.isfinite(daily_log_return):
                raise cfast.ProducerKernelError(
                    f"{product} roll-safe Donchian return is not finite"
                )
            returns.append(daily_log_return)

        previous_state = state
        exit_event = "NONE"
        if state > 0 and len(lows) >= D_EXIT_LOOKBACK:
            exit_level = min(lows[-D_EXIT_LOOKBACK:])
            if synthetic_close < exit_level:
                state = 0
                exit_event = "LONG_EXIT_PREVIOUS_10_LOW"
        elif state < 0 and len(highs) >= D_EXIT_LOOKBACK:
            exit_level = max(highs[-D_EXIT_LOOKBACK:])
            if synthetic_close > exit_level:
                state = 0
                exit_event = "SHORT_EXIT_PREVIOUS_10_HIGH"

        entry_event = "NONE"
        previous_high20: float | None = None
        previous_low20: float | None = None
        if len(highs) >= D_ENTRY_LOOKBACK:
            previous_high20 = max(highs[-D_ENTRY_LOOKBACK:])
            previous_low20 = min(lows[-D_ENTRY_LOOKBACK:])
            if synthetic_close > previous_high20:
                state = 1
                entry_event = "LONG_ENTRY_PREVIOUS_20_HIGH"
            elif synthetic_close < previous_low20:
                state = -1
                entry_event = "SHORT_ENTRY_PREVIOUS_20_LOW"

        roll = (
            previous_main is not None
            and previous_main["exact_contract"] != main["exact_contract"]
        )
        state_rows.append(
            {
                "official_day": official_day.isoformat(),
                "pit_main_exact_contract": main["exact_contract"],
                "comparable_exact_contract": comparable_exact,
                "eligible_contract_count": len(ranked),
                "roll_anchor": roll,
                "synthetic_open": synthetic_open,
                "synthetic_high": synthetic_high,
                "synthetic_low": synthetic_low,
                "synthetic_settlement": synthetic_close,
                "daily_roll_safe_log_return": daily_log_return,
                "previous_high20": previous_high20,
                "previous_low20": previous_low20,
                "state_before": previous_state,
                "exit_event": exit_event,
                "entry_event": entry_event,
                "state_after": state,
            }
        )

        highs.append(synthetic_high)
        lows.append(synthetic_low)
        if roll:
            new_main_settlement = float(main["settlement"])
            if new_main_settlement <= 0:
                raise cfast.ProducerKernelError(
                    f"{product} roll anchor settlement is invalid"
                )
            scale = synthetic_close / new_main_settlement
        previous_main = main
        previous_close = synthetic_close

    if len(state_rows) < D_ENTRY_LOOKBACK + 1:
        raise cfast.ProducerKernelError(
            f"{product} Donchian20 warmup is incomplete"
        )
    if len(returns) < cfast.VOLATILITY_LOOKBACK:
        raise cfast.ProducerKernelError(f"{product} D vol60 warmup is incomplete")
    vol60 = (
        cfast._sample_std(returns[-cfast.VOLATILITY_LOOKBACK :])
        * math.sqrt(252.0)
    )
    if not math.isfinite(vol60) or vol60 <= 0:
        raise cfast.ProducerKernelError(
            f"{product} D vol60 must be positive before flooring"
        )

    raw_risk_score = state / max(vol60, cfast.VOLATILITY_FLOOR)
    signal = {
        "product": product,
        "candidate_id": D_CANDIDATE_ID,
        "algorithm_id": D_ALGORITHM_ID,
        "entry_lookback_official_days": D_ENTRY_LOOKBACK,
        "exit_lookback_official_days": D_EXIT_LOOKBACK,
        "state": state,
        "vol60_annualized": vol60,
        "vol60_return_count": cfast.VOLATILITY_LOOKBACK,
        "vol60_ddof": 1,
        "raw_risk_score": raw_risk_score,
        "pit_main_exact_contract": state_rows[-1]["pit_main_exact_contract"],
        "source_day_comparable_exact_contract": state_rows[-1][
            "comparable_exact_contract"
        ],
        "history_official_day_count": len(state_rows),
    }
    trace = {
        "product": product,
        "roll_event_count": sum(
            1 for row in state_rows if row["roll_anchor"]
        ),
        "roll_events": [
            {
                "official_day": row["official_day"],
                "old_comparable_exact_contract": row[
                    "comparable_exact_contract"
                ],
                "new_pit_main_exact_contract": row[
                    "pit_main_exact_contract"
                ],
            }
            for row in state_rows
            if row["roll_anchor"]
        ],
        "selected_pit_main_history_sha256": cfast._sha256(
            cfast.canonical_json(
                [
                    {
                        "official_day": row["official_day"],
                        "pit_main_exact_contract": row[
                            "pit_main_exact_contract"
                        ],
                        "comparable_exact_contract": row[
                            "comparable_exact_contract"
                        ],
                        "roll_anchor": row["roll_anchor"],
                    }
                    for row in state_rows
                ]
            )
        ),
        "synthetic_ohlc_state_history_sha256": cfast._sha256(
            cfast.canonical_json(state_rows)
        ),
        "source_day_state": state_rows[-1],
    }
    return signal, trace


def cap_and_balance_composite(
    raw: Mapping[str, float],
) -> dict[str, float]:
    """Apply frozen source caps without re-levering a netted C/D target."""

    if set(raw) != set(cfast.PRODUCTS) or any(
        not math.isfinite(float(value)) for value in raw.values()
    ):
        raise cfast.ProducerKernelError("composite source weights are incomplete")
    weights = {
        product: max(
            -cfast.SOURCE_LIMITS["product"],
            min(cfast.SOURCE_LIMITS["product"], float(raw[product])),
        )
        for product in cfast.PRODUCTS
    }
    for sector in sorted(set(cfast.SECTOR_MAP.values())):
        members = [
            product
            for product in cfast.PRODUCTS
            if cfast.SECTOR_MAP[product] == sector
        ]
        gross = math.fsum(abs(weights[product]) for product in members)
        if gross > cfast.SOURCE_LIMITS["sector"]:
            scale = cfast.SOURCE_LIMITS["sector"] / gross
            for product in members:
                weights[product] *= scale
    gross = math.fsum(abs(value) for value in weights.values())
    if gross > cfast.SOURCE_LIMITS["gross"]:
        scale = cfast.SOURCE_LIMITS["gross"] / gross
        weights = {
            product: value * scale for product, value in weights.items()
        }

    positive = math.fsum(max(value, 0.0) for value in weights.values())
    negative = math.fsum(max(-value, 0.0) for value in weights.values())
    if min(positive, negative) <= 1e-14:
        weights = {product: 0.0 for product in cfast.PRODUCTS}
    elif positive > negative:
        scale = negative / positive
        weights = {
            product: value * scale if value > 0 else value
            for product, value in weights.items()
        }
    elif negative > positive:
        scale = positive / negative
        weights = {
            product: value * scale if value < 0 else value
            for product, value in weights.items()
        }
    cfast._verify_weight_limits(weights, cfast.SOURCE_LIMITS, "composite source")
    return weights


def build_composite_source_target(
    c_weights: Mapping[str, float],
    d_weights: Mapping[str, float],
) -> tuple[dict[str, dict[str, float]], dict[str, float]]:
    if set(c_weights) != set(cfast.PRODUCTS) or set(d_weights) != set(
        cfast.PRODUCTS
    ):
        raise cfast.ProducerKernelError("C/D source sleeves are incomplete")
    contributions = {
        product: {
            "C": CANDIDATE_WEIGHTS["C"] * float(c_weights[product]),
            "D": CANDIDATE_WEIGHTS["D"] * float(d_weights[product]),
        }
        for product in cfast.PRODUCTS
    }
    raw = {
        product: math.fsum(contributions[product].values())
        for product in cfast.PRODUCTS
    }
    return contributions, cap_and_balance_composite(raw)


def allocate_with_safe_zero_status(
    target: dict[str, float],
    unit_weights: dict[str, float],
) -> CompositeAllocation:
    allocation = cfast._joint_integer_allocate(target, unit_weights)
    candidate_sets = {
        product: cfast._candidate_quantities(
            allocation.raw_quantities[product],
            target[product],
            unit_weights[product],
        )
        for product in cfast.PRODUCTS
    }
    nonzero_product_candidate_available = any(
        quantity != 0
        for candidates in candidate_sets.values()
        for quantity in candidates
    )
    target_nonzero = any(abs(value) > 1e-14 for value in target.values())
    allocation_nonzero = any(
        quantity != 0 for quantity in allocation.quantities.values()
    )
    if not target_nonzero:
        status = "ZERO_ECONOMIC_TARGET_SAFE_ZERO"
    elif allocation_nonzero:
        status = "NONZERO_INTEGER_TARGET_SELECTED"
    elif not nonzero_product_candidate_available:
        status = "NO_FEASIBLE_PRODUCT_NONZERO_SAFE_ZERO"
    else:
        status = "BEAM_OBJECTIVE_SELECTED_SAFE_ZERO"
    return CompositeAllocation(
        allocation=allocation,
        allocation_status=status,
        nonzero_product_candidate_available=(
            nonzero_product_candidate_available
        ),
    )
