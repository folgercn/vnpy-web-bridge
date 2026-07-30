#!/usr/bin/env python3
"""Lot-aware safe allocator for the two frozen C/D/R schedulers.

Research only.  The runner consumes the canonical signal-netting v1r1 target
and integer-capital-ladder v1 evidence, projects each monthly target through a
pre-registered safety buffer, then jointly selects integer exact-contract lots
with a deterministic finite-neighbourhood beam search.  Positions are not
re-optimized between monthly target dates: exact-contract rolls preserve lots,
and every holding day is monitored for exposure drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.entry_redesign.scripts.futures_lead import commodity_candidate_integer_capital_ladder_v1 as ladder
from research.entry_redesign.scripts.futures_lead import commodity_candidate_signal_netting_v1 as canonical


OUTROOT = PROJECT_ROOT / "research/entry_redesign/scripts/output"
DEFAULT_OUTPUT = OUTROOT / "commodity_candidate_lot_aware_safe_allocator_v1_20260717"
CANONICAL_DIR = OUTROOT / "commodity_candidate_signal_netting_v1r1_20260717"
CANONICAL_TARGETS = CANONICAL_DIR / "monthly_targets.csv"
LADDER_DIR = OUTROOT / "commodity_candidate_integer_capital_ladder_v1_20260717"
TEST_FILE = Path(__file__).with_name("tests") / "test_commodity_candidate_lot_aware_safe_allocator_v1.py"

PRODUCTS = canonical.PRODUCTS
SECTORS = canonical.SECTORS
COMBINATION_ARMS = canonical.COMBINATION_ARMS
WINDOWS = canonical.WINDOWS
CAPITAL_LADDER_CNY = (
    100_000,
    200_000,
    500_000,
    1_000_000,
    2_000_000,
    5_000_000,
    10_000_000,
    20_000_000,
)

# These values are pre-registered operational buffers, not fitted parameters.
BUFFER_LIMITS = {
    "product": 0.14,
    "sector": 0.30,
    "gross": 0.90,
    "target_net": 0.0,
}
HARD_LIMITS = {
    "product": 0.15,
    "sector": 0.35,
    "gross": 1.00,
    "abs_net": 0.10,
}
TICK_STRESS_PER_FILL_SIDE = 2.5
NEIGHBOURHOOD_RADIUS_LOTS = 2
BEAM_WIDTH = 2048
NET_ERROR_PENALTY = 1.0
STRICT_EPSILON = 1e-12

# Reused unchanged from the already frozen integer-ladder diagnostic.  The new
# compatibility gate additionally requires zero risk breaches through 2026-07-09.
USABILITY_GATES = dict(ladder.USABILITY_GATES)


@dataclass(frozen=True)
class Allocation:
    quantities: dict[str, int]
    raw_quantities: dict[str, float]
    realized_weights: dict[str, float]
    squared_target_error: float
    residual_net: float
    objective: float
    gross: float
    sector_gross: dict[str, float]
    states_retained: int
    feasible: bool


@dataclass(frozen=True)
class Simulation:
    daily: pd.DataFrame
    allocations: pd.DataFrame
    optimizer_events: pd.DataFrame


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _binding(path: Path) -> dict[str, object]:
    return {"path": _path(path), "bytes": path.stat().st_size, "sha256": _sha256(path)}


def _bound_output(manifest: dict, name: str) -> str:
    rows = [row for row in manifest.get("output_bindings", []) if Path(row["path"]).name == name]
    if len(rows) != 1:
        raise ValueError(f"OUTPUT_BINDING_NOT_UNIQUE:{name}")
    return str(rows[0]["sha256"])


def _strictly_below(value: float, cap: float) -> bool:
    if not np.isfinite(value) or not np.isfinite(cap) or cap <= 0:
        raise ValueError("INVALID_RISK_VALUE_OR_CAP")
    return bool(value < cap - STRICT_EPSILON)


def load_inputs() -> tuple[canonical.Inputs, pd.DataFrame]:
    ladder_manifest_path = LADDER_DIR / "manifest.json"
    ladder_manifest = json.loads(ladder_manifest_path.read_text(encoding="utf-8"))
    if ladder_manifest.get("status") != "PASS_FIXED_INTEGER_CAPITAL_LADDER_DIAGNOSTIC":
        raise ValueError("INTEGER_LADDER_NOT_PASS")
    for flag in (
        "network_used",
        "legacy_event_trade_position_label_pnl_ledger_read",
        "confirmatory",
        "tradable",
        "shadow_authorized",
        "testnet_authorized",
        "live_authorized",
        "production_authorized",
    ):
        if ladder_manifest.get(flag) is not False:
            raise ValueError(f"INTEGER_LADDER_AUTHORITY_BOUNDARY_FAILED:{flag}")
    for required in ("capital_ladder_summary.csv", "capital_tier_decision.csv", "report.md"):
        if _sha256(LADDER_DIR / required) != _bound_output(ladder_manifest, required):
            raise ValueError(f"INTEGER_LADDER_HASH_MISMATCH:{required}")

    inputs, targets = ladder.load_inputs()
    if set(targets["combination_arm"]) != set(COMBINATION_ARMS):
        raise ValueError("FROZEN_COMBINATION_ARMS_CHANGED")
    return inputs, targets


def buffer_one_target(source: dict[str, float]) -> dict[str, float]:
    """Shrink only: product, sector, gross, then exact zero-net balancing."""
    if set(source) != set(PRODUCTS) or not all(np.isfinite(list(source.values()))):
        raise ValueError("INVALID_SOURCE_TARGET")
    weights = {
        product: float(np.clip(source[product], -BUFFER_LIMITS["product"], BUFFER_LIMITS["product"]))
        for product in PRODUCTS
    }
    for sector in sorted(set(SECTORS.values())):
        members = [product for product in PRODUCTS if SECTORS[product] == sector]
        sector_gross = sum(abs(weights[product]) for product in members)
        if sector_gross > BUFFER_LIMITS["sector"]:
            scale = BUFFER_LIMITS["sector"] / sector_gross
            for product in members:
                weights[product] *= scale
    gross = sum(abs(value) for value in weights.values())
    if gross > BUFFER_LIMITS["gross"]:
        scale = BUFFER_LIMITS["gross"] / gross
        weights = {product: value * scale for product, value in weights.items()}

    positive = sum(max(value, 0.0) for value in weights.values())
    negative = sum(max(-value, 0.0) for value in weights.values())
    if min(positive, negative) <= 1e-14:
        weights = {product: 0.0 for product in PRODUCTS}
    elif positive > negative:
        scale = negative / positive
        weights = {product: value * scale if value > 0 else value for product, value in weights.items()}
    elif negative > positive:
        scale = positive / negative
        weights = {product: value * scale if value < 0 else value for product, value in weights.items()}

    if max(abs(value) for value in weights.values()) > BUFFER_LIMITS["product"] + 1e-12:
        raise ValueError("BUFFER_PRODUCT_CAP_FAILED")
    for sector in sorted(set(SECTORS.values())):
        sector_gross = sum(abs(weights[p]) for p in PRODUCTS if SECTORS[p] == sector)
        if sector_gross > BUFFER_LIMITS["sector"] + 1e-12:
            raise ValueError("BUFFER_SECTOR_CAP_FAILED")
    if sum(abs(value) for value in weights.values()) > BUFFER_LIMITS["gross"] + 1e-12:
        raise ValueError("BUFFER_GROSS_CAP_FAILED")
    if abs(sum(weights.values())) > 1e-10:
        raise ValueError("BUFFER_NET_ZERO_FAILED")
    return weights


def build_buffered_targets(targets: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for (day, arm), group in targets.groupby(["execution_day", "combination_arm"], sort=True):
        if group["product"].nunique() != len(PRODUCTS):
            raise ValueError("INCOMPLETE_SOURCE_TARGET")
        indexed = group.set_index("product")
        source = {product: float(indexed.loc[product, "target_weight"]) for product in PRODUCTS}
        buffered = buffer_one_target(source)
        for product in PRODUCTS:
            rows.append(
                {
                    "execution_day": pd.Timestamp(day),
                    "source_official_day": pd.Timestamp(indexed.loc[product, "source_official_day"]),
                    "combination_arm": arm,
                    "product": product,
                    "sector": SECTORS[product],
                    "source_target_weight": source[product],
                    "buffered_target_weight": buffered[product],
                    "buffer_delta": buffered[product] - source[product],
                }
            )
    out = pd.DataFrame(rows).sort_values(["execution_day", "combination_arm", "product"])
    grouped = out.groupby(["execution_day", "combination_arm"])
    if grouped["buffered_target_weight"].sum().abs().max() > 1e-10:
        raise ValueError("BUFFERED_TARGET_NOT_NEUTRAL")
    return out.reset_index(drop=True)


def _candidate_quantities(raw_quantity: float, target_weight: float, unit_weight: float) -> tuple[int, ...]:
    if not all(np.isfinite([raw_quantity, target_weight, unit_weight])) or unit_weight <= 0:
        raise ValueError("INVALID_ALLOCATION_INPUT")
    if abs(target_weight) <= 1e-14:
        return (0,)
    center = int(np.rint(raw_quantity))
    values = set(range(center - NEIGHBOURHOOD_RADIUS_LOTS, center + NEIGHBOURHOOD_RADIUS_LOTS + 1))
    values.update({0, int(np.trunc(raw_quantity)), math.floor(raw_quantity), math.ceil(raw_quantity)})
    if target_weight > 0:
        values = {quantity for quantity in values if quantity >= 0}
    else:
        values = {quantity for quantity in values if quantity <= 0}
    values = {
        int(quantity)
        for quantity in values
        if _strictly_below(abs(float(quantity) * unit_weight), HARD_LIMITS["product"])
    }
    values.add(0)
    return tuple(sorted(values))


def joint_integer_allocate(target: dict[str, float], unit_weights: dict[str, float]) -> Allocation:
    """Deterministic joint finite-neighbourhood optimization with hard caps."""
    if set(target) != set(PRODUCTS) or set(unit_weights) != set(PRODUCTS):
        raise ValueError("INCOMPLETE_ALLOCATION_INPUT")
    target_values = np.asarray(list(target.values()), dtype=float)
    unit_values = np.asarray(list(unit_weights.values()), dtype=float)
    if not np.isfinite(target_values).all() or not np.isfinite(unit_values).all() or not (unit_values > 0).all():
        raise ValueError("INVALID_ALLOCATION_INPUT")

    raw = {product: target[product] / unit_weights[product] for product in PRODUCTS}
    candidates = {
        product: _candidate_quantities(raw[product], target[product], unit_weights[product])
        for product in PRODUCTS
    }
    order = tuple(sorted(PRODUCTS, key=lambda product: (-unit_weights[product], product)))
    sector_names = tuple(sorted(set(SECTORS.values())))
    sector_index = {sector: index for index, sector in enumerate(sector_names)}

    option_weights = {
        product: tuple(quantity * unit_weights[product] for quantity in candidates[product])
        for product in PRODUCTS
    }
    suffix_min_net = [0.0] * (len(order) + 1)
    suffix_max_net = [0.0] * (len(order) + 1)
    suffix_min_sse = [0.0] * (len(order) + 1)
    for index in range(len(order) - 1, -1, -1):
        product = order[index]
        options = option_weights[product]
        suffix_min_net[index] = suffix_min_net[index + 1] + min(options)
        suffix_max_net[index] = suffix_max_net[index + 1] + max(options)
        suffix_min_sse[index] = suffix_min_sse[index + 1] + min(
            (weight - target[product]) ** 2 for weight in options
        )

    # State: (sse, net, gross, sector gross tuple, quantity tuple).
    states: list[tuple[float, float, float, tuple[float, ...], tuple[int, ...]]] = [
        (0.0, 0.0, 0.0, tuple(0.0 for _ in sector_names), tuple())
    ]
    for index, product in enumerate(order):
        expanded: list[tuple[float, tuple[float, float, float, tuple[float, ...], tuple[int, ...]]]] = []
        sidx = sector_index[SECTORS[product]]
        for sse, net, gross, sector_gross, quantities in states:
            for quantity in candidates[product]:
                weight = quantity * unit_weights[product]
                next_gross = gross + abs(weight)
                if not _strictly_below(next_gross, HARD_LIMITS["gross"]):
                    continue
                next_sector = list(sector_gross)
                next_sector[sidx] += abs(weight)
                if not _strictly_below(next_sector[sidx], HARD_LIMITS["sector"]):
                    continue
                next_net = net + weight
                next_sse = sse + (weight - target[product]) ** 2
                low = next_net + suffix_min_net[index + 1]
                high = next_net + suffix_max_net[index + 1]
                if low > 0:
                    minimum_abs_net = low
                elif high < 0:
                    minimum_abs_net = -high
                else:
                    minimum_abs_net = 0.0
                lower_bound = (
                    next_sse
                    + suffix_min_sse[index + 1]
                    + NET_ERROR_PENALTY * minimum_abs_net**2
                )
                state = (next_sse, next_net, next_gross, tuple(next_sector), quantities + (quantity,))
                expanded.append((lower_bound, state))
        if not expanded:
            break
        expanded.sort(key=lambda item: (item[0], item[1][0], abs(item[1][1]), item[1][4]))
        states = [item[1] for item in expanded[:BEAM_WIDTH]]

    feasible = [state for state in states if len(state[4]) == len(order) and _strictly_below(abs(state[1]), HARD_LIMITS["abs_net"])]
    if not feasible:
        # All-zero is always a fail-safe feasible portfolio.  Reaching this
        # branch means the finite beam failed to retain a feasible nonzero path.
        zero_quantities = {product: 0 for product in PRODUCTS}
        squared_error = sum(target[product] ** 2 for product in PRODUCTS)
        return Allocation(
            zero_quantities,
            raw,
            {product: 0.0 for product in PRODUCTS},
            squared_error,
            0.0,
            squared_error,
            0.0,
            {sector: 0.0 for sector in sector_names},
            len(states),
            True,
        )

    best = min(
        feasible,
        key=lambda state: (
            state[0] + NET_ERROR_PENALTY * state[1] ** 2,
            state[0],
            abs(state[1]),
            state[4],
        ),
    )
    sse, residual_net, gross, sector_tuple, quantity_tuple = best
    quantities = dict(zip(order, quantity_tuple))
    realized = {product: quantities[product] * unit_weights[product] for product in PRODUCTS}
    return Allocation(
        quantities,
        raw,
        realized,
        sse,
        residual_net,
        sse + NET_ERROR_PENALTY * residual_net**2,
        gross,
        dict(zip(sector_names, sector_tuple)),
        len(states),
        True,
    )


def _price(lookup: pd.DataFrame, day: pd.Timestamp, product: str, symbol: str, field: str) -> float:
    value = float(lookup.loc[(day, product, symbol), field])
    if not np.isfinite(value) or value <= 0:
        raise ValueError(f"INVALID_PRICE:{day}:{product}:{symbol}:{field}")
    return value


def simulate_one(
    inputs: canonical.Inputs,
    buffered_targets: pd.DataFrame,
    arm: str,
    initial_capital_cny: int,
) -> Simulation:
    if arm not in COMBINATION_ARMS or initial_capital_cny not in CAPITAL_LADDER_CNY:
        raise ValueError("UNSUPPORTED_ARM_OR_CAPITAL")
    arm_targets = buffered_targets[buffered_targets["combination_arm"].eq(arm)]
    target_map = {day: group.set_index("product") for day, group in arm_targets.groupby("execution_day")}
    lookup = inputs.contracts.set_index(["source_official_day", "product", "exact_contract"])[
        ["open", "settlement"]
    ]
    daily_main = inputs.features.set_index(["available_official_day", "product"])["main_symbol"].to_dict()
    spec = inputs.spec.set_index("code")
    multiplier = spec["multiplier"].astype(float).to_dict()
    tick_size = spec["tick_size"].astype(float).to_dict()
    days = [pd.Timestamp(day) for day in sorted(inputs.contracts["source_official_day"].unique())]
    scheduler_id = "STATIC_CORE_EQUAL" if arm == "CORE_EQUAL_TARGET" else "STATIC_CORE_PLUS_RESERVE"

    quantities = {product: 0 for product in PRODUCTS}
    symbols: dict[str, str | None] = {product: None for product in PRODUCTS}
    equity = float(initial_capital_cny)
    previous_day: pd.Timestamp | None = None
    active_target: dict[str, float] | None = None
    daily_rows: list[dict[str, object]] = []
    allocation_rows: list[dict[str, object]] = []
    optimizer_rows: list[dict[str, object]] = []

    for day in days:
        if day < min(target_map):
            previous_day = day
            continue
        target_frame = target_map.get(day)
        rebalance = target_frame is not None
        desired_symbols = {product: str(daily_main[(day, product)]) for product in PRODUCTS}
        equity_previous = equity
        overnight_pnl = 0.0
        if previous_day is not None:
            for product in PRODUCTS:
                old_symbol, old_quantity = symbols[product], quantities[product]
                if old_symbol is not None and old_quantity != 0:
                    overnight_pnl += old_quantity * multiplier[product] * (
                        _price(lookup, day, product, old_symbol, "open")
                        - _price(lookup, previous_day, product, old_symbol, "settlement")
                    )
        equity_open = equity_previous + overnight_pnl
        if equity_open <= 0:
            raise ValueError("NON_POSITIVE_EQUITY_OPEN")

        allocation: Allocation | None = None
        if rebalance:
            active_target = {
                product: float(target_frame.loc[product, "buffered_target_weight"])
                for product in PRODUCTS
            }
            unit_weights = {
                product: multiplier[product]
                * _price(lookup, day, product, desired_symbols[product], "open")
                / equity_open
                for product in PRODUCTS
            }
            allocation = joint_integer_allocate(active_target, unit_weights)
            desired_quantities = allocation.quantities
            optimizer_rows.append(
                {
                    "date": day,
                    "scheduler_id": scheduler_id,
                    "combination_arm": arm,
                    "initial_capital_cny": initial_capital_cny,
                    "feasible": allocation.feasible,
                    "objective": allocation.objective,
                    "squared_target_error": allocation.squared_target_error,
                    "residual_net": allocation.residual_net,
                    "gross_exposure_open": allocation.gross,
                    "max_product_exposure_open": max(abs(value) for value in allocation.realized_weights.values()),
                    "max_sector_gross_exposure_open": max(allocation.sector_gross.values()),
                    "states_retained": allocation.states_retained,
                    "daily_auto_rebalance_used": False,
                }
            )
        else:
            if active_target is None:
                raise ValueError("ACTIVE_TARGET_MISSING")
            desired_quantities = quantities.copy()

        tick_cost = 0.0
        fill_notional = 0.0
        fill_count = 0
        roll_product_count = 0
        for product in PRODUCTS:
            new_symbol = desired_symbols[product]
            old_symbol, old_quantity = symbols[product], quantities[product]
            new_quantity = int(desired_quantities[product])
            roll = old_symbol is not None and old_symbol != new_symbol
            if not rebalance and not roll:
                continue
            event_notional = 0.0
            event_tick_cost = 0.0
            event_fills = 0
            current_new_symbol_quantity = old_quantity if old_symbol == new_symbol else 0
            if old_symbol == new_symbol:
                traded = abs(new_quantity - old_quantity)
                if traded:
                    event_fills = 1
                    event_notional = traded * multiplier[product] * _price(
                        lookup, day, product, new_symbol, "open"
                    )
                    event_tick_cost = (
                        traded * multiplier[product] * tick_size[product] * TICK_STRESS_PER_FILL_SIDE
                    )
            else:
                if old_symbol is not None and old_quantity != 0:
                    event_fills += 1
                    event_notional += abs(old_quantity) * multiplier[product] * _price(
                        lookup, day, product, old_symbol, "open"
                    )
                    event_tick_cost += (
                        abs(old_quantity)
                        * multiplier[product]
                        * tick_size[product]
                        * TICK_STRESS_PER_FILL_SIDE
                    )
                if new_quantity != 0:
                    event_fills += 1
                    event_notional += abs(new_quantity) * multiplier[product] * _price(
                        lookup, day, product, new_symbol, "open"
                    )
                    event_tick_cost += (
                        abs(new_quantity)
                        * multiplier[product]
                        * tick_size[product]
                        * TICK_STRESS_PER_FILL_SIDE
                    )
            tick_cost += event_tick_cost
            fill_notional += event_notional
            fill_count += event_fills
            roll_product_count += int(roll and event_fills > 0)
            quantities[product], symbols[product] = new_quantity, new_symbol

            if rebalance and allocation is not None:
                source_target = float(target_frame.loc[product, "source_target_weight"])
                buffered_target = active_target[product]
                allocation_rows.append(
                    {
                        "date": day,
                        "scheduler_id": scheduler_id,
                        "combination_arm": arm,
                        "initial_capital_cny": initial_capital_cny,
                        "product": product,
                        "sector": SECTORS[product],
                        "contract": new_symbol,
                        "old_contract": old_symbol or "",
                        "current_quantity": int(current_new_symbol_quantity),
                        "raw_target_quantity": allocation.raw_quantities[product],
                        "target_quantity": new_quantity,
                        "order_delta": int(new_quantity - current_new_symbol_quantity),
                        "source_target_weight": source_target,
                        "buffered_target_weight": buffered_target,
                        "realized_open_weight": allocation.realized_weights[product],
                        "buffered_target_error": allocation.realized_weights[product] - buffered_target,
                        "source_target_error": allocation.realized_weights[product] - source_target,
                        "zero_contract": bool(abs(buffered_target) > 1e-12 and new_quantity == 0),
                        "product_hard_cap_pass": _strictly_below(
                            abs(allocation.realized_weights[product]), HARD_LIMITS["product"]
                        ),
                        "fill_count": event_fills,
                        "fill_notional": event_notional,
                        "tick_cost": event_tick_cost,
                    }
                )

        intraday_pnl = 0.0
        product_notionals: dict[str, float] = {}
        for product in PRODUCTS:
            symbol, quantity = symbols[product], quantities[product]
            if symbol is None:
                product_notionals[product] = 0.0
                continue
            open_price = _price(lookup, day, product, symbol, "open")
            settlement = _price(lookup, day, product, symbol, "settlement")
            intraday_pnl += quantity * multiplier[product] * (settlement - open_price)
            product_notionals[product] = quantity * multiplier[product] * settlement
        equity = equity_open - tick_cost + intraday_pnl
        if equity <= 0:
            raise ValueError("NON_POSITIVE_EQUITY_CLOSE")
        product_weights = {product: notional / equity for product, notional in product_notionals.items()}
        sector_gross = {
            sector: sum(abs(product_weights[p]) for p in PRODUCTS if SECTORS[p] == sector)
            for sector in sorted(set(SECTORS.values()))
        }
        gross_exposure = sum(abs(value) for value in product_weights.values())
        net_exposure = sum(product_weights.values())
        product_breach_count = sum(
            not _strictly_below(abs(value), HARD_LIMITS["product"]) for value in product_weights.values()
        )
        sector_breach_count = sum(
            not _strictly_below(value, HARD_LIMITS["sector"]) for value in sector_gross.values()
        )
        gross_breach = not _strictly_below(gross_exposure, HARD_LIMITS["gross"])
        net_breach = not _strictly_below(abs(net_exposure), HARD_LIMITS["abs_net"])
        any_breach = bool(product_breach_count or sector_breach_count or gross_breach or net_breach)
        daily_rows.append(
            {
                "date": day,
                "scheduler_id": scheduler_id,
                "combination_arm": arm,
                "initial_capital_cny": initial_capital_cny,
                "equity": equity,
                "net_return": equity / equity_previous - 1.0,
                "overnight_pnl": overnight_pnl,
                "intraday_pnl": intraday_pnl,
                "tick_cost": tick_cost,
                "fill_count": fill_count,
                "fill_notional": fill_notional,
                "fill_turnover": fill_notional / equity_open,
                "rebalance": rebalance,
                "roll_product_count": roll_product_count,
                "daily_auto_rebalance_used": False,
                "holding_drift_monitor_day": not rebalance,
                "executable_product_count": sum(quantity != 0 for quantity in quantities.values()),
                "gross_exposure": gross_exposure,
                "net_exposure": net_exposure,
                "max_abs_product_exposure": max(abs(value) for value in product_weights.values()),
                "max_sector_gross_exposure": max(sector_gross.values()),
                "product_breach_count": product_breach_count,
                "sector_breach_count": sector_breach_count,
                "gross_breach": gross_breach,
                "net_breach": net_breach,
                "any_risk_breach": any_breach,
                "holding_drift_breach": bool(any_breach and not rebalance),
            }
        )
        previous_day = day

    return Simulation(pd.DataFrame(daily_rows), pd.DataFrame(allocation_rows), pd.DataFrame(optimizer_rows))


def _compound(values: pd.Series) -> float:
    return float((1.0 + values.astype(float)).prod() - 1.0)


def _mdd(values: pd.Series) -> float:
    curve = pd.Series(np.r_[1.0, (1.0 + values.astype(float)).cumprod().to_numpy()])
    return float((curve / curve.cummax() - 1.0).min())


def summarize(daily: pd.DataFrame, allocations: pd.DataFrame, optimizer: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    keys = ["combination_arm", "initial_capital_cny"]
    for window, (start, end) in WINDOWS.items():
        day_window = daily[daily["date"].between(start, end)]
        alloc_window = allocations[allocations["date"].between(start, end)]
        opt_window = optimizer[optimizer["date"].between(start, end)]
        for (arm, capital), group in day_window.groupby(keys):
            position = alloc_window[
                alloc_window["combination_arm"].eq(arm)
                & alloc_window["initial_capital_cny"].eq(capital)
            ]
            events = opt_window[
                opt_window["combination_arm"].eq(arm)
                & opt_window["initial_capital_cny"].eq(capital)
            ]
            active = position[position["buffered_target_weight"].abs() > 1e-12]
            rebalance_counts = position.groupby("date")["target_quantity"].apply(lambda x: int((x != 0).sum()))
            std = float(group["net_return"].std(ddof=1))
            rows.append(
                {
                    "window": window,
                    "combination_arm": arm,
                    "initial_capital_cny": int(capital),
                    "days": len(group),
                    "total_return": _compound(group["net_return"]),
                    "sharpe": float(group["net_return"].mean() / std * math.sqrt(252)) if std > 0 else np.nan,
                    "max_drawdown": _mdd(group["net_return"]),
                    "zero_contract_rate": float(active["zero_contract"].mean()) if len(active) else 1.0,
                    "mean_executable_products": float(rebalance_counts.mean()) if len(rebalance_counts) else 0.0,
                    "minimum_executable_products": int(rebalance_counts.min()) if len(rebalance_counts) else 0,
                    "mean_abs_buffered_target_error": float(position["buffered_target_error"].abs().mean()),
                    "max_abs_buffered_target_error": float(position["buffered_target_error"].abs().max()),
                    "mean_abs_source_target_error": float(position["source_target_error"].abs().mean()),
                    "mean_abs_optimizer_residual_net": float(events["residual_net"].abs().mean()),
                    "optimizer_infeasible_events": int((~events["feasible"]).sum()),
                    "allocation_open_product_cap_failures": int((~position["product_hard_cap_pass"]).sum()),
                    "max_gross_exposure": float(group["gross_exposure"].max()),
                    "max_abs_net_exposure": float(group["net_exposure"].abs().max()),
                    "max_product_exposure": float(group["max_abs_product_exposure"].max()),
                    "max_sector_gross_exposure": float(group["max_sector_gross_exposure"].max()),
                    "product_breach_days": int((group["product_breach_count"] > 0).sum()),
                    "sector_breach_days": int((group["sector_breach_count"] > 0).sum()),
                    "gross_breach_days": int(group["gross_breach"].sum()),
                    "net_breach_days": int(group["net_breach"].sum()),
                    "any_risk_breach_days": int(group["any_risk_breach"].sum()),
                    "holding_drift_breach_days": int(group["holding_drift_breach"].sum()),
                    "fill_turnover": float(group["fill_turnover"].sum()),
                    "max_daily_turnover": float(group["fill_turnover"].max()),
                    "max_rebalance_turnover": float(group.loc[group["rebalance"], "fill_turnover"].max()),
                    "execution_cost": float(group["tick_cost"].sum()),
                    "daily_auto_rebalance_days": int(group["daily_auto_rebalance_used"].sum()),
                }
            )
    return pd.DataFrame(rows)


def assess_capital(summary: pd.DataFrame, daily: pd.DataFrame, optimizer: pd.DataFrame) -> pd.DataFrame:
    required = tuple(USABILITY_GATES["required_windows"])
    rows: list[dict[str, object]] = []
    for (arm, capital), group in summary.groupby(["combination_arm", "initial_capital_cny"]):
        selected = group[group["window"].isin(required)]
        if set(selected["window"]) != set(required):
            raise ValueError("REQUIRED_WINDOW_MISSING")
        replay_days = daily[
            daily["combination_arm"].eq(arm) & daily["initial_capital_cny"].eq(capital)
        ]
        events = optimizer[
            optimizer["combination_arm"].eq(arm) & optimizer["initial_capital_cny"].eq(capital)
        ]
        economic = bool(
            (selected["total_return"] > USABILITY_GATES["minimum_total_return_exclusive"]).all()
        )
        drawdown = bool(
            (selected["max_drawdown"].abs() < USABILITY_GATES["maximum_drawdown_abs_exclusive"]).all()
        )
        zero = bool(
            (selected["zero_contract_rate"] <= USABILITY_GATES["maximum_zero_contract_rate_inclusive"]).all()
        )
        coverage = bool(
            (
                selected["mean_executable_products"]
                >= USABILITY_GATES["minimum_mean_executable_products_inclusive"]
            ).all()
        )
        error = bool(
            (
                selected["mean_abs_buffered_target_error"]
                <= USABILITY_GATES["maximum_mean_abs_product_target_error_inclusive"]
            ).all()
        )
        optimizer_feasible = bool(events["feasible"].all())
        allocation_hard_caps = bool(
            (events["gross_exposure_open"] < HARD_LIMITS["gross"] - STRICT_EPSILON).all()
            and (events["residual_net"].abs() < HARD_LIMITS["abs_net"] - STRICT_EPSILON).all()
            and (events["max_product_exposure_open"] < HARD_LIMITS["product"] - STRICT_EPSILON).all()
            and (events["max_sector_gross_exposure_open"] < HARD_LIMITS["sector"] - STRICT_EPSILON).all()
        )
        daily_zero_breach = bool((~replay_days["any_risk_breach"]).all())
        no_daily_reweight = bool((~replay_days["daily_auto_rebalance_used"]).all())
        research_usable = economic and drawdown and zero and coverage and error
        compatible = (
            research_usable
            and optimizer_feasible
            and allocation_hard_caps
            and daily_zero_breach
            and no_daily_reweight
        )
        rows.append(
            {
                "combination_arm": arm,
                "initial_capital_cny": int(capital),
                "economic_positive_both_windows": economic,
                "drawdown_gate_pass": drawdown,
                "zero_contract_rate_gate_pass": zero,
                "executable_product_coverage_gate_pass": coverage,
                "buffered_target_error_gate_pass": error,
                "research_operational_usable": research_usable,
                "optimizer_allocation_feasible": optimizer_feasible,
                "allocation_event_hard_caps_pass": allocation_hard_caps,
                "daily_risk_zero_breach_through_2026_07_09": daily_zero_breach,
                "no_daily_auto_reweight": no_daily_reweight,
                "testnet_safe_research_compatible": compatible,
                "authority_granted": False,
            }
        )
    return pd.DataFrame(rows)


def _yn(value: object) -> str:
    return "是" if bool(value) else "否"


def render_report(summary: pd.DataFrame, decisions: pd.DataFrame) -> str:
    lines = [
        "# 强候选固定调度器 lot-aware 安全分配研究 v1（2026-07-17）",
        "",
        "状态：`RESEARCH_ONLY_LOT_AWARE_ALLOCATOR_NOT_TRADABLE`。C/D/R sleeve权重与两个scheduler均未改变，未按PnL调buffer、搜索半径或资本门槛。",
        "",
        "## 结论",
        "",
    ]
    minima: dict[str, str] = {}
    for arm in COMBINATION_ARMS:
        rows = decisions[
            decisions["combination_arm"].eq(arm)
            & decisions["testnet_safe_research_compatible"]
        ]
        minima[arm] = "无" if rows.empty else f"{int(rows['initial_capital_cny'].min()):,} CNY"
        lines.append(f"- `{arm}` 最低testnet-safe研究兼容资本：**{minima[arm]}**。")
    common = decisions.groupby("initial_capital_cny")["testnet_safe_research_compatible"].all()
    common = common[common]
    common_text = "无" if common.empty else f"{int(common.index.min()):,} CNY"
    lines += [
        f"- 两个scheduler共同兼容的最低资本：**{common_text}**。",
        "- 兼容只表示该历史回放同时通过冻结经济/覆盖/误差门槛、分配时硬约束和逐日漂移零越界；不授予shadow或testnet authority。",
        "",
        "## 固定方法",
        "",
        "1. canonical单账户target先做shrink-only安全投影：product≤14%、sector gross≤30%、portfolio gross≤90%，最后只缩较大多空腿使target net=0。",
        "2. 月度execution day按当日PIT main exact contract开盘价，将buffer target换算为raw lots；每品种在nearest lot ±2、floor、ceil、toward-zero与0组成的固定有限邻域内联合搜索。",
        "3. 固定目标函数为 `Σ(realized-target)^2 + residual_net^2`；beam width=2048。分配结果必须严格满足product<15%、sector<35%、gross<100%、|net|<10%。",
        "4. 非月度日期不重新优化。main contract变化只按原lot数量换月；逐日结算后重新测风险，任何持有期漂移越界均记为不兼容，不触发自动减仓。",
        "5. 成本固定为每个单边fill 2.5 ticks（5T round trip口径），self-financing equity；未联网、未读旧事件/交易/持仓/PnL账本。",
        "",
        "## 逐窗口结果",
        "",
        "| scheduler | 资本 | 窗口 | 收益 | Sharpe | 回撤 | 零合约率 | 覆盖 | 平均buffer误差 | risk breach日 | 漂移breach日 | turnover |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for _, row in summary.sort_values(["combination_arm", "initial_capital_cny", "window"]).iterrows():
        lines.append(
            f"| `{row.combination_arm}` | {int(row.initial_capital_cny):,} | {row.window} | "
            f"{row.total_return:+.2%} | {row.sharpe:.2f} | {row.max_drawdown:+.2%} | "
            f"{row.zero_contract_rate:.1%} | {row.mean_executable_products:.1f} | "
            f"{row.mean_abs_buffered_target_error:.2%} | {int(row.any_risk_breach_days)} | "
            f"{int(row.holding_drift_breach_days)} | {row.fill_turnover:.1f}x |"
        )
    lines += [
        "",
        "## 固定判定矩阵",
        "",
        "| scheduler | 资本 | 经济 | 回撤 | 零合约 | 覆盖 | 误差 | allocation硬约束 | daily零越界 | 研究可用 | safe兼容 |",
        "|---|---:|---|---|---|---|---|---|---|---|---|",
    ]
    for _, row in decisions.sort_values(["combination_arm", "initial_capital_cny"]).iterrows():
        lines.append(
            f"| `{row.combination_arm}` | {int(row.initial_capital_cny):,} | "
            f"{_yn(row.economic_positive_both_windows)} | {_yn(row.drawdown_gate_pass)} | "
            f"{_yn(row.zero_contract_rate_gate_pass)} | {_yn(row.executable_product_coverage_gate_pass)} | "
            f"{_yn(row.buffered_target_error_gate_pass)} | {_yn(row.allocation_event_hard_caps_pass)} | "
            f"{_yn(row.daily_risk_zero_breach_through_2026_07_09)} | "
            f"{_yn(row.research_operational_usable)} | {_yn(row.testnet_safe_research_compatible)} |"
        )
    lines += [
        "",
        "## 边界",
        "",
        "- finite-neighbourhood beam search是固定可复现的联合启发式，不声称全局整数最优。全零组合是fail-safe可行后备，但仍受覆盖/经济门槛拒绝。",
        "- 未纳入正式手续费、保证金、实时bid/ask、容量和交易所下单约束；这些证据缺一不可，当前结果不能直接晋级testnet。",
        "- `confirmatory=false`、`tradable=false`、`shadow_authorized=false`、`testnet_authorized=false`、`live_authorized=false`、`production_authorized=false`。",
    ]
    return "\n".join(lines) + "\n"


def run(output_dir: Path) -> dict[str, pd.DataFrame]:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    inputs, source_targets = load_inputs()
    buffered_targets = build_buffered_targets(source_targets)
    simulations = [
        simulate_one(inputs, buffered_targets, arm, capital)
        for arm in COMBINATION_ARMS
        for capital in CAPITAL_LADDER_CNY
    ]
    daily = pd.concat([simulation.daily for simulation in simulations], ignore_index=True)
    allocations = pd.concat([simulation.allocations for simulation in simulations], ignore_index=True)
    optimizer = pd.concat([simulation.optimizer_events for simulation in simulations], ignore_index=True)
    summary = summarize(daily, allocations, optimizer)
    decisions = assess_capital(summary, daily, optimizer)
    breaches = daily[daily["any_risk_breach"]].copy()

    output_dir.mkdir(parents=True, exist_ok=False)
    outputs = {
        "buffered_monthly_targets.csv": buffered_targets,
        "daily_accounting.csv": daily,
        "allocation_rows.csv": allocations,
        "optimizer_events.csv": optimizer,
        "capital_summary.csv": summary,
        "capital_decision.csv": decisions,
        "risk_breach_rows.csv": breaches,
    }
    for name, frame in outputs.items():
        frame.to_csv(output_dir / name, index=False)

    contract = {
        "schema_version": "commodity_candidate_lot_aware_safe_allocator_contract_v1",
        "status": "FIXED_BEFORE_LOT_AWARE_RESULT_ASSESSMENT",
        "combination_arms_unchanged": COMBINATION_ARMS,
        "capital_ladder_cny": list(CAPITAL_LADDER_CNY),
        "buffer_limits": BUFFER_LIMITS,
        "promotion_hard_limits_strict": HARD_LIMITS,
        "integer_search": {
            "type": "deterministic_finite_neighbourhood_beam",
            "neighbourhood_radius_lots": NEIGHBOURHOOD_RADIUS_LOTS,
            "beam_width": BEAM_WIDTH,
            "objective": "sum_squared_buffered_target_error_plus_squared_residual_net",
            "net_error_penalty": NET_ERROR_PENALTY,
            "global_optimum_claimed": False,
            "all_zero_fail_safe": True,
        },
        "rebalance_policy": {
            "monthly_target_dates_only": True,
            "daily_auto_reweight": False,
            "roll_preserves_integer_lots": True,
            "holding_drift_breach_is_recorded_not_auto_repaired": True,
        },
        "cost": "5T_2.5_TICKS_PER_FILL_SIDE",
        "usability_gates_reused_unchanged": USABILITY_GATES,
        "weight_search_used": False,
        "network_used": False,
        "legacy_event_trade_position_label_pnl_ledger_read": False,
        "confirmatory": False,
        "tradable": False,
        "shadow_authorized": False,
        "testnet_authorized": False,
        "live_authorized": False,
        "production_authorized": False,
    }
    (output_dir / "allocator_contract.json").write_text(
        json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(render_report(summary, decisions), encoding="utf-8")
    receipt = {
        "status": "COMPLETE_FIXED_LOT_AWARE_SAFE_ALLOCATOR_RESEARCH",
        "combination_arms": list(COMBINATION_ARMS),
        "capital_ladder_cny": list(CAPITAL_LADDER_CNY),
        "fixed_runs_completed": len(COMBINATION_ARMS) * len(CAPITAL_LADDER_CNY),
        "buffer_target_rows": len(buffered_targets),
        "optimizer_events": len(optimizer),
        "daily_rows": len(daily),
        "daily_auto_reweight_used": False,
        "network_used": False,
        "legacy_event_trade_position_label_pnl_ledger_read": False,
        "confirmatory": False,
        "tradable": False,
        "shadow_authorized": False,
        "testnet_authorized": False,
        "live_authorized": False,
        "production_authorized": False,
        "python": platform.python_version(),
        "pandas": pd.__version__,
        "numpy": np.__version__,
    }
    (output_dir / "receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    inputs_bound = {
        "runner": Path(__file__).resolve(),
        "tests": TEST_FILE,
        "canonical_manifest": CANONICAL_DIR / "manifest.json",
        "canonical_monthly_targets": CANONICAL_TARGETS,
        "integer_ladder_manifest": LADDER_DIR / "manifest.json",
        "integer_ladder_summary": LADDER_DIR / "capital_ladder_summary.csv",
        "integer_ladder_decision": LADDER_DIR / "capital_tier_decision.csv",
        "promotion_contract_v1r1": ladder.PROMOTION_CONTRACT,
        "panel_manifest": canonical.PANEL_DIR / "manifest.json",
        "curve_features_daily": canonical.PANEL_DIR / "curve_features_daily.csv",
        "curve_contract_daily": canonical.PANEL_DIR / "curve_contract_daily.csv",
        "research_spec": canonical.SPEC_FILE,
        "research_spec_manifest": canonical.SPEC_FILE.with_name("manifest.json"),
    }
    files = sorted(path for path in output_dir.iterdir() if path.is_file() and path.name != "manifest.json")
    manifest = {
        "schema_version": "commodity_candidate_lot_aware_safe_allocator_v1_manifest",
        "status": "PASS_FIXED_LOT_AWARE_SAFE_ALLOCATOR_RESEARCH",
        "input_bindings": {name: _binding(path) for name, path in inputs_bound.items()},
        "output_bindings": [_binding(path) for path in files],
        "two_scheduler_weights_unchanged": True,
        "fixed_capital_ladder_all_reported": True,
        "pre_registered_buffer_applied_before_integer_search": True,
        "allocation_event_hard_constraints_strict": True,
        "holding_drift_monitored_daily": True,
        "daily_auto_reweight_used": False,
        "weight_search_used": False,
        "network_used": False,
        "legacy_event_trade_position_label_pnl_ledger_read": False,
        "confirmatory": False,
        "tradable": False,
        "shadow_authorized": False,
        "testnet_authorized": False,
        "live_authorized": False,
        "production_authorized": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    outputs = run(args.output_dir)
    print(outputs["capital_decision.csv"].to_string(index=False))
    print(f"output_dir={args.output_dir}")


if __name__ == "__main__":
    main()
