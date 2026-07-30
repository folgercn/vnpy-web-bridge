from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from research.entry_redesign.scripts.futures_lead.commodity_fast_tsmom_self_financing_sidecar_v1 import (
    DEFAULT_OUTPUT,
    PRODUCTS,
    SECTORS,
    Inputs,
    _neutral_weights,
    simulate_one,
)


def _inputs(roll: bool = False) -> tuple[Inputs, pd.DataFrame]:
    days = pd.to_datetime(["2025-01-02", "2025-01-03"])
    feature_rows = []
    contract_rows = []
    for product in PRODUCTS:
        first_symbol = f"X.{product}2501"
        second_symbol = f"X.{product}2502" if roll and product == "ag" else first_symbol
        for index, day in enumerate(days):
            symbol = first_symbol if index == 0 else second_symbol
            feature_rows.append(
                {
                    "source_official_day": day - pd.Timedelta(days=1),
                    "available_official_day": day,
                    "product": product,
                    "main_symbol": symbol,
                }
            )
        if product == "ag" and not roll:
            prices = [(first_symbol, 100.0, 110.0), (first_symbol, 110.0, 121.0)]
        elif product == "ag" and roll:
            prices = [(first_symbol, 100.0, 100.0), (second_symbol, 200.0, 210.0)]
        else:
            prices = [(first_symbol, 100.0, 100.0), (first_symbol, 100.0, 100.0)]
        for day, (symbol, open_price, settlement) in zip(days, prices):
            contract_rows.append(
                {
                    "source_official_day": day,
                    "available_official_day": day + pd.Timedelta(days=1),
                    "product": product,
                    "exact_contract": symbol,
                    "open": open_price,
                    "settlement": settlement,
                }
            )
        if roll and product == "ag":
            contract_rows.append(
                {
                    "source_official_day": days[1],
                    "available_official_day": days[1] + pd.Timedelta(days=1),
                    "product": product,
                    "exact_contract": first_symbol,
                    "open": 100.0,
                    "settlement": 100.0,
                }
            )
    spec = pd.DataFrame(
        [
            {
                "code": product,
                "multiplier": 1.0,
                "tick_size": 1.0,
                "verification_status": "official_daily_empirically_verified_research_only",
                "research_5t_authorized": True,
                "production_authorized": False,
            }
            for product in PRODUCTS
        ]
    )
    targets = pd.DataFrame(
        [
            {
                "execution_day": days[0],
                "arm": "fast_cross_section_neutral",
                "product": product,
                "target_weight": 0.10 if product == "ag" else 0.0,
            }
            for product in PRODUCTS
        ]
    )
    inputs = Inputs(
        pd.DataFrame(feature_rows),
        pd.DataFrame(contract_rows),
        pd.DataFrame(),
        spec,
        pd.DataFrame(),
        pd.DataFrame(),
    )
    return inputs, targets


def test_fractional_quantity_is_fixed_between_monthly_rebalances() -> None:
    inputs, targets = _inputs()
    result = simulate_one(
        inputs,
        targets,
        "fast_cross_section_neutral",
        "fractional_fixed_quantity",
        "GROSS",
        1000.0,
    )
    assert result.daily.iloc[-1]["equity"] == pytest.approx(1021.0)
    ag = result.executions[result.executions["product"].eq("ag")]
    assert len(ag) == 1
    assert ag.iloc[0]["new_quantity"] == pytest.approx(1.0)


def test_roll_closes_and_opens_same_quantity_and_charges_both_fills() -> None:
    inputs, targets = _inputs(roll=True)
    result = simulate_one(
        inputs,
        targets,
        "fast_cross_section_neutral",
        "fractional_fixed_quantity",
        "5T",
        1000.0,
    )
    roll = result.executions[
        result.executions["product"].eq("ag") & result.executions["roll"]
    ].iloc[0]
    assert roll["old_quantity"] == pytest.approx(roll["new_quantity"])
    assert roll["tick_cost"] == pytest.approx(5.0)


def test_integer_mode_emits_integer_contract_counts() -> None:
    inputs, targets = _inputs()
    targets.loc[targets["product"].eq("ag"), "target_weight"] = 0.16
    result = simulate_one(
        inputs,
        targets,
        "fast_cross_section_neutral",
        "integer_contract_illustrative",
        "GROSS",
        1000.0,
    )
    quantities = result.executions["new_quantity"]
    assert all(value == round(value) for value in quantities)
    assert result.executions[result.executions["product"].eq("ag")].iloc[0][
        "new_quantity"
    ] == 2.0


def test_invalid_initial_capital_fails_closed() -> None:
    inputs, targets = _inputs()
    with pytest.raises(ValueError, match="INVALID_INITIAL_CAPITAL"):
        simulate_one(
            inputs,
            targets,
            "fast_cross_section_neutral",
            "fractional_fixed_quantity",
            "5T",
            0.0,
        )


def test_neutral_mapping_respects_net_product_sector_and_gross_caps() -> None:
    rows = []
    for index, product in enumerate(PRODUCTS):
        rows.append(
            {
                "product": product,
                "score_fast": -1.0 if index < len(PRODUCTS) // 2 else 1.0,
                "vol60": 0.08 + index * 0.01,
            }
        )
    weights = _neutral_weights(pd.DataFrame(rows), "score_fast")
    assert sum(weights.values()) == pytest.approx(0.0, abs=1e-12)
    assert sum(abs(value) for value in weights.values()) <= 1.0 + 1e-12
    assert max(abs(value) for value in weights.values()) <= 0.20 + 1e-12
    for sector in set(SECTORS.values()):
        gross = sum(
            abs(weights[product]) for product in PRODUCTS if SECTORS[product] == sector
        )
        assert gross <= 0.35 + 1e-12


def test_final_manifest_binds_tests_and_is_research_only_if_present() -> None:
    manifest_path = DEFAULT_OUTPUT / "manifest.json"
    if not manifest_path.exists():
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["confirmatory"] is False
    assert manifest["tradable"] is False
    assert manifest["production_authorized"] is False
    assert manifest["network_used"] is False
    assert manifest["legacy_event_trade_position_label_pnl_ledger_read"] is False
    tests = manifest["input_bindings"]["tests"]
    path = Path(tests["path"])
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[5] / path
    assert hashlib.sha256(path.read_bytes()).hexdigest() == tests["sha256"]
