from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

from research.entry_redesign.scripts.futures_lead import (
    commodity_candidate_lot_aware_safe_allocator_v1 as v1,
)
from research.entry_redesign.scripts.futures_lead.commodity_candidate_lot_aware_safe_allocator_guardband_v2 import (
    BUFFER_LIMITS,
    CAPITAL_LADDER_CNY,
    COMBINATION_ARMS,
    DEFAULT_OUTPUT,
    HARD_LIMITS,
    PRODUCTS,
    SECTORS,
    buffer_one_target,
    joint_integer_allocate,
)


def test_guardband_is_the_only_changed_axis_from_v1() -> None:
    assert BUFFER_LIMITS == {"product": 0.12, "sector": 0.27, "gross": 0.80, "target_net": 0.0}
    assert COMBINATION_ARMS == {
        "CORE_EQUAL_TARGET": {"C": 0.5, "D": 0.5},
        "CORE_PLUS_RESERVE_TARGET": {"C": 0.4, "D": 0.4, "R": 0.2},
    }
    assert CAPITAL_LADDER_CNY == v1.CAPITAL_LADDER_CNY
    assert HARD_LIMITS == {"product": 0.15, "sector": 0.35, "gross": 1.0, "abs_net": 0.10}
    assert v1.TICK_STRESS_PER_FILL_SIDE == 2.5
    assert v1.NEIGHBOURHOOD_RADIUS_LOTS == 2
    assert v1.BEAM_WIDTH == 2048


def test_guardband_projection_is_shrink_only_and_exactly_neutral() -> None:
    source = {
        product: value
        for product, value in zip(
            PRODUCTS,
            (0.20, 0.18, 0.16, 0.12, 0.08, -0.20, -0.18, -0.16, -0.12, -0.08),
        )
    }
    buffered = buffer_one_target(source)
    assert abs(sum(buffered.values())) < 1e-10
    assert max(abs(value) for value in buffered.values()) <= 0.12 + 1e-12
    assert sum(abs(value) for value in buffered.values()) <= 0.80 + 1e-12
    for sector in set(SECTORS.values()):
        assert sum(abs(buffered[p]) for p in PRODUCTS if SECTORS[p] == sector) <= 0.27 + 1e-12
    assert all(abs(buffered[product]) <= abs(source[product]) + 1e-12 for product in PRODUCTS)


def test_joint_allocator_retains_strict_v1_hard_caps() -> None:
    target = {product: 0.0 for product in PRODUCTS}
    target[PRODUCTS[0]] = 0.12
    target[PRODUCTS[1]] = -0.12
    unit = {product: 0.06 for product in PRODUCTS}
    allocation = joint_integer_allocate(target, unit)
    assert allocation.feasible
    assert max(abs(value) for value in allocation.realized_weights.values()) < 0.15
    assert max(allocation.sector_gross.values()) < 0.35
    assert allocation.gross < 1.0
    assert abs(allocation.residual_net) < 0.10


@pytest.mark.parametrize("bad_value", [np.nan, 0.0, -0.01])
def test_joint_allocator_fails_closed_on_bad_unit_weight(bad_value: float) -> None:
    target = {product: 0.0 for product in PRODUCTS}
    units = {product: 0.01 for product in PRODUCTS}
    units[PRODUCTS[0]] = bad_value
    with pytest.raises(ValueError, match="INVALID_ALLOCATION_INPUT"):
        joint_integer_allocate(target, units)


def test_manifest_is_hash_bound_and_all_authorities_false_if_present() -> None:
    path = DEFAULT_OUTPUT / "manifest.json"
    if not path.exists():
        return
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["sole_changed_axis_from_v1"] == "buffer_14_30_90_to_12_27_80_target_net_zero_unchanged"
    for key in (
        "two_scheduler_weights_unchanged",
        "joint_integer_algorithm_unchanged",
        "capital_ladder_unchanged",
        "five_tick_accounting_unchanged",
        "strict_hard_caps_15_35_100_10_unchanged",
        "holding_drift_monitored_daily",
    ):
        assert manifest[key] is True
    for key in (
        "daily_auto_reweight_used",
        "buffer_scan_used",
        "result_conditioned_reweight_used",
        "network_used",
        "legacy_event_trade_position_label_pnl_ledger_read",
        "confirmatory",
        "tradable",
        "shadow_authorized",
        "testnet_authorized",
        "live_authorized",
        "production_authorized",
    ):
        assert manifest[key] is False
    root = Path(__file__).resolve().parents[5]
    for binding in manifest["output_bindings"]:
        bound = Path(binding["path"])
        if not bound.is_absolute():
            bound = root / bound
        assert bound.stat().st_size == binding["bytes"]
        assert hashlib.sha256(bound.read_bytes()).hexdigest() == binding["sha256"]
