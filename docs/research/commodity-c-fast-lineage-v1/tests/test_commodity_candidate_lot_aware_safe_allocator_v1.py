from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

from research.entry_redesign.scripts.futures_lead.commodity_candidate_lot_aware_safe_allocator_v1 import (
    BEAM_WIDTH,
    BUFFER_LIMITS,
    CAPITAL_LADDER_CNY,
    COMBINATION_ARMS,
    DEFAULT_OUTPUT,
    HARD_LIMITS,
    PRODUCTS,
    SECTORS,
    _candidate_quantities,
    buffer_one_target,
    joint_integer_allocate,
)


def test_fixed_axes_and_scheduler_weights_are_unchanged() -> None:
    assert CAPITAL_LADDER_CNY == (
        100_000,
        200_000,
        500_000,
        1_000_000,
        2_000_000,
        5_000_000,
        10_000_000,
        20_000_000,
    )
    assert COMBINATION_ARMS == {
        "CORE_EQUAL_TARGET": {"C": 0.5, "D": 0.5},
        "CORE_PLUS_RESERVE_TARGET": {"C": 0.4, "D": 0.4, "R": 0.2},
    }
    assert BUFFER_LIMITS == {"product": 0.14, "sector": 0.30, "gross": 0.90, "target_net": 0.0}
    assert HARD_LIMITS == {"product": 0.15, "sector": 0.35, "gross": 1.0, "abs_net": 0.10}
    assert BEAM_WIDTH == 2048


def test_buffer_is_shrink_only_neutral_and_inside_registered_limits() -> None:
    source = {
        product: value
        for product, value in zip(
            PRODUCTS,
            (0.20, 0.18, 0.16, 0.12, 0.08, -0.20, -0.18, -0.16, -0.12, -0.08),
        )
    }
    buffered = buffer_one_target(source)
    assert abs(sum(buffered.values())) < 1e-10
    assert max(abs(value) for value in buffered.values()) <= BUFFER_LIMITS["product"] + 1e-12
    assert sum(abs(value) for value in buffered.values()) <= BUFFER_LIMITS["gross"] + 1e-12
    for sector in set(SECTORS.values()):
        assert (
            sum(abs(buffered[p]) for p in PRODUCTS if SECTORS[p] == sector)
            <= BUFFER_LIMITS["sector"] + 1e-12
        )
    assert all(abs(buffered[product]) <= abs(source[product]) + 1e-12 for product in PRODUCTS)


def test_joint_allocator_obeys_strict_caps_and_balances_discrete_lots() -> None:
    target = {product: 0.0 for product in PRODUCTS}
    target[PRODUCTS[0]] = 0.14
    target[PRODUCTS[1]] = -0.14
    unit = {product: 0.08 for product in PRODUCTS}
    allocation = joint_integer_allocate(target, unit)
    assert allocation.feasible
    assert allocation.quantities[PRODUCTS[0]] == 1
    assert allocation.quantities[PRODUCTS[1]] == -1
    assert max(abs(value) for value in allocation.realized_weights.values()) < HARD_LIMITS["product"]
    assert allocation.gross < HARD_LIMITS["gross"]
    assert abs(allocation.residual_net) < HARD_LIMITS["abs_net"]
    assert max(allocation.sector_gross.values()) < HARD_LIMITS["sector"]


def test_candidate_neighbourhood_always_contains_safe_zero_and_rejects_cap_touch() -> None:
    candidates = _candidate_quantities(raw_quantity=1.0, target_weight=0.14, unit_weight=0.15)
    assert candidates == (0,)


@pytest.mark.parametrize(
    "bad_units",
    [
        {product: (np.nan if index == 0 else 0.01) for index, product in enumerate(PRODUCTS)},
        {product: (0.0 if index == 0 else 0.01) for index, product in enumerate(PRODUCTS)},
    ],
)
def test_joint_allocator_fails_closed_on_invalid_unit_weights(bad_units: dict[str, float]) -> None:
    with pytest.raises(ValueError, match="INVALID_ALLOCATION_INPUT"):
        joint_integer_allocate({product: 0.0 for product in PRODUCTS}, bad_units)


def test_manifest_is_hash_bound_and_authority_false_if_present() -> None:
    path = DEFAULT_OUTPUT / "manifest.json"
    if not path.exists():
        return
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["two_scheduler_weights_unchanged"] is True
    assert manifest["pre_registered_buffer_applied_before_integer_search"] is True
    assert manifest["allocation_event_hard_constraints_strict"] is True
    assert manifest["holding_drift_monitored_daily"] is True
    assert manifest["daily_auto_reweight_used"] is False
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
        assert manifest[flag] is False
    root = Path(__file__).resolve().parents[5]
    for binding in manifest["output_bindings"]:
        bound = Path(binding["path"])
        if not bound.is_absolute():
            bound = root / bound
        assert bound.stat().st_size == binding["bytes"]
        assert hashlib.sha256(bound.read_bytes()).hexdigest() == binding["sha256"]
