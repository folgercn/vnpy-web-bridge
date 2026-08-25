from __future__ import annotations

from copy import deepcopy

import pytest

from app.execution.start_quote_proof import (
    ExecutionStartQuotePriceIncompatible,
    build_execution_start_quote_proof,
)
from shared.commodity_execution import (
    TargetPlan,
    simnow_experimental_adverse_cushion_ticks,
)
from test_issue362_execution_two_quote_proofs import QUOTE_TIME, _Reader
from test_issue362_full_portfolio_planner import _decision
from test_issue362_target_plan_v3 import _v3_plan


EXPERIMENTAL_RUN_ID = "simnow-experimental-" + "a" * 48
TARGET_QUANTITIES = {
    "ag": -2,
    "al": 11,
    "au": -2,
    "bu": 30,
    "cu": 4,
    "rb": -81,
    "ru": -8,
    "sc": 2,
    "sp": -29,
    "zn": 12,
}
TICK_VALUE_BY_PRODUCT = {
    "ag": 15,
    "al": 25,
    "au": 20,
    "bu": 10,
    "cu": 50,
    "rb": 10,
    "ru": 50,
    "sc": 100,
    "sp": 20,
    "zn": 25,
}


def _cushion_ticks(product: str) -> int:
    return simnow_experimental_adverse_cushion_ticks(
        execution_run_id=EXPERIMENTAL_RUN_ID,
        symbol=f"{product}0000",
    )


def _experimental_plan() -> TargetPlan:
    plan = _v3_plan(
        execution_run_id=EXPERIMENTAL_RUN_ID,
        orders=[
            {
                "symbol": "ag2609",
                "exchange": "SHFE",
                "direction": "LONG",
                "type": "LIMIT",
                "volume": 1,
                "price": 5011.0,
                "offset": "OPEN",
                "reference": "issue421-bounded-order-0001",
                "gateway_name": "CTP",
            }
        ],
    )
    return TargetPlan.from_mapping(plan)


def test_experimental_plan_uses_frozen_product_cushions_within_budget() -> None:
    assert {product: _cushion_ticks(product) for product in TARGET_QUANTITIES} == {
        "ag": 10,
        "al": 1,
        "au": 15,
        "bu": 2,
        "cu": 1,
        "rb": 1,
        "ru": 1,
        "sc": 3,
        "sp": 1,
        "zn": 1,
    }
    decision = _decision(
        selected=TARGET_QUANTITIES,
        run_id=EXPERIMENTAL_RUN_ID,
        target_plan_version=3,
    )
    assert decision.open_handoff is not None
    plan = decision.open_handoff.target_plan
    assert len(plan["orders"]) == 181

    by_product = {
        order["symbol"][:-4].lower(): order for order in plan["orders"]
    }
    assert set(by_product) == set(TARGET_QUANTITIES)
    for product, order in by_product.items():
        exact_contract = f"{order['exchange']}.{order['symbol']}"
        binding = plan["creation_quote_proof"]["bindings"][exact_contract]
        reference = float(binding["reference_price"])
        tick = float(binding["price_tick"])
        steps = 1 + _cushion_ticks(product)
        expected = (
            reference + tick * steps
            if order["direction"] == "LONG"
            else reference - tick * steps
        )
        assert order["price"] == expected

    budget = sum(
        abs(TARGET_QUANTITIES[product])
        * _cushion_ticks(product)
        * TICK_VALUE_BY_PRODUCT[product]
        for product in TARGET_QUANTITIES
    )
    assert budget == 4_665
    assert budget <= 30_000


@pytest.mark.parametrize(
    ("reference_price", "protected_price"),
    [(5009.0, 5010.0), (5010.0, 5011.0)],
)
def test_experimental_start_accepts_favorable_or_within_limit_price_without_mutating_plan(
    reference_price: float,
    protected_price: float,
) -> None:
    plan = _experimental_plan()
    before = deepcopy(plan.raw)

    proof = build_execution_start_quote_proof(
        plan,
        reader=_Reader(reference_price=reference_price),
        clock=lambda: QUOTE_TIME,
    )

    assert (
        proof["bindings"]["issue421-bounded-order-0001"]["protected_price"]
        == protected_price
    )
    assert plan.raw == before
    assert plan.raw["orders"][0]["price"] == 5011.0


def test_experimental_start_rejects_price_beyond_immutable_limit() -> None:
    with pytest.raises(
        ExecutionStartQuotePriceIncompatible,
        match="outside immutable order limit",
    ):
        build_execution_start_quote_proof(
            _experimental_plan(),
            reader=_Reader(reference_price=5011.0),
            clock=lambda: QUOTE_TIME,
        )


def test_non_experimental_start_keeps_exact_equality() -> None:
    plan = TargetPlan.from_mapping(_v3_plan())
    build_execution_start_quote_proof(
        plan,
        reader=_Reader(reference_price=5000.0),
        clock=lambda: QUOTE_TIME,
    )
    with pytest.raises(
        ExecutionStartQuotePriceIncompatible,
        match="differs from immutable order price",
    ):
        build_execution_start_quote_proof(
            plan,
            reader=_Reader(reference_price=5001.0),
            clock=lambda: QUOTE_TIME,
        )
