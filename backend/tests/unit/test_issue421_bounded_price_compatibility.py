from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from app.execution.final_runtime import DurableTargetPlanRepository
from app.execution.start_quote_proof import (
    ExecutionStartQuotePriceIncompatible,
    ExecutionStartQuoteProofError,
    build_execution_start_quote_proof,
    validate_execution_start_quote_proof,
)
from test_issue362_execution_two_quote_proofs import QUOTE_TIME, _Reader
from test_issue362_full_portfolio_planner import _decision
from test_issue362_target_plan_v3 import _v3_fields, _v3_plan

from shared.commodity_execution import (
    CommodityExecutionContractError,
    TargetPlan,
    sha256_json,
    simnow_experimental_adverse_cushion_ticks,
)

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


def _legacy_experimental_plan() -> TargetPlan:
    return TargetPlan.from_mapping(_v3_plan(execution_run_id=EXPERIMENTAL_RUN_ID))


def _experimental_short_plan() -> TargetPlan:
    fields = _v3_fields()
    fields["execution_run_id"] = EXPERIMENTAL_RUN_ID
    binding = fields["creation_quote_proof"]["bindings"]["SHFE.ag2609"]
    binding["price_side"] = "bid"
    fields["orders"] = [
        {
            "symbol": "ag2609",
            "exchange": "SHFE",
            "direction": "SHORT",
            "type": "LIMIT",
            "volume": 1,
            "price": 4989.0,
            "offset": "OPEN",
            "reference": "issue421-bounded-short-0001",
            "gateway_name": "CTP",
        }
    ]
    return TargetPlan.from_mapping(_v3_plan(**fields))


def _experimental_au_budget_plan(order_count: int) -> dict:
    fields = _v3_fields()
    fields["execution_run_id"] = EXPERIMENTAL_RUN_ID
    binding = fields["creation_quote_proof"]["bindings"].pop("SHFE.ag2609")
    binding.update(
        {
            "vt_symbol": "au2609.SHFE",
            "price_side": "ask",
            "reference_price": 5000.0,
            "price_tick": 0.02,
        }
    )
    fields["creation_quote_proof"]["bindings"] = {"SHFE.au2609": binding}
    fields["orders"] = [
        {
            "symbol": "au2609",
            "exchange": "SHFE",
            "direction": "LONG",
            "type": "LIMIT",
            "volume": 1,
            "price": 5000.32,
            "offset": "OPEN",
            "reference": f"issue421-au-budget-{index:04d}",
            "gateway_name": "CTP",
        }
        for index in range(1, order_count + 1)
    ]
    return _v3_plan(**fields)


def _mixed_experimental_plan() -> dict:
    fields = _v3_fields()
    fields["execution_run_id"] = EXPERIMENTAL_RUN_ID
    au_binding = deepcopy(fields["creation_quote_proof"]["bindings"]["SHFE.ag2609"])
    au_binding.update(
        {
            "vt_symbol": "au2609.SHFE",
            "price_side": "ask",
            "reference_price": 5000.0,
            "price_tick": 0.02,
        }
    )
    fields["creation_quote_proof"]["bindings"]["SHFE.au2609"] = au_binding
    fields["orders"] = [
        fields["orders"][0],
        {
            "symbol": "au2609",
            "exchange": "SHFE",
            "direction": "LONG",
            "type": "LIMIT",
            "volume": 1,
            "price": 5000.32,
            "offset": "OPEN",
            "reference": "issue421-mixed-bounded-0001",
            "gateway_name": "CTP",
        },
    ]
    return _v3_plan(**fields)


def _experimental_near_grid_plan(
    *, symbol: str, price_tick: float, reference_price: float, limit_price: float
) -> TargetPlan:
    fields = _v3_fields()
    fields["execution_run_id"] = EXPERIMENTAL_RUN_ID
    binding = fields["creation_quote_proof"]["bindings"].pop("SHFE.ag2609")
    binding.update(
        {
            "vt_symbol": f"{symbol}.SHFE",
            "price_side": "ask",
            "reference_price": reference_price,
            "price_tick": price_tick,
        }
    )
    fields["creation_quote_proof"]["bindings"] = {f"SHFE.{symbol}": binding}
    fields["orders"] = [
        {
            "symbol": symbol,
            "exchange": "SHFE",
            "direction": "LONG",
            "type": "LIMIT",
            "volume": 1,
            "price": limit_price,
            "offset": "OPEN",
            "reference": f"issue421-near-grid-{symbol}-0001",
            "gateway_name": "CTP",
        }
    ]
    return TargetPlan.from_mapping(_v3_plan(**fields))


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


def test_legacy_experimental_durable_plan_recovers_and_keeps_exact_equality(
    tmp_path: Path,
) -> None:
    legacy = _legacy_experimental_plan()
    repository = DurableTargetPlanRepository(tmp_path / "plans")
    repository.put(legacy)
    recovered = repository.get(legacy.plan_id)
    assert recovered is not None
    assert recovered.plan_hash == legacy.plan_hash

    build_execution_start_quote_proof(
        recovered,
        reader=_Reader(reference_price=5000.0),
        clock=lambda: QUOTE_TIME,
    )
    with pytest.raises(
        ExecutionStartQuotePriceIncompatible,
        match="differs from immutable order price",
    ):
        build_execution_start_quote_proof(
            recovered,
            reader=_Reader(reference_price=4999.0),
            clock=lambda: QUOTE_TIME,
        )


def test_experimental_short_start_accepts_favorable_or_within_limit_price() -> None:
    for reference_price, protected_price in ((4990.0, 4989.0), (4991.0, 4990.0)):
        proof = build_execution_start_quote_proof(
            _experimental_short_plan(),
            reader=_Reader(reference_price=reference_price),
            clock=lambda: QUOTE_TIME,
        )
        assert (
            proof["bindings"]["issue421-bounded-short-0001"]["protected_price"]
            == protected_price
        )


def test_experimental_short_start_rejects_price_beyond_immutable_limit() -> None:
    with pytest.raises(
        ExecutionStartQuotePriceIncompatible,
        match="outside immutable order limit",
    ):
        build_execution_start_quote_proof(
            _experimental_short_plan(),
            reader=_Reader(reference_price=4988.0),
            clock=lambda: QUOTE_TIME,
        )


def test_experimental_creation_proof_rejects_arbitrarily_wider_cushion() -> None:
    fields = _v3_fields()
    fields["execution_run_id"] = EXPERIMENTAL_RUN_ID
    fields["orders"][0]["price"] = 5012.0
    with pytest.raises(
        CommodityExecutionContractError,
        match="creation quote does not bind order price",
    ):
        _v3_plan(**fields)


def test_experimental_creation_proof_rejects_non_frozen_price_tick() -> None:
    fields = _v3_fields()
    fields["execution_run_id"] = EXPERIMENTAL_RUN_ID
    fields["creation_quote_proof"]["bindings"]["SHFE.ag2609"]["price_tick"] = 0.5
    fields["orders"][0]["price"] = 5005.5
    with pytest.raises(
        CommodityExecutionContractError,
        match="price tick mismatches frozen product spec",
    ):
        _v3_plan(**fields)


def test_experimental_adverse_limit_budget_accepts_exact_cny_30000() -> None:
    plan = _experimental_au_budget_plan(100)
    assert len(plan["orders"]) == 100


def test_experimental_adverse_limit_budget_rejects_over_cny_30000() -> None:
    with pytest.raises(
        CommodityExecutionContractError,
        match="adverse limit budget exceeds CNY 30000",
    ):
        _experimental_au_budget_plan(101)


def test_experimental_creation_proof_rejects_mixed_price_contracts() -> None:
    with pytest.raises(
        CommodityExecutionContractError,
        match="mixes price contracts",
    ):
        _mixed_experimental_plan()


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


@pytest.mark.parametrize(
    ("symbol", "price_tick", "reference_price", "limit_price", "normalized"),
    [
        ("au2609", 0.02, 5000.000000000001, 5000.32, 5000.0),
        ("sc2609", 0.1, 596.3000000000001, 596.7, 596.3),
    ],
)
def test_creation_and_start_quote_proofs_normalize_near_grid_machine_error(
    symbol: str,
    price_tick: float,
    reference_price: float,
    limit_price: float,
    normalized: float,
) -> None:
    plan = _experimental_near_grid_plan(
        symbol=symbol,
        price_tick=price_tick,
        reference_price=reference_price,
        limit_price=limit_price,
    )
    before = deepcopy(plan.raw)

    proof = build_execution_start_quote_proof(
        plan,
        reader=_Reader(reference_price=reference_price),
        clock=lambda: QUOTE_TIME,
    )

    binding = proof["bindings"][f"issue421-near-grid-{symbol}-0001"]
    assert binding["reference_price"] == normalized
    assert plan.raw == before
    assert plan.raw["orders"][0]["price"] == limit_price


@pytest.mark.parametrize(
    ("symbol", "price_tick", "reference_price", "limit_price", "off_grid"),
    [
        ("au2609", 0.02, 5000.0, 5000.32, 5000.0001),
        ("sc2609", 0.1, 596.3, 596.7, 596.300001),
    ],
)
def test_creation_and_start_quote_proofs_reject_real_off_grid_prices(
    symbol: str,
    price_tick: float,
    reference_price: float,
    limit_price: float,
    off_grid: float,
) -> None:
    with pytest.raises(CommodityExecutionContractError, match="creation quote price"):
        _experimental_near_grid_plan(
            symbol=symbol,
            price_tick=price_tick,
            reference_price=off_grid,
            limit_price=limit_price,
        )

    plan = _experimental_near_grid_plan(
        symbol=symbol,
        price_tick=price_tick,
        reference_price=reference_price,
        limit_price=limit_price,
    )
    proof = build_execution_start_quote_proof(
        plan,
        reader=_Reader(reference_price=reference_price),
        clock=lambda: QUOTE_TIME,
    )
    order_ref = f"issue421-near-grid-{symbol}-0001"
    proof["bindings"][order_ref]["reference_price"] = off_grid
    proof["proof_sha256"] = sha256_json(
        {key: item for key, item in proof.items() if key != "proof_sha256"}
    )
    with pytest.raises(ExecutionStartQuoteProofError, match="price/tick is invalid"):
        validate_execution_start_quote_proof(proof, plan=plan)
