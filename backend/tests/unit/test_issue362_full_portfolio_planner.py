from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from app.execution.executable_target_adapter import (
    ExecutableTargetAdapterError,
    StaticCoreEqualFullPortfolioQuoteInputBinding,
    StaticCoreEqualFullPortfolioQuoteRequirement,
    StaticCoreEqualFullPortfolioQuoteRequirements,
    build_full_portfolio_quote_requests,
    build_static_core_equal_full_portfolio_keyless_decision,
    full_portfolio_phase_plan_id_from_preimage,
    full_portfolio_phase_plan_id_from_payload,
)
from app.execution.formal_tick_reader import FormalTickRequest
from shared.commodity_execution import (
    FORMAL_QUOTE_PROOF_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    before_position_projection_hash,
    canonical_before_position_projection,
    canonical_target_position_projection,
    sha256_json,
    target_position_projection_hash,
)
from test_issue353_static_core_keyless import (
    _position_manager_snapshot,
    _snapshot,
    _static_outputs,
)

PRODUCTS = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
EVENT_GENERATED_AT = "2030-01-01T00:00:00Z"
_AUTO_QUOTES = object()
_AUTO_REQUIREMENTS = object()


def _targets(**overrides: int) -> dict[str, int]:
    return {product: overrides.get(product, 0) for product in PRODUCTS}


def _row_by_product(manager: dict) -> dict[str, dict]:
    return {row["product"]: row for row in manager["targets"]}


def _position(
    exact_contract: str,
    *,
    direction: str,
    volume: int,
    yd_volume: int = 0,
) -> tuple[str, dict]:
    exchange, symbol = exact_contract.split(".", 1)
    row = {
        "gateway_name": "CTP",
        "symbol": symbol,
        "exchange": exchange,
        "direction": direction,
        "volume": volume,
    }
    if exchange in {"SHFE", "INE"}:
        row["yd_volume"] = yd_volume
    return f"{symbol}.{exchange}.{direction}.fixture", row


def _formal_quote(
    exact_contract: str,
    *,
    price_side: str,
    price_tick: object,
    ingest_seq: int,
    received_at_utc: str = EVENT_GENERATED_AT,
) -> dict[str, object]:
    exchange, symbol = exact_contract.split(".", 1)
    tick = Decimal(str(price_tick))
    reference = tick * Decimal(100_000 + ingest_seq)
    return {
        "source": "windows-tick-wire-v1",
        "vt_symbol": f"{symbol}.{exchange}",
        "price_side": price_side,
        "stream_generation": "formal-generation-0001",
        "ingest_id": f"formal-ingest-{ingest_seq:04d}",
        "ingest_seq": ingest_seq,
        "event_hash": sha256_json(
            {
                "exact_contract": exact_contract,
                "price_side": price_side,
                "ingest_seq": ingest_seq,
            }
        ),
        "received_at_utc": received_at_utc,
        "reference_price": float(reference),
        "price_tick": float(tick),
    }


def _required_formal_quotes(
    manager: dict,
    positions: dict[str, dict],
    *,
    received_at_utc: str = EVENT_GENERATED_AT,
) -> dict[str, dict[str, object]]:
    rows = _row_by_product(manager)
    current: dict[str, tuple[str, int]] = {}
    for raw in positions.values():
        if raw["volume"] == 0:
            continue
        match = re.fullmatch(r"([A-Za-z]+)[0-9]{4}", str(raw["symbol"]))
        assert match is not None
        product = match.group(1).lower()
        quantity = raw["volume"] if raw["direction"] == "LONG" else -raw["volume"]
        current[product] = (f"{raw['exchange']}.{raw['symbol']}", quantity)

    close_required: dict[str, tuple[str, object]] = {}
    open_required: dict[str, tuple[str, object]] = {}

    def bind(
        required: dict[str, tuple[str, object]],
        contract: str,
        side: str,
        tick: object,
    ) -> None:
        prior = required.setdefault(contract, (side, tick))
        assert prior == (side, tick)

    for product in PRODUCTS:
        target = rows[product]
        target_contract = target["exact_contract"]
        target_quantity = target["shadow_target_quantity"]
        current_contract, current_quantity = current.get(product, ("", 0))
        same_contract = current_contract.upper() == target_contract.upper()
        if current_quantity:
            if (
                not same_contract
                or target_quantity == 0
                or current_quantity * target_quantity < 0
            ):
                close_count = abs(current_quantity)
            elif abs(current_quantity) > abs(target_quantity):
                close_count = abs(current_quantity) - abs(target_quantity)
            else:
                close_count = 0
            if close_count:
                bind(
                    close_required,
                    current_contract,
                    "bid" if current_quantity > 0 else "ask",
                    target["price_tick"],
                )
                current_quantity += (
                    -close_count if current_quantity > 0 else close_count
                )
                if current_quantity == 0:
                    current_contract = ""
        if current_contract and current_contract.upper() != target_contract.upper():
            raise AssertionError("test quote planner retained stale contract")
        delta = target_quantity - current_quantity
        if delta:
            bind(
                open_required,
                target_contract,
                "ask" if delta > 0 else "bid",
                target["price_tick"],
            )
    # A cycle with CLOSE work must not even consume the initial OPEN quote.
    # The fresh post-close cycle has no CLOSE work and therefore selects OPEN.
    required = close_required if close_required else open_required
    return {
        contract: _formal_quote(
            contract,
            price_side=side,
            price_tick=tick,
            ingest_seq=index,
            received_at_utc=received_at_utc,
        )
        for index, (contract, (side, tick)) in enumerate(
            sorted(required.items()), start=1
        )
    }


def _decision(
    *,
    selected: dict[str, int],
    positions: dict[str, dict] | None = None,
    quote_requirements: object = _AUTO_REQUIREMENTS,
    formal_quotes: object = _AUTO_QUOTES,
    quote_overrides: dict[str, dict[str, object]] | None = None,
    drop_quotes: set[str] | None = None,
    reconciliation: dict[str, object] | None = None,
    run_id: str = "issue362-full-portfolio-0001",
    event_generated_at: str = EVENT_GENERATED_AT,
    expires_at: str | None = "2099-01-01T00:00:00Z",
    now: datetime = NOW,
    target_plan_version: int = 2,
):
    projection, freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=selected)
    current_positions = {} if positions is None else positions
    normalized_reconciliation = (
        {"state": "RECONCILED", "unknown_outcomes": 0}
        if reconciliation is None
        else reconciliation
    )
    requirements = (
        build_full_portfolio_quote_requests(
            static_core_equal_projection=projection,
            static_core_equal_freeze_contract=freeze,
            static_core_equal_target_evidence=target,
            position_manager_snapshot=manager,
            position_manager_sha256=sha256_json(manager),
            current_facts=_snapshot(current_positions),
            reconciliation=normalized_reconciliation,
            run_id=run_id,
            event_generated_at=event_generated_at,
            now=now,
            target_plan_version=target_plan_version,
        )
        if quote_requirements is _AUTO_REQUIREMENTS
        else quote_requirements
    )
    quotes = (
        _required_formal_quotes(
            manager,
            current_positions,
            received_at_utc=event_generated_at,
        )
        if formal_quotes is _AUTO_QUOTES
        else formal_quotes
    )
    if isinstance(quotes, dict):
        quotes = deepcopy(quotes)
        for contract, override in (quote_overrides or {}).items():
            quotes[contract].update(override)
        for contract in drop_quotes or set():
            quotes.pop(contract, None)
    return build_static_core_equal_full_portfolio_keyless_decision(
        static_core_equal_projection=projection,
        static_core_equal_freeze_contract=freeze,
        static_core_equal_target_evidence=target,
        position_manager_snapshot=manager,
        position_manager_sha256=sha256_json(manager),
        current_facts=_snapshot(current_positions),
        reconciliation=normalized_reconciliation,
        quote_requirements=requirements,
        formal_quotes_by_exact_contract=quotes,
        run_id=run_id,
        event_generated_at=event_generated_at,
        expires_at=expires_at,
        now=now,
        target_plan_version=target_plan_version,
    )


def _requirements(
    *,
    selected: dict[str, int],
    positions: dict[str, dict] | None = None,
    run_id: str = "issue362-full-portfolio-0001",
    event_generated_at: str = EVENT_GENERATED_AT,
    now: datetime = NOW,
    target_plan_version: int = 2,
):
    projection, freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=selected)
    result = build_full_portfolio_quote_requests(
        static_core_equal_projection=projection,
        static_core_equal_freeze_contract=freeze,
        static_core_equal_target_evidence=target,
        position_manager_snapshot=manager,
        position_manager_sha256=sha256_json(manager),
        current_facts=_snapshot({} if positions is None else positions),
        reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
        run_id=run_id,
        event_generated_at=event_generated_at,
        now=now,
        target_plan_version=target_plan_version,
    )
    return result, manager


def _quotes_for_requirements(requirements) -> dict[str, dict[str, object]]:
    return {
        row.exact_contract: _formal_quote(
            row.exact_contract,
            price_side=row.request.price_side,
            price_tick=row.request.price_tick,
            ingest_seq=index,
        )
        for index, row in enumerate(requirements.requirements, start=1)
    }


def test_full_portfolio_mixed_delta_defers_open_until_fresh_second_cycle() -> None:
    projection, _freeze, target = _static_outputs()
    del projection
    manager = _position_manager_snapshot(
        target,
        selected=_targets(ag=0, al=1, au=3, bu=-2, cu=2, rb=1),
    )
    rows = _row_by_product(manager)
    old_cu_contract = rows["cu"]["exact_contract"][:-2] + "09"
    positions = dict(
        [
            _position(rows["ag"]["exact_contract"], direction="LONG", volume=2),
            _position(
                rows["al"]["exact_contract"],
                direction="LONG",
                volume=3,
                yd_volume=1,
            ),
            _position(
                rows["au"]["exact_contract"],
                direction="LONG",
                volume=1,
                yd_volume=1,
            ),
            _position(rows["bu"]["exact_contract"], direction="LONG", volume=1),
            _position(
                old_cu_contract,
                direction="LONG",
                volume=2,
                yd_volume=1,
            ),
            _position(
                rows["rb"]["exact_contract"],
                direction="LONG",
                volume=1,
                yd_volume=1,
            ),
        ]
    )
    original_positions = deepcopy(positions)

    decision = _decision(
        selected=_targets(ag=0, al=1, au=3, bu=-2, cu=2, rb=1),
        positions=positions,
    )

    assert decision.noop is False
    assert positions == original_positions
    assert decision.close_handoff is not None
    assert decision.open_handoff is None
    assert decision.deferred_open_intent is not None
    assert decision.close_order_count == 7
    assert decision.open_order_count == 0
    assert decision.deferred_open_order_count == 6
    assert len(decision.handoffs) == 1

    close = decision.close_handoff.target_plan
    assert close["schema_version"] == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
    assert close["phase"] == "CLOSE"
    deferred = decision.deferred_open_intent.template
    assert deferred["custody_allowed"] is False
    assert deferred["executable"] is False
    assert deferred["expected_post_close_before_position_hash"] == (
        decision.phase_boundary.open_expected_before_position_hash
    )
    assert "formal_quote_bindings" not in deferred
    assert "expires_at" not in deferred
    assert not hasattr(
        decision.deferred_open_intent, "trusted_keyless_custody_artifact"
    )
    assert close["expected_before_position_hash"] == (
        decision.current_before_position_hash
    )
    assert decision.current_target_position_hash == target_position_projection_hash(
        positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    assert close["expected_after_position_hash"] == (
        decision.phase_boundary.close_expected_after_position_hash
    )

    boundary = decision.phase_boundary
    assert boundary.target_projection == canonical_target_position_projection(
        boundary.positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    assert boundary.before_projection == canonical_before_position_projection(
        boundary.positions,
        account_scope="account:windows",
        environment="SIMNOW",
    )
    assert boundary.close_expected_after_position_hash == (
        target_position_projection_hash(
            boundary.positions,
            account_scope="account:windows",
            environment="SIMNOW",
        )
    )
    assert boundary.open_expected_before_position_hash == (
        before_position_projection_hash(
            boundary.positions,
            account_scope="account:windows",
            environment="SIMNOW",
        )
    )
    # Existing v2 runtime deliberately uses two different canonical hash
    # semantics around a non-flat SHFE/INE boundary.
    assert (
        boundary.close_expected_after_position_hash
        != boundary.open_expected_before_position_hash
    )

    second = _decision(
        selected=_targets(ag=0, al=1, au=3, bu=-2, cu=2, rb=1),
        positions=deepcopy(boundary.positions),
        run_id="issue362-full-portfolio-0001",
        event_generated_at="2030-01-01T00:00:01Z",
        now=NOW + timedelta(seconds=1),
    )
    assert second.close_handoff is None
    assert second.open_handoff is not None
    assert second.deferred_open_intent is None
    assert second.close_order_count == 0
    assert second.open_order_count == 6
    assert second.deferred_open_order_count == 0
    assert second.handoffs == (second.open_handoff,)
    open_ = second.open_handoff.target_plan
    assert open_["schema_version"] == KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
    assert open_["phase"] == "OPEN"
    assert open_["expected_before_position_hash"] == (
        boundary.open_expected_before_position_hash
    )
    assert open_["expected_after_position_hash"] == second.final_position_hash

    all_orders = close["orders"] + open_["orders"]
    assert {order["volume"] for order in all_orders} == {1}
    references = [order["reference"] for order in all_orders]
    assert len(references) == len(set(references))
    assert not any(order["symbol"].startswith("rb") for order in all_orders)
    assert sum(order["symbol"].startswith("cu") for order in close["orders"]) == 2
    assert sum(order["symbol"].startswith("cu") for order in open_["orders"]) == 2
    assert {order["offset"] for order in close["orders"]} <= {
        "CLOSE",
        "CLOSETODAY",
        "CLOSEYESTERDAY",
    }
    assert {order["offset"] for order in open_["orders"]} == {"OPEN"}
    for plan, source in ((close, decision), (open_, second)):
        assert plan["production_allowed"] is False
        assert plan["live_trading_authorized"] is False
        assert plan["countable_forward"] is False
        assert plan["lineage"] == {
            "static_core_equal_sha256": source.static_core_equal_sha256,
            "position_manager_sha256": source.position_manager_sha256,
            "final_target_sha256": source.final_target_sha256,
        }


@pytest.mark.parametrize(
    ("selected", "positions"),
    [
        (_targets(), {}),
        (
            _targets(ag=1, au=-1),
            None,
        ),
    ],
)
def test_full_portfolio_true_noop_has_no_handoff(
    selected: dict[str, int], positions: dict[str, dict] | None
) -> None:
    if positions is None:
        _projection, _freeze, target = _static_outputs()
        manager = _position_manager_snapshot(target, selected=selected)
        rows = _row_by_product(manager)
        positions = dict(
            [
                _position(rows["ag"]["exact_contract"], direction="LONG", volume=1),
                _position(rows["au"]["exact_contract"], direction="SHORT", volume=1),
            ]
        )

    decision = _decision(
        selected=selected,
        positions=positions,
        formal_quotes={},
        expires_at=None,
    )

    assert decision.noop is True
    assert decision.close_handoff is None
    assert decision.open_handoff is None
    assert decision.deferred_open_intent is None
    assert decision.handoffs == ()
    assert decision.close_order_count == 0
    assert decision.open_order_count == 0
    assert decision.deferred_open_order_count == 0


def test_full_portfolio_open_only_and_close_only_are_independent_plans() -> None:
    open_only = _decision(selected=_targets(ag=2))
    assert open_only.close_handoff is None
    assert open_only.open_handoff is not None
    assert open_only.deferred_open_intent is None
    assert open_only.open_order_count == 2

    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets())
    ag = _row_by_product(manager)["ag"]
    positions = dict(
        [_position(ag["exact_contract"], direction="LONG", volume=2, yd_volume=1)]
    )
    close_only = _decision(selected=_targets(), positions=positions)
    assert close_only.close_handoff is not None
    assert close_only.open_handoff is None
    assert close_only.deferred_open_intent is None
    assert close_only.close_order_count == 2
    assert close_only.close_handoff.target_plan["expected_after_position_hash"] == (
        target_position_projection_hash(
            {}, account_scope="account:windows", environment="SIMNOW"
        )
    )


@pytest.mark.parametrize(
    (
        "product",
        "current_quantity",
        "target_quantity",
        "roll",
        "expected_phase",
        "expected_side",
        "expected_order_count",
        "expected_deferred_open_count",
    ),
    [
        ("ag", 0, 0, False, None, None, 0, 0),
        ("ag", 0, 2, False, "OPEN", "ask", 2, 0),
        ("ag", 1, 3, False, "OPEN", "ask", 2, 0),
        ("ag", 3, 1, False, "CLOSE", "bid", 2, 0),
        ("au", -2, 2, False, "CLOSE", "ask", 2, 2),
        ("cu", 2, 2, True, "CLOSE", "bid", 2, 2),
        ("sc", -3, 0, False, "CLOSE", "ask", 3, 0),
    ],
)
def test_quote_requirements_use_the_exact_planner_delta_and_immediate_phase(
    product: str,
    current_quantity: int,
    target_quantity: int,
    roll: bool,
    expected_phase: str | None,
    expected_side: str | None,
    expected_order_count: int,
    expected_deferred_open_count: int,
) -> None:
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(
        target, selected=_targets(**{product: target_quantity})
    )
    target_row = _row_by_product(manager)[product]
    current_contract = (
        target_row["exact_contract"][:-2] + "09"
        if roll
        else target_row["exact_contract"]
    )
    positions = {}
    if current_quantity:
        positions = dict(
            [
                _position(
                    current_contract,
                    direction="LONG" if current_quantity > 0 else "SHORT",
                    volume=abs(current_quantity),
                    yd_volume=min(1, abs(current_quantity)),
                )
            ]
        )

    requirements, _manager = _requirements(
        selected=_targets(**{product: target_quantity}), positions=positions
    )

    assert requirements.phase == expected_phase
    assert requirements.noop is (expected_phase is None)
    assert requirements.deferred_open_order_count == expected_deferred_open_count
    if expected_phase is None:
        assert requirements.requirements == ()
        assert requirements.requests == ()
        decision = _decision(
            selected=_targets(**{product: target_quantity}),
            positions=positions,
            formal_quotes={},
            expires_at=None,
        )
        assert decision.noop is True
        return

    assert len(requirements.requirements) == 1
    requirement = requirements.requirements[0]
    expected_contract = (
        current_contract if expected_phase == "CLOSE" else target_row["exact_contract"]
    )
    exchange, symbol = expected_contract.split(".", 1)
    assert requirement.phase == expected_phase
    assert requirement.product == product
    assert requirement.exact_contract == expected_contract
    assert requirement.request.vt_symbol == f"{symbol}.{exchange}"
    assert requirement.request.price_side == expected_side
    assert requirement.request.price_tick == float(target_row["price_tick"])
    assert len(requirement.order_references) == expected_order_count
    assert requirements.requests == (requirement.request,)

    decision = _decision(
        selected=_targets(**{product: target_quantity}),
        positions=positions,
        formal_quotes=_quotes_for_requirements(requirements),
    )
    handoff = (
        decision.close_handoff if expected_phase == "CLOSE" else decision.open_handoff
    )
    assert handoff is not None
    actual_references = tuple(
        order["reference"]
        for order in handoff.target_plan["orders"]
        if f"{order['exchange']}.{order['symbol']}" == expected_contract
    )
    assert actual_references == requirement.order_references


def test_close_requirements_defer_roll_open_until_fresh_post_close_facts() -> None:
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets(cu=2))
    cu = _row_by_product(manager)["cu"]
    old_contract = cu["exact_contract"][:-2] + "09"
    positions = dict([_position(old_contract, direction="LONG", volume=2, yd_volume=1)])
    close_requirements, _manager = _requirements(
        selected=_targets(cu=2), positions=positions
    )
    assert close_requirements.phase == "CLOSE"
    assert [row.exact_contract for row in close_requirements.requirements] == [
        old_contract
    ]
    assert close_requirements.deferred_open_order_count == 2

    close_decision = _decision(
        selected=_targets(cu=2),
        positions=positions,
        formal_quotes=_quotes_for_requirements(close_requirements),
    )
    open_requirements, _manager = _requirements(
        selected=_targets(cu=2),
        positions=deepcopy(close_decision.phase_boundary.positions),
        event_generated_at="2030-01-01T00:00:01Z",
        now=NOW + timedelta(seconds=1),
    )
    assert open_requirements.phase == "OPEN"
    assert [row.exact_contract for row in open_requirements.requirements] == [
        cu["exact_contract"]
    ]
    assert open_requirements.requirements[0].request.price_side == "ask"
    assert len(open_requirements.requirements[0].order_references) == 2
    assert open_requirements.deferred_open_order_count == 0


def test_quote_requirements_are_sorted_deduplicated_and_match_all_final_orders() -> (
    None
):
    selected = _targets(ag=2, cu=-3, sc=1)
    requirements, _manager = _requirements(selected=selected)
    assert requirements.phase == "OPEN"
    contracts = [row.exact_contract for row in requirements.requirements]
    assert contracts == sorted(contracts)
    assert len(contracts) == len(set(contracts)) == 3
    assert sum(len(row.order_references) for row in requirements.requirements) == 6

    decision = _decision(
        selected=selected,
        formal_quotes=_quotes_for_requirements(requirements),
    )
    assert decision.open_handoff is not None
    required_references = {
        reference
        for row in requirements.requirements
        for reference in row.order_references
    }
    actual_references = {
        order["reference"] for order in decision.open_handoff.target_plan["orders"]
    }
    assert actual_references == required_references


def test_planner_rejects_any_deviation_from_the_quote_requirement_batch() -> None:
    requirements, manager = _requirements(selected=_targets(ag=2))
    quotes = _quotes_for_requirements(requirements)
    requirement = requirements.requirements[0]
    contract = requirement.exact_contract

    with pytest.raises(ExecutableTargetAdapterError, match="formal quote is missing"):
        _decision(selected=_targets(ag=2), formal_quotes={})

    extra = deepcopy(quotes)
    cu = _row_by_product(manager)["cu"]
    extra[cu["exact_contract"]] = _formal_quote(
        cu["exact_contract"],
        price_side="ask",
        price_tick=cu["price_tick"],
        ingest_seq=99,
    )
    with pytest.raises(ExecutableTargetAdapterError, match="contract set is not exact"):
        _decision(selected=_targets(ag=2), formal_quotes=extra)

    wrong_side = deepcopy(quotes)
    wrong_side[contract]["price_side"] = "bid"
    with pytest.raises(ExecutableTargetAdapterError, match="identity is invalid"):
        _decision(selected=_targets(ag=2), formal_quotes=wrong_side)

    wrong_tick = deepcopy(quotes)
    wrong_tick[contract]["price_tick"] = requirement.request.price_tick * 2
    with pytest.raises(
        ExecutableTargetAdapterError, match="frozen product price tick mismatch"
    ):
        _decision(selected=_targets(ag=2), formal_quotes=wrong_tick)


def test_planner_rejects_requirements_from_different_target_run_or_phase() -> None:
    one_lot, _manager = _requirements(selected=_targets(ag=1))
    one_lot_quotes = _quotes_for_requirements(one_lot)
    with pytest.raises(ExecutableTargetAdapterError, match="requirements do not match"):
        _decision(
            selected=_targets(ag=2),
            quote_requirements=one_lot,
            formal_quotes=one_lot_quotes,
        )
    with pytest.raises(ExecutableTargetAdapterError, match="requirements do not match"):
        _decision(
            selected=_targets(ag=1),
            run_id="issue362-full-run-different-0001",
            quote_requirements=one_lot,
            formal_quotes=one_lot_quotes,
        )

    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets(ag=1))
    ag = _row_by_product(manager)["ag"]
    positions = dict([_position(ag["exact_contract"], direction="LONG", volume=2)])
    close_requirements, _manager = _requirements(
        selected=_targets(ag=1), positions=positions
    )
    assert close_requirements.phase == "CLOSE"
    with pytest.raises(ExecutableTargetAdapterError, match="requirements do not match"):
        _decision(
            selected=_targets(ag=1),
            positions=positions,
            quote_requirements=one_lot,
            formal_quotes=_quotes_for_requirements(close_requirements),
        )
    with pytest.raises(ValueError, match="intent binding is inconsistent"):
        StaticCoreEqualFullPortfolioQuoteRequirements(
            phase="CLOSE",
            requirements=close_requirements.requirements,
            deferred_open_order_count=1,
            input_binding=close_requirements.input_binding,
        )


def test_quote_requirements_bind_same_shape_open_to_exact_inputs() -> None:
    flat_two, _manager = _requirements(selected=_targets(ag=2))
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets(ag=3))
    ag = _row_by_product(manager)["ag"]
    one_long = dict(
        [_position(ag["exact_contract"], direction="LONG", volume=1, yd_volume=0)]
    )
    one_to_three, _manager = _requirements(selected=_targets(ag=3), positions=one_long)

    assert flat_two.phase == one_to_three.phase == "OPEN"
    assert flat_two.requirements == one_to_three.requirements
    assert flat_two.input_binding.current_before_position_hash != (
        one_to_three.input_binding.current_before_position_hash
    )
    assert flat_two.input_binding.desired_target_sha256 != (
        one_to_three.input_binding.desired_target_sha256
    )
    assert flat_two.quote_requirements_sha256 != (
        one_to_three.quote_requirements_sha256
    )
    with pytest.raises(ExecutableTargetAdapterError, match="requirements do not match"):
        _decision(
            selected=_targets(ag=3),
            positions=one_long,
            quote_requirements=flat_two,
            formal_quotes=_quotes_for_requirements(flat_two),
        )


def test_close_requirements_bind_exact_deferred_open_intent() -> None:
    _projection, _freeze, target = _static_outputs()
    ag_manager = _position_manager_snapshot(target, selected=_targets(ag=-1))
    ag = _row_by_product(ag_manager)["ag"]
    one_long = dict(
        [_position(ag["exact_contract"], direction="LONG", volume=1, yd_volume=0)]
    )
    deferred_ag, _manager = _requirements(selected=_targets(ag=-1), positions=one_long)
    deferred_au, _manager = _requirements(selected=_targets(au=-1), positions=one_long)

    assert deferred_ag.phase == deferred_au.phase == "CLOSE"
    assert deferred_ag.requirements == deferred_au.requirements
    assert deferred_ag.deferred_open_order_count == 1
    assert deferred_au.deferred_open_order_count == 1
    assert deferred_ag.input_binding.phase_boundary_sha256 == (
        deferred_au.input_binding.phase_boundary_sha256
    )
    assert deferred_ag.input_binding.deferred_open_intent_sha256 != (
        deferred_au.input_binding.deferred_open_intent_sha256
    )
    assert deferred_ag.quote_requirements_sha256 != (
        deferred_au.quote_requirements_sha256
    )
    with pytest.raises(ExecutableTargetAdapterError, match="requirements do not match"):
        _decision(
            selected=_targets(au=-1),
            positions=one_long,
            quote_requirements=deferred_ag,
            formal_quotes=_quotes_for_requirements(deferred_ag),
        )


def test_planner_requires_exact_noop_requirements_and_empty_quote_batch() -> None:
    noop, _manager = _requirements(selected=_targets())
    assert noop.noop is True
    assert _decision(
        selected=_targets(), quote_requirements=noop, formal_quotes={}
    ).noop
    with pytest.raises(ExecutableTargetAdapterError, match="contract set is not exact"):
        _decision(
            selected=_targets(),
            quote_requirements=noop,
            formal_quotes={"SHFE.ag2609": {}},
        )
    with pytest.raises(ExecutableTargetAdapterError, match="contract set is not exact"):
        _decision(selected=_targets(), quote_requirements=noop, formal_quotes=None)


def test_quote_requirement_dtos_reject_mutable_containers_and_subclasses() -> None:
    requirements, _manager = _requirements(selected=_targets(ag=1))
    row = requirements.requirements[0]
    with pytest.raises(ValueError, match="orders are invalid"):
        StaticCoreEqualFullPortfolioQuoteRequirement(
            phase=row.phase,
            product=row.product,
            exact_contract=row.exact_contract,
            request=row.request,
            order_references=list(row.order_references),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="requirements are invalid"):
        StaticCoreEqualFullPortfolioQuoteRequirements(
            phase="OPEN",
            requirements=[row],  # type: ignore[arg-type]
            deferred_open_order_count=0,
            input_binding=requirements.input_binding,
        )

    class ForeignFormalTickRequest(FormalTickRequest):
        pass

    with pytest.raises(ValueError, match="request is invalid"):
        StaticCoreEqualFullPortfolioQuoteRequirement(
            phase=row.phase,
            product=row.product,
            exact_contract=row.exact_contract,
            request=ForeignFormalTickRequest(
                vt_symbol=row.request.vt_symbol,
                price_side=row.request.price_side,
                price_tick=row.request.price_tick,
            ),
            order_references=row.order_references,
        )

    class ForeignRequirement(StaticCoreEqualFullPortfolioQuoteRequirement):
        pass

    foreign_row = ForeignRequirement(
        phase=row.phase,
        product=row.product,
        exact_contract=row.exact_contract,
        request=row.request,
        order_references=row.order_references,
    )
    with pytest.raises(ValueError, match="requirements are invalid"):
        StaticCoreEqualFullPortfolioQuoteRequirements(
            phase="OPEN",
            requirements=(foreign_row,),
            deferred_open_order_count=0,
            input_binding=requirements.input_binding,
        )

    class ForeignRequirements(StaticCoreEqualFullPortfolioQuoteRequirements):
        pass

    foreign_requirements = ForeignRequirements(
        phase=requirements.phase,
        requirements=requirements.requirements,
        deferred_open_order_count=requirements.deferred_open_order_count,
        input_binding=requirements.input_binding,
    )
    with pytest.raises(ExecutableTargetAdapterError, match="requirements are required"):
        _decision(
            selected=_targets(ag=1),
            quote_requirements=foreign_requirements,
            formal_quotes=_quotes_for_requirements(requirements),
        )

    class ForeignInputBinding(StaticCoreEqualFullPortfolioQuoteInputBinding):
        pass

    binding = requirements.input_binding
    foreign_binding = ForeignInputBinding(
        static_core_equal_projection_sha256=(
            binding.static_core_equal_projection_sha256
        ),
        static_core_equal_freeze_contract_sha256=(
            binding.static_core_equal_freeze_contract_sha256
        ),
        static_core_equal_target_evidence_sha256=(
            binding.static_core_equal_target_evidence_sha256
        ),
        position_manager_sha256=binding.position_manager_sha256,
        current_before_position_hash=binding.current_before_position_hash,
        desired_target_sha256=binding.desired_target_sha256,
        reconciliation_sha256=binding.reconciliation_sha256,
        phase_boundary_sha256=binding.phase_boundary_sha256,
        deferred_open_intent_sha256=binding.deferred_open_intent_sha256,
        run_id=binding.run_id,
        event_generated_at=binding.event_generated_at,
        target_plan_version=binding.target_plan_version,
    )
    with pytest.raises(ValueError, match="input binding is invalid"):
        StaticCoreEqualFullPortfolioQuoteRequirements(
            phase=requirements.phase,
            requirements=requirements.requirements,
            deferred_open_order_count=requirements.deferred_open_order_count,
            input_binding=foreign_binding,
        )


def test_roll_binds_exact_formal_quotes_and_derives_protected_sides() -> None:
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets(cu=1))
    cu = _row_by_product(manager)["cu"]
    old_contract = cu["exact_contract"][:-2] + "09"
    positions = dict([_position(old_contract, direction="LONG", volume=1, yd_volume=0)])

    decision = _decision(
        selected=_targets(cu=1),
        positions=positions,
    )
    assert decision.close_handoff is not None
    assert decision.open_handoff is None
    assert decision.deferred_open_intent is not None
    close_binding = decision.close_formal_quote_bindings[old_contract]
    assert set(decision.close_formal_quote_bindings) == {old_contract}
    assert close_binding["price_side"] == "bid"
    assert decision.open_formal_quote_bindings == {}
    tick = Decimal(str(cu["price_tick"]))
    assert decision.deferred_open_intent.template["intents"] == [
        {
            "product": "cu",
            "exact_contract": cu["exact_contract"],
            "direction": "LONG",
            "volume": 1,
            "price_side": "ask",
            "frozen_product_price_tick": cu["price_tick"],
        }
    ]
    assert (
        Decimal(str(decision.close_handoff.target_plan["orders"][0]["price"]))
        == Decimal(str(close_binding["reference_price"])) - tick
    )

    second = _decision(
        selected=_targets(cu=1),
        positions=deepcopy(decision.phase_boundary.positions),
        event_generated_at="2030-01-01T00:00:01Z",
        now=NOW + timedelta(seconds=1),
    )
    assert second.close_handoff is None
    assert second.open_handoff is not None
    assert second.deferred_open_intent is None
    open_binding = second.open_formal_quote_bindings[cu["exact_contract"]]
    assert open_binding["price_side"] == "ask"
    assert (
        Decimal(str(second.open_handoff.target_plan["orders"][0]["price"]))
        == Decimal(str(open_binding["reference_price"])) + tick
    )

    with pytest.raises(
        ExecutableTargetAdapterError, match="frozen product price tick mismatch"
    ):
        _decision(
            selected=_targets(cu=1),
            positions=deepcopy(decision.phase_boundary.positions),
            event_generated_at="2030-01-01T00:00:01Z",
            now=NOW + timedelta(seconds=1),
            quote_overrides={
                cu["exact_contract"]: {"price_tick": cu["price_tick"] * 2}
            },
        )


def test_quote_aware_v3_is_explicit_and_close_still_defers_open() -> None:
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets(cu=1))
    cu = _row_by_product(manager)["cu"]
    old_contract = cu["exact_contract"][:-2] + "09"
    positions = dict([_position(old_contract, direction="LONG", volume=1, yd_volume=0)])

    default = _decision(selected=_targets(cu=1), positions=positions)
    explicit_v3 = _decision(
        selected=_targets(cu=1),
        positions=positions,
        target_plan_version=3,
    )

    assert default.close_handoff is not None
    assert default.close_handoff.target_plan["schema_version"] == (
        KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
    )
    assert default.close_handoff.identity_preimage is not None
    assert "creation_quote_proof" not in default.close_handoff.target_plan
    assert "execution_run_id" not in default.close_handoff.target_plan

    assert explicit_v3.close_handoff is not None
    assert explicit_v3.open_handoff is None
    assert explicit_v3.deferred_open_intent is not None
    handoff = explicit_v3.close_handoff
    plan = handoff.target_plan
    assert plan["schema_version"] == KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    assert plan["execution_run_id"] == "issue362-full-portfolio-0001"
    assert plan["creation_quote_proof"] == {
        "schema_version": FORMAL_QUOTE_PROOF_SCHEMA_VERSION,
        "validated_at_utc": EVENT_GENERATED_AT,
        "max_age_seconds": 2,
        "future_skew_seconds": 2,
        "journal_authenticated": False,
        "start_authorized": False,
        "bindings": explicit_v3.close_formal_quote_bindings,
    }
    assert handoff.identity_preimage is None
    assert full_portfolio_phase_plan_id_from_payload(plan) == plan["plan_id"]
    assert handoff.recompute_plan_id() == plan["plan_id"]
    assert handoff.trusted_keyless_custody_artifact()["schema_ref"] == (
        KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
    )
    assert "creation_quote_proof" not in explicit_v3.deferred_open_intent.template
    assert explicit_v3.deferred_open_intent.custody_allowed is False


def test_roll_quote_binding_requires_exact_frozen_tick_identity_and_freshness() -> None:
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets(cu=1))
    cu = _row_by_product(manager)["cu"]
    old_contract = cu["exact_contract"][:-2] + "09"
    positions = dict([_position(old_contract, direction="LONG", volume=1, yd_volume=0)])

    with pytest.raises(ExecutableTargetAdapterError, match="formal quote is missing"):
        _decision(
            selected=_targets(cu=1),
            positions=positions,
            drop_quotes={old_contract},
        )

    with pytest.raises(
        ExecutableTargetAdapterError, match="frozen product price tick mismatch"
    ):
        _decision(
            selected=_targets(cu=1),
            positions=positions,
            quote_overrides={old_contract: {"price_tick": cu["price_tick"] * 2}},
        )

    with pytest.raises(ExecutableTargetAdapterError, match="stale or from the future"):
        _decision(
            selected=_targets(cu=1),
            positions=positions,
            quote_overrides={old_contract: {"received_at_utc": "2029-12-31T23:59:57Z"}},
        )

    with pytest.raises(ExecutableTargetAdapterError, match="identity is invalid"):
        _decision(
            selected=_targets(cu=1),
            positions=positions,
            quote_overrides={old_contract: {"price_side": "ask"}},
        )


def test_ambiguous_or_out_of_universe_portfolio_fails_closed() -> None:
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets(ag=1))
    ag = _row_by_product(manager)["ag"]
    second_ag = ag["exact_contract"][:-2] + "09"
    split = dict(
        [
            _position(ag["exact_contract"], direction="LONG", volume=1),
            _position(second_ag, direction="LONG", volume=1),
        ]
    )
    with pytest.raises(ExecutableTargetAdapterError, match="split, hedged"):
        _decision(selected=_targets(ag=1), positions=split)

    key, outside = _position("DCE.i2609", direction="LONG", volume=1)
    with pytest.raises(ExecutableTargetAdapterError, match="outside the frozen"):
        _decision(selected=_targets(), positions={key: outside})

    key, wrong_exchange = _position(
        "INE.ag2609", direction="LONG", volume=1, yd_volume=0
    )
    with pytest.raises(ExecutableTargetAdapterError, match="unexpected exchange"):
        _decision(selected=_targets(), positions={key: wrong_exchange})

    projection, freeze, target = (deepcopy(item) for item in _static_outputs())
    target_ag = next(row for row in target["targets"] if row["product"] == "ag")
    target_ag["exact_contract"] = target_ag["exact_contract"].replace(
        "SHFE.", "INE.", 1
    )
    for digest in projection["artifact_digests"]:
        if digest["role"] == "target_evidence":
            digest["sha256"] = sha256_json(target)
            break
    else:  # pragma: no cover - fixture contract
        raise AssertionError("target evidence digest is missing")
    manager = _position_manager_snapshot(target, selected=_targets(ag=1))
    noop_requirements, _noop_manager = _requirements(selected=_targets())
    with pytest.raises(ExecutableTargetAdapterError, match="does not match product"):
        build_static_core_equal_full_portfolio_keyless_decision(
            static_core_equal_projection=projection,
            static_core_equal_freeze_contract=freeze,
            static_core_equal_target_evidence=target,
            position_manager_snapshot=manager,
            position_manager_sha256=sha256_json(manager),
            current_facts=_snapshot({}),
            reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
            quote_requirements=noop_requirements,
            formal_quotes_by_exact_contract=None,
            run_id="target-exchange-mismatch-0001",
            event_generated_at=EVENT_GENERATED_AT,
            now=NOW,
        )


def test_unknown_outcome_blocks_full_portfolio_planning() -> None:
    with pytest.raises(ExecutableTargetAdapterError, match="unknown or unreconciled"):
        _decision(
            selected=_targets(ag=1),
            reconciliation={"state": "RECONCILED", "unknown_outcomes": 1},
        )


def test_fresh_run_changes_only_execution_identity() -> None:
    first = _decision(selected=_targets(ag=2), run_id="issue362-full-run-0001")
    second = _decision(selected=_targets(ag=2), run_id="issue362-full-run-0002")
    assert first.open_handoff is not None and second.open_handoff is not None
    assert first.static_core_equal_sha256 == second.static_core_equal_sha256
    assert first.position_manager_sha256 == second.position_manager_sha256
    assert first.final_target_sha256 == second.final_target_sha256
    assert first.final_target_projection == second.final_target_projection
    assert (
        first.open_handoff.target_plan["plan_id"]
        != second.open_handoff.target_plan["plan_id"]
    )
    assert (
        first.open_handoff.target_plan["orders"][0]["reference"]
        != second.open_handoff.target_plan["orders"][0]["reference"]
    )


def test_same_event_is_byte_identical_and_all_plan_material_changes_identity() -> None:
    first = _decision(selected=_targets(ag=2), run_id="stable-event-run-0001")
    replay = _decision(
        selected=_targets(ag=2),
        run_id="stable-event-run-0001",
        now=NOW + timedelta(seconds=1),
    )
    assert first.open_handoff is not None and replay.open_handoff is not None
    assert first.open_handoff.target_plan == replay.open_handoff.target_plan
    assert first.open_handoff.identity_preimage == replay.open_handoff.identity_preimage
    assert sha256_json(first.open_handoff.target_plan) == (
        "eefbdf7d244ae3a88c34414a3f4f4dcbe028039276b3b6b1fd115b9887844b69"
    )
    assert sha256_json(first.open_handoff.identity_preimage) == (
        "cf3704b69da27f312b95b5ca6292c729aeb89fd09b7fdaaaeeb22f86b8253e77"
    )
    assert (
        first.open_handoff.recompute_plan_id()
        == (first.open_handoff.target_plan["plan_id"])
    )
    assert (
        full_portfolio_phase_plan_id_from_preimage(first.open_handoff.identity_preimage)
        == first.open_handoff.target_plan["plan_id"]
    )

    expiry_changed = _decision(
        selected=_targets(ag=2),
        run_id="stable-event-run-0001",
        expires_at="2099-02-01T00:00:00Z",
    )
    generated_changed = _decision(
        selected=_targets(ag=2),
        run_id="stable-event-run-0001",
        event_generated_at="2030-01-01T00:00:01Z",
    )
    quote_changed = _decision(
        selected=_targets(ag=2),
        run_id="stable-event-run-0001",
        quote_overrides={
            next(iter(first.open_formal_quote_bindings)): {"event_hash": "d" * 64}
        },
    )
    variants = (expiry_changed, generated_changed, quote_changed)
    assert all(item.open_handoff is not None for item in variants)
    assert (
        len(
            {
                first.open_handoff.target_plan["plan_id"],
                *(item.open_handoff.target_plan["plan_id"] for item in variants),
            }
        )
        == 4
    )


def test_phase_identity_preimage_is_detached_and_cannot_hide_quote_tamper() -> None:
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets(ag=1))
    quotes = _required_formal_quotes(manager, {})
    decision = _decision(selected=_targets(ag=1), formal_quotes=quotes)
    assert decision.open_handoff is not None
    handoff = decision.open_handoff
    assert handoff.identity_preimage is not None
    saved = deepcopy(handoff.identity_preimage)

    quote = next(iter(quotes.values()))
    quote["event_hash"] = "e" * 64
    assert handoff.identity_preimage == saved
    assert handoff.recompute_plan_id() == handoff.target_plan["plan_id"]
    assert handoff.validate_identity_proof() == handoff.target_plan["plan_id"]
    assert handoff.trusted_keyless_custody_artifact()["payload"] == (
        handoff.target_plan
    )

    tampered = deepcopy(handoff.identity_preimage)
    binding = next(iter(tampered["formal_quote_bindings"].values()))
    binding["event_hash"] = "f" * 64
    assert (
        full_portfolio_phase_plan_id_from_preimage(tampered)
        != (handoff.target_plan["plan_id"])
    )
    tampered_handoff = deepcopy(handoff)
    assert tampered_handoff.identity_preimage is not None
    tampered_handoff.identity_preimage["formal_quote_bindings"] = tampered[
        "formal_quote_bindings"
    ]
    with pytest.raises(ExecutableTargetAdapterError, match="does not match"):
        tampered_handoff.validate_identity_proof()


@pytest.mark.parametrize(
    ("product", "current", "target", "roll", "close_count", "open_count"),
    [
        ("ag", -3, -1, False, 2, 0),
        ("ag", -1, -3, False, 0, 2),
        ("au", -2, 2, False, 2, 2),
        ("cu", -2, 3, True, 2, 3),
    ],
)
def test_short_reduce_increase_reversal_and_roll_matrix(
    product: str,
    current: int,
    target: int,
    roll: bool,
    close_count: int,
    open_count: int,
) -> None:
    _projection, _freeze, target_evidence = _static_outputs()
    manager = _position_manager_snapshot(
        target_evidence, selected=_targets(**{product: target})
    )
    row = _row_by_product(manager)[product]
    contract = row["exact_contract"][:-2] + "09" if roll else row["exact_contract"]
    positions = dict(
        [
            _position(
                contract,
                direction="LONG" if current > 0 else "SHORT",
                volume=abs(current),
                yd_volume=min(1, abs(current)),
            )
        ]
    )

    decision = _decision(selected=_targets(**{product: target}), positions=positions)

    assert decision.close_order_count == close_count
    assert decision.open_order_count == (0 if close_count else open_count)
    assert decision.deferred_open_order_count == (open_count if close_count else 0)
    if close_count:
        assert decision.close_handoff is not None
    if open_count and close_count:
        assert decision.open_handoff is None
        assert decision.deferred_open_intent is not None
    elif open_count:
        assert decision.open_handoff is not None


def test_ine_yd_inventory_uses_today_then_yesterday_offsets() -> None:
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets())
    sc = _row_by_product(manager)["sc"]
    positions = dict(
        [_position(sc["exact_contract"], direction="LONG", volume=3, yd_volume=2)]
    )

    decision = _decision(selected=_targets(), positions=positions)

    assert decision.close_handoff is not None
    assert [
        order["offset"] for order in decision.close_handoff.target_plan["orders"]
    ] == ["CLOSETODAY", "CLOSEYESTERDAY", "CLOSEYESTERDAY"]


def test_formal_quote_contract_set_is_exact() -> None:
    _projection, _freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=_targets(ag=1))
    quotes = _required_formal_quotes(manager, {})
    cu = _row_by_product(manager)["cu"]
    quotes[cu["exact_contract"]] = _formal_quote(
        cu["exact_contract"],
        price_side="ask",
        price_tick=cu["price_tick"],
        ingest_seq=99,
    )

    with pytest.raises(ExecutableTargetAdapterError, match="contract set is not exact"):
        _decision(selected=_targets(ag=1), formal_quotes=quotes)
