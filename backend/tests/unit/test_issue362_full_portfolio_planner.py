from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from app.execution.executable_target_adapter import (
    ExecutableTargetAdapterError,
    build_static_core_equal_full_portfolio_keyless_decision,
    full_portfolio_phase_plan_id_from_preimage,
)
from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
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
    formal_quotes: object = _AUTO_QUOTES,
    quote_overrides: dict[str, dict[str, object]] | None = None,
    drop_quotes: set[str] | None = None,
    reconciliation: dict[str, object] | None = None,
    run_id: str = "issue362-full-portfolio-0001",
    event_generated_at: str = EVENT_GENERATED_AT,
    expires_at: str | None = "2099-01-01T00:00:00Z",
    now: datetime = NOW,
):
    projection, freeze, target = _static_outputs()
    manager = _position_manager_snapshot(target, selected=selected)
    current_positions = {} if positions is None else positions
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
        reconciliation=(
            {"state": "RECONCILED", "unknown_outcomes": 0}
            if reconciliation is None
            else reconciliation
        ),
        formal_quotes_by_exact_contract=quotes,
        run_id=run_id,
        event_generated_at=event_generated_at,
        expires_at=expires_at,
        now=now,
    )


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
        formal_quotes=None,
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
    with pytest.raises(ExecutableTargetAdapterError, match="does not match product"):
        build_static_core_equal_full_portfolio_keyless_decision(
            static_core_equal_projection=projection,
            static_core_equal_freeze_contract=freeze,
            static_core_equal_target_evidence=target,
            position_manager_snapshot=manager,
            position_manager_sha256=sha256_json(manager),
            current_facts=_snapshot({}),
            reconciliation={"state": "RECONCILED", "unknown_outcomes": 0},
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
