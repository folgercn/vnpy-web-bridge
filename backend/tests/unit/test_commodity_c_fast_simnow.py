from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from app.core.errors import (
    CommoditySimNowSafetyError,
    CommoditySimNowStateError,
)
from app.schemas.commodity_c_fast_shadow import CommodityCFastShadowDTO
from app.services.commodity_simnow import CommoditySimNowService
from test_commodity_c_fast_shadow import sign_payload, unsigned_payload
from test_commodity_simnow import (
    ACCOUNT_HASH,
    NOW,
    RpcTimeoutTrade,
    fills_for_requests,
    make_key,
    make_service,
    position,
)


def prepare_c_fast_shakedown(
    tmp_path: Path,
    *,
    trade=None,
) -> tuple[
    CommoditySimNowService,
    object,
    CommodityCFastShadowDTO,
    str,
]:
    service, _, rpc = make_service(
        tmp_path,
        trade=trade,
        now=NOW,
        contract_months=("2612",),
    )
    private_key = make_key()
    signed, snapshot_hash = sign_payload(unsigned_payload(), private_key)
    snapshot = CommodityCFastShadowDTO.model_validate(signed)
    service.settings = service.settings.model_copy(
        update={
            "commodity_c_fast_shadow_enabled": True,
            "commodity_c_fast_simnow_shakedown_enabled": True,
            "commodity_c_fast_simnow_account_hashes": ACCOUNT_HASH,
            "commodity_c_fast_simnow_state_path": str(
                tmp_path / "c-fast-shakedown.json"
            ),
            "commodity_c_fast_simnow_auto_dispatch_enabled": True,
            "commodity_c_fast_simnow_max_selected_products": 2,
        }
    )
    service.bind_c_fast_snapshot_provider(
        lambda: (snapshot.model_copy(deep=True), snapshot_hash)
    )
    return service, rpc, snapshot, snapshot_hash


def test_c_fast_preview_builds_masked_signed_target_plan(
    tmp_path: Path,
) -> None:
    service, _, snapshot, snapshot_hash = prepare_c_fast_shakedown(
        tmp_path
    )

    result = service.preview_c_fast_shakedown(
        ["ag"],
        operator="admin",
        role="admin",
        source_ip="127.0.0.1",
    )

    preview = result["preview"]
    plan = preview["plan"]
    ag = next(row for row in snapshot.targets if row.product == "ag")
    assert preview["source_snapshot_hash"] == snapshot_hash
    assert preview["selected_products"] == ["ag"]
    assert plan["expected_final_positions"] == {
        "ag2612.SHFE": ag.target_quantity
    }
    assert sum(
        order["volume"] for order in plan["open_orders"]
    ) == abs(ag.target_quantity)
    assert all(
        order["reference"].startswith("commodity_cf:sh:")
        for order in plan["open_orders"]
    )
    assert preview["countable_forward"] is False
    assert preview["production_allowed"] is False


def test_c_fast_start_auto_dispatches_and_archives_reconciled_pnl(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"],
        operator="admin",
        role="admin",
        source_ip=None,
    )["preview"]

    started = service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert started["action"] == "open_submitted"
    requests = list(service.trade.requests)
    assert requests
    ag = next(row for row in snapshot.targets if row.product == "ag")
    rpc.positions = [position("ag", ag.target_quantity, contract_month="2612")]
    rpc.trades = fills_for_requests(requests)
    completed = service.auto_candidate_shakedown_advance()

    assert completed["action"] == "open_reconciled"
    assert service.current_plan is None
    status = service.c_fast_shakedown_status()
    assert status["session"]["status"] == "COMPLETE"
    assert (
        status["session"]["execution"]["pnl"]["countable_forward"]
        is False
    )
    assert (
        status["session"]["execution"]["pnl"]["fees_state"]
        == "UNBOUND_NOT_ASSUMED_ZERO"
    )


def test_c_fast_terminal_reconciliation_survives_unavailable_pnl_mark(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"],
        operator="admin",
        role="admin",
        source_ip=None,
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(row for row in snapshot.targets if row.product == "ag")
    rpc.positions = [
        position("ag", ag.target_quantity, contract_month="2612")
    ]
    rpc.trades = fills_for_requests(list(service.trade.requests))
    for tick in service.tick_store.ticks.values():
        tick["received_at"] = (NOW - timedelta(minutes=1)).isoformat()

    completed = service.auto_candidate_shakedown_advance()

    assert completed["action"] == "open_reconciled"
    pnl = service.c_fast_shakedown_status()["session"]["execution"]["pnl"]
    assert pnl["mark_state"] == "UNAVAILABLE"
    assert pnl["execution_mark_to_market_pnl_cny"] is None


def test_c_fast_preview_rejects_non_allowlisted_account(
    tmp_path: Path,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_c_fast_simnow_account_hashes": "0" * 64}
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.preview_c_fast_shakedown(
            ["ag"],
            operator="admin",
            role="admin",
            source_ip=None,
        )


def test_c_fast_preview_rejects_positions_outside_signed_scope(
    tmp_path: Path,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    rpc.positions = [
        {
            "symbol": "IF2609",
            "exchange": "CFFEX",
            "vt_symbol": "IF2609.CFFEX",
            "direction": "long",
            "volume": 1,
            "yd_volume": 1,
            "frozen": 0,
        }
    ]

    with pytest.raises(CommoditySimNowSafetyError):
        service.preview_c_fast_shakedown(
            ["ag"],
            operator="admin",
            role="admin",
            source_ip=None,
        )


def test_c_fast_start_rejects_snapshot_change_after_preview(
    tmp_path: Path,
) -> None:
    service, _, snapshot, snapshot_hash = prepare_c_fast_shakedown(
        tmp_path
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"],
        operator="admin",
        role="admin",
        source_ip=None,
    )["preview"]
    service.bind_c_fast_snapshot_provider(
        lambda: (snapshot.model_copy(deep=True), "f" * 64)
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )
    assert snapshot_hash != "f" * 64
    assert not service.trade.requests


def test_c_fast_rpc_timeout_never_replays_send_intent(
    tmp_path: Path,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=RpcTimeoutTrade()
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"],
        operator="admin",
        role="admin",
        source_ip=None,
    )["preview"]

    with pytest.raises(CommoditySimNowStateError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )
    intents = service.current_plan["send_intents"]["open"]
    assert len(intents) == 1
    assert intents[0]["intent_status"] == "OUTCOME_UNKNOWN"
    assert service.current_plan["status"] in {
        "SUBMISSION_OUTCOME_UNKNOWN",
        "CANCEL_PENDING",
    }
    assert (
        service.auto_candidate_shakedown_advance()["action"]
        != "open_submitted"
    )
    assert len(service.trade.requests) == 0


def test_c_fast_one_start_continues_with_next_accepted_snapshot(
    tmp_path: Path,
) -> None:
    service, rpc, first_snapshot, first_hash = (
        prepare_c_fast_shakedown(tmp_path)
    )
    current = {
        "snapshot": first_snapshot,
        "hash": first_hash,
    }
    service.bind_c_fast_snapshot_provider(
        lambda: (
            current["snapshot"].model_copy(deep=True),
            current["hash"],
        )
    )
    first_preview = service.preview_c_fast_shakedown(
        ["ag"],
        operator="admin",
        role="admin",
        source_ip=None,
    )["preview"]
    service.start_c_fast_shakedown(
        first_preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(
        row for row in first_snapshot.targets if row.product == "ag"
    )
    rpc.positions = [
        position("ag", ag.target_quantity, contract_month="2612")
    ]
    rpc.trades = fills_for_requests(list(service.trade.requests))
    service.auto_candidate_shakedown_advance()
    assert service.c_fast_continuous_authorized is True

    previous_targets = {
        row.product: {
            "exact_contract": row.exact_contract,
            "target_quantity": row.target_quantity,
        }
        for row in first_snapshot.targets
    }
    next_payload = unsigned_payload(
        snapshot_id="c-fast-2026-09-linked",
        source_month="2026-09",
        source_day="2026-09-30",
        execution_day="2026-10-01",
        input_cutoff="2026-09-30T07:00:00Z",
        previous_snapshot_hash=first_hash,
        previous_targets=previous_targets,
    )
    next_payload["targets"][0]["target_quantity"] += 1
    next_signed, next_hash = sign_payload(next_payload, make_key())
    current["snapshot"] = CommodityCFastShadowDTO.model_validate(
        next_signed
    )
    current["hash"] = next_hash
    next_now = datetime(2026, 10, 1, 2, tzinfo=timezone.utc)
    service.clock = lambda: next_now
    for tick in service.tick_store.ticks.values():
        tick["received_at"] = next_now.isoformat()
    rpc.trades = []

    continued = service.auto_c_fast_continuous_advance()

    assert continued["action"] == "open_submitted"
    assert service.current_plan["source_snapshot_hash"] == next_hash
    assert service.current_plan["selected_products"] == ["ag"]
    assert service.c_fast_continuous_authorized is True


def test_c_fast_idle_stop_revokes_continuous_authority_and_restart_stays_closed(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"],
        operator="admin",
        role="admin",
        source_ip=None,
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(row for row in snapshot.targets if row.product == "ag")
    rpc.positions = [
        position("ag", ag.target_quantity, contract_month="2612")
    ]
    rpc.trades = fills_for_requests(list(service.trade.requests))
    service.auto_candidate_shakedown_advance()
    assert service.current_plan is None
    assert service.c_fast_continuous_authorized is True

    stopped = service.stop_c_fast_shakedown(
        "operator requested continuous stop",
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert stopped["action"] == "continuous_authorization_revoked"
    assert service.c_fast_continuous_authorized is False

    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=service.rpc,
        trade=service.trade,
        risk=service.risk,
        audit=service.audit,
        tick_store=service.tick_store,
        clock=service.clock,
    )
    assert recovered.c_fast_continuous_authorized is False
    assert (
        recovered.auto_c_fast_continuous_advance()["reason"]
        == "continuous_authorization_not_active"
    )
