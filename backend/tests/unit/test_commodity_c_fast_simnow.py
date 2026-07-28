from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread
from time import monotonic, sleep

import pytest
from app.core.config import Settings
from app.core.errors import (
    CommoditySimNowSafetyError,
    CommoditySimNowStateError,
)
from app.schemas.commodity_c_fast_shadow import (
    CommodityCFastRuntimeSnapshotDTO,
    CommodityCFastShakedownSnapshotDTO,
)
from app.schemas.commodity_simnow import (
    CommodityCFastShakedownPreviewRequestDTO,
    CommoditySimNowDisableRequestDTO,
)
from app.services.commodity_simnow import CommoditySimNowService
from app.services.commodity_c_fast_shadow_common import (
    formula_target_binding_sha256,
    sha256_json,
    unsigned_snapshot_payload,
)
from app.services.vnpy_rpc_service import RpcTimeoutError
from pydantic import ValidationError
from test_commodity_c_fast_shadow import (
    sign_payload as official_sign_payload,
    unsigned_payload,
)
from test_commodity_simnow import (
    ACCOUNT_HASH,
    NOW,
    FakeTrade,
    LocalRiskRejectTrade,
    RpcTimeoutTrade,
    fills_for_requests,
    enable_payload,
    make_key,
    make_service,
    make_settings,
    position,
)


def sign_payload(payload: dict, private_key) -> tuple[dict, str]:
    signed, _ = official_sign_payload(payload, private_key)
    bindings = signed["research_bindings"]
    bindings["snapshot_producer_status"] = (
        "IMPLEMENTED_HUMAN_CONFIRMED_BUNDLE_V1"
    )
    bindings["producer_sha256"] = "1" * 64
    bindings["input_bundle_sha256"] = "2" * 64
    signed.update(
        {
            "schema_version": "commodity_c_fast_simnow_shakedown_snapshot_v1",
            "mode": "simnow_shakedown",
            "execution_lane": "simnow_shakedown",
            "frequency": "ONE_SHOT",
            "source_is_month_last_official_day": False,
            "execution_is_next_cross_month_official_day": False,
            "input_cutoff_after_source_close": False,
            "calendar_alignment": "HUMAN_CONFIRMED_RESEARCH_BUNDLE",
            "allocator_output_validation": (
                "PRODUCER_RECOMPUTED_AND_SIGNER_CONFIRMED"
            ),
            "daily_roll_alignment": (
                "HUMAN_CONFIRMED_PIT_EXACT_CONTRACT"
            ),
            "research_observed_at_utc": signed[
                "snapshot_created_at_utc"
            ],
            "research_signature": signed["signature"],
            "control_acceptance_id": "cfast-accept-testfixture1",
            "execution_permit_id": "cfast-permit-testfixture1",
            "accepted_at_utc": signed["snapshot_created_at_utc"],
            "expires_at_utc": (
                datetime.fromisoformat(
                    signed["snapshot_created_at_utc"].replace(
                        "Z", "+00:00"
                    )
                )
                + timedelta(hours=6)
            ).isoformat(),
            "account_sha256": ACCOUNT_HASH,
            "max_selected_products": 2,
            "max_child_order_lots": 0,
            "countable_forward": False,
            "control_signer_key_id": "c-fast-control-test",
        }
    )
    draft = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    signed["formula_target_binding_sha256"] = (
        formula_target_binding_sha256(draft)
    )
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    return (
        snapshot.model_dump(mode="json"),
        sha256_json(unsigned_snapshot_payload(snapshot)),
    )


class AcceptedWithoutIdentityTimeoutTrade(FakeTrade):
    def send_order(self, request, **kwargs):
        assert self.rpc is not None
        self.rpc.orders.append(
            {
                "vt_orderid": "CTP.unattributed",
                "orderid": "unattributed",
                "reference": "",
                "symbol": request.symbol,
                "vt_symbol": f"{request.symbol}.{request.exchange}",
                "direction": request.direction,
                "offset": request.offset,
                "volume": request.volume,
                "price": request.price,
                "status": "not_traded",
            }
        )
        raise RpcTimeoutError()


class PartialAcceptedWithoutIdentityTimeoutTrade(FakeTrade):
    def send_order(self, request, **kwargs):
        assert self.rpc is not None
        if not self.requests:
            self.requests.append(request)
            self.rpc.orders.append(
                {
                    "vt_orderid": "CTP.1",
                    "orderid": "1",
                    "reference": request.reference,
                    "symbol": request.symbol,
                    "vt_symbol": f"{request.symbol}.{request.exchange}",
                    "direction": request.direction,
                    "offset": request.offset,
                    "volume": request.volume,
                    "price": request.price,
                    "status": "not_traded",
                }
            )
            return {"vt_orderid": "CTP.1", "accepted": True}
        self.rpc.orders.append(
            {
                "vt_orderid": "CTP.unattributed",
                "orderid": "unattributed",
                "reference": "",
                "symbol": request.symbol,
                "vt_symbol": f"{request.symbol}.{request.exchange}",
                "direction": request.direction,
                "offset": request.offset,
                "volume": request.volume,
                "price": request.price,
                "status": "not_traded",
            }
        )
        raise RpcTimeoutError()


class FilledWithoutEvidenceTimeoutTrade(FakeTrade):
    def __init__(self, target_quantity: int) -> None:
        super().__init__()
        self.target_quantity = target_quantity

    def send_order(self, request, **kwargs):
        assert self.rpc is not None
        self.requests.append(request)
        self.rpc.positions = [
            position(
                "ag",
                self.target_quantity,
                contract_month="2612",
            )
        ]
        raise RpcTimeoutError()


class AbortAfterFirstChildTrade(FakeTrade):
    def __init__(self) -> None:
        super().__init__()
        self.service: CommoditySimNowService | None = None

    def send_order(self, request, **kwargs):
        result = super().send_order(request, **kwargs)
        assert self.service is not None
        self.service._dispatch_abort_requested = True
        return result


class ExternalFactAfterFirstChildTrade(FakeTrade):
    def send_order(self, request, **kwargs):
        result = super().send_order(request, **kwargs)
        assert self.rpc is not None
        self.rpc.orders.append(
            {
                "vt_orderid": "CTP.external-complete",
                "orderid": "external-complete",
                "reference": "",
                "symbol": "IF2609",
                "vt_symbol": "IF2609.CFFEX",
                "direction": "long",
                "offset": "open",
                "volume": 1,
                "traded": 1,
                "status": "all_traded",
                "gateway_name": "CTP",
            }
        )
        return result


class GenerationChangeAfterFirstChildTrade(FakeTrade):
    def send_order(self, request, **kwargs):
        result = super().send_order(request, **kwargs)
        assert self.rpc is not None
        self.rpc.last_connected_at = "fake-generation-B"
        return result


class BlockingAfterFirstChildTrade(FakeTrade):
    def __init__(self) -> None:
        super().__init__()
        self.first_child_sent = Event()
        self.release_first_child = Event()

    def send_order(self, request, **kwargs):
        result = super().send_order(request, **kwargs)
        if len(self.requests) == 1:
            self.first_child_sent.set()
            assert self.release_first_child.wait(5)
        return result


class ProductionWindowGenerationChangeTrade(FakeTrade):
    def send_order(self, request, **kwargs):
        assert self.rpc is not None
        self.rpc.last_connected_at = "fake-generation-B"
        kwargs["pre_rpc_guard"]()
        pytest.fail("non-idempotent RPC must not be reached")


class ClockChangeAfterFirstChildTrade(FakeTrade):
    def __init__(self, next_now: datetime) -> None:
        super().__init__()
        self.service: CommoditySimNowService | None = None
        self.next_now = next_now

    def send_order(self, request, **kwargs):
        kwargs["pre_rpc_guard"]()
        result = super().send_order(request, **kwargs)
        if len(self.requests) == 1:
            assert self.service is not None
            self.service.clock = lambda: self.next_now
        return result


def fills_for_submitted(plan: dict) -> list[dict]:
    rows: list[dict] = []
    for phase in ("close", "open"):
        for index, submitted in enumerate(
            plan["submitted"][phase],
            start=len(rows) + 1,
        ):
            rows.append(
                {
                    "vt_tradeid": f"CTP.S{index}",
                    "vt_orderid": submitted["vt_orderid"],
                    "gateway_name": "CTP",
                    "symbol": submitted["symbol"],
                    "exchange": submitted["exchange"],
                    "vt_symbol": submitted["vt_symbol"],
                    "direction": submitted["direction"],
                    "offset": submitted["offset"],
                    "reference": submitted["reference"],
                    "price": submitted["price"],
                    "volume": submitted["volume"],
                }
            )
    return rows


def prepare_c_fast_shakedown(
    tmp_path: Path,
    *,
    trade=None,
) -> tuple[
    CommoditySimNowService,
    object,
    CommodityCFastRuntimeSnapshotDTO,
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
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
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


def complete_c_fast_ag_session(
    service: CommoditySimNowService,
    rpc,
    snapshot: CommodityCFastRuntimeSnapshotDTO,
) -> dict:
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.trades = fills_for_submitted(service.current_plan)
    service.auto_candidate_shakedown_advance()
    return preview


def install_next_c_fast_snapshot(
    service: CommoditySimNowService,
    rpc,
    first_snapshot: CommodityCFastRuntimeSnapshotDTO,
    first_hash: str,
) -> tuple[CommodityCFastRuntimeSnapshotDTO, str]:
    previous_targets = {
        row.product: {
            "exact_contract": row.exact_contract,
            "target_quantity": row.target_quantity,
        }
        for row in first_snapshot.targets
    }
    payload = unsigned_payload(
        snapshot_id="c-fast-2026-09-chain-test",
        source_month="2026-09",
        source_day="2026-09-30",
        execution_day="2026-10-01",
        input_cutoff="2026-09-30T07:00:00Z",
        previous_snapshot_hash=first_hash,
        previous_targets=previous_targets,
    )
    payload["targets"][0]["target_quantity"] += 1
    signed, snapshot_hash = sign_payload(payload, make_key())
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    service.bind_c_fast_snapshot_provider(
        lambda: (snapshot.model_copy(deep=True), snapshot_hash)
    )
    next_now = datetime(2026, 10, 1, 2, tzinfo=timezone.utc)
    service.clock = lambda: next_now
    for tick in service.tick_store.ticks.values():
        tick["received_at"] = next_now.isoformat()
    rpc.trades = []
    return snapshot, snapshot_hash


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
    assert len(plan["open_orders"]) == 1
    assert plan["open_orders"][0]["volume"] == abs(ag.target_quantity)
    assert all(
        order["reference"].startswith("commodity_cf:sh:")
        for order in plan["open_orders"]
    )
    assert preview["countable_forward"] is False
    assert preview["production_allowed"] is False


def test_c_fast_start_auto_dispatches_and_archives_reconciled_pnl(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, snapshot_hash = (
        prepare_c_fast_shakedown(tmp_path)
    )
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


@pytest.mark.parametrize("stage", ["preview", "start"])
@pytest.mark.parametrize("status", ["future_gateway_state", "pending_cancel", ""])
def test_c_fast_rejects_unknown_order_status_before_dispatch(
    tmp_path: Path,
    stage: str,
    status: str,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = None
    if stage == "start":
        preview = service.preview_c_fast_shakedown(
            ["ag"], operator="admin", role="admin", source_ip=None
        )["preview"]
    rpc.orders = [
        {
            "vt_orderid": "CTP.unknown-status",
            "orderid": "unknown-status",
            "reference": "",
            "symbol": "IF2609",
            "vt_symbol": "IF2609.CFFEX",
            "status": status,
        }
    ]

    with pytest.raises(
        CommoditySimNowSafetyError,
        match="状态未知",
    ):
        if stage == "preview":
            service.preview_c_fast_shakedown(
                ["ag"],
                operator="admin",
                role="admin",
                source_ip=None,
            )
        else:
            service.start_c_fast_shakedown(
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            )

    assert not service.trade.requests


def test_c_fast_start_binds_previous_positions_to_rebuilt_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    watermark = service._c_fast_terminal_fact_watermark
    calls = {"count": 0}

    def mutate_after_rebuild():
        result = watermark()
        calls["count"] += 1
        if calls["count"] == 2:
            ag = next(
                row
                for row in snapshot.targets
                if row.product == "ag"
            )
            rpc.positions = [
                position(
                    "ag",
                    ag.target_quantity,
                    contract_month="2612",
                )
            ]
        return result

    monkeypatch.setattr(
        service,
        "_c_fast_terminal_fact_watermark",
        mutate_after_rebuild,
    )

    with pytest.raises(
        CommoditySimNowSafetyError,
        match="start 持仓在计划重建后发生变化",
    ):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.current_plan is None
    assert not service.trade.requests


@pytest.mark.parametrize("status", ["pending_cancel", ""])
def test_c_fast_order_scan_rejects_unknown_status(
    tmp_path: Path,
    status: str,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    rpc.orders = [
        {
            "vt_orderid": "CTP.uncertain",
            "orderid": "uncertain",
            "reference": "",
            "symbol": "ag2612",
            "vt_symbol": "ag2612.SHFE",
            "status": status,
        }
    ]

    with pytest.raises(
        CommoditySimNowSafetyError,
        match="状态未知",
    ):
        service._c_fast_external_active_orders(None)

    assert not service.trade.requests


@pytest.mark.parametrize("status", ["pending_cancel", ""])
def test_c_fast_start_rebuild_rejects_new_unknown_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    unknown = {
        "vt_orderid": "CTP.uncertain-during-start",
        "orderid": "uncertain-during-start",
        "reference": "",
        "symbol": "ag2612",
        "vt_symbol": "ag2612.SHFE",
        "status": status,
    }
    calls = {"count": 0}

    def changing_orders():
        calls["count"] += 1
        return [] if calls["count"] == 1 else [unknown]

    monkeypatch.setattr(rpc, "get_orders", changing_orders)

    with pytest.raises(
        CommoditySimNowSafetyError,
        match="状态未知",
    ):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.current_plan is None
    assert not service.trade.requests


@pytest.mark.parametrize("status", ["pending_cancel", ""])
def test_c_fast_ready_dispatch_rejects_unknown_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    advance = service.auto_candidate_shakedown_advance
    monkeypatch.setattr(
        service,
        "auto_candidate_shakedown_advance",
        lambda **_kwargs: {"action": "held_for_test"},
    )
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    monkeypatch.setattr(
        service, "auto_candidate_shakedown_advance", advance
    )
    rpc.orders = [
        {
            "vt_orderid": "CTP.uncertain-ready",
            "orderid": "uncertain-ready",
            "reference": "",
            "symbol": "ag2612",
            "vt_symbol": "ag2612.SHFE",
            "status": status,
        }
    ]

    result = service.auto_candidate_shakedown_advance()

    assert result["action"] == "halted"
    assert result["reason"] == "shakedown_execution_trust_failed"
    assert not service.trade.requests


@pytest.mark.parametrize("status", ["pending_cancel", ""])
def test_c_fast_ready_open_rejects_unknown_status_after_close_reconcile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    payload = unsigned_payload()
    ag = next(
        row for row in payload["targets"] if row["product"] == "ag"
    )
    ag["previous_exact_contract"] = "SHFE.ag2612"
    ag["previous_target_quantity"] = 2
    ag["target_quantity"] = -1
    signed, snapshot_hash = sign_payload(payload, make_key())
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    service.bind_c_fast_snapshot_provider(
        lambda: (snapshot.model_copy(deep=True), snapshot_hash)
    )
    rpc.positions = [
        position("ag", 2, contract_month="2612")
    ]
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    close_request_count = len(service.trade.requests)
    rpc.positions = []
    rpc.orders = []
    rpc.trades = fills_for_submitted(service.current_plan)
    reconcile = service.reconcile

    def reconcile_then_inject(*args, **kwargs):
        result = reconcile(*args, **kwargs)
        rpc.orders = [
            {
                "vt_orderid": "CTP.uncertain-ready-open",
                "orderid": "uncertain-ready-open",
                "reference": "",
                "symbol": "ag2612",
                "vt_symbol": "ag2612.SHFE",
                "status": status,
            }
        ]
        return result

    monkeypatch.setattr(service, "reconcile", reconcile_then_inject)

    result = service.auto_candidate_shakedown_advance()

    assert result["action"] == "halted"
    assert result["reason"] == "shakedown_execution_trust_failed"
    assert len(service.trade.requests) == close_request_count


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


@pytest.mark.parametrize("reverse_rows", [False, True])
def test_c_fast_conflicting_same_trade_id_blocks_terminal(
    tmp_path: Path,
    reverse_rows: bool,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(
        row for row in snapshot.targets if row.product == "ag"
    )
    rpc.positions = [
        position(
            "ag", ag.target_quantity, contract_month="2612"
        )
    ]
    fills = fills_for_submitted(service.current_plan)
    conflict = {
        **fills[0],
        "price": float(fills[0]["price"]) + 1,
    }
    pair = [fills[0], conflict]
    if reverse_rows:
        pair.reverse()
    rpc.trades = [*pair, *fills[1:]]

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    assert service.current_plan is not None
    assert (
        "INCONSISTENT_SESSION_TRADE_EVIDENCE"
        in service.current_plan["halt"]["terminal_guard"][
            "blockers"
        ]
    )
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_identical_duplicate_trade_is_idempotent(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(
        row for row in snapshot.targets if row.product == "ag"
    )
    rpc.positions = [
        position(
            "ag", ag.target_quantity, contract_month="2612"
        )
    ]
    fills = fills_for_submitted(service.current_plan)
    rpc.trades = [fills[0], dict(fills[0]), *fills[1:]]

    result = service.auto_candidate_shakedown_advance()

    assert result["action"] == "open_reconciled"
    assert service.current_plan is None
    assert service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


@pytest.mark.parametrize("reverse_rows", [False, True])
def test_c_fast_late_conflicting_trade_blocks_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reverse_rows: bool,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(
        row for row in snapshot.targets if row.product == "ag"
    )
    rpc.positions = [
        position(
            "ag", ag.target_quantity, contract_month="2612"
        )
    ]
    fills = fills_for_submitted(service.current_plan)
    rpc.trades = fills
    execution_snapshot = service._execution_snapshot
    injected = {"done": False}

    def snapshot_then_inject(plan, **kwargs):
        result = execution_snapshot(plan, **kwargs)
        if not kwargs and not injected["done"]:
            injected["done"] = True
            conflict = {
                **fills[0],
                "price": float(fills[0]["price"]) + 1,
            }
            pair = [fills[0], conflict]
            if reverse_rows:
                pair.reverse()
            rpc.trades = [*pair, *fills[1:]]
        return result

    monkeypatch.setattr(
        service, "_execution_snapshot", snapshot_then_inject
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    assert (
        "CONFLICTING_TRADE_IDENTITIES"
        in service.current_plan["halt"]["terminal_guard"][
            "blockers"
        ]
    )
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


@pytest.mark.parametrize("reverse_rows", [False, True])
def test_c_fast_conflicting_same_order_id_blocks_terminal(
    tmp_path: Path,
    reverse_rows: bool,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(
        row for row in snapshot.targets if row.product == "ag"
    )
    rpc.positions = [
        position(
            "ag", ag.target_quantity, contract_month="2612"
        )
    ]
    rpc.trades = fills_for_submitted(service.current_plan)
    submitted = service.current_plan["submitted"]["open"][0]
    rows = [
        {**submitted, "status": "all_traded"},
        {**submitted, "status": "cancelled"},
    ]
    if reverse_rows:
        rows.reverse()
    rpc.orders = rows

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    assert (
        "CONFLICTING_ORDER_IDENTITIES"
        in service.current_plan["halt"]["terminal_guard"][
            "blockers"
        ]
    )


@pytest.mark.parametrize(
    "trade_type",
    [
        AbortAfterFirstChildTrade,
        ExternalFactAfterFirstChildTrade,
        GenerationChangeAfterFirstChildTrade,
    ],
)
def test_c_fast_each_child_has_final_dispatch_barrier(
    tmp_path: Path,
    trade_type,
) -> None:
    trade = trade_type()
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    if isinstance(trade, AbortAfterFirstChildTrade):
        trade.service = service
    preview = service.preview_c_fast_shakedown(
        ["ag", "al"], operator="admin", role="admin", source_ip=None
    )["preview"]
    assert len(preview["plan"]["open_orders"]) >= 2

    with pytest.raises(CommoditySimNowStateError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert len(trade.requests) == 1
    assert service.current_plan is not None
    assert service.current_plan["status"] in {
        "CANCEL_PENDING",
        "HALTED_RECONCILE_REQUIRED",
        "SUBMISSION_OUTCOME_UNKNOWN",
    }


def test_c_fast_stop_preempts_blocked_child_loop(
    tmp_path: Path,
) -> None:
    trade = BlockingAfterFirstChildTrade()
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    preview = service.preview_c_fast_shakedown(
        ["ag", "al"], operator="admin", role="admin", source_ip=None
    )["preview"]
    start_error: list[Exception] = []
    stop_result: list[dict] = []

    def start_session():
        try:
            service.start_c_fast_shakedown(
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            )
        except Exception as exc:
            start_error.append(exc)

    def stop_session():
        stop_result.append(
            service.stop_c_fast_shakedown(
                "concurrent operator stop",
                operator="admin",
                role="admin",
                source_ip=None,
            )
        )

    start_thread = Thread(target=start_session)
    start_thread.start()
    assert trade.first_child_sent.wait(5)
    stop_thread = Thread(target=stop_session)
    stop_thread.start()
    deadline = monotonic() + 5
    while (
        not service._dispatch_abort_requested
        and monotonic() < deadline
    ):
        sleep(0.01)
    assert service._dispatch_abort_requested is True
    trade.release_first_child.set()
    start_thread.join(5)
    stop_thread.join(5)

    assert not start_thread.is_alive()
    assert not stop_thread.is_alive()
    assert len(trade.requests) == 1
    assert start_error
    assert stop_result
    assert (
        service.c_fast_shakedown_auto_dispatch_authorized
        is False
    )


def test_c_fast_queued_stop_epoch_cannot_be_cleared_by_start(
    tmp_path: Path,
) -> None:
    trade = FakeTrade()
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    start_error: list[Exception] = []
    stop_error: list[Exception] = []

    service._cycle_lock.acquire()
    try:
        start_thread = Thread(
            target=lambda: _capture_thread_error(
                start_error,
                lambda: service.start_c_fast_shakedown(
                    preview["plan_hash"],
                    operator="admin",
                    role="admin",
                    source_ip=None,
                ),
            )
        )
        start_thread.start()
        sleep(0.05)
        stop_thread = Thread(
            target=lambda: _capture_thread_error(
                stop_error,
                lambda: service.stop_c_fast_shakedown(
                    "queued stop", operator="admin",
                    role="admin", source_ip=None
                ),
            )
        )
        stop_thread.start()
        deadline = monotonic() + 5
        while (
            service._dispatch_abort_epoch == 0
            and monotonic() < deadline
        ):
            sleep(0.01)
        assert service._dispatch_abort_epoch > 0
    finally:
        service._cycle_lock.release()

    start_thread.join(5)
    stop_thread.join(5)
    assert start_error
    assert not trade.requests


def test_c_fast_start_entered_during_pending_halt_cannot_authorize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trade = FakeTrade()
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    halt_entered = Event()
    release_halt = Event()
    pending_snapshot_taken = Event()
    original_snapshot = service._dispatch_epoch_state_snapshot

    def blocking_safe_halt(*args, **kwargs):
        halt_entered.set()
        assert release_halt.wait(5)
        return {"required": False, "status": "IDLE"}

    def observed_snapshot():
        state = original_snapshot()
        if state[1]:
            pending_snapshot_taken.set()
        return state

    monkeypatch.setattr(
        service, "_begin_safe_halt", blocking_safe_halt
    )
    monkeypatch.setattr(
        service,
        "_dispatch_epoch_state_snapshot",
        observed_snapshot,
    )
    disable_errors: list[Exception] = []
    start_errors: list[Exception] = []
    disable_thread = Thread(
        target=lambda: _capture_thread_error(
            disable_errors,
            lambda: service.disable(
                CommoditySimNowDisableRequestDTO(
                    reason="pending halt race"
                ),
                operator="admin",
                role="admin",
                source_ip=None,
            ),
        )
    )
    disable_thread.start()
    assert halt_entered.wait(5)
    start_thread = Thread(
        target=lambda: _capture_thread_error(
            start_errors,
            lambda: service.start_c_fast_shakedown(
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            ),
        )
    )
    start_thread.start()
    assert pending_snapshot_taken.wait(5)
    release_halt.set()
    disable_thread.join(5)
    start_thread.join(5)

    assert not disable_thread.is_alive()
    assert not start_thread.is_alive()
    assert not disable_errors
    assert start_errors
    assert isinstance(
        start_errors[0], CommoditySimNowSafetyError
    )
    assert not trade.requests
    assert service._dispatch_epoch_state_snapshot() == (
        1, frozenset()
    )

    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert trade.requests


@pytest.mark.parametrize(
    "authorization_entry",
    ["enable", "c_fast", "position_manager"],
)
def test_pending_halt_blocks_every_authorization_entry(
    tmp_path: Path,
    authorization_entry: str,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    abort_epoch = service._request_dispatch_abort()

    with pytest.raises(CommoditySimNowSafetyError):
        if authorization_entry == "enable":
            service.enable(
                enable_payload(),
                operator="admin",
                role="admin",
                source_ip=None,
            )
        elif authorization_entry == "c_fast":
            service.start_c_fast_shakedown(
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            )
        else:
            service.start_position_manager_shakedown(
                "pending-halt-must-win",
                operator="admin",
                role="admin",
                source_ip=None,
            )

    assert service._dispatch_epoch_state_snapshot() == (
        abort_epoch,
        frozenset({abort_epoch}),
    )
    service._complete_dispatch_halt(abort_epoch)
    requested, pending = service._dispatch_epoch_state_snapshot()
    assert service._begin_dispatch_epoch(
        requested, pending
    ) == abort_epoch


def test_service_shutdown_pending_halt_blocks_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    halt_entered = Event()
    release_halt = Event()

    def blocking_safe_halt(*args, **kwargs):
        halt_entered.set()
        assert release_halt.wait(5)
        return {"required": False, "status": "IDLE"}

    monkeypatch.setattr(
        service, "_begin_safe_halt", blocking_safe_halt
    )

    async def scenario() -> None:
        stop_task = asyncio.create_task(service.stop())
        assert await asyncio.to_thread(halt_entered.wait, 5)
        with pytest.raises(CommoditySimNowSafetyError):
            await asyncio.to_thread(
                service.start_c_fast_shakedown,
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            )
        release_halt.set()
        await stop_task

    asyncio.run(scenario())

    assert service._dispatch_epoch_state_snapshot() == (
        1, frozenset()
    )


def test_later_halt_completion_cannot_skip_earlier_pending_halt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    monkeypatch.setattr(
        service,
        "auto_candidate_shakedown_advance",
        lambda **_kwargs: {"action": "held_for_test"},
    )
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    first_abort_requested = Event()
    release_first_abort = Event()
    original_request_abort = service._request_dispatch_abort

    def request_abort_with_first_paused():
        epoch = original_request_abort()
        if epoch == 1:
            first_abort_requested.set()
            assert release_first_abort.wait(5)
        return epoch

    monkeypatch.setattr(
        service,
        "_request_dispatch_abort",
        request_abort_with_first_paused,
    )
    disable_errors: list[Exception] = []
    stop_errors: list[Exception] = []
    disable_thread = Thread(
        target=lambda: _capture_thread_error(
            disable_errors,
            lambda: service.disable(
                CommoditySimNowDisableRequestDTO(
                    reason="earlier global disable"
                ),
                operator="admin",
                role="admin",
                source_ip=None,
            ),
        )
    )
    disable_thread.start()
    assert first_abort_requested.wait(5)
    stop_thread = Thread(
        target=lambda: _capture_thread_error(
            stop_errors,
            lambda: service.stop_c_fast_shakedown(
                "later scoped stop",
                operator="admin",
                role="admin",
                source_ip=None,
            ),
        )
    )
    stop_thread.start()
    stop_thread.join(5)

    assert not stop_thread.is_alive()
    assert not stop_errors
    assert service._dispatch_epoch_state_snapshot() == (
        2, frozenset({1})
    )
    with pytest.raises(CommoditySimNowSafetyError):
        service.enable(
            enable_payload(),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    release_first_abort.set()
    disable_thread.join(5)
    assert not disable_thread.is_alive()
    assert not disable_errors
    assert service._dispatch_epoch_state_snapshot() == (
        2, frozenset()
    )
    service.enable(
        enable_payload(),
        operator="admin",
        role="admin",
        source_ip=None,
    )


@pytest.mark.parametrize(
    "stop_name",
    [
        "stop_c_fast_shakedown",
        "stop_position_manager_shakedown",
    ],
)
def test_idle_repeated_stop_is_idempotent_and_does_not_lock_authority(
    tmp_path: Path,
    stop_name: str,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    stop_method = getattr(service, stop_name)

    for _ in range(2):
        result = stop_method(
            "idempotent idle stop",
            operator="admin",
            role="admin",
            source_ip=None,
        )
        assert result["action"] == "already_stopped"

    assert service._dispatch_epoch_state_snapshot() == (
        2, frozenset()
    )
    service.enable(
        enable_payload(),
        operator="admin",
        role="admin",
        source_ip=None,
    )


def test_failed_safe_halt_token_remains_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)

    def fail_safe_halt(*args, **kwargs):
        raise RuntimeError("safe halt failed")

    monkeypatch.setattr(
        service,
        "_begin_safe_halt",
        fail_safe_halt,
    )

    with pytest.raises(RuntimeError, match="safe halt failed"):
        service.disable(
            CommoditySimNowDisableRequestDTO(
                reason="failed safe halt"
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service._dispatch_epoch_state_snapshot() == (
        1, frozenset({1})
    )
    with pytest.raises(CommoditySimNowSafetyError):
        service.enable(
            enable_payload(),
            operator="admin",
            role="admin",
            source_ip=None,
        )


def test_c_fast_continuous_nested_start_inherits_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, first_snapshot, first_hash = (
        prepare_c_fast_shakedown(tmp_path)
    )
    complete_c_fast_ag_session(
        service, rpc, first_snapshot
    )
    install_next_c_fast_snapshot(
        service, rpc, first_snapshot, first_hash
    )
    before = len(service.trade.requests)
    preview = service.preview_c_fast_shakedown
    preview_ready = Event()
    release_preview = Event()

    def blocking_preview(*args, **kwargs):
        result = preview(*args, **kwargs)
        preview_ready.set()
        assert release_preview.wait(5)
        return result

    monkeypatch.setattr(
        service,
        "preview_c_fast_shakedown",
        blocking_preview,
    )
    continuous_errors: list[Exception] = []
    stop_errors: list[Exception] = []
    continuous_thread = Thread(
        target=lambda: _capture_thread_error(
            continuous_errors,
            service.auto_c_fast_continuous_advance,
        )
    )
    continuous_thread.start()
    assert preview_ready.wait(5)
    epoch_before_stop = service._dispatch_epoch_snapshot()
    stop_thread = Thread(
        target=lambda: _capture_thread_error(
            stop_errors,
            lambda: service.stop_c_fast_shakedown(
                "stop nested continuous start",
                operator="admin",
                role="admin",
                source_ip=None,
            ),
        )
    )
    stop_thread.start()
    deadline = monotonic() + 5
    while (
        service._dispatch_epoch_snapshot()
        == epoch_before_stop
        and monotonic() < deadline
    ):
        sleep(0.01)
    assert (
        service._dispatch_epoch_snapshot()
        > epoch_before_stop
    )
    release_preview.set()
    continuous_thread.join(5)
    stop_thread.join(5)

    assert continuous_errors
    assert len(service.trade.requests) == before
    assert service.c_fast_continuous_authorized is False
    assert service.current_plan is None


def _capture_thread_error(
    errors: list[Exception],
    callback,
) -> None:
    try:
        callback()
    except Exception as exc:
        errors.append(exc)


def test_c_fast_final_guard_runs_after_pending_intent_persist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    trade = service.trade
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    original_persist = service._persist_active_plan
    injected = False

    def persist_and_inject():
        nonlocal injected
        original_persist()
        intents = (
            (service.current_plan or {})
            .get("send_intents", {})
            .get("open", [])
        )
        if intents and not injected:
            injected = True
            rpc.orders.append(
                {
                    "vt_orderid": "CTP.external-terminal",
                    "orderid": "external-terminal",
                    "reference": "",
                    "symbol": "IF2609",
                    "vt_symbol": "IF2609.CFFEX",
                    "direction": "long",
                    "offset": "open",
                    "volume": 1,
                    "traded": 1,
                    "status": "all_traded",
                    "gateway_name": "CTP",
                }
            )

    monkeypatch.setattr(
        service, "_persist_active_plan", persist_and_inject
    )
    with pytest.raises(CommoditySimNowStateError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )
    assert injected
    assert not trade.requests


def test_c_fast_trade_service_window_rechecks_generation(
    tmp_path: Path,
) -> None:
    trade = ProductionWindowGenerationChangeTrade()
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]

    with pytest.raises(CommoditySimNowStateError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert not trade.requests


def test_c_fast_final_guard_rejects_next_trading_day_child(
    tmp_path: Path,
) -> None:
    trade = ClockChangeAfterFirstChildTrade(
        datetime(2026, 9, 2, 1, tzinfo=timezone.utc)
    )
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    trade.service = service
    preview = service.preview_c_fast_shakedown(
        ["ag", "al"], operator="admin", role="admin", source_ip=None
    )["preview"]

    with pytest.raises(
        CommoditySimNowStateError,
        match="委托部分提交",
    ) as exc_info:
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert len(trade.requests) == 1
    assert isinstance(
        exc_info.value.__cause__,
        CommoditySimNowSafetyError,
    )
    assert "child 最终发送绑定已失效" in str(
        exc_info.value.__cause__
    )


def test_c_fast_final_guard_allows_night_natural_day_rollover(
    tmp_path: Path,
) -> None:
    after_midnight = datetime(
        2026, 8, 31, 16, 30, tzinfo=timezone.utc
    )
    trade = ClockChangeAfterFirstChildTrade(after_midnight)
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    trade.service = service
    before_midnight = datetime(
        2026, 8, 31, 13, 30, tzinfo=timezone.utc
    )
    service.clock = lambda: before_midnight
    for tick in service.tick_store.ticks.values():
        tick["received_at"] = before_midnight.isoformat()
    preview = service.preview_c_fast_shakedown(
        ["ag", "al"], operator="admin", role="admin", source_ip=None
    )["preview"]

    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert len(trade.requests) >= 2
    assert all(
        intent["pre_send_binding_guard"]["execution_day"]
        == "2026-09-01"
        for intent in service.current_plan["send_intents"]["open"]
    )


@pytest.mark.parametrize("with_late_order", [False, True])
def test_c_fast_historical_intent_is_never_overwritten_or_replayed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    with_late_order: bool,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    advance = service.auto_candidate_shakedown_advance
    monkeypatch.setattr(
        service,
        "auto_candidate_shakedown_advance",
        lambda **_kwargs: {"action": "held_for_test"},
    )
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    monkeypatch.setattr(
        service, "auto_candidate_shakedown_advance", advance
    )
    child = service.current_plan["open_orders"][0]
    service.current_plan["send_intents"]["open"].append(
        {
            **child,
            "intent_status": "NO_EVIDENCE_STABLE",
        }
    )
    if with_late_order:
        rpc.orders = [
            {
                **child,
                "vt_orderid": "CTP.late-original",
                "orderid": "late-original",
                "status": "all_traded",
                "traded": child["volume"],
                "gateway_name": "CTP",
            }
        ]

    with pytest.raises(CommoditySimNowStateError):
        service.auto_candidate_shakedown_advance()

    assert not service.trade.requests
    intents = service.current_plan["send_intents"]["open"]
    assert len(intents) == 1
    assert intents[0]["intent_status"] == "NO_EVIDENCE_STABLE"


def test_c_fast_pre_submit_stop_uses_strict_full_orders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    monkeypatch.setattr(
        service,
        "auto_candidate_shakedown_advance",
        lambda **_kwargs: {"action": "held_for_test"},
    )
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    child = service.current_plan["open_orders"][0]
    service.current_plan["send_intents"]["open"].append(
        {
            **child,
            "intent_status": "NO_EVIDENCE_STABLE",
        }
    )
    service.current_plan["status"] = "HALTED_PRE_SUBMIT_SAFE"
    service.current_plan["halt"] = {
        "resume_status": "READY_OPEN",
    }
    late = {
        **child,
        "vt_orderid": "CTP.late-terminal",
        "orderid": "late-terminal",
        "status": "all_traded",
        "traded": child["volume"],
        "gateway_name": "CTP",
    }
    monkeypatch.setattr(rpc, "get_orders", lambda: [])
    monkeypatch.setattr(
        rpc, "get_all_orders", lambda: [late]
    )

    service.stop_c_fast_shakedown(
        "strict stop check",
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert service.current_plan is not None
    assert service.current_plan["status"] in {
        "CANCEL_PENDING",
        "SUBMISSION_OUTCOME_UNKNOWN",
        "HALTED_RECONCILE_REQUIRED",
    }
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_reprice_position_drift_sends_no_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    reprice = service._reprice_order
    mutated = {"done": False}

    def reprice_then_fill(order, *, passive=False):
        result = reprice(order, passive=passive)
        if not mutated["done"]:
            mutated["done"] = True
            ag = next(
                row for row in snapshot.targets
                if row.product == "ag"
            )
            rpc.positions = [
                position(
                    "ag",
                    ag.target_quantity,
                    contract_month="2612",
                )
            ]
        return result

    monkeypatch.setattr(
        service, "_reprice_order", reprice_then_fill
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert not service.trade.requests


def test_c_fast_start_rejects_order_status_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    order = {
        "vt_orderid": "CTP.external-transition",
        "orderid": "external-transition",
        "reference": "",
        "symbol": "ag2612",
        "vt_symbol": "ag2612.SHFE",
        "direction": "long",
        "offset": "open",
        "volume": 1,
        "traded": 0,
        "status": "not_traded",
        "gateway_name": "CTP",
    }
    calls = {"count": 0}

    def transitioning_orders():
        calls["count"] += 1
        return [
            {
                **order,
                "status":
                "not_traded"
                if calls["count"] == 1
                else "all_traded",
                "traded": 0 if calls["count"] == 1 else 1,
            }
        ]

    monkeypatch.setattr(
        rpc, "get_all_orders", transitioning_orders
    )

    with pytest.raises(
        CommoditySimNowSafetyError,
        match="事实不稳定",
    ):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert not service.trade.requests


def test_c_fast_requires_full_order_capability(
    tmp_path: Path,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    rpc.get_all_orders = None

    with pytest.raises(
        CommoditySimNowSafetyError,
        match="完整订单快照",
    ):
        service.preview_c_fast_shakedown(
            ["ag"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert not service.trade.requests


def test_c_fast_start_rejects_rpc_generation_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    safety = service._safety_snapshot
    calls = {"count": 0}

    def changing_generation(**kwargs):
        result = safety(**kwargs)
        calls["count"] += 1
        return {
            **result,
            "rpc_last_connected_at":
            "generation-A"
            if calls["count"] <= 3
            else "generation-B",
        }

    monkeypatch.setattr(
        service, "_safety_snapshot", changing_generation
    )

    with pytest.raises(
        CommoditySimNowSafetyError,
        match="事实不稳定",
    ):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert not service.trade.requests


def test_c_fast_ready_dispatch_rejects_rpc_generation_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    advance = service.auto_candidate_shakedown_advance
    monkeypatch.setattr(
        service,
        "auto_candidate_shakedown_advance",
        lambda **_kwargs: {"action": "held_for_test"},
    )
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    monkeypatch.setattr(
        service, "auto_candidate_shakedown_advance", advance
    )
    rpc.last_connected_at = "fake-generation-B"

    result = service.auto_candidate_shakedown_advance()

    assert result["action"] == "halted"
    assert result["reason"] == "shakedown_execution_trust_failed"
    assert not service.trade.requests


def test_c_fast_filled_timeout_without_order_or_trade_stays_unknown(
    tmp_path: Path,
) -> None:
    payload = unsigned_payload()
    ag_target = next(
        row["target_quantity"]
        for row in payload["targets"]
        if row["product"] == "ag"
    )
    trade = FilledWithoutEvidenceTimeoutTrade(ag_target)
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]

    with pytest.raises(CommoditySimNowStateError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    for _ in range(3):
        advanced = service.auto_candidate_shakedown_advance()
        assert advanced["action"] == "submission_outcome_unknown"
    assert service.current_plan is not None
    assert service.current_plan["status"] == "SUBMISSION_OUTCOME_UNKNOWN"
    assert (
        service.current_plan["halt"]["recovery_blocker"]
        == "UNRESOLVED_SEND_INTENTS"
    )
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()
    pnl = service.c_fast_shakedown_pnl()
    assert pnl["trade_evidence_state"] == "INCOMPLETE"
    assert pnl["execution_mark_to_market_pnl_cny"] is None


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
    current["snapshot"] = CommodityCFastShakedownSnapshotDTO.model_validate(
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
    next_ag = next(
        row
        for row in current["snapshot"].targets
        if row.product == "ag"
    )
    rpc.positions = [
        position(
            "ag",
            next_ag.target_quantity,
            contract_month="2612",
        )
    ]
    rpc.trades = fills_for_submitted(service.current_plan)
    service.auto_candidate_shakedown_advance()
    history = service.c_fast_shakedown_history()
    assert len(history) == 2
    assert all(row["chain_state"] == "VALID" for row in history)
    oldest = history[-1]
    service._c_fast_terminal_archive_path(
        oldest["session_id"]
    ).unlink()
    broken = service.c_fast_shakedown_history()
    assert broken[0]["chain_state"] == "CHAIN_BROKEN"


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


def test_c_fast_stop_revokes_memory_before_session_persist_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, base_snapshot, _ = prepare_c_fast_shakedown(
        tmp_path
    )
    previous_targets = {
        row.product: {
            "exact_contract": row.exact_contract,
            "target_quantity": -1 if row.product == "ag" else 0,
        }
        for row in base_snapshot.targets
    }
    close_payload = unsigned_payload(
        snapshot_id="c-fast-2026-08-close-stop",
        previous_snapshot_hash="e" * 64,
        previous_targets=previous_targets,
    )
    close_signed, close_hash = sign_payload(close_payload, make_key())
    close_snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(
        close_signed
    )
    service.bind_c_fast_snapshot_provider(
        lambda: (close_snapshot.model_copy(deep=True), close_hash)
    )
    rpc.positions = [position("ag", -1, contract_month="2612")]
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert service.current_plan["status"] == "CLOSE_SUBMITTED"
    request = service.trade.requests[0]
    rpc.orders = [
        {
            "vt_orderid": "CTP.1",
            "reference": request.reference,
            "symbol": request.symbol,
            "vt_symbol": f"{request.symbol}.{request.exchange}",
            "status": "not_traded",
        }
    ]
    save_state = service._save_c_fast_shakedown_state
    monkeypatch.setattr(
        service,
        "_save_c_fast_shakedown_state",
        lambda _session: (_ for _ in ()).throw(OSError("disk full")),
    )

    stopped = service.stop_c_fast_shakedown(
        "operator requested fail closed stop",
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert service.c_fast_continuous_authorized is False
    assert service.c_fast_shakedown_auto_dispatch_authorized is False
    assert "CTP.1" in service.trade.cancel_requests
    assert stopped["halt"]["status"] in {
        "CANCEL_PENDING",
        "HALTED_RECONCILE_REQUIRED",
    }
    monkeypatch.setattr(
        service, "_save_c_fast_shakedown_state", save_state
    )
    before = len(service.trade.requests)
    rpc.positions = []
    rpc.trades = fills_for_requests(list(service.trade.requests))
    service.auto_candidate_shakedown_advance()
    assert len(service.trade.requests) == before


def test_c_fast_terminal_evidence_failure_restores_plan_but_not_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert service.current_plan is not None
    service.current_plan["status"] = "READY_OPEN"
    service.current_plan["submitted"]["open"] = []
    service.current_plan["send_intents"]["open"] = []
    rpc.orders = []
    monkeypatch.setattr(
        service,
        "_archive_candidate_shakedown_terminal",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("archive unavailable")
        ),
    )

    with pytest.raises(CommoditySimNowStateError):
        service.stop_c_fast_shakedown(
            "operator requested evidence failure stop",
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.current_plan["status"] == "READY_OPEN"
    assert service.c_fast_continuous_authorized is False
    assert service.c_fast_shakedown_auto_dispatch_authorized is False


def test_c_fast_stop_cancels_when_first_active_state_persist_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, base_snapshot, _ = prepare_c_fast_shakedown(
        tmp_path
    )
    previous_targets = {
        row.product: {
            "exact_contract": row.exact_contract,
            "target_quantity": -1 if row.product == "ag" else 0,
        }
        for row in base_snapshot.targets
    }
    payload = unsigned_payload(
        snapshot_id="c-fast-2026-08-active-persist-stop",
        previous_snapshot_hash="d" * 64,
        previous_targets=previous_targets,
    )
    signed, snapshot_hash = sign_payload(payload, make_key())
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    service.bind_c_fast_snapshot_provider(
        lambda: (snapshot.model_copy(deep=True), snapshot_hash)
    )
    rpc.positions = [position("ag", -1, contract_month="2612")]
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert service.current_plan["status"] == "CLOSE_SUBMITTED"
    request = service.trade.requests[0]
    rpc.orders = [
        {
            "vt_orderid": "CTP.1",
            "reference": request.reference,
            "symbol": request.symbol,
            "vt_symbol": f"{request.symbol}.{request.exchange}",
            "status": "not_traded",
        }
    ]
    persist = service._persist_active_plan
    calls = {"count": 0}

    def fail_once() -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("disk full")
        persist()

    monkeypatch.setattr(service, "_persist_active_plan", fail_once)

    stopped = service.stop_c_fast_shakedown(
        "operator requested active persist failure stop",
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert service.c_fast_continuous_authorized is False
    assert service.c_fast_shakedown_auto_dispatch_authorized is False
    assert service.trade.cancel_requests == ["CTP.1"]
    assert (
        stopped["halt"]["active_state_persistence_error"]
        == "OSError"
    )
    persisted = json.loads(
        service._active_state_path().read_text(encoding="utf-8")
    )
    persisted_halt = persisted["plan"]["halt"]
    assert (
        persisted_halt["active_state_persistence_recovered_at_utc"]
    )
    before = len(service.trade.requests)
    rpc.positions = []
    rpc.trades = fills_for_requests(list(service.trade.requests))
    service.auto_candidate_shakedown_advance()
    assert len(service.trade.requests) == before


def test_service_stop_always_cancels_worker_after_halt_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)

    async def scenario() -> None:
        worker = asyncio.create_task(asyncio.Event().wait())
        service._task = worker
        monkeypatch.setattr(
            service,
            "_begin_safe_halt",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("disk unavailable")
            ),
        )
        with pytest.raises(OSError):
            await service.stop()
        assert worker.cancelled()
        assert service._task is None

    asyncio.run(scenario())


def test_c_fast_continuous_trust_failure_revokes_persisted_authority(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    service.bind_c_fast_snapshot_provider(
        lambda: (_ for _ in ()).throw(RuntimeError("signature invalid"))
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_c_fast_continuous_advance()

    assert service.c_fast_continuous_authorized is False
    assert (
        service._load_c_fast_shakedown_state()["continuous_authorized"]
        is False
    )


def test_c_fast_pre_submit_risk_failure_revokes_continuous_authority(
    tmp_path: Path,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(
        tmp_path, trade=LocalRiskRejectTrade()
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]

    with pytest.raises(CommoditySimNowStateError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.c_fast_continuous_authorized is False
    assert service.c_fast_shakedown_auto_dispatch_authorized is False
    assert (
        service._load_c_fast_shakedown_state()["continuous_authorized"]
        is False
    )


def test_c_fast_idle_emergency_revocation_survives_later_clear(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    service.risk.emergency_stopped = True

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_c_fast_continuous_advance()

    service.risk.emergency_stopped = False
    assert service.c_fast_continuous_authorized is False
    assert (
        service.auto_c_fast_continuous_advance()["reason"]
        == "continuous_authorization_not_active"
    )


def test_c_fast_timeout_with_unattributed_active_order_never_clears_plan(
    tmp_path: Path,
) -> None:
    trade = AcceptedWithoutIdentityTimeoutTrade()
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]

    with pytest.raises(CommoditySimNowStateError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.current_plan is not None
    assert service.current_plan["status"] == "SUBMISSION_OUTCOME_UNKNOWN"
    ag = next(row for row in snapshot.targets if row.product == "ag")
    rpc.orders = []
    rpc.positions = [
        position("ag", ag.target_quantity, contract_month="2612")
    ]
    rpc.trades = []

    advanced = service.auto_candidate_shakedown_advance()

    assert advanced["action"] == "submission_outcome_unknown"
    assert service.current_plan is not None
    assert service.current_plan["status"] == "SUBMISSION_OUTCOME_UNKNOWN"
    assert (
        service.current_plan["halt"]["recovery_blocker"]
        == "UNATTRIBUTED_FIXED_SCOPE_ACTIVE_ORDERS"
    )
    assert (
        service.current_plan["halt"]["recovery_blocker"]
        == "UNATTRIBUTED_FIXED_SCOPE_ACTIVE_ORDERS"
    )
    service.stop_c_fast_shakedown(
        "operator requested unknown outcome stop",
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert service.current_plan is not None
    assert service.current_plan["status"] == "SUBMISSION_OUTCOME_UNKNOWN"


def test_position_manager_start_rejects_stale_preview_during_c_fast_authority(
    tmp_path: Path,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={
            "commodity_position_manager_simnow_shakedown_enabled": True,
            "commodity_position_manager_simnow_auto_dispatch_enabled": True,
        }
    )
    service.c_fast_continuous_authorized = True

    with pytest.raises(
        CommoditySimNowStateError,
        match="C_FAST 持续运行授权占用执行权",
    ):
        service.start_position_manager_shakedown(
            "0" * 64,
            operator="admin",
            role="admin",
            source_ip=None,
        )


def test_c_fast_partial_ack_does_not_hide_unattributed_timeout_child(
    tmp_path: Path,
) -> None:
    trade = PartialAcceptedWithoutIdentityTimeoutTrade()
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(
        tmp_path, trade=trade
    )
    preview = service.preview_c_fast_shakedown(
        ["ag", "al"], operator="admin", role="admin", source_ip=None
    )["preview"]
    assert len(preview["plan"]["open_orders"]) >= 2

    with pytest.raises(CommoditySimNowStateError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    plan = service.current_plan
    assert plan is not None
    assert len(plan["submitted"]["open"]) == 1
    assert (
        plan["halt"]["recovery_blocker"]
        == "UNATTRIBUTED_FIXED_SCOPE_ACTIVE_ORDERS"
    )
    assert len(plan["halt"]["unresolved_send_intent_references"]) == 1
    ag = next(row for row in snapshot.targets if row.product == "ag")
    rpc.orders = []
    rpc.positions = [
        position("ag", ag.target_quantity, contract_month="2612")
    ]
    first_request = service.trade.requests[0]
    rpc.trades = fills_for_requests([first_request])

    advanced = service.auto_candidate_shakedown_advance()

    assert advanced["action"] == "submission_outcome_unknown"
    assert service.current_plan is not None
    assert service.current_plan["status"] == "SUBMISSION_OUTCOME_UNKNOWN"
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_terminal_archive_survives_next_preview_start_failure(
    tmp_path: Path,
) -> None:
    service, rpc, first_snapshot, first_hash = (
        prepare_c_fast_shakedown(tmp_path)
    )
    current = {"snapshot": first_snapshot, "hash": first_hash}
    service.bind_c_fast_snapshot_provider(
        lambda: (
            current["snapshot"].model_copy(deep=True),
            current["hash"],
        )
    )
    first = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        first["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(row for row in first_snapshot.targets if row.product == "ag")
    rpc.positions = [
        position("ag", ag.target_quantity, contract_month="2612")
    ]
    rpc.trades = fills_for_requests(list(service.trade.requests))
    service.auto_candidate_shakedown_advance()
    first_terminal = service._load_c_fast_shakedown_state()

    previous_targets = {
        row.product: {
            "exact_contract": row.exact_contract,
            "target_quantity": row.target_quantity,
        }
        for row in first_snapshot.targets
    }
    next_payload = unsigned_payload(
        snapshot_id="c-fast-2026-09-archive-test",
        source_month="2026-09",
        source_day="2026-09-30",
        execution_day="2026-10-01",
        input_cutoff="2026-09-30T07:00:00Z",
        previous_snapshot_hash=first_hash,
        previous_targets=previous_targets,
    )
    next_payload["targets"][0]["target_quantity"] += 1
    next_signed, next_hash = sign_payload(next_payload, make_key())
    current["snapshot"] = CommodityCFastShakedownSnapshotDTO.model_validate(
        next_signed
    )
    current["hash"] = next_hash
    next_now = datetime(2026, 10, 1, 2, tzinfo=timezone.utc)
    service.clock = lambda: next_now
    for tick in service.tick_store.ticks.values():
        tick["received_at"] = next_now.isoformat()
    second = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    current["hash"] = "f" * 64

    with pytest.raises(CommoditySimNowSafetyError):
        service.start_c_fast_shakedown(
            second["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    history = service.c_fast_shakedown_history()
    assert len(history) == 1
    assert history[0]["session_id"] == first_terminal["session_id"]
    assert (
        second["previous_terminal_checksum"]
        == first_terminal["terminal_checksum"]
    )


def test_c_fast_preview_rejects_missing_pointer_with_existing_archive(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    complete_c_fast_ag_session(service, rpc, snapshot)
    service._c_fast_shakedown_state_path().unlink()

    with pytest.raises(
        CommoditySimNowStateError,
        match="current pointer 缺失",
    ):
        service.preview_c_fast_shakedown(
            ["ag"], operator="admin", role="admin", source_ip=None
        )


def test_c_fast_start_rejects_deleted_predecessor_archive(
    tmp_path: Path,
) -> None:
    service, rpc, first_snapshot, first_hash = (
        prepare_c_fast_shakedown(tmp_path)
    )
    first = complete_c_fast_ag_session(
        service, rpc, first_snapshot
    )
    install_next_c_fast_snapshot(
        service, rpc, first_snapshot, first_hash
    )
    second = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service._c_fast_terminal_archive_path(first["session_id"]).unlink()
    before = len(service.trade.requests)

    with pytest.raises(CommoditySimNowSafetyError):
        service.start_c_fast_shakedown(
            second["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert len(service.trade.requests) == before


def test_c_fast_ready_dispatch_rejects_deleted_predecessor_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, first_snapshot, first_hash = (
        prepare_c_fast_shakedown(tmp_path)
    )
    first = complete_c_fast_ag_session(
        service, rpc, first_snapshot
    )
    install_next_c_fast_snapshot(
        service, rpc, first_snapshot, first_hash
    )
    second = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    advance = service.auto_candidate_shakedown_advance
    monkeypatch.setattr(
        service,
        "auto_candidate_shakedown_advance",
        lambda **_kwargs: {"action": "paused"},
    )
    service.start_c_fast_shakedown(
        second["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    monkeypatch.setattr(
        service, "auto_candidate_shakedown_advance", advance
    )
    service._c_fast_terminal_archive_path(first["session_id"]).unlink()
    before = len(service.trade.requests)

    halted = service.auto_candidate_shakedown_advance()

    assert halted["action"] == "halted"
    assert len(service.trade.requests) == before
    assert service.current_plan is not None
    assert not service._c_fast_terminal_archive_path(
        second["session_id"]
    ).exists()


def test_c_fast_submitted_plan_halts_when_predecessor_archive_disappears(
    tmp_path: Path,
) -> None:
    service, rpc, first_snapshot, first_hash = (
        prepare_c_fast_shakedown(tmp_path)
    )
    first = complete_c_fast_ag_session(
        service, rpc, first_snapshot
    )
    install_next_c_fast_snapshot(
        service, rpc, first_snapshot, first_hash
    )
    second = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        second["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    service._c_fast_terminal_archive_path(first["session_id"]).unlink()

    halted = service.auto_candidate_shakedown_advance()

    assert halted["action"] == "halted"
    assert service.current_plan is not None
    assert service.c_fast_continuous_authorized is False
    assert not service._c_fast_terminal_archive_path(
        second["session_id"]
    ).exists()


def test_c_fast_terminal_retry_reuses_archive_after_pointer_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    save = service._save_c_fast_shakedown_state
    failed = {"value": False}

    def fail_terminal_pointer_once(session) -> None:
        if session.get("status") == "COMPLETE" and not failed["value"]:
            failed["value"] = True
            raise OSError("pointer write failed")
        save(session)

    monkeypatch.setattr(
        service,
        "_save_c_fast_shakedown_state",
        fail_terminal_pointer_once,
    )

    with pytest.raises(OSError):
        service.auto_candidate_shakedown_advance()

    assert service.current_plan is not None
    archive_path = service._c_fast_terminal_archive_path(
        preview["session_id"]
    )
    archived_before = archive_path.read_bytes()

    completed = service.auto_candidate_shakedown_advance()

    assert completed["action"] == "open_reconciled"
    assert service.current_plan is None
    assert archive_path.read_bytes() == archived_before
    history = service.c_fast_shakedown_history()
    assert len(history) == 1
    assert history[0]["chain_state"] == "VALID"


def test_c_fast_restart_adopts_archive_after_pointer_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, snapshot_hash = (
        prepare_c_fast_shakedown(tmp_path)
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    save = service._save_c_fast_shakedown_state

    def fail_terminal_pointer(session) -> None:
        if session.get("status") == "COMPLETE":
            raise OSError("pointer write failed")
        save(session)

    monkeypatch.setattr(
        service, "_save_c_fast_shakedown_state", fail_terminal_pointer
    )
    with pytest.raises(OSError):
        service.auto_candidate_shakedown_advance()
    archive_path = service._c_fast_terminal_archive_path(
        preview["session_id"]
    )
    archived_bytes = archive_path.read_bytes()

    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=service.rpc,
        trade=service.trade,
        risk=service.risk,
        audit=service.audit,
        tick_store=service.tick_store,
        clock=service.clock,
    )
    recovered.bind_c_fast_snapshot_provider(
        lambda: (
            snapshot.model_copy(deep=True),
            snapshot_hash,
        )
    )

    async def exercise() -> None:
        recovered.start()
        assert recovered.current_plan is None
        await recovered.stop()

    asyncio.run(exercise())

    assert recovered.current_plan is None
    assert not recovered._active_state_path().exists()
    assert archive_path.read_bytes() == archived_bytes
    pointer = recovered._load_c_fast_shakedown_state()
    assert pointer["terminal_checksum"] == json.loads(
        archived_bytes
    )["terminal_checksum"]


def test_c_fast_pnl_is_unavailable_when_execution_snapshot_fails(
    tmp_path: Path,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.get_orders_error = RuntimeError("orders unavailable")

    pnl = service.c_fast_shakedown_pnl()

    assert pnl["mark_state"] == "UNAVAILABLE"
    assert pnl["trade_cashflow_cny"] is None
    assert pnl["inventory_change_mark_cny"] is None
    assert pnl["execution_mark_to_market_pnl_cny"] is None
    assert pnl["execution_snapshot_available"] is False
    assert pnl["execution_error_type"] == "RuntimeError"


def test_c_fast_terminal_pnl_is_incomplete_when_trade_callback_lags(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.orders = []
    rpc.trades = []

    service.auto_candidate_shakedown_advance()

    pnl = service.c_fast_shakedown_status()["session"]["execution"]["pnl"]
    assert pnl["execution_snapshot_available"] is True
    assert pnl["trade_evidence_state"] == "INCOMPLETE"
    assert pnl["mark_state"] == "UNAVAILABLE"
    assert pnl["trade_cashflow_cny"] is None
    assert pnl["inventory_change_mark_cny"] is None
    assert pnl["execution_mark_to_market_pnl_cny"] is None


@pytest.mark.parametrize("dispatch_mode", ["auto", "manual"])
def test_c_fast_reconcile_rejects_outside_scope_position(
    tmp_path: Path,
    dispatch_mode: str,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(row for row in snapshot.targets if row.product == "ag")
    rpc.positions = [
        position("ag", ag.target_quantity, contract_month="2612"),
        {
            "symbol": "IF2609",
            "exchange": "CFFEX",
            "vt_symbol": "IF2609.CFFEX",
            "direction": "long",
            "volume": 1,
            "yd_volume": 1,
            "frozen": 0,
        },
    ]
    rpc.orders = []
    rpc.trades = fills_for_requests(list(service.trade.requests))

    with pytest.raises(CommoditySimNowSafetyError):
        service.reconcile(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
            dispatch_mode=dispatch_mode,
        )

    assert service.current_plan is not None
    assert service.current_plan["status"] in {
        "CANCEL_PENDING",
        "HALTED_RECONCILE_REQUIRED",
    }
    assert (
        service.current_plan["halt"]["recovery_blocker"]
        == "OUTSIDE_C_FAST_POSITION_SCOPE"
    )
    assert service.current_plan["halt"]["outside_scope_positions"] == [
        "IF2609"
    ]
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_zero_quantity_contract_change_archives_noop(
    tmp_path: Path,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    payload = unsigned_payload()
    ag = next(
        row for row in payload["targets"] if row["product"] == "ag"
    )
    ag["previous_target_quantity"] = 0
    ag["previous_exact_contract"] = None
    ag["target_quantity"] = 0
    signed, snapshot_hash = sign_payload(payload, make_key())
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    service.bind_c_fast_snapshot_provider(
        lambda: (snapshot.model_copy(deep=True), snapshot_hash)
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    assert preview["plan"]["phase_status"] == "COMPLETE"
    assert preview["plan"]["order_count"] == 0

    result = service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert result["action"] == "noop_reconciled"
    assert service.current_plan is None
    assert not service._active_state_path().exists()
    terminal = service._load_c_fast_shakedown_state()
    assert terminal["status"] == "COMPLETE"
    assert terminal["execution"]["reconciliation"][
        "no_order_session"
    ] is True
    assert service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()
    continuous = service.auto_c_fast_continuous_advance()
    assert continuous["action"] == "idle"
    assert service.current_plan is None


def test_c_fast_zero_quantity_noop_recovers_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    payload = unsigned_payload()
    ag = next(
        row for row in payload["targets"] if row["product"] == "ag"
    )
    ag["previous_target_quantity"] = 0
    ag["previous_exact_contract"] = None
    ag["target_quantity"] = 0
    signed, snapshot_hash = sign_payload(payload, make_key())
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    provider = lambda: (
        snapshot.model_copy(deep=True),
        snapshot_hash,
    )
    service.bind_c_fast_snapshot_provider(provider)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    complete = service._complete_c_fast_noop_plan
    monkeypatch.setattr(
        service,
        "_complete_c_fast_noop_plan",
        lambda _plan: (_ for _ in ()).throw(
            OSError("simulated no-op finalize crash")
        ),
    )

    with pytest.raises(OSError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.current_plan is not None
    assert service.current_plan["status"] == "NOOP_FINALIZING"
    assert service._active_state_path().exists()
    monkeypatch.setattr(
        service, "_complete_c_fast_noop_plan", complete
    )
    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=service.rpc,
        trade=service.trade,
        risk=service.risk,
        audit=service.audit,
        tick_store=service.tick_store,
        clock=service.clock,
    )
    recovered.bind_c_fast_snapshot_provider(provider)

    async def exercise() -> None:
        recovered.start()
        assert recovered.current_plan is None
        await recovered.stop()

    asyncio.run(exercise())
    assert recovered.current_plan is None
    assert recovered._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_noop_rpc_failure_does_not_abort_service_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    payload = unsigned_payload()
    ag = next(
        row for row in payload["targets"] if row["product"] == "ag"
    )
    ag["previous_target_quantity"] = 0
    ag["previous_exact_contract"] = None
    ag["target_quantity"] = 0
    signed, snapshot_hash = sign_payload(payload, make_key())
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    provider = lambda: (
        snapshot.model_copy(deep=True),
        snapshot_hash,
    )
    service.bind_c_fast_snapshot_provider(provider)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    monkeypatch.setattr(
        service,
        "_complete_c_fast_noop_plan",
        lambda _plan: (_ for _ in ()).throw(
            OSError("simulated pre-archive crash")
        ),
    )
    with pytest.raises(OSError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )
    rpc.get_positions_error = RuntimeError("positions unavailable")
    recovered = CommoditySimNowService(
        settings=service.settings.model_copy(
            update={
                "commodity_simnow_auto_dispatch_interval_seconds":
                0.25,
            }
        ),
        rpc=rpc,
        trade=service.trade,
        risk=service.risk,
        audit=service.audit,
        tick_store=service.tick_store,
        clock=service.clock,
    )
    recovered.bind_c_fast_snapshot_provider(provider)

    async def exercise() -> None:
        recovered.start()
        assert recovered.current_plan is not None
        assert (
            recovered.current_plan["status"]
            == "NOOP_FINALIZING"
        )
        assert (
            recovered.current_plan["halt"][
                "noop_recovery_error_type"
            ]
            == "RuntimeError"
        )
        rpc.get_positions_error = None
        await asyncio.sleep(0.4)
        assert recovered.current_plan is None
        await recovered.stop()

    asyncio.run(exercise())
    assert recovered.current_plan is None


def test_c_fast_noop_restart_adopts_archive_after_pointer_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    payload = unsigned_payload()
    ag = next(
        row for row in payload["targets"] if row["product"] == "ag"
    )
    ag["previous_target_quantity"] = 0
    ag["previous_exact_contract"] = None
    ag["target_quantity"] = 0
    signed, snapshot_hash = sign_payload(payload, make_key())
    snapshot = CommodityCFastShakedownSnapshotDTO.model_validate(signed)
    service.bind_c_fast_snapshot_provider(
        lambda: (snapshot.model_copy(deep=True), snapshot_hash)
    )
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    save = service._save_c_fast_shakedown_state

    def fail_terminal_pointer(session) -> None:
        if session.get("status") == "COMPLETE":
            raise OSError("pointer write failed")
        save(session)

    monkeypatch.setattr(
        service, "_save_c_fast_shakedown_state", fail_terminal_pointer
    )
    with pytest.raises(OSError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )
    archive_path = service._c_fast_terminal_archive_path(
        preview["session_id"]
    )
    archived_bytes = archive_path.read_bytes()

    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=service.rpc,
        trade=service.trade,
        risk=service.risk,
        audit=service.audit,
        tick_store=service.tick_store,
        clock=service.clock,
    )
    recovered.bind_c_fast_snapshot_provider(
        lambda: (
            snapshot.model_copy(deep=True),
            snapshot_hash,
        )
    )

    async def exercise() -> None:
        recovered.start()
        assert recovered.current_plan is None
        await recovered.stop()

    asyncio.run(exercise())

    assert recovered.current_plan is None
    assert archive_path.read_bytes() == archived_bytes
    assert recovered._load_c_fast_shakedown_state()[
        "terminal_checksum"
    ] == json.loads(archived_bytes)["terminal_checksum"]


def test_c_fast_terminal_pnl_uses_reconciliation_execution_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.orders = []
    rpc.trades = fills_for_requests(list(service.trade.requests))
    original = service._execution_snapshot
    calls = {"count": 0}

    def counted(plan):
        calls["count"] += 1
        return original(plan)

    monkeypatch.setattr(service, "_execution_snapshot", counted)
    service.auto_candidate_shakedown_advance()

    execution = service._load_c_fast_shakedown_state()["execution"]
    assert calls["count"] == 1
    assert (
        execution["pnl"]["execution_captured_at_utc"]
        == execution["execution_snapshot"]["captured_at_utc"]
    )
    assert (
        execution["pnl"]["expected_volume"]
        == execution["execution_snapshot"]["expected_volume"]
    )
    assert (
        execution["pnl"]["filled_volume"]
        == execution["execution_snapshot"]["filled_volume"]
    )


def test_c_fast_pnl_requires_complete_evidence_per_child(
    tmp_path: Path,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag", "al"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    requests = list(service.trade.requests)
    assert len(requests) >= 2
    rpc.trades = fills_for_requests(requests[:2])
    for trade in rpc.trades:
        trade["vt_tradeid"] = "CTP.DUPLICATE"

    pnl = service.c_fast_shakedown_pnl()

    assert pnl["trade_evidence_state"] == "INCONSISTENT"
    assert pnl["trade_cashflow_cny"] is None
    execution = service._execution_snapshot(service.current_plan)
    assert any(
        row["trade_evidence_state"] == "INCONSISTENT"
        for row in execution["orders"]
    )


def test_c_fast_pnl_marks_child_overfill_inconsistent(
    tmp_path: Path,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    request = service.trade.requests[0]
    rpc.trades = [
        {
            "vt_tradeid": "CTP.OVERFILL",
            "vt_orderid": "CTP.1",
            "price": request.price,
            "volume": request.volume + 1,
        }
    ]

    pnl = service.c_fast_shakedown_pnl()

    assert pnl["trade_evidence_state"] == "INCONSISTENT"
    assert pnl["trade_cashflow_cny"] is None
    execution = service._execution_snapshot(service.current_plan)
    assert (
        execution["orders"][0]["trade_evidence_state"]
        == "INCONSISTENT"
    )


def test_c_fast_finalize_rechecks_outside_scope_position(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.orders = []
    rpc.trades = fills_for_requests(list(service.trade.requests))
    snapshots = [[], [], ["IF2609"]]
    monkeypatch.setattr(
        service,
        "_c_fast_outside_scope_positions",
        lambda *_positions: snapshots.pop(0),
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    assert service.current_plan is not None
    assert (
        service.current_plan["status"]
        == "HALTED_RECONCILE_REQUIRED"
    )
    assert (
        service.current_plan["halt"]["recovery_blocker"]
        == "OUTSIDE_C_FAST_POSITION_SCOPE"
    )
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


@pytest.mark.parametrize(
    "drift",
    [
        "position",
        "external_order",
        "outside_scope_order",
        "unknown_symbol_order",
        "unknown_status_order",
    ],
)
def test_c_fast_terminal_guard_rejects_last_moment_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.orders = []
    rpc.trades = fills_for_requests(list(service.trade.requests))
    execution_snapshot = service._execution_snapshot

    def inject_drift(plan):
        result = execution_snapshot(plan)
        if drift == "position":
            rpc.positions.append(
                position("al", 1, contract_month="2612")
            )
        else:
            symbol = (
                "IF2609"
                if drift == "outside_scope_order"
                else ""
                if drift == "unknown_symbol_order"
                else "ag2612"
            )
            rpc.orders.append(
                {
                    "vt_orderid": "CTP.external-final",
                    "orderid": "external-final",
                    "reference": "",
                    "symbol": symbol,
                    "vt_symbol": (
                        f"{symbol}.CFFEX"
                        if symbol
                        else ""
                    ),
                    "status": "not_traded",
                }
            )
            if drift == "unknown_status_order":
                rpc.orders[-1]["status"] = "mystery_state"
        return result

    monkeypatch.setattr(
        service, "_execution_snapshot", inject_drift
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    assert service.current_plan is not None
    assert (
        service.current_plan["status"]
        == "HALTED_RECONCILE_REQUIRED"
    )
    if drift == "unknown_status_order":
        assert (
            service.current_plan["halt"]["reconcile_error_type"]
            == "CommoditySimNowSafetyError"
        )
        assert "terminal_guard" not in service.current_plan["halt"]
    else:
        assert (
            service.current_plan["halt"]["terminal_guard"]["state"]
            == "BLOCKED"
        )
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_terminal_guard_revalidates_account_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.orders = []
    rpc.trades = fills_for_requests(list(service.trade.requests))
    changed_account = "changed-simnow-account"
    changed_hash = hashlib.sha256(
        changed_account.encode()
    ).hexdigest()
    service.settings = service.settings.model_copy(
        update={
            "commodity_simnow_account_hashes":
            f"{ACCOUNT_HASH},{changed_hash}",
        }
    )
    execution_snapshot = service._execution_snapshot

    def switch_account(plan):
        result = execution_snapshot(plan)
        monkeypatch.setattr(
            rpc,
            "get_accounts",
            lambda: [
                {
                    "accountid": changed_account,
                    "gateway_name": "CTP",
                }
            ],
        )
        return result

    monkeypatch.setattr(
        service, "_execution_snapshot", switch_account
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    assert service.current_plan is not None
    guard = service.current_plan["halt"]["terminal_guard"]
    assert guard["state"] == "BLOCKED"
    assert guard["blockers"][0] == "ACCOUNT_HASH_MISMATCH"
    assert guard["expected_account_hash"] == ACCOUNT_HASH
    assert guard["observed_account_hash"] == changed_hash
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_terminal_guard_rejects_account_change_during_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.orders = []
    rpc.trades = fills_for_requests(list(service.trade.requests))
    changed_hash = hashlib.sha256(
        b"changed-during-terminal-capture"
    ).hexdigest()
    service.settings = service.settings.model_copy(
        update={
            "commodity_c_fast_simnow_account_hashes":
            f"{ACCOUNT_HASH},{changed_hash}",
        }
    )
    safety_snapshot = service._safety_snapshot
    calls = {"count": 0}

    def changing_safety_snapshot(**kwargs):
        calls["count"] += 1
        result = safety_snapshot(**kwargs)
        if calls["count"] == 3:
            result = {**result, "account_hash": changed_hash}
        return result

    monkeypatch.setattr(
        service, "_safety_snapshot", changing_safety_snapshot
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    assert service.current_plan is not None
    guard = service.current_plan["halt"]["terminal_guard"]
    assert guard["state"] == "BLOCKED"
    assert guard["account_hash_before"] == ACCOUNT_HASH
    assert changed_hash in guard["first_snapshot"][
        "account_hashes"
    ]
    assert guard["account_hash_valid"] is False
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_terminal_guard_rejects_unstable_position_order_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(row for row in snapshot.targets if row.product == "ag")
    settled = [
        position("ag", ag.target_quantity, contract_month="2612")
    ]
    drifted = [
        *settled,
        position("al", 1, contract_month="2612"),
    ]
    rpc.positions = settled
    rpc.orders = []
    rpc.trades = fills_for_requests(list(service.trade.requests))
    execution_snapshot = service._execution_snapshot

    def inject_fill_between_terminal_snapshots(plan):
        result = execution_snapshot(plan)
        calls = {"count": 0}

        def racing_positions():
            calls["count"] += 1
            return list(
                settled if calls["count"] == 1 else drifted
            )

        monkeypatch.setattr(rpc, "get_positions", racing_positions)
        return result

    monkeypatch.setattr(
        service,
        "_execution_snapshot",
        inject_fill_between_terminal_snapshots,
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    assert service.current_plan is not None
    guard = service.current_plan["halt"]["terminal_guard"]
    assert guard["state"] == "BLOCKED"
    assert guard["blockers"][0] == "UNSTABLE_TERMINAL_SNAPSHOT"
    assert guard["facts_stable"] is False
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_terminal_guard_rejects_external_fill_between_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    ag = next(row for row in snapshot.targets if row.product == "ag")
    settled = [
        position("ag", ag.target_quantity, contract_month="2612")
    ]
    drifted = [
        position(
            "ag",
            ag.target_quantity + 1,
            contract_month="2612",
        )
    ]
    rpc.positions = settled
    rpc.orders = []
    rpc.trades = fills_for_submitted(service.current_plan)
    execution_snapshot = service._execution_snapshot

    def inject_after_execution(plan):
        result = execution_snapshot(plan)
        external_order = {
            "vt_orderid": "CTP.EXTERNAL-FILL",
            "orderid": "EXTERNAL-FILL",
            "gateway_name": "CTP",
            "symbol": "ag2612",
            "exchange": "SHFE",
            "vt_symbol": "ag2612.SHFE",
            "direction": "long",
            "offset": "open",
            "reference": "manual-external",
            "status": "all_traded",
        }
        external_trade = {
            **external_order,
            "vt_tradeid": "CTP.T-EXTERNAL-FILL",
            "price": 10_000,
            "volume": 1,
        }
        calls = {"count": 0}

        def racing_orders():
            calls["count"] += 1
            if calls["count"] == 1:
                rpc.positions = drifted
                rpc.trades = [
                    *rpc.trades,
                    external_trade,
                ]
            return [external_order]

        monkeypatch.setattr(rpc, "get_orders", racing_orders)
        return result

    monkeypatch.setattr(
        service, "_execution_snapshot", inject_after_execution
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    guard = service.current_plan["halt"]["terminal_guard"]
    assert guard["state"] == "BLOCKED"
    assert "UNSTABLE_TERMINAL_SNAPSHOT" in guard["blockers"]
    assert "NEW_EXTERNAL_ORDER_FACTS" in guard["blockers"]
    assert "NEW_EXTERNAL_TRADE_FACTS" in guard["blockers"]
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_terminal_guard_rejects_net_neutral_external_facts(
    tmp_path: Path,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.orders = [
        {
            "vt_orderid": f"CTP.EXTERNAL-{index}",
            "orderid": f"EXTERNAL-{index}",
            "gateway_name": "CTP",
            "symbol": "ag2612",
            "exchange": "SHFE",
            "vt_symbol": "ag2612.SHFE",
            "direction": direction,
            "offset": "open",
            "reference": "manual-external",
            "status": "all_traded",
        }
        for index, direction in enumerate(
            ("long", "short"), start=1
        )
    ]
    rpc.trades = [
        *fills_for_submitted(service.current_plan),
        *[
            {
                **order,
                "vt_tradeid": f"CTP.T-EXTERNAL-{index}",
                "price": 10_000,
                "volume": 1,
            }
            for index, order in enumerate(rpc.orders, start=1)
        ],
    ]

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    guard = service.current_plan["halt"]["terminal_guard"]
    assert guard["facts_stable"] is True
    assert "NEW_EXTERNAL_ORDER_FACTS" in guard["blockers"]
    assert "NEW_EXTERNAL_TRADE_FACTS" in guard["blockers"]
    assert not service._c_fast_terminal_archive_path(
        preview["session_id"]
    ).exists()


def test_c_fast_terminal_guard_rejects_order_after_first_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.orders = []
    rpc.trades = fills_for_submitted(service.current_plan)
    execution_snapshot = service._execution_snapshot

    def inject_after_execution(plan):
        result = execution_snapshot(plan)
        calls = {"count": 0}
        active = {
            "vt_orderid": "CTP.EXTERNAL-LATE",
            "orderid": "EXTERNAL-LATE",
            "gateway_name": "CTP",
            "symbol": "IF2609",
            "exchange": "CFFEX",
            "vt_symbol": "IF2609.CFFEX",
            "direction": "long",
            "offset": "open",
            "reference": "manual-external",
            "status": "not_traded",
        }

        def racing_orders():
            calls["count"] += 1
            return [] if calls["count"] == 1 else [active]

        monkeypatch.setattr(rpc, "get_orders", racing_orders)
        return result

    monkeypatch.setattr(
        service, "_execution_snapshot", inject_after_execution
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    guard = service.current_plan["halt"]["terminal_guard"]
    assert guard["facts_stable"] is False
    assert "EXTERNAL_ACTIVE_ORDERS" in guard["blockers"]


def test_c_fast_terminal_guard_rejects_rpc_generation_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    rpc.orders = []
    rpc.trades = fills_for_submitted(service.current_plan)
    safety_snapshot = service._safety_snapshot
    calls = {"count": 0}
    generations = ["A", "A", "B", "A", "A"]

    def changing_generation(**kwargs):
        result = safety_snapshot(**kwargs)
        generation = generations[min(
            calls["count"], len(generations) - 1
        )]
        calls["count"] += 1
        return {
            **result,
            "rpc_last_connected_at": generation,
        }

    monkeypatch.setattr(
        service, "_safety_snapshot", changing_generation
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    guard = service.current_plan["halt"]["terminal_guard"]
    assert guard["rpc_generation_valid"] is False
    assert "RPC_GENERATION_MISMATCH" in guard["blockers"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("gateway_name", "OTHER"),
        ("vt_symbol", "al2612.SHFE"),
        ("direction", "short"),
        ("offset", "close"),
        ("reference", "different-reference"),
    ],
)
def test_c_fast_trade_evidence_rejects_semantic_mismatch(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    trade = fills_for_submitted(service.current_plan)[0]
    trade[field] = value
    if field == "gateway_name":
        trade["vt_orderid"] = trade["vt_orderid"].replace(
            "CTP.", "OTHER."
        )
        trade["orderid"] = trade["vt_orderid"].split(".", 1)[-1]
    rpc.trades = [trade]

    pnl = service.c_fast_shakedown_pnl()

    assert pnl["trade_evidence_state"] == "INCONSISTENT"
    assert pnl["trade_cashflow_cny"] is None


def test_c_fast_trade_evidence_rejects_missing_semantics(
    tmp_path: Path,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    submitted = service.current_plan["submitted"]["open"][0]
    rpc.trades = [
        {
            "vt_tradeid": "CTP.MISSING-SEMANTICS",
            "vt_orderid": submitted["vt_orderid"],
            "price": submitted["price"],
            "volume": submitted["volume"],
        }
    ]

    pnl = service.c_fast_shakedown_pnl()

    assert pnl["trade_evidence_state"] == "INCONSISTENT"
    assert pnl["trade_cashflow_cny"] is None


def test_c_fast_submitted_reconcile_error_enters_cancel_recovery(
    tmp_path: Path,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    submitted = service.current_plan["submitted"]["open"][0]
    rpc.orders = [
        {
            **submitted,
            "status": "not_traded",
        }
    ]
    rpc.get_positions_error = RuntimeError("positions unavailable")

    with pytest.raises(RuntimeError):
        service.auto_candidate_shakedown_advance()

    assert service.trade.cancel_requests == sorted(
        row["vt_orderid"]
        for row in service.current_plan["submitted"]["open"]
    )
    assert service.current_plan is not None
    assert service.current_plan["status"] in {
        "CANCEL_PENDING",
        "HALTED_RECONCILE_REQUIRED",
    }
    assert (
        service.current_plan["halt"]["reconcile_error_type"]
        == "RuntimeError"
    )


def test_c_fast_manual_reconcile_error_enters_cancel_recovery(
    tmp_path: Path,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.orders = [
        {
            **submitted,
            "status": "not_traded",
        }
        for submitted in service.current_plan["submitted"]["open"]
    ]
    rpc.get_positions_error = RuntimeError("positions unavailable")

    with pytest.raises(RuntimeError):
        service.reconcile(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
            dispatch_mode="manual",
        )

    assert service.trade.cancel_requests == sorted(
        row["vt_orderid"]
        for row in service.current_plan["submitted"]["open"]
    )
    assert service.current_plan is not None
    assert service.current_plan["status"] in {
        "CANCEL_PENDING",
        "HALTED_RECONCILE_REQUIRED",
    }


def test_c_fast_submitted_reconcile_and_orders_failure_persists_cancel_pending(
    tmp_path: Path,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.get_positions_error = RuntimeError("positions unavailable")
    rpc.get_orders_error = RuntimeError("orders unavailable")

    with pytest.raises(RuntimeError):
        service.auto_candidate_shakedown_advance()

    assert service.current_plan is not None
    assert service.current_plan["status"] == "CANCEL_PENDING"
    assert (
        service.current_plan["halt"]["orders_snapshot_available"]
        is False
    )
    persisted = json.loads(
        service._active_state_path().read_text(encoding="utf-8")
    )["plan"]
    assert persisted["status"] == "CANCEL_PENDING"
    assert persisted["halt"]["reconcile_error_type"] == "RuntimeError"

    rpc.get_positions_error = None
    rpc.get_orders_error = None
    submitted = service.current_plan["submitted"]["open"][0]
    rpc.orders = [{**submitted, "status": "not_traded"}]

    advanced = service.auto_candidate_shakedown_advance()

    assert advanced["action"] == "halted_reconcile_required"
    assert service.trade.cancel_requests == sorted(
        row["vt_orderid"]
        for row in service.current_plan["submitted"]["open"]
    )
    assert (
        service.current_plan["status"]
        == "HALTED_RECONCILE_REQUIRED"
    )


def test_c_fast_account_change_during_reconcile_enters_cancel_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    submitted = service.current_plan["submitted"]["open"][0]
    rpc.orders = [{**submitted, "status": "not_traded"}]
    monkeypatch.setattr(
        rpc,
        "get_accounts",
        lambda: [
            {
                "accountid": "different-account",
                "gateway_name": "CTP",
            }
        ],
    )

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_candidate_shakedown_advance()

    assert service.trade.cancel_requests == sorted(
        row["vt_orderid"]
        for row in service.current_plan["submitted"]["open"]
    )
    assert service.current_plan is not None
    assert service.current_plan["status"] in {
        "CANCEL_PENDING",
        "HALTED_RECONCILE_REQUIRED",
    }
    assert (
        service.current_plan["halt"]["reconcile_error_type"]
        == "CommoditySimNowSafetyError"
    )


def test_c_fast_ack_persistence_failure_still_cancels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    persist = service._persist_active_plan

    def fail_after_ack() -> None:
        plan = service.current_plan or {}
        if any(
            intent.get("intent_status") == "ACKNOWLEDGED"
            for intent in plan.get("send_intents", {}).get("open", [])
        ):
            raise OSError("active state unavailable")
        persist()

    monkeypatch.setattr(
        service, "_persist_active_plan", fail_after_ack
    )

    with pytest.raises(CommoditySimNowStateError):
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    intent = service.current_plan["send_intents"]["open"][0]
    assert intent["intent_status"] == "ACKNOWLEDGED"
    assert service.trade.cancel_requests == ["CTP.1"]
    assert (
        service.current_plan["halt"][
            "submission_evidence_persistence_error"
        ]
        == "OSError"
    )


@pytest.mark.parametrize(
    "tamper",
    [
        "missing_execution",
        "missing_terminal_checksum",
        "bad_execution_checksum",
        "missing_archive",
    ],
)
def test_c_fast_terminal_pointer_tamper_revokes_continuous_authority(
    tmp_path: Path,
    tamper: str,
) -> None:
    service, rpc, snapshot, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
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
    pointer_path = service._c_fast_shakedown_state_path()
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    if tamper == "missing_execution":
        pointer.pop("execution")
        pointer_path.write_text(
            json.dumps(pointer), encoding="utf-8"
        )
    elif tamper == "missing_terminal_checksum":
        pointer.pop("terminal_checksum")
        pointer_path.write_text(
            json.dumps(pointer), encoding="utf-8"
        )
    elif tamper == "bad_execution_checksum":
        pointer["execution"]["state_checksum"] = "0" * 64
        pointer_path.write_text(
            json.dumps(pointer), encoding="utf-8"
        )
    else:
        service._c_fast_terminal_archive_path(
            preview["session_id"]
        ).unlink()

    with pytest.raises(CommoditySimNowSafetyError):
        service.auto_c_fast_continuous_advance()

    assert service.c_fast_continuous_authorized is False
    assert service.current_plan is None


def test_c_fast_restart_keeps_active_plan_when_terminal_pointer_is_invalid(
    tmp_path: Path,
) -> None:
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    service.start_c_fast_shakedown(
        preview["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    pointer_path = service._c_fast_shakedown_state_path()
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    pointer["status"] = "COMPLETE"
    pointer["continuous_authorized"] = True
    pointer.pop("execution", None)
    pointer.pop("terminal_checksum", None)
    pointer_path.write_text(json.dumps(pointer), encoding="utf-8")

    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=service.rpc,
        trade=service.trade,
        risk=service.risk,
        audit=service.audit,
        tick_store=service.tick_store,
        clock=service.clock,
    )

    assert recovered.current_plan is not None
    assert recovered.current_plan["plan_hash"] == preview["plan_hash"]
    assert recovered.c_fast_continuous_authorized is False


def test_c_fast_state_path_rejects_shared_active_plan_path(
    tmp_path: Path,
) -> None:
    base = make_settings(tmp_path, make_key()).model_dump()
    completed = Path(base["commodity_simnow_state_path"])
    active = completed.with_name(
        f"{completed.stem}.active{completed.suffix}"
    )
    base.update(
        {
            "commodity_c_fast_shadow_enabled": True,
            "commodity_c_fast_shadow_snapshot_path":
            str(tmp_path / "c-fast-snapshot.json"),
            "commodity_c_fast_shadow_state_path":
            str(tmp_path / "c-fast-shadow-state.json"),
            "commodity_c_fast_shadow_evidence_path":
            str(tmp_path / "c-fast-shadow-evidence.jsonl"),
            "commodity_c_fast_simnow_shakedown_enabled": True,
            "commodity_c_fast_simnow_account_hashes": ACCOUNT_HASH,
            "commodity_c_fast_simnow_state_path": str(active),
        }
    )

    with pytest.raises(ValidationError):
        Settings.model_validate(base)


def test_c_fast_preview_dto_hard_limits_scope_to_two_products() -> None:
    with pytest.raises(ValidationError):
        CommodityCFastShakedownPreviewRequestDTO(
            selected_products=["ag", "al", "au"]
        )
