from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread
from time import monotonic, sleep
from typing import Any

import app.services.risk_service as risk_service_module
import pytest
from app.core.errors import CommoditySimNowStateError, RpcCallError
from app.services.audit_service import AuditService
from app.services.commodity_c_fast_one_shot_custody import canonical_json
from app.services.risk_service import RiskService
from app.services.trade_service import TradeService
from app.services.vnpy_rpc_service import VnpyRpcService
from test_commodity_c_fast_simnow import (
    bind_test_execution_permit,
    prepare_c_fast_shakedown,
)
from test_commodity_simnow import ACCOUNT_ID, PRODUCT_SPECS


class ControlledRpcClient:
    def __init__(
        self,
        *,
        fail_send_state: bool = False,
        block_send: bool = False,
    ) -> None:
        self.fail_send_state = fail_send_state
        self.block_send = block_send
        self.send_attempts: list[tuple[Any, str]] = []
        self.send_entered = Event()
        self.release_send = Event()
        self.stopped = False
        self.joined = False

    def get_all_accounts(self, *, timeout: int) -> list[dict[str, Any]]:
        return [{"accountid": ACCOUNT_ID, "gateway_name": "CTP"}]

    def get_all_contracts(self, *, timeout: int) -> list[dict[str, Any]]:
        return [
            {
                "symbol": f"{product}2612",
                "exchange": spec["exchange"],
                "vt_symbol": f"{product}2612.{spec['exchange']}",
                "size": spec["multiplier"],
                "pricetick": spec["price_tick"],
                "gateway_name": "CTP",
            }
            for product, spec in PRODUCT_SPECS.items()
        ]

    def get_all_positions(self, *, timeout: int) -> list[dict[str, Any]]:
        return []

    def get_all_orders(self, *, timeout: int) -> list[dict[str, Any]]:
        return []

    def get_all_active_orders(self, *, timeout: int) -> list[dict[str, Any]]:
        return []

    def get_all_trades(self, *, timeout: int) -> list[dict[str, Any]]:
        return []

    def send_order(
        self,
        order_request: Any,
        gateway_name: str,
        *,
        timeout: int,
    ) -> str:
        self.send_attempts.append((order_request, gateway_name))
        self.send_entered.set()
        if self.block_send:
            assert self.release_send.wait(5)
        if self.fail_send_state:
            raise RuntimeError("Operation cannot be accomplished in current state")
        return f"CTP.{len(self.send_attempts)}"

    def stop(self) -> None:
        self.stopped = True

    def join(self) -> None:
        self.joined = True


def make_real_trade_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    client: ControlledRpcClient | None = None,
):
    service, _, _, _ = prepare_c_fast_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={
            "risk_max_symbol_position": 500,
            "risk_max_daily_loss": 0,
            "risk_price_protection_percent": 0,
            "risk_trading_time_check_enabled": False,
        }
    )
    rpc = VnpyRpcService(service.settings)
    rpc.client = client or ControlledRpcClient()  # type: ignore[assignment]
    rpc.started = True
    rpc.last_connected_at = datetime(2026, 9, 1, 8, tzinfo=timezone.utc)
    monkeypatch.setattr(risk_service_module, "rpc_service", rpc)
    risk = RiskService(service.settings)
    audit = AuditService(tmp_path / "audit.log")
    trade = TradeService(
        settings=service.settings,
        audit=audit,
        risk=risk,
        rpc=rpc,
        _c_fast_capability_issuers=(service,),
    )
    service.rpc = rpc
    service.risk = risk
    service.trade = trade
    bind_test_execution_permit(service, selected_products=("ag", "al"))
    return service, rpc, risk


def test_real_trade_rpc_lock_disable_preempts_child_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, rpc, risk = make_real_trade_service(tmp_path, monkeypatch)
    client = rpc.client
    assert isinstance(client, ControlledRpcClient)
    preview = service.preview_c_fast_shakedown(["ag", "al"], operator="admin", role="admin", source_ip=None)["preview"]
    risk_checked = Event()
    release_risk = Event()
    original_check_order = risk._check_c_fast_order

    def blocking_check_order(*args, **kwargs) -> None:
        original_check_order(*args, **kwargs)
        risk_checked.set()
        assert release_risk.wait(5)

    monkeypatch.setattr(
        risk, "_check_c_fast_order", blocking_check_order
    )
    start_errors: list[Exception] = []
    revoke_results: list[dict[str, Any]] = []

    def start_session() -> None:
        try:
            service.start_c_fast_shakedown(
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            )
        except Exception as exc:
            start_errors.append(exc)

    def revoke() -> None:
        revoke_results.append(
            service.revoke_all_execution_authority(
                "risk_trade_disabled",
                operator="admin",
                source_ip=None,
            )
        )

    start_thread = Thread(target=start_session)
    start_thread.start()
    assert risk_checked.wait(5), start_errors
    rpc._call_lock.acquire()
    try:
        initial_epoch = service._dispatch_epoch_snapshot()
        release_risk.set()
        risk.disable_trade()
        revoke_thread = Thread(target=revoke)
        revoke_thread.start()
        deadline = monotonic() + 5
        while service._dispatch_epoch_snapshot() == initial_epoch and monotonic() < deadline:
            sleep(0.01)
        assert service._dispatch_epoch_snapshot() > initial_epoch
    finally:
        rpc._call_lock.release()

    start_thread.join(5)
    revoke_thread.join(5)
    assert not start_thread.is_alive()
    assert not revoke_thread.is_alive()
    assert len(start_errors) == 1
    assert isinstance(start_errors[0], CommoditySimNowStateError)
    assert not client.send_attempts
    assert revoke_results[0]["authority_revoked"] is True


@pytest.mark.parametrize("mutation", ["stale_clock", "quote_update"])
def test_real_trade_rpc_final_guard_rejects_changed_bound_quote(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    service, rpc, risk = make_real_trade_service(
        tmp_path, monkeypatch
    )
    client = rpc.client
    assert isinstance(client, ControlledRpcClient)
    bind_test_execution_permit(service, selected_products=("ag",))
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    order = preview["plan"]["open_orders"][0]
    risk_checked = Event()
    release_risk = Event()
    original_check_order = risk._check_c_fast_order
    start_errors: list[Exception] = []

    def blocking_check_order(*args, **kwargs) -> None:
        original_check_order(*args, **kwargs)
        risk_checked.set()
        assert release_risk.wait(5)

    def start_session() -> None:
        try:
            service.start_c_fast_shakedown(
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            )
        except Exception as exc:
            start_errors.append(exc)

    monkeypatch.setattr(
        risk, "_check_c_fast_order", blocking_check_order
    )
    start_thread = Thread(target=start_session)
    start_thread.start()
    assert risk_checked.wait(5), start_errors
    assert service.current_plan is not None
    intent = service.current_plan["send_intents"]["open"][0]
    bound_quote = dict(intent["dispatch_quote"])
    bound_price = intent["price"]
    bound_now = service.clock()

    rpc._call_lock.acquire()
    try:
        release_risk.set()
        sleep(0.05)
        if mutation == "stale_clock":
            service.clock = lambda: (
                bound_now + timedelta(
                    seconds=(
                        service.settings.commodity_simnow_max_quote_age_seconds
                        + 1
                    )
                )
            )
        else:
            quote = service.tick_store.ticks[order["vt_symbol"]]
            tick = float(
                PRODUCT_SPECS[order["product"]]["price_tick"]
            )
            quote["bid_price_1"] += tick
            quote["ask_price_1"] += tick
    finally:
        rpc._call_lock.release()

    start_thread.join(5)
    assert not start_thread.is_alive()
    assert len(start_errors) == 1
    assert isinstance(start_errors[0], CommoditySimNowStateError)
    assert not client.send_attempts
    assert intent["dispatch_quote"] == bound_quote
    assert intent["price"] == bound_price


@pytest.mark.parametrize(
    "mutation",
    [
        "permit_receipt_checksum",
        "acceptance_use_checksum",
        "session_checksum",
        "active_plan_checksum",
    ],
)
def test_real_trade_rpc_final_guard_revalidates_durable_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    service, rpc, risk = make_real_trade_service(
        tmp_path, monkeypatch
    )
    client = rpc.client
    assert isinstance(client, ControlledRpcClient)
    bind_test_execution_permit(service, selected_products=("ag",))
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    risk_checked = Event()
    release_risk = Event()
    original_check_order = risk._check_c_fast_order
    start_errors: list[Exception] = []

    def blocking_check_order(*args, **kwargs) -> None:
        original_check_order(*args, **kwargs)
        risk_checked.set()
        assert release_risk.wait(5)

    def start_session() -> None:
        try:
            service.start_c_fast_shakedown(
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            )
        except Exception as exc:
            start_errors.append(exc)

    monkeypatch.setattr(
        risk, "_check_c_fast_order", blocking_check_order
    )
    start_thread = Thread(target=start_session)
    start_thread.start()
    assert risk_checked.wait(5), start_errors
    assert service.current_plan is not None

    if mutation == "permit_receipt_checksum":
        path = service._c_fast_permit_receipt_path(
            preview["execution_permit_id"]
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["receipt_checksum"] = "0" * 64
        path.write_bytes(canonical_json(payload) + b"\n")
    elif mutation == "acceptance_use_checksum":
        path = service._c_fast_acceptance_use_path(
            preview["acceptance_receipt_raw_sha256"]
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["receipt_checksum"] = "0" * 64
        path.write_bytes(canonical_json(payload) + b"\n")
    elif mutation == "session_checksum":
        path = service._c_fast_shakedown_state_path()
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["source_snapshot_hash"] = "0" * 64
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    else:
        path = service._active_state_path()
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["plan_checksum"] = "0" * 64
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    release_risk.set()
    start_thread.join(5)

    assert not start_thread.is_alive()
    assert len(start_errors) == 1
    assert isinstance(start_errors[0], CommoditySimNowStateError)
    assert not client.send_attempts
    assert service.current_plan is not None
    assert (
        service.current_plan["send_intents"]["open"][0][
            "intent_status"
        ]
        == "REJECTED_PRE_RPC"
    )


def test_real_trade_rpc_send_linearizes_before_late_abort(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ControlledRpcClient(block_send=True)
    service, rpc, risk = make_real_trade_service(
        tmp_path,
        monkeypatch,
        client=client,
    )
    bind_test_execution_permit(service, selected_products=("ag",))
    preview = service.preview_c_fast_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )["preview"]
    start_errors: list[Exception] = []
    revoke_results: list[dict[str, Any]] = []
    revoke_started = Event()

    def start_session() -> None:
        try:
            service.start_c_fast_shakedown(
                preview["plan_hash"],
                operator="admin",
                role="admin",
                source_ip=None,
            )
        except Exception as exc:
            start_errors.append(exc)

    def revoke() -> None:
        revoke_started.set()
        revoke_results.append(
            service.revoke_all_execution_authority(
                "risk_trade_disabled",
                operator="admin",
                source_ip=None,
            )
        )

    initial_epoch = service._dispatch_epoch_snapshot()
    start_thread = Thread(target=start_session)
    start_thread.start()
    assert client.send_entered.wait(5), start_errors
    risk.disable_trade()
    revoke_thread = Thread(target=revoke)
    revoke_thread.start()
    assert revoke_started.wait(5)
    sleep(0.05)
    assert revoke_thread.is_alive()
    assert not revoke_results

    client.release_send.set()
    start_thread.join(5)
    revoke_thread.join(5)

    assert not start_thread.is_alive()
    assert not revoke_thread.is_alive()
    assert not start_errors
    assert len(client.send_attempts) == 1
    assert service._dispatch_epoch_snapshot() > initial_epoch
    assert revoke_results[0]["authority_revoked"] is True


def test_real_trade_rpc_reconnect_never_retries_child_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed_client = ControlledRpcClient(fail_send_state=True)
    service, rpc, _ = make_real_trade_service(
        tmp_path,
        monkeypatch,
        client=failed_client,
    )
    replacement_client = ControlledRpcClient()

    def controlled_restart() -> None:
        rpc.client = replacement_client  # type: ignore[assignment]
        rpc.started = True
        rpc.last_connected_at = datetime(2026, 9, 1, 8, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(rpc, "start", controlled_restart)
    preview = service.preview_c_fast_shakedown(["ag", "al"], operator="admin", role="admin", source_ip=None)["preview"]

    with pytest.raises(CommoditySimNowStateError) as exc_info:
        service.start_c_fast_shakedown(
            preview["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert isinstance(exc_info.value.__cause__, RpcCallError)
    assert len(failed_client.send_attempts) == 1
    assert failed_client.stopped is True
    assert failed_client.joined is True
    assert not replacement_client.send_attempts
    assert service.current_plan is not None
    assert service.current_plan["send_intents"]["open"][0]["intent_status"] == "OUTCOME_UNKNOWN"
