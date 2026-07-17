from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from app.core.config import Settings
from app.core.errors import (
    CommoditySimNowBatchError,
    CommoditySimNowDisabledError,
    CommoditySimNowSafetyError,
    CommoditySimNowStateError,
)
from app.schemas.commodity_simnow import (
    CommodityPlanExecuteRequestDTO,
    CommoditySimNowDisableRequestDTO,
    CommoditySimNowEnableRequestDTO,
    CommodityTargetBatchDTO,
)
from app.services.commodity_simnow import (
    PRODUCT_SPECS,
    CommoditySimNowService,
    _canonical_json,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NOW = datetime(2026, 9, 1, 1, 0, tzinfo=timezone.utc)
SHAKEDOWN_NOW = datetime(2026, 7, 17, 1, 0, tzinfo=timezone.utc)
ACCOUNT_ID = "simnow-test-account"
ACCOUNT_HASH = hashlib.sha256(ACCOUNT_ID.encode()).hexdigest()


class FakeRpc:
    def __init__(self) -> None:
        self.positions: list[dict[str, Any]] = []
        self.orders: list[dict[str, Any]] = []
        self.trades: list[dict[str, Any]] = []
        self.subscriptions: list[str] = []

    def status(self, *, probe: bool = False) -> dict[str, Any]:
        return {"connected": True, "gateway_name": "CTP"}

    def get_accounts(self) -> list[dict[str, Any]]:
        return [{"accountid": ACCOUNT_ID, "gateway_name": "CTP"}]

    def get_contracts(self) -> list[dict[str, Any]]:
        rows = []
        for product, spec in PRODUCT_SPECS.items():
            exchange = spec["exchange"]
            symbol = f"{product}2609"
            rows.append(
                {
                    "symbol": symbol,
                    "exchange": exchange,
                    "vt_symbol": f"{symbol}.{exchange}",
                    "size": spec["multiplier"],
                    "pricetick": spec["price_tick"],
                    "gateway_name": "CTP",
                }
            )
        return rows

    def get_positions(self) -> list[dict[str, Any]]:
        return list(self.positions)

    def get_orders(self) -> list[dict[str, Any]]:
        return list(self.orders)

    def get_trades(self) -> list[dict[str, Any]]:
        return list(self.trades)

    def subscribe_market(self, symbol: str, exchange: str) -> dict[str, Any]:
        self.subscriptions.append(f"{symbol}.{exchange}")
        return {"subscribed": True}


class FakeRisk:
    def __init__(self) -> None:
        self.web_trade_enabled = True
        self.emergency_stopped = False

    def status(self) -> dict[str, Any]:
        return {
            "web_trade_enabled": self.web_trade_enabled,
            "emergency_stopped": self.emergency_stopped,
        }


class FakeTrade:
    def __init__(self, fail_after: int | None = None) -> None:
        self.requests = []
        self.fail_after = fail_after

    def send_order(self, request, **kwargs) -> dict[str, Any]:
        if self.fail_after is not None and len(self.requests) >= self.fail_after:
            raise RuntimeError("simulated send failure")
        self.requests.append(request)
        return {"vt_orderid": f"CTP.{len(self.requests)}", "accepted": True}


class FakeAudit:
    def record(self, **kwargs) -> None:
        return None


class FakeTickStore:
    def __init__(self, now: datetime = NOW) -> None:
        self.ticks: dict[str, dict[str, Any]] = {}
        for index, (product, spec) in enumerate(PRODUCT_SPECS.items(), start=1):
            exchange = spec["exchange"]
            vt_symbol = f"{product}2609.{exchange}"
            tick = float(spec["price_tick"])
            mid = 1000.0 + index * 100.0
            bid = round(mid / tick) * tick
            self.ticks[vt_symbol] = {
                "bid_price_1": bid,
                "ask_price_1": bid + tick,
                "bid_volume_1": 50,
                "ask_volume_1": 50,
                "received_at": now.isoformat(),
            }

    def get_tick(self, vt_symbol: str) -> dict[str, Any] | None:
        return self.ticks.get(vt_symbol)


def make_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_json(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return json.dumps({"research-key": base64.b64encode(raw).decode()})


def make_settings(tmp_path: Path, private_key: Ed25519PrivateKey) -> Settings:
    return Settings(
        commodity_simnow_enabled=True,
        commodity_simnow_account_hashes=ACCOUNT_HASH,
        commodity_simnow_trusted_public_keys_json=public_key_json(private_key),
        commodity_simnow_state_path=str(tmp_path / "commodity-state.json"),
        commodity_simnow_max_child_order_lots=10,
        commodity_simnow_max_orders_per_phase=128,
        web_trade_enabled=True,
    )


def enable_payload() -> CommoditySimNowEnableRequestDTO:
    return CommoditySimNowEnableRequestDTO(
        manual_approval=True,
        simnow_mode=True,
        reason="manual SimNow integration test",
        confirm_simnow_only=True,
        confirm_no_production=True,
        confirm_cold_start_or_reconciled_state=True,
        confirm_manual_two_phase_dispatch=True,
        confirm_auto_dispatch=True,
        confirm_no_auto_promotion=True,
    )


def exact_contract(product: str) -> str:
    return f"{PRODUCT_SPECS[product]['exchange']}.{product}2609"


def completed_targets(quantities: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {
            "product": product,
            "exact_contract": exact_contract(product),
            "target_quantity": quantities.get(product, 0),
        }
        for product in PRODUCT_SPECS
    ]


def reference_price(product: str) -> float:
    return 1000.0 + (list(PRODUCT_SPECS).index(product) + 1) * 100.0


def make_batch(
    private_key: Ed25519PrivateKey,
    *,
    targets: dict[str, int] | None = None,
    previous: dict[str, int] | None = None,
    previous_batch_hash: str | None = None,
    execution_lane: str = "official_forward",
    source_month: str = "2026-08",
    execution_day: str = "2026-09-01",
) -> CommodityTargetBatchDTO:
    targets = targets or {"ag": 2, "al": -1}
    previous = previous or {}
    positives = [product for product, quantity in targets.items() if quantity > 0]
    negatives = [product for product, quantity in targets.items() if quantity < 0]
    weights = {product: 0.0 for product in PRODUCT_SPECS}
    if positives and negatives:
        for product in positives:
            weights[product] = 0.05 / len(positives)
        for product in negatives:
            weights[product] = -0.05 / len(negatives)
    rows = []
    for product, spec in PRODUCT_SPECS.items():
        previous_quantity = previous.get(product, 0)
        rows.append(
            {
                "product": product,
                "previous_exact_contract": exact_contract(product) if previous_batch_hash else None,
                "previous_target_quantity": previous_quantity,
                "exact_contract": exact_contract(product),
                "target_quantity": targets.get(product, 0),
                "source_target_weight": weights[product],
                "buffered_target_weight": weights[product],
                "reference_open_price": reference_price(product),
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
            }
        )
    data = {
        "schema_version": "commodity_static_core_equal_target_batch_v2",
        "batch_id": f"batch-{execution_day}-static-core",
        "scheduler_id": "STATIC_CORE_EQUAL",
        "source_combination_arm": "CORE_EQUAL_TARGET",
        "execution_lane": execution_lane,
        "source_month": source_month,
        "execution_day": execution_day,
        "virtual_nav_cny": 20_000_000,
        "candidate_weights": {"C": 0.5, "D": 0.5},
        "guardband": {"product": 0.12, "sector": 0.27, "gross": 0.8, "target_net": 0.0},
        "allocator": {
            "algorithm_id": "FINITE_NEIGHBOURHOOD_BEAM_V1",
            "neighbourhood_radius_lots": 2,
            "beam_width": 2048,
            "net_error_penalty": 1.0,
            "monthly_target_dates_only": True,
            "daily_auto_reweight": False,
            "roll_preserves_integer_lots": True,
        },
        "previous_batch_hash": previous_batch_hash,
        "targets": rows,
        "signer_key_id": "research-key",
        "signature": base64.b64encode(bytes(64)).decode(),
    }
    draft = CommodityTargetBatchDTO.model_validate(data)
    canonical = _canonical_json(draft.model_dump(mode="json", exclude={"signature"}))
    data["signature"] = base64.b64encode(private_key.sign(canonical)).decode()
    return CommodityTargetBatchDTO.model_validate(data)


def make_service(tmp_path: Path, *, trade: FakeTrade | None = None, now: datetime = NOW):
    private_key = make_key()
    rpc = FakeRpc()
    tick_store = FakeTickStore(now)
    service = CommoditySimNowService(
        settings=make_settings(tmp_path, private_key),
        rpc=rpc,  # type: ignore[arg-type]
        trade=trade or FakeTrade(),  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=tick_store,
        clock=lambda: now,
    )
    service.enable(enable_payload(), operator="admin", role="admin", source_ip="127.0.0.1")
    return service, private_key, rpc


def position(product: str, quantity: int, *, today: int = 0) -> dict[str, Any]:
    exact = exact_contract(product)
    exchange, symbol = exact.split(".", 1)
    return {
        "symbol": symbol,
        "exchange": exchange,
        "vt_symbol": f"{symbol}.{exchange}",
        "direction": "long" if quantity > 0 else "short",
        "volume": abs(quantity),
        "yd_volume": abs(quantity) - today,
        "frozen": 0,
    }


def move_quotes_against_orders(service: CommoditySimNowService, orders: list[dict[str, Any]]) -> None:
    for order in orders:
        quote = service.tick_store.ticks[order["vt_symbol"]]
        tick = float(PRODUCT_SPECS[order["product"]]["price_tick"])
        shift = tick if order["direction"] == "long" else -tick
        quote["bid_price_1"] += shift
        quote["ask_price_1"] += shift


def fills_for_requests(requests: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "vt_tradeid": f"CTP.T{index}",
            "vt_orderid": f"CTP.{index}",
            "price": request.price,
            "volume": request.volume,
        }
        for index, request in enumerate(requests, start=1)
    ]


def test_cold_start_preview_creates_open_only_plan(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)

    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    assert plan["status"] == "READY_OPEN"
    assert plan["close_orders"] == []
    assert {(row["product"], row["direction"], row["offset"], row["volume"]) for row in plan["open_orders"]} == {
        ("ag", "long", "open", 2),
        ("al", "short", "open", 1),
    }
    assert service.status()["production_allowed"] is False
    assert service.status()["auto_dispatch_allowed"] is True
    assert service.status()["auto_dispatch_active"] is False
    assert plan["execution_lane"] == "official_forward"
    assert plan["countable_forward"] is True


def test_shakedown_batch_can_trade_before_official_forward_window(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path, now=SHAKEDOWN_NOW)
    batch = make_batch(
        private_key,
        execution_lane="simnow_shakedown",
        source_month="2026-07",
        execution_day="2026-07-17",
    )

    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)
    submitted = service.auto_advance()

    assert plan["execution_lane"] == "simnow_shakedown"
    assert plan["countable_forward"] is False
    assert submitted["action"] == "open_submitted"
    assert service.plan()["status"] == "OPEN_SUBMITTED"

    rpc.positions = [position("ag", 2, today=2), position("al", -1, today=1)]
    completed = service.auto_advance()
    persisted = json.loads((tmp_path / "commodity-state.json").read_text(encoding="utf-8"))

    assert completed["status"] == "COMPLETE"
    assert persisted["execution_lane"] == "simnow_shakedown"
    assert persisted["countable_forward"] is False


def test_shakedown_batch_rejects_future_source_month(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path, now=SHAKEDOWN_NOW)
    batch = make_batch(
        private_key,
        execution_lane="simnow_shakedown",
        source_month="2026-08",
        execution_day="2026-07-17",
    )

    with pytest.raises(CommoditySimNowBatchError, match="未来 source month"):
        service.preview(batch, operator="admin", role="admin", source_ip=None)


def test_official_forward_still_rejects_pre_freeze_source_month(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path, now=SHAKEDOWN_NOW)
    batch = make_batch(
        private_key,
        execution_lane="official_forward",
        source_month="2026-07",
        execution_day="2026-07-17",
    )

    with pytest.raises(CommoditySimNowBatchError, match="official forward source month"):
        service.preview(batch, operator="admin", role="admin", source_ip=None)


def test_signed_reversal_runs_close_reconcile_open_reconcile(tmp_path: Path) -> None:
    trade = FakeTrade()
    service, private_key, rpc = make_service(tmp_path, trade=trade)
    previous_hash = "a" * 64
    previous = {"ag": 2, "al": -1}
    service._completed_state = {
        "last_completed_batch_hash": previous_hash,
        "targets": completed_targets(previous),
    }
    rpc.positions = [position("ag", 2), position("al", -1)]
    batch = make_batch(
        private_key,
        targets={"ag": -1, "al": 1},
        previous=previous,
        previous_batch_hash=previous_hash,
    )

    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)
    assert plan["status"] == "READY_CLOSE"
    assert [row["offset"] for row in plan["close_orders"]] == ["closeyesterday", "closeyesterday"]
    assert [row["offset"] for row in plan["open_orders"]] == ["open", "open"]

    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="close",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="manual close phase test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.positions = []
    reconciled = service.reconcile(plan["plan_hash"], operator="admin", role="admin", source_ip=None)
    assert reconciled["status"] == "READY_OPEN"

    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="manual open phase test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.positions = [position("ag", -1, today=1), position("al", 1, today=1)]
    completed = service.reconcile(plan["plan_hash"], operator="admin", role="admin", source_ip=None)

    assert completed["status"] == "COMPLETE"
    assert len(trade.requests) == 4
    assert all(request.gateway_name == "CTP" and request.confirm for request in trade.requests)
    persisted = json.loads((tmp_path / "commodity-state.json").read_text(encoding="utf-8"))
    assert persisted["last_completed_batch_hash"] == plan["batch_hash"]


def test_invalid_signature_is_rejected_before_plan(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    batch = make_batch(private_key)
    tampered = batch.model_copy(update={"signature": base64.b64encode(bytes(64)).decode()})

    with pytest.raises(CommoditySimNowBatchError, match="签名无效"):
        service.preview(tampered, operator="admin", role="admin", source_ip=None)


def test_execution_lane_is_covered_by_signature(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    batch = make_batch(private_key)
    tampered = batch.model_copy(update={"execution_lane": "simnow_shakedown"})

    with pytest.raises(CommoditySimNowBatchError, match="签名无效"):
        service.preview(tampered, operator="admin", role="admin", source_ip=None)


def test_unallowlisted_account_blocks_enable(tmp_path: Path) -> None:
    private_key = make_key()
    settings = make_settings(tmp_path, private_key).model_copy(
        update={"commodity_simnow_account_hashes": "b" * 64}
    )
    service = CommoditySimNowService(
        settings=settings,
        rpc=FakeRpc(),  # type: ignore[arg-type]
        trade=FakeTrade(),  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=FakeTickStore(),
        clock=lambda: NOW,
    )

    with pytest.raises(CommoditySimNowSafetyError, match="白名单 SimNow 账户"):
        service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)


def test_today_position_blocks_monthly_offset_plan(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    previous_hash = "c" * 64
    service._completed_state = {
        "last_completed_batch_hash": previous_hash,
        "targets": completed_targets({"ag": 2}),
    }
    rpc.positions = [position("ag", 2, today=1)]
    batch = make_batch(
        private_key,
        targets={"ag": 1, "al": -1},
        previous={"ag": 2},
        previous_batch_hash=previous_hash,
    )

    with pytest.raises(CommoditySimNowSafetyError, match="平今仓位"):
        service.preview(batch, operator="admin", role="admin", source_ip=None)


def test_partial_submission_fail_closed(tmp_path: Path) -> None:
    trade = FakeTrade(fail_after=1)
    service, private_key, _ = make_service(tmp_path, trade=trade)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    with pytest.raises(CommoditySimNowStateError, match="部分提交"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="manual partial failure test",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.plan()["status"] == "OPEN_SUBMISSION_PARTIAL"
    assert service.order_endpoint_touched is True


def test_noop_batch_completes_and_advances_chain_on_preview(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    batch = make_batch(private_key, targets={product: 0 for product in PRODUCT_SPECS})

    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)

    assert plan["status"] == "COMPLETE"
    persisted = json.loads((tmp_path / "commodity-state.json").read_text(encoding="utf-8"))
    assert persisted["last_completed_batch_hash"] == plan["batch_hash"]


def test_disable_preserves_submitted_plan_but_blocks_reconcile(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="manual disable state test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    with pytest.raises(CommoditySimNowStateError, match="不允许覆盖"):
        service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    service.disable(
        CommoditySimNowDisableRequestDTO(reason="manual stop"),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert service.plan()["status"] == "OPEN_SUBMITTED"
    assert service.status()["simnow_mode"] is False
    with pytest.raises(CommoditySimNowDisabledError, match="未启用"):
        service.reconcile(plan["plan_hash"], operator="admin", role="admin", source_ip=None)


def test_corrupt_completed_state_blocks_enable(tmp_path: Path) -> None:
    private_key = make_key()
    state_path = tmp_path / "commodity-state.json"
    state_path.write_text('{"schema_version":"wrong","targets":[]}', encoding="utf-8")
    service = CommoditySimNowService(
        settings=make_settings(tmp_path, private_key),
        rpc=FakeRpc(),  # type: ignore[arg-type]
        trade=FakeTrade(),  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=FakeTickStore(),
        clock=lambda: NOW,
    )

    with pytest.raises(CommoditySimNowSafetyError, match="持久化状态损坏"):
        service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)


def test_auto_dispatch_reversal_records_fills_and_slippage(tmp_path: Path) -> None:
    trade = FakeTrade()
    service, private_key, rpc = make_service(tmp_path, trade=trade)
    previous_hash = "d" * 64
    previous = {"ag": 2, "al": -1}
    service._completed_state = {
        "last_completed_batch_hash": previous_hash,
        "targets": completed_targets(previous),
    }
    rpc.positions = [position("ag", 2), position("al", -1)]
    plan = service.preview(
        make_batch(
            private_key,
            targets={"ag": -1, "al": 1},
            previous=previous,
            previous_batch_hash=previous_hash,
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    move_quotes_against_orders(service, plan["close_orders"])

    close_result = service.auto_advance()

    assert close_result["action"] == "close_submitted"
    assert service.plan()["status"] == "CLOSE_SUBMITTED"
    assert all(row["dispatch_mode"] == "auto" for row in service.plan()["submitted"]["close"])

    rpc.trades = fills_for_requests(trade.requests)
    rpc.positions = []
    open_result = service.auto_advance()

    assert open_result["action"] == "close_reconciled_open_submitted"
    assert service.plan()["status"] == "OPEN_SUBMITTED"
    assert len(trade.requests) == 4

    rpc.trades = fills_for_requests(trade.requests)
    rpc.positions = [position("ag", -1, today=1), position("al", 1, today=1)]
    completed = service.auto_advance()

    assert completed["action"] == "open_reconciled"
    assert completed["status"] == "COMPLETE"
    execution = completed["execution"]
    assert execution["fill_ratio"] == 1.0
    assert execution["filled_volume"] == 5
    assert execution["average_adverse_slippage_ticks"] == pytest.approx(1.0)
    assert execution["slippage_cny"] > 0
    persisted = json.loads((tmp_path / "commodity-state.json").read_text(encoding="utf-8"))
    assert persisted["execution"]["fill_ratio"] == 1.0


def test_auto_dispatch_partial_submission_revokes_authorization(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path, trade=FakeTrade(fail_after=1))
    service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    with pytest.raises(CommoditySimNowStateError, match="部分提交"):
        service.auto_advance()

    assert service.plan()["status"] == "OPEN_SUBMISSION_PARTIAL"
    assert service.status()["auto_dispatch_allowed"] is False
    assert service.auto_advance()["reason"] == "auto_dispatch_not_active"


def test_auto_dispatch_requires_explicit_enable_confirmation(tmp_path: Path) -> None:
    private_key = make_key()
    service = CommoditySimNowService(
        settings=make_settings(tmp_path, private_key),
        rpc=FakeRpc(),  # type: ignore[arg-type]
        trade=FakeTrade(),  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=FakeTickStore(),
        clock=lambda: NOW,
    )

    with pytest.raises(CommoditySimNowSafetyError, match="自动派单授权"):
        service.enable(
            enable_payload().model_copy(update={"confirm_auto_dispatch": False}),
            operator="admin",
            role="admin",
            source_ip=None,
        )


def test_auto_dispatch_worker_starts_and_stops(tmp_path: Path) -> None:
    service, _, _ = make_service(tmp_path)

    async def exercise() -> None:
        service.start()
        await asyncio.sleep(0)
        assert service.status()["auto_dispatch_worker_alive"] is True
        assert service.status()["auto_dispatch_active"] is True
        await service.stop()
        assert service.status()["auto_dispatch_worker_alive"] is False
        assert service.status()["auto_dispatch_active"] is False
        assert service.status()["auto_dispatch_allowed"] is False

    asyncio.run(exercise())


def test_auto_dispatch_halts_after_terminal_reconciliation_mismatch(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.auto_advance()
    service.clock = lambda: NOW + timedelta(seconds=31)

    result = service.auto_advance()

    assert result["action"] == "open_reconciliation_mismatch"
    assert result["status"] == "OPEN_RECONCILIATION_MISMATCH"
    assert result["reconciliation"]["mismatch_halted"] is True
    assert service.status()["auto_dispatch_allowed"] is False


def test_auto_dispatch_waits_while_partial_order_is_active(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.auto_advance()
    submitted = service.plan()["submitted"]["open"][0]
    rpc.orders = [
        {
            "vt_orderid": submitted["vt_orderid"],
            "reference": submitted["reference"],
            "status": "部分成交",
        }
    ]
    service.clock = lambda: NOW + timedelta(seconds=31)

    result = service.auto_advance()

    assert result["action"] == "open_reconciled"
    assert result["status"] == "OPEN_SUBMITTED"
    assert result["reconciliation"]["active_order_ids"] == [submitted["vt_orderid"]]
    assert result["reconciliation"]["mismatch_halted"] is False
    assert service.status()["auto_dispatch_allowed"] is True
