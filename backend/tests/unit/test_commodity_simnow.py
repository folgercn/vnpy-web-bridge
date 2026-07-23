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
    CommoditySimNowSafetyError,
    CommoditySimNowStateError,
    RiskMaxOrderVolumeError,
    RpcTimeoutError,
)
from app.schemas.commodity_simnow import (
    CommodityPlanExecuteRequestDTO,
    CommodityPositionManagerShadowDTO,
    CommoditySimNowDisableRequestDTO,
    CommoditySimNowEnableRequestDTO,
    CommodityTemplateStartRequestDTO,
    CommodityTargetBatchDTO,
)
from app.services.commodity_simnow import (
    POSITION_MANAGER_SECTOR_MAP_V1,
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
    def __init__(self, contract_months: tuple[str, ...] = ("2610",)) -> None:
        self.positions: list[dict[str, Any]] = []
        self.orders: list[dict[str, Any]] = []
        self.trades: list[dict[str, Any]] = []
        self.subscriptions: list[str] = []
        self.contract_months = contract_months
        self.get_orders_error: Exception | None = None

    def status(self, *, probe: bool = False) -> dict[str, Any]:
        return {"connected": True, "gateway_name": "CTP"}

    def get_accounts(self) -> list[dict[str, Any]]:
        return [{"accountid": ACCOUNT_ID, "gateway_name": "CTP"}]

    def get_contracts(self) -> list[dict[str, Any]]:
        rows = []
        for product, spec in PRODUCT_SPECS.items():
            exchange = spec["exchange"]
            for contract_month in self.contract_months:
                symbol = f"{product}{contract_month}"
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
        if self.get_orders_error is not None:
            raise self.get_orders_error
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
        self.rules = {"max_symbol_position": 500}

    def status(self) -> dict[str, Any]:
        return {
            "web_trade_enabled": self.web_trade_enabled,
            "emergency_stopped": self.emergency_stopped,
        }

    def get_rules(self) -> dict[str, Any]:
        return dict(self.rules)


class FakeTrade:
    def __init__(self, fail_after: int | None = None, *, complete_cancel: bool = True) -> None:
        self.requests = []
        self.cancel_requests: list[str] = []
        self.fail_after = fail_after
        self.complete_cancel = complete_cancel
        self.rpc: FakeRpc | None = None

    def send_order(self, request, **kwargs) -> dict[str, Any]:
        if self.fail_after is not None and len(self.requests) >= self.fail_after:
            raise RuntimeError("simulated send failure")
        self.requests.append(request)
        return {"vt_orderid": f"CTP.{len(self.requests)}", "accepted": True}

    def cancel_order(self, vt_orderid: str, **kwargs) -> dict[str, Any]:
        self.cancel_requests.append(vt_orderid)
        if self.complete_cancel and self.rpc:
            for order in self.rpc.orders:
                if order.get("vt_orderid") == vt_orderid:
                    order["status"] = "cancelled"
        return {"vt_orderid": vt_orderid, "cancel_requested": True}


class CrashBeforeSendTrade(FakeTrade):
    def send_order(self, request, **kwargs) -> dict[str, Any]:
        raise SystemExit("simulated process crash before RPC send")


class CrashAfterAcceptTrade(FakeTrade):
    def send_order(self, request, **kwargs) -> dict[str, Any]:
        self.requests.append(request)
        vt_orderid = f"CTP.{len(self.requests)}"
        assert self.rpc is not None
        self.rpc.orders.append(
            {
                "vt_orderid": vt_orderid,
                "reference": request.reference,
                "status": "not_traded",
                "offset": request.offset,
                "volume": request.volume,
            }
        )
        raise SystemExit("simulated process crash after exchange acceptance")


class LocalRiskRejectTrade(FakeTrade):
    def send_order(self, request, **kwargs) -> dict[str, Any]:
        raise RiskMaxOrderVolumeError()


class RpcTimeoutTrade(FakeTrade):
    def send_order(self, request, **kwargs) -> dict[str, Any]:
        raise RpcTimeoutError()


class FakeAudit:
    def record(self, **kwargs) -> None:
        return None


class FakeTickStore:
    def __init__(
        self,
        now: datetime = NOW,
        contract_months: tuple[str, ...] = ("2610",),
    ) -> None:
        self.ticks: dict[str, dict[str, Any]] = {}
        for index, (product, spec) in enumerate(PRODUCT_SPECS.items(), start=1):
            exchange = spec["exchange"]
            tick = float(spec["price_tick"])
            mid = 1000.0 + index * 100.0
            bid = round(mid / tick) * tick
            for contract_month in contract_months:
                vt_symbol = f"{product}{contract_month}.{exchange}"
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
        commodity_position_manager_shadow_state_path=str(
            tmp_path / "position-manager-shadow-state.json"
        ),
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


def template_start_payload() -> CommodityTemplateStartRequestDTO:
    return CommodityTemplateStartRequestDTO(
        reason="one-click STATIC_CORE_EQUAL SimNow integration test",
        confirm_strategy_template=True,
        confirm_simnow_only=True,
        confirm_auto_dispatch=True,
        confirm_no_production=True,
    )


def exact_contract(product: str, contract_month: str = "2610") -> str:
    return f"{PRODUCT_SPECS[product]['exchange']}.{product}{contract_month}"


def completed_targets(quantities: dict[str, int], contract_month: str = "2610") -> list[dict[str, Any]]:
    return [
        {
            "product": product,
            "exact_contract": exact_contract(product, contract_month),
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
    target_contract_month: str = "2610",
    previous_contract_month: str | None = None,
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
                "previous_exact_contract": (exact_contract(product, previous_contract_month or target_contract_month) if previous_batch_hash else None),
                "previous_target_quantity": previous_quantity,
                "exact_contract": exact_contract(product, target_contract_month),
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


def make_position_manager_shadow(
    private_key: Ed25519PrivateKey,
    *,
    baseline_batch_hash: str,
    raw_scale: float | None = None,
    previous_scale: float = 1.0,
    continuity_mode: str = "genesis",
    previous_snapshot_hash: str | None = None,
    source_month: str = "2026-08",
    execution_day: str = "2026-09-01",
    input_cutoff_day: str = "2026-08-31",
) -> CommodityPositionManagerShadowDTO:
    fast_vol = 0.04
    slow_vol = 0.05
    calculated_raw = (slow_vol / fast_vol) ** 0.5
    effective_raw = calculated_raw if raw_scale is None else raw_scale
    smoothed_scale = 0.5 * effective_raw + 0.5 * previous_scale
    rows = []
    baseline_quantities = {"ag": 2, "al": -1}
    shadow_quantities = {"ag": 3, "al": -2}
    baseline_weights = {product: 0.0 for product in PRODUCT_SPECS}
    shadow_weights = {product: 0.0 for product in PRODUCT_SPECS}
    baseline_weights.update({"ag": 0.05, "al": -0.05})
    shadow_weights.update({"ag": 0.05 * smoothed_scale, "al": -0.05 * smoothed_scale})
    for product, spec in PRODUCT_SPECS.items():
        rows.append(
            {
                "product": product,
                "exact_contract": exact_contract(product),
                "baseline_target_quantity": baseline_quantities.get(product, 0),
                "shadow_target_quantity": shadow_quantities.get(product, 0),
                "baseline_source_target_weight": baseline_weights[product],
                "shadow_source_target_weight": baseline_weights[product] * smoothed_scale,
                "baseline_buffered_target_weight": baseline_weights[product],
                "shadow_buffered_target_weight": shadow_weights[product],
                "reference_open_price": reference_price(product),
                "multiplier": spec["multiplier"],
                "price_tick": spec["price_tick"],
            }
        )
    data = {
        "schema_version": "commodity_relative_vol_position_manager_shadow_v2",
        "snapshot_id": "shadow-2026-09-static-core",
        "position_manager_id": "MONTHLY_RELATIVE_VOL_THERMOSTAT_V1",
        "sector_map_id": "POSITION_MANAGER_SECTOR_MAP_V1",
        "mode": "shadow_only",
        "baseline_scheduler_id": "STATIC_CORE_EQUAL",
        "baseline_batch_hash": baseline_batch_hash,
        "source_month": source_month,
        "execution_day": execution_day,
        "input_cutoff_day": input_cutoff_day,
        "fast_lookback_days": 21,
        "slow_lookback_days": 126,
        "annualization_days": 252,
        "fast_annual_vol": fast_vol,
        "slow_annual_vol": slow_vol,
        "scale_min": 0.8,
        "scale_max": 1.2,
        "raw_scale": effective_raw,
        "continuity_mode": continuity_mode,
        "previous_snapshot_hash": previous_snapshot_hash,
        "previous_smoothed_scale": previous_scale,
        "smoothing_alpha": 0.5,
        "smoothed_scale": smoothed_scale,
        "daily_auto_reweight": False,
        "guardband_reapplied": True,
        "authority_granted": False,
        "dispatch_allowed": False,
        "targets": rows,
        "signer_key_id": "research-key",
        "signature": base64.b64encode(bytes(64)).decode(),
    }
    return sign_position_manager_shadow_payload(data, private_key)


def sign_position_manager_shadow_payload(
    data: dict[str, Any], private_key: Ed25519PrivateKey
) -> CommodityPositionManagerShadowDTO:
    payload = json.loads(json.dumps(data))
    payload["signature"] = base64.b64encode(bytes(64)).decode()
    draft = CommodityPositionManagerShadowDTO.model_validate(payload)
    canonical = _canonical_json(draft.model_dump(mode="json", exclude={"signature"}))
    payload["signature"] = base64.b64encode(private_key.sign(canonical)).decode()
    return CommodityPositionManagerShadowDTO.model_validate(payload)


def make_service(
    tmp_path: Path,
    *,
    trade: FakeTrade | None = None,
    now: datetime = NOW,
    contract_months: tuple[str, ...] = ("2610",),
    auto_enable: bool = True,
    template_batch_path: Path | None = None,
):
    private_key = make_key()
    rpc = FakeRpc(contract_months)
    tick_store = FakeTickStore(now, contract_months)
    settings = make_settings(tmp_path, private_key)
    if template_batch_path is not None:
        settings = settings.model_copy(update={"commodity_simnow_template_batch_path": str(template_batch_path)})
    trade_service = trade or FakeTrade()
    trade_service.rpc = rpc
    risk_service = FakeRisk()
    service = CommoditySimNowService(
        settings=settings,
        rpc=rpc,  # type: ignore[arg-type]
        trade=trade_service,  # type: ignore[arg-type]
        risk=risk_service,  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=tick_store,
        clock=lambda: now,
    )
    if auto_enable:
        service.enable(enable_payload(), operator="admin", role="admin", source_ip="127.0.0.1")
    return service, private_key, rpc


def position(
    product: str,
    quantity: int,
    *,
    today: int = 0,
    contract_month: str = "2610",
) -> dict[str, Any]:
    exact = exact_contract(product, contract_month)
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


def write_batch(path: Path, batch: CommodityTargetBatchDTO) -> None:
    path.write_text(
        json.dumps(batch.model_dump(mode="json"), ensure_ascii=False),
        encoding="utf-8",
    )


def write_position_manager_shadow(
    path: Path, snapshot: CommodityPositionManagerShadowDTO
) -> None:
    path.write_text(
        json.dumps(snapshot.model_dump(mode="json"), ensure_ascii=False),
        encoding="utf-8",
    )


def prepare_position_manager_shakedown(tmp_path: Path):
    service, private_key, rpc = make_service(tmp_path)
    baseline = service.preview(
        make_batch(private_key), operator="admin", role="admin", source_ip=None
    )
    service.current_plan["status"] = "COMPLETE"
    service._save_completed_state(service.current_plan)
    service.current_plan = None
    shadow_path = tmp_path / "position-manager-shadow.json"
    write_position_manager_shadow(
        shadow_path,
        make_position_manager_shadow(private_key, baseline_batch_hash=baseline["batch_hash"]),
    )
    service.settings = service.settings.model_copy(
        update={
            "commodity_position_manager_shadow_path": str(shadow_path),
            "commodity_position_manager_simnow_shakedown_enabled": True,
            "commodity_position_manager_simnow_state_path": str(
                tmp_path / "position-manager-shakedown.json"
            ),
        }
    )
    rpc.positions = [position("ag", 2), position("al", -1)]
    return service, rpc


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


def test_acceptance_passive_limit_is_explicit_and_uses_touch_price(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path, now=SHAKEDOWN_NOW)
    service.settings = service.settings.model_copy(
        update={"commodity_simnow_acceptance_passive_limit_enabled": True}
    )
    batch = make_batch(
        private_key,
        targets={"ag": 1, "al": -1},
        execution_lane="simnow_shakedown",
        source_month="2026-07",
        execution_day="2026-07-17",
    )
    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)

    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            acceptance_passive_limit=True,
            confirm_acceptance_passive_limit=True,
            reason="SimNow passive limit acceptance test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    requests = service.trade.requests
    assert requests[0].price == service.tick_store.ticks["ag2610.SHFE"]["bid_price_1"]
    assert requests[1].price == service.tick_store.ticks["al2610.SHFE"]["ask_price_1"]
    assert service.plan()["submitted"]["open"][0]["price_mode"] == "acceptance_passive"


def test_acceptance_passive_limit_rejects_official_forward_plan(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_simnow_acceptance_passive_limit_enabled": True}
    )
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    with pytest.raises(CommoditySimNowSafetyError, match="只允许 SimNow shakedown"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                acceptance_passive_limit=True,
                confirm_acceptance_passive_limit=True,
                reason="SimNow passive limit acceptance test",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )


def test_acceptance_passive_limit_requires_config_and_manual_dispatch(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path, now=SHAKEDOWN_NOW)
    batch = make_batch(
        private_key,
        targets={"ag": 1, "al": -1},
        execution_lane="simnow_shakedown",
        source_month="2026-07",
        execution_day="2026-07-17",
    )
    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)
    payload = CommodityPlanExecuteRequestDTO(
        plan_hash=plan["plan_hash"],
        phase="open",
        confirm=True,
        confirm_simnow_only=True,
        confirm_manual_one_shot=True,
        acceptance_passive_limit=True,
        confirm_acceptance_passive_limit=True,
        reason="SimNow passive limit acceptance test",
    )

    with pytest.raises(CommoditySimNowSafetyError, match="未启用"):
        service.execute(payload, operator="admin", role="admin", source_ip=None)

    service.settings = service.settings.model_copy(
        update={"commodity_simnow_acceptance_passive_limit_enabled": True}
    )
    with pytest.raises(CommoditySimNowSafetyError, match="只允许人工单次派单"):
        service.execute(
            payload,
            operator="admin",
            role="admin",
            source_ip=None,
            dispatch_mode="auto",
        )


def test_acceptance_passive_limit_rejects_phase_above_hard_limit(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path, now=SHAKEDOWN_NOW)
    service.settings = service.settings.model_copy(
        update={"commodity_simnow_acceptance_passive_limit_enabled": True}
    )
    batch = make_batch(
        private_key,
        execution_lane="simnow_shakedown",
        source_month="2026-07",
        execution_day="2026-07-17",
    )
    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)

    with pytest.raises(CommoditySimNowSafetyError, match="规模超过硬上限"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                acceptance_passive_limit=True,
                confirm_acceptance_passive_limit=True,
                reason="SimNow passive limit acceptance test",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )
    assert service.trade.requests == []


def test_acceptance_passive_limit_ttl_cancels_and_halts(tmp_path: Path) -> None:
    now = [SHAKEDOWN_NOW]
    trade = FakeTrade()
    service, private_key, rpc = make_service(tmp_path, now=SHAKEDOWN_NOW, trade=trade)
    service.clock = lambda: now[0]
    service.settings = service.settings.model_copy(
        update={
            "commodity_simnow_acceptance_passive_limit_enabled": True,
            "commodity_simnow_acceptance_passive_limit_ttl_seconds": 5,
        }
    )
    batch = make_batch(
        private_key,
        targets={"ag": 1, "al": -1},
        execution_lane="simnow_shakedown",
        source_month="2026-07",
        execution_day="2026-07-17",
    )
    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            acceptance_passive_limit=True,
            confirm_acceptance_passive_limit=True,
            reason="SimNow passive limit acceptance test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.orders = [
        {
            "vt_orderid": f"CTP.{index}",
            "reference": request.reference,
            "status": "not_traded",
            "offset": request.offset,
            "volume": request.volume,
        }
        for index, request in enumerate(trade.requests, start=1)
    ]
    now[0] = SHAKEDOWN_NOW + timedelta(seconds=5)

    result = service._acceptance_passive_ttl_advance()

    assert result["action"] == "halted"
    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
    assert trade.cancel_requests == ["CTP.1", "CTP.2"]

    reconciled = service.reconcile(
        plan["plan_hash"], operator="admin", role="admin", source_ip=None
    )

    assert reconciled["status"] == "HALTED_RECONCILED"
    assert reconciled["reconciliation"]["expected_positions"] == {}
    assert reconciled["reconciliation"]["observed_positions"] == {}
    assert service.plan()["halt"]["resume_status"] == "READY_OPEN"


def test_acceptance_passive_limit_ttl_persists_cancel_pending_when_rpc_unavailable(tmp_path: Path) -> None:
    now = [SHAKEDOWN_NOW]
    service, private_key, rpc = make_service(tmp_path, now=SHAKEDOWN_NOW)
    service.clock = lambda: now[0]
    service.settings = service.settings.model_copy(
        update={
            "commodity_simnow_acceptance_passive_limit_enabled": True,
            "commodity_simnow_acceptance_passive_limit_ttl_seconds": 5,
        }
    )
    batch = make_batch(
        private_key,
        targets={"ag": 1, "al": -1},
        execution_lane="simnow_shakedown",
        source_month="2026-07",
        execution_day="2026-07-17",
    )
    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            acceptance_passive_limit=True,
            confirm_acceptance_passive_limit=True,
            reason="SimNow passive limit acceptance test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    now[0] = SHAKEDOWN_NOW + timedelta(seconds=5)
    rpc.get_orders_error = RuntimeError("SimNow RPC unavailable")

    result = service._acceptance_passive_ttl_advance()

    assert result["action"] == "halted"
    assert service.plan()["status"] == "CANCEL_PENDING"


def test_recovery_worker_retries_acceptance_cancel_when_auto_dispatch_is_disabled(tmp_path: Path) -> None:
    now = [SHAKEDOWN_NOW]
    trade = FakeTrade()
    service, private_key, rpc = make_service(tmp_path, now=SHAKEDOWN_NOW, trade=trade)
    service.clock = lambda: now[0]
    service.settings = service.settings.model_copy(
        update={
            "commodity_simnow_auto_dispatch_enabled": False,
            "commodity_simnow_auto_dispatch_interval_seconds": 0.25,
            "commodity_simnow_acceptance_passive_limit_enabled": True,
            "commodity_simnow_acceptance_passive_limit_ttl_seconds": 5,
        }
    )
    batch = make_batch(
        private_key,
        targets={"ag": 1, "al": -1},
        execution_lane="simnow_shakedown",
        source_month="2026-07",
        execution_day="2026-07-17",
    )
    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            acceptance_passive_limit=True,
            confirm_acceptance_passive_limit=True,
            reason="SimNow passive limit acceptance test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.orders = [
        {
            "vt_orderid": f"CTP.{index}",
            "reference": request.reference,
            "status": "not_traded",
            "offset": request.offset,
            "volume": request.volume,
        }
        for index, request in enumerate(trade.requests, start=1)
    ]
    now[0] = SHAKEDOWN_NOW + timedelta(seconds=5)
    rpc.get_orders_error = RuntimeError("SimNow RPC unavailable")
    service._acceptance_passive_ttl_advance()
    assert service.plan()["status"] == "CANCEL_PENDING"
    rpc.get_orders_error = None

    async def exercise() -> None:
        service.start()
        await asyncio.sleep(0.35)
        assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
        assert trade.cancel_requests == ["CTP.1", "CTP.2"]
        assert len(trade.requests) == 2
        await service.stop()

    asyncio.run(exercise())


def test_position_manager_shadow_is_verified_and_never_dispatched(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    path = tmp_path / "position-manager-shadow.json"
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(private_key, baseline_batch_hash=plan["batch_hash"]),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["valid"] is True
    assert snapshot["baseline_link_state"] == "active"
    assert snapshot["sector_map_id"] == "POSITION_MANAGER_SECTOR_MAP_V1"
    assert snapshot["continuity_state"] == "genesis"
    assert snapshot["continuity_verified"] is True
    assert snapshot["target_change_count"] == 2
    assert snapshot["maximum_abs_target_quantity_delta"] == 1
    assert snapshot["authority_granted"] is False
    assert snapshot["dispatch_allowed"] is False
    assert len(snapshot["targets"]) == 10
    assert {(row["product"], row["volume"]) for row in plan["open_orders"]} == {
        ("ag", 2),
        ("al", 1),
    }


def test_position_manager_shakedown_preview_builds_non_executing_two_phase_plan(
    tmp_path: Path,
) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)

    result = service.preview_position_manager_shakedown(
        ["ag", "al"], operator="admin", role="admin", source_ip=None
    )

    session = result["session"]
    assert result["execution_enabled"] is False
    assert session["status"] == "PREVIEW_READY"
    assert session["countable_forward"] is False
    assert session["plan"]["phase_status"] == "READY_OPEN"
    assert session["plan"]["close_orders"] == []
    assert {(row["product"], row["direction"], row["volume"]) for row in session["plan"]["open_orders"]} == {
        ("ag", "long", 1),
        ("al", "short", 1),
    }
    references = {row["reference"] for row in session["plan"]["open_orders"]}
    assert len(references) == 2
    assert all(reference.startswith("commodity_pm:sh:") for reference in references)
    assert service.trade.requests == []


def test_position_manager_shakedown_preview_rejects_account_change(tmp_path: Path) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_simnow_account_hashes": "b" * 64}
    )

    with pytest.raises(CommoditySimNowSafetyError, match="白名单"):
        service.preview_position_manager_shakedown(
            ["ag"], operator="admin", role="admin", source_ip=None
        )


def test_position_manager_shakedown_preview_rejects_unfinished_baseline(
    tmp_path: Path,
) -> None:
    service, private_key, rpc = make_service(tmp_path)
    baseline = service.preview(
        make_batch(private_key), operator="admin", role="admin", source_ip=None
    )
    shadow_path = tmp_path / "position-manager-shadow.json"
    write_position_manager_shadow(
        shadow_path,
        make_position_manager_shadow(private_key, baseline_batch_hash=baseline["batch_hash"]),
    )
    service.settings = service.settings.model_copy(
        update={
            "commodity_position_manager_shadow_path": str(shadow_path),
            "commodity_position_manager_simnow_shakedown_enabled": True,
        }
    )
    rpc.positions = [position("ag", 2), position("al", -1)]

    with pytest.raises(CommoditySimNowStateError, match="正式 SimNow 计划占用"):
        service.preview_position_manager_shakedown(
            ["ag"], operator="admin", role="admin", source_ip=None
        )


def test_position_manager_shakedown_preview_rejects_conflicting_active_order(
    tmp_path: Path,
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    rpc.orders = [{
        "vt_orderid": "CTP.conflict",
        "symbol": "ag2610",
        "exchange": "SHFE",
        "reference": "manual-order",
        "status": "not_traded",
    }]

    with pytest.raises(CommoditySimNowStateError, match="活动策略委托"):
        service.preview_position_manager_shakedown(
            ["ag"], operator="admin", role="admin", source_ip=None
        )


@pytest.mark.parametrize(
    "bad_position",
    [
        position("ag", 1),
        position("ag", 2, today=1),
    ],
)
def test_position_manager_shakedown_preview_rejects_unattributed_or_today_position(
    tmp_path: Path, bad_position: dict[str, Any]
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    rpc.positions = [bad_position, position("al", -1)]

    with pytest.raises(CommoditySimNowSafetyError):
        service.preview_position_manager_shakedown(
            ["ag"], operator="admin", role="admin", source_ip=None
        )


def test_position_manager_shakedown_preview_rejects_unselected_baseline_drift(
    tmp_path: Path,
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    rpc.positions = [position("ag", 2), position("al", -2)]

    with pytest.raises(CommoditySimNowSafetyError, match="完整证明属于关联 baseline"):
        service.preview_position_manager_shakedown(
            ["ag"], operator="admin", role="admin", source_ip=None
        )


def test_position_manager_shakedown_preview_uses_unique_session_references(
    tmp_path: Path,
) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    first = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    second = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    first_references = {row["reference"] for row in first["session"]["plan"]["open_orders"]}
    second_references = {row["reference"] for row in second["session"]["plan"]["open_orders"]}
    assert first_references.isdisjoint(second_references)


def test_position_manager_shakedown_preview_checks_complete_mixed_portfolio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    captured: dict[str, Any] = {}

    def verify(
        targets: list[dict[str, Any]], positions: dict[str, int], *, sector_map: dict[str, str] | None = None
    ) -> dict[str, Any]:
        captured["targets"] = targets
        captured["positions"] = positions
        captured["sector_map"] = sector_map
        return {"snapshot_hash": "risk-snapshot"}

    monkeypatch.setattr(service, "_verify_realtime_exposures", verify)
    result = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    assert {row["product"] for row in captured["targets"]} == set(PRODUCT_SPECS)
    assert next(row for row in captured["targets"] if row["product"] == "ag")["target_quantity"] == 3
    assert next(row for row in captured["targets"] if row["product"] == "al")["target_quantity"] == -1
    assert captured["sector_map"] == POSITION_MANAGER_SECTOR_MAP_V1
    assert result["session"]["plan"]["preview_exposure_snapshot"] == {"snapshot_hash": "risk-snapshot"}


def test_position_manager_shakedown_preview_checks_phase_order_limit(tmp_path: Path) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_simnow_max_orders_per_phase": 1}
    )

    with pytest.raises(CommoditySimNowSafetyError, match="拆单数量超过单阶段上限"):
        service.preview_position_manager_shakedown(
            ["ag", "al"], operator="admin", role="admin", source_ip=None
        )


def test_position_manager_shakedown_start_auto_submits_previewed_phase(tmp_path: Path) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    service.enabled = False
    service.manual_approval = False
    service.simnow_mode = False
    service.auto_dispatch_authorized = False
    service.template_authorized = False
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    result = service.start_position_manager_shakedown(
        preview["preview"]["plan_hash"], operator="admin", role="admin", source_ip=None
    )

    assert result["action"] == "open_submitted"
    assert service.current_plan is not None
    assert service.current_plan["position_manager_shakedown_session_id"] == preview["preview"]["session_id"]
    assert service.current_plan["status"] == "OPEN_SUBMITTED"
    assert len(service.trade.requests) == 1
    assert service.trade.requests[0].reference.startswith("commodity_pm:sh:")
    assert service.enabled is True
    assert service.manual_approval is True
    assert service.simnow_mode is True
    assert service.auto_dispatch_authorized is False


def test_position_manager_shakedown_start_rejects_changed_account_or_plan_hash(tmp_path: Path) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    with pytest.raises(CommoditySimNowStateError, match="哈希不匹配"):
        service.start_position_manager_shakedown(
            "0" * 64, operator="admin", role="admin", source_ip=None
        )

    service.settings = service.settings.model_copy(
        update={"commodity_simnow_account_hashes": "b" * 64}
    )
    with pytest.raises(CommoditySimNowSafetyError, match="白名单"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"], operator="admin", role="admin", source_ip=None
        )


def test_position_manager_shakedown_stop_only_cancels_session_reference(tmp_path: Path) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    service.start_position_manager_shakedown(
        preview["preview"]["plan_hash"], operator="admin", role="admin", source_ip=None
    )
    request = service.trade.requests[0]
    rpc.orders = [
        {
            "vt_orderid": "CTP.1", "symbol": request.symbol, "exchange": request.exchange,
            "reference": request.reference, "status": "not_traded",
        },
        {
            "vt_orderid": "CTP.manual", "symbol": "al2610", "exchange": "SHFE",
            "reference": "manual-order", "status": "not_traded",
        },
    ]

    stopped = service.stop_position_manager_shakedown(
        "operator requested stop", operator="admin", role="admin", source_ip=None
    )

    assert service.trade.cancel_requests == ["CTP.1"]
    assert stopped["halt"]["status"] == "HALTED_RECONCILE_REQUIRED"


def test_position_manager_shakedown_pre_submit_stop_archives_and_unblocks_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    def fail_before_submit(**kwargs):
        raise CommoditySimNowStateError("simulated pre-submit failure")

    monkeypatch.setattr(
        service, "auto_position_manager_shakedown_advance", fail_before_submit
    )
    with pytest.raises(CommoditySimNowStateError, match="simulated pre-submit"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    stopped = service.stop_position_manager_shakedown(
        "operator abandons pre-submit shakedown",
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert stopped["halt"]["status"] == "HALTED_RECONCILED"
    assert stopped["halt"]["abandoned_pre_submit"] is True
    assert service.current_plan is None
    assert not service._active_state_path().exists()
    replacement = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    assert replacement["session"]["status"] == "PREVIEW_READY"


def test_position_manager_shakedown_restart_resumes_via_dedicated_start_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    def fail_before_submit(**kwargs):
        raise CommoditySimNowStateError("simulated pre-submit failure")

    monkeypatch.setattr(
        service, "auto_position_manager_shakedown_advance", fail_before_submit
    )
    with pytest.raises(CommoditySimNowStateError, match="simulated pre-submit"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    recovered_trade = FakeTrade()
    recovered_trade.rpc = rpc
    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=rpc,  # type: ignore[arg-type]
        trade=recovered_trade,  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=service.tick_store,
        clock=lambda: NOW,
    )

    assert recovered.position_manager_shakedown_status()["execution_enabled"] is True
    assert recovered.enabled is False
    resumed = recovered.start_position_manager_shakedown(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert resumed["action"] == "open_submitted"
    assert recovered.plan()["status"] == "OPEN_SUBMITTED"
    assert len(recovered_trade.requests) == 1
    assert recovered.auto_dispatch_authorized is False


def test_position_manager_shakedown_initial_state_write_failure_cannot_dispatch_later(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    def fail_persist() -> None:
        raise OSError("disk unavailable")

    monkeypatch.setattr(service, "_persist_active_plan", fail_persist)
    with pytest.raises(OSError, match="disk unavailable"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.current_plan is None
    assert service.shakedown_auto_dispatch_authorized is False
    assert service.auto_position_manager_shakedown_advance()["action"] == "idle"
    assert service.trade.requests == []


@pytest.mark.parametrize("formal_status", ["COMPLETE", "HALTED_RECONCILED"])
def test_position_manager_shakedown_cannot_overwrite_formal_terminal_plan(
    tmp_path: Path, formal_status: str
) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    formal_plan = {
        "status": formal_status,
        "plan_hash": "f" * 64,
        "execution_lane": "official_forward",
    }
    service.current_plan = formal_plan

    with pytest.raises(CommoditySimNowStateError, match="正式 SimNow 计划占用"):
        service.preview_position_manager_shakedown(
            ["ag"], operator="admin", role="admin", source_ip=None
        )
    with pytest.raises(CommoditySimNowStateError, match="禁止候选测试覆盖"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.current_plan is formal_plan
    assert service.shakedown_auto_dispatch_authorized is False
    assert service.trade.requests == []


def test_position_manager_shakedown_pre_submit_stop_rechecks_late_trade_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    def fail_before_submit(**kwargs):
        raise CommoditySimNowStateError("simulated pre-submit failure")

    monkeypatch.setattr(
        service, "auto_position_manager_shakedown_advance", fail_before_submit
    )
    with pytest.raises(CommoditySimNowStateError, match="simulated pre-submit"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )
    plan = service.current_plan
    assert plan is not None
    reference = plan["open_orders"][0]["reference"]
    plan["send_intents"]["open"] = [{
        **plan["open_orders"][0],
        "reference": reference,
        "intent_status": "NO_EVIDENCE_STABLE",
    }]
    service._persist_active_plan()
    rpc.trades = [{
        "vt_tradeid": "CTP.LATE",
        "vt_orderid": "CTP.99",
        "reference": reference,
        "price": plan["open_orders"][0]["price"],
        "volume": plan["open_orders"][0]["volume"],
    }]

    stopped = service.stop_position_manager_shakedown(
        "operator abandons after stable no-evidence",
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert stopped["halt"]["status"] == "HALTED_RECONCILE_REQUIRED"
    assert service.current_plan is not None
    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
    assert service.plan()["halt"]["submission_evidence_references"] == [reference]


def test_position_manager_shakedown_pre_submit_stop_retries_rpc_then_archives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    def fail_before_submit(**kwargs):
        raise CommoditySimNowStateError("simulated pre-submit failure")

    monkeypatch.setattr(
        service, "auto_position_manager_shakedown_advance", fail_before_submit
    )
    with pytest.raises(CommoditySimNowStateError, match="simulated pre-submit"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )
    monkeypatch.undo()
    rpc.get_orders_error = RuntimeError("RPC unavailable")

    stopped = service.stop_position_manager_shakedown(
        "operator abandons while RPC unavailable",
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert stopped["halt"]["status"] == "CANCEL_PENDING"
    assert service.plan()["status"] == "CANCEL_PENDING"
    assert service.plan()["halt"]["orders_snapshot_available"] is False
    assert service.plan()["halt"]["abandon_pre_submit_requested"] is True
    rpc.get_orders_error = None
    retried = service.auto_position_manager_shakedown_advance()
    assert retried["action"] == "halted_reconcile_required"
    reconciled = service.auto_position_manager_shakedown_advance()
    assert reconciled["action"] == "halted_reconciled"
    assert service.current_plan is None


def test_position_manager_shakedown_pre_submit_stop_routes_position_drift_to_reconcile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )

    def fail_before_submit(**kwargs):
        raise CommoditySimNowStateError("simulated pre-submit failure")

    monkeypatch.setattr(
        service, "auto_position_manager_shakedown_advance", fail_before_submit
    )
    with pytest.raises(CommoditySimNowStateError, match="simulated pre-submit"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )
    rpc.positions = [position("ag", 3), position("al", -1)]

    stopped = service.stop_position_manager_shakedown(
        "operator abandons after position drift",
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert stopped["halt"]["status"] == "HALTED_RECONCILE_REQUIRED"
    assert stopped["halt"]["pre_submit_position_mismatch"] is True
    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
    assert service.plan()["halt"]["observed_positions"] == {
        "ag2610.SHFE": 3,
        "al2610.SHFE": -1,
    }


def test_position_manager_shakedown_terminal_write_failure_preserves_active_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    service.start_position_manager_shakedown(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.positions = [position("ag", 3), position("al", -1)]

    def fail_terminal_write(session: dict[str, Any]) -> None:
        raise OSError("terminal evidence disk failure")

    monkeypatch.setattr(
        service, "_save_position_manager_shakedown_state", fail_terminal_write
    )
    with pytest.raises(OSError, match="terminal evidence disk failure"):
        service.reconcile(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
            dispatch_mode="auto",
        )

    assert service.current_plan is not None
    assert service.plan()["status"] == "OPEN_SUBMITTED"
    assert service.plan()["halt"]["terminal_finalize_error_type"] == "OSError"
    assert service.shakedown_auto_dispatch_authorized is False
    assert service._active_state_path().exists()


def test_generic_entrypoints_cannot_resume_or_dispatch_halted_shakedown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    original_advance = service.auto_position_manager_shakedown_advance

    def fail_before_submit(**kwargs):
        raise CommoditySimNowStateError("simulated pre-submit failure")

    monkeypatch.setattr(
        service, "auto_position_manager_shakedown_advance", fail_before_submit
    )
    with pytest.raises(CommoditySimNowStateError, match="simulated pre-submit"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"
    assert service.shakedown_auto_dispatch_authorized is False
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    assert service.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"
    with pytest.raises(CommoditySimNowStateError, match="通用自动派单"):
        service.auto_advance()
    with pytest.raises(CommoditySimNowStateError, match="正式模板不得恢复"):
        service.start_template(
            template_start_payload(),
            operator="admin",
            role="admin",
            source_ip=None,
        )
    with pytest.raises(CommoditySimNowSafetyError, match="专用自动派单模式"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=preview["preview"]["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="generic dispatch must be rejected",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
            dispatch_mode="auto",
        )
    assert service.trade.requests == []

    monkeypatch.setattr(
        service, "auto_position_manager_shakedown_advance", original_advance
    )
    resumed = service.start_position_manager_shakedown(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert resumed["action"] == "open_submitted"
    assert len(service.trade.requests) == 1


def test_failed_shakedown_start_cannot_submit_later_after_conflict_clears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    monkeypatch.setattr(
        service, "_position_manager_shakedown_active_orders", lambda products: []
    )
    rpc.orders = [{
        "vt_orderid": "CTP.formal",
        "symbol": "ag2610",
        "exchange": "SHFE",
        "reference": "commodity_static_core:formal",
        "status": "not_traded",
    }]

    with pytest.raises(CommoditySimNowStateError, match="外部活动委托"):
        service.start_position_manager_shakedown(
            preview["preview"]["plan_hash"],
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"
    assert service.shakedown_auto_dispatch_authorized is False
    assert service.trade.requests == []
    rpc.orders = []
    idle = service.auto_position_manager_shakedown_advance()
    assert idle["action"] == "idle"
    assert service.trade.requests == []


def test_completed_shakedown_atomically_archives_and_clears_active_plan(
    tmp_path: Path,
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    service.auto_dispatch_authorized = True
    service.template_authorized = True
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    service.start_position_manager_shakedown(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.positions = [position("ag", 3), position("al", -1)]

    result = service.reconcile(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
        dispatch_mode="auto",
    )

    assert result["status"] == "COMPLETE"
    assert service.current_plan is None
    assert not service._active_state_path().exists()
    assert service.auto_dispatch_authorized is True
    assert service.template_authorized is True
    assert service.shakedown_auto_dispatch_authorized is False
    session = service.position_manager_shakedown_status()["session"]
    assert session["status"] == "COMPLETE"
    assert session["execution"]["reconciliation"]["matched"] is True
    assert session["execution"]["execution_snapshot"] is not None
    assert len(session["execution"]["state_checksum"]) == 64
    assert len(session["terminal_checksum"]) == 64


def test_halted_shakedown_preserves_template_authorization_and_full_evidence(
    tmp_path: Path,
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    service.auto_dispatch_authorized = True
    service.template_authorized = True
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    service.start_position_manager_shakedown(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    request = service.trade.requests[0]
    rpc.orders = [{
        "vt_orderid": "CTP.1",
        "symbol": request.symbol,
        "exchange": request.exchange,
        "reference": request.reference,
        "status": "not_traded",
        "offset": request.offset,
        "volume": request.volume,
    }]

    service.stop_position_manager_shakedown(
        "operator requested stop",
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert service.auto_dispatch_authorized is True
    assert service.template_authorized is True
    assert service.shakedown_auto_dispatch_authorized is False

    result = service.reconcile(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert result["status"] == "HALTED_RECONCILED"
    assert service.current_plan is None
    session = service.position_manager_shakedown_status()["session"]
    execution = session["execution"]
    assert execution["reconciliation"]["matched"] is True
    assert execution["execution_snapshot"] is not None
    assert execution["halt"]["reason"] == "operator requested stop"
    assert len(execution["state_checksum"]) == 64
    assert len(session["terminal_checksum"]) == 64


def test_terminal_shakedown_evidence_checksum_detects_tampering(
    tmp_path: Path,
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    service.start_position_manager_shakedown(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.positions = [position("ag", 3), position("al", -1)]
    service.reconcile(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
        dispatch_mode="auto",
    )
    state_path = Path(
        service.settings.commodity_position_manager_simnow_state_path
    )
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["execution"]["final_positions"]["ag2610.SHFE"] = 999
    state_path.write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
    )

    status = service.position_manager_shakedown_status()

    assert status["session"]["status"] == "RESULT_UNKNOWN"
    assert status["session"]["error_type"] == "ValueError"


def test_terminal_shakedown_envelope_checksum_detects_status_tampering(
    tmp_path: Path,
) -> None:
    service, rpc = prepare_position_manager_shakedown(tmp_path)
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_simnow_auto_dispatch_enabled": True}
    )
    preview = service.preview_position_manager_shakedown(
        ["ag"], operator="admin", role="admin", source_ip=None
    )
    service.start_position_manager_shakedown(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.positions = [position("ag", 3), position("al", -1)]
    service.reconcile(
        preview["preview"]["plan_hash"],
        operator="admin",
        role="admin",
        source_ip=None,
        dispatch_mode="auto",
    )
    state_path = Path(
        service.settings.commodity_position_manager_simnow_state_path
    )
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["status"] = "HALTED_RECONCILED"
    state_path.write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
    )

    status = service.position_manager_shakedown_status()

    assert status["session"]["status"] == "RESULT_UNKNOWN"
    assert status["session"]["error_type"] == "ValueError"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_month", "2026-07"),
        ("baseline_target_quantity", 3),
    ],
)
def test_position_manager_shadow_rejects_mismatched_linked_baseline(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    service, private_key, _ = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    path = tmp_path / "mismatched-linked-shadow.json"
    data = make_position_manager_shadow(
        private_key, baseline_batch_hash=plan["batch_hash"]
    ).model_dump(mode="json")
    if field == "baseline_target_quantity":
        data["targets"][0][field] = value
    else:
        data[field] = value
    write_position_manager_shadow(
        path,
        sign_position_manager_shadow_payload(data, private_key),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["valid"] is False
    assert snapshot["error_type"] == "CommoditySimNowBatchError"


def test_position_manager_shadow_marks_unavailable_baseline_unlinked(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    path = tmp_path / "unlinked-position-manager-shadow.json"
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(private_key, baseline_batch_hash="c" * 64),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["valid"] is True
    assert snapshot["baseline_link_state"] == "unlinked"


def test_baseline_sector_mapping_remains_identical_to_main() -> None:
    assert {product: spec["sector"] for product, spec in PRODUCT_SPECS.items()} == {
        "ag": "precious",
        "al": "nonferrous",
        "au": "precious",
        "bu": "energy",
        "cu": "nonferrous",
        "rb": "ferrous",
        "ru": "chemicals",
        "sc": "energy",
        "sp": "agriculture",
        "zn": "nonferrous",
    }


def test_shadow_sector_map_does_not_change_baseline_weight_acceptance(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    batch = make_batch(
        private_key,
        targets={"bu": 1, "ru": 1, "ag": -1, "al": -1},
    )
    source_weights = {"bu": 0.2, "ru": 0.2, "ag": -0.2, "al": -0.2}
    buffered_weights = {"bu": 0.1, "ru": 0.1, "ag": -0.1, "al": -0.1}
    batch = batch.model_copy(
        update={
            "targets": [
                row.model_copy(
                    update={
                        "source_target_weight": source_weights.get(row.product, 0.0),
                        "buffered_target_weight": buffered_weights.get(row.product, 0.0),
                    }
                )
                for row in batch.targets
            ]
        }
    )

    service._verify_weight_caps(batch)

    baseline_sector_gross = {
        sector: sum(
            abs(source_weights.get(product, 0.0))
            for product, spec in PRODUCT_SPECS.items()
            if spec["sector"] == sector
        )
        for sector in {spec["sector"] for spec in PRODUCT_SPECS.values()}
    }
    shadow_energy_chemical_gross = sum(
        abs(source_weights.get(product, 0.0))
        for product, sector in POSITION_MANAGER_SECTOR_MAP_V1.items()
        if sector == "energy_chemical"
    )
    assert max(baseline_sector_gross.values()) == pytest.approx(0.2)
    assert shadow_energy_chemical_gross == pytest.approx(0.4)


def test_position_manager_shadow_verifies_monthly_continuity(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    path = tmp_path / "position-manager-shadow.json"
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(private_key, baseline_batch_hash=plan["batch_hash"]),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )
    genesis = service.position_manager_shadow()
    service.current_plan["source_month"] = "2026-09"
    service.current_plan["execution_day"] = "2026-10-01"
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(
            private_key,
            baseline_batch_hash=plan["batch_hash"],
            previous_scale=genesis["smoothed_scale"],
            continuity_mode="linked",
            previous_snapshot_hash=genesis["snapshot_hash"],
            source_month="2026-09",
            execution_day="2026-10-01",
            input_cutoff_day="2026-09-30",
        ),
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["valid"] is True
    assert snapshot["continuity_state"] == "verified"
    assert snapshot["continuity_verified"] is True


def test_position_manager_shadow_rejects_genesis_reset(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    path = tmp_path / "position-manager-shadow.json"
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(private_key, baseline_batch_hash=plan["batch_hash"]),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )
    assert service.position_manager_shadow()["continuity_state"] == "genesis"
    service.current_plan["source_month"] = "2026-09"
    service.current_plan["execution_day"] = "2026-10-01"
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(
            private_key,
            baseline_batch_hash=plan["batch_hash"],
            source_month="2026-09",
            execution_day="2026-10-01",
            input_cutoff_day="2026-09-30",
        ),
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["valid"] is False
    assert snapshot["error_type"] == "CommoditySimNowBatchError"


@pytest.mark.parametrize("continuity_error", ["hash", "month", "scale"])
def test_position_manager_shadow_rejects_broken_monthly_continuity(
    tmp_path: Path,
    continuity_error: str,
) -> None:
    service, private_key, _ = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    path = tmp_path / "position-manager-shadow.json"
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(private_key, baseline_batch_hash=plan["batch_hash"]),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )
    genesis = service.position_manager_shadow()
    source_month = "2026-10" if continuity_error == "month" else "2026-09"
    execution_day = "2026-11-01" if continuity_error == "month" else "2026-10-01"
    input_cutoff_day = "2026-10-31" if continuity_error == "month" else "2026-09-30"
    service.current_plan["source_month"] = source_month
    service.current_plan["execution_day"] = execution_day
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(
            private_key,
            baseline_batch_hash=plan["batch_hash"],
            previous_scale=(
                0.9 if continuity_error == "scale" else genesis["smoothed_scale"]
            ),
            continuity_mode="linked",
            previous_snapshot_hash=(
                "f" * 64
                if continuity_error == "hash"
                else genesis["snapshot_hash"]
            ),
            source_month=source_month,
            execution_day=execution_day,
            input_cutoff_day=input_cutoff_day,
        ),
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["valid"] is False
    assert snapshot["error_type"] == "CommoditySimNowBatchError"


def test_position_manager_shadow_marks_missing_continuity_evidence_unlinked(
    tmp_path: Path,
) -> None:
    service, private_key, _ = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    path = tmp_path / "position-manager-shadow.json"
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(
            private_key,
            baseline_batch_hash=plan["batch_hash"],
            continuity_mode="linked",
            previous_snapshot_hash="d" * 64,
        ),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["valid"] is True
    assert snapshot["continuity_state"] == "unlinked"
    assert snapshot["continuity_verified"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_month", "2026-99"),
        ("input_cutoff_day", "2026-07-31"),
        ("input_cutoff_day", "2024-08-31"),
        ("fast_annual_vol", float("inf")),
        ("reference_open_price", float("inf")),
        ("baseline_source_target_weight", float("inf")),
    ],
)
def test_position_manager_shadow_rejects_invalid_time_or_nonfinite_number(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    service, private_key, _ = make_service(tmp_path)
    path = tmp_path / "invalid-position-manager-shadow.json"
    data = make_position_manager_shadow(
        private_key, baseline_batch_hash="e" * 64
    ).model_dump(mode="json")
    if field in {"reference_open_price", "baseline_source_target_weight"}:
        data["targets"][2][field] = value
    else:
        data[field] = value
    write_position_manager_shadow(
        path,
        sign_position_manager_shadow_payload(data, private_key),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["valid"] is False
    assert snapshot["error_type"] == "CommoditySimNowBatchError"


def test_position_manager_shadow_bad_formula_fails_closed_without_stopping_baseline(
    tmp_path: Path,
) -> None:
    service, private_key, _ = make_service(tmp_path)
    path = tmp_path / "bad-position-manager-shadow.json"
    write_position_manager_shadow(
        path,
        make_position_manager_shadow(
            private_key,
            baseline_batch_hash="a" * 64,
            raw_scale=1.01,
        ),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["configured"] is True
    assert snapshot["valid"] is False
    assert snapshot["error_type"] == "CommoditySimNowBatchError"
    assert snapshot["authority_granted"] is False
    assert snapshot["dispatch_allowed"] is False
    assert service.status()["auto_dispatch_allowed"] is True


def test_position_manager_shadow_rejects_signed_target_not_derived_from_scale(
    tmp_path: Path,
) -> None:
    service, private_key, _ = make_service(tmp_path)
    path = tmp_path / "mismatched-position-manager-shadow.json"
    data = make_position_manager_shadow(
        private_key, baseline_batch_hash="b" * 64
    ).model_dump(mode="json")
    data["targets"][0]["shadow_source_target_weight"] += 0.001
    write_position_manager_shadow(
        path,
        sign_position_manager_shadow_payload(data, private_key),
    )
    service.settings = service.settings.model_copy(
        update={"commodity_position_manager_shadow_path": str(path)}
    )

    snapshot = service.position_manager_shadow()

    assert snapshot["valid"] is False
    assert snapshot["error_type"] == "CommoditySimNowBatchError"
    assert snapshot["authority_granted"] is False
    assert snapshot["dispatch_allowed"] is False


def test_one_click_template_loads_signed_target_and_dispatches(tmp_path: Path) -> None:
    target_path = tmp_path / "signed-target.json"
    trade = FakeTrade()
    service, private_key, _ = make_service(
        tmp_path,
        trade=trade,
        auto_enable=False,
        template_batch_path=target_path,
    )
    write_batch(target_path, make_batch(private_key))

    result = service.start_template(
        template_start_payload(),
        operator="admin",
        role="admin",
        source_ip="127.0.0.1",
    )

    assert result["action"] == "strategy_template_started"
    assert result["prepared"]["action"] == "target_loaded"
    assert result["dispatched"]["action"] == "open_submitted"
    assert service.status()["strategy_template"]["authorized"] is True
    assert service.plan()["status"] == "OPEN_SUBMITTED"
    assert len(trade.requests) == 2


def test_one_click_template_invalid_target_fails_closed(tmp_path: Path) -> None:
    target_path = tmp_path / "missing-target.json"
    service, _, _ = make_service(
        tmp_path,
        auto_enable=False,
        template_batch_path=target_path,
    )

    with pytest.raises(CommoditySimNowBatchError, match="目标文件无效"):
        service.start_template(
            template_start_payload(),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.status()["auto_dispatch_allowed"] is False
    assert service.status()["strategy_template"]["authorized"] is False
    assert service.status()["enabled"] is False


def test_main_contract_roll_closes_old_then_opens_new(tmp_path: Path) -> None:
    trade = FakeTrade()
    service, private_key, rpc = make_service(
        tmp_path,
        trade=trade,
        contract_months=("2609", "2610"),
    )
    previous_hash = "e" * 64
    previous = {"ag": 2, "al": -1}
    service._completed_state = {
        "last_completed_batch_hash": previous_hash,
        "targets": completed_targets(previous, "2609"),
    }
    rpc.positions = [
        position("ag", 2, contract_month="2609"),
        position("al", -1, contract_month="2609"),
    ]
    batch = make_batch(
        private_key,
        targets=previous,
        previous=previous,
        previous_batch_hash=previous_hash,
        previous_contract_month="2609",
        target_contract_month="2610",
    )

    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)

    assert plan["status"] == "READY_CLOSE"
    assert plan["roll_products"] == ["ag", "al"]
    assert {row["vt_symbol"] for row in plan["close_orders"]} == {
        "ag2609.SHFE",
        "al2609.SHFE",
    }
    assert {row["vt_symbol"] for row in plan["open_orders"]} == {
        "ag2610.SHFE",
        "al2610.SHFE",
    }

    assert service.auto_advance()["action"] == "close_submitted"
    rpc.positions = []
    assert service.auto_advance()["action"] == "close_reconciled_open_submitted"
    rpc.positions = [position("ag", 2), position("al", -1)]
    assert service.auto_advance()["status"] == "COMPLETE"
    assert [request.symbol for request in trade.requests] == [
        "ag2609",
        "al2609",
        "ag2610",
        "al2610",
    ]


def test_delivery_month_target_is_rejected_from_first_day(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    batch = make_batch(private_key, target_contract_month="2609")

    with pytest.raises(CommoditySimNowBatchError, match="交割风险截止区间"):
        service.preview(batch, operator="admin", role="admin", source_ip=None)


def test_signed_zero_target_can_flatten_delivery_month_holding(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(
        tmp_path,
        contract_months=("2609",),
    )
    previous_hash = "f" * 64
    previous = {"ag": 2}
    service._completed_state = {
        "last_completed_batch_hash": previous_hash,
        "targets": completed_targets(previous, "2609"),
    }
    rpc.positions = [position("ag", 2, contract_month="2609")]
    batch = make_batch(
        private_key,
        targets={product: 0 for product in PRODUCT_SPECS},
        previous=previous,
        previous_batch_hash=previous_hash,
        previous_contract_month="2609",
        target_contract_month="2609",
    )

    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)

    assert plan["status"] == "READY_CLOSE"
    assert plan["open_orders"] == []
    assert [(row["vt_symbol"], row["volume"]) for row in plan["close_orders"]] == [
        ("ag2609.SHFE", 2)
    ]


def test_sc_target_is_rejected_in_pre_delivery_cutoff(tmp_path: Path) -> None:
    now = datetime(2026, 9, 15, 1, 0, tzinfo=timezone.utc)
    service, private_key, _ = make_service(tmp_path, now=now)
    batch = make_batch(
        private_key,
        targets={"ag": -1, "sc": 1},
        execution_day="2026-09-15",
        target_contract_month="2610",
    )

    with pytest.raises(CommoditySimNowBatchError, match="原油目标合约"):
        service.preview(batch, operator="admin", role="admin", source_ip=None)


def test_stale_target_with_expiring_holding_halts_template(tmp_path: Path) -> None:
    target_path = tmp_path / "stale-target.json"
    service, private_key, rpc = make_service(
        tmp_path,
        contract_months=("2609", "2610"),
        template_batch_path=target_path,
    )
    stale = make_batch(
        private_key,
        execution_lane="simnow_shakedown",
        source_month="2026-08",
        execution_day="2026-08-31",
        target_contract_month="2610",
    )
    write_batch(target_path, stale)
    rpc.positions = [position("ag", 2, contract_month="2609")]
    service.template_authorized = True

    result = service.auto_template_advance()

    assert result["action"] == "halted"
    assert result["reason"] == "delivery_guard_breached_without_current_roll_target"
    assert service.status()["auto_dispatch_allowed"] is False
    assert service.status()["strategy_template"]["authorized"] is False


def test_existing_position_delivery_guard_uses_month_end_night_trading_day(tmp_path: Path) -> None:
    month_end_night = datetime(2026, 8, 31, 13, 30, tzinfo=timezone.utc)  # 21:30 Shanghai
    target_path = tmp_path / "future-target.json"
    service, private_key, rpc = make_service(
        tmp_path,
        now=month_end_night,
        contract_months=("2609", "2610"),
        template_batch_path=target_path,
    )
    write_batch(
        target_path,
        make_batch(
            private_key,
            execution_lane="simnow_shakedown",
            source_month="2026-09",
            execution_day="2026-09-02",
        ),
    )
    rpc.positions = [position("ag", 1, contract_month="2609")]
    service.template_authorized = True

    result = service.auto_template_advance()

    assert result["action"] == "halted"
    assert result["reason"] == "delivery_guard_breached_without_current_roll_target"


def test_delivery_guard_cancels_active_plan_orders(tmp_path: Path) -> None:
    target_path = tmp_path / "roll-target.json"
    service, private_key, rpc = make_service(
        tmp_path,
        contract_months=("2609", "2610"),
        template_batch_path=target_path,
    )
    previous_hash = "e" * 64
    service._completed_state = {
        "last_completed_batch_hash": previous_hash,
        "targets": completed_targets({"ag": 2}, contract_month="2609"),
    }
    rpc.positions = [position("ag", 2, contract_month="2609")]
    batch = make_batch(
        private_key,
        targets={"ag": 2, "al": -1},
        previous={"ag": 2},
        previous_batch_hash=previous_hash,
        previous_contract_month="2609",
        target_contract_month="2610",
    )
    write_batch(target_path, batch)
    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="close",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="delivery guard active order test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    submitted = service.plan()["submitted"]["close"][0]
    rpc.orders = [
        {
            "vt_orderid": submitted["vt_orderid"],
            "reference": submitted["reference"],
            "status": "not_traded",
            "offset": "closeyesterday",
            "volume": submitted["volume"],
        }
    ]
    service.template_authorized = True

    result = service.auto_template_advance()

    assert result["reason"] == "delivery_guard_breached_without_current_roll_target"
    assert service.trade.cancel_requests == [submitted["vt_orderid"]]
    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"


def test_active_plan_cannot_roll_into_next_execution_day(tmp_path: Path) -> None:
    target_path = tmp_path / "signed-target.json"
    service, private_key, rpc = make_service(
        tmp_path,
        template_batch_path=target_path,
    )
    write_batch(target_path, make_batch(private_key))
    service.template_authorized = True
    service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.auto_advance()
    submitted = service.plan()["submitted"]["open"][0]
    rpc.orders = [
        {
            "vt_orderid": submitted["vt_orderid"],
            "reference": submitted["reference"],
            "status": "not_traded",
            "offset": "open",
            "volume": submitted["volume"],
        }
    ]
    service.clock = lambda: NOW + timedelta(days=1)

    result = service.auto_template_advance()

    assert result["action"] == "halted"
    assert result["reason"] == "active_plan_execution_day_expired"
    assert service.status()["auto_dispatch_allowed"] is False
    assert service.trade.cancel_requests == sorted(
        row["vt_orderid"] for row in service.plan()["submitted"]["open"]
    )
    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"


def test_night_session_crossing_midnight_keeps_same_execution_trading_day(tmp_path: Path) -> None:
    before_midnight = datetime(2026, 6, 21, 15, 30, tzinfo=timezone.utc)  # 23:30 Shanghai
    after_midnight = datetime(2026, 6, 21, 16, 30, tzinfo=timezone.utc)  # 00:30 Shanghai
    service, private_key, _ = make_service(tmp_path, now=before_midnight)
    batch = make_batch(
        private_key,
        execution_lane="simnow_shakedown",
        source_month="2026-06",
        execution_day="2026-06-22",
    )
    service.preview(batch, operator="admin", role="admin", source_ip=None)
    service.template_authorized = True
    service.clock = lambda: after_midnight
    for quote in service.tick_store.ticks.values():
        quote["received_at"] = after_midnight.isoformat()

    result = service.auto_template_advance()

    assert result["action"] == "idle"
    assert result["reason"] == "plan_active"
    assert service.status()["auto_dispatch_allowed"] is True


def test_month_end_night_uses_next_trading_month_for_shakedown_source(tmp_path: Path) -> None:
    month_end_night = datetime(2026, 8, 31, 13, 30, tzinfo=timezone.utc)  # 21:30 Shanghai
    service, private_key, _ = make_service(tmp_path, now=month_end_night)
    batch = make_batch(
        private_key,
        execution_lane="simnow_shakedown",
        source_month="2026-09",
        execution_day="2026-09-01",
    )

    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)

    assert plan["execution_day"] == "2026-09-01"


def test_month_end_night_applies_shfe_delivery_guard_on_next_trading_day(tmp_path: Path) -> None:
    month_end_night = datetime(2026, 8, 31, 13, 30, tzinfo=timezone.utc)  # 21:30 Shanghai
    service, private_key, _ = make_service(
        tmp_path,
        now=month_end_night,
        contract_months=("2609",),
    )
    batch = make_batch(
        private_key,
        execution_lane="simnow_shakedown",
        source_month="2026-09",
        execution_day="2026-09-01",
        target_contract_month="2609",
    )

    with pytest.raises(CommoditySimNowBatchError, match="交割风险截止区间"):
        service.preview(batch, operator="admin", role="admin", source_ip=None)


def test_sc_cutoff_uses_next_trading_day_at_night(tmp_path: Path) -> None:
    cutoff_night = datetime(2026, 9, 14, 13, 30, tzinfo=timezone.utc)  # 21:30 Shanghai
    service, private_key, _ = make_service(tmp_path, now=cutoff_night)
    batch = make_batch(
        private_key,
        targets={"ag": -1, "sc": 1},
        execution_lane="simnow_shakedown",
        source_month="2026-09",
        execution_day="2026-09-15",
    )

    with pytest.raises(CommoditySimNowBatchError, match="原油目标合约"):
        service.preview(batch, operator="admin", role="admin", source_ip=None)


def test_shakedown_batch_can_trade_before_official_forward_window(
    tmp_path: Path,
) -> None:
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
    assert [row["offset"] for row in plan["close_orders"]] == [
        "closeyesterday",
        "closeyesterday",
    ]
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
    settings = make_settings(tmp_path, private_key).model_copy(update={"commodity_simnow_account_hashes": "b" * 64})
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


def test_realtime_exposure_jump_rejects_open_phase_before_any_submission(tmp_path: Path) -> None:
    trade = FakeTrade()
    service, private_key, _ = make_service(tmp_path, trade=trade)
    plan = service.preview(
        make_batch(private_key, targets={"ag": 100, "al": -1}),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    quote = service.tick_store.ticks["ag2610.SHFE"]
    quote["bid_price_1"] = 3000.0
    quote["ask_price_1"] = 3001.0

    with pytest.raises(CommoditySimNowSafetyError, match="实时整数目标"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="realtime exposure guard test",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert trade.requests == []
    assert service.plan()["status"] == "READY_OPEN"


def test_split_orders_exceeding_symbol_limit_reject_entire_phase(tmp_path: Path) -> None:
    trade = FakeTrade()
    service, private_key, _ = make_service(tmp_path, trade=trade)
    service.risk.rules["max_symbol_position"] = 5
    plan = service.preview(
        make_batch(private_key, targets={"ag": 20, "al": -1}),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert len([row for row in plan["open_orders"] if row["product"] == "ag"]) == 2

    with pytest.raises(CommoditySimNowSafetyError, match="拆单累计量"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="aggregate symbol limit test",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert trade.requests == []
    assert service.plan()["status"] == "READY_OPEN"


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

    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
    assert trade.cancel_requests == ["CTP.1"]
    assert service.order_endpoint_touched is True


def test_noop_batch_completes_and_advances_chain_on_preview(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    batch = make_batch(private_key, targets={product: 0 for product in PRODUCT_SPECS})

    plan = service.preview(batch, operator="admin", role="admin", source_ip=None)

    assert plan["status"] == "COMPLETE"
    persisted = json.loads((tmp_path / "commodity-state.json").read_text(encoding="utf-8"))
    assert persisted["last_completed_batch_hash"] == plan["batch_hash"]


def test_disable_cancels_active_orders_and_allows_halted_reconcile(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
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
    submitted = service.plan()["submitted"]["open"][0]
    rpc.orders = [
        {
            "vt_orderid": submitted["vt_orderid"],
            "reference": submitted["reference"],
            "status": "not_traded",
            "offset": "open",
            "volume": submitted["volume"],
        }
    ]

    service.disable(
        CommoditySimNowDisableRequestDTO(reason="manual stop"),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
    assert service.status()["simnow_mode"] is False
    assert service.trade.cancel_requests == sorted(
        row["vt_orderid"] for row in service.plan()["submitted"]["open"]
    )
    reconciled = service.reconcile(
        plan["plan_hash"], operator="admin", role="admin", source_ip=None
    )
    assert reconciled["reconciliation"]["halted_reconcile"] is True
    assert reconciled["status"] == "HALTED_RECONCILED"


def test_ready_open_disable_is_safely_resumable(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    disabled = service.disable(
        CommoditySimNowDisableRequestDTO(reason="stop before first open order"),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert disabled["halt"]["status"] == "HALTED_PRE_SUBMIT_SAFE"
    assert disabled["halt"]["resume_status"] == "READY_OPEN"
    assert service.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"
    enabled = service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    assert enabled["plan_status"] == "READY_OPEN"
    assert service.plan()["plan_hash"] == plan["plan_hash"]


def test_ready_close_disable_is_safely_resumable(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    previous_hash = "1" * 64
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

    service.disable(
        CommoditySimNowDisableRequestDTO(reason="stop before first close order"),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert service.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"
    assert service.plan()["halt"]["resume_status"] == "READY_CLOSE"
    enabled = service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    assert enabled["plan_status"] == "READY_CLOSE"
    assert service.plan()["plan_hash"] == plan["plan_hash"]


def test_disable_stays_cancel_pending_until_exchange_order_is_terminal(tmp_path: Path) -> None:
    trade = FakeTrade(complete_cancel=False)
    service, private_key, rpc = make_service(tmp_path, trade=trade)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="cancel pending state test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    submitted = service.plan()["submitted"]["open"][0]
    rpc.orders = [
        {
            "vt_orderid": submitted["vt_orderid"],
            "reference": submitted["reference"],
            "status": "not_traded",
            "offset": "open",
            "volume": submitted["volume"],
        }
    ]

    service.disable(
        CommoditySimNowDisableRequestDTO(reason="manual cancel pending test"),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert service.plan()["status"] == "CANCEL_PENDING"
    assert service.auto_advance()["action"] == "cancel_pending"
    rpc.orders[0]["status"] = "cancelled"
    assert service.auto_advance()["action"] == "halted_reconcile_required"
    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"


def test_disable_persists_cancel_pending_when_rpc_orders_are_unavailable(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="rpc unavailable disable test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    submitted = service.plan()["submitted"]["open"][0]
    rpc.orders = [
        {
            "vt_orderid": submitted["vt_orderid"],
            "reference": submitted["reference"],
            "status": "not_traded",
            "offset": "open",
            "volume": submitted["volume"],
        }
    ]
    rpc.get_orders_error = RuntimeError("RPC unavailable")

    disabled = service.disable(
        CommoditySimNowDisableRequestDTO(reason="rpc unavailable"),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert disabled["halt"]["status"] == "CANCEL_PENDING"
    assert disabled["halt"]["orders_snapshot_available"] is False
    active_path = tmp_path / "commodity-state.active.json"
    persisted = json.loads(active_path.read_text(encoding="utf-8"))
    assert persisted["plan"]["status"] == "CANCEL_PENDING"
    rpc.get_orders_error = None
    recovered = service.auto_advance()
    assert recovered["action"] == "halted_reconcile_required"
    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"


def test_halted_close_reconcile_requires_explicit_reauthorization_before_open(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    previous_hash = "f" * 64
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
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="close",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="halted close reconcile test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    service.disable(
        CommoditySimNowDisableRequestDTO(reason="stop between phases"),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.positions = []

    reconciled = service.reconcile(
        plan["plan_hash"], operator="admin", role="admin", source_ip=None
    )

    assert reconciled["status"] == "HALTED_RECONCILED"
    assert service.status()["auto_dispatch_allowed"] is False
    enabled = service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    assert enabled["plan_status"] == "READY_OPEN"


def test_emergency_stop_cancels_active_plan_orders(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="emergency halt test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    submitted = service.plan()["submitted"]["open"][0]
    rpc.orders = [
        {
            "vt_orderid": submitted["vt_orderid"],
            "reference": submitted["reference"],
            "status": "not_traded",
            "offset": "open",
            "volume": submitted["volume"],
        }
    ]
    service.risk.emergency_stopped = True
    service.risk.web_trade_enabled = False

    result = service.auto_advance()

    assert result["reason"] == "emergency_stop"
    assert service.trade.cancel_requests == sorted(
        row["vt_orderid"] for row in service.plan()["submitted"]["open"]
    )
    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
    reconciled = service.reconcile(
        plan["plan_hash"], operator="admin", role="admin", source_ip=None
    )
    assert reconciled["reconciliation"]["halted_reconcile"] is True


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

    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
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


def test_process_restart_restores_plan_and_cancels_active_orders(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="restart recovery test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    submitted = service.plan()["submitted"]["open"][0]
    rpc.orders = [
        {
            "vt_orderid": submitted["vt_orderid"],
            "reference": submitted["reference"],
            "status": "not_traded",
            "offset": "open",
            "volume": submitted["volume"],
        }
    ]
    recovered_trade = FakeTrade()
    recovered_trade.rpc = rpc
    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=rpc,  # type: ignore[arg-type]
        trade=recovered_trade,  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=service.tick_store,
        clock=lambda: NOW,
    )

    async def exercise() -> None:
        recovered.start()
        await asyncio.sleep(0)
        assert recovered.plan()["plan_hash"] == plan["plan_hash"]
        assert recovered.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
        assert recovered_trade.cancel_requests == sorted(
            row["vt_orderid"] for row in recovered.plan()["submitted"]["open"]
        )
        await recovered.stop()

    asyncio.run(exercise())


def test_process_restart_restores_ready_plan_as_pre_submit_safe(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=rpc,  # type: ignore[arg-type]
        trade=FakeTrade(),  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=service.tick_store,
        clock=lambda: NOW,
    )

    async def exercise() -> None:
        recovered.start()
        assert recovered.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"
        enabled = recovered.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
        assert enabled["plan_status"] == "READY_OPEN"
        assert recovered.plan()["plan_hash"] == plan["plan_hash"]
        await recovered.stop()

    asyncio.run(exercise())


def test_process_restart_recovers_submitting_open_without_order_evidence(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path, trade=CrashBeforeSendTrade())
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    with pytest.raises(SystemExit, match="before RPC send"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="crash before first send",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    persisted = json.loads(
        (tmp_path / "commodity-state.active.json").read_text(encoding="utf-8")
    )["plan"]
    assert persisted["status"] == "SUBMITTING_OPEN"
    assert persisted["submitted"]["open"] == []
    assert persisted["send_intents"]["open"][0]["intent_status"] == "PENDING_SEND"

    recovered_trade = FakeTrade()
    recovered_trade.rpc = rpc
    recovery_now = [NOW]
    recovered = CommoditySimNowService(
        settings=service.settings.model_copy(
            update={
                "commodity_simnow_submission_outcome_grace_seconds": 5,
                "commodity_simnow_submission_outcome_min_empty_snapshots": 2,
            }
        ),
        rpc=rpc,  # type: ignore[arg-type]
        trade=recovered_trade,  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=service.tick_store,
        clock=lambda: recovery_now[0],
    )
    async def exercise() -> None:
        recovered.start()
        assert recovered.plan()["status"] == "SUBMISSION_OUTCOME_UNKNOWN"
        assert recovered_trade.requests == []
        recovery_now[0] += timedelta(seconds=6)
        advanced = recovered.auto_advance()
        assert advanced["action"] == "halted_pre_submit_safe"
        assert recovered.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"
        assert recovered.plan()["halt"]["resume_status"] == "READY_OPEN"
        assert recovered.plan()["send_intents"]["open"][0]["intent_status"] == "NO_EVIDENCE_STABLE"
        enabled = recovered.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
        assert enabled["plan_status"] == "READY_OPEN"
        assert "halt" not in recovered.plan()
        await recovered.stop()

    asyncio.run(exercise())


def test_process_restart_recovers_accepted_order_by_send_intent_reference(tmp_path: Path) -> None:
    crashed_trade = CrashAfterAcceptTrade()
    service, private_key, rpc = make_service(tmp_path, trade=crashed_trade)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    with pytest.raises(SystemExit, match="after exchange acceptance"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="crash after first order acceptance",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    persisted = json.loads(
        (tmp_path / "commodity-state.active.json").read_text(encoding="utf-8")
    )["plan"]
    assert persisted["status"] == "SUBMITTING_OPEN"
    assert persisted["submitted"]["open"] == []
    reference = persisted["send_intents"]["open"][0]["reference"]

    recovered_trade = FakeTrade()
    recovered_trade.rpc = rpc
    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=rpc,  # type: ignore[arg-type]
        trade=recovered_trade,  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=service.tick_store,
        clock=lambda: NOW,
    )
    async def exercise() -> None:
        recovered.start()
        recovered_plan = recovered.plan()
        assert recovered_plan["status"] == "HALTED_RECONCILE_REQUIRED"
        assert recovered_plan["halt"]["submission_evidence_references"] == [reference]
        assert recovered_plan["submitted"]["open"][0]["reference"] == reference
        assert recovered_plan["submitted"]["open"][0]["recovered_from_reference"] is True
        assert recovered_trade.cancel_requests == ["CTP.1"]
        assert recovered_trade.requests == []
        await recovered.stop()

    asyncio.run(exercise())


def test_delayed_order_evidence_blocks_ready_and_is_cancelled(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path, trade=CrashBeforeSendTrade())
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    with pytest.raises(SystemExit, match="before RPC send"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="delayed order event test",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    recovered_trade = FakeTrade()
    recovered_trade.rpc = rpc
    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=rpc,  # type: ignore[arg-type]
        trade=recovered_trade,  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=service.tick_store,
        clock=lambda: NOW,
    )

    async def exercise() -> None:
        recovered.start()
        assert recovered.plan()["status"] == "SUBMISSION_OUTCOME_UNKNOWN"
        assert recovered_trade.requests == []
        reference = recovered.plan()["send_intents"]["open"][0]["reference"]
        rpc.orders = [
            {
                "vt_orderid": "CTP.LATE1",
                "reference": reference,
                "status": "not_traded",
                "offset": "open",
                "volume": 1,
            }
        ]
        advanced = recovered.auto_advance()
        assert advanced["action"] == "halted_reconcile_required"
        assert recovered.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
        assert recovered_trade.cancel_requests == ["CTP.LATE1"]
        assert recovered_trade.requests == []
        await recovered.stop()

    asyncio.run(exercise())


def test_first_order_unknown_failure_uses_submission_outcome_state(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path, trade=RpcTimeoutTrade())
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    with pytest.raises(CommoditySimNowStateError, match="send-intent outcome"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="first order RPC failure",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.plan()["status"] == "SUBMISSION_OUTCOME_UNKNOWN"
    assert service.plan()["submitted"]["open"] == []
    assert service.plan()["send_intents"]["open"][0]["intent_status"] == "OUTCOME_UNKNOWN"
    reference = service.plan()["send_intents"]["open"][0]["reference"]
    rpc.orders = [
        {
            "vt_orderid": "CTP.TIMEOUT1",
            "reference": reference,
            "status": "not_traded",
            "offset": "open",
            "volume": 1,
        }
    ]
    advanced = service.auto_advance()
    assert advanced["action"] == "halted_reconcile_required"
    assert service.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
    assert service.trade.cancel_requests == ["CTP.TIMEOUT1"]


def test_reauthorization_rechecks_late_send_intent_evidence(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path, trade=CrashBeforeSendTrade())
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    with pytest.raises(SystemExit, match="before RPC send"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="reauthorization late evidence test",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    recovery_now = [NOW]
    recovered_trade = FakeTrade()
    recovered_trade.rpc = rpc
    recovered = CommoditySimNowService(
        settings=service.settings.model_copy(
            update={
                "commodity_simnow_submission_outcome_grace_seconds": 5,
                "commodity_simnow_submission_outcome_min_empty_snapshots": 2,
            }
        ),
        rpc=rpc,  # type: ignore[arg-type]
        trade=recovered_trade,  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=service.tick_store,
        clock=lambda: recovery_now[0],
    )

    async def exercise() -> None:
        recovered.start()
        recovery_now[0] += timedelta(seconds=6)
        assert recovered.auto_advance()["action"] == "halted_pre_submit_safe"
        reference = recovered.plan()["send_intents"]["open"][0]["reference"]
        rpc.orders = [
            {
                "vt_orderid": "CTP.LATE2",
                "reference": reference,
                "status": "not_traded",
                "offset": "open",
                "volume": 1,
            }
        ]
        with pytest.raises(CommoditySimNowStateError, match="迟到委托"):
            recovered.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
        assert recovered.plan()["status"] == "HALTED_RECONCILE_REQUIRED"
        assert recovered_trade.cancel_requests == ["CTP.LATE2"]
        assert recovered_trade.requests == []
        await recovered.stop()

    asyncio.run(exercise())


def test_first_order_local_risk_rejection_is_pre_submit_safe(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path, trade=LocalRiskRejectTrade())
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    with pytest.raises(CommoditySimNowStateError, match="send-intent outcome"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="first order local risk rejection",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"
    assert service.plan()["submitted"]["open"] == []
    assert service.plan()["send_intents"]["open"][0]["intent_status"] == "REJECTED_PRE_RPC"
    enabled = service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    assert enabled["plan_status"] == "READY_OPEN"


def test_first_order_timeout_without_evidence_becomes_safe_after_grace(tmp_path: Path) -> None:
    service, private_key, _ = make_service(tmp_path, trade=RpcTimeoutTrade())
    outcome_now = [NOW]
    service.clock = lambda: outcome_now[0]
    service.settings = service.settings.model_copy(
        update={
            "commodity_simnow_submission_outcome_grace_seconds": 5,
            "commodity_simnow_submission_outcome_min_empty_snapshots": 2,
        }
    )
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    with pytest.raises(CommoditySimNowStateError, match="send-intent outcome"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="first order timeout without evidence",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.plan()["status"] == "SUBMISSION_OUTCOME_UNKNOWN"
    outcome_now[0] += timedelta(seconds=6)
    advanced = service.auto_advance()
    assert advanced["action"] == "halted_pre_submit_safe"
    assert service.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"


def test_process_restart_recovers_trade_only_evidence_by_send_intent_reference(tmp_path: Path) -> None:
    crashed_trade = CrashAfterAcceptTrade()
    service, private_key, rpc = make_service(tmp_path, trade=crashed_trade)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)

    with pytest.raises(SystemExit, match="after exchange acceptance"):
        service.execute(
            CommodityPlanExecuteRequestDTO(
                plan_hash=plan["plan_hash"],
                phase="open",
                confirm=True,
                confirm_simnow_only=True,
                confirm_manual_one_shot=True,
                reason="crash before trade evidence persistence",
            ),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    reference = rpc.orders[0]["reference"]
    rpc.orders = []
    rpc.trades = [
        {
            "vt_tradeid": "CTP.T1",
            "vt_orderid": "CTP.1",
            "reference": reference,
            "price": service.plan()["send_intents"]["open"][0]["price"],
            "volume": 1,
        }
    ]
    recovered_trade = FakeTrade()
    recovered_trade.rpc = rpc
    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=rpc,  # type: ignore[arg-type]
        trade=recovered_trade,  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=service.tick_store,
        clock=lambda: NOW,
    )

    async def exercise() -> None:
        recovered.start()
        recovered_plan = recovered.plan()
        assert recovered_plan["status"] == "HALTED_RECONCILE_REQUIRED"
        assert recovered_plan["halt"]["submission_evidence_references"] == [reference]
        assert recovered_plan["submitted"]["open"][0]["vt_orderid"] == "CTP.1"
        assert recovered_trade.requests == []
        await recovered.stop()

    asyncio.run(exercise())


def test_halt_metadata_is_cleared_before_next_phase_halt(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    previous_hash = "9" * 64
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

    service.disable(
        CommoditySimNowDisableRequestDTO(reason="first pre-close halt"),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    assert service.plan()["status"] == "READY_CLOSE"
    assert "halt" not in service.plan()

    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="close",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="complete close before second halt",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    rpc.positions = []
    reconciled = service.reconcile(
        plan["plan_hash"], operator="admin", role="admin", source_ip=None
    )
    assert reconciled["status"] == "READY_OPEN"

    service.disable(
        CommoditySimNowDisableRequestDTO(reason="second pre-open halt"),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    halted = service.plan()
    assert halted["status"] == "HALTED_PRE_SUBMIT_SAFE"
    assert halted["halt"]["phase"] == "open"
    assert halted["halt"]["resume_status"] == "READY_OPEN"
    assert halted["halt"]["pre_phase_expected_positions"] == {}
    enabled = service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    assert enabled["plan_status"] == "READY_OPEN"
    assert "halt" not in service.plan()


def test_process_restart_survives_rpc_unavailable_and_retries_cancel(tmp_path: Path) -> None:
    service, private_key, rpc = make_service(tmp_path)
    plan = service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.execute(
        CommodityPlanExecuteRequestDTO(
            plan_hash=plan["plan_hash"],
            phase="open",
            confirm=True,
            confirm_simnow_only=True,
            confirm_manual_one_shot=True,
            reason="restart rpc unavailable test",
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    submitted = service.plan()["submitted"]["open"][0]
    rpc.orders = [
        {
            "vt_orderid": submitted["vt_orderid"],
            "reference": submitted["reference"],
            "status": "not_traded",
            "offset": "open",
            "volume": submitted["volume"],
        }
    ]
    rpc.get_orders_error = RuntimeError("RPC unavailable")
    recovered_trade = FakeTrade()
    recovered_trade.rpc = rpc
    recovered = CommoditySimNowService(
        settings=service.settings,
        rpc=rpc,  # type: ignore[arg-type]
        trade=recovered_trade,  # type: ignore[arg-type]
        risk=FakeRisk(),  # type: ignore[arg-type]
        audit=FakeAudit(),  # type: ignore[arg-type]
        tick_store=service.tick_store,
        clock=lambda: NOW,
    )

    async def exercise() -> None:
        recovered.start()
        assert recovered.plan()["status"] == "CANCEL_PENDING"
        assert recovered.plan()["halt"]["orders_snapshot_available"] is False
        rpc.get_orders_error = None
        result = recovered.auto_advance()
        assert result["action"] == "halted_reconcile_required"
        assert recovered_trade.cancel_requests == sorted(
            row["vt_orderid"] for row in recovered.plan()["submitted"]["open"]
        )
        await recovered.stop()

    asyncio.run(exercise())


def test_template_start_can_retry_after_pre_submit_risk_failure(tmp_path: Path) -> None:
    target_path = tmp_path / "retry-target.json"
    service, private_key, _ = make_service(
        tmp_path,
        auto_enable=False,
        template_batch_path=target_path,
    )
    write_batch(target_path, make_batch(private_key))
    service.risk.rules["max_symbol_position"] = 1

    with pytest.raises(CommoditySimNowSafetyError, match="拆单累计量"):
        service.start_template(
            template_start_payload(),
            operator="admin",
            role="admin",
            source_ip=None,
        )

    assert service.plan()["status"] == "HALTED_PRE_SUBMIT_SAFE"
    service.risk.rules["max_symbol_position"] = 500
    retried = service.start_template(
        template_start_payload(),
        operator="admin",
        role="admin",
        source_ip=None,
    )
    assert retried["dispatched"]["action"] == "open_submitted"


def test_auto_dispatch_halts_after_terminal_reconciliation_mismatch(
    tmp_path: Path,
) -> None:
    service, private_key, _ = make_service(tmp_path)
    service.preview(make_batch(private_key), operator="admin", role="admin", source_ip=None)
    service.auto_advance()
    service.clock = lambda: NOW + timedelta(seconds=31)

    result = service.auto_advance()

    assert result["action"] == "open_reconciliation_mismatch"
    assert result["status"] == "HALTED_RECONCILE_REQUIRED"
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
