from __future__ import annotations

from app.schemas.mak_v2_observer import MakV2DryRunSignalRequestDTO, MakV2ObserverEnableRequestDTO
from app.services.mak_v2_testnet_observer.event_store import MakV2ObserverEventStore
from app.services.mak_v2_testnet_observer.service import MakV2TestnetObserverService


class FakeRisk:
    def __init__(self, *, emergency_stopped: bool = False) -> None:
        self.emergency_stopped = emergency_stopped

    def status(self) -> dict:
        return {
            "risk_enabled": True,
            "web_trade_enabled": False,
            "emergency_stopped": self.emergency_stopped,
            "rules_version": 1,
        }


class FakeAudit:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def record(self, **kwargs) -> None:
        self.rows.append(kwargs)


def make_service(*, emergency_stopped: bool = False) -> MakV2TestnetObserverService:
    return MakV2TestnetObserverService(store=MakV2ObserverEventStore(), risk=FakeRisk(emergency_stopped=emergency_stopped), audit=FakeAudit())  # type: ignore[arg-type]


def enable_payload() -> MakV2ObserverEnableRequestDTO:
    return MakV2ObserverEnableRequestDTO(
        manual_approval=True,
        testnet_mode=True,
        reason="manual testnet waiver for controlled observer",
        confirm_testnet_only=True,
        confirm_no_production=True,
        confirm_max_one_lot=True,
        confirm_no_auto_promotion=True,
    )


def ps_signal(**overrides) -> MakV2DryRunSignalRequestDTO:
    payload = {
        "instrument": "ps",
        "exact_contract": "GFEX.ps2609",
        "side": "long",
        "z_score": -1.6,
        "last_price": 39155,
        "bid_price_1": 39150,
        "ask_price_1": 39155,
        "bid_volume_1": 1,
        "ask_volume_1": 1,
        "quote_age_ms": 250,
        "cluster_id": "cluster-a",
        "active_overlap_900s": 2,
        "cooldown_state": "clear",
        "data_quality_status": "pass",
    }
    payload.update(overrides)
    return MakV2DryRunSignalRequestDTO(**payload)


def test_enable_requires_all_manual_waiver_confirmations() -> None:
    service = make_service()
    result = service.enable(
        MakV2ObserverEnableRequestDTO(
            manual_approval=True,
            testnet_mode=True,
            reason="missing production confirmation",
            confirm_testnet_only=True,
            confirm_no_production=False,
            confirm_max_one_lot=True,
            confirm_no_auto_promotion=True,
        ),
        operator="admin",
        role="admin",
        source_ip=None,
    )

    assert result["enabled"] is False
    assert result["enable_rejected"] is True
    assert service.status()["guardrail_events_total"] == 1


def test_dry_run_signal_creates_intent_without_touching_order_endpoint() -> None:
    service = make_service()
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)

    result = service.dry_run_signal(ps_signal(), operator="admin", role="admin")

    assert result["signal"]["eligible_for_testnet"] is True
    assert result["decision"]["decision"] == "dry_run_intent"
    assert result["decision"]["final_allow_order"] is True
    assert result["order_intent"]["requested_lots"] == 1
    assert result["order_intent"]["dry_run_only"] is True
    assert result["order_intent"]["order_endpoint_touched"] is False
    assert result["status"]["order_endpoint_touched"] is False


def test_cooldown_blocks_duplicate_signal_after_intent() -> None:
    service = make_service()
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)
    service.dry_run_signal(ps_signal(cluster_id="cluster-a"), operator="admin", role="admin")

    result = service.dry_run_signal(ps_signal(cluster_id="cluster-b"), operator="admin", role="admin")

    assert result["signal"]["eligible_for_testnet"] is False
    assert result["decision"]["decision"] == "blocked"
    assert "cooldown_active" in result["decision"]["decision_reason"]
    assert result["order_intent"] is None


def test_continuous_contract_symbol_is_not_order_eligible() -> None:
    service = make_service()
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)

    result = service.dry_run_signal(ps_signal(exact_contract="KQ.m@GFEX.ps"), operator="admin", role="admin")

    assert result["signal"]["eligible_for_testnet"] is False
    assert "exact_contract_invalid" in result["decision"]["decision_reason"]


def test_exact_contract_must_match_exchange_instrument_and_delivery_month() -> None:
    service = make_service()
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)

    for exact_contract in ("GFEX.ps", "GFEX.psfoo", "GFEX.lc2609"):
        result = service.dry_run_signal(
            ps_signal(exact_contract=exact_contract, cluster_id=exact_contract),
            operator="admin",
            role="admin",
        )

        assert result["signal"]["eligible_for_testnet"] is False
        assert "exact_contract_invalid" in result["decision"]["decision_reason"]


def test_risk_emergency_stop_blocks_intent() -> None:
    service = make_service(emergency_stopped=True)
    service.enable(enable_payload(), operator="admin", role="admin", source_ip=None)

    result = service.dry_run_signal(ps_signal(), operator="admin", role="admin")

    assert result["signal"]["eligible_for_testnet"] is False
    assert "risk_emergency_stopped" in result["decision"]["decision_reason"]
