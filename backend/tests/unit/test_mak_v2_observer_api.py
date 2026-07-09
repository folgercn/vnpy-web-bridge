from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.security import CurrentUser, create_access_token
from app.main import app
from app.services.mak_v2_testnet_observer.event_store import MakV2ObserverEventStore
from app.services.mak_v2_testnet_observer.service import MakV2TestnetObserverService
from app.services.vnpy_rpc_service import rpc_service


class FakeAudit:
    def record(self, **kwargs) -> None:
        return None


def auth_headers(role: str = "viewer") -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(CurrentUser(role, role))}"}


def client_without_rpc(monkeypatch):
    monkeypatch.setattr(rpc_service, "start", lambda: None)
    monkeypatch.setattr(rpc_service, "stop", lambda: None)
    return TestClient(app)


def install_observer(monkeypatch) -> MakV2TestnetObserverService:
    from app.api import routes_mak_v2_observer

    service = MakV2TestnetObserverService(store=MakV2ObserverEventStore(), audit=FakeAudit())  # type: ignore[arg-type]
    monkeypatch.setattr(routes_mak_v2_observer, "mak_v2_observer_service", service)
    return service


def waiver_payload() -> dict:
    return {
        "manual_approval": True,
        "testnet_mode": True,
        "reason": "manual testnet waiver for api route",
        "confirm_testnet_only": True,
        "confirm_no_production": True,
        "confirm_max_one_lot": True,
        "confirm_no_auto_promotion": True,
    }


def signal_payload() -> dict:
    return {
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
        "cluster_id": "api-test",
        "active_overlap_900s": 1,
        "cooldown_state": "clear",
        "data_quality_status": "pass",
    }


def test_viewer_can_read_status_but_cannot_enable(monkeypatch) -> None:
    install_observer(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        status = client.get("/api/mak-v2/testnet-observer/status", headers=auth_headers("viewer"))
        forbidden = client.post("/api/mak-v2/testnet-observer/enable", headers=auth_headers("viewer"), json=waiver_payload())

    assert status.status_code == 200
    assert status.json()["data"]["capacity_status"] == "L1_CONSTRAINED_WATCH"
    assert forbidden.status_code == 403


def test_admin_enable_then_trader_dry_run_signal_creates_intent(monkeypatch) -> None:
    install_observer(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        enabled = client.post("/api/mak-v2/testnet-observer/enable", headers=auth_headers("admin"), json=waiver_payload())
        result = client.post("/api/mak-v2/testnet-observer/dry-run/signal", headers=auth_headers("trader"), json=signal_payload())
        orders = client.get("/api/mak-v2/testnet-observer/orders", headers=auth_headers("viewer"))

    assert enabled.status_code == 200
    assert enabled.json()["data"]["enabled"] is True
    assert result.status_code == 200
    data = result.json()["data"]
    assert data["decision"]["decision"] == "dry_run_intent"
    assert data["order_intent"]["dry_run_only"] is True
    assert data["order_intent"]["order_endpoint_touched"] is False
    assert orders.json()["data"][0]["intent_id"] == data["order_intent"]["intent_id"]


def test_safety_audit_requires_admin_and_defaults_to_fail_until_waived(monkeypatch) -> None:
    install_observer(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        forbidden = client.post("/api/mak-v2/testnet-observer/safety-audit", headers=auth_headers("viewer"), json={})
        result = client.post("/api/mak-v2/testnet-observer/safety-audit", headers=auth_headers("admin"), json={})

    assert forbidden.status_code == 403
    assert result.status_code == 200
    data = result.json()["data"]
    assert data["overall"] == "FAIL"
    assert data["single_order_smoke_allowed"] is False
    failed = {row["name"] for row in data["checks"] if row["status"] == "FAIL"}
    assert {"observer_enabled", "manual_approval_active", "testnet_mode_active"} <= failed


def test_safety_audit_history_is_readable_by_all_observer_roles(monkeypatch) -> None:
    install_observer(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        created = client.post("/api/mak-v2/testnet-observer/safety-audit", headers=auth_headers("admin"), json={})
        for role in ("admin", "viewer", "trader"):
            history = client.get("/api/mak-v2/testnet-observer/safety-audits", headers=auth_headers(role))
            latest = client.get("/api/mak-v2/testnet-observer/safety-audit/latest", headers=auth_headers(role))

            assert history.status_code == 200
            assert latest.status_code == 200
            assert history.json()["data"][0] == created.json()["data"]
            assert latest.json()["data"] == created.json()["data"]


def test_latest_safety_audit_is_empty_before_first_audit(monkeypatch) -> None:
    install_observer(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        result = client.get("/api/mak-v2/testnet-observer/safety-audit/latest", headers=auth_headers("viewer"))

    assert result.status_code == 200
    assert result.json()["data"] == {}
