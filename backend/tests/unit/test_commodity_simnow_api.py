from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.security import CurrentUser, create_access_token
from app.main import app
from app.services.vnpy_rpc_service import rpc_service


class FakeCommoditySimNowService:
    def __init__(self) -> None:
        self.enabled = False
        self.preview_calls = 0

    def status(self) -> dict:
        return {"configured": True, "enabled": self.enabled, "production_allowed": False}

    def plan(self) -> dict:
        return {}

    def list_events(self, limit: int) -> list[dict]:
        return []

    def enable(self, payload, **kwargs) -> dict:
        self.enabled = True
        return self.status()

    def disable(self, payload, **kwargs) -> dict:
        self.enabled = False
        return self.status()

    def preview(self, batch, **kwargs) -> dict:
        self.preview_calls += 1
        return {"status": "READY_OPEN", "batch_id": batch.batch_id}

    def execute(self, payload, **kwargs) -> dict:
        return {"status": f"{payload.phase.upper()}_SUBMITTED"}

    def reconcile(self, plan_hash, **kwargs) -> dict:
        return {"status": "COMPLETE", "plan_hash": plan_hash}


def auth_headers(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(CurrentUser(role, role))}"}


def client_without_rpc(monkeypatch):
    monkeypatch.setattr(rpc_service, "start", lambda: None)
    monkeypatch.setattr(rpc_service, "stop", lambda: None)
    return TestClient(app)


def install_service(monkeypatch) -> FakeCommoditySimNowService:
    from app.api import routes_commodity_simnow

    service = FakeCommoditySimNowService()
    monkeypatch.setattr(routes_commodity_simnow, "commodity_simnow_service", service)
    return service


def enable_payload() -> dict:
    return {
        "manual_approval": True,
        "simnow_mode": True,
        "reason": "manual SimNow route test",
        "confirm_simnow_only": True,
        "confirm_no_production": True,
        "confirm_cold_start_or_reconciled_state": True,
        "confirm_manual_two_phase_dispatch": True,
        "confirm_no_auto_promotion": True,
    }


def test_viewer_can_read_status_but_cannot_enable(monkeypatch) -> None:
    install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        status = client.get("/api/commodity-simnow/status", headers=auth_headers("viewer"))
        forbidden = client.post(
            "/api/commodity-simnow/enable",
            headers=auth_headers("viewer"),
            json=enable_payload(),
        )

    assert status.status_code == 200
    assert status.json()["data"]["production_allowed"] is False
    assert forbidden.status_code == 403


def test_admin_can_enable_controller(monkeypatch) -> None:
    service = install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        response = client.post(
            "/api/commodity-simnow/enable",
            headers=auth_headers("admin"),
            json=enable_payload(),
        )

    assert response.status_code == 200
    assert response.json()["data"]["enabled"] is True
    assert service.enabled is True


def test_commodity_routes_require_authentication(monkeypatch) -> None:
    install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        status = client.get("/api/commodity-simnow/status")
        plan = client.get("/api/commodity-simnow/plan")

    assert status.status_code == 401
    assert plan.status_code == 401
