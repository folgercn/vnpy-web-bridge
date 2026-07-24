from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.security import CurrentUser, create_access_token
from app.main import app
from app.services.vnpy_rpc_service import rpc_service


class FakeCFastShadowService:
    def __init__(self) -> None:
        self.reload_calls = 0

    def status(self) -> dict:
        return {
            "configured": True,
            "enabled": True,
            "valid": True,
            "validation_valid": True,
            "accepted": True,
            "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
            "mode": "shadow_only",
            "authority_granted": False,
            "dispatch_allowed": False,
            "replacement_allowed": False,
            "production_allowed": False,
        }

    def reload(self, **kwargs) -> dict:
        self.reload_calls += 1
        return {**self.status(), "reloaded_by": kwargs["operator"]}


def auth_headers(role: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {create_access_token(CurrentUser(role, role))}"
    }


def client_without_rpc(monkeypatch):
    monkeypatch.setattr(rpc_service, "start", lambda: None)
    monkeypatch.setattr(rpc_service, "stop", lambda: None)
    monkeypatch.setattr(rpc_service, "get_contracts", lambda: [])
    return TestClient(app)


def install_service(monkeypatch) -> FakeCFastShadowService:
    from app.api import routes_commodity_c_fast_shadow

    service = FakeCFastShadowService()
    monkeypatch.setattr(
        routes_commodity_c_fast_shadow,
        "commodity_c_fast_shadow_service",
        service,
    )
    return service


def test_status_is_readable_without_triggering_reload(monkeypatch) -> None:
    service = install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        response = client.get(
            "/api/commodity-simnow/c-fast-shadow/status",
            headers=auth_headers("viewer"),
        )

    assert response.status_code == 200
    assert response.json()["data"]["authority_granted"] is False
    assert response.json()["data"]["dispatch_allowed"] is False
    assert service.reload_calls == 0


def test_reload_is_admin_only_and_has_no_execution_route(monkeypatch) -> None:
    service = install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        forbidden = client.post(
            "/api/commodity-simnow/c-fast-shadow/reload",
            headers=auth_headers("trader"),
        )
        reloaded = client.post(
            "/api/commodity-simnow/c-fast-shadow/reload",
            headers=auth_headers("admin"),
        )
        no_execute = client.post(
            "/api/commodity-simnow/c-fast-shadow/execute",
            headers=auth_headers("admin"),
        )

    assert forbidden.status_code == 403
    assert reloaded.status_code == 200
    assert reloaded.json()["data"]["reloaded_by"] == "admin"
    assert service.reload_calls == 1
    assert no_execute.status_code == 404
