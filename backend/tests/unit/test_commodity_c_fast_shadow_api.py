from __future__ import annotations

from app.core.security import CurrentUser, create_access_token
from app.main import app
from app.services.vnpy_rpc_service import rpc_service
from fastapi.testclient import TestClient


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
    return {"Authorization": f"Bearer {create_access_token(CurrentUser(role, role))}"}


def client_without_rpc(monkeypatch):
    monkeypatch.setattr(rpc_service, "start", lambda: None)
    monkeypatch.setattr(rpc_service, "stop", lambda: None)
    monkeypatch.setattr(rpc_service, "get_contracts", list)
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
    """C_FAST shadow is a Phase-B producer, not a Control API surface."""
    service = install_service(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        response = client.get(
            "/api/commodity-simnow/c-fast-shadow/status",
            headers=auth_headers("viewer"),
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert service.reload_calls == 0


def test_reload_is_admin_only_and_has_no_execution_route(monkeypatch) -> None:
    """Retired reload/execute paths fail closed for every authenticated role."""
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

    for response in (forbidden, reloaded, no_execute):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert service.reload_calls == 0
