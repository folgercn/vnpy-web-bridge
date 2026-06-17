from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.security import CurrentUser, create_access_token
from app.main import app
from app.services.vnpy_rpc_service import rpc_service


def auth_headers(role: str = "viewer") -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(CurrentUser(role, role))}"}


def client_without_rpc(monkeypatch):
    monkeypatch.setattr(rpc_service, "start", lambda: None)
    monkeypatch.setattr(rpc_service, "stop", lambda: None)
    return TestClient(app)


def install_strategy_route_mocks(monkeypatch) -> None:
    from app.api import routes_strategy

    async def init_strategy(name, user_id, role, source_ip=None):
        return {"strategy_name": name, "operation": "init", "accepted": True}

    monkeypatch.setattr(
        routes_strategy.strategy_service,
        "list_strategies",
        lambda: [{"strategy_name": "ma_demo", "class_name": "MaStrategy", "status": "stopped"}],
    )
    monkeypatch.setattr(routes_strategy.strategy_service, "get_setting", lambda name: {"fast_window": 10})
    monkeypatch.setattr(routes_strategy.strategy_service, "get_variables", lambda name: {"pos": 0})
    monkeypatch.setattr(
        routes_strategy.strategy_service,
        "init_strategy",
        init_strategy,
    )


def test_viewer_can_list_strategies(monkeypatch) -> None:
    install_strategy_route_mocks(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/strategies", headers=auth_headers("viewer"))

    assert response.status_code == 200
    assert response.json()["data"][0]["strategy_name"] == "ma_demo"


def test_strategy_requires_auth(monkeypatch) -> None:
    install_strategy_route_mocks(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/strategies")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_REQUIRED"


def test_viewer_cannot_init_strategy(monkeypatch) -> None:
    install_strategy_route_mocks(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        response = client.post("/api/strategies/ma_demo/init", headers=auth_headers("viewer"))

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PERMISSION_DENIED"


def test_admin_can_init_strategy(monkeypatch) -> None:
    install_strategy_route_mocks(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        response = client.post("/api/strategies/ma_demo/init", headers=auth_headers("admin"))

    assert response.status_code == 200
    assert response.json()["data"]["accepted"] is True
