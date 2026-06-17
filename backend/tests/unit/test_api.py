from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.security import CurrentUser, create_access_token
from app.main import app
from app.services.risk_service import risk_service
from app.services.vnpy_rpc_service import rpc_service


def client_without_rpc(monkeypatch):
    monkeypatch.setattr(rpc_service, "start", lambda: None)
    monkeypatch.setattr(rpc_service, "stop", lambda: None)
    return TestClient(app)


def auth_headers(role: str = "trader") -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(CurrentUser(role, role))}"}


def test_status_returns_unified_success_payload(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/status")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["data"]["status"] == "ok"


def test_rpc_status_is_available_without_rpc_server(monkeypatch) -> None:
    monkeypatch.setattr(rpc_service, "status", lambda probe=False: {"connected": False, "last_error": "offline"})

    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/rpc/status")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert "connected" in body["data"]


def test_validation_errors_use_unified_error_payload(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.post("/api/market/subscribe", json={})

    assert response.status_code == 422
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "VALIDATION_ERROR"


def test_websocket_sends_gateway_status_and_pong(monkeypatch) -> None:
    monkeypatch.setattr(rpc_service, "status", lambda probe=False: {"connected": False, "last_error": "offline"})

    with client_without_rpc(monkeypatch) as client:
        with client.websocket_connect("/ws/events") as websocket:
            initial = websocket.receive_json()
            websocket.send_text("ping")
            pong = websocket.receive_json()

    assert initial["type"] == "gateway_status"
    assert initial["data"]["connected"] is False
    assert pong["type"] == "pong"


def test_trade_config_returns_safe_default(monkeypatch) -> None:
    risk_service.disable_trade()
    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/trade/config")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["data"]["web_trade_enabled"] is False


def test_create_order_validation_error_uses_unified_payload(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.post(
            "/api/orders",
            headers=auth_headers("trader"),
            json={
                "symbol": "rb2610",
                "exchange": "SHFE",
                "direction": "bad",
                "offset": "open",
                "type": "limit",
                "price": 3000,
                "volume": 1,
                "confirm": True,
            },
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_create_order_requires_auth(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.post(
            "/api/orders",
            json={
                "symbol": "rb2610",
                "exchange": "SHFE",
                "direction": "long",
                "offset": "open",
                "type": "limit",
                "price": 3000,
                "volume": 1,
                "confirm": True,
            },
        )

    assert response.status_code == 401
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "AUTH_REQUIRED"


def test_viewer_cannot_create_order(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.post(
            "/api/orders",
            headers=auth_headers("viewer"),
            json={
                "symbol": "rb2610",
                "exchange": "SHFE",
                "direction": "long",
                "offset": "open",
                "type": "limit",
                "price": 3000,
                "volume": 1,
                "confirm": True,
            },
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PERMISSION_DENIED"


def test_trader_create_order_disabled_returns_trade_disabled(monkeypatch) -> None:
    risk_service.disable_trade()
    with client_without_rpc(monkeypatch) as client:
        response = client.post(
            "/api/orders",
            headers=auth_headers("trader"),
            json={
                "symbol": "rb2610",
                "exchange": "SHFE",
                "direction": "long",
                "offset": "open",
                "type": "limit",
                "price": 3000,
                "volume": 1,
                "confirm": True,
            },
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "TRADE_DISABLED"


def test_create_order_success_uses_trade_service(monkeypatch) -> None:
    from app.api import routes_trade

    monkeypatch.setattr(
        routes_trade.trade_service,
        "send_order",
        lambda payload, source_ip=None, operator="anonymous": {"vt_orderid": "CTP.1", "accepted": True},
    )

    with client_without_rpc(monkeypatch) as client:
        response = client.post(
            "/api/orders",
            headers=auth_headers("trader"),
            json={
                "symbol": "rb2610",
                "exchange": "SHFE",
                "direction": "long",
                "offset": "open",
                "type": "limit",
                "price": 3000,
                "volume": 1,
                "confirm": True,
            },
        )

    assert response.status_code == 200
    assert response.json()["data"]["vt_orderid"] == "CTP.1"


def test_cancel_order_not_found_uses_unified_payload(monkeypatch) -> None:
    from app.core.errors import OrderNotFoundError
    from app.api import routes_trade

    def fail(*args, **kwargs):
        raise OrderNotFoundError(detail={"vt_orderid": "CTP.missing"})

    monkeypatch.setattr(routes_trade.trade_service, "cancel_order", fail)

    with client_without_rpc(monkeypatch) as client:
        response = client.post("/api/orders/CTP.missing/cancel", headers=auth_headers("trader"), json={})

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "ORDER_NOT_FOUND"


def test_cancel_all_returns_items(monkeypatch) -> None:
    from app.api import routes_trade

    monkeypatch.setattr(
        routes_trade.trade_service,
        "cancel_all",
        lambda payload, source_ip=None, operator="anonymous": {
            "requested": 2,
            "success": 1,
            "failed": 1,
            "items": [
                {"vt_orderid": "CTP.1", "cancel_requested": True, "error": None},
                {"vt_orderid": "CTP.2", "cancel_requested": False, "error": "cancel failed"},
            ],
        },
    )

    with client_without_rpc(monkeypatch) as client:
        response = client.post("/api/orders/cancel-all", headers=auth_headers("trader"), json={})

    assert response.status_code == 200
    assert response.json()["data"]["failed"] == 1


def test_admin_can_enable_and_disable_trade(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        enable = client.post("/api/risk/trade/enable", headers=auth_headers("admin"))
        disable = client.post("/api/risk/trade/disable", headers=auth_headers("admin"))

    assert enable.status_code == 200
    assert enable.json()["data"]["web_trade_enabled"] is True
    assert disable.status_code == 200
    assert disable.json()["data"]["web_trade_enabled"] is False


def test_trader_cannot_update_risk_rules(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.patch("/api/risk/rules", headers=auth_headers("trader"), json={"max_order_volume": 2})

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PERMISSION_DENIED"


def test_admin_emergency_stop_disables_trade(monkeypatch) -> None:
    risk_service.enable_trade()
    with client_without_rpc(monkeypatch) as client:
        response = client.post(
            "/api/risk/emergency-stop",
            headers=auth_headers("admin"),
            json={"cancel_all": False, "reason": "test"},
        )

    assert response.status_code == 200
    assert response.json()["data"]["status"]["emergency_stopped"] is True


def test_risk_change_pushes_websocket_alert(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        with client.websocket_connect("/ws/events") as websocket:
            assert websocket.receive_json()["type"] == "gateway_status"
            response = client.post("/api/risk/trade/enable", headers=auth_headers("admin"))
            message = websocket.receive_json()

    assert response.status_code == 200
    assert message["type"] == "risk_alert"
    assert message["data"]["action"] == "trade_enable"
