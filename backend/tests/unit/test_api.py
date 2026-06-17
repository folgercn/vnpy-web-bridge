from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.services.vnpy_rpc_service import rpc_service


def client_without_rpc(monkeypatch):
    monkeypatch.setattr(rpc_service, "start", lambda: None)
    monkeypatch.setattr(rpc_service, "stop", lambda: None)
    return TestClient(app)


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
