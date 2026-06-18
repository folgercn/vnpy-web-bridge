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


def auth_headers_for(username: str, role: str = "viewer") -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(CurrentUser(username, role))}"}


class FakeWatchlistService:
    def __init__(self) -> None:
        self.rows: dict[str, list[dict]] = {}

    def list_items(self, username: str) -> list[dict]:
        return self.rows.get(username, [])

    def add_contract(self, username: str, item: dict) -> dict:
        row = {
            "watch_type": "contract",
            "watch_key": f"contract:{item['vt_symbol']}",
            "product_codes": [],
            "exchange_codes": [],
            **item,
        }
        self.rows.setdefault(username, []).append(row)
        return row

    def remove_item(self, username: str, watch_key: str) -> dict:
        rows = self.rows.get(username, [])
        before = len(rows)
        self.rows[username] = [row for row in rows if row["watch_key"] != watch_key]
        return {"removed": len(self.rows[username]) != before, "watch_key": watch_key}


def test_status_returns_unified_success_payload(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/status")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["data"]["status"] == "ok"


def test_health_live_is_public_and_minimal(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/health/live")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["data"]["status"] == "live"
    assert "rpc" not in body["data"]


def test_rpc_status_is_available_without_rpc_server(monkeypatch) -> None:
    monkeypatch.setattr(rpc_service, "status", lambda probe=False: {"connected": False, "last_error": "offline"})

    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/rpc/status", headers=auth_headers("viewer"))

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert "connected" in body["data"]


def test_monitor_routes_require_auth_and_hide_telegram_secret(monkeypatch) -> None:
    from app.api import routes_monitoring

    monkeypatch.setattr(
        routes_monitoring.telegram_service,
        "config_status",
        lambda: {
            "enabled": True,
            "configured": True,
            "send_levels": ["warning", "critical"],
            "timeout_seconds": 8,
        },
    )

    with client_without_rpc(monkeypatch) as client:
        unauthenticated = client.get("/api/monitor/summary")
        response = client.get("/api/monitor/telegram/config", headers=auth_headers("viewer"))

    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["configured"] is True
    assert "token" not in str(data).lower()
    assert "chat_id" not in data


def test_admin_can_ack_and_create_silence(monkeypatch) -> None:
    from datetime import datetime, timedelta, timezone
    from app.api import routes_monitoring

    class FakeAlertService:
        def ack(self, incident_id, *, operator):
            return {"incident_id": incident_id, "status": "acknowledged", "acknowledged_by": operator}

        def create_silence(self, **kwargs):
            return {"silence_id": "sil_1", "reason": kwargs["reason"], "created_by": kwargs["operator"]}

    monkeypatch.setattr(routes_monitoring, "alert_service", FakeAlertService())

    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    with client_without_rpc(monkeypatch) as client:
        viewer_ack = client.post("/api/monitor/incidents/rpc_unavailable:CTP/ack", headers=auth_headers("viewer"))
        admin_ack = client.post("/api/monitor/incidents/rpc_unavailable:CTP/ack", headers=auth_headers("admin"))
        silence = client.post(
            "/api/monitor/silences",
            headers=auth_headers("admin"),
            json={"rule_id": "rpc_unavailable", "scope_id": "CTP", "expires_at": expires_at, "reason": "maintenance"},
        )

    assert viewer_ack.status_code == 403
    assert admin_ack.status_code == 200
    assert admin_ack.json()["data"]["status"] == "acknowledged"
    assert silence.status_code == 200
    assert silence.json()["data"]["silence_id"] == "sil_1"


def test_rpc_probe_runs_explicit_probe(monkeypatch) -> None:
    calls: list[bool] = []

    def status(probe=False):
        calls.append(probe)
        return {"connected": False, "last_error": "offline"}

    monkeypatch.setattr(rpc_service, "status", status)

    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/rpc/probe", headers=auth_headers("viewer"))

    assert response.status_code == 200
    assert calls == [True]


def test_validation_errors_use_unified_error_payload(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.post("/api/market/subscribe", headers=auth_headers("viewer"), json={})

    assert response.status_code == 422
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "VALIDATION_ERROR"


def test_websocket_sends_gateway_status_and_pong(monkeypatch) -> None:
    monkeypatch.setattr(rpc_service, "status", lambda probe=False: {"connected": False, "last_error": "offline"})
    token = create_access_token(CurrentUser("viewer", "viewer"))

    with client_without_rpc(monkeypatch) as client:
        with client.websocket_connect(f"/ws/events?token={token}") as websocket:
            initial = websocket.receive_json()
            websocket.send_text("ping")
            pong = websocket.receive_json()

    assert initial["type"] == "gateway_status"
    assert initial["data"]["connected"] is False
    assert pong["type"] == "pong"


def test_websocket_rejects_missing_token(monkeypatch) -> None:
    from starlette.websockets import WebSocketDisconnect

    with client_without_rpc(monkeypatch) as client:
        try:
            with client.websocket_connect("/ws/events"):
                raise AssertionError("websocket should not connect")
        except WebSocketDisconnect as exc:
            assert exc.code == 1008


def test_trade_config_returns_safe_default(monkeypatch) -> None:
    risk_service.disable_trade()
    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/trade/config", headers=auth_headers("viewer"))

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["data"]["web_trade_enabled"] is False


def test_market_bars_requires_auth_and_returns_rows(monkeypatch) -> None:
    monkeypatch.setattr(
        rpc_service,
        "get_bars",
        lambda symbol, exchange, interval, limit: [{"vt_symbol": f"{symbol}.{exchange}", "interval": interval, "close_price": 3000}],
    )

    with client_without_rpc(monkeypatch) as client:
        unauthenticated = client.get("/api/market/bars?symbol=rb2610&exchange=SHFE")
        response = client.get("/api/market/bars?symbol=rb2610&exchange=SHFE", headers=auth_headers("viewer"))

    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    assert response.json()["data"][0]["vt_symbol"] == "rb2610.SHFE"


def test_market_data_status_requires_auth_and_returns_pipeline_snapshot(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.api.routes_market.tick_persistence_service.snapshot",
        lambda: {
            "enabled": True,
            "running": True,
            "connected": True,
            "received_total": 1,
            "valid_total": 1,
            "invalid_total": 0,
            "persisted_total": 1,
            "retry_total": 0,
            "failed_total": 0,
            "dropped_total": 0,
            "queue_depth": 0,
            "queue_capacity": 100,
            "spool_rows": 0,
            "spool_bytes": 0,
            "last_received_at": "2026-06-18T02:00:00+00:00",
            "last_persisted_at": "2026-06-18T02:00:01+00:00",
            "persistence_lag_seconds": 0.0,
            "last_error": None,
        },
    )

    with client_without_rpc(monkeypatch) as client:
        unauthenticated = client.get("/api/market/data/status")
        response = client.get("/api/market/data/status", headers=auth_headers("viewer"))

    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["data"]["enabled"] is True
    assert body["data"]["received_total"] == 1
    assert body["data"]["queue_depth"] == 0


def test_market_unsubscribe_requires_auth_and_returns_result(monkeypatch) -> None:
    monkeypatch.setattr(
        rpc_service,
        "unsubscribe_market",
        lambda symbol, exchange: {"vt_symbol": f"{symbol}.{exchange}", "subscribed": False},
    )

    with client_without_rpc(monkeypatch) as client:
        unauthenticated = client.post("/api/market/unsubscribe", json={"symbol": "rb2610", "exchange": "SHFE"})
        response = client.post(
            "/api/market/unsubscribe",
            headers=auth_headers("viewer"),
            json={"symbol": "rb2610", "exchange": "SHFE"},
        )

    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    assert response.json()["data"] == {"vt_symbol": "rb2610.SHFE", "subscribed": False}


def test_market_data_overview_requires_auth(monkeypatch) -> None:
    from app.api import routes_market

    monkeypatch.setattr(
        routes_market.market_data_service,
        "get_overview",
        lambda limit=500: [{"vt_symbol": "rb2610.SHFE", "row_count": 2}],
    )

    with client_without_rpc(monkeypatch) as client:
        unauthenticated = client.get("/api/market/data/overview")
        response = client.get("/api/market/data/overview", headers=auth_headers("viewer"))

    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    assert response.json()["data"][0]["vt_symbol"] == "rb2610.SHFE"


def test_market_data_ticks_uses_filters(monkeypatch) -> None:
    from app.api import routes_market

    calls: list[dict[str, object]] = []

    def query_ticks(**kwargs):
        calls.append(kwargs)
        return [{"vt_symbol": kwargs["vt_symbol"], "last_price": 3126}]

    monkeypatch.setattr(routes_market.market_data_service, "query_ticks", query_ticks)

    with client_without_rpc(monkeypatch) as client:
        response = client.get(
            "/api/market/data/ticks?vt_symbol=rb2610.SHFE&limit=20",
            headers=auth_headers("viewer"),
        )

    assert response.status_code == 200
    assert response.json()["data"][0]["last_price"] == 3126
    assert calls[0]["vt_symbol"] == "rb2610.SHFE"
    assert calls[0]["limit"] == 20


def test_market_data_import_requires_admin(monkeypatch) -> None:
    from app.api import routes_market

    monkeypatch.setattr(
        routes_market.market_data_service,
        "import_ticks_csv",
        lambda content: {"imported": 1, "skipped": 0},
    )
    files = {"file": ("ticks.csv", b"vt_symbol,last_price\nrb2610.SHFE,3126\n", "text/csv")}

    with client_without_rpc(monkeypatch) as client:
        viewer = client.post("/api/market/data/import", headers=auth_headers("viewer"), files=files)
        admin = client.post("/api/market/data/import", headers=auth_headers("admin"), files=files)

    assert viewer.status_code == 403
    assert admin.status_code == 200
    assert admin.json()["data"]["imported"] == 1


def test_watchlist_is_scoped_by_username(monkeypatch) -> None:
    from app.api import routes_market

    fake = FakeWatchlistService()
    monkeypatch.setattr(routes_market, "watchlist_service", fake)

    with client_without_rpc(monkeypatch) as client:
        alice_add = client.post(
            "/api/market/watchlist",
            headers=auth_headers_for("alice"),
            json={"vt_symbol": "ru2609.SHFE", "symbol": "ru2609", "exchange": "SHFE", "display_name": "天然橡胶2609 / RU2609 · 上期所"},
        )
        bob_list = client.get("/api/market/watchlist", headers=auth_headers_for("bob"))
        alice_list = client.get("/api/market/watchlist", headers=auth_headers_for("alice"))

    assert alice_add.status_code == 200
    assert bob_list.status_code == 200
    assert bob_list.json()["data"] == []
    assert alice_list.json()["data"][0]["vt_symbol"] == "ru2609.SHFE"


def test_watchlist_delete_uses_authenticated_username(monkeypatch) -> None:
    from app.api import routes_market

    fake = FakeWatchlistService()
    fake.rows["alice"] = [{"watch_type": "contract", "watch_key": "contract:ru2609.SHFE", "vt_symbol": "ru2609.SHFE"}]
    fake.rows["bob"] = [{"watch_type": "contract", "watch_key": "contract:ru2609.SHFE", "vt_symbol": "ru2609.SHFE"}]
    monkeypatch.setattr(routes_market, "watchlist_service", fake)

    with client_without_rpc(monkeypatch) as client:
        response = client.delete("/api/market/watchlist/contract:ru2609.SHFE", headers=auth_headers_for("alice"))

    assert response.status_code == 200
    assert fake.rows["alice"] == []
    assert fake.rows["bob"][0]["vt_symbol"] == "ru2609.SHFE"


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
        token = create_access_token(CurrentUser("viewer", "viewer"))
        with client.websocket_connect(f"/ws/events?token={token}") as websocket:
            assert websocket.receive_json()["type"] == "gateway_status"
            response = client.post("/api/risk/trade/enable", headers=auth_headers("admin"))
            message = websocket.receive_json()

    assert response.status_code == 200
    assert message["type"] == "risk_alert"
    assert message["data"]["action"] == "trade_enable"


def test_calendar_month_returns_holiday_and_adjusted_workday(monkeypatch) -> None:
    with client_without_rpc(monkeypatch) as client:
        response = client.get("/api/calendar/month?year=2026&month=2", headers=auth_headers("viewer"))

    assert response.status_code == 200
    rows = {item["date"]: item for item in response.json()["data"]["days"]}
    assert rows["2026-02-16"]["holiday_name"] == "春节"
    assert rows["2026-02-16"]["is_trading_day"] is False
    assert rows["2026-02-14"]["is_adjusted_workday"] is True
    assert rows["2026-02-14"]["is_trading_day"] is False
