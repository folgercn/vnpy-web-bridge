"""Compatibility-path tests after the Issue #291 Phase A API split.

The former 675-line test module exercised the web-bridge monolith (RPC,
TradeService, monitoring and worker singletons).  Those behaviours are not a
valid Phase A entrypoint.  The retained tests prove the replacement boundary:
``app.main`` is only a Control alias, typed commands are the sole mutation
surface, and stale legacy routes return an explicit fail-closed response.
Detailed Control and Execution behaviour lives in the Issue #291 test modules.
"""

from __future__ import annotations

from app.control_api import app as control_app
from app.core.security import CurrentUser, create_access_token
from app.main import app as main_app
from fastapi.testclient import TestClient


def _headers(role: str = "viewer", username: str | None = None) -> dict[str, str]:
    principal = username or role
    return {
        "Authorization": f"Bearer {create_access_token(CurrentUser(principal, role))}"
    }


def _typed_overview_command() -> dict[str, object]:
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": "cmd-api-compat-0001",
        "idempotency_key": "idem-api-compat-0001",
        "correlation_id": "corr-api-compat-0001",
        "issued_at": "2030-01-01T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "viewer",
            "operator": "viewer",
            "role": "viewer",
        },
        "command": "overview",
        "expected": {"state_version": 0},
        "payload": {},
    }


def test_main_is_the_control_entrypoint_without_monolith_lifecycle() -> None:
    assert main_app is control_app
    assert not any(getattr(route, "path", "") == "/" for route in main_app.routes)
    assert not any(
        getattr(route, "path", "").startswith("/frontend") for route in main_app.routes
    )


def test_control_health_and_version_are_public_process_metadata() -> None:
    with TestClient(control_app) as client:
        live = client.get("/health/live")
        version = client.get("/version")

    assert live.status_code == 200
    assert live.json()["service"] == "control-api"
    assert version.status_code == 200
    assert version.json()["service"] == "control-api"


def test_legacy_rpc_and_order_routes_fail_closed_without_rpc_or_trade_imports() -> None:
    with TestClient(control_app) as client:
        rpc = client.get("/api/rpc/status", headers=_headers())
        orders = client.post("/api/orders", headers=_headers("trader"), json={})

    assert rpc.status_code == 503
    assert rpc.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert orders.status_code == 503
    assert orders.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_control_mutation_requires_complete_typed_execution_envelope() -> None:
    with TestClient(control_app) as client:
        missing = client.post(
            "/api/control/execution/commands",
            headers=_headers(),
            json={"command": "overview"},
        )

    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "COMMAND_SCHEMA_INVALID"


def test_control_command_rejects_actor_mismatch_before_execution() -> None:
    command = _typed_overview_command()
    command["actor"] = {**command["actor"], "operator": "different-user"}
    with TestClient(control_app) as client:
        response = client.post(
            "/api/control/execution/commands",
            headers=_headers("viewer"),
            json=command,
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PERMISSION_DENIED"
