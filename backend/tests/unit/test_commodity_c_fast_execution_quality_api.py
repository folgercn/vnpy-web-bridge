from __future__ import annotations

import ast
from pathlib import Path

from app.core.security import CurrentUser, create_access_token
from app.main import app
from app.services.vnpy_rpc_service import rpc_service
from fastapi.testclient import TestClient

FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}


class FakeExecutionQualityRuntime:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def status(self) -> dict[str, object]:
        self.calls.append("status")
        return self._projection("DISABLED_DEFAULT_OFF")

    def reload(self) -> dict[str, object]:
        self.calls.append("reload")
        return self._projection("BLOCKED_FULL_REVALIDATION_VERIFIER_NOT_BOUND")

    def recover(self) -> dict[str, object]:
        self.calls.append("recovery")
        return self._projection("BLOCKED_FULL_REVALIDATION_VERIFIER_NOT_BOUND")

    def intents(self) -> tuple[dict[str, object], ...]:
        self.calls.append("intents")
        return ({"intent_id": "cfast-virtual-intent-v1-" + "a" * 64},)

    def execution_quality(self) -> tuple[dict[str, object], ...]:
        self.calls.append("execution_quality")
        return ({"target_key": "decision", "completion_state": "SEALED"},)

    def evidence_export(self) -> dict[str, object]:
        self.calls.append("evidence_export")
        return {
            "artifact_filename": "immutable.json",
            "artifact_state": "ALREADY_PRESENT",
            "export": {"export_sha256": "b" * 64},
        }

    @staticmethod
    def _projection(state: str) -> dict[str, object]:
        return {
            "schema_version": ("commodity_c_fast_execution_quality_runtime_status_v1"),
            "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
            "runtime_state": state,
            "runtime_active": False,
            "execution_quality_implemented": False,
            "orders_sent": 0,
            "positions_modified": 0,
            **FALSE_AUTHORITY,
        }


def auth_headers(role: str) -> dict[str, str]:
    return {"Authorization": (f"Bearer {create_access_token(CurrentUser(role, role))}")}


def client_without_rpc(monkeypatch) -> TestClient:
    monkeypatch.setattr(rpc_service, "start", lambda: None)
    monkeypatch.setattr(rpc_service, "stop", lambda: None)
    monkeypatch.setattr(rpc_service, "get_contracts", list)
    return TestClient(app)


def install_runtime(monkeypatch) -> FakeExecutionQualityRuntime:
    from app.api import routes_commodity_c_fast_execution_quality

    runtime = FakeExecutionQualityRuntime()
    monkeypatch.setattr(
        routes_commodity_c_fast_execution_quality,
        "commodity_c_fast_execution_quality_production_assembly",
        runtime,
    )
    return runtime


def test_status_is_readonly_authenticated_and_zero_authority(
    monkeypatch,
) -> None:
    runtime = install_runtime(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        unauthenticated = client.get("/api/commodity-c-fast/execution-quality/status")
        response = client.get(
            "/api/commodity-c-fast/execution-quality/status",
            headers=auth_headers("viewer"),
        )

    assert unauthenticated.status_code == 401
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert runtime.calls == []


def test_lifecycle_revalidation_is_admin_only_and_has_no_start_route(
    monkeypatch,
) -> None:
    runtime = install_runtime(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        viewer_reload = client.post(
            "/api/commodity-c-fast/execution-quality/reload",
            headers=auth_headers("viewer"),
        )
        trader_recover = client.post(
            "/api/commodity-c-fast/execution-quality/recover",
            headers=auth_headers("trader"),
        )
        reload_response = client.post(
            "/api/commodity-c-fast/execution-quality/reload",
            headers=auth_headers("admin"),
        )
        recover_response = client.post(
            "/api/commodity-c-fast/execution-quality/recover",
            headers=auth_headers("admin"),
        )
        absent_start = client.post(
            "/api/commodity-c-fast/execution-quality/start",
            headers=auth_headers("admin"),
        )
        absent_execute = client.post(
            "/api/commodity-c-fast/execution-quality/execute",
            headers=auth_headers("admin"),
        )

    for response in (
        viewer_reload,
        trader_recover,
        reload_response,
        recover_response,
        absent_start,
        absent_execute,
    ):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert runtime.calls == []


def test_readonly_projection_endpoints_require_auth_and_allow_all_read_roles(
    monkeypatch,
) -> None:
    runtime = install_runtime(monkeypatch)
    with client_without_rpc(monkeypatch) as client:
        unauthenticated = client.get("/api/commodity-c-fast/execution-quality/intents")
        intents = client.get(
            "/api/commodity-c-fast/execution-quality/intents",
            headers=auth_headers("viewer"),
        )
        quality = client.get(
            "/api/commodity-c-fast/execution-quality/execution-quality",
            headers=auth_headers("trader"),
        )
        exported = client.get(
            "/api/commodity-c-fast/execution-quality/evidence-export",
            headers=auth_headers("admin"),
        )

    assert unauthenticated.status_code == 401
    for response in (intents, quality, exported):
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert runtime.calls == []


def test_failed_current_projection_returns_503_without_mutation(
    monkeypatch,
) -> None:
    runtime = install_runtime(monkeypatch)

    def unavailable():
        raise ValueError("PRODUCTION_ASSEMBLY_CURRENT_PROJECTION_UNAVAILABLE")

    monkeypatch.setattr(runtime, "intents", unavailable)
    with client_without_rpc(monkeypatch) as client:
        response = client.get(
            "/api/commodity-c-fast/execution-quality/intents",
            headers=auth_headers("viewer"),
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"
    assert runtime.calls == []


def test_lifecycle_api_has_no_market_rpc_or_trading_dependency() -> None:
    route_path = (
        Path(__file__).resolve().parents[2]
        / "app/api/routes_commodity_c_fast_execution_quality.py"
    )
    tree = ast.parse(route_path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.add(module)
            imports.update(f"{module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)

    forbidden_imports = {
        "app.services.commodity_simnow",
        "app.services.market_data_service",
        "app.services.tick_persistence",
        "app.services.trade_service",
        "app.services.vnpy_rpc_service",
        "psycopg",
        "questdb",
    }
    forbidden_names = {
        "cancel_order",
        "gateway",
        "position",
        "rpc_service",
        "send_order",
        "start",
        "trade_service",
    }

    assert imports.isdisjoint(forbidden_imports)
    assert names.isdisjoint(forbidden_names)
