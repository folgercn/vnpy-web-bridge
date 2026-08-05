from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import httpx
import pytest
from app.control_api import app
from app.core.security import CurrentUser, create_access_token
from app.execution.models import CommandEnvelope
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]


def _hash(char: str = "a") -> str:
    return char * 64


def _headers(username: str = "admin", role: str = "admin") -> dict[str, str]:
    return {
        "Authorization": f"Bearer {create_access_token(CurrentUser(username, role))}"
    }


def _command(
    command: str = "overview", *, user: str = "admin", role: str = "admin"
) -> dict:
    return {
        "schema_version": "web_bridge_control_execution_command_v1",
        "command_id": "cmd-291-test-0001",
        "idempotency_key": "idem-291-test-command-0001",
        "correlation_id": "corr-291-test-command-0001",
        "issued_at": "2026-08-05T00:00:00Z",
        "actor": {
            "service": "control-api",
            "principal": "control-api-test",
            "operator": user,
            "role": role,
        },
        "command": command,
        "expected": {"state_version": 0},
        "payload": {},
    }


class FakeExecutionClient:
    def __init__(self) -> None:
        self.commands: list[CommandEnvelope] = []
        self.ready_calls = 0
        self.status_calls = 0

    async def submit(self, command):
        envelope = (
            command
            if isinstance(command, CommandEnvelope)
            else CommandEnvelope.model_validate(command)
        )
        self.commands.append(envelope)
        result = {"accepted": True}
        return {
            "receipt": {
                "service": "control-api",
                "idempotency_key": envelope.idempotency_key,
                "command_hash": envelope.command_hash(),
                "command_id": envelope.command_id,
                "correlation_id": envelope.correlation_id,
                "actor": envelope.actor.as_dict(),
                "status": "COMPLETED",
                "state_version": 1,
                "result": result,
                "observed_at": "2026-08-05T00:00:01Z",
            },
            "result": result,
            "reused": False,
        }

    async def status(self):
        from app.schemas.control_execution import ExecutionStatusProjection

        self.status_calls += 1
        return ExecutionStatusProjection.model_validate(
            {
                "schema_version": "web_bridge_execution_status_v1",
                "service": "execution-orchestrator",
                "service_version": "phase-a-test",
                "observed_at": "2026-08-05T00:00:00Z",
                "lifecycle": "HALTED_RECONCILE_REQUIRED",
                "state_version": 0,
                "leader": {
                    "scope": "account:test",
                    "owner_id": "execution-test-00",
                    "held": False,
                    "epoch": 0,
                    "fencing_token": 0,
                    "lease_expires_at": "1970-01-01T00:00:00Z",
                },
                "authority": {
                    "state": "DISABLED",
                    "artifact_id": "authority-test",
                    "artifact_hash": _hash(),
                    "expires_at": "1970-01-01T00:00:00Z",
                },
                "plan": {
                    "state": "IDLE",
                    "plan_id": "plan-test-00",
                    "plan_hash": _hash("b"),
                    "version": 0,
                },
                "send_intents": [],
                "reconciliation": {
                    "state": "REQUIRED",
                    "run_id": "reconcile-test",
                    "last_completed_at": "1970-01-01T00:00:00Z",
                    "unknown_outcomes": 0,
                    "fresh_snapshot_id": "snapshot-test",
                },
                "safe_to_restart": False,
                "broker": {
                    "connected": False,
                    "generation": 0,
                    "active_order_count": 0,
                    "position_snapshot_hash": _hash("c"),
                    "last_snapshot_at": "1970-01-01T00:00:00Z",
                },
            }
        )

    async def probe(self, path=None):
        return {"status": "ready", "service": "execution-orchestrator"}

    async def ready(self):
        self.ready_calls += 1
        return {"status": "ready", "service": "execution-orchestrator"}


def test_control_source_has_no_legacy_execution_imports() -> None:
    forbidden = {
        "vnpy_rpc_service",
        "trade_service",
        "commodity_simnow",
        "manual_execution_permit",
        "strategy_service",
        "tick_persistence",
        "monitoring_service",
        "commodity_c_fast",
    }
    for relative in (
        "backend/app/control_api.py",
        "backend/app/control_execution_client.py",
        "backend/app/control_execution_projection.py",
        "backend/app/api/routes_control_execution.py",
        "backend/app/api/routes_control_safe.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports |= {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        assert not any(any(part in item for part in forbidden) for item in imports), (
            relative
        )


def test_main_is_only_a_control_entrypoint() -> None:
    source = (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
    assert "app.control_api" in source
    assert "@app.on_event" not in source
    assert "frontend/dist" not in source


def test_auth_routes_keep_the_frontend_api_prefix() -> None:
    paths = {route.path for route in app.routes if hasattr(route, "path")}
    assert "/api/auth/login" in paths
    assert "/api/auth/me" in paths
    assert "/auth/login" not in paths


def test_safe_control_surface_is_present_and_legacy_surface_is_explicit() -> None:
    paths = {route.path for route in app.routes if hasattr(route, "path")}
    assert "/api/calendar/today" in paths
    assert "/api/market/watchlist" in paths
    assert "/api/control/config" in paths
    assert "/api/audit/receipts/{idempotency_key}" in paths
    assert "/api/rpc/status" in paths
    assert "/api/orders" in paths


def test_control_route_forwards_typed_command_and_projects_receipt(monkeypatch) -> None:
    from app.api import routes_control_execution

    fake = FakeExecutionClient()
    monkeypatch.setattr(routes_control_execution, "execution_client", fake)
    with TestClient(app) as client:
        response = client.post(
            "/api/control/execution/commands",
            headers=_headers(),
            json=_command(),
        )
        assert response.status_code == 200
        assert response.json()["data"]["status"] == "COMPLETED"
        assert response.json()["data"]["expected"] == {"state_version": 0}
        assert [item.command for item in fake.commands] == ["overview"]


def test_control_rejects_unknown_envelope_fields_before_execution(monkeypatch) -> None:
    from app.api import routes_control_execution

    fake = FakeExecutionClient()
    monkeypatch.setattr(routes_control_execution, "execution_client", fake)
    payload = _command()
    payload["unknown"] = True
    with TestClient(app) as client:
        response = client.post(
            "/api/execution/commands", headers=_headers(), json=payload
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "COMMAND_SCHEMA_INVALID"
    assert fake.commands == []


def test_control_exposes_status_projection_and_fail_closed_legacy_surface(
    monkeypatch,
) -> None:
    from app.api import routes_control_execution

    monkeypatch.setattr(
        routes_control_execution, "execution_client", FakeExecutionClient()
    )
    with TestClient(app) as client:
        status = client.get(
            "/api/execution/status", headers=_headers("viewer", "viewer")
        )
        legacy = client.get("/api/rpc/status", headers=_headers("viewer", "viewer"))
    assert status.status_code == 200
    assert status.json()["data"]["service"] == "execution-orchestrator"
    assert legacy.status_code == 503
    assert legacy.json()["error"]["code"] == "CONTROL_SURFACE_UNAVAILABLE"


def test_health_and_version_are_independent_process_endpoints(monkeypatch) -> None:
    from app.api import routes_control_execution

    monkeypatch.setattr(
        routes_control_execution, "execution_client", FakeExecutionClient()
    )
    with TestClient(app) as client:
        assert client.get("/health/live").json()["service"] == "control-api"
        readiness = client.get("/health/ready")
        assert readiness.status_code == 503
        assert readiness.json()["status"] == "not_ready"
        assert readiness.json()["business_ready"] is False
        assert client.get("/version").json()["service"] == "control-api"
        assert client.get("/some/deep/link").status_code == 404


def test_gateway_down_execution_readiness_cannot_be_masked_by_stale_ready_status(
    monkeypatch,
) -> None:
    from app.api import routes_control_execution
    from app.control_execution_client import ExecutionRejectedError

    class GatewayDownClient(FakeExecutionClient):
        async def ready(self):
            self.ready_calls += 1
            raise ExecutionRejectedError(
                "Execution 服务错误",
                status_code=503,
                detail={"status": "not_ready", "reason": "gateway unavailable"},
            )

        async def status(self):
            # This stale snapshot must never be consulted after ready fails.
            projection = await super().status()
            value = projection.model_dump(mode="json")
            value["lifecycle"] = "READY"
            value["reconciliation"]["state"] = "RECONCILED"
            return type(projection).model_validate(value)

    fake = GatewayDownClient()
    monkeypatch.setattr(routes_control_execution, "execution_client", fake)

    with TestClient(app) as client:
        readiness = client.get("/health/ready")

    assert readiness.status_code == 503
    assert readiness.json()["status"] == "not_ready"
    assert readiness.json()["dependencies"]["execution-orchestrator"] == "unavailable"
    assert fake.ready_calls == 1
    assert fake.status_calls == 0
    edge = (ROOT / "frontend/nginx.conf").read_text(encoding="utf-8")
    assert "proxy_pass http://control_api/health/ready;" in edge
    assert "proxy_intercept_errors off;" in edge


def test_auth_audit_uses_explicit_writable_path(monkeypatch, tmp_path) -> None:
    from app.services.audit_service import AuditService

    path = tmp_path / "control-audit.log"
    monkeypatch.setenv("CONTROL_AUDIT_LOG_PATH", str(path))
    service = AuditService()
    service.record(action="phase_a_test", operator="tester")
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8"))["action"] == "phase_a_test"


def test_non_test_runtime_rejects_default_jwt_and_empty_users(monkeypatch) -> None:
    from app.control_api import _require_runtime_auth_configuration

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("AUTH_USERS_JSON", raising=False)
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        _require_runtime_auth_configuration()

    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 64)
    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", "y" * 64)
    with pytest.raises(RuntimeError, match="AUTH_USERS_JSON"):
        _require_runtime_auth_configuration()


def test_private_execution_client_sends_secret_and_bound_actor() -> None:
    from app.control_execution_client import ExecutionClient, ExecutionClientSettings

    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["secret"] = request.headers.get("X-Control-Execution-Secret", "")
        seen["principal"] = request.headers.get("X-Control-Actor-Principal", "")
        seen["role"] = request.headers.get("X-Control-Actor-Role", "")
        envelope = CommandEnvelope.model_validate(json.loads(request.read().decode()))
        result = {"accepted": True}
        return httpx.Response(
            200,
            json={
                "receipt": {
                    "service": "control-api",
                    "idempotency_key": envelope.idempotency_key,
                    "command_hash": envelope.command_hash(),
                    "command_id": envelope.command_id,
                    "correlation_id": envelope.correlation_id,
                    "actor": envelope.actor.as_dict(),
                    "status": "COMPLETED",
                    "state_version": 1,
                    "result": result,
                    "observed_at": "2026-08-05T00:00:01Z",
                },
                "result": result,
                "reused": False,
            },
        )

    client = ExecutionClient(
        ExecutionClientSettings(
            base_url="http://execution",
            timeout_seconds=1,
            shared_secret="s" * 32,
        ),
        transport=httpx.MockTransport(handler),
    )
    asyncio.run(client.submit(_command("overview")))
    assert seen == {
        "secret": "s" * 32,
        "principal": "control-api-test",
        "role": "admin",
    }


def test_execution_readiness_uses_canonical_authenticated_headers() -> None:
    from app.control_execution_client import ExecutionClient, ExecutionClientSettings

    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["secret"] = request.headers.get("X-Control-Execution-Secret", "")
        seen["service"] = request.headers.get("X-Control-Service", "")
        return httpx.Response(
            200,
            json={
                "status": "ready",
                "service": "execution-orchestrator",
                "lifecycle": "READY",
                "gateway_snapshot_id": "snapshot-test",
                "gateway_generation": 1,
            },
        )

    client = ExecutionClient(
        ExecutionClientSettings(
            base_url="http://execution",
            timeout_seconds=1,
            shared_secret="s" * 32,
        ),
        transport=httpx.MockTransport(handler),
    )
    result = asyncio.run(client.ready())

    assert result["status"] == "ready"
    assert seen == {
        "path": "/health/ready",
        "secret": "s" * 32,
        "service": "control-api",
    }


def test_execution_client_marks_5xx_command_as_unknown_and_queryable() -> None:
    from app.control_execution_client import (
        ExecutionClient,
        ExecutionClientSettings,
        ExecutionUnknownOutcomeError,
    )

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"detail": "gateway unavailable"})

    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution", shared_secret="s" * 32),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ExecutionUnknownOutcomeError) as error:
        asyncio.run(client.submit(_command("overview")))
    assert error.value.code == "EXECUTION_UNKNOWN_OUTCOME"
    assert error.value.detail["query_same_intent_only"] is True
    assert "idem-291-test-command-0001" in error.value.detail["query_receipt_path"]


def test_execution_http_requires_secret_and_server_bound_actor(monkeypatch) -> None:
    from app.execution.gateway import InMemoryGateway
    from app.execution.orchestrator import ExecutionOrchestrator
    from app.execution.repository import InMemoryExecutionRepository
    from app.execution_orchestrator import create_app

    monkeypatch.setenv("CONTROL_EXECUTION_SHARED_SECRET", "s" * 32)
    monkeypatch.setenv("CONTROL_EXECUTION_PRINCIPAL", "control-api-test")
    monkeypatch.setenv("CONTROL_EXECUTION_ROLE", "admin")
    target = ExecutionOrchestrator(
        repository=InMemoryExecutionRepository(scope="account:http-test"),
        gateway=InMemoryGateway(),
        scope="account:http-test",
        environment="test",
        test_mode=True,
    )
    http_app = create_app(target)
    headers = {
        "X-Control-Execution-Secret": "s" * 32,
        "X-Control-Service": "control-api",
        "X-Control-Actor-Principal": "control-api-test",
        "X-Control-Actor-Role": "admin",
    }
    payload = _command()
    payload["expected"]["state_version"] = 1
    with TestClient(http_app) as client:
        status = client.get("/internal/v1/status", headers=headers)
        command = client.post("/internal/v1/commands", headers=headers, json=payload)
        receipt = client.get(
            "/internal/v1/receipts/idem-291-test-command-0001", headers=headers
        )
        forged = dict(payload)
        forged["actor"] = dict(payload["actor"])
        forged["actor"]["principal"] = "forged-principal"
        forged_response = client.post(
            "/internal/v1/commands", headers=headers, json=forged
        )

    assert status.status_code == 200
    assert command.status_code == 200
    assert receipt.status_code == 200
    assert receipt.json()["idempotency_key"] == "idem-291-test-command-0001"
    assert forged_response.status_code == 403


def test_websocket_ticket_is_one_time_and_bound() -> None:
    from app.control_ws_ticket import OneTimeWebSocketTicketStore, WebSocketTicketError

    store = OneTimeWebSocketTicketStore(ttl_seconds=10)
    ticket, claim = store.issue(principal="alice", role="viewer")
    assert claim.principal == "alice"
    assert store.consume(ticket).role == "viewer"
    with pytest.raises(WebSocketTicketError):
        store.consume(ticket)


def test_control_receipt_projection_restores_strict_unknown_and_terminal(
    tmp_path,
) -> None:
    from app.control_execution_projection import ControlProjectionStore

    path = tmp_path / "receipt-projection.jsonl"
    envelope = CommandEnvelope.model_validate(_command("overview"))
    store = ControlProjectionStore(path)
    pending = store.record_unknown(
        envelope,
        error_code="EXECUTION_UNKNOWN_OUTCOME",
        observed_at="2026-08-05T00:00:01Z",
    )
    restored = ControlProjectionStore(path)
    assert restored.get_receipt(envelope.idempotency_key) == pending

    response = asyncio.run(FakeExecutionClient().submit(envelope))
    resolved = restored.resolve_receipt(pending, response["receipt"])
    assert resolved.status == "COMPLETED"
    assert resolved.command_hash == envelope.command_hash()
    assert resolved.actor == envelope.actor.as_dict()
    assert resolved.expected == envelope.expected.as_dict()
    assert (
        ControlProjectionStore(path).get_receipt(envelope.idempotency_key) == resolved
    )


def test_control_receipt_projection_corruption_fails_closed(tmp_path) -> None:
    from app.control_execution_projection import ControlProjectionStore

    path = tmp_path / "receipt-projection.jsonl"
    path.write_text('{"kind":"receipt","value":{}}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="journal is corrupt"):
        ControlProjectionStore(path)


def test_execution_client_rejects_unbound_receipt_response() -> None:
    from app.control_execution_client import (
        ExecutionClient,
        ExecutionClientSettings,
        ExecutionProtocolError,
    )

    client = ExecutionClient(
        ExecutionClientSettings(base_url="http://execution", shared_secret="s" * 32),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "receipt": {"status": "COMPLETED"},
                    "result": {},
                    "reused": False,
                },
            )
        ),
    )
    with pytest.raises(ExecutionProtocolError, match="receipt"):
        asyncio.run(client.submit(_command("overview")))


def test_timeout_is_durably_audited_unknown_then_resolved_by_same_key(
    monkeypatch, tmp_path
) -> None:
    from app.api import routes_control_execution
    from app.control_execution_client import ExecutionTimeoutError
    from app.control_execution_projection import ControlProjectionStore
    from app.services.audit_service import audit_service

    envelope = CommandEnvelope.model_validate(_command("overview"))
    terminal = asyncio.run(FakeExecutionClient().submit(envelope))["receipt"]

    class TimeoutThenReceiptClient(FakeExecutionClient):
        def __init__(self) -> None:
            super().__init__()
            self.queried: list[str] = []

        async def submit(self, command):
            raise ExecutionTimeoutError(
                "timeout",
                detail={
                    "idempotency_key": envelope.idempotency_key,
                    "query_same_intent_only": True,
                },
            )

        async def receipt(self, idempotency_key: str):
            self.queried.append(idempotency_key)
            return terminal

    fake = TimeoutThenReceiptClient()
    store = ControlProjectionStore(tmp_path / "receipts.jsonl")
    monkeypatch.setattr(routes_control_execution, "execution_client", fake)
    monkeypatch.setattr(routes_control_execution, "projection_store", store)
    monkeypatch.setattr(audit_service, "log_path", tmp_path / "audit.jsonl")

    with TestClient(app) as client:
        submitted = client.post(
            "/api/execution/commands", headers=_headers(), json=_command("overview")
        )
        pending = store.get_receipt(envelope.idempotency_key)
        resolved = client.get(
            f"/api/execution/receipts/{envelope.idempotency_key}",
            headers=_headers(),
        )

    assert submitted.status_code == 504
    assert pending is not None and pending.status == "UNKNOWN"
    assert pending.result_state_version is None
    assert fake.queried == [envelope.idempotency_key]
    assert resolved.status_code == 200
    assert resolved.json()["data"]["status"] == "COMPLETED"
    audit = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert audit["error_code"] == "EXECUTION_UNKNOWN_OUTCOME"
    assert audit["result"]["status"] == "UNKNOWN"
