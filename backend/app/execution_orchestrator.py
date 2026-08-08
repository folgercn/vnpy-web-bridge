"""Private HTTP/process entrypoint for the Phase A Execution Orchestrator."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

from .execution import (
    CommandEnvelope,
    CommandValidationError,
    DurableExecutionRepository,
    ExecutionError,
    ExecutionOrchestrator,
    ExpectedVersionConflict,
    FencingError,
    GatewayConfigurationError,
    GatewayTimeout,
    GatewayUnavailable,
    IdempotencyConflictError,
    InMemoryExecutionRepository,
    NullGateway,
    RepositoryUnavailableError,
    VnpyWindowsGateway,
)
from .execution.errors import SnapshotRejected
from .execution.readiness import GatewayReadinessProbe


def _test_mode_from_env() -> bool:
    return os.getenv("EXECUTION_TEST_MODE", "").lower() in {
        "1",
        "true",
        "yes",
    } or os.getenv("APP_ENV", "").lower() in {"test", "testing"}


def _control_secret() -> str:
    return (
        os.getenv("CONTROL_EXECUTION_SECRET", "").strip()
        or os.getenv("CONTROL_EXECUTION_SHARED_SECRET", "").strip()
    )


def _configured_principal() -> str:
    return os.getenv("CONTROL_EXECUTION_PRINCIPAL", "").strip()


def _configured_role() -> str:
    return os.getenv("CONTROL_EXECUTION_ROLE", "").strip()


def _readiness_timeout_seconds() -> float:
    raw = os.getenv("EXECUTION_READINESS_TIMEOUT_SECONDS", "1.0")
    try:
        value = float(raw)
    except ValueError as exc:
        raise GatewayConfigurationError(
            "EXECUTION_READINESS_TIMEOUT_SECONDS must be numeric"
        ) from exc
    if value <= 0 or value > 10:
        raise GatewayConfigurationError(
            "EXECUTION_READINESS_TIMEOUT_SECONDS must be within (0, 10]"
        )
    return value


def build_orchestrator() -> ExecutionOrchestrator:
    """Build a production typed gateway or an explicitly test-only fake."""

    test_mode = _test_mode_from_env()
    scope = os.getenv("EXECUTION_SCOPE", "").strip()
    if test_mode:
        scope = scope or "account:default"
    elif not scope or scope == "account:default":
        raise GatewayConfigurationError(
            "EXECUTION_SCOPE must be an explicit non-default scope outside tests"
        )
    environment = os.getenv("EXECUTION_ENVIRONMENT", "").strip()
    if test_mode:
        environment = environment or "test"
    elif not environment:
        raise GatewayConfigurationError(
            "EXECUTION_ENVIRONMENT is required outside tests"
        )
    state_path = os.getenv("EXECUTION_STATE_PATH", "").strip()
    if state_path:
        repository = DurableExecutionRepository(Path(state_path), scope=scope)
    elif test_mode:
        repository = InMemoryExecutionRepository(scope=scope)
    else:
        raise GatewayConfigurationError(
            "EXECUTION_STATE_PATH is required outside tests"
        )
    gateway = NullGateway() if test_mode else VnpyWindowsGateway.from_env()
    if not test_mode and (
        gateway.account_scope != scope or gateway.environment != environment
    ):
        raise GatewayConfigurationError(
            "Windows gateway account scope/environment must match Execution"
        )
    if not test_mode and not _control_secret():
        raise GatewayConfigurationError(
            "CONTROL_EXECUTION_SECRET is required outside tests"
        )
    if not test_mode and (not _configured_principal() or not _configured_role()):
        raise GatewayConfigurationError(
            "CONTROL_EXECUTION_PRINCIPAL and CONTROL_EXECUTION_ROLE are required outside tests"
        )
    return ExecutionOrchestrator(
        repository=repository,
        gateway=gateway,
        scope=scope,
        environment=environment,
        test_mode=test_mode,
    )


startup_error: Exception | None = None
try:
    orchestrator: ExecutionOrchestrator | None = build_orchestrator()
except (
    ExecutionError,
    ValueError,
) as exc:  # report startup failure through health, never trade
    orchestrator = None
    startup_error = exc


def create_app(service: ExecutionOrchestrator | None = None) -> Any:
    """Create the private FastAPI app; routes never expose order methods."""

    try:
        from fastapi import FastAPI, HTTPException, Request
    except ImportError as exc:  # pragma: no cover - deployment image supplies FastAPI
        raise RuntimeError(
            "FastAPI is required for the execution HTTP entrypoint"
        ) from exc
    # The module uses postponed annotations while keeping FastAPI optional at
    # import time.  Make the lazily imported Request class visible to
    # FastAPI's route annotation resolver (otherwise it is mistaken for a
    # required query parameter named ``request``).
    globals()["Request"] = Request

    instance = service or orchestrator
    app = FastAPI(title="Execution Orchestrator", docs_url=None, redoc_url=None)
    readiness_probe = (
        GatewayReadinessProbe(instance, timeout_seconds=_readiness_timeout_seconds())
        if instance is not None
        else None
    )

    def require_instance() -> ExecutionOrchestrator:
        if instance is None:
            raise HTTPException(
                status_code=503,
                detail=str(startup_error or "execution startup failed"),
            )
        return instance

    def authenticate(request: Request, envelope: CommandEnvelope | None = None) -> None:
        target = require_instance()
        expected_secret = _control_secret()
        supplied_secret = request.headers.get("X-Control-Execution-Secret", "")
        if (not target.test_mode or expected_secret) and (
            not expected_secret
            or not supplied_secret
            or not hmac.compare_digest(supplied_secret, expected_secret)
        ):
            raise HTTPException(
                status_code=401, detail="Execution control authentication failed"
            )
        if envelope is None:
            return
        actor = envelope.actor
        principal = request.headers.get("X-Control-Actor-Principal", "")
        role = request.headers.get("X-Control-Actor-Role", "")
        service_header = request.headers.get("X-Control-Service", "")
        if principal != actor.principal:
            raise HTTPException(
                status_code=403, detail="actor principal/header mismatch"
            )
        if role != actor.role:
            raise HTTPException(status_code=403, detail="actor role/header mismatch")
        if service_header != actor.service:
            raise HTTPException(status_code=403, detail="actor service/header mismatch")
        configured_principal = _configured_principal()
        configured_role = _configured_role()
        if configured_principal and actor.principal != configured_principal:
            raise HTTPException(
                status_code=403, detail="actor principal is not server-authorized"
            )
        if configured_role and actor.role != configured_role:
            raise HTTPException(
                status_code=403, detail="actor role is not server-authorized"
            )
        if actor.service != "control-api":
            raise HTTPException(
                status_code=403, detail="actor service is not server-authorized"
            )

    def assert_http_fence(
        target: ExecutionOrchestrator, envelope: CommandEnvelope
    ) -> None:
        if envelope.command not in {"start", "stop", "revoke", "drain"}:
            return
        if (
            envelope.expected.leader_epoch is None
            or envelope.expected.fencing_token is None
        ):
            raise HTTPException(
                status_code=409,
                detail="leader fence is required before execution command",
            )
        try:
            target.fencer.admission(
                leader_epoch=envelope.expected.leader_epoch,
                fencing_token=envelope.expected.fencing_token,
                token=target.fencer.token,
            )
        except ExecutionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/internal/v1/commands")
    def commands(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        try:
            envelope = CommandEnvelope.model_validate(payload)
            target = require_instance()
            authenticate(request, envelope)
            assert_http_fence(target, envelope)
            response = target.process_command(envelope)
            return dict(response)
        except (ExpectedVersionConflict, IdempotencyConflictError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (
            FencingError,
            GatewayUnavailable,
            GatewayTimeout,
            RepositoryUnavailableError,
        ) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ExecutionError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/internal/v1/status")
    def status(request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            return require_instance().status()
        except RepositoryUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/health/live")
    def health_live() -> dict[str, str]:
        return {"status": "ok", "service": "execution-orchestrator"}

    @app.get("/health/ready")
    def health_ready(request: Request) -> dict[str, Any]:
        # Readiness is intentionally protected in non-test deployments while
        # liveness remains a process-only probe.
        target = require_instance()
        authenticate(request)
        if request.headers.get("X-Control-Service", "") != "control-api":
            raise HTTPException(
                status_code=403, detail="canonical control service header required"
            )
        try:
            snapshot = readiness_probe.probe() if readiness_probe is not None else None
            projection = target.status()
        except (
            GatewayTimeout,
            GatewayUnavailable,
            SnapshotRejected,
            RepositoryUnavailableError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "not_ready",
                    "service": "execution-orchestrator",
                    "reason": str(exc),
                },
            ) from exc
        ready = (
            snapshot is not None
            and projection["lifecycle"] in {"READY", "DEGRADED", "DRAINING"}
            and projection["reconciliation"]["state"] == "RECONCILED"
        )
        body = {
            "status": "ready" if ready else "not_ready",
            "service": "execution-orchestrator",
            "lifecycle": projection["lifecycle"],
            "gateway_snapshot_id": snapshot.snapshot_id
            if snapshot is not None
            else None,
            "gateway_generation": snapshot.generation if snapshot is not None else None,
        }
        if not ready:
            raise HTTPException(status_code=503, detail=body)
        return body

    @app.get("/version")
    def version() -> dict[str, str]:
        return {
            "service": "execution-orchestrator",
            "service_version": instance.service_version if instance else "unconfigured",
        }

    @app.get("/internal/v1/receipts/{idempotency_key}")
    def receipt(idempotency_key: str, request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            value = require_instance().get_receipt(idempotency_key)
        except CommandValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if value is None:
            raise HTTPException(status_code=404, detail="receipt not found")
        return value

    @app.post("/internal/v1/leader/acquire")
    def leader_acquire(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            return require_instance().leader_acquire(str(payload.get("owner_id", "")))
        except ExecutionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/internal/v1/leader/renew")
    def leader_renew(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            return require_instance().leader_renew(payload.get("token"))
        except ExecutionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/internal/v1/leader")
    def leader_status(request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            return require_instance().leader_status()
        except RepositoryUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    # Phase C remains inside this canonical execution-orchestrator process.
    # It has a separate offline-only projection state file and never reaches
    # the Trade/Gateway surface owned by the surrounding orchestrator.
    phase_c_path = os.getenv("PHASE_C_EXECUTION_STATE_PATH", "").strip()
    if phase_c_path:
        from .phase_c.execution_service import (
            ExecutionSettings as PhaseCExecutionSettings,
        )
        from .phase_c.execution_service import (
            PhaseCExecutionService,
        )
        from .phase_c.execution_service import (
            create_app as create_phase_c_app,
        )

        phase_c_service = PhaseCExecutionService(PhaseCExecutionSettings.from_env())
        app.mount("/internal/v1/phase-c", create_phase_c_app(phase_c_service))

    return app


try:  # Keep the core importable in minimal offline tooling without FastAPI.
    app = create_app(orchestrator)
except RuntimeError:  # pragma: no cover - deployment image includes FastAPI
    app = None


def main() -> None:
    import uvicorn

    target = build_orchestrator()
    target.start()
    host = os.getenv("EXECUTION_HOST", "0.0.0.0")
    port = int(os.getenv("EXECUTION_PORT", "8090"))
    uvicorn.run(create_app(target), host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    main()
