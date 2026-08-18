"""Private HTTP/process entrypoint for the Phase A Execution Orchestrator."""

from __future__ import annotations

import hmac
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
from urllib.request import Request as UrlRequest

from shared.commodity_execution import TRUSTED_KEYLESS_SIMNOW_SCOPE

from .execution import (
    CommandEnvelope,
    CommandValidationError,
    DurableExecutionRepository,
    DurableTargetPlanRepository,
    ExecutionError,
    ExecutionOrchestrator,
    ExpectedVersionConflict,
    FencingError,
    FinalExecutionRuntime,
    GatewayConfigurationError,
    GatewayTimeout,
    GatewayUnavailable,
    IdempotencyConflictError,
    InMemoryExecutionRepository,
    NullGateway,
    PlanRejected,
    RepositoryUnavailableError,
    VnpyWindowsGateway,
)
from .execution.errors import SnapshotRejected
from .execution.final_runtime import CustodyReadClient
from .execution.models import validate_identifier
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


def _final_runtime_required() -> bool:
    return os.getenv("FINAL_EXECUTION_RUNTIME_REQUIRED", "").lower() in {
        "1",
        "true",
        "yes",
    }


def _trusted_keyless_simnow_enabled() -> bool:
    return os.getenv("SIMNOW_EXECUTION_ENABLED", "").lower() in {"1", "true", "yes"}


def _false_env(name: str) -> bool:
    return os.getenv(name, "").strip().lower() not in {"1", "true", "yes"}


class _HttpCustodyReadClient(CustodyReadClient):
    """Narrow read-only custody client used only by final Execution.

    The endpoint contract is intentionally explicit: receipt lookup, immutable
    artifact lookup, and a health probe.  No signing, publishing, lifecycle or
    broker capability is available on this client.
    """

    def __init__(self, *, base_url: str, secret: str) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not secret
        ):
            raise GatewayConfigurationError(
                "final custody read configuration is invalid"
            )
        self.base_url = base_url.rstrip("/")
        self.secret = secret
        self._opener = build_opener(_NoRedirect())

    def _request(
        self, path: str, *, missing_is_none: bool = False
    ) -> dict[str, Any] | None:
        request = UrlRequest(
            f"{self.base_url}{path}",
            headers={
                "X-Phase-C-Principal": "execution-orchestrator",
                "X-Phase-C-Custody-Secret": self.secret,
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=3.0) as response:
                if response.status != 200:
                    raise GatewayUnavailable("custody read returned non-200 status")
                raw = response.read(1024 * 1024 + 1)
        except HTTPError as exc:
            if missing_is_none and exc.code == 404:
                return None
            raise GatewayUnavailable("custody read was rejected") from exc
        except (URLError, OSError, TimeoutError) as exc:
            raise GatewayUnavailable("custody read outcome is unknown") from exc
        if len(raw) > 1024 * 1024:
            raise GatewayUnavailable("custody response is too large")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayUnavailable("custody response is invalid JSON") from exc
        if not isinstance(value, dict):
            raise GatewayUnavailable("custody response is not an object")
        return value

    def receipt(self, receipt_id: str) -> dict[str, Any] | None:
        return self._request(
            f"/internal/v1/receipts/{validate_identifier(receipt_id, 'receipt_id')}",
            missing_is_none=True,
        )

    def artifact(self, artifact_id: str) -> dict[str, Any] | None:
        return self._request(
            f"/internal/v1/artifacts/{validate_identifier(artifact_id, 'artifact_id')}",
            missing_is_none=True,
        )

    def probe(self) -> None:
        self._request("/health/live")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


def build_execution_service() -> ExecutionOrchestrator | FinalExecutionRuntime:
    """Build raw Execution normally, or a fail-closed final SIMNOW runtime."""

    core = build_orchestrator()
    if not _final_runtime_required():
        return core
    if core.environment.upper() != "SIMNOW":
        raise GatewayConfigurationError(
            "FINAL_EXECUTION_RUNTIME_REQUIRED requires EXECUTION_ENVIRONMENT=SIMNOW"
        )
    root = os.getenv("EXECUTION_TARGET_PLAN_ROOT", "").strip()
    custody_url = os.getenv("EXECUTION_CUSTODY_URL", "").strip()
    custody_secret = os.getenv("EXECUTION_CUSTODY_SECRET", "").strip()
    scope_raw = os.getenv("EXECUTION_ALLOWED_SCOPE_JSON", "").strip()
    if not root or not custody_url or not custody_secret or not scope_raw:
        raise GatewayConfigurationError(
            "final Execution requires target-plan root, custody URL/secret and allowed scope"
        )
    try:
        allowed_scope = json.loads(scope_raw)
    except json.JSONDecodeError as exc:
        raise GatewayConfigurationError(
            "EXECUTION_ALLOWED_SCOPE_JSON must be JSON"
        ) from exc
    if not isinstance(allowed_scope, Mapping):
        raise GatewayConfigurationError(
            "EXECUTION_ALLOWED_SCOPE_JSON must be an object"
        )
    try:
        max_order_volume = int(os.getenv("EXECUTION_SIMNOW_MAX_ORDER_VOLUME", "1"))
    except ValueError as exc:
        raise GatewayConfigurationError(
            "EXECUTION_SIMNOW_MAX_ORDER_VOLUME must be an integer"
        ) from exc
    keyless_enabled = _trusted_keyless_simnow_enabled()
    if keyless_enabled and (
        core.scope != "account:windows"
        or os.getenv("SIMNOW_ACCOUNT_SCOPE", "").strip() != "account:windows"
        or os.getenv("SIMNOW_GATEWAY", "").strip() != "CTP"
        or dict(allowed_scope) != TRUSTED_KEYLESS_SIMNOW_SCOPE
        or not _false_env("SIMNOW_PRODUCTION")
        or not _false_env("SIMNOW_LIVE_TRADING_AUTHORIZED")
        or not _false_env("SIMNOW_COUNTABLE_FORWARD")
    ):
        raise GatewayConfigurationError(
            "trusted keyless SIMNOW configuration is not the fixed safe tuple"
        )
    return FinalExecutionRuntime(
        core,
        plans=DurableTargetPlanRepository(Path(root)),
        custody=_HttpCustodyReadClient(base_url=custody_url, secret=custody_secret),
        allowed_scope=allowed_scope,
        allow_simnow_execution=os.getenv("EXECUTION_ALLOW_SIMNOW_EXECUTION", "").lower()
        in {"1", "true", "yes"},
        allow_trusted_keyless_simnow=keyless_enabled,
        max_order_volume=max_order_volume,
    )


startup_error: Exception | None = None
try:
    execution_service: ExecutionOrchestrator | FinalExecutionRuntime | None = (
        build_execution_service()
    )
    orchestrator: ExecutionOrchestrator | None = (
        execution_service.orchestrator
        if isinstance(execution_service, FinalExecutionRuntime)
        else execution_service
    )
except (
    ExecutionError,
    ValueError,
) as exc:  # report startup failure through health, never trade
    orchestrator = None
    execution_service = None
    startup_error = exc


def create_app(
    service: ExecutionOrchestrator | FinalExecutionRuntime | None = None,
) -> Any:
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

    instance = service or execution_service
    core = (
        instance.orchestrator
        if isinstance(instance, FinalExecutionRuntime)
        else instance
    )
    app = FastAPI(title="Execution Orchestrator", docs_url=None, redoc_url=None)
    readiness_probe = (
        GatewayReadinessProbe(core, timeout_seconds=_readiness_timeout_seconds())
        if core is not None
        else None
    )

    def require_instance() -> ExecutionOrchestrator | FinalExecutionRuntime:
        if instance is None:
            raise HTTPException(
                status_code=503,
                detail=str(startup_error or "execution startup failed"),
            )
        return instance

    def require_core() -> ExecutionOrchestrator:
        if core is None:
            raise HTTPException(
                status_code=503,
                detail=str(startup_error or "execution startup failed"),
            )
        return core

    def authenticate(request: Request, envelope: CommandEnvelope | None = None) -> None:
        target = require_core()
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
            authenticate(request, envelope)
            assert_http_fence(require_core(), envelope)
            response = require_instance().process_command(envelope)
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
            return require_core().status()
        except RepositoryUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/internal/v1/completions/latest")
    def latest_completion(request: Request) -> dict[str, Any] | None:
        authenticate(request)
        target = require_instance()
        if not isinstance(target, FinalExecutionRuntime):
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_COMPLETION_RUNTIME_UNAVAILABLE",
                    "message": "completion projection requires final Execution runtime",
                },
            )
        try:
            return target.latest_completion_projection()
        except PlanRejected as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_COMPLETION_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except RepositoryUnavailableError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_COMPLETION_REPOSITORY_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc

    @app.get("/internal/v1/completions/{plan_id}")
    def completion(plan_id: str, request: Request) -> dict[str, Any] | None:
        authenticate(request)
        try:
            validate_identifier(plan_id, "plan_id")
        except CommandValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "EXECUTION_COMPLETION_PLAN_ID_INVALID",
                    "message": str(exc),
                },
            ) from exc
        target = require_instance()
        if not isinstance(target, FinalExecutionRuntime):
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_COMPLETION_RUNTIME_UNAVAILABLE",
                    "message": "completion projection requires final Execution runtime",
                },
            )
        try:
            return target.completion_projection(plan_id=plan_id)
        except PlanRejected as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_COMPLETION_INVALID",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc
        except RepositoryUnavailableError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_COMPLETION_REPOSITORY_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc

    @app.get("/health/live")
    def health_live() -> dict[str, str]:
        return {"status": "ok", "service": "execution-orchestrator"}

    @app.get("/health/ready")
    def health_ready(request: Request) -> dict[str, Any]:
        # Readiness is intentionally protected in non-test deployments while
        # liveness remains a process-only probe.
        target = require_core()
        authenticate(request)
        if request.headers.get("X-Control-Service", "") != "control-api":
            raise HTTPException(
                status_code=403, detail="canonical control service header required"
            )
        try:
            snapshot = readiness_probe.probe() if readiness_probe is not None else None
            if isinstance(instance, FinalExecutionRuntime):
                instance.readiness()
            projection = target.status()
        except (
            GatewayTimeout,
            GatewayUnavailable,
            SnapshotRejected,
            RepositoryUnavailableError,
            ExecutionError,
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
            "service_version": core.service_version if core else "unconfigured",
        }

    @app.get("/internal/v1/receipts/{idempotency_key}")
    def receipt(idempotency_key: str, request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            value = require_core().get_receipt(idempotency_key)
        except CommandValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if value is None:
            raise HTTPException(status_code=404, detail="receipt not found")
        return value

    @app.post("/internal/v1/leader/acquire")
    def leader_acquire(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            if set(payload) != {"owner_id"} or not isinstance(
                payload.get("owner_id"), str
            ):
                raise FencingError("leader acquire payload fields are not exact")
            return require_core().leader_acquire(payload["owner_id"])
        except RepositoryUnavailableError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_LEADER_REPOSITORY_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc
        except ExecutionError as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "EXECUTION_LEADER_ACQUIRE_REJECTED",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc

    @app.post("/internal/v1/leader/renew")
    def leader_renew(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            if set(payload) != {"token"}:
                raise FencingError("leader renew payload fields are not exact")
            return require_core().leader_renew(payload["token"])
        except RepositoryUnavailableError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_LEADER_REPOSITORY_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc
        except ExecutionError as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "EXECUTION_LEADER_RENEW_REJECTED",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc

    @app.post("/internal/v1/leader/release")
    def leader_release(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            if set(payload) != {"token"}:
                raise FencingError("leader release payload fields are not exact")
            return require_core().leader_release(payload.get("token"))
        except RepositoryUnavailableError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_LEADER_REPOSITORY_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc
        except ExecutionError as exc:
            # Release is deliberately fail-closed rather than replay-idempotent:
            # after the exact lease is gone, the same token is stale and cannot
            # affect a later leader that may already hold a higher fence.
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "EXECUTION_LEADER_RELEASE_REJECTED",
                    "message": str(exc),
                    "retryable": False,
                },
            ) from exc

    @app.get("/internal/v1/leader")
    def leader_status(request: Request) -> dict[str, Any]:
        authenticate(request)
        try:
            return require_core().leader_status()
        except RepositoryUnavailableError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "EXECUTION_LEADER_REPOSITORY_UNAVAILABLE",
                    "message": str(exc),
                    "retryable": True,
                },
            ) from exc

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
    app = create_app(execution_service)
except RuntimeError:  # pragma: no cover - deployment image includes FastAPI
    app = None


def main() -> None:
    import uvicorn

    target = build_execution_service()
    core = target.orchestrator if isinstance(target, FinalExecutionRuntime) else target
    core.start()
    host = os.getenv("EXECUTION_HOST", "0.0.0.0")
    port = int(os.getenv("EXECUTION_PORT", "8090"))
    uvicorn.run(create_app(target), host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    main()
