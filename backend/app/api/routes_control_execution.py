"""Control API routes for the typed Execution boundary.

This router intentionally contains no legacy RPC, account, order, strategy,
tick, monitoring, Commodity or signing imports.  Browser mutations are always
complete command envelopes and are forwarded through ``ExecutionClient``.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import JSONResponse

from app.control_execution_client import (
    ExecutionClient,
    ExecutionClientError,
    execution_client,
)
from app.control_execution_projection import ReceiptProjectionError, projection_store
from app.control_ws_ticket import WebSocketTicketError, websocket_ticket_store
from app.core.errors import AppError, PermissionDeniedError, ok
from app.core.security import CurrentUser, get_current_user, require_roles
from app.execution.errors import CommandValidationError, UnknownCommandError
from app.execution.models import CommandEnvelope
from app.schemas.control_execution import ExecutionStatusProjection

router = APIRouter(tags=["control-execution"])

AuthorizedUser = Annotated[
    CurrentUser, Depends(require_roles("viewer", "trader", "admin"))
]
AuthenticatedUser = Annotated[CurrentUser, Depends(get_current_user)]
CommandBody = Annotated[Any, Body()]
CorrelationId = Annotated[str | None, Header(alias="X-Correlation-ID")]

_VERSION = os.getenv("CONTROL_API_VERSION", "phase-a-dev")
_READ_COMMANDS = {"status", "overview"}
_TRADER_COMMANDS = {"preview"}
_ADMIN_COMMANDS = {
    "enable",
    "revoke",
    "start",
    "stop",
    "reconcile",
    "drain",
    "safe_to_restart",
}


def _client_error(exc: ExecutionClientError) -> AppError:
    detail = exc.detail if isinstance(exc.detail, dict) else {"detail": exc.detail}
    return AppError(
        exc.message, code=exc.code, status_code=exc.status_code, detail=detail
    )


def _validate_envelope(body: Any) -> CommandEnvelope:
    try:
        return CommandEnvelope.model_validate(body)
    except (CommandValidationError, UnknownCommandError, ValueError, TypeError) as exc:
        raise AppError(
            "Control→Execution command 不符合冻结 schema",
            code="COMMAND_SCHEMA_INVALID",
            status_code=422,
            detail={"error": str(exc)},
        ) from exc


def _enforce_actor(user: CurrentUser, envelope: CommandEnvelope) -> None:
    actor = envelope.actor
    # The envelope is caller supplied, but the authenticated principal is the
    # authority for the web request.  A mismatched actor cannot be relayed.
    if actor.operator != user.username or actor.role != user.role:
        raise PermissionDeniedError(
            "命令 actor 与当前登录主体不一致",
            detail={"operator": user.username, "role": user.role},
        )
    if envelope.command in _READ_COMMANDS:
        return
    if envelope.command in _TRADER_COMMANDS and user.role in {"trader", "admin"}:
        return
    if envelope.command in _ADMIN_COMMANDS and user.role == "admin":
        return
    raise PermissionDeniedError(
        "当前角色无权执行该 Control 命令",
        detail={"command": envelope.command, "role": user.role},
    )


async def _status_projection(client: ExecutionClient) -> ExecutionStatusProjection:
    try:
        projection = await client.status()
    except ExecutionClientError as exc:
        raise _client_error(exc) from exc
    projection_store.record_status(projection)
    return projection


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _control_database_probe() -> dict[str, Any]:
    """Probe the Control role without making readiness depend on Execution state."""

    database_url = os.getenv("DATABASE_URL", "").strip()
    runtime = os.getenv("APP_ENV", "development").strip().lower()
    if not database_url:
        if runtime in {"test", "development", "local"}:
            return {"status": "skipped", "reason": "DATABASE_URL not configured"}
        return {"status": "unavailable", "reason": "DATABASE_URL not configured"}

    def _probe() -> dict[str, Any]:
        try:
            import psycopg

            with (
                psycopg.connect(database_url, connect_timeout=2) as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute("SELECT 1")
                cursor.fetchone()
            return {"status": "ready"}
        except Exception as exc:  # noqa: BLE001 - readiness must fail closed on any driver error
            return {"status": "unavailable", "error": exc.__class__.__name__}

    return await asyncio.to_thread(_probe)


@router.get("/health/live", include_in_schema=False)
async def health_live() -> dict[str, Any]:
    return {"status": "live", "service": "control-api", "version": _VERSION}


@router.get("/health/ready", include_in_schema=False, response_model=None)
async def health_ready() -> JSONResponse | dict[str, Any]:
    try:
        execution_ready = await execution_client.ready()
        execution_projection = await execution_client.status()
    except ExecutionClientError as exc:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "service": "control-api",
                "version": _VERSION,
                "dependencies": {"execution-orchestrator": "unavailable"},
                "error": {"code": exc.code, "message": exc.message},
            },
        )
    database = await _control_database_probe()
    if database.get("status") == "unavailable":
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "service": "control-api",
                "version": _VERSION,
                "dependencies": {
                    "postgres": database,
                    "execution-orchestrator": {"status": "reachable"},
                },
            },
        )
    reconciliation = execution_projection.value["reconciliation"]
    business_ready = bool(
        execution_projection.lifecycle in {"READY", "DEGRADED", "DRAINING"}
        and reconciliation["state"] == "RECONCILED"
        and reconciliation["unknown_outcomes"] == 0
    )
    content = {
        "status": "ready",
        "service": "control-api",
        "version": _VERSION,
        "business_ready": business_ready,
        "dependencies": {
            "postgres": database,
            "execution-orchestrator": {
                "status": "reachable",
                "ready": execution_ready,
                "lifecycle": execution_projection.lifecycle,
                "business_ready": business_ready,
            },
        },
    }
    if not business_ready:
        content["status"] = "not_ready"
        return JSONResponse(status_code=503, content=content)
    return content


@router.get("/version", include_in_schema=False)
async def version() -> dict[str, Any]:
    return {"service": "control-api", "version": _VERSION}


@router.get("/api/status")
async def api_status() -> dict[str, Any]:
    """Public Control metadata; execution details live under ``/api/execution``."""

    latest = projection_store.latest_status()
    return ok(
        {
            "service": "control-api",
            "status": "ok",
            "version": _VERSION,
            "execution_projection": latest.lifecycle if latest else "unavailable",
            "phase_b_workers": "unavailable",
            "mutation_boundary": "execution-orchestrator-only",
        }
    )


@router.get("/api/health/live")
async def api_health_live() -> dict[str, Any]:
    return ok(await health_live())


@router.get("/api/health/ready", response_model=None)
async def api_health_ready() -> JSONResponse | dict[str, Any]:
    result = await health_ready()
    if isinstance(result, JSONResponse):
        return result
    return ok(result)


@router.get("/api/execution/status")
@router.get("/api/control/execution/status")
async def execution_status(
    _: AuthorizedUser,
) -> dict[str, Any]:
    projection = await _status_projection(execution_client)
    return ok(projection.model_dump(mode="json"))


@router.get("/api/execution/overview")
@router.get("/api/control/execution/overview")
async def execution_overview(
    _: AuthorizedUser,
) -> dict[str, Any]:
    projection = await _status_projection(execution_client)
    return ok(projection.model_dump(mode="json"))


@router.get("/api/execution/receipts/{idempotency_key}")
@router.get("/api/control/execution/receipts/{idempotency_key}")
async def execution_receipt(
    idempotency_key: str,
    _: AuthorizedUser,
) -> dict[str, Any]:
    receipt = projection_store.get_receipt(idempotency_key)
    if receipt is None:
        raise AppError(
            "Control durable receipt projection 不存在；拒绝返回未绑定的 Execution receipt",
            code="RECEIPT_PROJECTION_NOT_FOUND",
            status_code=409,
            detail={"idempotency_key": idempotency_key, "fail_closed": True},
        )
    if receipt.status == "UNKNOWN":
        try:
            durable = await execution_client.receipt(idempotency_key)
        except ExecutionClientError as exc:
            if getattr(exc, "status_code", 502) == 404:
                # Absence immediately after a timeout is not proof that the
                # command was never accepted.  Preserve UNKNOWN and never turn
                # it into a replayable/not-found outcome.
                return ok(receipt.as_dict())
            raise _client_error(exc) from exc
        try:
            receipt = projection_store.resolve_receipt(receipt, durable)
        except ReceiptProjectionError as exc:
            raise AppError(
                "Execution receipt 与 Control durable binding 不一致",
                code="RECEIPT_BINDING_INVALID",
                status_code=502,
                detail={"idempotency_key": idempotency_key, "fail_closed": True},
            ) from exc
    return ok(receipt.as_dict())


@router.post("/api/ws/ticket")
async def issue_ws_ticket(
    request: Request,
    user: AuthenticatedUser,
) -> dict[str, Any]:
    ticket, claim = websocket_ticket_store.issue(
        principal=user.username,
        role=user.role,
    )
    from app.services.audit_service import audit_service

    audit_service.record(
        action="websocket_ticket_issue",
        result={"expires_at": claim.expires_at.isoformat()},
        operator=user.username,
        user_id=user.username,
        role=user.role,
        source_ip=_source_ip(request),
    )
    return ok(
        {
            "ticket": ticket,
            "expires_at": claim.expires_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "ttl_seconds": websocket_ticket_store.ttl_seconds,
        }
    )


@router.post("/api/execution/commands")
@router.post("/api/control/execution/commands")
@router.post("/api/control/commands")
async def execution_command(
    request: Request,
    body: CommandBody,
    user: AuthenticatedUser,
    x_correlation_id: CorrelationId = None,
) -> dict[str, Any]:
    del x_correlation_id  # correlation_id is part of the strict command envelope
    envelope = _validate_envelope(body)
    _enforce_actor(user, envelope)
    try:
        response = await execution_client.submit(envelope)
    except ExecutionClientError as exc:
        # A timeout is deliberately surfaced as unknown; this route never
        # creates a second command or retries with a new idempotency key.
        observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        receipt = projection_store.record_unknown(
            envelope,
            error_code=exc.code,
            observed_at=observed_at,
        )
        from app.services.audit_service import audit_service

        audit_service.record(
            action=f"execution_command_{envelope.command}",
            request=envelope.model_dump(mode="json"),
            result=receipt.as_dict(),
            error_code=exc.code,
            error_message=exc.message,
            operator=user.username,
            user_id=user.username,
            role=user.role,
            source_ip=_source_ip(request),
        )
        raise _client_error(exc) from exc
    try:
        receipt = projection_store.record_response(envelope, response)
    except ReceiptProjectionError as exc:
        raise AppError(
            "Execution receipt 与提交命令不匹配",
            code="RECEIPT_BINDING_INVALID",
            status_code=502,
            detail={"idempotency_key": envelope.idempotency_key, "fail_closed": True},
        ) from exc
    from app.services.audit_service import audit_service

    audit_service.record(
        action=f"execution_command_{envelope.command}",
        request=envelope.model_dump(mode="json"),
        result=receipt.as_dict(),
        operator=user.username,
        user_id=user.username,
        role=user.role,
        source_ip=_source_ip(request),
    )
    return ok(receipt.as_dict())


@router.websocket("/ws/events")
async def control_events(websocket: WebSocket) -> None:
    """Read-only Control event channel; no tick/monitor worker is started."""

    ticket = websocket.query_params.get("ticket")
    try:
        # A bearer token in the URL is never accepted.  Nginx access logs only
        # record ``$uri`` (not the query string), but tickets are still
        # one-time and short-lived to bound accidental disclosure.
        if websocket.query_params.get("token") or not ticket:
            raise WebSocketTicketError("missing one-time WebSocket ticket")
        websocket_ticket_store.consume(ticket)
    except WebSocketTicketError:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        try:
            projection = await _status_projection(execution_client)
            await websocket.send_json(
                {"type": "execution_status", "data": projection.model_dump(mode="json")}
            )
        except AppError as exc:
            await websocket.send_json(
                {
                    "type": "execution_status",
                    "data": {"status": "unavailable", "error": exc.code},
                }
            )
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        return


__all__ = ["router"]
