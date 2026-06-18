from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.errors import AppError, ok
from app.core.security import CurrentUser, require_roles
from app.schemas.monitoring import SilenceCreateDTO
from app.services.alert_service import alert_service
from app.services.audit_service import audit_service
from app.services.telegram_service import TelegramDeliveryError, telegram_service

router = APIRouter()


@router.get("/health/dependencies")
def health_dependencies(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(alert_service.summary())


@router.get("/monitor/summary")
def monitor_summary(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(alert_service.summary())


@router.get("/monitor/incidents")
def monitor_incidents(
    include_resolved: bool = True,
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(alert_service.list_incidents(include_resolved=include_resolved))


@router.post("/monitor/incidents/{incident_id}/ack")
def ack_incident(incident_id: str, user: CurrentUser = Depends(require_roles("admin"))) -> dict:
    try:
        incident = alert_service.ack(incident_id, operator=user.username)
    except KeyError as exc:
        raise AppError("告警不存在", code="INCIDENT_NOT_FOUND", status_code=404) from exc
    audit_service.record(action="monitor_incident_ack", user_id=user.username, role=user.role, request={"incident_id": incident_id})
    return ok(incident)


@router.post("/monitor/silences")
def create_silence(payload: SilenceCreateDTO, user: CurrentUser = Depends(require_roles("admin"))) -> dict:
    try:
        silence = alert_service.create_silence(
            reason=payload.reason,
            operator=user.username,
            expires_at=payload.expires_at,
            rule_id=payload.rule_id,
            scope_id=payload.scope_id,
            incident_id=payload.incident_id,
        )
    except KeyError as exc:
        raise AppError("告警不存在", code="INCIDENT_NOT_FOUND", status_code=404) from exc
    except ValueError as exc:
        raise AppError(str(exc), code="INVALID_SILENCE", status_code=400) from exc
    audit_service.record(action="monitor_silence_create", user_id=user.username, role=user.role, request=silence)
    return ok(silence)


@router.delete("/monitor/silences/{silence_id}")
def delete_silence(silence_id: str, user: CurrentUser = Depends(require_roles("admin"))) -> dict:
    try:
        silence = alert_service.delete_silence(silence_id, operator=user.username)
    except KeyError as exc:
        raise AppError("静默不存在", code="SILENCE_NOT_FOUND", status_code=404) from exc
    audit_service.record(action="monitor_silence_delete", user_id=user.username, role=user.role, request={"silence_id": silence_id})
    return ok(silence)


@router.get("/monitor/telegram/config")
def telegram_config(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(telegram_service.config_status())


@router.post("/monitor/telegram/test")
def telegram_test(request: Request, user: CurrentUser = Depends(require_roles("admin"))) -> dict:
    try:
        result = telegram_service.send_test(operator=user.username)
    except TelegramDeliveryError as exc:
        raise AppError("Telegram 发送失败", code="TELEGRAM_SEND_FAILED", status_code=502, detail={"reason": str(exc)}) from exc
    audit_service.record(
        action="monitor_telegram_test",
        user_id=user.username,
        role=user.role,
        source_ip=request.client.host if request.client else None,
        result=result,
    )
    return ok(result)
