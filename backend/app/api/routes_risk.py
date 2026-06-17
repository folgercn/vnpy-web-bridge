from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.schemas.risk import EmergencyStopRequestDTO, RiskRulesPatchDTO
from app.schemas.trade import CancelAllRequestDTO
from app.services.audit_service import audit_service
from app.services.risk_service import risk_service
from app.services.trade_service import trade_service
from app.ws.events import ws_message
from app.ws.manager import ws_manager

router = APIRouter()


@router.get("/risk/status")
def risk_status() -> dict:
    return ok(risk_service.status())


@router.get("/risk/rules")
def risk_rules(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(risk_service.get_rules())


@router.patch("/risk/rules")
async def update_risk_rules(
    payload: RiskRulesPatchDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    result = risk_service.update_rules(payload)
    audit_service.record(
        action="risk_rules_update",
        user_id=user.username,
        role=user.role,
        request=payload.model_dump(exclude_none=True),
        result=result,
        source_ip=request.client.host if request.client else None,
    )
    await ws_manager.broadcast(ws_message("risk_alert", {"action": "rules_update", "status": risk_service.status()}))
    return ok(result)


@router.post("/risk/trade/enable")
async def enable_trade(request: Request, user: CurrentUser = Depends(require_roles("admin"))) -> dict:
    result = risk_service.enable_trade()
    audit_service.record(
        action="trade_enable",
        user_id=user.username,
        role=user.role,
        result=result,
        source_ip=request.client.host if request.client else None,
    )
    await ws_manager.broadcast(ws_message("risk_alert", {"action": "trade_enable", "status": result}))
    return ok(result)


@router.post("/risk/trade/disable")
async def disable_trade(request: Request, user: CurrentUser = Depends(require_roles("admin"))) -> dict:
    result = risk_service.disable_trade()
    audit_service.record(
        action="trade_disable",
        user_id=user.username,
        role=user.role,
        result=result,
        source_ip=request.client.host if request.client else None,
    )
    await ws_manager.broadcast(ws_message("risk_alert", {"action": "trade_disable", "status": result}))
    return ok(result)


@router.post("/risk/emergency-stop")
async def emergency_stop(
    payload: EmergencyStopRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    status = risk_service.emergency_stop()
    cancel_result = None
    if payload.cancel_all:
        previous = risk_service.web_trade_enabled
        risk_service.web_trade_enabled = True
        try:
            cancel_result = trade_service.cancel_all(
                CancelAllRequestDTO(),
                source_ip=request.client.host if request.client else None,
                operator=user.username,
            )
        finally:
            risk_service.web_trade_enabled = previous
            risk_service.emergency_stop()

    result = {"status": status, "cancel_all": cancel_result}
    audit_service.record(
        action="emergency_stop",
        user_id=user.username,
        role=user.role,
        request=payload.model_dump(),
        result=result,
        source_ip=request.client.host if request.client else None,
    )
    await ws_manager.broadcast(ws_message("risk_alert", {"action": "emergency_stop", "status": risk_service.status()}))
    return ok(result)
