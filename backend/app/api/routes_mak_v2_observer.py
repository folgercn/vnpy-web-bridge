from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.schemas.mak_v2_observer import (
    MakV2DryRunSignalRequestDTO,
    MakV2ObserverDisableRequestDTO,
    MakV2ObserverEnableRequestDTO,
    MakV2SafetyAuditRequestDTO,
)
from app.services.mak_v2_testnet_observer import mak_v2_observer_service
from app.ws.events import ws_message
from app.ws.manager import ws_manager

router = APIRouter(prefix="/mak-v2/testnet-observer")


@router.get("/status")
def status(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(mak_v2_observer_service.status())


@router.get("/signals")
def signals(
    limit: int = Query(default=200, ge=1, le=1000),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(mak_v2_observer_service.list_signals(limit=limit))


@router.get("/orders")
def orders(
    limit: int = Query(default=200, ge=1, le=1000),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(mak_v2_observer_service.list_order_intents(limit=limit))


@router.get("/fills")
def fills(
    limit: int = Query(default=200, ge=1, le=1000),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(mak_v2_observer_service.list_fills(limit=limit))


@router.get("/daily-summary")
def daily_summary(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(mak_v2_observer_service.daily_summary())


@router.get("/guardrails")
def guardrails(
    limit: int = Query(default=200, ge=1, le=1000),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(mak_v2_observer_service.list_guardrails(limit=limit))


@router.post("/safety-audit")
def safety_audit(
    payload: MakV2SafetyAuditRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    result = mak_v2_observer_service.safety_audit(
        payload,
        operator=user.username,
        role=user.role,
        source_ip=request.client.host if request.client else None,
    )
    return ok(result)


@router.post("/enable")
async def enable(
    payload: MakV2ObserverEnableRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    result = mak_v2_observer_service.enable(
        payload,
        operator=user.username,
        role=user.role,
        source_ip=request.client.host if request.client else None,
    )
    await ws_manager.broadcast(ws_message("mak_v2_guardrail", {"status": result}))
    return ok(result)


@router.post("/disable")
async def disable(
    payload: MakV2ObserverDisableRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    result = mak_v2_observer_service.disable(
        payload,
        operator=user.username,
        role=user.role,
        source_ip=request.client.host if request.client else None,
    )
    await ws_manager.broadcast(ws_message("mak_v2_guardrail", {"status": result}))
    return ok(result)


@router.post("/flatten-testnet")
async def flatten_testnet(request: Request, user: CurrentUser = Depends(require_roles("admin"))) -> dict:
    result = mak_v2_observer_service.flatten_testnet(
        operator=user.username,
        role=user.role,
        source_ip=request.client.host if request.client else None,
    )
    await ws_manager.broadcast(ws_message("mak_v2_guardrail", result))
    return ok(result)


@router.post("/dry-run/signal")
async def dry_run_signal(
    payload: MakV2DryRunSignalRequestDTO,
    user: CurrentUser = Depends(require_roles("trader", "admin")),
) -> dict:
    result = mak_v2_observer_service.dry_run_signal(payload, operator=user.username, role=user.role)
    await ws_manager.broadcast(ws_message("mak_v2_signal", result["signal"]))
    if result["order_intent"]:
        await ws_manager.broadcast(ws_message("mak_v2_order_intent", result["order_intent"]))
    return ok(result)
