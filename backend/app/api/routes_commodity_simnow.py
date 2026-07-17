from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.schemas.commodity_simnow import (
    CommodityPlanExecuteRequestDTO,
    CommodityPlanReconcileRequestDTO,
    CommoditySimNowDisableRequestDTO,
    CommoditySimNowEnableRequestDTO,
    CommodityTargetPreviewRequestDTO,
)
from app.services.commodity_simnow import commodity_simnow_service


router = APIRouter(prefix="/commodity-simnow")


@router.get("/status")
def status(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(commodity_simnow_service.status())


@router.get("/plan")
def plan(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(commodity_simnow_service.plan())


@router.get("/events")
def events(
    limit: int = Query(default=200, ge=1, le=1000),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(commodity_simnow_service.list_events(limit))


@router.post("/enable")
def enable(
    payload: CommoditySimNowEnableRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.enable(
            payload,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/disable")
def disable(
    payload: CommoditySimNowDisableRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.disable(
            payload,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/preview")
def preview(
    payload: CommodityTargetPreviewRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.preview(
            payload.batch,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/execute")
def execute(
    payload: CommodityPlanExecuteRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.execute(
            payload,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/reconcile")
def reconcile(
    payload: CommodityPlanReconcileRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.reconcile(
            payload.plan_hash,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/auto-advance")
def auto_advance(
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.auto_advance(
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )
