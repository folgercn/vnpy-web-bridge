from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.schemas.commodity_simnow import (
    CommodityCFastContinuousEnableRequestDTO,
    CommodityCFastShakedownPreviewRequestDTO,
    CommodityCFastShakedownStartRequestDTO,
    CommodityCFastShakedownStopRequestDTO,
    CommodityPlanExecuteRequestDTO,
    CommodityPlanReconcileRequestDTO,
    CommodityPositionManagerShakedownPreviewRequestDTO,
    CommodityPositionManagerShakedownStartRequestDTO,
    CommodityPositionManagerShakedownStopRequestDTO,
    CommoditySimNowDisableRequestDTO,
    CommoditySimNowEnableRequestDTO,
    CommodityTargetPreviewRequestDTO,
    CommodityTemplateStartRequestDTO,
)
from app.services.commodity_simnow import commodity_simnow_service

router = APIRouter(prefix="/commodity-simnow")


@router.get("/status")
def status(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(commodity_simnow_service.status())


@router.get("/plan")
def plan(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(commodity_simnow_service.plan())


@router.get("/position-manager-shadow")
def position_manager_shadow(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(commodity_simnow_service.position_manager_shadow())


@router.get("/position-manager-shakedown/status")
def position_manager_shakedown_status(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(commodity_simnow_service.position_manager_shakedown_status())


@router.get("/c-fast-shakedown/status")
def c_fast_shakedown_status(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(commodity_simnow_service.c_fast_shakedown_status())


@router.get("/c-fast-shakedown/events")
def c_fast_shakedown_events(
    limit: int = Query(default=200, ge=1, le=1000),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(commodity_simnow_service.c_fast_shakedown_events(limit))


@router.get("/c-fast-shakedown/sessions")
def c_fast_shakedown_sessions(
    limit: int = Query(default=100, ge=1, le=1000),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(commodity_simnow_service.c_fast_shakedown_history(limit))


@router.get("/c-fast-shakedown/pnl")
def c_fast_shakedown_pnl(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(commodity_simnow_service.c_fast_shakedown_pnl())


@router.post("/c-fast-shakedown/preview")
def c_fast_shakedown_preview(
    payload: CommodityCFastShakedownPreviewRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.preview_c_fast_shakedown(
            payload.selected_products,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/c-fast-shakedown/start")
def c_fast_shakedown_start(
    payload: CommodityCFastShakedownStartRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.start_c_fast_shakedown(
            payload.plan_hash,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/c-fast-shakedown/stop")
def c_fast_shakedown_stop(
    payload: CommodityCFastShakedownStopRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.stop_c_fast_shakedown(
            payload.reason,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/c-fast-shakedown/continuous/enable")
def c_fast_continuous_enable(
    payload: CommodityCFastContinuousEnableRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.enable_c_fast_continuous(
            payload,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/c-fast-shakedown/reconcile")
def c_fast_shakedown_reconcile(
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


@router.post("/position-manager-shakedown/preview")
def position_manager_shakedown_preview(
    payload: CommodityPositionManagerShakedownPreviewRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.preview_position_manager_shakedown(
            payload.selected_products,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/position-manager-shakedown/start")
def position_manager_shakedown_start(
    payload: CommodityPositionManagerShakedownStartRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.start_position_manager_shakedown(
            payload.plan_hash,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/position-manager-shakedown/stop")
def position_manager_shakedown_stop(
    payload: CommodityPositionManagerShakedownStopRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.stop_position_manager_shakedown(
            payload.reason,
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


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


@router.post("/template/start")
def start_template(
    payload: CommodityTemplateStartRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_simnow_service.start_template(
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
