from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.schemas.strategy import StrategySettingDTO
from app.services.strategy_service import strategy_service

router = APIRouter()


@router.get("/strategies")
def list_strategies(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(strategy_service.list_strategies())


@router.get("/strategies/{strategy_name}")
def get_strategy(strategy_name: str, _: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(strategy_service.get_strategy(strategy_name))


@router.get("/strategies/{strategy_name}/setting")
def get_strategy_setting(strategy_name: str, _: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(strategy_service.get_setting(strategy_name))


@router.patch("/strategies/{strategy_name}/setting")
async def update_strategy_setting(
    strategy_name: str,
    payload: StrategySettingDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        await strategy_service.update_setting(
            strategy_name,
            payload,
            user_id=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.get("/strategies/{strategy_name}/variables")
def get_strategy_variables(strategy_name: str, _: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(strategy_service.get_variables(strategy_name))


@router.post("/strategies/{strategy_name}/init")
async def init_strategy(
    strategy_name: str,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        await strategy_service.init_strategy(
            strategy_name,
            user_id=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/strategies/{strategy_name}/start")
async def start_strategy(
    strategy_name: str,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        await strategy_service.start_strategy(
            strategy_name,
            user_id=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.post("/strategies/{strategy_name}/stop")
async def stop_strategy(
    strategy_name: str,
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        await strategy_service.stop_strategy(
            strategy_name,
            user_id=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )


@router.get("/strategies/{strategy_name}/logs")
def get_strategy_logs(strategy_name: str, _: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(strategy_service.get_logs(strategy_name))
