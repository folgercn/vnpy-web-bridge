from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.services.commodity_c_fast_shadow import commodity_c_fast_shadow_service


router = APIRouter(prefix="/commodity-simnow/c-fast-shadow")


@router.get("/status")
def status(
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(commodity_c_fast_shadow_service.status())


@router.post("/reload")
def reload(
    request: Request,
    user: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    return ok(
        commodity_c_fast_shadow_service.reload(
            operator=user.username,
            role=user.role,
            source_ip=request.client.host if request.client else None,
        )
    )
