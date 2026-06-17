from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.services.vnpy_rpc_service import rpc_service

router = APIRouter()


@router.get("/account")
def account(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(rpc_service.get_accounts())


@router.get("/positions")
def positions(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(rpc_service.get_positions())
