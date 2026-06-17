from __future__ import annotations

from fastapi import APIRouter

from app.core.errors import ok
from app.services.vnpy_rpc_service import rpc_service

router = APIRouter()


@router.get("/account")
def account() -> dict:
    return ok(rpc_service.get_accounts())


@router.get("/positions")
def positions() -> dict:
    return ok(rpc_service.get_positions())
