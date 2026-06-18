from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.schemas.market import BarQueryDto, SubscribeRequestDto
from app.services.vnpy_rpc_service import rpc_service
from app.stores.memory_store import memory_store

router = APIRouter()


@router.get("/contracts")
def contracts(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(rpc_service.get_contracts())


@router.post("/market/subscribe")
def subscribe_market(payload: SubscribeRequestDto, _: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(rpc_service.subscribe_market(payload.symbol, payload.exchange))


@router.post("/market/unsubscribe")
def unsubscribe_market(payload: SubscribeRequestDto, _: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(rpc_service.unsubscribe_market(payload.symbol, payload.exchange))


@router.get("/market/tick/{vt_symbol}")
def tick_snapshot(vt_symbol: str, _: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(memory_store.get_tick(vt_symbol) or {})


@router.get("/market/bars")
def bars(
    query: BarQueryDto = Depends(),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(rpc_service.get_bars(query.symbol, query.exchange, query.interval, query.limit))
