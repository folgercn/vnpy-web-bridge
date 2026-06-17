from __future__ import annotations

from fastapi import APIRouter

from app.core.errors import ok
from app.schemas.market import SubscribeRequestDto
from app.services.vnpy_rpc_service import rpc_service
from app.stores.memory_store import memory_store

router = APIRouter()


@router.get("/contracts")
def contracts() -> dict:
    return ok(rpc_service.get_contracts())


@router.post("/market/subscribe")
def subscribe_market(payload: SubscribeRequestDto) -> dict:
    return ok(rpc_service.subscribe_market(payload.symbol, payload.exchange))


@router.get("/market/tick/{vt_symbol}")
def tick_snapshot(vt_symbol: str) -> dict:
    return ok(memory_store.get_tick(vt_symbol) or {})
