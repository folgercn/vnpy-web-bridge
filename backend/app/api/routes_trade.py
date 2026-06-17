from __future__ import annotations

from fastapi import APIRouter

from app.core.errors import ok
from app.services.vnpy_rpc_service import rpc_service
from app.stores.memory_store import memory_store

router = APIRouter()


@router.get("/orders")
def orders() -> dict:
    orders_data = rpc_service.get_orders()
    return ok(orders_data if orders_data else memory_store.orders())


@router.get("/trades")
def trades() -> dict:
    trades_data = rpc_service.get_trades()
    return ok(trades_data if trades_data else memory_store.trades())
