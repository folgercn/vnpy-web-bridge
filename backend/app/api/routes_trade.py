from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.schemas.trade import CancelAllRequestDTO, CancelRequestDTO, OrderRequestDTO
from app.services.trade_service import trade_service
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


@router.post("/orders")
def create_order(
    payload: OrderRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("trader", "admin")),
) -> dict:
    return ok(
        trade_service.send_order(
            payload,
            source_ip=request.client.host if request.client else None,
            operator=user.username,
        )
    )


@router.post("/orders/cancel-all")
def cancel_all_orders(
    payload: CancelAllRequestDTO,
    request: Request,
    user: CurrentUser = Depends(require_roles("trader", "admin")),
) -> dict:
    return ok(
        trade_service.cancel_all(
            payload,
            source_ip=request.client.host if request.client else None,
            operator=user.username,
        )
    )


@router.post("/orders/{vt_orderid}/cancel")
def cancel_order(
    vt_orderid: str,
    request: Request,
    payload: CancelRequestDTO | None = None,
    user: CurrentUser = Depends(require_roles("trader", "admin")),
) -> dict:
    source_ip = request.client.host if request.client else None
    return ok(trade_service.cancel_order(vt_orderid, payload, source_ip=source_ip, operator=user.username))
