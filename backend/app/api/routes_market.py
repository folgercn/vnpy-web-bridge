from __future__ import annotations

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import Response

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.schemas.market import BarQueryDto, MarketDataQueryDto, SubscribeRequestDto, WatchlistCreateDto
from app.services.market_data_service import market_data_service
from app.services.tick_persistence import tick_persistence_service
from app.services.watchlist_service import watchlist_service
from app.services.vnpy_rpc_service import rpc_service
from app.stores.memory_store import memory_store

router = APIRouter()


@router.get("/contracts")
def contracts(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(rpc_service.get_contracts())


@router.get("/market/watchlist")
def watchlist(user: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(watchlist_service.list_items(user.username))


@router.post("/market/watchlist")
def add_watchlist_item(
    payload: WatchlistCreateDto,
    user: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(watchlist_service.add_contract(user.username, payload.model_dump()))


@router.delete("/market/watchlist/{watch_key:path}")
def remove_watchlist_item(watch_key: str, user: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(watchlist_service.remove_item(user.username, watch_key))


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


@router.get("/market/data/overview")
def data_overview(
    limit: int = 500,
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(market_data_service.get_overview(limit))


@router.get("/market/data/status")
def data_status(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(tick_persistence_service.snapshot())


@router.get("/market/data/ticks")
def data_ticks(
    query: MarketDataQueryDto = Depends(),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(
        market_data_service.query_ticks(
            symbol=query.symbol,
            exchange=query.exchange,
            vt_symbol=query.vt_symbol,
            start=query.start,
            end=query.end,
            limit=query.limit,
        )
    )


@router.get("/market/data/export")
def export_data(
    query: MarketDataQueryDto = Depends(),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> Response:
    rows = market_data_service.query_ticks(
        symbol=query.symbol,
        exchange=query.exchange,
        vt_symbol=query.vt_symbol,
        start=query.start,
        end=query.end,
        limit=query.limit,
    )
    content = market_data_service.export_ticks_csv(rows)
    return Response(
        content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="market_ticks.csv"'},
    )


@router.post("/market/data/import")
async def import_data(
    file: UploadFile = File(...),
    _: CurrentUser = Depends(require_roles("admin")),
) -> dict:
    content = await file.read()
    return ok(market_data_service.import_ticks_csv(content))
