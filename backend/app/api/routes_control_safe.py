"""Control-owned non-execution routes and explicit legacy fail-closed surface.

Calendar and user watchlists are read/configuration projections and remain
available in Control.  Paths that formerly reached RPC, TradeService,
CommoditySimNow, strategy or worker singletons are retained as explicit
``503`` responses so a stale frontend cannot mistake a disappearing route for
an accidental success.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.control_execution_projection import projection_store
from app.core.errors import AppError, ok
from app.core.security import CurrentUser, require_roles
from app.services.calendar_service import calendar_service
from app.services.watchlist_service import watchlist_service

router = APIRouter(tags=["control-safe-surface"])
AuthorizedUser = Annotated[
    CurrentUser, Depends(require_roles("viewer", "trader", "admin"))
]


def _unavailable(surface: str) -> None:
    raise AppError(
        "该旧 API surface 已从 Control 进程移除；请使用 Execution projection/typed command",
        code="CONTROL_SURFACE_UNAVAILABLE",
        status_code=503,
        detail={"surface": surface, "fail_closed": True},
    )


@router.get("/api/calendar/today")
def calendar_today(
    _: AuthorizedUser,
) -> dict:
    return ok(calendar_service.today())


@router.get("/api/calendar/day")
def calendar_day(
    date: str,
    _: AuthorizedUser,
) -> dict:
    from datetime import date as date_type

    return ok(calendar_service.get_day(date_type.fromisoformat(date)))


@router.get("/api/calendar/month")
def calendar_month(
    year: int,
    month: int,
    _: AuthorizedUser,
) -> dict:
    return ok(calendar_service.get_month(year, month))


@router.get("/api/calendar/next-trading-day")
def calendar_next_trading_day(
    date: str,
    _: AuthorizedUser,
) -> dict:
    from datetime import date as date_type

    return ok(calendar_service.next_trading_day(date_type.fromisoformat(date)))


@router.get("/api/calendar/trading-session-profiles")
def calendar_session_profiles(
    _: AuthorizedUser,
) -> dict:
    return ok(calendar_service.session_profiles())


@router.get("/api/market/watchlist")
def market_watchlist(
    user: AuthorizedUser,
) -> dict:
    return ok(watchlist_service.list_items(user.username))


@router.post("/api/market/watchlist")
def add_market_watchlist(
    payload: dict,
    user: AuthorizedUser,
) -> dict:
    required = {"vt_symbol", "symbol", "exchange", "display_name"}
    if set(payload) - required or not required.issubset(payload):
        raise AppError(
            "watchlist 请求字段非法",
            code="VALIDATION_ERROR",
            status_code=422,
            detail={"required": sorted(required)},
        )
    return ok(watchlist_service.add_contract(user.username, payload))


@router.delete("/api/market/watchlist/{watch_key:path}")
def remove_market_watchlist(
    watch_key: str,
    user: AuthorizedUser,
) -> dict:
    return ok(watchlist_service.remove_item(user.username, watch_key))


@router.get("/api/control/config")
def control_config(
    _: AuthorizedUser,
) -> dict:
    return ok(
        {
            "service": "control-api",
            "production": False,
            "live_trading_authorized": False,
            "countable_forward": False,
            "execution_boundary": "typed_private_api_only",
        }
    )


@router.get("/api/audit/receipts/{idempotency_key}")
def audit_receipt(
    idempotency_key: str,
    _: AuthorizedUser,
) -> dict:
    receipt = projection_store.get_receipt(idempotency_key)
    if receipt is None:
        _unavailable("audit.receipt")
    return ok(receipt.as_dict())


@router.api_route("/api/account", methods=["GET"])
@router.api_route("/api/positions", methods=["GET"])
@router.api_route("/api/contracts", methods=["GET"])
@router.api_route("/api/orders", methods=["GET", "POST"])
@router.api_route("/api/trades", methods=["GET"])
@router.api_route("/api/rpc/status", methods=["GET"])
@router.api_route("/api/rpc/probe", methods=["GET"])
@router.api_route("/api/gateway/status", methods=["GET"])
@router.api_route("/api/trade/config", methods=["GET"])
@router.api_route("/api/risk/status", methods=["GET"])
@router.api_route("/api/risk/rules", methods=["GET", "PATCH"])
@router.api_route("/api/risk/trade/enable", methods=["POST"])
@router.api_route("/api/risk/trade/disable", methods=["POST"])
@router.api_route("/api/risk/emergency-stop", methods=["POST"])
@router.api_route("/api/market/subscribe", methods=["POST"])
@router.api_route("/api/market/unsubscribe", methods=["POST"])
@router.api_route("/api/market/data/{path:path}", methods=["GET", "POST"])
@router.api_route("/api/orders/{path:path}", methods=["GET", "POST", "DELETE"])
@router.api_route("/api/strategies/{path:path}", methods=["GET", "POST", "PATCH"])
@router.api_route("/api/commodity-simnow/{path:path}", methods=["GET", "POST", "PATCH"])
@router.api_route("/api/commodity-c-fast/{path:path}", methods=["GET", "POST", "PATCH"])
async def removed_execution_surface(
    request: Request,
    _: AuthorizedUser,
) -> None:
    _unavailable(f"{request.method} {request.url.path}")


@router.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def unknown_control_surface(
    request: Request,
    _: AuthorizedUser,
) -> None:
    _unavailable(f"{request.method} {request.url.path}")


__all__ = ["router"]
