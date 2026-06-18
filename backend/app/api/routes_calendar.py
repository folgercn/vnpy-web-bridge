from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, Query

from app.core.errors import ok
from app.core.security import CurrentUser, require_roles
from app.services.calendar_service import calendar_service

router = APIRouter()


@router.get("/calendar/today")
def calendar_today(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(calendar_service.today())


@router.get("/calendar/day")
def calendar_day(
    target_date: date = Query(alias="date"),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(calendar_service.get_day(target_date))


@router.get("/calendar/month")
def calendar_month(
    year: int,
    month: int,
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(calendar_service.get_month(year, month))


@router.get("/calendar/next-trading-day")
def calendar_next_trading_day(
    target_date: date = Query(alias="date"),
    _: CurrentUser = Depends(require_roles("viewer", "trader", "admin")),
) -> dict:
    return ok(calendar_service.next_trading_day(target_date))


@router.get("/calendar/trading-session-profiles")
def calendar_trading_session_profiles(_: CurrentUser = Depends(require_roles("viewer", "trader", "admin"))) -> dict:
    return ok(calendar_service.session_profiles())
