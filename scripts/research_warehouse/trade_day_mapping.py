"""Frozen UTC to Asia/Shanghai exchange trade-day mapping."""

from __future__ import annotations

from datetime import time, timedelta
from zoneinfo import ZoneInfo

from .calendar_models import ExchangeTimestampMapping, OfficialCalendar
from .errors import RegistryError
from .timeutil import require_utc

SHANGHAI = ZoneInfo("Asia/Shanghai")
DAY_START = time(8, 30)
DAY_END = time(16, 0)
NIGHT_START = time(20, 0)
NIGHT_END = time(3, 0)
SESSIONS = {"DAY", "NIGHT"}


def map_exchange_timestamp(
    observed_at,
    *,
    exchange: str,
    session: str,
    calendar: OfficialCalendar,
) -> ExchangeTimestampMapping:
    observed = require_utc(observed_at, "exchange observation timestamp")
    if exchange not in calendar.exchanges:
        raise RegistryError("exchange is outside official calendar authority")
    if session not in SESSIONS:
        raise RegistryError("exchange session must be DAY or NIGHT")
    local = observed.astimezone(SHANGHAI)
    local_time = local.timetz().replace(tzinfo=None)
    natural_day = local.date()
    if session == "DAY":
        if not (DAY_START <= local_time <= DAY_END):
            raise RegistryError("timestamp is outside frozen day-session window")
        trade_day = natural_day
        if not calendar.require_day(trade_day).is_official:
            raise RegistryError("day-session timestamp maps to a closed day")
    elif local_time >= NIGHT_START:
        trade_day = natural_day + timedelta(days=1)
        mapped = calendar.require_day(trade_day)
        if not mapped.is_official or not mapped.previous_evening_session:
            raise RegistryError("night session is not authorized for next trade day")
    elif local_time <= NIGHT_END:
        trade_day = natural_day
        mapped = calendar.require_day(trade_day)
        if not mapped.is_official or not mapped.previous_evening_session:
            raise RegistryError("after-midnight session has no official trade day")
    else:
        raise RegistryError("timestamp is outside frozen night-session window")
    return ExchangeTimestampMapping(
        observed_at_utc=observed,
        observed_at_shanghai=local,
        exchange=exchange,
        session=session,
        trade_day=trade_day,
        calendar_raw_sha256=calendar.raw_sha256,
    )
