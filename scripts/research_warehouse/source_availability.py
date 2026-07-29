"""Calendar-authoritative HTTP absence classification."""

from __future__ import annotations

from datetime import date

from .calendar_models import OfficialCalendar
from .errors import RegistryError


def classify_http_status(
    *,
    calendar: OfficialCalendar,
    exchange: str,
    requested_day: date,
    status: int,
) -> str:
    if exchange not in calendar.exchanges:
        raise RegistryError("source exchange is outside calendar authority")
    classification = calendar.require_day(requested_day)
    if status == 200:
        if not classification.is_official:
            raise RegistryError("official data appeared on calendar-closed day")
        return "OFFICIAL_DAY_RESPONSE"
    if status == 404:
        if classification.is_official:
            raise RegistryError("official-day source is missing")
        return "AUTHORITATIVE_NON_OFFICIAL_DAY_ABSENCE"
    raise RegistryError(f"official source returned unexpected HTTP {status}")
