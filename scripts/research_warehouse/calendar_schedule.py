"""Versioned SHFE/INE official-day schedules used for calendar issuance."""

from __future__ import annotations

from datetime import date, timedelta

from .errors import RegistryError

SCHEDULE_VERSION = "shfe-ine-closure-notices-2025-2026-v1"
VALID_FROM = date(2025, 1, 1)
VALID_TO = date(2026, 12, 31)

_CLOSED_RANGES = (
    (date(2025, 1, 1), date(2025, 1, 1)),
    (date(2025, 1, 28), date(2025, 2, 4)),
    (date(2025, 4, 4), date(2025, 4, 6)),
    (date(2025, 5, 1), date(2025, 5, 5)),
    (date(2025, 5, 31), date(2025, 6, 2)),
    (date(2025, 10, 1), date(2025, 10, 8)),
    (date(2026, 1, 1), date(2026, 1, 4)),
    (date(2026, 2, 15), date(2026, 2, 23)),
    (date(2026, 4, 4), date(2026, 4, 6)),
    (date(2026, 5, 1), date(2026, 5, 5)),
    (date(2026, 6, 19), date(2026, 6, 21)),
    (date(2026, 9, 25), date(2026, 9, 27)),
    (date(2026, 10, 1), date(2026, 10, 7)),
)
_NO_NIGHT = {
    date(2024, 12, 31),
    date(2025, 1, 27),
    date(2025, 4, 3),
    date(2025, 4, 30),
    date(2025, 5, 30),
    date(2025, 9, 30),
    date(2025, 12, 31),
    date(2026, 2, 13),
    date(2026, 4, 3),
    date(2026, 4, 30),
    date(2026, 6, 18),
    date(2026, 9, 24),
    date(2026, 9, 30),
}


def _closed_days() -> set[date]:
    result: set[date] = set()
    for first, last in _CLOSED_RANGES:
        if last < first:
            raise RegistryError("official closure range is reversed")
        current = first
        while current <= last:
            result.add(current)
            current += timedelta(days=1)
    return result


def official_calendar_days() -> list[dict[str, object]]:
    """Classify every natural day and bind each trade day to its night date."""
    closed = _closed_days()
    rows: list[dict[str, object]] = []
    previous_official: date | None = None
    current = VALID_FROM
    while current <= VALID_TO:
        official = current.weekday() < 5 and current not in closed
        evening = (
            previous_official
            if official
            and previous_official is not None
            and previous_official not in _NO_NIGHT
            else None
        )
        rows.append(
            {
                "date": current.isoformat(),
                "status": "OFFICIAL_DAY" if official else "CLOSED",
                "evening_session_natural_date": (
                    evening.isoformat() if evening is not None else None
                ),
            }
        )
        if official:
            previous_official = current
        current += timedelta(days=1)
    return rows
