from __future__ import annotations

from datetime import date

from app.services.calendar_service import calendar_service


def test_legal_holiday_is_not_trading_day() -> None:
    day = calendar_service.get_day(date(2026, 2, 16))

    assert day["is_legal_holiday"] is True
    assert day["holiday_name"] == "春节"
    assert day["is_trading_day"] is False


def test_adjusted_workday_on_weekend_is_not_futures_trading_day() -> None:
    day = calendar_service.get_day(date(2026, 2, 14))

    assert day["is_adjusted_workday"] is True
    assert day["is_legal_workday"] is True
    assert day["is_trading_day"] is False


def test_next_trading_day_skips_spring_festival() -> None:
    day = calendar_service.next_trading_day(date(2026, 2, 13))

    assert day["date"] == "2026-02-24"
    assert day["is_trading_day"] is True
