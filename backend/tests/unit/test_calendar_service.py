from __future__ import annotations

from datetime import date, datetime, timezone

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


def test_trading_session_rejects_legal_holiday() -> None:
    now = datetime(2026, 2, 16, 2, 0, tzinfo=timezone.utc)  # 10:00 Asia/Shanghai

    assert calendar_service.is_trading_session_active(now, ["rb2610.SHFE"]) is False


def test_trading_session_uses_product_night_end() -> None:
    late_night = datetime(2026, 6, 16, 15, 30, tzinfo=timezone.utc)  # 23:30 Asia/Shanghai
    after_midnight = datetime(2026, 6, 16, 18, 0, tzinfo=timezone.utc)  # 02:00 Asia/Shanghai, Jun 17

    assert calendar_service.is_trading_session_active(late_night, ["rb2610.SHFE"]) is False
    assert calendar_service.is_trading_session_active(late_night, ["au2612.SHFE"]) is True
    assert calendar_service.is_trading_session_active(after_midnight, ["au2612.SHFE"]) is True


def test_unknown_product_has_no_default_night_session() -> None:
    night = datetime(2026, 6, 18, 13, 30, tzinfo=timezone.utc)  # 21:30 Asia/Shanghai

    assert calendar_service.is_trading_session_active(night, ["zz2609.SHFE"]) is False


def test_cffex_has_no_night_session() -> None:
    night = datetime(2026, 6, 18, 13, 30, tzinfo=timezone.utc)  # 21:30 Asia/Shanghai

    assert calendar_service.is_trading_session_active(night, ["IF2606.CFFEX"]) is False


def test_cffex_uses_profile_day_session() -> None:
    before_open = datetime(2026, 6, 18, 1, 15, tzinfo=timezone.utc)  # 09:15 Asia/Shanghai
    after_open = datetime(2026, 6, 18, 1, 45, tzinfo=timezone.utc)  # 09:45 Asia/Shanghai

    assert calendar_service.is_trading_session_active(before_open, ["IF2606.CFFEX"]) is False
    assert calendar_service.is_trading_session_active(after_open, ["IF2606.CFFEX"]) is True


def test_night_session_requires_next_calendar_day_trading() -> None:
    friday_night = datetime(2026, 6, 19, 13, 30, tzinfo=timezone.utc)  # Friday 21:30 Asia/Shanghai
    sunday_night = datetime(2026, 6, 21, 13, 30, tzinfo=timezone.utc)  # Sunday 21:30 Asia/Shanghai
    pre_holiday_night = datetime(2026, 2, 13, 13, 30, tzinfo=timezone.utc)  # Friday before Spring Festival

    assert calendar_service.is_trading_session_active(friday_night, ["au2612.SHFE"]) is False
    assert calendar_service.is_trading_session_active(sunday_night, ["au2612.SHFE"]) is True
    assert calendar_service.is_trading_session_active(pre_holiday_night, ["au2612.SHFE"]) is False


def test_trading_session_status_reports_night_trading_day() -> None:
    sunday_night = datetime(2026, 6, 21, 13, 30, tzinfo=timezone.utc)  # Sunday 21:30 Asia/Shanghai

    status = calendar_service.trading_session_status(sunday_night, ["au2612.SHFE"])

    assert status["active"] is True
    assert status["trading_day"] == "2026-06-22"
    assert status["session"] == "night"
    assert status["reason"] == "next_trading_day"
