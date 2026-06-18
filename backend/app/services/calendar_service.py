from __future__ import annotations

import json
from calendar import monthrange
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

CHINA_TZ = timezone(timedelta(hours=8))
SESSION_PROFILE_PATH = Path(__file__).resolve().parents[3] / "shared" / "trading_session_profiles.json"


@dataclass(frozen=True)
class HolidayRange:
    name: str
    start: date
    end: date


class CalendarService:
    def __init__(self, data_path: Path | None = None, session_profile_path: Path | None = None) -> None:
        self.data_path = data_path or Path(__file__).resolve().parents[1] / "data" / "holiday_2026.json"
        self.session_profile_path = session_profile_path or SESSION_PROFILE_PATH
        self._data = self._load_data()
        self._session_profiles = self._load_session_profiles()
        self.year = int(self._data["year"])
        self.source = str(self._data["source"])
        self.holiday_ranges = [
            HolidayRange(item["name"], date.fromisoformat(item["start"]), date.fromisoformat(item["end"]))
            for item in self._data["holiday_ranges"]
        ]
        self.adjusted_workdays = {date.fromisoformat(item) for item in self._data["adjusted_workdays"]}
        self.holidays = self._expand_holidays()

    def get_day(self, target: date) -> dict[str, Any]:
        holiday_name = self.holidays.get(target)
        is_weekend = target.weekday() >= 5
        is_adjusted_workday = target in self.adjusted_workdays
        is_legal_holiday = holiday_name is not None
        is_legal_workday = is_adjusted_workday or (not is_weekend and not is_legal_holiday)
        is_trading_day = not is_weekend and not is_legal_holiday
        return {
            "date": target.isoformat(),
            "weekday": target.weekday() + 1,
            "is_weekend": is_weekend,
            "is_legal_holiday": is_legal_holiday,
            "holiday_name": holiday_name,
            "is_adjusted_workday": is_adjusted_workday,
            "is_legal_workday": is_legal_workday,
            "is_trading_day": is_trading_day,
            "source": self.source,
        }

    def get_month(self, year: int, month: int) -> dict[str, Any]:
        days = monthrange(year, month)[1]
        return {
            "year": year,
            "month": month,
            "source": self.source,
            "days": [self.get_day(date(year, month, day)) for day in range(1, days + 1)],
        }

    def is_trading_day(self, target: date) -> bool:
        return bool(self.get_day(target)["is_trading_day"])

    def is_trading_session_active(self, now: datetime, symbols: list[str] | None = None) -> bool:
        return bool(self.split_trading_session_symbols(now, symbols or [])["active"])

    def split_trading_session_symbols(self, now: datetime, symbols: list[str]) -> dict[str, list[str]]:
        active: list[str] = []
        quiet: list[str] = []
        for symbol in symbols:
            if self._is_symbol_session_active(now, symbol):
                active.append(symbol)
            else:
                quiet.append(symbol)
        return {"active": active, "quiet": quiet}

    def session_profiles(self) -> dict[str, Any]:
        return self._session_profiles

    def _is_symbol_session_active(self, now: datetime, symbol: str) -> bool:
        local = _to_china_time(now)
        product, exchange = _parse_symbol(symbol)
        current = local.time()
        if time(9, 0) <= current <= time(15, 15):
            return self.is_trading_day(local.date()) and self._in_day_session(current, exchange)
        if current >= time(21, 0):
            return self.is_trading_day(local.date() + timedelta(days=1)) and self._in_night_session(current, product, exchange)
        if current <= time(2, 30):
            return self.is_trading_day(local.date()) and self._in_night_session(current, product, exchange)
        return False

    def next_trading_day(self, target: date) -> dict[str, Any]:
        current = target + timedelta(days=1)
        for _ in range(370):
            if self.is_trading_day(current):
                return self.get_day(current)
            current += timedelta(days=1)
        raise ValueError("next trading day not found")

    def today(self) -> dict[str, Any]:
        return self.get_day(datetime.now().date())

    def _load_data(self) -> dict[str, Any]:
        return json.loads(self.data_path.read_text(encoding="utf-8"))

    def _load_session_profiles(self) -> dict[str, Any]:
        return json.loads(self.session_profile_path.read_text(encoding="utf-8"))

    def _expand_holidays(self) -> dict[date, str]:
        holidays: dict[date, str] = {}
        for item in self.holiday_ranges:
            current = item.start
            while current <= item.end:
                holidays[current] = item.name
                current += timedelta(days=1)
        return holidays

    def _in_day_session(self, current: time, exchange: str) -> bool:
        profiles = self._session_profiles["day_sessions"]
        profile_name = self._session_profiles.get("exchange_day_session", {}).get(exchange, "commodity")
        sessions = profiles.get(profile_name, profiles["commodity"])
        return any(_parse_time(item["start"]) <= current <= _parse_time(item["end"]) for item in sessions)

    def _in_night_session(self, current: time, product: str, exchange: str) -> bool:
        close_text = self._session_profiles.get("night_sessions", {}).get(exchange, {}).get(product.lower())
        if not close_text:
            return False
        end = _parse_time(close_text)
        if current >= time(21, 0):
            return end < time(21, 0) or current <= end
        return current <= end


calendar_service = CalendarService()


def _to_china_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(CHINA_TZ)


def _parse_symbol(vt_symbol: str) -> tuple[str, str]:
    symbol, _, exchange = vt_symbol.partition(".")
    product = "".join(char for char in symbol if char.isalpha()).lower()
    return product, exchange.upper()


def _parse_time(value: str) -> time:
    hour, minute = value.split(":", 1)
    return time(int(hour), int(minute))
