from __future__ import annotations

import json
from calendar import monthrange
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class HolidayRange:
    name: str
    start: date
    end: date


class CalendarService:
    def __init__(self, data_path: Path | None = None) -> None:
        self.data_path = data_path or Path(__file__).resolve().parents[1] / "data" / "holiday_2026.json"
        self._data = self._load_data()
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

    def _expand_holidays(self) -> dict[date, str]:
        holidays: dict[date, str] = {}
        for item in self.holiday_ranges:
            current = item.start
            while current <= item.end:
                holidays[current] = item.name
                current += timedelta(days=1)
        return holidays


calendar_service = CalendarService()
