"""Typed authoritative calendar and exchange-time mapping models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from types import MappingProxyType

from .errors import RegistryError


@dataclass(frozen=True)
class CalendarDay:
    day: date
    status: str
    evening_session_natural_date: date | None

    @property
    def is_official(self) -> bool:
        return self.status == "OFFICIAL_DAY"


@dataclass(frozen=True)
class CalendarSourceEvidence:
    exchange: str
    owner: str
    source_url: str
    source_type: str
    observed_at: datetime
    raw_sha256: str
    raw_bytes: int
    raw_relative_path: str


@dataclass(frozen=True)
class OfficialCalendar:
    calendar_id: str
    raw_sha256: str
    valid_from: date
    valid_to: date
    issued_at: datetime
    exchanges: tuple[str, ...]
    days: Mapping[date, CalendarDay]
    source_evidence: tuple[CalendarSourceEvidence, ...]
    source_evidence_root: Path

    @classmethod
    def create(
        cls,
        *,
        calendar_id: str,
        raw_sha256: str,
        valid_from: date,
        valid_to: date,
        issued_at: datetime,
        exchanges: tuple[str, ...],
        days: dict[date, CalendarDay],
        source_evidence: tuple[CalendarSourceEvidence, ...],
        source_evidence_root: Path,
    ) -> OfficialCalendar:
        return cls(
            calendar_id=calendar_id,
            raw_sha256=raw_sha256,
            valid_from=valid_from,
            valid_to=valid_to,
            issued_at=issued_at,
            exchanges=exchanges,
            days=MappingProxyType(dict(days)),
            source_evidence=source_evidence,
            source_evidence_root=source_evidence_root,
        )

    def require_day(self, value: date) -> CalendarDay:
        try:
            return self.days[value]
        except KeyError as exc:
            raise RegistryError(
                f"calendar has no authoritative classification for {value}"
            ) from exc

    def official_days_through(
        self,
        value: date,
        *,
        count: int,
    ) -> tuple[date, ...]:
        if count < 1:
            raise RegistryError("official-day count must be positive")
        self.require_day(value)
        eligible = sorted(
            day for day, item in self.days.items() if item.is_official and day <= value
        )
        if value not in eligible:
            raise RegistryError("as-of day is not an authoritative official day")
        if len(eligible) < count:
            raise RegistryError("calendar has insufficient official-day history")
        return tuple(eligible[-count:])


@dataclass(frozen=True)
class ExchangeTimestampMapping:
    observed_at_utc: datetime
    observed_at_shanghai: datetime
    exchange: str
    session: str
    trade_day: date
    calendar_raw_sha256: str
