"""Fail-closed 126+60 official-day Research history quality gate."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from .calendar_models import OfficialCalendar
from .clock_quality import TrustedClockSample, validate_observation_clock
from .commit_anchors import CommitAnchorLedger
from .daily_evidence import product_coverage_for_manifest
from .errors import RegistryError
from .filesystem import WarehousePaths
from .models import SourceRegistry
from .official_calendar import revalidate_official_calendar_evidence
from .quality_contracts import (
    DAILY_EVIDENCE_CLASS,
    REQUIRED_HISTORY_OFFICIAL_DAYS,
    TARGET_PRODUCTS,
    TREND_HISTORY_OFFICIAL_DAYS,
    VOLATILITY_LOOKBACK_OFFICIAL_DAYS,
)
from .timeutil import require_utc


def _next_official_day(calendar: OfficialCalendar, value: date) -> date:
    candidates = sorted(
        day
        for day, item in calendar.days.items()
        if item.is_official and day > value
    )
    if not candidates:
        raise RegistryError("calendar has no following official day")
    return candidates[0]


def _eligible_manifests_by_day(
    *,
    chain: list[dict[str, Any]],
    calendar: OfficialCalendar,
    ledger: CommitAnchorLedger,
    cutoff_at: datetime,
) -> dict[date, dict[str, Any]]:
    eligibility = ledger.available_at_by_batch()
    selected = {}
    for manifest in chain:
        try:
            trade_day = date.fromisoformat(manifest["trade_day"])
        except (TypeError, ValueError) as exc:
            raise RegistryError("manifest trade_day is invalid") from exc
        if trade_day.isoformat() != manifest["trade_day"]:
            raise RegistryError("manifest trade_day is not canonical")
        classification = calendar.require_day(trade_day)
        if not classification.is_official:
            raise RegistryError("signed daily manifest exists for calendar-closed day")
        if eligibility[manifest["batch_seal_sha256"]] <= cutoff_at:
            selected[trade_day] = manifest
    return selected


def require_intraday_observed_open(evidence_class: str) -> None:
    if evidence_class == DAILY_EVIDENCE_CLASS:
        raise RegistryError(
            "daily OPENPRICE is not intraday observed-open evidence"
        )
    raise RegistryError("intraday open evidence class is not trusted")


def evaluate_history_quality(
    *,
    paths: WarehousePaths,
    registry: SourceRegistry,
    chain: list[dict[str, Any]],
    ledger: CommitAnchorLedger,
    calendar: OfficialCalendar,
    as_of_official_day: date,
    execution_trade_day: date,
    cutoff_at: datetime,
    clock_sample: TrustedClockSample,
) -> dict[str, Any]:
    cutoff = require_utc(cutoff_at, "history quality PIT cutoff")
    validate_observation_clock(cutoff, sample=clock_sample)
    revalidate_official_calendar_evidence(calendar)
    ledger.require_chain(chain)
    if calendar.issued_at > cutoff or any(
        evidence.observed_at > cutoff for evidence in calendar.source_evidence
    ):
        raise RegistryError("calendar authority was not available at PIT cutoff")
    required_days = calendar.official_days_through(
        as_of_official_day,
        count=REQUIRED_HISTORY_OFFICIAL_DAYS,
    )
    if execution_trade_day != _next_official_day(calendar, as_of_official_day):
        raise RegistryError("execution day is not the next official day after as-of")
    eligible = _eligible_manifests_by_day(
        chain=chain,
        calendar=calendar,
        ledger=ledger,
        cutoff_at=cutoff,
    )
    missing_days = [day for day in required_days if day not in eligible]
    if missing_days:
        raise RegistryError(
            "official-day history is missing: "
            + ", ".join(day.isoformat() for day in missing_days)
        )
    day_results = []
    product_day_counts = {product: 0 for product in TARGET_PRODUCTS}
    for day in required_days:
        manifest = eligible[day]
        coverage = product_coverage_for_manifest(
            paths=paths,
            registry=registry,
            manifest=manifest,
            cutoff_at=cutoff,
        )
        for product in TARGET_PRODUCTS:
            product_day_counts[product] += 1
        day_results.append(
            {
                "trade_day": day.isoformat(),
                "batch_id": manifest["batch_id"],
                "batch_seal_sha256": manifest["batch_seal_sha256"],
                "products": coverage,
            }
        )
    if set(product_day_counts.values()) != {REQUIRED_HISTORY_OFFICIAL_DAYS}:
        raise RegistryError("target-product official-day coverage is incomplete")
    return {
        "status": "RESEARCH_HISTORY_QUALITY_VALID",
        "calendar_id": calendar.calendar_id,
        "calendar_raw_sha256": calendar.raw_sha256,
        "commit_anchor_ledger_sha256": ledger.raw_sha256,
        "as_of_official_day": as_of_official_day.isoformat(),
        "execution_trade_day": execution_trade_day.isoformat(),
        "cutoff_at": cutoff.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ),
        "trend_history_official_days": TREND_HISTORY_OFFICIAL_DAYS,
        "volatility_lookback_official_days": (
            VOLATILITY_LOOKBACK_OFFICIAL_DAYS
        ),
        "required_official_days": REQUIRED_HISTORY_OFFICIAL_DAYS,
        "products": list(TARGET_PRODUCTS),
        "product_day_counts": product_day_counts,
        "daily_evidence_class": DAILY_EVIDENCE_CLASS,
        "intraday_observed_open_eligible": False,
        "days": day_results,
    }
