
# ruff: noqa: E402

from __future__ import annotations

import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse.canonical import canonical_json, sha256
from research_warehouse.calendar_models import CalendarDay, OfficialCalendar
from research_warehouse.shfe_contract_parameters import (
    ShfeContractParameterError,
    evidence_from_pinned_raw,
    endpoint_for_day,
    evidence_from_raw,
    expiry_for_exact_contract,
    lineage_for_exact_contract,
)
from research_warehouse.static_core_baseline import SHFE_LAST_DAY_RULE, _last_trading_day


def _raw(*, instrument: str = "ru2701", expiry: str = "20270115") -> bytes:
    query = "20260819" if instrument != "br2603" else "20260312"
    return canonical_json(
        {
            "ContractBaseInfo": [
                {
                    "INSTRUMENTID": instrument,
                    "EXCHANGEID": "SHFE",
                    "COMMODITYID": instrument[:-4],
                    "TRADINGDAY": query,
                    "EXPIREDATE": expiry,
                }
            ],
            "report_date": query,
            "update_date": f"{query} 16:20:09",
        }
    )


def _evidence(raw: bytes, *, query_day: date = date(2026, 8, 19)):
    return evidence_from_raw(
        query_day=query_day,
        observed_at="2026-08-20T01:00:00.000000Z",
        raw=raw,
        expected_raw_sha256=sha256(raw),
    )


def test_current_ru2701_contract_parameter_parses_to_exchange_expiry() -> None:
    evidence = _evidence(_raw())
    assert evidence.endpoint == endpoint_for_day(date(2026, 8, 19))
    assert expiry_for_exact_contract(evidence, exact_contract="SHFE.ru2701") == date(
        2027, 1, 15
    )
    lineage = lineage_for_exact_contract(evidence, exact_contract="SHFE.ru2701")
    assert lineage["instrument_id"] == "ru2701"
    assert lineage["expire_date"] == "2027-01-15"


def test_pinned_raw_derives_its_strict_report_day() -> None:
    evidence = evidence_from_pinned_raw(
        observed_at="2026-08-21T11:52:57.000000Z",
        raw=_raw(),
        expected_raw_sha256=sha256(_raw()),
    )
    assert evidence.query_day == date(2026, 8, 19)


def test_exact_mismatch_hash_tamper_and_missing_or_invalid_expiry_fail_closed() -> None:
    raw = _raw()
    evidence = _evidence(raw)
    with pytest.raises(ShfeContractParameterError):
        expiry_for_exact_contract(evidence, exact_contract="SHFE.ru2609")
    with pytest.raises(ShfeContractParameterError):
        evidence_from_raw(
            query_day=date(2026, 8, 19),
            observed_at="2026-08-20T01:00:00.000000Z",
            raw=raw + b" ",
            expected_raw_sha256=sha256(raw),
        )
    for expiry in ("", "20271301"):
        with pytest.raises(ShfeContractParameterError):
            expiry_for_exact_contract(_evidence(_raw(expiry=expiry)), exact_contract="SHFE.ru2701")


def test_known_exchange_holiday_roll_case_matches_calendar_shfe_ldt() -> None:
    raw = _raw(instrument="br2603", expiry="20260316")
    evidence = _evidence(raw, query_day=date(2026, 3, 12))
    calendar = OfficialCalendar.create(
        calendar_id="test-shfe-br2603-calendar",
        raw_sha256="a" * 64,
        valid_from=date(2026, 3, 15),
        valid_to=date(2026, 3, 16),
        issued_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        exchanges=("SHFE", "INE"),
        days={
            date(2026, 3, 15): CalendarDay(
                day=date(2026, 3, 15),
                status="CLOSED",
                evening_session_natural_date=None,
            ),
            date(2026, 3, 16): CalendarDay(
                day=date(2026, 3, 16),
                status="OFFICIAL_DAY",
                evening_session_natural_date=None,
            ),
        },
        source_evidence=(),
        source_evidence_root=Path("/unused"),
    )
    parameter_expiry = expiry_for_exact_contract(evidence, exact_contract="SHFE.br2603")
    calendar_ldt = _last_trading_day(
        calendar,
        delivery_yyyymm=202603,
        rule=SHFE_LAST_DAY_RULE,
    )
    assert (parameter_expiry, calendar_ldt) == (date(2026, 3, 16), date(2026, 3, 16))
