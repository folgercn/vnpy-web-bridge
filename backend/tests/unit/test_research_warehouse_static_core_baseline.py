from __future__ import annotations

import json
import sys
from copy import deepcopy
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commodity_c_fast_pure_producer_kernel as frozen
from research_warehouse.calendar_models import (
    CalendarDay,
    OfficialCalendar,
)
from research_warehouse.canonical import canonical_json
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.pit_source_view import PitSourceViewError
from research_warehouse.static_core_baseline import (
    INE_SC_LAST_DAY_RULE,
    REGISTRY_SCHEMA,
    SHFE_LAST_DAY_RULE,
    _last_trading_day,
    build_historical_baseline,
    verify_built_baseline,
)
from test_research_warehouse_pit_source_view import _inputs


def _contract_registry() -> bytes:
    return canonical_json(
        {
            "schema_version": REGISTRY_SCHEMA,
            "registry_id": "static-core-contract-registry-test-v1",
            "generated_at": "2026-07-31T12:00:00+08:00",
            "sources": [
                {
                    "source_id": "official-contract-rules",
                    "url": "https://example.invalid/official-contract-rules",
                }
            ],
            "products": [
                {
                    "product": product,
                    "exchange": spec["exchange"],
                    "multiplier": spec["multiplier"],
                    "price_tick": spec["price_tick"],
                    "last_trading_day_rule": (
                        INE_SC_LAST_DAY_RULE
                        if product == "sc"
                        else SHFE_LAST_DAY_RULE
                    ),
                    "source_id": "official-contract-rules",
                }
                for product, spec in frozen.PRODUCT_SPECS.items()
            ],
            "authority": false_authority(),
        }
    )


def _build():
    calendar, history, daily_raw, _key = _inputs()
    rows = dict(calendar.days)
    current = max(rows) + timedelta(days=1)
    while current <= date(2026, 10, 20):
        rows[current] = CalendarDay(
            day=current,
            status="OFFICIAL_DAY" if current.weekday() < 5 else "CLOSED",
            evening_session_natural_date=None,
        )
        current += timedelta(days=1)
    calendar = OfficialCalendar.create(
        calendar_id=calendar.calendar_id,
        raw_sha256=calendar.raw_sha256,
        valid_from=calendar.valid_from,
        valid_to=date(2026, 10, 20),
        issued_at=calendar.issued_at,
        exchanges=calendar.exchanges,
        days=rows,
        source_evidence=calendar.source_evidence,
        source_evidence_root=calendar.source_evidence_root,
    )
    daily_raw = {
        day: {
            exchange: raw.replace(b"2612", b"2608")
            .replace(b"2701", b"2609")
            .replace(b"2702", b"2610")
            for exchange, raw in sources.items()
        }
        for day, sources in daily_raw.items()
    }
    return build_historical_baseline(
        calendar=calendar,
        calendar_anchor_raw_sha256="2" * 64,
        warehouse_registry_raw_sha256=history["registry_raw_sha256"],
        history_receipt=history,
        history_receipt_raw_sha256="3" * 64,
        operator_pins={
            "operator_state_raw_sha256": "4" * 64,
            "manifest_genesis_seal_sha256": "5" * 64,
            "manifest_head_seal_sha256": "6" * 64,
            "manifest_head_commit_seal_sha256": "7" * 64,
            "commit_anchor_ledger_raw_sha256": "8" * 64,
        },
        daily_source_raw=daily_raw,
        contract_registry_raw=_contract_registry(),
        source_month="2026-06",
        signer_key_id="research-key",
        execution_lane="simnow_shakedown",
    )


def test_historical_baseline_is_deterministic_and_freshly_replays() -> None:
    first = _build()
    second = _build()

    assert first == second
    verify_built_baseline(first)
    source = json.loads(first.source_view_raw)
    batch = json.loads(first.unsigned_batch_raw)
    evidence = json.loads(first.evidence_raw)
    assert source["research_as_of_official_day"] == "2026-06-30"
    assert source["execution_day"] == "2026-07-01"
    assert len(source["products"]) == 10
    assert batch["source_month"] == "2026-06"
    assert batch["execution_lane"] == "simnow_shakedown"
    assert [row["product"] for row in batch["targets"]] == list(frozen.PRODUCTS)
    assert evidence["logical_replay_is_not_acquisition_time"] is True
    assert evidence["authority"] == false_authority()


def test_historical_baseline_rejects_registry_drift_and_tamper() -> None:
    registry = json.loads(_contract_registry())
    registry["products"][0]["multiplier"] += 1
    calendar, history, daily_raw, _key = _inputs()
    with pytest.raises(PitSourceViewError, match="conflicts with freeze"):
        build_historical_baseline(
            calendar=calendar,
            calendar_anchor_raw_sha256="2" * 64,
            warehouse_registry_raw_sha256=history["registry_raw_sha256"],
            history_receipt=history,
            history_receipt_raw_sha256="3" * 64,
            operator_pins={"operator_state_raw_sha256": "4" * 64},
            daily_source_raw=daily_raw,
            contract_registry_raw=canonical_json(registry),
            source_month="2026-06",
            signer_key_id="research-key",
            execution_lane="simnow_shakedown",
        )

    built = _build()
    tampered = type(built)(
        source_view_raw=built.source_view_raw,
        artifacts=built.artifacts,
        unsigned_batch_raw=built.unsigned_batch_raw.replace(b"20000000", b"20000001"),
        evidence_raw=built.evidence_raw,
    )
    with pytest.raises(PitSourceViewError, match="evidence binding mismatch"):
        verify_built_baseline(tampered)


def test_full_ohlc_parser_skips_inactive_rows_but_keeps_true_main() -> None:
    _calendar, _history, daily_raw, _key = _inputs()
    payload = json.loads(daily_raw["2026-06-30"]["SHFE"])
    inactive = next(
        row
        for row in payload["o_curinstrument"]
        if row["PRODUCTID"] == "ag_f" and row["DELIVERYMONTH"] == "2702"
    )
    additional = deepcopy(inactive)
    additional["DELIVERYMONTH"] = "2703"
    additional["OPENINTEREST"] = "100"
    payload["o_curinstrument"].append(additional)
    inactive["OPENPRICE"] = ""
    inactive["HIGHESTPRICE"] = ""
    inactive["LOWESTPRICE"] = ""
    from research_warehouse.pit_source_view import contract_rows_from_daily_raw

    rows = contract_rows_from_daily_raw(
        raw=canonical_json(payload),
        exchange="SHFE",
        official_day="2026-06-30",
        include_ohlc=True,
    )
    assert len(rows["ag"]) == 3
    assert all(set(row) >= {"open", "high", "low"} for row in rows["ag"])


def test_last_trading_day_does_not_cross_rule_month() -> None:
    calendar, _history, _daily_raw, _key = _inputs()

    with pytest.raises(PitSourceViewError, match="cannot resolve"):
        _last_trading_day(
            calendar,
            delivery_yyyymm=202610,
            rule=SHFE_LAST_DAY_RULE,
        )
    with pytest.raises(PitSourceViewError, match="cannot resolve"):
        _last_trading_day(
            calendar,
            delivery_yyyymm=202610,
            rule=INE_SC_LAST_DAY_RULE,
        )
