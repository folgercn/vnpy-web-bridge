from __future__ import annotations

import json
import sys
from copy import deepcopy
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commodity_c_fast_pure_producer_kernel as frozen
import research_warehouse.static_core_baseline as static_baseline
from research_warehouse.calendar_models import (
    CalendarDay,
    OfficialCalendar,
)
from research_warehouse.canonical import canonical_json, sha256
from research_warehouse.errors import RegistryError
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.m2_receipts import RUN_RECEIPT_SCHEMA, run_receipt_id
from research_warehouse.pit_source_view import PitSourceViewError
from research_warehouse.static_core_baseline import (
    INE_SC_LAST_DAY_RULE,
    REGISTRY_SCHEMA,
    SHFE_LAST_DAY_RULE,
    _last_trading_day,
    build_historical_baseline,
    verified_static_baseline_daily_sources,
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


def _supplemental_receipts(
    daily_raw: dict[str, dict[str, bytes]],
    *days: str,
) -> list[dict]:
    return [
        {
            "trade_day": day,
            "run_receipt_raw_sha256": "9" * 64,
            "completed_at": f"{day}T10:30:00.000000Z",
            "manifest_batch_id": f"batch-{day}-test",
            "manifest_batch_seal_sha256": "a" * 64,
            "manifest_commit_seal_sha256": "b" * 64,
            "sources": [
                {
                    "exchange": exchange,
                    "raw_sha256": sha256(daily_raw[day][exchange]),
                    "raw_bytes": len(daily_raw[day][exchange]),
                    "revision_id": f"revision-{day}-{exchange.lower()}",
                }
                for exchange in ("SHFE", "INE")
            ],
        }
        for day in days
    ]


def _build():
    calendar, history, daily_raw, _key = _inputs()
    rows = dict(calendar.days)
    current = max(rows) + timedelta(days=1)
    while current <= date(2027, 3, 20):
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
        valid_to=date(2027, 3, 20),
        issued_at=calendar.issued_at,
        exchanges=calendar.exchanges,
        days=rows,
        source_evidence=calendar.source_evidence,
        source_evidence_root=calendar.source_evidence_root,
    )
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
    assert source["products"][0]["daily"][-1]["official_day"] == "2026-06-30"
    assert len(source["products"]) == 10
    assert batch["source_month"] == "2026-06"
    assert batch["execution_lane"] == "simnow_shakedown"
    assert [row["product"] for row in batch["targets"]] == list(frozen.PRODUCTS)
    assert evidence["logical_replay_is_not_acquisition_time"] is True
    assert evidence["authority"] == false_authority()
    assert evidence["pins"]["supplemental_daily_receipts"] == []


def test_historical_baseline_uses_research_day_supplement_but_not_execution_day() -> None:
    calendar, history, daily_raw, _key = _inputs()
    rows = dict(calendar.days)
    current = max(rows) + timedelta(days=1)
    while current <= date(2027, 3, 20):
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
        valid_to=date(2027, 3, 20),
        issued_at=calendar.issued_at,
        exchanges=calendar.exchanges,
        days=rows,
        source_evidence=calendar.source_evidence,
        source_evidence_root=calendar.source_evidence_root,
    )
    history["official_days"] = history["official_days"][:-1]
    history["daily_receipts"] = history["daily_receipts"][:-1]
    research_day = "2026-07-31"
    execution_day = "2026-08-03"
    daily_raw[execution_day] = {
        exchange: raw.replace(b'"report_date":"20260731"', b'"report_date":"20260803"')
        for exchange, raw in daily_raw[research_day].items()
    }
    built = build_historical_baseline(
        calendar=calendar,
        calendar_anchor_raw_sha256="2" * 64,
        warehouse_registry_raw_sha256=history["registry_raw_sha256"],
        history_receipt=history,
        history_receipt_raw_sha256="3" * 64,
        operator_pins={"operator_state_raw_sha256": "4" * 64},
        daily_source_raw=daily_raw,
        contract_registry_raw=_contract_registry(),
        source_month="2026-07",
        signer_key_id="research-key",
        execution_lane="simnow_shakedown",
        supplemental_daily_receipts=_supplemental_receipts(
            daily_raw,
            research_day,
            execution_day,
        ),
    )

    source = json.loads(built.source_view_raw)
    evidence = json.loads(built.evidence_raw)
    assert source["research_as_of_official_day"] == research_day
    assert source["execution_day"] == execution_day
    assert source["products"][0]["daily"][-1]["official_day"] == research_day
    assert all(
        execution_day
        not in [item["official_day"] for item in product["daily"]]
        for product in source["products"]
    )
    assert (
        evidence["pins"]["supplemental_daily_receipts"][-1]["trade_day"]
        == execution_day
    )


def test_historical_baseline_rejects_missing_or_drifted_supplemental_receipt_pin() -> None:
    calendar, history, daily_raw, _key = _inputs()
    history["official_days"] = history["official_days"][:-1]
    history["daily_receipts"] = history["daily_receipts"][:-1]
    research_day = "2026-07-31"
    execution_day = "2026-08-03"
    daily_raw[execution_day] = {
        exchange: raw.replace(b'"report_date":"20260731"', b'"report_date":"20260803"')
        for exchange, raw in daily_raw[research_day].items()
    }
    kwargs = {
        "calendar": calendar,
        "calendar_anchor_raw_sha256": "2" * 64,
        "warehouse_registry_raw_sha256": history["registry_raw_sha256"],
        "history_receipt": history,
        "history_receipt_raw_sha256": "3" * 64,
        "operator_pins": {"operator_state_raw_sha256": "4" * 64},
        "daily_source_raw": daily_raw,
        "contract_registry_raw": _contract_registry(),
        "source_month": "2026-07",
        "signer_key_id": "research-key",
        "execution_lane": "simnow_shakedown",
    }
    receipts = _supplemental_receipts(daily_raw, research_day, execution_day)
    with pytest.raises(PitSourceViewError, match="supplemental receipt days mismatch"):
        build_historical_baseline(
            **kwargs,
            supplemental_daily_receipts=receipts[:-1],
        )
    receipts[-1]["sources"][0]["raw_sha256"] = "0" * 64
    with pytest.raises(PitSourceViewError, match="supplemental source bytes mismatch"):
        build_historical_baseline(
            **kwargs,
            supplemental_daily_receipts=receipts,
        )


def _normal_supplemental_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    calendar, history, daily_raw, _key = _inputs()
    history["official_days"] = history["official_days"][:-1]
    history["daily_receipts"] = history["daily_receipts"][:-1]
    research_day = "2026-07-31"
    execution_day = "2026-08-03"
    daily_raw[execution_day] = {
        exchange: raw.replace(b'"report_date":"20260731"', b'"report_date":"20260803"')
        for exchange, raw in daily_raw[research_day].items()
    }
    run_receipts = tmp_path / "run-receipts"
    run_receipts.mkdir(mode=0o700)
    chain = []
    for day in (research_day, execution_day):
        sources = []
        revisions = []
        for exchange in ("SHFE", "INE"):
            raw = daily_raw[day][exchange]
            relative = f"raw/{day}-{exchange.lower()}.json"
            raw_path = tmp_path / relative
            raw_path.parent.mkdir(mode=0o700, exist_ok=True)
            raw_path.write_bytes(raw)
            raw_path.chmod(0o600)
            source = {
                "source_id": f"{exchange.lower()}-daily-market-data-v1",
                "exchange": exchange,
                "object_id": f"object-{day}-{exchange.lower()}",
                "observation_id": f"observation-{day}-{exchange.lower()}",
                "revision_id": f"revision-{day}-{exchange.lower()}",
                "raw_sha256": sha256(raw),
                "raw_bytes": len(raw),
                "raw_relative_path": relative,
            }
            sources.append(source)
            revisions.append(
                {
                    "revision_id": source["revision_id"],
                    "raw_sha256": source["raw_sha256"],
                    "raw_bytes": source["raw_bytes"],
                    "raw_relative_path": source["raw_relative_path"],
                }
            )
        receipt = {
            "schema_version": RUN_RECEIPT_SCHEMA,
            "receipt_id": "",
            "trade_day": day,
            "completed_at": f"{day}T10:30:00.000026Z",
            "registry_raw_sha256": "1" * 64,
            "calendar_raw_sha256": calendar.raw_sha256,
            "calendar_availability_anchor_raw_sha256": "2" * 64,
            "sources": sources,
            "authority": false_authority(),
        }
        receipt["receipt_id"] = run_receipt_id(receipt)
        receipt_path = run_receipts / f"{day}.json"
        receipt_path.write_bytes(canonical_json(receipt) + b"\n")
        receipt_path.chmod(0o600)
        chain.append(
            {
                "trade_day": day,
                "batch_id": f"batch-{day}-test",
                "batch_seal_sha256": "a" * 64,
                "commit_seal_sha256": "b" * 64,
                "commit_receipt": {"ready": True},
                "revisions": revisions,
            }
        )
    context = SimpleNamespace(
        calendar=calendar,
        runtime=SimpleNamespace(run_receipts=run_receipts),
        paths=SimpleNamespace(root=tmp_path),
        registry=SimpleNamespace(),
        availability=SimpleNamespace(raw_sha256="2" * 64),
    )
    history_raw = {
        day: daily_raw[day]
        for day in history["official_days"]
    }
    monkeypatch.setattr(
        static_baseline,
        "verified_daily_raw",
        lambda **_kwargs: history_raw,
    )
    monkeypatch.setattr(
        static_baseline,
        "verify_daily_run_receipt",
        lambda *_args, **_kwargs: None,
    )
    return context, history, daily_raw, chain, research_day, execution_day


def test_static_baseline_normal_supplemental_receipts_are_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, history, _daily_raw, chain, research_day, execution_day = (
        _normal_supplemental_context(tmp_path, monkeypatch)
    )

    verified = verified_static_baseline_daily_sources(
        context=context,
        history=history,
        chain=chain,
        source_month="2026-07",
    )

    assert set(verified.daily_raw) >= {research_day, execution_day}
    assert [
        item["trade_day"] for item in verified.supplemental_daily_receipts
    ] == [research_day, execution_day]
    assert verified.supplemental_daily_receipts[-1]["completed_at"] == (
        "2026-08-03T10:30:00.000026Z"
    )


def test_static_baseline_supplemental_rejects_missing_uncommitted_and_drifted_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, history, _daily_raw, chain, _research_day, execution_day = (
        _normal_supplemental_context(tmp_path, monkeypatch)
    )
    receipt_path = context.runtime.run_receipts / f"{execution_day}.json"
    receipt_path.unlink()
    with pytest.raises(RegistryError, match="unavailable"):
        verified_static_baseline_daily_sources(
            context=context,
            history=history,
            chain=chain,
            source_month="2026-07",
        )

    context, history, _daily_raw, chain, _research_day, _execution_day = (
        _normal_supplemental_context(tmp_path / "uncommitted", monkeypatch)
    )
    chain[-1]["commit_receipt"] = None
    with pytest.raises(PitSourceViewError, match="manifest is uncommitted"):
        verified_static_baseline_daily_sources(
            context=context,
            history=history,
            chain=chain,
            source_month="2026-07",
        )

    context, history, _daily_raw, chain, _research_day, execution_day = (
        _normal_supplemental_context(tmp_path / "drift", monkeypatch)
    )
    receipt_path = context.runtime.run_receipts / f"{execution_day}.json"
    receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
    with pytest.raises(PitSourceViewError, match="raw/path binding mismatch"):
        verified_static_baseline_daily_sources(
            context=context,
            history=history,
            chain=chain,
            source_month="2026-07",
        )


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
