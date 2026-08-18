# ruff: noqa: E402

from __future__ import annotations

import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import FormatChecker, ValidationError
from jsonschema import validate as validate_json_schema

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

import commodity_c_fast_pure_producer_kernel as frozen
import research_warehouse.daily_pit_main_roll_source as daily_roll
from research_warehouse.calendar_models import CalendarDay, OfficialCalendar
from research_warehouse.canonical import canonical_json, canonical_json_line, sha256
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.m2_receipts import RUN_RECEIPT_SCHEMA, run_receipt_id
from research_warehouse.static_core_baseline import (
    INE_SC_LAST_DAY_RULE,
    REGISTRY_SCHEMA,
    SHFE_LAST_DAY_RULE,
)

UTC = timezone.utc
CALENDAR_SHA = "a" * 64
CALENDAR_ANCHOR_SHA = "b" * 64
REGISTRY_SHA = "c" * 64


def _calendar() -> OfficialCalendar:
    start = date(2026, 1, 1)
    end = date(2027, 3, 31)
    rows = {}
    current = start
    while current <= end:
        rows[current] = CalendarDay(
            day=current,
            status="OFFICIAL_DAY" if current.weekday() < 5 else "CLOSED",
            evening_session_natural_date=None,
        )
        current += timedelta(days=1)
    return OfficialCalendar.create(
        calendar_id="official-calendar-daily-roll-test-v1",
        raw_sha256=CALENDAR_SHA,
        valid_from=start,
        valid_to=end,
        issued_at=datetime(2025, 12, 1, tzinfo=UTC),
        exchanges=("SHFE", "INE"),
        days=rows,
        source_evidence=(),
        source_evidence_root=Path("/unused"),
    )


def _raw_for_day(
    official_day: str,
    exchange: str,
    *,
    deliveries: tuple[str, str, str] = ("2610", "2611", "2612"),
) -> bytes:
    rows = []
    for product in frozen.PRODUCTS:
        if frozen.PRODUCT_SPECS[product]["exchange"] != exchange:
            continue
        for index, delivery in enumerate(deliveries):
            open_interest = 5000 - index * 1000
            if product == "ag" and index in (0, 1):
                open_interest = 5000
            rows.append(
                {
                    "DELIVERYMONTH": delivery,
                    "PRODUCTID": f"{product}_f",
                    "SETTLEMENTPRICE": str(100 + index),
                    "OPENINTEREST": str(open_interest),
                }
            )
    return canonical_json(
        {
            "report_date": official_day.replace("-", ""),
            "o_curinstrument": rows,
        }
    )


def _contract_registry() -> bytes:
    return canonical_json(
        {
            "schema_version": REGISTRY_SCHEMA,
            "registry_id": "static-core-contract-registry-daily-roll-test-v1",
            "generated_at": "2026-08-18T18:00:00+08:00",
            "sources": [
                {
                    "source_id": "official-contract-rules",
                    "url": "https://example.invalid/contracts",
                }
            ],
            "products": [
                {
                    "product": product,
                    "exchange": spec["exchange"],
                    "multiplier": spec["multiplier"],
                    "price_tick": spec["price_tick"],
                    "last_trading_day_rule": (
                        INE_SC_LAST_DAY_RULE if product == "sc" else SHFE_LAST_DAY_RULE
                    ),
                    "source_id": "official-contract-rules",
                }
                for product, spec in frozen.PRODUCT_SPECS.items()
            ],
            "authority": false_authority(),
        }
    )


def _inputs(official_day: str = "2026-08-18") -> dict:
    raw = {
        exchange: _raw_for_day(official_day, exchange) for exchange in ("SHFE", "INE")
    }
    sources = []
    for exchange in ("SHFE", "INE"):
        lower = exchange.lower()
        sources.append(
            {
                "source_id": f"{lower}-daily-market-data-v1",
                "exchange": exchange,
                "object_id": f"object-{official_day}-{lower}",
                "observation_id": f"observation-{official_day}-{lower}",
                "revision_id": f"revision-{official_day}-{lower}",
                "raw_sha256": sha256(raw[exchange]),
                "raw_bytes": len(raw[exchange]),
                "raw_relative_path": f"raw/{official_day}-{lower}.json",
            }
        )
    receipt = {
        "schema_version": RUN_RECEIPT_SCHEMA,
        "receipt_id": "",
        "trade_day": official_day,
        "completed_at": f"{official_day}T08:00:00.000000Z",
        "registry_raw_sha256": REGISTRY_SHA,
        "calendar_raw_sha256": CALENDAR_SHA,
        "calendar_availability_anchor_raw_sha256": CALENDAR_ANCHOR_SHA,
        "sources": sources,
        "authority": false_authority(),
    }
    receipt["receipt_id"] = run_receipt_id(receipt)
    manifest_sources = [
        {field: source[field] for field in daily_roll.MANIFEST_SOURCE_KEYS}
        for source in sources
    ]
    batch_seal = "d" * 64
    commit_seal = "e" * 64
    predecessor = {
        product: f"{spec['exchange']}.{product}2610"
        for product, spec in frozen.PRODUCT_SPECS.items()
    }
    return {
        "calendar": _calendar(),
        "calendar_availability_anchor_raw_sha256": CALENDAR_ANCHOR_SHA,
        "daily_source_raw": raw,
        "run_receipt_raw": canonical_json_line(receipt),
        "manifest_lineage": {
            "trade_day": official_day,
            "batch_id": f"batch-{official_day}-daily-roll-test",
            "batch_seal_sha256": batch_seal,
            "commit_seal_sha256": commit_seal,
            "manifest_raw_sha256": "f" * 64,
            "commit_receipt_raw_sha256": "0" * 64,
            "operator_state_raw_sha256": "1" * 64,
            "manifest_genesis_seal_sha256": "2" * 64,
            "manifest_head_seal_sha256": batch_seal,
            "manifest_head_commit_seal_sha256": commit_seal,
            "commit_anchor_ledger_raw_sha256": "3" * 64,
            "sources": manifest_sources,
        },
        "policy_lineage": {
            "isolation_policy_raw_sha256": "4" * 64,
            "runtime_input_raw_sha256": "5" * 64,
            "release_tree_manifest_raw_sha256": "6" * 64,
        },
        "contract_registry_raw": _contract_registry(),
        "predecessor_exact_contracts": predecessor,
    }


def _payload(raw: bytes) -> dict:
    return json.loads(raw)


def test_daily_roll_source_is_deterministic_canonical_and_schema_valid() -> None:
    kwargs = _inputs()

    first = daily_roll.build_daily_pit_main_roll_source(**kwargs)
    second = daily_roll.build_daily_pit_main_roll_source(**kwargs)
    payload = daily_roll.verify_daily_pit_main_roll_source(first.artifact_raw)

    assert first == second
    assert first.artifact_raw.endswith(b"\n")
    assert first.artifact_raw_sha256 == sha256(first.artifact_raw)
    assert payload["artifact_id"] == first.artifact_id
    assert payload["official_day"] == "2026-08-18"
    assert payload["execution_day"] == "2026-08-19"
    assert payload["following_official_day"] == "2026-08-20"
    assert [row["product"] for row in payload["mains"]] == list(frozen.PRODUCTS)
    assert payload["changed_products"] == []
    assert payload["roll_change_detected"] is False
    assert payload["input_lineage_status"] == daily_roll.INPUT_LINEAGE_STATUS
    assert payload["installable"] is False
    assert payload["event_ready"] is False
    assert payload["execution_lane"] == "simnow_shakedown"
    assert payload["production_allowed"] is False
    assert payload["live_trading_authorized"] is False
    assert payload["countable_forward"] is False
    assert payload["official_forward_claimed"] is False
    assert payload["authority"] == false_authority()
    schema = json.loads(
        (
            ROOT / "deployments/research-warehouse/"
            "daily-pit-main-roll-source-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    validate_json_schema(
        instance=payload,
        schema=schema,
        format_checker=FormatChecker(),
    )
    serialized = first.artifact_raw.decode("utf-8")
    for forbidden in (
        "target_quantity",
        "previous_target_quantity",
        "account_id",
        "order_id",
        "order_request",
        '"side"',
        '"offset"',
    ):
        assert forbidden not in serialized.lower()


def test_daily_roll_source_uses_frozen_tie_break_and_marks_only_real_changes() -> None:
    kwargs = _inputs()
    kwargs["predecessor_exact_contracts"]["ag"] = "SHFE.ag2611"

    built = daily_roll.build_daily_pit_main_roll_source(**kwargs)
    payload = _payload(built.artifact_raw)
    ag = payload["mains"][0]

    assert ag["exact_contract"] == "SHFE.ag2610"
    assert ag["open_interest"] == 5000.0
    assert ag["eligible_contract_count"] == 3
    assert ag["changed"] is True
    assert payload["changed_products"] == ["ag"]
    assert payload["roll_change_detected"] is True
    assert all(not row["changed"] for row in payload["mains"][1:])


def test_unverified_predecessor_map_cannot_change_selection_or_authority() -> None:
    unchanged = _payload(
        daily_roll.build_daily_pit_main_roll_source(**_inputs()).artifact_raw
    )
    changed_inputs = _inputs()
    changed_inputs["predecessor_exact_contracts"].update(
        {
            "ag": "SHFE.ag2611",
            "sc": "INE.sc2611",
        }
    )
    changed = _payload(
        daily_roll.build_daily_pit_main_roll_source(**changed_inputs).artifact_raw
    )

    assert {row["product"]: row["exact_contract"] for row in unchanged["mains"]} == {
        row["product"]: row["exact_contract"] for row in changed["mains"]
    }
    assert unchanged["changed_products"] == []
    assert unchanged["roll_change_detected"] is False
    assert changed["changed_products"] == ["ag", "sc"]
    assert changed["roll_change_detected"] is True
    assert (
        unchanged["claimed_lineage"]["predecessor_exact_contract_map_sha256"]
        != changed["claimed_lineage"]["predecessor_exact_contract_map_sha256"]
    )
    for payload in (unchanged, changed):
        assert payload["authority"] == false_authority()
        assert not any(payload["authority"].values())
        assert payload["input_lineage_status"] == "UNVERIFIED_FOUNDATION_ONLY"
        assert payload["installable"] is False
        assert payload["event_ready"] is False
        assert payload["execution_lane"] == "simnow_shakedown"
        assert payload["production_allowed"] is False
        assert payload["live_trading_authorized"] is False
        assert payload["countable_forward"] is False
        assert payload["official_forward_claimed"] is False
        assert "trigger_ready" not in payload


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_lineage_status", "VERIFIED"),
        ("installable", True),
        ("event_ready", True),
        ("execution_lane", "live"),
        ("production_allowed", True),
        ("live_trading_authorized", True),
        ("countable_forward", True),
        ("official_forward_claimed", True),
    ],
)
def test_daily_roll_source_foundation_gates_fail_closed(
    field: str,
    value: object,
) -> None:
    payload = _payload(
        daily_roll.build_daily_pit_main_roll_source(**_inputs()).artifact_raw
    )
    payload[field] = value

    with pytest.raises(
        daily_roll.DailyPitMainRollSourceError,
        match="identity mismatch",
    ):
        daily_roll.verify_daily_pit_main_roll_source(canonical_json_line(payload))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda payload: payload["mains"][0].__setitem__(
                "eligible_contract_count", 65
            ),
            "eligible count is outside the admitted range",
        ),
        (
            lambda payload: payload["claimed_lineage"]["sources"][0].__setitem__(
                "object_id", "x" * 257
            ),
            "source object_id is outside the admitted range",
        ),
        (
            lambda payload: payload["claimed_lineage"]["sources"][0].__setitem__(
                "raw_relative_path", "raw/" + "x" * 1021
            ),
            "source path is unsafe",
        ),
        (
            lambda payload: payload["claimed_lineage"]["sources"][0].__setitem__(
                "raw_relative_path", "raw/../outside.json"
            ),
            "source path is unsafe",
        ),
        (
            lambda payload: payload["claimed_lineage"]["calendar"].__setitem__(
                "calendar_id", "x" * 129
            ),
            "calendar ID is outside the admitted range",
        ),
        (
            lambda payload: payload["claimed_lineage"]["manifest"].__setitem__(
                "batch_id", "x" * 129
            ),
            "manifest identity is invalid",
        ),
    ],
)
def test_daily_roll_source_python_limits_match_schema(
    mutate,
    message: str,
) -> None:
    payload = _payload(
        daily_roll.build_daily_pit_main_roll_source(**_inputs()).artifact_raw
    )
    mutate(payload)

    with pytest.raises(daily_roll.DailyPitMainRollSourceError, match=message):
        daily_roll.verify_daily_pit_main_roll_source(canonical_json_line(payload))


def test_daily_roll_source_schema_uses_format_checker_for_calendar_dates() -> None:
    payload = _payload(
        daily_roll.build_daily_pit_main_roll_source(**_inputs()).artifact_raw
    )
    payload["official_day"] = "2026-02-30"
    schema = json.loads(
        (
            ROOT / "deployments/research-warehouse/"
            "daily-pit-main-roll-source-v1.schema.json"
        ).read_text(encoding="utf-8")
    )

    with pytest.raises(ValidationError):
        validate_json_schema(
            instance=payload,
            schema=schema,
            format_checker=FormatChecker(),
        )


@pytest.mark.parametrize(
    "completed_at",
    [
        "not-a-date-time",
        "2026-08-18T08:00:00+00:00",
        "2026-08-18T08:00:00Z",
    ],
)
def test_daily_roll_source_schema_requires_canonical_utc_completion(
    completed_at: str,
) -> None:
    payload = _payload(
        daily_roll.build_daily_pit_main_roll_source(**_inputs()).artifact_raw
    )
    payload["claimed_lineage"]["run_receipt"]["completed_at"] = completed_at
    schema = json.loads(
        (
            ROOT / "deployments/research-warehouse/"
            "daily-pit-main-roll-source-v1.schema.json"
        ).read_text(encoding="utf-8")
    )

    with pytest.raises(ValidationError):
        validate_json_schema(
            instance=payload,
            schema=schema,
            format_checker=FormatChecker(),
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["daily_source_raw"].pop("INE"),
            "exact SHFE/INE",
        ),
        (
            lambda value: value["manifest_lineage"]["sources"][0].__setitem__(
                "raw_sha256", "9" * 64
            ),
            "manifest/receipt source binding",
        ),
        (
            lambda value: value["predecessor_exact_contracts"].pop("zn"),
            "exact ten products",
        ),
        (
            lambda value: value["predecessor_exact_contracts"].__setitem__(
                "ag", "INE.ag2610"
            ),
            "exact contract is invalid",
        ),
        (
            lambda value: value["policy_lineage"].__setitem__("unexpected", "7" * 64),
            "policy lineage fields",
        ),
    ],
)
def test_daily_roll_source_rejects_incomplete_or_spliced_lineage(
    mutate,
    message: str,
) -> None:
    kwargs = _inputs()
    mutate(kwargs)

    with pytest.raises(daily_roll.DailyPitMainRollSourceError, match=message):
        daily_roll.build_daily_pit_main_roll_source(**kwargs)


def test_daily_roll_source_rejects_raw_byte_drift_and_missing_product() -> None:
    kwargs = _inputs()
    payload = json.loads(kwargs["daily_source_raw"]["SHFE"])
    payload["o_curinstrument"][0]["OPENINTEREST"] = "4999"
    kwargs["daily_source_raw"]["SHFE"] = canonical_json(payload)
    with pytest.raises(
        daily_roll.DailyPitMainRollSourceError,
        match="receipt/raw byte binding",
    ):
        daily_roll.build_daily_pit_main_roll_source(**kwargs)

    kwargs = _inputs()
    payload = json.loads(kwargs["daily_source_raw"]["SHFE"])
    payload["o_curinstrument"] = [
        row for row in payload["o_curinstrument"] if row["PRODUCTID"] != "zn_f"
    ]
    drifted = canonical_json(payload)
    kwargs["daily_source_raw"]["SHFE"] = drifted
    receipt = json.loads(kwargs["run_receipt_raw"])
    receipt["sources"][0]["raw_sha256"] = sha256(drifted)
    receipt["sources"][0]["raw_bytes"] = len(drifted)
    receipt["receipt_id"] = run_receipt_id(receipt)
    kwargs["run_receipt_raw"] = canonical_json_line(receipt)
    for source in kwargs["manifest_lineage"]["sources"]:
        if source["exchange"] == "SHFE":
            source["raw_sha256"] = sha256(drifted)
            source["raw_bytes"] = len(drifted)
    with pytest.raises(
        daily_roll.DailyPitMainRollSourceError,
        match="fewer than three",
    ):
        daily_roll.build_daily_pit_main_roll_source(**kwargs)


def test_daily_roll_source_rejects_main_inside_frozen_dte_boundary() -> None:
    kwargs = _inputs("2026-09-18")

    with pytest.raises(
        daily_roll.DailyPitMainRollSourceError,
        match="sc PIT main is inside the DTE safety boundary",
    ):
        daily_roll.build_daily_pit_main_roll_source(**kwargs)


def test_daily_roll_source_resource_limits_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _inputs()
    monkeypatch.setattr(daily_roll, "MAX_SOURCE_RAW_BYTES", 16)

    with pytest.raises(
        daily_roll.DailyPitMainRollSourceError,
        match="resource limit exceeded",
    ):
        daily_roll.build_daily_pit_main_roll_source(**kwargs)


def test_daily_roll_source_verifier_rejects_tampering_and_noncanonical_bytes() -> None:
    built = daily_roll.build_daily_pit_main_roll_source(**_inputs())
    payload = _payload(built.artifact_raw)
    payload["mains"][0]["target_quantity"] = 1

    with pytest.raises(
        daily_roll.DailyPitMainRollSourceError,
        match="main fields",
    ):
        daily_roll.verify_daily_pit_main_roll_source(canonical_json_line(payload))
    with pytest.raises(
        daily_roll.DailyPitMainRollSourceError,
        match="not canonical JSON",
    ):
        daily_roll.verify_daily_pit_main_roll_source(built.artifact_raw[:-1] + b" \n")


def test_daily_roll_source_consumes_no_execution_day_market_input() -> None:
    kwargs = _inputs()
    assert set(kwargs["daily_source_raw"]) == {"SHFE", "INE"}

    payload = _payload(
        daily_roll.build_daily_pit_main_roll_source(**kwargs).artifact_raw
    )

    assert all(
        source["raw_relative_path"].startswith("raw/2026-08-18-")
        for source in payload["claimed_lineage"]["sources"]
    )
    assert payload["execution_day"] == "2026-08-19"
