from __future__ import annotations

import ast
import base64
import json
import math
import sys
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commodity_c_fast_pure_producer_kernel as frozen
import commodity_relative_vol_snapshot_producer as producer
from research_warehouse.calendar_models import (
    CalendarDay,
    OfficialCalendar,
)
from research_warehouse.canonical import canonical_json, sha256
from research_warehouse.errors import RegistryError
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.m2_operator_state import OperatorState
from research_warehouse.pit_source_view import (
    DERIVATION_ID,
    PitSourceViewError,
    build_source_view,
    contract_rows_from_daily_raw,
    verify_built_source_view,
)
from research_warehouse.pit_source_view_custody import (
    publish_source_view,
    read_source_view,
)
from test_commodity_relative_vol_snapshot_producer import (
    source_view as relative_source_view,
)

UTC = timezone.utc
PRODUCT_BASE = {
    "ag": 8000.0,
    "al": 20000.0,
    "au": 500.0,
    "bu": 3800.0,
    "cu": 80000.0,
    "rb": 3600.0,
    "ru": 15000.0,
    "sc": 600.0,
    "sp": 6200.0,
    "zn": 24000.0,
}


def _calendar() -> OfficialCalendar:
    start = date(2025, 10, 1)
    end = date(2026, 8, 10)
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
        calendar_id="official-calendar-test-v1",
        raw_sha256="a" * 64,
        valid_from=start,
        valid_to=end,
        issued_at=datetime(2025, 9, 1, tzinfo=UTC),
        exchanges=("SHFE", "INE"),
        days=rows,
        source_evidence=(),
        source_evidence_root=Path("/unused"),
    )


def _official_days(calendar: OfficialCalendar, count: int = 186) -> list[str]:
    result = [
        day.isoformat()
        for day, row in calendar.days.items()
        if row.is_official and day <= date(2026, 7, 31)
    ]
    return result[-count:]


def _row(product: str, delivery: str, index: int, contract_index: int) -> dict:
    spec = frozen.PRODUCT_SPECS[product]
    tick = float(spec["price_tick"])
    base = PRODUCT_BASE[product]
    phase = list(frozen.PRODUCTS).index(product) * 0.37
    level = base * (
        1.0
        + 0.00035 * index
        + 0.0015 * math.sin(index / (4.0 + contract_index) + phase)
        + contract_index * 0.012
    )
    settlement = round(level / tick) * tick
    return {
        "DELIVERYMONTH": delivery,
        "PRODUCTID": product,
        "OPENPRICE": str(settlement),
        "HIGHESTPRICE": str(settlement + tick),
        "LOWESTPRICE": str(settlement - tick),
        "CLOSEPRICE": str(settlement),
        "SETTLEMENTPRICE": str(settlement),
        "VOLUME": str(1000 - contract_index * 10),
        "OPENINTEREST": str(5000 - contract_index * 1000),
    }


def _raw_for_day(raw_day: str, exchange: str, index: int) -> bytes:
    rows = []
    for product in frozen.PRODUCTS:
        if frozen.PRODUCT_SPECS[product]["exchange"] != exchange:
            continue
        for contract_index, delivery in enumerate(("2612", "2701", "2702")):
            rows.append(_row(product, delivery, index, contract_index))
        rows.append(
            {
                "DELIVERYMONTH": "",
                "PRODUCTID": f"{product}_f",
                "OPENPRICE": "",
                "HIGHESTPRICE": "",
                "LOWESTPRICE": "",
                "CLOSEPRICE": "",
                "SETTLEMENTPRICE": "",
                "VOLUME": "0",
                "OPENINTEREST": "0",
            }
        )
    return canonical_json(
        {
            "report_date": raw_day.replace("-", ""),
            "o_curinstrument": rows,
        }
    )


def _signed_baseline(private_key: Ed25519PrivateKey) -> dict:
    source = relative_source_view(
        source_month="2026-07",
        execution_day=date(2026, 8, 3),
        execution_lane="simnow_shakedown",
    )
    baseline = deepcopy(source["baseline_batch"])
    signature = private_key.sign(
        canonical_json({key: value for key, value in baseline.items() if key != "signature"})
    )
    baseline["signature"] = base64.b64encode(signature).decode("ascii")
    return baseline


def _resign(payload: dict, private_key: Ed25519PrivateKey) -> None:
    signature = private_key.sign(
        canonical_json({key: value for key, value in payload.items() if key != "signature"})
    )
    payload["signature"] = base64.b64encode(signature).decode("ascii")


def _operator_state() -> OperatorState:
    payload = {
        "manifest_sequence": 186,
        "manifest_genesis_seal_sha256": "b" * 64,
        "manifest_head_seal_sha256": "c" * 64,
        "manifest_head_commit_seal_sha256": "d" * 64,
        "commit_anchor_ledger_raw_sha256": "e" * 64,
    }
    return OperatorState(
        path=Path("/operator-state"),
        raw_sha256="f" * 64,
        payload=payload,
    )


def _inputs():
    calendar = _calendar()
    days = _official_days(calendar)
    daily_raw = {
        raw_day: {
            "SHFE": _raw_for_day(raw_day, "SHFE", index),
            "INE": _raw_for_day(raw_day, "INE", index),
        }
        for index, raw_day in enumerate(days)
    }
    history = {
        "required_official_days": 186,
        "official_days": days,
        "completed_at": "2026-07-31T14:00:00.000000Z",
        "registry_raw_sha256": "1" * 64,
        "daily_receipts": [
            {
                "trade_day": raw_day,
                "run_receipt_relative_path": f"history-run-receipts/{raw_day}.json",
                "run_receipt_raw_sha256": f"{index % 10}" * 64,
                "source_raw_sha256": [
                    sha256(daily_raw[raw_day]["SHFE"]),
                    sha256(daily_raw[raw_day]["INE"]),
                ],
                "source_raw_bytes": [
                    len(daily_raw[raw_day]["SHFE"]),
                    len(daily_raw[raw_day]["INE"]),
                ],
            }
            for index, raw_day in enumerate(days)
        ],
    }
    key = Ed25519PrivateKey.generate()
    return calendar, history, daily_raw, key


def test_real_shape_source_view_is_deterministic_and_producer_replays() -> None:
    calendar, history, daily_raw, key = _inputs()
    baseline = _signed_baseline(key)
    kwargs = {
        "calendar": calendar,
        "calendar_anchor_sha256": "2" * 64,
        "history_receipt": history,
        "history_receipt_sha256": "3" * 64,
        "operator_state": _operator_state(),
        "daily_source_raw": daily_raw,
        "baseline_batch": baseline,
        "business_public_key": key.public_key(),
        "source_month": "2026-07",
        "previous_snapshot": None,
    }

    first = build_source_view(**kwargs)
    second = build_source_view(**kwargs)

    assert first == second
    source = json.loads(first.source_view_raw)
    receipt = json.loads(first.receipt_raw)
    assert len(source["official_days"]) == 126
    assert len(source["baseline_daily_returns"]) == 126
    assert receipt["derivation_id"] == DERIVATION_ID
    assert receipt["source_view_raw_sha256"] == sha256(first.source_view_raw)
    assert receipt["authority"] == false_authority()
    receipt_schema = json.loads(
        (
            ROOT
            / "deployments/research-warehouse/"
            "relative-vol-pit-source-receipt-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(receipt_schema).validate(receipt)
    replay = producer.produce_snapshot(first.source_view_raw)
    assert replay.source_view_canonical_sha256 == sha256(first.source_view_raw)


def test_contract_extraction_rejects_missing_wrong_day_and_hash_shape() -> None:
    raw = _raw_for_day("2026-07-31", "SHFE", 1)
    rows = contract_rows_from_daily_raw(
        raw=raw,
        exchange="SHFE",
        official_day="2026-07-31",
    )
    assert rows["ag"][0]["exact_contract"] == "SHFE.ag2612"

    wrong_day = json.loads(raw)
    wrong_day["report_date"] = "20260730"
    with pytest.raises(PitSourceViewError, match="report date"):
        contract_rows_from_daily_raw(
            raw=canonical_json(wrong_day),
            exchange="SHFE",
            official_day="2026-07-31",
        )

    missing = json.loads(raw)
    missing["o_curinstrument"] = [
        row for row in missing["o_curinstrument"] if row["PRODUCTID"] != "ag"
    ]
    with pytest.raises(RegistryError, match="fewer than three"):
        contract_rows_from_daily_raw(
            raw=canonical_json(missing),
            exchange="SHFE",
            official_day="2026-07-31",
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda history, daily, baseline: history["official_days"].pop(),
            "186-day plan",
        ),
        (
            lambda history, daily, baseline: daily.pop(history["official_days"][-1]),
            "daily source evidence is missing",
        ),
        (
            lambda history, daily, baseline: baseline["targets"][0].__setitem__(
                "exact_contract",
                "SHFE.ag2610",
            ),
            "signature is invalid",
        ),
        (
            lambda history, daily, baseline: daily[
                history["official_days"][-1]
            ].__setitem__(
                "SHFE",
                _raw_for_day(history["official_days"][-2], "SHFE", 1),
            ),
            "report date mismatch",
        ),
    ],
)
def test_missing_wrong_day_tamper_and_baseline_splice_fail_closed(
    mutate,
    message: str,
) -> None:
    calendar, history, daily_raw, key = _inputs()
    baseline = _signed_baseline(key)
    mutate(history, daily_raw, baseline)
    with pytest.raises(PitSourceViewError, match=message):
        build_source_view(
            calendar=calendar,
            calendar_anchor_sha256="2" * 64,
            history_receipt=history,
            history_receipt_sha256="3" * 64,
            operator_state=_operator_state(),
            daily_source_raw=daily_raw,
            baseline_batch=baseline,
            business_public_key=key.public_key(),
            source_month="2026-07",
            previous_snapshot=None,
        )


def test_create_only_custody_replay_and_file_set_fail_closed(tmp_path: Path) -> None:
    calendar, history, daily_raw, key = _inputs()
    built = build_source_view(
        calendar=calendar,
        calendar_anchor_sha256="2" * 64,
        history_receipt=history,
        history_receipt_sha256="3" * 64,
        operator_state=_operator_state(),
        daily_source_raw=daily_raw,
        baseline_batch=_signed_baseline(key),
        business_public_key=key.public_key(),
        source_month="2026-07",
        previous_snapshot=None,
    )
    root = tmp_path / "exports"
    root.mkdir(mode=0o700)
    output = publish_source_view(
        root,
        built.source_view_id,
        source_view_raw=built.source_view_raw,
        receipt_raw=built.receipt_raw,
    )
    assert read_source_view(output) == (built.source_view_raw, built.receipt_raw)
    assert (
        verify_built_source_view(
            built.source_view_raw,
            built.receipt_raw,
            expected_receipt_raw_sha256=sha256(built.receipt_raw),
        )["receipt_id"]
        == built.receipt_id
    )
    with pytest.raises(PitSourceViewError, match="receipt SHA256"):
        verify_built_source_view(
            built.source_view_raw,
            built.receipt_raw,
            expected_receipt_raw_sha256="0" * 64,
        )
    tampered_source = built.source_view_raw.replace(
        b'"daily_return":',
        b'"daily_return":0.1,"ignored":',
        1,
    )
    with pytest.raises(PitSourceViewError):
        verify_built_source_view(
            tampered_source,
            built.receipt_raw,
            expected_receipt_raw_sha256=sha256(built.receipt_raw),
        )
    with pytest.raises(RegistryError, match="overwrite forbidden"):
        publish_source_view(
            root,
            built.source_view_id,
            source_view_raw=built.source_view_raw,
            receipt_raw=built.receipt_raw,
        )
    (output / "unexpected").write_bytes(b"x")
    with pytest.raises(RegistryError, match="file set"):
        read_source_view(output)


def test_future_availability_spec_and_output_permission_fail_closed(
    tmp_path: Path,
) -> None:
    calendar, history, daily_raw, key = _inputs()
    baseline = _signed_baseline(key)
    history["completed_at"] = "2026-08-01T00:00:00.000000Z"
    with pytest.raises(PitSourceViewError, match="unavailable at PIT cutoff"):
        build_source_view(
            calendar=calendar,
            calendar_anchor_sha256="2" * 64,
            history_receipt=history,
            history_receipt_sha256="3" * 64,
            operator_state=_operator_state(),
            daily_source_raw=daily_raw,
            baseline_batch=baseline,
            business_public_key=key.public_key(),
            source_month="2026-07",
            previous_snapshot=None,
        )

    history["completed_at"] = "2026-07-31T14:00:00.000000Z"
    baseline["targets"][0]["multiplier"] += 1
    _resign(baseline, key)
    with pytest.raises(PitSourceViewError, match="contract spec"):
        build_source_view(
            calendar=calendar,
            calendar_anchor_sha256="2" * 64,
            history_receipt=history,
            history_receipt_sha256="3" * 64,
            operator_state=_operator_state(),
            daily_source_raw=daily_raw,
            baseline_batch=baseline,
            business_public_key=key.public_key(),
            source_month="2026-07",
            previous_snapshot=None,
        )

    public_root = tmp_path / "public"
    public_root.mkdir(mode=0o755)
    with pytest.raises(RegistryError, match="private"):
        publish_source_view(
            public_root,
            "warehouse-pit-test",
            source_view_raw=b"{}",
            receipt_raw=b"{}\n",
        )


def test_receipt_schema_and_static_authority_boundary() -> None:
    schema = json.loads(
        (
            ROOT
            / "deployments/research-warehouse/"
            "relative-vol-pit-source-receipt-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)

    paths = (
        ROOT / "scripts/research_warehouse/pit_source_view.py",
        ROOT / "scripts/research_warehouse/pit_source_view_cli.py",
        ROOT / "scripts/research_warehouse/pit_source_view_verify_cli.py",
    )
    forbidden_imports = {
        "app",
        "vnpy",
        "requests",
        "httpx",
        "socket",
        "subprocess",
        "trade_service",
    }
    forbidden_functions = {
        "send_order",
        "cancel_order",
        "connect",
        "dispatch",
        "trade",
    }
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = set()
        functions = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.add(node.name)
        assert imports.isdisjoint(forbidden_imports)
        assert functions.isdisjoint(forbidden_functions)
