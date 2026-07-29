from __future__ import annotations

import base64
import json
import sys
from contextlib import contextmanager
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse.absence_anchors import (
    ANCHOR_SCHEMA as ABSENCE_ANCHOR_SCHEMA,
)
from research_warehouse.absence_anchors import (
    load_absence_availability_anchor,
)
from research_warehouse.absence_receipts import create_absence_receipt
from research_warehouse.acquisition import acquire_daily
from research_warehouse.acquisition_models import (
    AuthoritativeAbsence,
    HttpResponse,
)
from research_warehouse.calendar_anchors import (
    ANCHOR_SCHEMA,
    load_calendar_availability_anchor,
)
from research_warehouse.calendar_models import OfficialCalendar
from research_warehouse.canonical import canonical_json, canonical_json_line, sha256
from research_warehouse.clock_quality import (
    TrustedClockSample,
    validate_observation_clock,
)
from research_warehouse.commit_anchors import CommitAnchor, CommitAnchorLedger
from research_warehouse.errors import RegistryError
from research_warehouse.filesystem import WarehousePaths
from research_warehouse.official_calendar import (
    CALENDAR_AUTHORITY,
    CALENDAR_SCHEMA,
    SOURCE_TYPE,
    load_official_calendar,
    revalidate_official_calendar_evidence,
)
from research_warehouse.quality_contracts import TARGET_PRODUCTS
from research_warehouse.quality_gate import (
    evaluate_history_quality,
    require_intraday_observed_open,
)
from research_warehouse.registry import load_registry
from research_warehouse.signing import (
    load_public_key,
    public_key_sha256,
    sign_payload,
)
from research_warehouse.trade_day_mapping import map_exchange_timestamp

REGISTRY_PATH = ROOT / "deployments/research-warehouse/source-registry-v1.json"
CALENDAR_SCHEMA_PATH = (
    ROOT / "deployments/research-warehouse/official-calendar-v1.schema.json"
)
CALENDAR_ANCHOR_SCHEMA_PATH = (
    ROOT
    / "deployments/research-warehouse/calendar-availability-anchor-v1.schema.json"
)
ABSENCE_SCHEMA_PATH = (
    ROOT / "deployments/research-warehouse/authoritative-absence-v1.schema.json"
)
ABSENCE_ANCHOR_SCHEMA_PATH = (
    ROOT
    / "deployments/research-warehouse/absence-availability-anchor-v1.schema.json"
)
UTC = timezone.utc


class StatusTransport:
    def __init__(self, status: int) -> None:
        self.status = status

    @contextmanager
    def open(self, url: str, **_kwargs):
        yield HttpResponse(
            final_url=url,
            status=self.status,
            headers={},
            chunks=iter(()),
        )


def private_key_paths(tmp_path: Path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "calendar-private.key"
    public_path = tmp_path / "calendar-public.key"
    private_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        base64.b64encode(
            private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        + b"\n"
    )
    private_path.chmod(0o600)
    public_path.chmod(0o600)
    return private, private_path, public_path


def signed_calendar(
    tmp_path: Path,
    *,
    closed: set[date] | None = None,
) -> tuple[OfficialCalendar, Path, dict]:
    closed = closed or set()
    start = date(2025, 7, 1)
    end = date(2026, 7, 31)
    evidence_root = tmp_path / "calendar-evidence"
    evidence_root.mkdir(mode=0o700)
    evidence_values = []
    for exchange, owner, host in (
        ("INE", "Shanghai International Energy Exchange", "www.ine.cn"),
        ("SHFE", "Shanghai Futures Exchange", "www.shfe.com.cn"),
    ):
        raw = f"official-{exchange}-calendar-evidence".encode()
        digest = sha256(raw)
        sources = evidence_root / "calendar-sources"
        sources.mkdir(mode=0o700, exist_ok=True)
        sources.chmod(0o700)
        parent = sources / exchange.lower()
        parent.mkdir(mode=0o700)
        path = parent / f"{digest}.raw"
        path.write_bytes(raw)
        path.chmod(0o600)
        evidence_values.append(
            {
                "exchange": exchange,
                "owner": owner,
                "source_url": f"https://{host}/services/trading-calendar",
                "source_type": SOURCE_TYPE,
                "observed_at": "2025-06-30T01:00:00.000000Z",
                "raw_sha256": digest,
                "raw_bytes": len(raw),
                "raw_relative_path": (
                    f"calendar-sources/{exchange.lower()}/{digest}.raw"
                ),
            }
        )
    days = []
    current = start
    official_dates = set()
    while current <= end:
        official = current.weekday() < 5 and current not in closed
        candidate = current - timedelta(
            days=3 if current.weekday() == 0 else 1
        )
        evening_session = (
            candidate
            if official and candidate in official_dates
            else None
        )
        days.append(
            {
                "date": current.isoformat(),
                "status": "OFFICIAL_DAY" if official else "CLOSED",
                "evening_session_natural_date": (
                    evening_session.isoformat()
                    if evening_session is not None
                    else None
                ),
            }
        )
        if official:
            official_dates.add(current)
        current += timedelta(days=1)
    private, _private_path, _public_path = private_key_paths(tmp_path)
    payload = {
        "schema_version": CALENDAR_SCHEMA,
        "calendar_id": "",
        "timezone": "Asia/Shanghai",
        "timestamp_storage": "UTC",
        "valid_from": start.isoformat(),
        "valid_to": end.isoformat(),
        "issued_at": "2025-06-30T02:00:00.000000Z",
        "exchanges": ["INE", "SHFE"],
        "source_evidence": evidence_values,
        "days": days,
        "authority": CALENDAR_AUTHORITY,
        "signer_key_id": "calendar-test-key-v1",
        "signer_public_key_sha256": public_key_sha256(private.public_key()),
    }
    base = dict(payload)
    base.pop("calendar_id")
    payload["calendar_id"] = "calendar-" + sha256(canonical_json(base))
    signed = sign_payload(payload, private)
    raw = canonical_json_line(signed)
    calendar_path = tmp_path / "official-calendar.json"
    calendar_path.write_bytes(raw)
    calendar_path.chmod(0o600)
    calendar = load_official_calendar(
        calendar_path,
        public_key=private.public_key(),
        expected_raw_sha256=sha256(raw),
        source_evidence_root=evidence_root,
    )
    return calendar, calendar_path, signed


def shanghai_utc(day: date, value: time) -> datetime:
    local = datetime.combine(day, value).replace(
        tzinfo=__import__("zoneinfo").ZoneInfo("Asia/Shanghai")
    )
    return local.astimezone(UTC)


def calendar_anchor(tmp_path: Path, calendar: OfficialCalendar, available_at):
    payload = {
        "schema_version": ANCHOR_SCHEMA,
        "calendar_raw_sha256": calendar.raw_sha256,
        "source_evidence_sha256": {
            item.exchange: item.raw_sha256
            for item in calendar.source_evidence
        },
        "available_at": available_at.isoformat(timespec="microseconds").replace(
            "+00:00",
            "Z",
        ),
    }
    raw = canonical_json_line(payload)
    path = tmp_path / "calendar-availability-anchor.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    return load_calendar_availability_anchor(
        path,
        expected_raw_sha256=sha256(raw),
    )


def calendar_clock_args(now: datetime, *, elapsed_seconds: float = 0):
    monotonic_values = iter((0.0, elapsed_seconds))
    return {
        "utc_clock": lambda: now,
        "monotonic_clock": lambda: next(monotonic_values),
    }


def absence_anchor(
    tmp_path: Path,
    absence: AuthoritativeAbsence,
    *,
    available_at: datetime,
    calendar: OfficialCalendar,
    calendar_availability,
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    receipt_raw = absence.receipt_path.read_bytes()
    payload = {
        "schema_version": ABSENCE_ANCHOR_SCHEMA,
        "absence_id": absence.absence_id,
        "receipt_sha256": sha256(receipt_raw),
        "calendar_raw_sha256": absence.calendar_raw_sha256,
        "available_at": available_at.isoformat(timespec="microseconds").replace(
            "+00:00",
            "Z",
        ),
    }
    raw = canonical_json_line(payload)
    path = tmp_path / "absence-availability-anchor.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    return load_absence_availability_anchor(
        path,
        expected_raw_sha256=sha256(raw),
        receipt_path=absence.receipt_path,
        calendar=calendar,
        calendar_anchor=calendar_availability,
    )


def official_raw(exchange: str, day: date) -> bytes:
    products = [product for product in TARGET_PRODUCTS if product != "sc"]
    if exchange == "INE":
        products = ["sc"]
    rows = [
        {
            "DELIVERYMONTH": "2612",
            "PRODUCTID": f"{product}_f",
            "OPENPRICE": "10",
            "HIGHESTPRICE": "11",
            "LOWESTPRICE": "9",
            "CLOSEPRICE": "10",
            "SETTLEMENTPRICE": "10",
            "VOLUME": "1",
            "OPENINTEREST": "2",
        }
        for product in products
    ]
    return json.dumps(
        {
            "o_curinstrument": rows,
            "report_date": day.strftime("%Y%m%d"),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def history_chain(
    tmp_path: Path,
    calendar: OfficialCalendar,
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    paths = WarehousePaths.initialize(tmp_path / "warehouse")
    registry = load_registry(REGISTRY_PATH)
    official_days = sorted(
        day for day, item in calendar.days.items() if item.is_official
    )
    execution_day = official_days[-1]
    as_of_day = official_days[-2]
    required = official_days[-187:-1]
    chain = []
    anchors = []
    for sequence, day in enumerate(required, start=1):
        revisions = []
        for source in registry.sources:
            raw = official_raw(source.exchange, day)
            digest = sha256(raw)
            relative = (
                f"raw/{source.exchange.lower()}/{day}/{source.source_id}/"
                f"{digest}.raw"
            )
            path = paths.root / relative
            path.parent.mkdir(parents=True, mode=0o700)
            path.write_bytes(raw)
            path.chmod(0o600)
            revisions.append(
                {
                    "revision_id": f"revision-{sequence}-{source.exchange.lower()}",
                    "revision_sequence": 1,
                    "source_id": source.source_id,
                    "first_seen_at": (
                        datetime.combine(day, time(7), tzinfo=UTC)
                        .isoformat(timespec="microseconds")
                        .replace("+00:00", "Z")
                    ),
                    "raw_relative_path": relative,
                    "raw_bytes": len(raw),
                    "raw_sha256": digest,
                }
            )
        batch_seal = sha256(f"batch-{sequence}".encode())
        commit_seal = sha256(f"commit-{sequence}".encode())
        committed = datetime.combine(day, time(7, 30), tzinfo=UTC)
        available = datetime.combine(day, time(8), tzinfo=UTC)
        chain.append(
            {
                "batch_id": f"batch-{sequence:04d}",
                "trade_day": day.isoformat(),
                "batch_seal_sha256": batch_seal,
                "commit_seal_sha256": commit_seal,
                "commit_receipt": {
                    "committed_at": committed.isoformat(
                        timespec="microseconds"
                    ).replace("+00:00", "Z")
                },
                "revisions": revisions,
            }
        )
        anchors.append(
            CommitAnchor(
                sequence=sequence,
                batch_seal_sha256=batch_seal,
                commit_seal_sha256=commit_seal,
                available_at=available,
            )
        )
    ledger = CommitAnchorLedger(
        raw_sha256="a" * 64,
        entries=tuple(anchors),
    )
    cutoff = datetime.combine(as_of_day, time(9), tzinfo=UTC)
    clock = TrustedClockSample(
        trusted_now=cutoff,
        sampled_at=cutoff,
        ntp_offset_milliseconds=0,
    )
    anchor = calendar_anchor(
        tmp_path,
        calendar,
        datetime(2025, 6, 30, 3, tzinfo=UTC),
    )
    return (
        paths,
        registry,
        chain,
        ledger,
        as_of_day,
        execution_day,
        cutoff,
        clock,
        anchor,
    )


def test_signed_calendar_schema_and_raw_evidence_binding(tmp_path: Path) -> None:
    calendar, _path, payload = signed_calendar(tmp_path)
    schema = json.loads(CALENDAR_SCHEMA_PATH.read_bytes())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).validate(payload)
    Draft202012Validator.check_schema(
        json.loads(CALENDAR_ANCHOR_SCHEMA_PATH.read_bytes())
    )
    assert len(calendar.official_days_through(date(2026, 7, 30), count=186)) == 186


def test_calendar_missing_day_and_tampered_source_fail_closed(
    tmp_path: Path,
) -> None:
    calendar, path, _payload = signed_calendar(tmp_path)
    with pytest.raises(RegistryError, match="no authoritative classification"):
        calendar.require_day(date(2027, 1, 1))
    source_path = Path(
        next(iter(calendar.source_evidence)).raw_relative_path
    )
    evidence_root = tmp_path / "calendar-evidence"
    (evidence_root / source_path).write_bytes(b"tampered")
    with pytest.raises(RegistryError, match="source evidence changed"):
        revalidate_official_calendar_evidence(calendar)
    with pytest.raises(RegistryError, match="source evidence changed"):
        load_official_calendar(
            path,
            public_key=load_public_key(tmp_path / "calendar-public.key"),
            expected_raw_sha256=sha256(path.read_bytes()),
            source_evidence_root=evidence_root,
        )


def test_friday_night_and_saturday_after_midnight_map_to_monday(
    tmp_path: Path,
) -> None:
    calendar, _path, _payload = signed_calendar(tmp_path)
    monday = date(2026, 7, 20)
    friday = monday - timedelta(days=3)
    saturday = monday - timedelta(days=2)
    before_midnight = map_exchange_timestamp(
        shanghai_utc(friday, time(21, 30)),
        exchange="SHFE",
        session="NIGHT",
        calendar=calendar,
    )
    after_midnight = map_exchange_timestamp(
        shanghai_utc(saturday, time(0, 30)),
        exchange="SHFE",
        session="NIGHT",
        calendar=calendar,
    )
    assert before_midnight.trade_day == monday
    assert after_midnight.trade_day == monday
    with pytest.raises(RegistryError, match="session"):
        map_exchange_timestamp(
            shanghai_utc(monday - timedelta(days=1), time(21, 30)),
            exchange="SHFE",
            session="NIGHT",
            calendar=calendar,
        )


def test_holiday_night_mapping_and_clock_skew_fail_closed(
    tmp_path: Path,
) -> None:
    closed = {date(2026, 7, 20)}
    calendar, _path, _payload = signed_calendar(tmp_path, closed=closed)
    with pytest.raises(RegistryError, match="session"):
        map_exchange_timestamp(
            shanghai_utc(date(2026, 7, 19), time(21)),
            exchange="SHFE",
            session="NIGHT",
            calendar=calendar,
        )
    now = datetime(2026, 7, 19, 13, tzinfo=UTC)
    with pytest.raises(RegistryError, match="NTP offset"):
        validate_observation_clock(
            now,
            sample=TrustedClockSample(
                trusted_now=now,
                sampled_at=now,
                ntp_offset_milliseconds=1_001,
            ),
        )
    with pytest.raises(RegistryError, match="future"):
        validate_observation_clock(
            now + timedelta(seconds=6),
            sample=TrustedClockSample(
                trusted_now=now,
                sampled_at=now,
                ntp_offset_milliseconds=0,
            ),
        )
    with pytest.raises(RegistryError, match="stale"):
        validate_observation_clock(
            now,
            sample=TrustedClockSample(
                trusted_now=now,
                sampled_at=now - timedelta(seconds=301),
                ntp_offset_milliseconds=0,
            ),
        )


def test_404_requires_explicit_calendar_closed_day(tmp_path: Path) -> None:
    closed_day = date(2026, 7, 20)
    calendar, _path, _payload = signed_calendar(tmp_path, closed={closed_day})
    paths = WarehousePaths.initialize(tmp_path / "warehouse")
    observed = datetime(2026, 7, 20, 8, tzinfo=UTC)
    sample = TrustedClockSample(observed, observed, 0)
    result = acquire_daily(
        paths=paths,
        registry=load_registry(REGISTRY_PATH),
        source_id="shfe-daily-market-data-v1",
        trade_day=closed_day.isoformat(),
        collector_version="calendar-test-v1",
        transport=StatusTransport(404),
        calendar=calendar,
        clock_sample=sample,
        **calendar_clock_args(observed, elapsed_seconds=2),
    )
    assert isinstance(result, AuthoritativeAbsence)
    assert result.status == "CALENDAR_AUTHORIZED_ABSENCE_AWAITING_EXTERNAL_ANCHOR"
    assert result.observed_at == observed + timedelta(seconds=2)
    assert result.receipt_path.exists()
    Draft202012Validator(
        json.loads(ABSENCE_SCHEMA_PATH.read_bytes()),
        format_checker=FormatChecker(),
    ).validate(json.loads(result.receipt_path.read_bytes()))
    assert not list(paths.raw.rglob("*.raw"))
    calendar_availability = calendar_anchor(
        tmp_path,
        calendar,
        datetime(2025, 6, 30, 3, tzinfo=UTC),
    )
    anchor = absence_anchor(
        tmp_path,
        result,
        available_at=observed + timedelta(seconds=3),
        calendar=calendar,
        calendar_availability=calendar_availability,
    )
    Draft202012Validator(
        json.loads(ABSENCE_ANCHOR_SCHEMA_PATH.read_bytes()),
        format_checker=FormatChecker(),
    ).validate(
        json.loads((tmp_path / "absence-availability-anchor.json").read_bytes())
    )
    with pytest.raises(RegistryError, match="unavailable at PIT cutoff"):
        anchor.require_available(cutoff_at=observed + timedelta(seconds=1))
    anchor.require_available(cutoff_at=observed + timedelta(seconds=3))
    late_calendar_anchor = calendar_anchor(
        tmp_path,
        calendar,
        observed + timedelta(seconds=1),
    )
    with pytest.raises(RegistryError, match="unavailable at PIT cutoff"):
        absence_anchor(
            tmp_path / "late-calendar",
            result,
            available_at=observed + timedelta(seconds=3),
            calendar=calendar,
            calendar_availability=late_calendar_anchor,
        )

    official_absence_id, official_receipt = create_absence_receipt(
        paths=paths,
        source_id="shfe-daily-market-data-v1",
        exchange="SHFE",
        trade_day="2026-07-21",
        source_url="https://www.shfe.com.cn/data/dailydata/kx/kx20260721.dat",
        request_started_at=observed,
        response_received_at=observed + timedelta(seconds=1),
        ntp_sampled_at=observed,
        ntp_offset_milliseconds=0,
        http_metadata={
            "content-length": None,
            "content-type": None,
            "etag": None,
            "last-modified": None,
        },
        calendar_raw_sha256=calendar.raw_sha256,
        collector_version="calendar-test-v1",
    )
    forged_official_absence = AuthoritativeAbsence(
        absence_id=official_absence_id,
        receipt_path=official_receipt,
        source_id="shfe-daily-market-data-v1",
        exchange="SHFE",
        trade_day="2026-07-21",
        observed_at=observed + timedelta(seconds=1),
        http_status=404,
        calendar_raw_sha256=calendar.raw_sha256,
        status="CALENDAR_AUTHORIZED_ABSENCE_AWAITING_EXTERNAL_ANCHOR",
    )
    with pytest.raises(RegistryError, match="official-day source is missing"):
        absence_anchor(
            tmp_path / "official-day",
            forged_official_absence,
            available_at=observed + timedelta(seconds=3),
            calendar=calendar,
            calendar_availability=calendar_availability,
        )
    stale_absence_id, stale_receipt = create_absence_receipt(
        paths=paths,
        source_id="shfe-daily-market-data-v1",
        exchange="SHFE",
        trade_day=closed_day.isoformat(),
        source_url="https://www.shfe.com.cn/data/dailydata/kx/kx20260720.dat",
        request_started_at=observed,
        response_received_at=observed + timedelta(seconds=1),
        ntp_sampled_at=observed - timedelta(seconds=301),
        ntp_offset_milliseconds=0,
        http_metadata={
            "content-length": None,
            "content-type": None,
            "etag": None,
            "last-modified": None,
        },
        calendar_raw_sha256=calendar.raw_sha256,
        collector_version="calendar-test-v1",
    )
    stale_absence = AuthoritativeAbsence(
        absence_id=stale_absence_id,
        receipt_path=stale_receipt,
        source_id="shfe-daily-market-data-v1",
        exchange="SHFE",
        trade_day=closed_day.isoformat(),
        observed_at=observed + timedelta(seconds=1),
        http_status=404,
        calendar_raw_sha256=calendar.raw_sha256,
        status="CALENDAR_AUTHORIZED_ABSENCE_AWAITING_EXTERNAL_ANCHOR",
    )
    with pytest.raises(RegistryError, match="time ordering"):
        absence_anchor(
            tmp_path / "stale-ntp",
            stale_absence,
            available_at=observed + timedelta(seconds=3),
            calendar=calendar,
            calendar_availability=calendar_availability,
        )

    with pytest.raises(RegistryError, match="official-day source is missing"):
        acquire_daily(
            paths=paths,
            registry=load_registry(REGISTRY_PATH),
            source_id="shfe-daily-market-data-v1",
            trade_day="2026-07-21",
            collector_version="calendar-test-v1",
            transport=StatusTransport(404),
            calendar=calendar,
            clock_sample=sample,
            **calendar_clock_args(observed),
        )
    with pytest.raises(RegistryError, match="calendar-closed day"):
        acquire_daily(
            paths=paths,
            registry=load_registry(REGISTRY_PATH),
            source_id="shfe-daily-market-data-v1",
            trade_day=closed_day.isoformat(),
            collector_version="calendar-test-v1",
            transport=StatusTransport(200),
            calendar=calendar,
            clock_sample=sample,
            **calendar_clock_args(observed),
        )
    with pytest.raises(RegistryError, match="no authoritative classification"):
        acquire_daily(
            paths=paths,
            registry=load_registry(REGISTRY_PATH),
            source_id="shfe-daily-market-data-v1",
            trade_day="2027-01-01",
            collector_version="calendar-test-v1",
            transport=StatusTransport(404),
            calendar=calendar,
            clock_sample=sample,
            **calendar_clock_args(observed),
        )
    with pytest.raises(RegistryError, match="forbids caller-supplied"):
        acquire_daily(
            paths=paths,
            registry=load_registry(REGISTRY_PATH),
            source_id="shfe-daily-market-data-v1",
            trade_day=closed_day.isoformat(),
            collector_version="calendar-test-v1",
            observed_at=observed - timedelta(days=1),
            transport=StatusTransport(404),
            calendar=calendar,
            clock_sample=sample,
            **calendar_clock_args(observed),
        )
    with pytest.raises(RegistryError, match="not aligned with live wall time"):
        acquire_daily(
            paths=paths,
            registry=load_registry(REGISTRY_PATH),
            source_id="shfe-daily-market-data-v1",
            trade_day=closed_day.isoformat(),
            collector_version="calendar-test-v1",
            transport=StatusTransport(404),
            calendar=calendar,
            clock_sample=sample,
            **calendar_clock_args(observed + timedelta(days=1)),
        )
    evidence = calendar.source_evidence[0]
    evidence_path = calendar.source_evidence_root / evidence.raw_relative_path
    evidence_path.write_bytes(b"changed-after-calendar-load")
    with pytest.raises(RegistryError, match="source evidence changed"):
        acquire_daily(
            paths=paths,
            registry=load_registry(REGISTRY_PATH),
            source_id="shfe-daily-market-data-v1",
            trade_day=closed_day.isoformat(),
            collector_version="calendar-test-v1",
            transport=StatusTransport(404),
            calendar=calendar,
            clock_sample=sample,
            **calendar_clock_args(observed),
        )


def test_daily_open_is_never_intraday_observed_evidence() -> None:
    with pytest.raises(RegistryError, match="not intraday"):
        require_intraday_observed_open("OFFICIAL_DAILY_SUMMARY_POST_CLOSE")


def test_ten_product_186_day_quality_gate(tmp_path: Path) -> None:
    calendar, _path, _payload = signed_calendar(tmp_path)
    values = history_chain(tmp_path, calendar)
    result = evaluate_history_quality(
        paths=values[0],
        registry=values[1],
        chain=values[2],
        ledger=values[3],
        calendar=calendar,
        calendar_anchor=values[8],
        as_of_official_day=values[4],
        execution_trade_day=values[5],
        cutoff_at=values[6],
        clock_sample=values[7],
    )
    assert result["status"] == "RESEARCH_HISTORY_QUALITY_VALID"
    assert result["required_official_days"] == 186
    assert set(result["product_day_counts"].values()) == {186}
    assert result["intraday_observed_open_eligible"] is False
    late_anchor = calendar_anchor(
        tmp_path,
        calendar,
        values[6] + timedelta(seconds=1),
    )
    with pytest.raises(RegistryError, match="unavailable at PIT cutoff"):
        evaluate_history_quality(
            paths=values[0],
            registry=values[1],
            chain=values[2],
            ledger=values[3],
            calendar=calendar,
            calendar_anchor=late_anchor,
            as_of_official_day=values[4],
            execution_trade_day=values[5],
            cutoff_at=values[6],
            clock_sample=values[7],
        )

    latest = values[2][-1]["revisions"][0]
    revised = dict(latest)
    revised["revision_id"] += "-official-correction"
    revised["revision_sequence"] = 2
    revised["first_seen_at"] = values[6].isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    values[2][-1]["revisions"].append(revised)
    revised_result = evaluate_history_quality(
        paths=values[0],
        registry=values[1],
        chain=values[2],
        ledger=values[3],
        calendar=calendar,
        calendar_anchor=values[8],
        as_of_official_day=values[4],
        execution_trade_day=values[5],
        cutoff_at=values[6],
        clock_sample=values[7],
    )
    last_day_products = revised_result["days"][-1]["products"]
    revised_product = next(
        product
        for product, evidence in last_day_products.items()
        if evidence["exchange"] == values[1].sources[0].exchange
    )
    assert (
        last_day_products[revised_product]["revision_id"]
        == revised["revision_id"]
    )


def test_missing_official_day_and_future_revision_fail_closed(
    tmp_path: Path,
) -> None:
    calendar, _path, _payload = signed_calendar(tmp_path)
    values = history_chain(tmp_path, calendar)
    values[2][10]["trade_day"] = values[2][9]["trade_day"]
    with pytest.raises(RegistryError, match="history is missing"):
        evaluate_history_quality(
            paths=values[0],
            registry=values[1],
            chain=values[2],
            ledger=values[3],
            calendar=calendar,
            calendar_anchor=values[8],
            as_of_official_day=values[4],
            execution_trade_day=values[5],
            cutoff_at=values[6],
            clock_sample=values[7],
        )

    values = history_chain(tmp_path / "future", calendar)
    values[2][-1]["revisions"][0]["first_seen_at"] = (
        values[6] + timedelta(seconds=1)
    ).isoformat(timespec="microseconds").replace("+00:00", "Z")
    with pytest.raises(RegistryError, match="first_seen_at is in the future"):
        evaluate_history_quality(
            paths=values[0],
            registry=values[1],
            chain=values[2],
            ledger=values[3],
            calendar=calendar,
            calendar_anchor=values[8],
            as_of_official_day=values[4],
            execution_trade_day=values[5],
            cutoff_at=values[6],
            clock_sample=values[7],
        )


def test_missing_target_product_fails_closed(tmp_path: Path) -> None:
    calendar, _path, _payload = signed_calendar(tmp_path)
    values = history_chain(tmp_path, calendar)
    manifest = values[2][-1]
    revision = next(
        item
        for item in manifest["revisions"]
        if item["source_id"] == "shfe-daily-market-data-v1"
    )
    raw_path = values[0].root / revision["raw_relative_path"]
    payload = json.loads(raw_path.read_bytes())
    payload["o_curinstrument"] = [
        row
        for row in payload["o_curinstrument"]
        if row["PRODUCTID"] != "ag_f"
    ]
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    digest = sha256(raw)
    replacement = raw_path.with_name(f"{digest}.raw")
    replacement.write_bytes(raw)
    replacement.chmod(0o600)
    revision["raw_relative_path"] = str(replacement.relative_to(values[0].root))
    revision["raw_sha256"] = digest
    revision["raw_bytes"] = len(raw)
    with pytest.raises(RegistryError, match="missing target products: ag"):
        evaluate_history_quality(
            paths=values[0],
            registry=values[1],
            chain=values[2],
            ledger=values[3],
            calendar=calendar,
            calendar_anchor=values[8],
            as_of_official_day=values[4],
            execution_trade_day=values[5],
            cutoff_at=values[6],
            clock_sample=values[7],
        )
