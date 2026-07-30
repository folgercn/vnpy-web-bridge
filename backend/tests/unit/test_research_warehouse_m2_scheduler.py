from __future__ import annotations

import ast
import json
import sys
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from research_warehouse import m2_ntp
from research_warehouse.acquisition import acquire_daily
from research_warehouse.acquisition_models import AcquiredObject, HttpResponse
from research_warehouse.backup_custody import BackupPaths
from research_warehouse.calendar_models import CalendarDay, OfficialCalendar
from research_warehouse.canonical import canonical_json_line, sha256
from research_warehouse.clock_quality import TrustedClockSample
from research_warehouse.errors import RegistryError
from research_warehouse.filesystem import WarehousePaths
from research_warehouse.m2_daily_scheduler import run_daily
from research_warehouse.m2_isolation_contracts import false_authority
from research_warehouse.m2_monitor import evaluate_monitor
from research_warehouse.m2_monitor_facts import (
    _unreviewed_revisions,
    derive_monitor_facts,
    verify_daily_run_receipt,
)
from research_warehouse.m2_receipts import (
    RUN_RECEIPT_SCHEMA,
    load_monitor_receipt,
    publish_monitor_receipt,
    run_receipt_id,
)
from research_warehouse.m2_runtime_input import (
    RUNTIME_INPUT_SCHEMA,
    load_runtime_input,
)
from research_warehouse.m2_runtime_paths import RuntimePaths
from research_warehouse.registry import load_registry

UTC = timezone.utc
REGISTRY_PATH = ROOT / "deployments/research-warehouse/source-registry-v1.json"
DAY = date(2026, 7, 30)
NOW = datetime(2026, 7, 30, 10, 30, tzinfo=UTC)


def calendar(*, closed: bool = False) -> OfficialCalendar:
    days = {}
    for offset in range(-3, 2):
        value = DAY + timedelta(days=offset)
        days[value] = CalendarDay(
            day=value,
            status="CLOSED" if closed and value == DAY else "OFFICIAL_DAY",
            evening_session_natural_date=None,
        )
    return OfficialCalendar.create(
        calendar_id="calendar-test",
        raw_sha256="a" * 64,
        valid_from=min(days),
        valid_to=max(days),
        issued_at=NOW - timedelta(days=30),
        exchanges=("SHFE", "INE"),
        days=days,
        source_evidence=(),
        source_evidence_root=Path("/unused"),
    )


def scheduler_paths(tmp_path: Path):
    return (
        WarehousePaths.initialize(tmp_path / "custody"),
        RuntimePaths.ensure(tmp_path / "runtime"),
    )


def acquired(paths: WarehousePaths, source_id: str, sequence: int):
    raw_path = paths.raw / f"{source_id}.raw"
    raw_path.write_bytes(b"evidence")
    raw_path.chmod(0o600)
    return AcquiredObject(
        object_id=f"object-{sequence}",
        observation_id=f"obs-{sequence}",
        revision_id=f"revision-{sequence}",
        raw_sha256=f"{sequence}" * 64,
        raw_bytes=8,
        raw_path=raw_path,
        first_seen_at=NOW,
        last_seen_at=NOW + timedelta(seconds=sequence),
        supersedes_object_id=None,
        supersedes_revision_id=None,
        idempotent_raw=False,
    )


def official_raw(marker: str) -> bytes:
    return json.dumps(
        {
            "o_curinstrument": [
                {
                    "DELIVERYMONTH": "2608",
                    "PRODUCTID": "cu_f",
                    "OPENPRICE": "80000",
                    "HIGHESTPRICE": "80100",
                    "LOWESTPRICE": "79900",
                    "CLOSEPRICE": "80050",
                    "SETTLEMENTPRICE": "80020",
                    "VOLUME": "100",
                    "OPENINTEREST": "200",
                    "TEST_MARKER": marker,
                }
            ],
            "report_date": "20260730",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


class RawTransport:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    @contextmanager
    def open(self, url: str, **_kwargs):
        yield HttpResponse(
            final_url=url,
            status=200,
            headers={
                "content-length": str(len(self.raw)),
                "content-type": "application/json",
            },
            chunks=iter((self.raw,)),
        )


class FakeNtpSocket:
    def __init__(self, *, server_time: float) -> None:
        self.server_time = server_time
        self.request = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def settimeout(self, _value):
        return None

    def connect(self, _address):
        return None

    def send(self, value):
        self.request = bytes(value)
        return len(value)

    def recv(self, _limit):
        response = bytearray(48)
        response[0] = 0x24
        response[1] = 2
        response[24:32] = self.request[40:48]
        response[32:40] = m2_ntp._encode_timestamp(self.server_time)
        response[40:48] = m2_ntp._encode_timestamp(self.server_time)
        return bytes(response)


def test_scheduler_publishes_only_after_both_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, runtime = scheduler_paths(tmp_path)
    registry = load_registry(REGISTRY_PATH)
    calls = []

    def acquire(**kwargs):
        calls.append(kwargs["source_id"])
        return acquired(paths, kwargs["source_id"], len(calls))

    monkeypatch.setattr(
        "research_warehouse.m2_daily_scheduler.revalidate_official_calendar_evidence",
        lambda _calendar: None,
    )
    availability = SimpleNamespace(
        raw_sha256="b" * 64,
        require_available=lambda *_args, **_kwargs: None,
    )
    result = run_daily(
        paths=paths,
        runtime=runtime,
        registry=registry,
        calendar=calendar(),
        availability=availability,
        clock_sample=TrustedClockSample(NOW, NOW, 0),
        collector_version="m2-daily-scheduler-v1",
        verify_receipt=lambda _receipt: None,
        acquire=acquire,
        utc_clock=lambda: NOW,
    )
    assert result["status"] == "OFFICIAL_DAY_COMPLETE"
    assert calls == [
        "shfe-daily-market-data-v1",
        "ine-daily-market-data-v1",
    ]
    assert len(list(runtime.run_receipts.glob("*.json"))) == 1
    second = run_daily(
        paths=paths,
        runtime=runtime,
        registry=registry,
        calendar=calendar(),
        availability=availability,
        clock_sample=TrustedClockSample(NOW, NOW, 0),
        collector_version="m2-daily-scheduler-v1",
        verify_receipt=lambda _receipt: None,
        acquire=acquire,
        utc_clock=lambda: NOW,
    )
    assert second["status"] == "ALREADY_COMPLETE"
    assert len(calls) == 2


def test_scheduler_closed_partial_and_clock_skew_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, runtime = scheduler_paths(tmp_path)
    registry = load_registry(REGISTRY_PATH)
    monkeypatch.setattr(
        "research_warehouse.m2_daily_scheduler.revalidate_official_calendar_evidence",
        lambda _calendar: None,
    )
    availability = SimpleNamespace(
        raw_sha256="b" * 64,
        require_available=lambda *_args, **_kwargs: None,
    )
    calls = []
    closed = run_daily(
        paths=paths,
        runtime=runtime,
        registry=registry,
        calendar=calendar(closed=True),
        availability=availability,
        clock_sample=TrustedClockSample(NOW, NOW, 0),
        collector_version="m2-daily-scheduler-v1",
        verify_receipt=lambda _receipt: None,
        acquire=lambda **kwargs: calls.append(kwargs),
        utc_clock=lambda: NOW,
    )
    assert closed["status"] == "CALENDAR_CLOSED_SKIPPED"
    assert not calls

    def partial(**kwargs):
        calls.append(kwargs["source_id"])
        if len(calls) == 2:
            raise RegistryError("timeout")
        return acquired(paths, kwargs["source_id"], 1)

    with pytest.raises(RegistryError, match="timeout"):
        run_daily(
            paths=paths,
            runtime=runtime,
            registry=registry,
            calendar=calendar(),
            availability=availability,
            clock_sample=TrustedClockSample(NOW, NOW, 0),
            collector_version="m2-daily-scheduler-v1",
            verify_receipt=lambda _receipt: None,
            acquire=partial,
            utc_clock=lambda: NOW,
        )
    assert not list(runtime.run_receipts.glob("*.json"))
    with pytest.raises(RegistryError, match="NTP offset"):
        run_daily(
            paths=paths,
            runtime=runtime,
            registry=registry,
            calendar=calendar(),
            availability=availability,
            clock_sample=TrustedClockSample(NOW, NOW, 1_001),
            collector_version="m2-daily-scheduler-v1",
            verify_receipt=lambda _receipt: None,
            utc_clock=lambda: NOW,
        )


def test_live_ntp_clock_accepts_bound_reply_and_rejects_skew(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        m2_ntp.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 2, 17, "", ("203.0.113.1", 123))],
    )
    monkeypatch.setattr(
        m2_ntp.socket,
        "socket",
        lambda *_args: FakeNtpSocket(server_time=1_000.05),
    )
    wall_values = iter((1_000.0, 1_000.1))
    monotonic_values = iter((5.0, 5.1))
    sample = m2_ntp.query_trusted_clock(
        wall_clock=lambda: next(wall_values),
        monotonic_clock=lambda: next(monotonic_values),
    )
    assert sample.ntp_offset_milliseconds == 0

    monkeypatch.setattr(
        m2_ntp.socket,
        "socket",
        lambda *_args: FakeNtpSocket(server_time=1_002.0),
    )
    wall_values = iter((1_000.0, 1_000.1))
    monotonic_values = iter((5.0, 5.1))
    with pytest.raises(RegistryError, match="NTP offset"):
        m2_ntp.query_trusted_clock(
            wall_clock=lambda: next(wall_values),
            monotonic_clock=lambda: next(monotonic_values),
        )


def test_runtime_input_requires_exact_external_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime-input-v1.json"
    policy = SimpleNamespace(payload={"authority": false_authority()})
    payload = {
        "schema_version": RUNTIME_INPUT_SCHEMA,
        "policy_path": str(tmp_path / "isolation-policy-v1.json"),
        "registry_path": str(tmp_path / "source-registry-v1.json"),
        "calendar_path": str(tmp_path / "calendar.json"),
        "calendar_public_key_path": str(tmp_path / "calendar.pub"),
        "calendar_source_evidence_root": str(tmp_path / "calendar-evidence"),
        "calendar_availability_anchor_path": str(tmp_path / "availability.json"),
        "backup_public_key_path": str(tmp_path / "backup.pub"),
        "expected_calendar_raw_sha256": "a" * 64,
        "expected_calendar_public_key_sha256": "b" * 64,
        "expected_calendar_availability_anchor_raw_sha256": "c" * 64,
        "expected_backup_public_key_sha256": "d" * 64,
        "expected_backup_head_anchor_raw_sha256": "e" * 64,
        "monitor_from_day": DAY.isoformat(),
        "collector_version": "m2-daily-scheduler-v1",
        "authority": false_authority(),
    }
    path.write_bytes(canonical_json_line(payload))
    monkeypatch.setattr(
        "research_warehouse.m2_runtime_input.require_root_managed",
        lambda _path: None,
    )
    loaded = load_runtime_input(path, policy=policy)
    assert loaded.payload == payload
    payload["unexpected"] = True
    path.write_bytes(canonical_json_line(payload))
    with pytest.raises(RegistryError, match="contract mismatch"):
        load_runtime_input(path, policy=policy)


def test_monitor_facts_derive_missing_revision_hash_disk_and_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, runtime = scheduler_paths(tmp_path)
    registry = load_registry(REGISTRY_PATH)
    receipt = runtime.run_receipts / f"{DAY.isoformat()}.json"
    receipt.write_text("{}\n")
    receipt.chmod(0o600)
    value = {
        "trade_day": DAY.isoformat(),
        "completed_at": "2026-07-30T10:30:00.000000Z",
    }
    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts.load_run_receipt",
        lambda _path: value,
    )
    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts.verify_daily_run_receipt",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts._unreviewed_revisions",
        lambda *_args, **_kwargs: 2,
    )
    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts.verify_backup_anchor",
        lambda **_kwargs: SimpleNamespace(created_at=NOW - timedelta(hours=1)),
    )
    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts.shutil.disk_usage",
        lambda _path: SimpleNamespace(free=1234),
    )
    backup_root = BackupPaths.initialize(tmp_path / "backup").root
    facts = derive_monitor_facts(
        paths=paths,
        runtime=runtime,
        registry=registry,
        calendar=calendar(),
        calendar_availability_raw_sha256="b" * 64,
        monitor_from_day=DAY - timedelta(days=1),
        backup_root=backup_root,
        backup_public_key_path=tmp_path / "backup.pub",
        expected_backup_public_key_sha256="c" * 64,
        expected_backup_head_anchor_raw_sha256="d" * 64,
        now=NOW,
    )
    assert facts["missing_official_days"] == ["2026-07-29"]
    assert facts["unreviewed_revision_count"] == 2
    assert facts["hash_mismatch_count"] == 0
    assert facts["disk_free_bytes"] == 1234
    assert facts["backup_verified"] is True

    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts.verify_daily_run_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RegistryError("hash mismatch")),
    )
    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts.verify_backup_anchor",
        lambda **_kwargs: (_ for _ in ()).throw(RegistryError("bad backup")),
    )
    degraded = derive_monitor_facts(
        paths=paths,
        runtime=runtime,
        registry=registry,
        calendar=calendar(),
        calendar_availability_raw_sha256="b" * 64,
        monitor_from_day=DAY,
        backup_root=backup_root,
        backup_public_key_path=tmp_path / "backup.pub",
        expected_backup_public_key_sha256="c" * 64,
        expected_backup_head_anchor_raw_sha256="d" * 64,
        now=NOW,
    )
    assert degraded["hash_mismatch_count"] == 1
    assert degraded["backup_verified"] is False
    assert degraded["last_backup_at"] is None


def test_run_receipt_rechecks_real_custody_hash_and_revision(
    tmp_path: Path,
) -> None:
    paths = WarehousePaths.initialize(tmp_path / "custody")
    registry = load_registry(REGISTRY_PATH)
    acquired_values = []
    for sequence, source in enumerate(registry.sources, start=1):
        acquired_values.append(
            (
                source,
                acquire_daily(
                    paths=paths,
                    registry=registry,
                    source_id=source.source_id,
                    trade_day=DAY.isoformat(),
                    collector_version="m2-daily-scheduler-v1",
                    observed_at=NOW + timedelta(seconds=sequence),
                    transport=RawTransport(official_raw("first")),
                ),
            )
        )
    receipt = {
        "schema_version": RUN_RECEIPT_SCHEMA,
        "receipt_id": "",
        "trade_day": DAY.isoformat(),
        "completed_at": "2026-07-30T10:30:02.000000Z",
        "registry_raw_sha256": registry.raw_sha256,
        "calendar_raw_sha256": "a" * 64,
        "calendar_availability_anchor_raw_sha256": "b" * 64,
        "sources": [
            {
                "source_id": source.source_id,
                "exchange": source.exchange,
                "object_id": value.object_id,
                "observation_id": value.observation_id,
                "revision_id": value.revision_id,
                "raw_sha256": value.raw_sha256,
                "raw_bytes": value.raw_bytes,
                "raw_relative_path": str(value.raw_path.relative_to(paths.root)),
            }
            for source, value in acquired_values
        ],
        "authority": false_authority(),
    }
    receipt["receipt_id"] = run_receipt_id(receipt)
    verify_daily_run_receipt(
        receipt,
        paths=paths,
        registry=registry,
        calendar=calendar(),
        calendar_availability_raw_sha256="b" * 64,
    )
    raw_path = acquired_values[0][1].raw_path
    original = raw_path.read_bytes()
    raw_path.write_bytes(b"tampered")
    with pytest.raises(RegistryError):
        verify_daily_run_receipt(
            receipt,
            paths=paths,
            registry=registry,
            calendar=calendar(),
            calendar_availability_raw_sha256="b" * 64,
        )
    raw_path.write_bytes(original)
    acquire_daily(
        paths=paths,
        registry=registry,
        source_id=registry.sources[0].source_id,
        trade_day=DAY.isoformat(),
        collector_version="m2-daily-scheduler-v1",
        observed_at=NOW + timedelta(minutes=1),
        transport=RawTransport(official_raw("revision")),
    )
    assert _unreviewed_revisions(receipt, paths=paths, registry=registry) == 1


def test_monitor_marks_absent_success_and_backup_degraded() -> None:
    policy = SimpleNamespace(
        payload={
            "monitor_thresholds": {
                "last_success_max_age_seconds": 10,
                "disk_free_min_bytes": 100,
                "backup_max_age_seconds": 10,
            }
        }
    )
    result = evaluate_monitor(
        {
            "last_success_at": None,
            "expected_official_day": DAY.isoformat(),
            "latest_official_day": None,
            "missing_official_days": [DAY.isoformat()],
            "unreviewed_revision_count": 0,
            "hash_mismatch_count": 0,
            "disk_free_bytes": 100,
            "last_backup_at": None,
            "backup_verified": False,
        },
        policy=policy,
        now=NOW,
    )
    assert result["status"] == "DEGRADED"
    assert result["incidents"] == [
        "LAST_SUCCESS_STALE",
        "OFFICIAL_DAY_MISSING",
        "BACKUP_STALE_OR_UNVERIFIED",
    ]


def test_monitor_receipt_is_create_only_private_and_hash_bindable(
    tmp_path: Path,
) -> None:
    runtime = RuntimePaths.ensure(tmp_path / "runtime")
    path, payload = publish_monitor_receipt(
        runtime,
        checked_at="2026-07-30T10:30:00.000000Z",
        runtime_input_raw_sha256="a" * 64,
        facts={"derived": True},
        result={"status": "HEALTHY"},
    )
    assert path.stat().st_mode & 0o077 == 0
    assert (
        load_monitor_receipt(
            path,
            expected_raw_sha256=sha256(path.read_bytes()),
        )
        == payload
    )
    with pytest.raises(RegistryError, match="SHA256 mismatch"):
        load_monitor_receipt(path, expected_raw_sha256="b" * 64)


def test_runtime_layers_import_no_trading_or_signing_authority() -> None:
    forbidden = {
        "app",
        "vnpy",
        "rpc",
        "account",
        "order",
        "position",
        "trading",
        "load_private_key",
    }
    for name in (
        "m2_runtime_input.py",
        "m2_runtime_paths.py",
        "m2_receipts.py",
        "m2_daily_scheduler.py",
        "m2_monitor_facts.py",
        "m2_runtime_loader.py",
        "m2_scheduler_cli.py",
    ):
        tree = ast.parse((ROOT / "scripts/research_warehouse" / name).read_text())
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert imported.isdisjoint(forbidden)
