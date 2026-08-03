from __future__ import annotations

import ast
import json
import os
import pwd
import subprocess
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
from research_warehouse.m2_daily_scheduler import run_daily, run_trade_day
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


def runtime_input_payload(root: Path) -> dict:
    return {
        "schema_version": RUNTIME_INPUT_SCHEMA,
        "policy_path": str(root / "isolation-policy-v1.json"),
        "registry_path": str(root / "source-registry-v1.json"),
        "calendar_path": str(root / "calendar.json"),
        "calendar_public_key_path": str(root / "calendar.pub"),
        "calendar_source_evidence_root": str(root / "calendar-evidence"),
        "calendar_availability_anchor_path": str(root / "availability.json"),
        "backup_public_key_path": str(root / "backup.pub"),
        "expected_calendar_raw_sha256": "a" * 64,
        "expected_calendar_public_key_sha256": "b" * 64,
        "expected_calendar_availability_anchor_raw_sha256": "c" * 64,
        "expected_backup_public_key_sha256": "d" * 64,
        "expected_backup_head_anchor_raw_sha256": "e" * 64,
        "monitor_from_day": DAY.isoformat(),
        "collector_version": "m2-daily-scheduler-v1",
        "authority": false_authority(),
    }


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


class FailingNtpSocket(FakeNtpSocket):
    def recv(self, _limit):
        raise TimeoutError("first NTP address timed out")


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


def test_history_resume_reuses_each_completed_source_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, runtime = scheduler_paths(tmp_path)
    registry = load_registry(REGISTRY_PATH)
    recovered = acquired(paths, "shfe-daily-market-data-v1", 1)
    calls = []
    monkeypatch.setattr(
        "research_warehouse.m2_daily_scheduler.revalidate_official_calendar_evidence",
        lambda _calendar: None,
    )
    monkeypatch.setattr(
        "research_warehouse.m2_daily_scheduler.latest_acquired_observation",
        lambda _paths, _registry, *, source_id, **_kwargs: (
            recovered if source_id == "shfe-daily-market-data-v1" else None
        ),
    )
    availability = SimpleNamespace(
        raw_sha256="b" * 64,
        available_at=NOW - timedelta(days=1),
        require_available=lambda *_args, **_kwargs: None,
    )

    def acquire(**kwargs):
        calls.append(kwargs["source_id"])
        return acquired(paths, kwargs["source_id"], 2)

    result = run_trade_day(
        paths=paths,
        runtime=runtime,
        registry=registry,
        calendar=calendar(),
        availability=availability,
        trade_day=DAY.isoformat(),
        clock_sample=TrustedClockSample(NOW, NOW, 0),
        collector_version="m2-daily-scheduler-v1",
        verify_receipt=lambda _receipt: None,
        acquire=acquire,
        utc_clock=lambda: NOW,
        receipt_directory=runtime.history_run_receipts,
        resume_source_observations=True,
    )
    assert result["status"] == "OFFICIAL_DAY_COMPLETE"
    assert calls == ["ine-daily-market-data-v1"]
    receipt = runtime.history_run_receipts / f"{DAY}.json"
    assert receipt.is_file()


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


def test_live_ntp_clock_times_only_the_successful_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        m2_ntp.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (2, 2, 17, "", ("203.0.113.1", 123)),
            (2, 2, 17, "", ("203.0.113.2", 123)),
        ],
    )
    sockets = iter(
        (
            FailingNtpSocket(server_time=1_000.0),
            FakeNtpSocket(server_time=1_001.05),
        )
    )
    monkeypatch.setattr(
        m2_ntp.socket,
        "socket",
        lambda *_args: next(sockets),
    )
    wall_values = iter((1_000.0, 1_001.0, 1_001.1))
    monotonic_values = iter((0.0, 5.1, 5.2))
    sample = m2_ntp.query_trusted_clock(
        wall_clock=lambda: next(wall_values),
        monotonic_clock=lambda: next(monotonic_values),
    )
    assert sample.ntp_offset_milliseconds == 0


def test_live_ntp_clock_retries_transient_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolutions = []

    def resolve(*_args, **_kwargs):
        resolutions.append(True)
        return [(2, 2, 17, "", ("203.0.113.1", 123))]

    monkeypatch.setattr(m2_ntp.socket, "getaddrinfo", resolve)
    sockets = iter(
        (
            FailingNtpSocket(server_time=1_000.0),
            FakeNtpSocket(server_time=1_001.05),
        )
    )
    monkeypatch.setattr(
        m2_ntp.socket,
        "socket",
        lambda *_args: next(sockets),
    )
    wall_values = iter((1_000.0, 1_001.0, 1_001.1))
    monotonic_values = iter((0.0, 1.0, 2.0, 2.1))
    delays = []

    sample = m2_ntp.query_trusted_clock(
        wall_clock=lambda: next(wall_values),
        monotonic_clock=lambda: next(monotonic_values),
        sleep=delays.append,
    )

    assert sample.ntp_offset_milliseconds == 0
    assert len(resolutions) == 2 * len(m2_ntp.NTP_SERVERS)
    assert delays == [0.25]


def test_live_ntp_clock_does_not_retry_invalid_bound_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        m2_ntp.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 2, 17, "", ("203.0.113.1", 123))],
    )
    socket_calls = []

    def invalid_socket(*_args):
        socket_calls.append(True)
        return FakeNtpSocket(server_time=1_002.0)

    monkeypatch.setattr(m2_ntp.socket, "socket", invalid_socket)
    wall_values = iter((1_000.0, 1_000.1))
    monotonic_values = iter((5.0, 5.1))

    with pytest.raises(RegistryError, match="NTP offset"):
        m2_ntp.query_trusted_clock(
            wall_clock=lambda: next(wall_values),
            monotonic_clock=lambda: next(monotonic_values),
            sleep=lambda _seconds: pytest.fail("invalid response was retried"),
        )

    assert len(socket_calls) == 1


def test_runtime_input_requires_exact_external_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime-input-v1.json"
    policy = SimpleNamespace(payload={"authority": false_authority()})
    payload = runtime_input_payload(tmp_path)
    path.write_bytes(canonical_json_line(payload))
    monkeypatch.setattr(
        "research_warehouse.m2_runtime_input._require_root_owner_mode",
        lambda *_args: None,
    )
    checked = []
    monkeypatch.setattr(
        "research_warehouse.m2_runtime_input.require_acl_free_path",
        lambda value, _label: checked.append(value),
    )
    loaded = load_runtime_input(path, policy=policy)
    assert loaded.payload == payload
    assert checked == [tmp_path, path]
    payload["unexpected"] = True
    path.write_bytes(canonical_json_line(payload))
    with pytest.raises(RegistryError, match="contract mismatch"):
        load_runtime_input(path, policy=policy)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL")
@pytest.mark.parametrize("target", ["file", "inheritable-parent", "fd-only"])
def test_runtime_input_rejects_darwin_acl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    path = tmp_path / "runtime-input-v1.json"
    path.write_bytes(canonical_json_line(runtime_input_payload(tmp_path)))
    policy = SimpleNamespace(payload={"authority": false_authority()})
    monkeypatch.setattr(
        "research_warehouse.m2_runtime_input._require_root_owner_mode",
        lambda *_args: None,
    )
    account = pwd.getpwuid(os.getuid()).pw_name
    acl = (
        f"user:{account} allow write"
        if target in {"file", "fd-only"}
        else (f"user:{account} allow write,file_inherit,directory_inherit,only_inherit")
    )
    subprocess.check_call(
        ["chmod", "+a", acl, str(path if target == "file" else tmp_path)]
    )
    if target == "fd-only":
        subprocess.check_call(["chmod", "-a", acl, str(tmp_path)])
        subprocess.check_call(["chmod", "+a", acl, str(path)])
        monkeypatch.setattr(
            "research_warehouse.m2_runtime_input.require_acl_free_path",
            lambda *_args: None,
        )
    with pytest.raises(RegistryError, match="extended ACL"):
        load_runtime_input(path, policy=policy)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL")
def test_private_custody_roots_and_receipt_reject_acl(tmp_path: Path) -> None:
    account = pwd.getpwuid(os.getuid()).pw_name
    explicit_acl = f"user:{account} allow write"
    paths = WarehousePaths.initialize(tmp_path / "warehouse")
    backup = BackupPaths.initialize(tmp_path / "backup")
    runtime = RuntimePaths.ensure(tmp_path / "runtime")
    for root, reopen in (
        (paths.root, lambda: WarehousePaths.open(paths.root)),
        (backup.root, lambda: BackupPaths.open(backup.root)),
        (runtime.root, lambda: RuntimePaths.ensure(runtime.root)),
    ):
        subprocess.check_call(["chmod", "+a", explicit_acl, str(root)])
        with pytest.raises(RegistryError, match="extended ACL"):
            reopen()

    clean_runtime = RuntimePaths.ensure(tmp_path / "clean-runtime")
    receipt_path, _payload = publish_monitor_receipt(
        clean_runtime,
        checked_at="2026-07-30T10:30:00.000000Z",
        runtime_input_raw_sha256="a" * 64,
        facts={"derived": True},
        result={"status": "HEALTHY"},
    )
    subprocess.check_call(["chmod", "+a", explicit_acl, str(receipt_path)])
    with pytest.raises(RegistryError, match="extended ACL"):
        load_monitor_receipt(
            receipt_path,
            expected_raw_sha256=sha256(receipt_path.read_bytes()),
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL")
def test_runtime_creation_rejects_inherited_parent_acl(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o700)
    account = pwd.getpwuid(os.getuid()).pw_name
    inheritable_acl = (
        f"user:{account} allow read,write,file_inherit,directory_inherit,only_inherit"
    )
    subprocess.check_call(["chmod", "+a", inheritable_acl, str(shared)])
    with pytest.raises(RegistryError, match="extended ACL"):
        RuntimePaths.ensure(shared / "runtime")


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
        lambda *_args, **_kwargs: NOW,
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


def test_monitor_facts_accept_current_history_receipt_after_calendar_rotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, runtime = scheduler_paths(tmp_path)
    registry = load_registry(REGISTRY_PATH)
    daily_path = runtime.run_receipts / f"{DAY.isoformat()}.json"
    history_path = runtime.history_run_receipts / f"{DAY.isoformat()}.json"
    for receipt_path in (daily_path, history_path):
        receipt_path.write_text("{}\n")
        receipt_path.chmod(0o600)

    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts.load_run_receipt",
        lambda path: {
            "trade_day": DAY.isoformat(),
            "candidate": "history" if path == history_path else "daily",
        },
    )

    def verify(receipt: dict[str, object], **_kwargs: object) -> datetime:
        if receipt["candidate"] == "daily":
            raise RegistryError("M2 run receipt authority binding mismatch")
        return NOW

    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts.verify_daily_run_receipt",
        verify,
    )
    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts._unreviewed_revisions",
        lambda *_args, **_kwargs: 0,
    )
    monkeypatch.setattr(
        "research_warehouse.m2_monitor_facts.verify_backup_anchor",
        lambda **_kwargs: SimpleNamespace(created_at=NOW - timedelta(hours=1)),
    )
    backup_root = BackupPaths.initialize(tmp_path / "backup").root

    facts = derive_monitor_facts(
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

    assert facts["latest_official_day"] == DAY.isoformat()
    assert facts["missing_official_days"] == []
    assert facts["hash_mismatch_count"] == 0


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
    forged = dict(receipt)
    forged["completed_at"] = "2026-07-30T10:31:00.000000Z"
    forged["receipt_id"] = run_receipt_id(forged)
    with pytest.raises(RegistryError, match="completion time binding"):
        verify_daily_run_receipt(
            forged,
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
