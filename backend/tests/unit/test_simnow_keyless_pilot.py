from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _execution_status(
    *,
    position_hash: str,
    fresh_snapshot_id: str = "snapshot-run-0001",
    timestamp: str = "2030-01-01T00:00:00Z",
    state_version: int = 0,
):
    from app.schemas.control_execution import ExecutionStatusProjection

    return ExecutionStatusProjection.model_validate(
        {
            "schema_version": "web_bridge_execution_status_v1",
            "service": "execution-orchestrator",
            "service_version": "pilot-test",
            "observed_at": timestamp,
            "lifecycle": "READY",
            "state_version": state_version,
            "leader": {
                "scope": "account:windows",
                "owner_id": "pilot-owner-0001",
                "held": True,
                "epoch": 1,
                "fencing_token": 1,
                "lease_expires_at": "2030-01-01T00:01:00Z",
            },
            "authority": {
                "state": "DISABLED",
                "artifact_id": "authority-0001",
                "artifact_hash": "a" * 64,
                "expires_at": "2030-01-01T00:00:00Z",
            },
            "plan": {
                "state": "IDLE",
                "plan_id": "plan-idle-0001",
                "plan_hash": "b" * 64,
                "version": 0,
            },
            "send_intents": [],
            "reconciliation": {
                "state": "RECONCILED",
                "run_id": "reconcile-0001",
                "last_completed_at": timestamp,
                "unknown_outcomes": 0,
                "fresh_snapshot_id": fresh_snapshot_id,
            },
            "safe_to_restart": True,
            "broker": {
                "connected": True,
                "generation": 1,
                "active_order_count": 0,
                "position_snapshot_hash": position_hash,
                "last_snapshot_at": timestamp,
            },
        }
    )


def _module(name: str):
    path = ROOT / "scripts" / "simnow_keyless_pilot.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _positions(*, long: int = 0, short: int = 0, short_yd: int = 0) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for direction, volume in (("LONG", long), ("SHORT", short)):
        rows[f"ru2609.SHFE.{direction}"] = {
            "gateway_name": "CTP",
            "exchange": "SHFE",
            "symbol": "ru2609",
            "direction": direction,
            "volume": volume,
            "yd_volume": short_yd if direction == "SHORT" else 0,
            "price": 3500.0,
        }
    return rows


def test_pilot_cli_accepts_only_fixed_target_and_no_source_selection_inputs() -> None:
    module = _module("simnow_keyless_pilot_cli")
    parser = module.build_parser()
    target = parser.parse_args(
        [
            "--target",
            "SHORT1",
            "--peek-current-facts",
            "peek.json",
            "--reconciliation-state",
            "reconcile.json",
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--principal",
            "pilot-admin",
            "--operator",
            "pilot-admin",
            "--idempotency-suffix",
            "pilot-0001",
            "--expected-custody-version",
            "0",
        ]
    )
    assert target.target == "SHORT1"
    for forbidden in (
        "--product",
        "--contract",
        "--qty",
        "--map-source",
        "--c-fast-source",
    ):
        with pytest.raises(SystemExit):
            parser.parse_args([forbidden, "x"])
    source = (ROOT / "scripts/simnow_keyless_pilot.py").read_text(encoding="utf-8")
    assert 'status["broker"]["snapshot_id"]' not in source
    assert source.count('status["reconciliation"]["fresh_snapshot_id"]') == 2
    assert "simnow_run_once" not in source


def test_pilot_accepts_only_fixed_ru2609_position_rows_and_empty_short1_facts() -> None:
    module = _module("simnow_keyless_pilot_projection")
    module._require_fixed_position_rows({})
    module._require_fixed_position_rows(_positions())
    rows = _positions()
    rows["au2601.SHFE.LONG"] = {
        "gateway_name": "CTP",
        "exchange": "SHFE",
        "symbol": "au2601",
        "direction": "LONG",
        "volume": 0,
        "yd_volume": 0,
        "price": 1.0,
    }
    with pytest.raises(ValueError, match="fixed ru2609"):
        module._require_fixed_position_rows(rows)


def _write_formal_tick_state(
    module,
    root: Path,
    *,
    vt_symbol: str = "ru2609.SHFE",
    event_time_utc: str = "2030-01-01T00:00:00Z",
    last_price: float | None = 3700.0,
    source: str = "windows-tick-wire-v1",
) -> None:
    from phase_b_workers.contracts import VerifiedTick
    from phase_b_workers.durable import AtomicCheckpoint, DurableVerifiedTickStream
    from phase_b_workers.projections import build_projection, publish_projection

    tick = VerifiedTick.from_raw(
        {
            "ask_price": 3701.0,
            "ask_volume": 1.0,
            "bid_price": 3699.0,
            "bid_volume": 1.0,
            "event_time_utc": event_time_utc,
            "last_price": last_price,
            "last_volume": 1.0,
            "source_event_id": "tick-event-0001",
            "vt_symbol": vt_symbol,
        },
        stream_generation="tick-generation-0001",
        ingest_seq=1,
        source=source,
        received_at=datetime.fromisoformat(event_time_utc.replace("Z", "+00:00")),
    )
    stream = DurableVerifiedTickStream(
        root / "stream", generation="tick-generation-0001"
    )
    stream.initialize()
    stream.append(tick)
    stream.acknowledge_tick_write(tick)
    AtomicCheckpoint(root / "source_fence.json").write(
        {
            "worker_generation": "tick-generation-0001",
            "sources": {
                "windows-tick-wire-v1": {
                    "generation": "source-generation-0001",
                    "seq": 1,
                    "event_hash": "a" * 64,
                }
            },
            "events": {},
        }
    )
    publish_projection(
        root / "projection",
        build_projection(
            service_id="market-data-worker",
            generation="test-revision:tick-generation-0001",
            health={
                "service_id": "market-data-worker",
                "status": "healthy",
                "dependencies": {"verified_stream": stream.stats()},
            },
            readiness={"service_id": "market-data-worker", "ready": True},
            version={
                "service_id": "market-data-worker",
                "contract_versions": ["phase_b_worker_contract_v1"],
            },
        ),
    )


def _append_formal_tick(root: Path, *, vt_symbol: str, source_event_id: str) -> None:
    from phase_b_workers.contracts import VerifiedTick
    from phase_b_workers.durable import AtomicCheckpoint, DurableVerifiedTickStream
    from phase_b_workers.projections import build_projection, publish_projection

    generation = "tick-generation-0001"
    stream = DurableVerifiedTickStream(root / "stream", generation=generation)
    sequence = int(
        AtomicCheckpoint(root / "stream" / "producer_watermark.json", read_only=True)
        .read()["last_ingest_seq"]
    ) + 1
    tick = VerifiedTick.from_raw(
        {
            "event_time_utc": "2030-01-01T00:00:00Z",
            "last_price": 3700.0,
            "source_event_id": source_event_id,
            "vt_symbol": vt_symbol,
        },
        stream_generation=generation,
        ingest_seq=sequence,
        source="windows-tick-wire-v1",
        received_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    stream.append(tick)
    stream.acknowledge_tick_write(tick)
    AtomicCheckpoint(root / "source_fence.json").write(
        {
            "worker_generation": generation,
            "sources": {
                "windows-tick-wire-v1": {
                    "generation": "source-generation-0001",
                    "seq": sequence,
                    "event_hash": "a" * 64,
                }
            },
            "events": {},
        }
    )
    publish_projection(
        root / "projection",
        build_projection(
            service_id="market-data-worker",
            generation="test-revision:" + generation,
            health={
                "service_id": "market-data-worker",
                "status": "healthy",
                "dependencies": {"verified_stream": stream.stats()},
            },
            readiness={"service_id": "market-data-worker", "ready": True},
            version={
                "service_id": "market-data-worker",
                "contract_versions": ["phase_b_worker_contract_v1"],
            },
        ),
    )


def test_pilot_requires_fresh_canonical_fixed_ctp_tick_for_reference_price(
    tmp_path: Path,
) -> None:
    module = _module("simnow_keyless_pilot_formal_tick")
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    _write_formal_tick_state(module, tmp_path)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(module, "_FORMAL_MARKET_STATE_DIR", tmp_path)
    monkeypatch.setattr(module, "_FORMAL_MARKET_PROJECTION_DIR", tmp_path / "projection")
    try:
        assert module._formal_tick_binding(clock=lambda: now)[-1] == 3700.0
        _write_formal_tick_state(
            module, tmp_path / "forged", source="readonly_market_source"
        )
        monkeypatch.setattr(module, "_FORMAL_MARKET_STATE_DIR", tmp_path / "forged")
        monkeypatch.setattr(
            module, "_FORMAL_MARKET_PROJECTION_DIR", tmp_path / "forged" / "projection"
        )
        with pytest.raises(ValueError, match="durable tick state"):
            module._formal_tick_binding(clock=lambda: now)
        _write_formal_tick_state(
            module, tmp_path / "stale", event_time_utc="2029-12-31T23:59:57Z"
        )
        monkeypatch.setattr(module, "_FORMAL_MARKET_STATE_DIR", tmp_path / "stale")
        monkeypatch.setattr(
            module, "_FORMAL_MARKET_PROJECTION_DIR", tmp_path / "stale" / "projection"
        )
        with pytest.raises(ValueError, match="stale"):
            module._formal_tick_binding(clock=lambda: now)
        _write_formal_tick_state(module, tmp_path / "fence")
        from phase_b_workers.durable import AtomicCheckpoint

        AtomicCheckpoint(tmp_path / "fence" / "source_fence.json").write(
            {"worker_generation": "wrong", "sources": {}, "events": {}}
        )
        monkeypatch.setattr(module, "_FORMAL_MARKET_STATE_DIR", tmp_path / "fence")
        monkeypatch.setattr(
            module, "_FORMAL_MARKET_PROJECTION_DIR", tmp_path / "fence" / "projection"
        )
        with pytest.raises(ValueError, match="durable tick state"):
            module._formal_tick_binding(clock=lambda: now)
    finally:
        monkeypatch.undo()


def test_pilot_waits_for_projection_watermark_to_converge(tmp_path: Path) -> None:
    module = _module("simnow_keyless_pilot_projection_wait")
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    _write_formal_tick_state(module, tmp_path)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(module, "_FORMAL_MARKET_STATE_DIR", tmp_path)
    monkeypatch.setattr(module, "_FORMAL_MARKET_PROJECTION_DIR", tmp_path / "projection")
    original = module._formal_market_checkpoint
    calls = 0

    def delayed_checkpoint():
        nonlocal calls
        calls += 1
        if calls <= 3:
            raise ValueError("formal CTP watermark/projection is invalid")
        return original()

    monkeypatch.setattr(module, "_formal_market_checkpoint", delayed_checkpoint)
    try:
        assert module._formal_tick_binding(clock=lambda: now)[-1] == 3700.0
        assert calls == 5
    finally:
        monkeypatch.undo()


def test_pilot_rejects_projection_watermark_that_never_converges(tmp_path: Path) -> None:
    module = _module("simnow_keyless_pilot_projection_wait_timeout")
    _write_formal_tick_state(module, tmp_path)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(module, "_FORMAL_MARKET_STATE_DIR", tmp_path)
    monkeypatch.setattr(module, "_FORMAL_MARKET_PROJECTION_DIR", tmp_path / "projection")
    calls = 0

    def mismatched_checkpoint():
        nonlocal calls
        calls += 1
        raise ValueError("formal CTP watermark/projection is invalid")

    monkeypatch.setattr(module, "_formal_market_checkpoint", mismatched_checkpoint)
    monkeypatch.setattr(module, "_FORMAL_TICK_SNAPSHOT_MAX_WAIT_SECONDS", 0.01)
    monkeypatch.setattr(module, "_FORMAL_TICK_SNAPSHOT_RETRY_SECONDS", 0.001)
    try:
        with pytest.raises(ValueError, match="durable tick state"):
            module._formal_tick_binding(
                clock=lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
            )
        assert calls > 1
    finally:
        monkeypatch.undo()


@pytest.mark.parametrize(
    "artifact",
    [
        "projection",
        "watermark",
        "fence",
        "ack",
        "ack_removed",
        "ack_frontier",
        "ack_gap",
        "selected_ack_missing",
        "events",
        "tail",
    ],
)
def test_pilot_rejects_tampered_formal_tick_state(
    tmp_path: Path, artifact: str
) -> None:
    from phase_b_workers.contracts import canonical_json, sha256_hex
    from phase_b_workers.durable import AtomicCheckpoint

    module = _module(f"simnow_keyless_pilot_tamper_{artifact}")
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    _write_formal_tick_state(module, tmp_path)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(module, "_FORMAL_MARKET_STATE_DIR", tmp_path)
    monkeypatch.setattr(module, "_FORMAL_MARKET_PROJECTION_DIR", tmp_path / "projection")
    try:
        if artifact == "projection":
            path = tmp_path / "projection" / "market-data-worker.json"
            value = AtomicCheckpoint(path, read_only=True).read()
            value["payload_sha256"] = "0" * 64
            AtomicCheckpoint(path).write(value)
        elif artifact == "watermark":
            path = tmp_path / "stream" / "producer_watermark.json"
            value = AtomicCheckpoint(path, read_only=True).read()
            value["last_ingest_seq"] = 2
            AtomicCheckpoint(path).write(value)
        elif artifact == "fence":
            path = tmp_path / "source_fence.json"
            value = AtomicCheckpoint(path, read_only=True).read()
            value["worker_generation"] = "other-generation"
            AtomicCheckpoint(path).write(value)
        elif artifact == "events":
            path = tmp_path / "projection" / "market-data-worker.json"
            value = AtomicCheckpoint(path, read_only=True).read()
            stream = value["payload"]["health"]["dependencies"]["verified_stream"]
            stream["events"] = 2
            value["payload_sha256"] = sha256_hex(value["payload"])
            AtomicCheckpoint(path).write(value)
        elif artifact == "ack_removed":
            path = tmp_path / "stream" / "tick_writer_acks.jsonl"
            path.write_bytes(b"")
        elif artifact == "ack_frontier":
            path = tmp_path / "stream" / "tick_writer_acks.jsonl"
            record = json.loads(path.read_text(encoding="utf-8"))
            record["event_hash"] = "b" * 64
            path.write_text(canonical_json(record) + "\n", encoding="utf-8")
        elif artifact in {"ack_gap", "selected_ack_missing"}:
            _append_formal_tick(
                tmp_path, vt_symbol="au2601.SHFE", source_event_id="tick-event-0002"
            )
            if artifact == "ack_gap":
                _append_formal_tick(
                    tmp_path,
                    vt_symbol="au2601.SHFE",
                    source_event_id="tick-event-0003",
                )
                drop_sequence = 2
            else:
                drop_sequence = 1
            path = tmp_path / "stream" / "tick_writer_acks.jsonl"
            retained = [
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if json.loads(line)["ingest_seq"] != drop_sequence
            ]
            path.write_text("\n".join(retained) + "\n", encoding="utf-8")
        else:
            name = "tick_writer_acks.jsonl" if artifact == "ack" else "verified_ticks.jsonl"
            path = tmp_path / "stream" / name
            path.write_bytes(path.read_bytes() + b"{}\n")
        with pytest.raises(ValueError, match="durable tick state"):
            module._formal_tick_binding(clock=lambda: now)
    finally:
        monkeypatch.undo()


def test_pilot_reads_a_fresh_tail_without_replaying_310k_history(tmp_path: Path) -> None:
    from phase_b_workers.contracts import VerifiedTick, canonical_json
    from phase_b_workers.durable import AtomicCheckpoint, DurableVerifiedTickStream
    from phase_b_workers.projections import build_projection, publish_projection

    module = _module("simnow_keyless_pilot_bounded_tail")
    generation = "tick-generation-310k"
    stream = DurableVerifiedTickStream(tmp_path / "stream", generation=generation)
    stream.initialize()
    journal = tmp_path / "stream" / "verified_ticks.jsonl"
    acknowledgements = tmp_path / "stream" / "tick_writer_acks.jsonl"
    total = 310_000
    with journal.open("wb") as journal_file, acknowledgements.open("wb") as ack_file:
        for sequence in range(1, total + 1):
            tick = VerifiedTick.from_raw(
                {
                    "event_time_utc": "2029-12-31T23:00:00Z",
                    "last_price": 3600.0 + sequence / 1_000_000,
                    "source_event_id": f"history-{sequence}",
                    "vt_symbol": "au2601.SHFE",
                },
                stream_generation=generation,
                ingest_seq=sequence,
                source="windows-tick-wire-v1",
                received_at=datetime(2029, 12, 31, 23, tzinfo=timezone.utc),
            )
            journal_file.write(
                (canonical_json({"record_type": "verified_tick", "tick": tick.as_dict()}) + "\n").encode()
            )
            ack_file.write(
                (
                    canonical_json(
                        {
                            "ingest_id": tick.ingest_id,
                            "stream_generation": generation,
                            "ingest_seq": sequence,
                            "event_hash": tick.event_hash,
                        }
                    )
                    + "\n"
                ).encode()
            )
        current = VerifiedTick.from_raw(
            {
                "event_time_utc": "2030-01-01T00:00:00Z",
                "last_price": 3700.0,
                "source_event_id": "current-ru2609",
                "vt_symbol": "ru2609.SHFE",
            },
            stream_generation=generation,
            ingest_seq=total + 1,
            source="windows-tick-wire-v1",
            received_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
        journal_file.write(
            (canonical_json({"record_type": "verified_tick", "tick": current.as_dict()}) + "\n").encode()
        )
        ack_file.write(
            (
                canonical_json(
                    {
                        "ingest_id": current.ingest_id,
                        "stream_generation": generation,
                        "ingest_seq": current.ingest_seq,
                        "event_hash": current.event_hash,
                    }
                )
                + "\n"
            ).encode()
        )
    AtomicCheckpoint(tmp_path / "stream" / "producer_watermark.json").write(
        {
            "stream_generation": generation,
            "last_ingest_seq": total + 1,
            "last_event_hash": current.event_hash,
        }
    )
    AtomicCheckpoint(tmp_path / "source_fence.json").write(
        {
            "worker_generation": generation,
            "sources": {
                "windows-tick-wire-v1": {
                    "generation": "source-generation-310k",
                    "seq": total + 1,
                    "event_hash": "a" * 64,
                }
            },
            "events": {},
        }
    )
    publish_projection(
        tmp_path / "projection",
        build_projection(
            service_id="market-data-worker",
            generation="test-revision:" + generation,
            health={
                "service_id": "market-data-worker",
                "status": "healthy",
                "dependencies": {
                    "verified_stream": {
                        "stream_generation": generation,
                        "events": total + 1,
                        "last_ingest_seq": total + 1,
                        "pending_writer_acks": 0,
                    }
                },
            },
            readiness={"service_id": "market-data-worker", "ready": True},
            version={
                "service_id": "market-data-worker",
                "contract_versions": ["phase_b_worker_contract_v1"],
            },
        ),
    )
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(module, "_FORMAL_MARKET_STATE_DIR", tmp_path)
    monkeypatch.setattr(module, "_FORMAL_MARKET_PROJECTION_DIR", tmp_path / "projection")
    try:
        started = time.monotonic()
        binding = module._formal_tick_binding(
            clock=lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
        )
        assert time.monotonic() - started < 2.0
        assert binding[1:3] == ("current-ru2609", total + 1)
    finally:
        monkeypatch.undo()


@pytest.mark.parametrize(
    ("target", "long", "short", "short_yd", "direction", "offset"),
    [
        ("SHORT1", 0, 0, 0, "SHORT", "OPEN"),
        ("FLAT", 0, 1, 0, "LONG", "CLOSETODAY"),
        ("FLAT", 0, 1, 1, "LONG", "CLOSEYESTERDAY"),
    ],
)
def test_pilot_builds_only_short1_open_or_flat_close(
    target: str,
    long: int,
    short: int,
    short_yd: int,
    direction: str,
    offset: str,
) -> None:
    module = _module(f"simnow_keyless_pilot_{target}")
    plan = module._pilot_target_plan(
        positions=_positions(long=long, short=short, short_yd=short_yd),
        long_volume=long,
        short_volume=short,
        matching=[
            (key, row)
            for key, row in _positions(
                long=long, short=short, short_yd=short_yd
            ).items()
        ],
        target=target,
        price=3700.0,
        expires_at="2099-01-01T00:00:00Z",
        generated_at="2030-01-01T00:00:00Z",
    )
    assert plan["scope"] == {
        "account_scope": "account:windows",
        "environment": "SIMNOW",
        "gateway_name": "CTP",
    }
    assert plan["orders"][0]["direction"] == direction
    assert plan["orders"][0]["offset"] == offset
    assert plan["orders"][0]["volume"] == 1
    assert plan["orders"][0]["symbol"] == "ru2609"
    assert plan["orders"][0]["exchange"] == "SHFE"


def test_pilot_rejects_hedged_long1_short1_for_flat() -> None:
    module = _module("simnow_keyless_pilot_hedged_flat")
    with pytest.raises(ValueError, match="exactly one short"):
        module._pilot_target_plan(
            positions=_positions(long=1, short=1),
            long_volume=1,
            short_volume=1,
            matching=[(key, row) for key, row in _positions(long=1, short=1).items()],
            target="FLAT",
            price=3700.0,
            expires_at="2099-01-01T00:00:00Z",
            generated_at="2030-01-01T00:00:00Z",
        )
    assert not module._is_exact_target_gross(
        target="FLAT", long_volume=1, short_volume=1
    )


def test_runner_packages_and_loads_frozen_execution_status_schema() -> None:
    from app.schemas.control_execution import _SCHEMA_PATH, _STATUS_VALIDATOR

    expected = ROOT / "docs/schemas/web-bridge-execution-status-v1.schema.json"
    containerfile = (
        ROOT / "deployments/phase-b/Containerfile.simnow-runner"
    ).read_text(encoding="utf-8")
    assert _SCHEMA_PATH == expected
    assert _SCHEMA_PATH.is_file()
    assert _STATUS_VALIDATOR.schema == json.loads(expected.read_text(encoding="utf-8"))
    assert (
        "COPY docs/schemas/web-bridge-execution-status-v1.schema.json "
        "/app/docs/schemas/web-bridge-execution-status-v1.schema.json"
    ) in containerfile


def test_pilot_requires_execution_status_to_bind_peek_position_hash() -> None:
    module = _module("simnow_keyless_pilot_snapshot_binding")
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    status = _execution_status(position_hash="a" * 64).as_dict()
    module._require_execution_hard_gates(
        status, expected_position_snapshot_hash="a" * 64, clock=lambda: now
    )
    with pytest.raises(ValueError, match="snapshot binding"):
        module._require_execution_hard_gates(
            status, expected_position_snapshot_hash="b" * 64, clock=lambda: now
        )


def test_pilot_rejects_stale_or_naive_execution_status_timestamps() -> None:
    module = _module("simnow_keyless_pilot_status_freshness")
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="stale"):
        module._require_execution_hard_gates(
            _execution_status(
                position_hash="a" * 64, timestamp="2029-12-31T23:26:40Z"
            ).as_dict(),
            expected_position_snapshot_hash="a" * 64,
            clock=lambda: now,
        )
    with pytest.raises(ValueError, match="explicit UTC"):
        module._fresh_utc("2030-01-01T00:00:00", label="test", now=now)
    module._require_execution_hard_gates(
        _execution_status(position_hash="a" * 64).as_dict(),
        expected_position_snapshot_hash="a" * 64,
        clock=lambda: now,
    )


def _pilot_args() -> argparse.Namespace:
    return argparse.Namespace(
        target="SHORT1",
        peek_current_facts=Path("peek.json"),
        reconciliation_state=Path("reconcile.json"),
        expires_at="2099-01-01T00:00:00Z",
        principal="pilot-admin",
        operator="pilot-admin",
        idempotency_suffix="pilot-0001",
        expected_custody_version=0,
        execute=True,
        completion_timeout_seconds=1.0,
        completion_poll_seconds=0.1,
    )


def _stub_pilot_build(
    module, monkeypatch: pytest.MonkeyPatch, *, position_hash: str
) -> None:
    monkeypatch.setattr(module, "_object", lambda _path, _label: {})
    monkeypatch.setattr(module, "_require_reconciliation", lambda _value: None)
    monkeypatch.setattr(
        module,
        "peek_current_facts_to_snapshot",
        lambda *_args, **_kwargs: type(
            "Peek",
            (),
            {
                "snapshot": type(
                    "Snapshot",
                    (),
                    {"positions": {}, "position_snapshot_hash": position_hash},
                )()
            },
        )(),
    )
    monkeypatch.setattr(module, "_require_fixed_position_rows", lambda _positions: None)
    monkeypatch.setattr(
        module, "_current_position", lambda *_args, **_kwargs: (0, 0, [])
    )
    monkeypatch.setattr(
        module,
        "_formal_tick_binding",
        lambda **_kwargs: ("tick-generation", "tick", 1, "a" * 64, "2030-01-01T00:00:00Z", 3700.0),
    )
    monkeypatch.setattr(
        module,
        "_pilot_target_plan",
        lambda **_kwargs: {
            "plan_id": "plan-0001",
            "plan_hash": "b" * 64,
            "generated_at": "2030-01-01T00:00:00Z",
            "scope": {},
            "expires_at": "2099-01-01T00:00:00Z",
            "expected_after_position_hash": "c" * 64,
        },
    )
    monkeypatch.setattr(module, "new_artifact_envelope", lambda **_kwargs: {})


def test_pilot_rechecks_live_clock_after_custody_before_preview(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("simnow_keyless_pilot_post_custody_freshness")
    position_hash = module.sha256_json({})
    _stub_pilot_build(module, monkeypatch, position_hash=position_hash)
    monkeypatch.setattr(
        module,
        "_formal_tick_binding",
        lambda **_kwargs: (
            "tick-generation",
            "tick",
            1,
            "a" * 64,
            "2030-01-01T00:00:58Z",
            3700.0,
        ),
    )
    statuses = _execution_status(
        position_hash=position_hash, timestamp="2030-01-01T00:00:00Z"
    )
    custody_calls: list[str] = []
    clocks = iter(
        [
            datetime(2030, 1, 1, 0, 0, 59, tzinfo=timezone.utc),
            datetime(2030, 1, 1, 0, 0, 59, tzinfo=timezone.utc),
            datetime(2030, 1, 1, 0, 0, 59, tzinfo=timezone.utc),
            datetime(2030, 1, 1, 0, 0, 59, tzinfo=timezone.utc),
            datetime(2030, 1, 1, 0, 1, 1, tzinfo=timezone.utc),
        ]
    )

    class FakeExecution:
        async def status(self):
            return statuses

    class FakeCustody:
        def install_trusted_keyless_target_plan(self, _upload):
            custody_calls.append("custody")
            return type(
                "Receipt",
                (),
                {"receipt_id": "receipt-0001", "artifact_sha256": "a" * 64},
            )()

    monkeypatch.setattr(module, "_now", lambda: "2030-01-01T00:00:59Z")
    monkeypatch.setattr(module, "_utc_clock", lambda: next(clocks))
    monkeypatch.setattr(module, "ExecutionClient", FakeExecution)
    monkeypatch.setattr(module, "RemotePhaseCWorkflowClient", FakeCustody)

    with pytest.raises(ValueError, match="stale"):
        asyncio.run(module.run(_pilot_args()))
    assert custody_calls == ["custody"]


def test_pilot_rejects_state_version_change_before_custody_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("simnow_keyless_pilot_state_version")
    position_hash = module.sha256_json({})
    _stub_pilot_build(module, monkeypatch, position_hash=position_hash)
    statuses = iter(
        [
            _execution_status(position_hash=position_hash, state_version=3),
            _execution_status(position_hash=position_hash, state_version=4),
        ]
    )
    custody_calls: list[str] = []

    class FakeExecution:
        async def status(self):
            return next(statuses)

    class FakeCustody:
        def install_trusted_keyless_target_plan(self, _upload):
            custody_calls.append("custody")
            raise AssertionError("custody must not be reached")

    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(module, "_now", lambda: "2030-01-01T00:00:00Z")
    monkeypatch.setattr(module, "_utc_clock", lambda: now)
    monkeypatch.setattr(module, "ExecutionClient", FakeExecution)
    monkeypatch.setattr(module, "RemotePhaseCWorkflowClient", FakeCustody)

    with pytest.raises(ValueError, match="status changed"):
        asyncio.run(module.run(_pilot_args()))
    assert custody_calls == []


def test_pilot_rechecks_the_same_fresh_durable_tick_before_custody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("simnow_keyless_pilot_tick_changed_before_custody")
    position_hash = module.sha256_json({})
    _stub_pilot_build(module, monkeypatch, position_hash=position_hash)
    bindings = iter(
        [
            ("tick-generation", "tick-1", 1, "a" * 64, "2030-01-01T00:00:00Z", 3700.0),
            ("tick-generation", "tick-1", 1, "b" * 64, "2030-01-01T00:00:00Z", 3701.0),
        ]
    )
    monkeypatch.setattr(
        module, "_formal_tick_binding", lambda **_kwargs: next(bindings)
    )

    class FakeExecution:
        async def status(self):
            return _execution_status(position_hash=position_hash)

    monkeypatch.setattr(module, "ExecutionClient", FakeExecution)
    monkeypatch.setattr(
        module,
        "RemotePhaseCWorkflowClient",
        lambda: pytest.fail("changed tick must block custody"),
    )
    monkeypatch.setattr(module, "_now", lambda: "2030-01-01T00:00:00Z")
    monkeypatch.setattr(
        module, "_utc_clock", lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
    )
    with pytest.raises(ValueError, match="tick changed"):
        asyncio.run(module.run(_pilot_args()))


def test_pilot_tick_boundary_accepts_a_newer_same_generation_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("simnow_keyless_pilot_tick_advance")
    initial = (
        "tick-generation",
        "tick-1",
        1,
        "a" * 64,
        "2030-01-01T00:00:00Z",
        3700.0,
    )
    monkeypatch.setattr(
        module,
        "_formal_tick_binding",
        lambda **_kwargs: (
            "tick-generation",
            "tick-2",
            2,
            "b" * 64,
            "2030-01-01T00:00:01Z",
            3701.0,
        ),
    )
    module._require_tick_boundary(
        initial, clock=lambda: datetime(2030, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("active_order_count", 1),
        ("unknown_outcomes", 1),
        ("position_snapshot_hash", "f" * 64),
    ],
)
def test_pilot_refuses_start_when_execution_hard_gates_change_after_enable(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    module = _module(f"simnow_keyless_pilot_start_hard_gate_{field}")
    position_hash = module.sha256_json({})
    _stub_pilot_build(module, monkeypatch, position_hash=position_hash)
    commands: list[str] = []
    enabled = False

    class FakeExecution:
        async def status(self):
            projection = _execution_status(position_hash=position_hash).as_dict()
            if enabled:
                if field == "unknown_outcomes":
                    projection["reconciliation"][field] = value
                else:
                    projection["broker"][field] = value
            from app.schemas.control_execution import ExecutionStatusProjection

            return ExecutionStatusProjection.model_validate(projection)

        async def submit(self, command):
            nonlocal enabled
            commands.append(command["command"])
            if command["command"] == "enable":
                enabled = True
            return {"accepted": True}

    class FakeCustody:
        def install_trusted_keyless_target_plan(self, _upload):
            return type(
                "Receipt",
                (),
                {"receipt_id": "receipt-0001", "artifact_sha256": "a" * 64},
            )()

    monkeypatch.setattr(module, "ExecutionClient", FakeExecution)
    monkeypatch.setattr(module, "RemotePhaseCWorkflowClient", FakeCustody)
    monkeypatch.setattr(module, "_now", lambda: "2030-01-01T00:00:00Z")
    monkeypatch.setattr(
        module, "_utc_clock", lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
    )
    with pytest.raises(ValueError, match="hard gates|snapshot binding"):
        asyncio.run(module.run(_pilot_args()))
    assert commands == ["preview", "reconcile", "enable"]


def test_pilot_noop_does_not_create_custody_or_execution_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("simnow_keyless_pilot_noop")
    facts = {
        "schema_version": "windows_execution_current_facts_v1",
        "position_query_complete": True,
        "account": {"CTP.sim": {"gateway_name": "CTP"}},
        "positions": _positions(short=1),
        "active_orders": {},
        "gateway": {
            "gateway_name": "CTP",
            "account_scope": "account:windows",
            "environment": "simnow",
            "connected": True,
        },
        "execution": {"orders": {}},
        "admission": {
            "account_scope": "account:windows",
            "environment": "simnow",
            "durable_state_version": 0,
            "durable_state_hash": "0" * 64,
            "snapshot_generation": 0,
            "fence": {
                "active": False,
                "current_epoch": 0,
                "current_fencing_token": 0,
                "high_water_epoch": 0,
                "high_water_fencing_token": 0,
            },
            "receipt_intents": [],
        },
    }
    monkeypatch.setattr(
        module,
        "_object",
        lambda _path, label: (
            facts
            if label == "peek current facts"
            else {"state": "RECONCILED", "unknown_outcomes": 0}
        ),
    )
    status_calls: list[str] = []
    position_hash = module.sha256_json(_positions(short=1))

    class FakeExecution:
        async def status(self):
            status_calls.append("status")
            return _execution_status(position_hash=position_hash)

    monkeypatch.setattr(
        module,
        "ExecutionClient",
        FakeExecution,
    )
    monkeypatch.setattr(
        module,
        "RemotePhaseCWorkflowClient",
        lambda: pytest.fail("NOOP must not construct custody client"),
    )
    monkeypatch.setattr(
        module,
        "_formal_tick_binding",
        lambda **_kwargs: ("tick-generation", "tick", 1, "a" * 64, "2030-01-01T00:00:00Z", 3700.0),
    )
    monkeypatch.setattr(module, "_now", lambda: "2030-01-01T00:00:00Z")
    monkeypatch.setattr(
        module, "_utc_clock", lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
    )
    result = asyncio.run(module.run(_pilot_args()))
    assert result["no_op"] is True
    assert result["reason"] == "target_already_current"
    assert status_calls == ["status"]


def test_pilot_noop_rejects_dirty_execution_status_before_custody(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.schemas.control_execution import ExecutionStatusProjection

    module = _module("simnow_keyless_pilot_noop_dirty_status")
    positions = _positions(short=1)
    facts = {
        "schema_version": "windows_execution_current_facts_v1",
        "position_query_complete": True,
        "account": {"CTP.sim": {"gateway_name": "CTP"}},
        "positions": positions,
        "active_orders": {},
        "gateway": {
            "gateway_name": "CTP",
            "account_scope": "account:windows",
            "environment": "simnow",
            "connected": True,
        },
        "execution": {"orders": {}},
        "admission": {
            "account_scope": "account:windows",
            "environment": "simnow",
            "durable_state_version": 0,
            "durable_state_hash": "0" * 64,
            "snapshot_generation": 0,
            "fence": {
                "active": False,
                "current_epoch": 0,
                "current_fencing_token": 0,
                "high_water_epoch": 0,
                "high_water_fencing_token": 0,
            },
            "receipt_intents": [],
        },
    }
    dirty = _execution_status(position_hash=module.sha256_json(positions)).as_dict()
    dirty["broker"]["active_order_count"] = 1

    class FakeExecution:
        async def status(self):
            return ExecutionStatusProjection.model_validate(dirty)

    monkeypatch.setattr(
        module,
        "_object",
        lambda _path, label: (
            facts
            if label == "peek current facts"
            else {"state": "RECONCILED", "unknown_outcomes": 0}
        ),
    )
    monkeypatch.setattr(module, "ExecutionClient", FakeExecution)
    monkeypatch.setattr(
        module,
        "RemotePhaseCWorkflowClient",
        lambda: pytest.fail("dirty NOOP must not construct custody client"),
    )
    monkeypatch.setattr(
        module,
        "_formal_tick_binding",
        lambda **_kwargs: ("tick-generation", "tick", 1, "a" * 64, "2030-01-01T00:00:00Z", 3700.0),
    )
    monkeypatch.setattr(module, "_now", lambda: "2030-01-01T00:00:00Z")
    monkeypatch.setattr(
        module, "_utc_clock", lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
    )

    with pytest.raises(ValueError, match="hard gates"):
        asyncio.run(module.run(_pilot_args()))


def test_pilot_start_uncertainty_never_retries_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module("simnow_keyless_pilot_start_uncertainty")
    commands: list[dict] = []
    status = _execution_status(position_hash=module.sha256_json({}))
    monkeypatch.setattr(module, "_now", lambda: "2030-01-01T00:00:00Z")
    monkeypatch.setattr(
        module, "_utc_clock", lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
    )

    class FakeExecution:
        async def status(self):
            return status

        async def submit(self, command):
            commands.append(command)
            if command["command"] == "start":
                raise module.ExecutionClientError("timeout")
            return {"accepted": True}

    class FakeCustody:
        def install_trusted_keyless_target_plan(self, _upload):
            return type(
                "Receipt",
                (),
                {"receipt_id": "receipt-0001", "artifact_sha256": "a" * 64},
            )()

    monkeypatch.setattr(module, "_object", lambda _path, _label: {})
    monkeypatch.setattr(module, "_require_reconciliation", lambda _value: None)
    monkeypatch.setattr(
        module,
        "peek_current_facts_to_snapshot",
        lambda *_args, **_kwargs: type(
            "Peek",
            (),
            {
                "snapshot": type(
                    "Snapshot",
                    (),
                    {
                        "positions": {},
                        "position_snapshot_hash": module.sha256_json({}),
                    },
                )()
            },
        )(),
    )
    monkeypatch.setattr(module, "_require_fixed_position_rows", lambda _positions: None)
    monkeypatch.setattr(
        module, "_current_position", lambda *_args, **_kwargs: (0, 0, [])
    )
    monkeypatch.setattr(
        module,
        "_formal_tick_binding",
        lambda **_kwargs: ("tick-generation", "tick", 1, "a" * 64, "2030-01-01T00:00:00Z", 3700.0),
    )
    monkeypatch.setattr(
        module,
        "_pilot_target_plan",
        lambda **_kwargs: {
            "plan_id": "plan-0001",
            "plan_hash": "b" * 64,
            "generated_at": "2030-01-01T00:00:00Z",
            "scope": {},
            "expires_at": "2099-01-01T00:00:00Z",
            "expected_after_position_hash": "c" * 64,
        },
    )
    monkeypatch.setattr(module, "new_artifact_envelope", lambda **_kwargs: {})
    monkeypatch.setattr(module, "ExecutionClient", FakeExecution)
    monkeypatch.setattr(module, "RemotePhaseCWorkflowClient", FakeCustody)
    args = argparse.Namespace(
        target="SHORT1",
        peek_current_facts=Path("peek.json"),
        reconciliation_state=Path("reconcile.json"),
        expires_at="2099-01-01T00:00:00Z",
        principal="pilot-admin",
        operator="pilot-admin",
        idempotency_suffix="pilot-0001",
        expected_custody_version=0,
        execute=True,
        completion_timeout_seconds=1.0,
        completion_poll_seconds=0.1,
    )

    result = asyncio.run(module.run(args))

    assert result["reason"] == "start_outcome_unknown"
    assert [item["command"] for item in commands] == [
        "preview",
        "reconcile",
        "enable",
        "start",
    ]
    assert commands[1]["payload"]["snapshot_id"] == "snapshot-run-0001"
