from __future__ import annotations

import ast
import json
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from app.execution import formal_tick_reader as reader
from phase_b_workers.contracts import VerifiedTick, canonical_json
from phase_b_workers.durable import (
    AtomicCheckpoint,
    DurableVerifiedTickStream,
)
from phase_b_workers.projections import build_projection, publish_projection
from scripts.ci.classify_changes import classify_phase_a, classify_phase_b

ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def _write_state(
    root: Path,
    *,
    vt_symbol: str = "ru2609.SHFE",
    received_at: datetime = NOW,
    generation: str = "tick-generation-0001",
) -> VerifiedTick:
    tick = VerifiedTick.from_raw(
        {
            "ask_price": 3701.0,
            "ask_volume": 1.0,
            "bid_price": 3699.0,
            "bid_volume": 1.0,
            "event_time_utc": received_at.isoformat().replace("+00:00", "Z"),
            "last_price": 3700.0,
            "last_volume": 1.0,
            "source_event_id": "tick-event-0001",
            "vt_symbol": vt_symbol,
        },
        stream_generation=generation,
        ingest_seq=1,
        source=reader.FORMAL_TICK_SOURCE,
        received_at=received_at,
    )
    stream = DurableVerifiedTickStream(root / "stream", generation=generation)
    stream.initialize()
    stream.append(tick)
    stream.acknowledge_tick_write(tick)
    AtomicCheckpoint(root / "source_fence.json").write(
        {
            "worker_generation": generation,
            "sources": {
                reader.FORMAL_TICK_SOURCE: {
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
            generation=f"test-revision:{generation}",
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
    return tick


def _append_state_tick(root: Path, *, vt_symbol: str) -> VerifiedTick:
    generation = "tick-generation-0001"
    stream = DurableVerifiedTickStream(root / "stream", generation=generation)
    tick = VerifiedTick.from_raw(
        {
            "ask_price": 5001.0,
            "bid_price": 4999.0,
            "event_time_utc": "2030-01-01T00:00:00Z",
            "last_price": 5000.0,
            "source_event_id": "tick-event-0002",
            "vt_symbol": vt_symbol,
        },
        stream_generation=generation,
        ingest_seq=2,
        source=reader.FORMAL_TICK_SOURCE,
        received_at=NOW,
    )
    stream.append(tick)
    stream.acknowledge_tick_write(tick)
    AtomicCheckpoint(root / "source_fence.json").write(
        {
            "worker_generation": generation,
            "sources": {
                reader.FORMAL_TICK_SOURCE: {
                    "generation": "source-generation-0001",
                    "seq": 2,
                    "event_hash": "b" * 64,
                }
            },
            "events": {},
        }
    )
    publish_projection(
        root / "projection",
        build_projection(
            service_id="market-data-worker",
            generation=f"test-revision:{generation}",
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
    return tick


def _read(root: Path, *, symbol: str = "ru2609.SHFE", side: str = "last", tick=0.2):
    return reader.read_formal_tick_binding(
        reader.FormalTickRequest(
            vt_symbol=symbol,
            price_side=side,  # type: ignore[arg-type]
            price_tick=tick,
        ),
        state_dir=root,
        projection_dir=root / "projection",
        clock=lambda: NOW,
    )


def test_reader_returns_strict_exact_contract_side_tick_binding(tmp_path: Path) -> None:
    event = _write_state(tmp_path)
    binding = _read(tmp_path, side="bid")

    assert binding == reader.FormalTickBinding(
        source=reader.FORMAL_TICK_SOURCE,
        vt_symbol="ru2609.SHFE",
        price_side="bid",
        price_tick=0.2,
        stream_generation=event.stream_generation,
        ingest_id=event.ingest_id,
        ingest_seq=event.ingest_seq,
        event_hash=event.event_hash,
        received_at_utc=event.received_at_utc,
        reference_price=3699.0,
    )
    assert set(binding.as_dict()) == {
        "source",
        "vt_symbol",
        "price_side",
        "stream_generation",
        "ingest_id",
        "ingest_seq",
        "event_hash",
        "received_at_utc",
        "reference_price",
        "price_tick",
    }
    with pytest.raises(ValueError, match="sequence"):
        replace(binding, ingest_seq=True)


def test_batch_reader_uses_one_stable_generation_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_state(tmp_path)
    _append_state_tick(tmp_path, vt_symbol="au2609.SHFE")
    requests = (
        reader.FormalTickRequest("ru2609.SHFE", "bid", 0.2),
        reader.FormalTickRequest("au2609.SHFE", "ask", 1.0),
    )
    bindings = reader.read_formal_tick_bindings(
        requests,
        state_dir=tmp_path,
        projection_dir=tmp_path / "projection",
        clock=lambda: NOW,
    )
    assert {item.vt_symbol for item in bindings} == {
        "ru2609.SHFE",
        "au2609.SHFE",
    }
    assert len({item.stream_generation for item in bindings}) == 1

    original = reader._formal_market_checkpoint
    calls = 0

    def generation_crossing(*, state_dir: Path, projection_dir: Path):
        nonlocal calls
        calls += 1
        projection, watermark, fence = original(
            state_dir=state_dir, projection_dir=projection_dir
        )
        if calls == 2:
            watermark = {**watermark, "stream_generation": "foreign-generation"}
        return projection, watermark, fence

    monkeypatch.setattr(reader, "_formal_market_checkpoint", generation_crossing)
    with pytest.raises(reader.FormalTickEvidenceInvalid, match="durable tick state"):
        reader.read_formal_tick_bindings(
            requests,
            state_dir=tmp_path,
            projection_dir=tmp_path / "projection",
            clock=lambda: NOW,
        )
    assert calls == 2


@pytest.mark.parametrize(
    ("symbol", "side", "tick", "message"),
    [
        ("", "last", 0.2, "contract"),
        ("ru2609.SHFE", "mid", 0.2, "reference price"),
        ("ru2609.SHFE", "last", 0.0, "price tick"),
        ("ru2609.SHFE", "last", float("inf"), "price tick"),
    ],
)
def test_reader_rejects_invalid_contract_side_or_tick(
    symbol: str, side: str, tick: float, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        reader.FormalTickRequest(
            vt_symbol=symbol,
            price_side=side,  # type: ignore[arg-type]
            price_tick=tick,
        )


def test_reader_rejects_unaligned_price_and_nonexact_contract_set(
    tmp_path: Path,
) -> None:
    _write_state(tmp_path)
    with pytest.raises(ValueError, match="aligned"):
        _read(tmp_path, tick=0.3)
    with pytest.raises(ValueError, match="durable tick state"):
        _read(tmp_path, symbol="au2609.SHFE")
    request = reader.FormalTickRequest("ru2609.SHFE", "last", 0.2)
    with pytest.raises(ValueError, match="duplicate contracts"):
        reader.read_formal_tick_bindings(
            (request, request),
            state_dir=tmp_path,
            projection_dir=tmp_path / "projection",
            clock=lambda: NOW,
        )


@pytest.mark.parametrize("delta", [timedelta(seconds=-3), timedelta(seconds=3)])
def test_reader_rejects_stale_or_future_tick(tmp_path: Path, delta: timedelta) -> None:
    _write_state(tmp_path, received_at=NOW + delta)
    with pytest.raises(ValueError, match="stale or from the future"):
        _read(tmp_path)


@pytest.mark.parametrize("kind", ["symlink", "nonregular", "mode", "nlink"])
def test_bounded_reader_rejects_unsafe_journal(tmp_path: Path, kind: str) -> None:
    journal = tmp_path / "ticks.jsonl"
    journal.write_text(canonical_json({"ok": True}) + "\n", encoding="utf-8")
    journal.chmod(0o600)
    if kind == "symlink":
        target = tmp_path / "target.jsonl"
        target.write_bytes(journal.read_bytes())
        target.chmod(0o600)
        journal.unlink()
        journal.symlink_to(target)
    elif kind == "nonregular":
        journal.unlink()
        journal.mkdir(mode=0o700)
    elif kind == "mode":
        journal.chmod(0o640)
    else:
        os.link(journal, tmp_path / "second-link.jsonl")

    with pytest.raises(reader.DurableCorruptionError):
        reader._bounded_jsonl_tail(journal)


def test_bounded_reader_rejects_noncanonical_hash_and_ack_splice(
    tmp_path: Path,
) -> None:
    _write_state(tmp_path)
    journal = tmp_path / "stream" / "verified_ticks.jsonl"
    journal.write_bytes(journal.read_bytes() + b'{ "not":"canonical"}\n')
    with pytest.raises(reader.FormalTickEvidenceInvalid) as invalid:
        _read(tmp_path)
    assert invalid.value.code == "EVIDENCE_INVALID"
    assert invalid.value.retryable is False

    other = tmp_path / "other"
    _write_state(other)
    ack = other / "stream" / "tick_writer_acks.jsonl"
    record = json.loads(ack.read_text(encoding="utf-8"))
    record["event_hash"] = "f" * 64
    ack.write_text(canonical_json(record) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="durable tick state"):
        _read(other)


def test_reader_rejects_generation_splice_and_missing_mount(tmp_path: Path) -> None:
    _write_state(tmp_path)
    watermark = tmp_path / "stream" / "producer_watermark.json"
    value = AtomicCheckpoint(watermark, read_only=True).read()
    value["stream_generation"] = "foreign-generation"
    AtomicCheckpoint(watermark).write(value)
    with pytest.raises(reader.FormalTickEvidenceInvalid, match="durable tick state"):
        _read(tmp_path)

    missing = tmp_path / "not-mounted"
    with pytest.raises(reader.FormalTickSourceUnavailable) as unavailable:
        _read(missing)
    assert unavailable.value.code == "SOURCE_UNAVAILABLE"
    assert unavailable.value.retryable is True


def test_reader_rejects_oversize_checkpoint_without_writing(tmp_path: Path) -> None:
    _write_state(tmp_path)
    checkpoint = tmp_path / "projection" / "market-data-worker.json"
    checkpoint.write_bytes(b"x" * (reader._FORMAL_CHECKPOINT_MAX_BYTES + 1))
    checkpoint.chmod(0o600)
    before = checkpoint.stat()

    with pytest.raises(reader.FormalTickEvidenceInvalid):
        _read(tmp_path)

    after = checkpoint.stat()
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )


def test_bounded_reader_rejects_inode_race_and_partial_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = tmp_path / "ticks.jsonl"
    journal.write_text(canonical_json({"ok": True}) + "\n", encoding="utf-8")
    journal.chmod(0o600)
    original = reader._read_bounded_range
    calls = 0

    def replace_after_first_read(descriptor: int, *, offset: int, length: int) -> bytes:
        nonlocal calls
        calls += 1
        raw = original(descriptor, offset=offset, length=length)
        if calls == 1:
            replacement = tmp_path / "replacement.jsonl"
            replacement.write_bytes(raw)
            replacement.chmod(0o600)
            replacement.replace(journal)
        return raw

    with pytest.raises(reader.DurableCorruptionError, match="changed"):
        reader._bounded_jsonl_tail(journal, read_range=replace_after_first_read)

    journal.write_bytes(canonical_json({"ok": True}).encode() + b"\n{")
    journal.chmod(0o600)
    with pytest.raises(reader.RetryableFormalTickTail, match="partial"):
        reader._bounded_jsonl_tail(journal)


def test_reader_packaging_is_read_only_and_has_no_transport_imports() -> None:
    source = (ROOT / "backend/app/execution/formal_tick_reader.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(name.name.split(".")[0] for name in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert not imports.intersection(
        {
            "phase_b_workers",
            "zmq",
            "psycopg",
            "requests",
            "httpx",
            "urllib",
            "socket",
        }
    )
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not called_attributes.intersection(
        {"write", "append", "ack", "acknowledge_tick_write", "initialize", "repair"}
    )
    os_flags = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    }
    assert not os_flags.intersection({"O_CREAT", "O_WRONLY", "O_RDWR"})

    compose = yaml.safe_load(
        (ROOT / "deployments/docker-compose.final.yml").read_text(encoding="utf-8")
    )
    volumes = compose["services"]["execution-orchestrator"]["volumes"]
    assert "market_data_state:/run/market-data:ro" in volumes
    assert "market_projection:/run/market-projection:ro" in volumes
    execution_image = (
        ROOT / "deployments/phase-a/Containerfile.execution-orchestrator"
    ).read_text(encoding="utf-8")
    runner_image = (ROOT / "deployments/phase-b/Containerfile.simnow-runner").read_text(
        encoding="utf-8"
    )
    assert "phase_b_workers" not in execution_image
    assert "execution/formal_tick_reader.py" in runner_image

    changed = "backend/app/execution/formal_tick_reader.py"
    assert classify_phase_a([changed])["selected_units"] == ["execution-orchestrator"]
    assert classify_phase_b([changed])["selected_units"]
