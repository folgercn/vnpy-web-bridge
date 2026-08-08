from __future__ import annotations

import ast
import sys
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent))

from phase_b_workers.contracts import GatewayTickEnvelope, VerifiedTick
from phase_b_workers.durable import (
    AppendOnlyJsonl,
    BackpressureError,
    BoundedIngressQueue,
    DurableCorruptionError,
    DurableStateError,
    DurableVerifiedTickStream,
)
from phase_b_workers.execution_quality_worker import ExecutionQualityWorker
from phase_b_workers.market_data_worker import MarketDataWorker
from phase_b_workers.monitor_worker import MonitorConfig, MonitorWorker, NullNotifier


def envelope(event_id="tick-1", seq=1, **payload):
    return GatewayTickEnvelope.create(event_id=event_id, source_service="gateway-market-reader", source_generation="source-g1", source_seq=seq, observed_at=datetime(2026, 8, 5, tzinfo=timezone.utc), payload={"vt_symbol": "rb2610.SHFE", "bid_price": 100, "ask_price": 102, **payload})


class Writer:
    def __init__(self, fail=False): self.fail, self.events = fail, []
    def write_verified_tick(self, tick):
        if self.fail: raise OSError("writer unavailable")
        self.events.append(tick)


class Notifier:
    def __init__(self, delivered=False): self.delivered, self.events = delivered, []
    def send(self, incident):
        self.events.append(incident)
        return self.delivered


class Projection:
    def __init__(self, *values): self.values = values
    def read(self): return list(self.values)


def test_gateway_contract_rejects_privileged_or_legacy_source():
    value = envelope().as_dict(); value["capability"] = "order.send"
    with pytest.raises(ValueError): GatewayTickEnvelope.from_dict(value)
    value = envelope().as_dict(); value["source_service"] = "vnpy-rpc-service"
    with pytest.raises(ValueError): GatewayTickEnvelope.from_dict(value)


def test_market_sequence_fence_dedup_and_replay(tmp_path):
    writer = Writer(); worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer); worker.recover()
    worker.accept(envelope()); first = worker.process_one()
    assert first.ingest_seq == 1 and worker.stream.is_acknowledged(first)
    worker.accept(envelope()); assert worker.process_one().event_hash == first.event_hash and len(writer.events) == 1
    worker.accept(envelope("tick-2", 1, last_price=101))
    with pytest.raises(DurableStateError): worker.process_one()


def test_market_writer_failure_is_replayed(tmp_path):
    writer = Writer(True); worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer); worker.recover(); worker.accept(envelope())
    with pytest.raises(OSError): worker.process_one()
    assert len(worker.stream.pending_for_tick_writer()) == 1
    writer.fail = False; assert worker.replay_pending_writes() == 1
    assert not worker.stream.pending_for_tick_writer()


def test_durable_state_rejects_symlink_noncanonical_and_unsafe_journals(tmp_path):
    state = tmp_path / "state"; state.mkdir(mode=0o700)
    journal = AppendOnlyJsonl(state / "journal.jsonl")
    journal.append({"record_type": "ok"})
    journal.path.unlink()
    target = tmp_path / "elsewhere.jsonl"
    target.write_text('{"record_type":"bad"}\n', encoding="utf-8")
    journal.path.symlink_to(target)
    with pytest.raises(DurableCorruptionError): journal.read_all()
    journal.path.unlink()
    journal.path.write_text('{"record_type": "not-canonical"}\n', encoding="utf-8")
    journal.path.chmod(0o600)
    with pytest.raises(DurableCorruptionError): journal.read_all()


def test_verified_stream_rejects_gap_and_forged_ack_before_polluting_journal(tmp_path):
    market = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    market.recover(); market.accept(envelope()); first = market.process_one()
    forged = VerifiedTick.from_raw(
        {"source_event_id": first.source_event_id, "vt_symbol": first.vt_symbol},
        stream_generation="g1", ingest_seq=2, source=first.source,
    )
    with pytest.raises(DurableCorruptionError): market.stream.acknowledge_tick_write(forged)
    assert len(market.stream.acknowledgements.values()) == 1
    gap = VerifiedTick.from_raw(
        {"source_event_id": "gap", "vt_symbol": "rb2610.SHFE"},
        stream_generation="g1", ingest_seq=3, source="gateway-market-reader",
    )
    market.stream.journal.append({"record_type": "verified_tick", "tick": gap.as_dict()})
    restarted = DurableVerifiedTickStream(tmp_path / "market" / "stream", generation="g1")
    with pytest.raises(DurableCorruptionError, match="gap/duplicate"):
        restarted.stats()


def test_verified_stream_serializes_competing_producers_without_duplicate_sequence(tmp_path):
    stream_dir = tmp_path / "stream"
    first = DurableVerifiedTickStream(stream_dir, generation="g1")
    second = DurableVerifiedTickStream(stream_dir, generation="g1")
    candidates = [
        VerifiedTick.from_raw(
            {"source_event_id": event_id, "vt_symbol": "rb2610.SHFE"},
            stream_generation="g1", ingest_seq=1, source="gateway-market-reader",
        )
        for event_id in ("first", "second")
    ]
    barrier = threading.Barrier(2)
    outcomes = []

    def append(stream, tick):
        barrier.wait()
        try:
            outcomes.append(stream.append(tick))
        except DurableStateError:
            outcomes.append(False)

    threads = [
        threading.Thread(target=append, args=(first, candidates[0])),
        threading.Thread(target=append, args=(second, candidates[1])),
    ]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert outcomes.count(True) == 1
    assert DurableVerifiedTickStream(stream_dir, generation="g1").stats()["events"] == 1


def test_market_revalidates_constructed_envelopes_and_persists_event_fence_before_sink(tmp_path):
    writer = Writer(True)
    worker = MarketDataWorker(tmp_path / "market", generation="g1", writer=writer)
    worker.recover()
    valid = envelope("same-id", 1)
    with pytest.raises(ValueError): worker.accept(replace(valid, capability="order.send"))
    worker.accept(valid)
    with pytest.raises(OSError): worker.process_one()
    restarted = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    restarted.recover()
    restarted.accept(envelope("same-id", 2))
    with pytest.raises(DurableStateError, match="reused with different content"):
        restarted.process_one()


def test_market_run_recovers_and_replays_before_readiness(tmp_path):
    failed = Writer(True)
    first = MarketDataWorker(tmp_path / "market", generation="g1", writer=failed)
    first.recover(); first.accept(envelope())
    with pytest.raises(OSError): first.process_one()
    recovered_writer = Writer()
    restarted = MarketDataWorker(tmp_path / "market", generation="g1", writer=recovered_writer)
    stop = threading.Event(); stop.set()
    restarted.run(stop_event=stop)
    assert [tick.ingest_seq for tick in recovered_writer.events] == [1]
    assert restarted.readiness().ready


def test_execution_checkpoint_follows_evidence(tmp_path):
    market = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer()); market.recover(); market.accept(envelope()); tick = market.process_one()
    eq = ExecutionQualityWorker(tmp_path / "eq", generation="g1", tick_stream_dir=tmp_path / "market" / "stream"); eq.recover()
    prior = eq._make_evidence(tick); eq.evidence.append(prior)
    assert eq.process_one() is not None and eq.last_ingest_seq == 1


def test_execution_recovery_binds_checkpoint_event_evidence_generation_and_algorithm(tmp_path):
    market = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer())
    market.recover(); market.accept(envelope()); market.process_one()
    eq = ExecutionQualityWorker(
        tmp_path / "eq", generation="g1", tick_stream_dir=tmp_path / "market" / "stream"
    )
    eq.recover(); assert eq.process_one() is not None
    checkpoint = eq.checkpoint.read()
    eq.checkpoint.write({**checkpoint, "last_evidence_hash": "0" * 64})
    restarted = ExecutionQualityWorker(
        tmp_path / "eq", generation="g1", tick_stream_dir=tmp_path / "market" / "stream"
    )
    with pytest.raises(DurableCorruptionError, match="checkpoint evidence hash mismatch"):
        restarted.recover()


def test_monitor_outbox_fences_delivery(tmp_path):
    worker = MonitorWorker(tmp_path / "monitor", generation="old"); worker.recover(); incident = worker.observe("execution-orchestrator", {"status": "unavailable", "token": "secret"})
    assert incident is not None and len(worker.repository.pending()) == 1
    delivery = int(worker.repository.pending()[0]["delivery_id"])
    new = MonitorWorker(tmp_path / "monitor", generation="new"); new.recover()
    assert not worker.repository.mark_delivered(delivery, generation="old", epoch=worker.fence_epoch)
    assert new.repository.mark_delivered(delivery, generation="new", epoch=new.fence_epoch)


def test_monitor_run_once_durably_records_incident_and_outbox_then_replays(tmp_path):
    config = MonitorConfig(tmp_path / "monitor", None, generation="g1")
    projection = {"service_id": "market-data-worker", "status": "unhealthy", "ready": False}
    first_notifier = Notifier(False)
    worker = MonitorWorker(config, source=Projection(projection), notifier=first_notifier)
    result = worker.run_once()
    assert len(result["transitions"]) == 1
    assert len(worker.incidents.records()) == 1
    assert len(worker.repository.pending()) == 1
    second_notifier = Notifier(True)
    restarted = MonitorWorker(config, source=Projection(projection), notifier=second_notifier)
    restarted.run_once()
    assert len(second_notifier.events) == 1
    assert not restarted.repository.pending()


def test_monitor_projection_absence_blocks_readiness_and_network_notifier_is_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("PHASE_B_TELEGRAM_TOKEN", "not-a-real-token")
    monkeypatch.setenv("PHASE_B_TELEGRAM_CHAT_ID", "not-a-real-chat")
    config = MonitorConfig(tmp_path / "monitor", None, generation="g1", telegram_enabled=False)
    worker = MonitorWorker(config)
    worker.recover()
    assert isinstance(worker.notifier, NullNotifier)
    assert worker.notifier.status()["status"] == "disabled"
    readiness = worker.readiness()
    assert not readiness.ready and "projection_dir_missing" in readiness.blockers


def test_queue_overflow_is_visible():
    queue = BoundedIngressQueue[int](1); queue.put(1)
    with pytest.raises(BackpressureError): queue.put(2)


def test_sources_have_no_application_imports():
    package = Path(__file__).resolve().parents[1]
    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom): assert not (node.module or "").startswith(("app", "backend", "vnpy"))
            if isinstance(node, ast.Import): assert all(not alias.name.startswith(("app", "backend", "vnpy")) for alias in node.names)


def test_worker_containerfiles_are_scripts_only():
    root = Path(__file__).resolve().parents[3]
    for name in ("Containerfile.market-data-worker", "Containerfile.execution-quality-worker", "Containerfile.monitor-worker"):
        text = (root / "deployments" / "phase-b" / name).read_text(encoding="utf-8")
        assert "COPY backend" not in text and "uvicorn" not in text and "EXPOSE" not in text
