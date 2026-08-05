from __future__ import annotations

import ast
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent))

from phase_b_workers.contracts import GatewayTickEnvelope
from phase_b_workers.durable import (
    BackpressureError,
    BoundedIngressQueue,
    DurableStateError,
)
from phase_b_workers.execution_quality_worker import ExecutionQualityWorker
from phase_b_workers.market_data_worker import MarketDataWorker
from phase_b_workers.monitor_worker import MonitorWorker


def envelope(event_id="tick-1", seq=1, **payload):
    return GatewayTickEnvelope.create(event_id=event_id, source_service="gateway-market-reader", source_generation="source-g1", source_seq=seq, observed_at=datetime(2026, 8, 5, tzinfo=timezone.utc), payload={"vt_symbol": "rb2610.SHFE", "bid_price": 100, "ask_price": 102, **payload})


class Writer:
    def __init__(self, fail=False): self.fail, self.events = fail, []
    def write_verified_tick(self, tick):
        if self.fail: raise OSError("writer unavailable")
        self.events.append(tick)


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


def test_execution_checkpoint_follows_evidence(tmp_path):
    market = MarketDataWorker(tmp_path / "market", generation="g1", writer=Writer()); market.recover(); market.accept(envelope()); tick = market.process_one()
    eq = ExecutionQualityWorker(tmp_path / "eq", generation="g1", tick_stream_dir=tmp_path / "market" / "stream"); eq.recover()
    prior = eq._make_evidence(tick); eq.evidence.append(prior)
    assert eq.process_one() is not None and eq.last_ingest_seq == 1


def test_monitor_outbox_fences_delivery(tmp_path):
    worker = MonitorWorker(tmp_path / "monitor", generation="old"); worker.recover(); incident = worker.observe("execution-orchestrator", {"status": "unavailable", "token": "secret"})
    assert incident is not None and len(worker.repository.pending()) == 1
    delivery = int(worker.repository.pending()[0]["delivery_id"])
    new = MonitorWorker(tmp_path / "monitor", generation="new"); new.recover()
    assert not worker.repository.mark_delivered(delivery, generation="old", epoch=worker.fence_epoch)
    assert new.repository.mark_delivered(delivery, generation="new", epoch=new.fence_epoch)


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
