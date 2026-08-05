"""Standalone market-data worker with a durable verified-tick handoff."""

from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

try:
    from . import CONTRACT_VERSION
    from .contracts import (
        GatewayTickEnvelope,
        HealthSnapshot,
        ReadinessSnapshot,
        VerifiedTick,
        WorkerIdentity,
        WorkerMetrics,
        isoformat,
        sha256_hex,
    )
    from .durable import (
        AppendOnlyJsonl,
        AtomicCheckpoint,
        BackpressureError,
        BoundedIngressQueue,
        DurableStateError,
        DurableVerifiedTickStream,
        GenerationMismatch,
    )
except ImportError:  # pragma: no cover
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from phase_b_workers import CONTRACT_VERSION
    from phase_b_workers.contracts import (
        GatewayTickEnvelope,
        HealthSnapshot,
        ReadinessSnapshot,
        VerifiedTick,
        WorkerIdentity,
        WorkerMetrics,
        isoformat,
        sha256_hex,
    )
    from phase_b_workers.durable import (
        AppendOnlyJsonl,
        AtomicCheckpoint,
        BackpressureError,
        BoundedIngressQueue,
        DurableStateError,
        DurableVerifiedTickStream,
        GenerationMismatch,
    )


class ReadonlyMarketSource(Protocol):
    def query(self, symbols: Iterable[str]) -> Iterable[Mapping[str, object]]: ...

    def subscribe(self, callback: Callable[[Mapping[str, object]], None]) -> None: ...

    def close(self) -> None: ...


class TickWriter(Protocol):
    def write_tick(self, tick: Mapping[str, object]) -> None: ...


class JsonlTickWriter:
    """Small idempotent adapter standing in for the QuestDB tick sink."""

    def __init__(self, path: str | Path) -> None:
        self.log = AppendOnlyJsonl(path)
        self._ids: set[str] | None = None
        self._lock = threading.RLock()

    def _load(self) -> set[str]:
        if self._ids is None:
            self._ids = {str(row["ingest_id"]) for row in self.log.records() if row.get("ingest_id")}
        return self._ids

    def write_tick(self, tick: Mapping[str, object]) -> None:
        ingest_id = str(tick.get("ingest_id") or "")
        if not ingest_id:
            raise ValueError("ingest_id is required")
        with self._lock:
            if ingest_id in self._load():
                return
            self.log.append({"record_type": "questdb_tick", **dict(tick)})
            self._ids.add(ingest_id)

    def write_verified_tick(self, tick: VerifiedTick) -> None:
        self.write_tick(tick.as_dict())

    def health(self) -> Mapping[str, object]:
        return {"status": "healthy", "written_ticks": len(self._load())}


# Deployment adapters can replace this implementation while preserving the
# narrow tick-write protocol; the name documents the intended QuestDB sink.
QuestDbTickWriter = JsonlTickWriter


@dataclass(frozen=True)
class MarketDataConfig:
    state_dir: Path
    stream_generation: str = "generation-1"
    queue_maxsize: int = 2048
    source_name: str = "readonly_market_source"
    runtime_mode: str = "disabled"

    @classmethod
    def from_environment(cls, state_dir: str | Path | None = None) -> MarketDataConfig:
        return cls(
            state_dir=Path(state_dir or os.getenv("PHASE_B_MARKET_DATA_STATE_DIR", "/var/lib/phase-b/market-data")),
            stream_generation=os.getenv("PHASE_B_STREAM_GENERATION", "generation-1"),
            queue_maxsize=max(1, int(os.getenv("PHASE_B_MARKET_QUEUE_MAXSIZE", "2048"))),
            source_name=os.getenv("PHASE_B_MARKET_SOURCE", "readonly_market_source"),
            runtime_mode=os.getenv("PHASE_B_RUNTIME_MODE", "disabled"),
        )


class MarketDataWorker:
    service_id = "market-data-worker"

    def __init__(
        self,
        config: MarketDataConfig | str | Path,
        *,
        generation: str | None = None,
        source: ReadonlyMarketSource | None = None,
        writer: TickWriter | None = None,
        queue_size: int | None = None,
        identity: WorkerIdentity | None = None,
    ) -> None:
        if not isinstance(config, MarketDataConfig):
            config = MarketDataConfig(Path(config), generation or "generation-1", queue_size or 2048)
        self.config = config
        config.state_dir.mkdir(parents=True, exist_ok=True)
        self.identity = identity or WorkerIdentity.from_environment(self.service_id, runtime_mode=config.runtime_mode)
        self.stream = DurableVerifiedTickStream(config.state_dir / "stream", generation=config.stream_generation)
        self.source_fence = AtomicCheckpoint(
            config.state_dir / "source_fence.json",
            default={"worker_generation": config.stream_generation, "sources": {}},
        )
        self.writer = writer or JsonlTickWriter(config.state_dir / "persisted_ticks.jsonl")
        self.ingress: BoundedIngressQueue[Mapping[str, object] | GatewayTickEnvelope] = BoundedIngressQueue(config.queue_maxsize)
        self.source = source
        self._source_bound = False
        self._last_error: str | None = None
        self._state_recovered = True
        self.metrics = WorkerMetrics(self.service_id, isoformat(), worker_generation=config.stream_generation)

    def recover(self) -> None:
        self.stream.stats()
        state = self.source_fence.read()
        if str(state.get("worker_generation") or self.config.stream_generation) != self.config.stream_generation:
            self._state_recovered = False
            raise GenerationMismatch("market-data generation changed without a new state directory")
        self._state_recovered = True
        self._last_error = None

    def bind_source(self) -> None:
        if self.source is not None and not self._source_bound:
            self.source.subscribe(self.enqueue)
            self._source_bound = True

    def enqueue(self, raw: Mapping[str, object]) -> None:
        try:
            self.ingress.put(dict(raw))
        except BackpressureError:
            self.metrics.increment("backpressure_total")
            raise
        self.metrics.increment("received_total")
        self.metrics.queue_depth = self.ingress.qsize()

    def accept(self, value: GatewayTickEnvelope | Mapping[str, object]) -> None:
        envelope = value if isinstance(value, GatewayTickEnvelope) else GatewayTickEnvelope.from_dict(value)
        try:
            self.ingress.put(envelope)
        except BackpressureError:
            self.metrics.increment("backpressure_total")
            raise
        self.metrics.increment("ingress_accepted")
        self.metrics.queue_depth = self.ingress.qsize()

    def _assert_source_fence(self, event: GatewayTickEnvelope) -> None:
        state = self.source_fence.read()
        sources = dict(state.get("sources") or {})
        prior = dict(sources.get(event.source_service) or {})
        old_generation = str(prior.get("generation") or event.source_generation)
        old_seq = int(prior.get("seq") or 0)
        if old_generation != event.source_generation:
            raise GenerationMismatch("source generation changed; rotate the stream explicitly")
        if event.source_seq < old_seq:
            raise DurableStateError("stale source sequence")
        if event.source_seq == old_seq and old_seq and prior.get("event_hash") != event.envelope_hash:
            raise DurableStateError("source sequence was reused with different content")

    def _write(self, tick: VerifiedTick) -> None:
        if self.stream.is_acknowledged(tick):
            return
        fn = getattr(self.writer, "write_verified_tick", None)
        if callable(fn):
            fn(tick)
        else:
            self.writer.write_tick(tick.as_dict())
        self.stream.acknowledge_tick_write(tick)
        self.metrics.increment("ticks_persisted")
        self.metrics.last_success_at_utc = isoformat()

    def ingest(self, raw: Mapping[str, object]) -> VerifiedTick:
        event_id = str(raw.get("source_event_id") or raw.get("event_id") or raw.get("id") or "").strip()
        existing = self.stream.find_by_source_event_id(event_id) if event_id else None
        if existing is None and not event_id:
            existing = self.stream.find_by_raw_hash(sha256_hex(dict(raw)))
        if existing is not None:
            self.metrics.increment("ticks_deduplicated")
            try:
                self._write(existing)
            except Exception as exc:
                self._last_error = type(exc).__name__
                raise
            self.metrics.checkpoint_or_watermark = existing.ingest_seq
            return existing
        tick = VerifiedTick.from_raw(
            raw,
            stream_generation=self.config.stream_generation,
            ingest_seq=self.stream.next_sequence(),
            source=self.config.source_name,
        )
        self.stream.append(tick)
        self.metrics.increment("ticks_durable")
        try:
            self._write(tick)
        except Exception as exc:
            self._last_error = type(exc).__name__
            raise
        self.metrics.checkpoint_or_watermark = tick.ingest_seq
        self._last_error = None
        return tick

    def _process_envelope(self, event: GatewayTickEnvelope) -> VerifiedTick:
        self._assert_source_fence(event)
        raw = {**dict(event.payload), "source_event_id": event.event_id}
        tick = self.stream.find_by_source_event_id(event.event_id)
        if tick is None:
            tick = self.stream.find_by_raw_hash(sha256_hex(raw))
        if tick is None:
            tick = VerifiedTick.from_raw(raw, stream_generation=self.config.stream_generation, ingest_seq=self.stream.next_sequence(), source=event.source_service)
            self.stream.append(tick)
            self.metrics.increment("ticks_durable")
        else:
            self.metrics.increment("ticks_deduplicated")
        self._write(tick)
        state = self.source_fence.read()
        sources = dict(state.get("sources") or {})
        sources[event.source_service] = {"generation": event.source_generation, "seq": event.source_seq, "event_hash": event.envelope_hash}
        self.source_fence.write({"worker_generation": self.config.stream_generation, "sources": sources})
        self.metrics.checkpoint_or_watermark = tick.ingest_seq
        self._last_error = None
        return tick

    def process_one(self) -> VerifiedTick:
        value = self.ingress.get()
        self.metrics.queue_depth = self.ingress.qsize()
        return self._process_envelope(value) if isinstance(value, GatewayTickEnvelope) else self.ingest(value)

    def process_queue(self, *, limit: int | None = None) -> int:
        processed = 0
        while limit is None or processed < limit:
            try:
                self.process_one()
            except Exception as exc:
                if type(exc).__name__ == "Empty":
                    break
                raise
            processed += 1
        return processed

    def replay_pending(self) -> int:
        recovered = 0
        for tick in self.stream.pending_for_tick_writer():
            self._write(tick)
            recovered += 1
        if recovered:
            self._last_error = None
        return recovered

    replay_pending_writes = replay_pending

    def query(self, symbols: Iterable[str]) -> list[Mapping[str, object]]:
        return [dict(row) for row in self.source.query(symbols)] if self.source else []

    def run(self, *, stop_event: threading.Event | None = None, idle_seconds: float = 0.1) -> None:
        self.bind_source()
        stop_event = stop_event or threading.Event()
        while not stop_event.is_set():
            try:
                self.process_queue()
            except Exception as exc:  # noqa: BLE001
                self._last_error = type(exc).__name__
            stop_event.wait(max(0.01, float(idle_seconds)))

    def health(self) -> HealthSnapshot:
        writer_health = getattr(self.writer, "health", None)
        return HealthSnapshot(
            self.service_id,
            "healthy" if not self._last_error else "degraded",
            isoformat(),
            self.metrics.started_at_utc,
            {"verified_stream": self.stream.stats(), "tick_writer": writer_health() if callable(writer_health) else {"status": "configured"}},
            self._last_error,
        )

    def readiness(self) -> ReadinessSnapshot:
        blockers = ("writer_recovery_required",) if self._last_error else ()
        return ReadinessSnapshot(self.service_id, not blockers, isoformat(), CONTRACT_VERSION in self.identity.contract_versions, True, not bool(self._last_error), self._state_recovered and not bool(self._last_error), blockers)

    def metrics_snapshot(self) -> dict[str, object]:
        self.metrics.queue_depth = self.ingress.qsize()
        self.metrics.checkpoint_or_watermark = self.stream.stats().get("last_ingest_seq", 0)
        return self.metrics.as_dict()

    def version(self) -> dict[str, object]:
        return self.identity.as_dict()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase B market-data worker")
    parser.add_argument("--state-dir")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--version", action="store_true")
    group.add_argument("--health", action="store_true")
    group.add_argument("--ready", action="store_true")
    group.add_argument("--metrics", action="store_true")
    group.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    worker = MarketDataWorker(MarketDataConfig.from_environment(args.state_dir))
    if args.version:
        value = worker.version()
    elif args.ready:
        value = worker.readiness().as_dict()
    elif args.metrics:
        value = worker.metrics_snapshot()
    elif args.run:
        stop = threading.Event()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda *_: stop.set())
        worker.run(stop_event=stop, idle_seconds=float(os.getenv("PHASE_B_MARKET_IDLE_SECONDS", "0.1")))
        return 0
    else:
        value = worker.health().as_dict()
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
