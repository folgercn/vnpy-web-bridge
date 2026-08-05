"""Standalone execution-quality consumer for the durable verified stream."""

from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

try:
    from . import CONTRACT_VERSION
    from .contracts import (
        ExecutionQualityEvidence,
        HealthSnapshot,
        ReadinessSnapshot,
        VerifiedTick,
        WorkerIdentity,
        WorkerMetrics,
        isoformat,
    )
    from .durable import (
        AppendOnlyEvidenceLog,
        AtomicCheckpoint,
        DurableVerifiedTickStream,
        GenerationMismatch,
    )
except ImportError:  # pragma: no cover
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from phase_b_workers import CONTRACT_VERSION
    from phase_b_workers.contracts import (
        ExecutionQualityEvidence,
        HealthSnapshot,
        ReadinessSnapshot,
        VerifiedTick,
        WorkerIdentity,
        WorkerMetrics,
        isoformat,
    )
    from phase_b_workers.durable import (
        AppendOnlyEvidenceLog,
        AtomicCheckpoint,
        DurableVerifiedTickStream,
        GenerationMismatch,
    )


class VerifiedTickSource(Protocol):
    def iter_from(self, after_seq: int = 0, *, limit: int | None = None) -> Iterable[VerifiedTick]: ...


class EvidenceWriter(Protocol):
    def append(self, evidence: ExecutionQualityEvidence | Mapping[str, object]) -> bool: ...


@dataclass(frozen=True)
class ExecutionQualityConfig:
    state_dir: Path
    stream_dir: Path
    stream_generation: str = "generation-1"
    algorithm_version: str = "eq_v1"
    runtime_mode: str = "disabled"

    @classmethod
    def from_environment(cls, state_dir: str | Path | None = None) -> ExecutionQualityConfig:
        root = Path(state_dir or os.getenv("PHASE_B_EQ_STATE_DIR", "/var/lib/phase-b/execution-quality"))
        stream = Path(os.getenv("PHASE_B_VERIFIED_STREAM_DIR", str(Path(os.getenv("PHASE_B_MARKET_DATA_STATE_DIR", "/var/lib/phase-b/market-data")) / "stream")))
        return cls(root, stream, os.getenv("PHASE_B_STREAM_GENERATION", "generation-1"), os.getenv("PHASE_B_EQ_ALGORITHM_VERSION", "eq_v1"), os.getenv("PHASE_B_RUNTIME_MODE", "disabled"))


class ExecutionQualityWorker:
    service_id = "execution-quality-worker"

    def __init__(
        self,
        config: ExecutionQualityConfig | str | Path,
        *,
        generation: str | None = None,
        tick_stream_dir: str | Path | None = None,
        stream: VerifiedTickSource | None = None,
        evidence: EvidenceWriter | None = None,
        identity: WorkerIdentity | None = None,
    ) -> None:
        if not isinstance(config, ExecutionQualityConfig):
            root = Path(config)
            config = ExecutionQualityConfig(root, Path(tick_stream_dir or root / "stream"), generation or "generation-1")
        self.config = config
        config.state_dir.mkdir(parents=True, exist_ok=True)
        self.identity = identity or WorkerIdentity.from_environment(self.service_id, runtime_mode=config.runtime_mode)
        self.stream = stream or DurableVerifiedTickStream(config.stream_dir, generation=config.stream_generation)
        self.evidence = evidence or AppendOnlyEvidenceLog(config.state_dir / "evidence.jsonl")
        self.checkpoint = AtomicCheckpoint(config.state_dir / "checkpoint.json", default={"stream_generation": config.stream_generation, "last_ingest_seq": 0})
        state = self.checkpoint.read()
        if str(state.get("stream_generation") or config.stream_generation) != config.stream_generation:
            raise GenerationMismatch("execution-quality checkpoint generation mismatch")
        self.metrics = WorkerMetrics(self.service_id, isoformat(), worker_generation=config.stream_generation, checkpoint_or_watermark=int(state.get("last_ingest_seq") or 0))
        self._last_error: str | None = None
        self._state_recovered = True
        self._lock = threading.RLock()

    @property
    def last_ingest_seq(self) -> int:
        return int(self.checkpoint.read().get("last_ingest_seq") or 0)

    @staticmethod
    def measure(tick: VerifiedTick) -> dict[str, object]:
        spread = tick.ask_price - tick.bid_price if tick.bid_price is not None and tick.ask_price is not None else None
        midpoint = (tick.bid_price + tick.ask_price) / 2 if tick.bid_price is not None and tick.ask_price is not None else None
        return {"spread": spread, "midpoint": midpoint, "last_price": tick.last_price}

    def recover(self) -> None:
        state = self.checkpoint.read()
        if str(state.get("stream_generation") or self.config.stream_generation) != self.config.stream_generation:
            self._state_recovered = False
            raise GenerationMismatch("execution-quality checkpoint generation mismatch")
        seq = int(state.get("last_ingest_seq") or 0)
        if seq and not any(int(row.get("ingest_seq") or 0) == seq for row in self.evidence.records()):
            self._state_recovered = False
            raise GenerationMismatch("checkpoint has no durable evidence anchor")
        self._state_recovered = True
        self._last_error = None

    def _next_evidence(self) -> tuple[VerifiedTick, ExecutionQualityEvidence] | None:
        tick = next(self.stream.iter_from(self.last_ingest_seq, limit=1), None)
        if tick is None:
            return None
        return tick, ExecutionQualityEvidence.for_tick(tick, metrics=self.measure(tick), algorithm_version=self.config.algorithm_version)

    def _make_evidence(self, tick: VerifiedTick) -> ExecutionQualityEvidence:
        return ExecutionQualityEvidence.for_tick(tick, metrics=self.measure(tick), algorithm_version=self.config.algorithm_version)

    def process_one(self) -> ExecutionQualityEvidence | None:
        with self._lock:
            item = self._next_evidence()
            if item is None:
                return None
            tick, evidence = item
            try:
                inserted = self.evidence.append(evidence)
                self.checkpoint.write({"stream_generation": self.config.stream_generation, "last_ingest_seq": tick.ingest_seq, "last_event_hash": tick.event_hash, "last_evidence_hash": evidence.evidence_hash, "algorithm_version": self.config.algorithm_version})
            except Exception as exc:
                self._last_error = type(exc).__name__
                raise
            self.metrics.increment("evidence_durable" if inserted else "evidence_recovered")
            self.metrics.checkpoint_or_watermark = tick.ingest_seq
            self.metrics.last_success_at_utc = isoformat()
            self._last_error = None
            return evidence

    def consume(self, *, limit: int | None = None) -> int:
        count = 0
        while limit is None or count < limit:
            if self.process_one() is None:
                break
            count += 1
        return count

    replay = consume

    def run(self, *, stop_event: threading.Event | None = None, interval_seconds: float = 1.0) -> None:
        stop_event = stop_event or threading.Event()
        while not stop_event.is_set():
            try:
                self.consume()
            except Exception as exc:  # noqa: BLE001
                self._last_error = type(exc).__name__
            stop_event.wait(max(0.01, float(interval_seconds)))

    def health(self) -> HealthSnapshot:
        return HealthSnapshot(self.service_id, "healthy" if not self._last_error else "degraded", isoformat(), self.metrics.started_at_utc, {"verified_tick_stream": {"status": "healthy", "checkpoint": self.last_ingest_seq}, "evidence_store": {"status": "healthy"}}, self._last_error)

    def readiness(self) -> ReadinessSnapshot:
        blockers = ("consumer_recovery_required",) if self._last_error else ()
        return ReadinessSnapshot(self.service_id, not blockers, isoformat(), CONTRACT_VERSION in self.identity.contract_versions, True, not bool(self._last_error), self._state_recovered and not bool(self._last_error), blockers)

    def metrics_snapshot(self) -> dict[str, object]:
        self.metrics.checkpoint_or_watermark = self.last_ingest_seq
        return self.metrics.as_dict()

    def version(self) -> dict[str, object]:
        return self.identity.as_dict()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase B execution-quality worker")
    parser.add_argument("--state-dir")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--version", action="store_true")
    group.add_argument("--health", action="store_true")
    group.add_argument("--ready", action="store_true")
    group.add_argument("--metrics", action="store_true")
    group.add_argument("--consume", action="store_true")
    group.add_argument("--run", action="store_true")
    args = parser.parse_args(argv)
    worker = ExecutionQualityWorker(ExecutionQualityConfig.from_environment(args.state_dir))
    if args.version:
        value = worker.version()
    elif args.ready:
        value = worker.readiness().as_dict()
    elif args.metrics:
        value = worker.metrics_snapshot()
    elif args.consume:
        value = {"consumed": worker.consume(), "metrics": worker.metrics_snapshot()}
    elif args.run:
        stop = threading.Event()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda *_: stop.set())
        worker.run(stop_event=stop, interval_seconds=float(os.getenv("PHASE_B_EQ_POLL_SECONDS", "1")))
        return 0
    else:
        value = worker.health().as_dict()
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
