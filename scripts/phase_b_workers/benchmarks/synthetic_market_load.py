"""Synthetic MarketDataWorker load probe (no live connections by default)."""

from __future__ import annotations

import argparse
import json
import os
import resource
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from phase_b_workers.contracts import GatewayTickEnvelope, sha256_hex
from phase_b_workers.market_data_worker import (
    MarketDataConfig,
    MarketDataWorker,
    QuestDbTickWriter,
)


def _rss_mib() -> float:
    try:
        pages = int(Path("/proc/self/statm").read_text().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)
    except (FileNotFoundError, IndexError, OSError, ValueError):
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return value / (1024 * 1024) if value > 1_000_000 else value / 1024


def _quantiles(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p95": None, "p99": None, "max": None}
    ordered = sorted(values)
    return {
        "p50": ordered[len(ordered) // 2],
        "p95": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))],
        "p99": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.99))],
        "max": ordered[-1],
    }


class SyntheticQuestDbWriter(QuestDbTickWriter):
    """QuestDbTickWriter-shaped sink that never opens a network connection."""

    def __init__(self) -> None:
        super().__init__("synthetic://local")
        self.committed_ids: list[str] = []
        self.batches: list[list[str]] = []
        self.commit_ages_ms: list[float] = []

    def write_verified_ticks(self, ticks: tuple[Any, ...] | list[Any]) -> None:
        batch = [str(tick.ingest_id) for tick in ticks]
        self.batches.append(batch)
        self.committed_ids.extend(batch)
        committed_at = datetime.now(timezone.utc)
        for tick in ticks:
            received = datetime.fromisoformat(
                str(tick.received_at_utc).replace("Z", "+00:00")
            )
            self.commit_ages_ms.append(
                max(0.0, (committed_at - received).total_seconds() * 1000)
            )

    def readback(self, tick: Any) -> None:
        return None

    def health(self) -> dict[str, object]:
        return {
            "status": "healthy",
            "writer": "synthetic",
            "written_ticks": len(self.committed_ids),
        }

    def close(self) -> None:
        return None


class MeasuredQuestDbWriter(QuestDbTickWriter):
    """Real QuestDB writer with benchmark-only batch and freshness samples."""

    def __init__(self, dsn: str) -> None:
        super().__init__(dsn)
        self.committed_ids: list[str] = []
        self.batches: list[list[str]] = []
        self.commit_ages_ms: list[float] = []

    def write_verified_ticks(self, ticks: tuple[Any, ...] | list[Any]) -> None:
        values = list(ticks)
        super().write_verified_ticks(values)
        committed_at = datetime.now(timezone.utc)
        self.batches.append([str(tick.ingest_id) for tick in values])
        self.committed_ids.extend(str(tick.ingest_id) for tick in values)
        self.commit_ages_ms.extend(
            max(0.0, (committed_at - tick.received_at_utc).total_seconds() * 1000)
            for tick in values
        )


def _event(index: int, generated_at: datetime) -> GatewayTickEnvelope:
    payload = {
        "vt_symbol": "SYNTH.LOCAL",
        "last_price": 100.0 + (index % 1000) / 100,
        "bid_price": 99.9,
        "ask_price": 100.1,
        "last_volume": index,
        "datetime": generated_at.isoformat(),
    }
    generation = "issue332-synthetic"
    event_id = sha256_hex(
        {
            "source_generation": generation,
            "source_seq": index,
            "topic": "eTick.SYNTH.LOCAL",
            "payload": payload,
        }
    )[:32]
    return GatewayTickEnvelope.create(
        event_id=event_id,
        source_service="gateway-publish-proxy",
        source_generation=generation,
        source_seq=index,
        observed_at=generated_at,
        payload=payload,
    )


def run(rate: float, duration: float) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="issue332-market-load-") as temporary:
        root = Path(temporary)
        fake = SyntheticQuestDbWriter()
        dsn = os.getenv("ISSUE332_QUESTDB_DSN", "").strip()
        writer: Any = MeasuredQuestDbWriter(dsn) if dsn else fake
        config = MarketDataConfig(root, stream_generation="issue332-synthetic")
        worker = MarketDataWorker(config, writer=writer)
        worker.recover()
        ages: list[float] = []
        rss: list[float] = [_rss_mib()]
        queue_max = generated = processed = errors = 0
        started = time.monotonic()
        deadline = started + duration
        slice_seconds = 0.02
        next_slice = started
        source_seq = 0
        carry = 0.0
        while time.monotonic() < deadline:
            next_slice += slice_seconds
            now = time.monotonic()
            if now < next_slice:
                time.sleep(next_slice - now)
            carry += rate * slice_seconds
            burst = int(carry)
            carry -= burst
            if not burst:
                continue
            burst_ages: list[float] = []
            try:
                for _ in range(burst):
                    source_seq += 1
                    generated += 1
                    generated_at = datetime.now(timezone.utc)
                    worker.accept(_event(source_seq, generated_at))
                    burst_ages.append(
                        (datetime.now(timezone.utc) - generated_at).total_seconds() * 1000
                    )
                    queue_max = max(queue_max, worker.ingress.qsize())
                # Keep the worker's durable QuestDB pending group across loop
                # iterations so its real max-wait scheduler can form groups.
                processed += worker.process_queue(flush=False)
                ages.extend(burst_ages)
            except Exception:  # noqa: BLE001 - benchmark reports opaque failures
                errors += 1
                break
            rss.append(_rss_mib())
        worker._flush_questdb_pending(reason="benchmark_end")
        elapsed = max(0.0, time.monotonic() - started)
        recovery_started = time.monotonic()
        restarted_writer = SyntheticQuestDbWriter() if not dsn else QuestDbTickWriter(dsn)
        restarted = MarketDataWorker(config, writer=restarted_writer)
        restarted.recover()
        replayed = restarted.replay_pending()
        recovery_seconds = time.monotonic() - recovery_started
        worker_batch_metrics = worker.metrics_snapshot()["questdb_batch"]
        return {
            "benchmark": "issue-332-synthetic-market-load",
            "rate_target_ticks_per_second": rate,
            "duration_seconds": duration,
            "elapsed_seconds": elapsed,
            "writer": "questdb" if dsn else "fake",
            "generated": generated,
            "processed": processed,
            "persisted": len(writer.committed_ids),
            "errors": errors,
            "queue_max": queue_max,
            "processed_ticks_per_second": processed / elapsed if elapsed else 0.0,
            "tick_age_ms": _quantiles(
                writer.commit_ages_ms
                if isinstance(writer, (SyntheticQuestDbWriter, MeasuredQuestDbWriter))
                else ages
            ),
            "commit_age_ms": _quantiles(
                writer.commit_ages_ms
                if isinstance(writer, (SyntheticQuestDbWriter, MeasuredQuestDbWriter))
                else []
            ),
            "rss_mib": {"start": rss[0], "max": max(rss), "samples": rss},
            "worker_counters": dict(worker.metrics.counters),
            "group_metrics": {
                "implemented": True,
                "batch_sizes": [len(batch) for batch in writer.batches],
                "commit_age_ms": _quantiles(writer.commit_ages_ms),
                "flushes": len(writer.batches),
                "worker": worker_batch_metrics,
            },
            "durable_stream": {
                "stats": worker.stream.stats(),
                "journal_records": len(worker.stream.journal.read_all()),
                "ack_records": len(worker.stream.acknowledgements.journal.read_all()),
                "watermark": worker.stream.watermark.read(),
            },
            "restart_recovery": {
                "seconds": recovery_seconds,
                "replayed_pending": replayed,
                "recovered_events": restarted.stream.stats().get("events", 0),
            },
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rate", type=float, default=55.5)
    parser.add_argument("--duration", type=float, default=5.0)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if args.rate <= 0 or args.duration <= 0:
        parser.error("rate and duration must be positive")
    encoded = json.dumps(run(args.rate, args.duration), indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
