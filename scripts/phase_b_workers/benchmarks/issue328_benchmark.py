"""Repeatable local measurements for the Issue #328 acceptance gates.

Examples::

    PYTHONPATH=. python scripts/phase_b_workers/benchmarks/issue328_benchmark.py \
        --ticks 2000 --json-out /tmp/issue328-small.json
    PYTHONPATH=. python scripts/phase_b_workers/benchmarks/issue328_benchmark.py \
        --ticks 100000 --sample-every 10000

The default is intentionally small enough for a developer laptop.  Increase
``--ticks`` for a million-tick-equivalent run.  Results are JSON so CI and a
container can consume the same measurements without parsing human logs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Permit both ``PYTHONPATH=scripts`` and direct execution from the repository
# root, matching the worker scripts' standalone invocation behavior.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from phase_b_workers.contracts import (
    CONTRACT_VERSION,
    GatewayTickEnvelope,
    VerifiedTick,
)
from phase_b_workers.durable import DurableVerifiedTickStream
from phase_b_workers.market_data_worker import MarketDataConfig, MarketDataWorker


def _rss_bytes() -> int:
    """Return current RSS where available (Linux container and macOS host)."""
    try:
        pages = int(Path("/proc/self/statm").read_text().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE")
    except (FileNotFoundError, IndexError, ValueError, OSError):
        # macOS exposes ru_maxrss in bytes; this is a conservative peak proxy.
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return value if value > 1_000_000 else value * 1024


def _tick(index: int, generation: str) -> VerifiedTick:
    # Deterministic content makes repeated probes genuine positive duplicate
    # fallbacks rather than accidentally creating a new raw hash each call.
    now = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=index)
    return VerifiedTick.from_raw(
        {
            "source_event_id": f"bench-event-{index}",
            "vt_symbol": f"TEST{index % 32}.LOCAL",
            "event_time_utc": now.isoformat(),
            "last_price": 100.0 + (index % 100) / 100,
            "bid_price": 99.9,
            "ask_price": 100.1,
            "volume": index + 1,
        },
        stream_generation=generation,
        ingest_seq=index,
        received_at=now,
    )


def _quantiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {}
    values = sorted(values)
    return {
        "p50": values[len(values) // 2],
        "p95": values[min(len(values) - 1, int(len(values) * 0.95))],
        "max": values[-1],
    }


def benchmark_stream(root: Path, ticks: int, sample_every: int) -> dict[str, Any]:
    generation = "issue328-benchmark"
    path = root / "stream"
    stream = DurableVerifiedTickStream(path, generation=generation)
    stream.initialize()
    rss: list[float] = []
    start = time.perf_counter()
    for index in range(1, ticks + 1):
        stream.append(_tick(index, generation))
        if index == 1 or index % sample_every == 0:
            rss.append(_rss_bytes() / (1024 * 1024))
    elapsed = time.perf_counter() - start
    before_restart = _rss_bytes() / (1024 * 1024)
    recovery_start = time.perf_counter()
    reopened = DurableVerifiedTickStream(path, generation=generation, read_only=True)
    recovery_seconds = time.perf_counter() - recovery_start
    return {
        "events": ticks,
        "append_seconds": elapsed,
        "append_ticks_per_second": ticks / elapsed if elapsed else 0.0,
        "recovery_seconds": recovery_seconds,
        "recovered_events": int(reopened.stats()["events"]),
        "rss_mib_samples": rss,
        "rss_mib_before_restart": before_restart,
        "rss_trend": _quantiles(rss),
    }


def benchmark_lookup(root: Path, ticks: int, probes: int) -> dict[str, Any]:
    generation = "issue328-lookup"
    path = root / "lookup"
    stream = DurableVerifiedTickStream(path, generation=generation)
    stream.initialize()
    for index in range(1, ticks + 1):
        stream.append(_tick(index, generation))
    source_start = time.perf_counter()
    source_hits = sum(
        stream.find_by_source_event_id(f"bench-event-{(i % ticks) + 1}") is not None
        for i in range(probes)
    )
    source_seconds = time.perf_counter() - source_start
    raw = _tick(ticks, generation).raw_hash
    raw_start = time.perf_counter()
    raw_hits = sum(stream.find_by_raw_hash(raw) is not None for _ in range(probes))
    raw_seconds = time.perf_counter() - raw_start
    return {
        "events": ticks,
        "probes": probes,
        "positive_source_fallback_hits": source_hits,
        "positive_source_fallback_seconds": source_seconds,
        "positive_raw_fallback_hits": raw_hits,
        "positive_raw_fallback_seconds": raw_seconds,
    }


def benchmark_worker_path(root: Path, ticks: int, sample_every: int) -> dict[str, Any]:
    """Exercise the real deterministic gateway-publish-proxy worker path.

    Deterministic source identities are intentionally not retained in the
    ``events`` map; only the bounded source frontier is checkpointed.
    """
    config = MarketDataConfig(root / "worker", stream_generation="worker-bench", projection_dir=root / "projection")
    worker = MarketDataWorker(config)
    worker.recover()
    sizes: list[dict[str, float]] = []
    start = time.perf_counter()
    for index in range(1, ticks + 1):
        payload = {"vt_symbol": "TEST.LOCAL", "last_price": 100.0 + index / 1000, "volume": index}
        # The deterministic identity is part of the production validator.
        from phase_b_workers.contracts import sha256_hex
        event = GatewayTickEnvelope.create(
            event_id=sha256_hex({"source_generation": "worker-bench", "source_seq": index,
                                 "topic": "eTick.TEST.LOCAL", "payload": payload})[:32],
            source_service="gateway-publish-proxy", source_generation="worker-bench",
            source_seq=index, payload=payload,
        )
        worker.accept(event)
        tick_start = time.perf_counter()
        worker.process_one()
        if index == 1 or index % sample_every == 0:
            state_path = config.state_dir / "source_fence.json"
            state = worker.source_fence.read()
            sizes.append({"events": index, "bytes": state_path.stat().st_size,
                          "event_entries": len(dict(state.get("events") or {})),
                          "process_write_ms": (time.perf_counter() - tick_start) * 1000})
    elapsed = time.perf_counter() - start
    return {"events": ticks, "seconds": elapsed, "writes_per_second": ticks / elapsed if elapsed else 0.0, "checkpoint_samples": sizes, "fsync": True}


def benchmark_projection(root: Path, ticks: int, interval: int) -> dict[str, Any]:
    worker = MarketDataWorker(MarketDataConfig(root / "projection-worker", projection_dir=root / "projection-real"))
    worker.recover()
    start = time.perf_counter()
    writes = 0
    for index in range(1, ticks + 1):
        if index == 1 or index % max(1, interval) == 0:
            worker._next_projection_monotonic = 0.0
        if worker._publish_projection_if_due():
            writes += 1
    elapsed = time.perf_counter() - start
    return {"ticks": ticks, "interval": interval, "projection_writes": writes, "seconds": elapsed}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ticks", type=int, default=2000)
    parser.add_argument("--probes", type=int, default=100)
    parser.add_argument("--sample-every", type=int, default=500)
    parser.add_argument(
        "--stream-only",
        action="store_true",
        help=(
            "run only durable stream append/fsync, RSS trend, and read-only "
            "recovery; skip lookup, worker-path, and projection benchmarks"
        ),
    )
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if args.ticks < 1 or args.sample_every < 1:
        parser.error("ticks and sample-every must be positive")
    if not args.stream_only and args.probes < 1:
        parser.error("probes must be positive unless --stream-only is selected")
    with tempfile.TemporaryDirectory(prefix="issue328-benchmark-") as directory:
        root = Path(directory)
        result = {
            "benchmark": "issue-328",
            "contract_version": CONTRACT_VERSION,
            "ticks": args.ticks,
            "mode": "stream-only" if args.stream_only else "full",
            "stream": benchmark_stream(root, args.ticks, args.sample_every),
        }
        if not args.stream_only:
            result.update(
                {
                    "lookup": benchmark_lookup(root, args.ticks, args.probes),
                    "worker_path": benchmark_worker_path(
                        root, args.ticks, args.sample_every
                    ),
                    "projection": benchmark_projection(
                        root, args.ticks, max(1, args.ticks // 60)
                    ),
                }
            )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json_out:
        args.json_out.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
