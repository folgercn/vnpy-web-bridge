from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import statistics
import sys
import time

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

if load_dotenv:
    load_dotenv(BACKEND_ROOT / ".env")
    load_dotenv(REPO_ROOT / ".env")

from app.core.config import Settings
from app.services.market_data_service import QuestDbMarketDataService
from app.services.tick_persistence import TickPersistenceService
from tick_persistence_smoke import build_tick, wait_for_row_count


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * pct)))
    return ordered[index]


def build_settings(*, count: int, batch_size: int, queue_size: int | None, spool_dir: str | None) -> Settings:
    configured_queue_size = int(os.getenv("QUESTDB_TICK_QUEUE_SIZE", "100000"))
    effective_queue_size = queue_size if queue_size is not None else max(count + 1, configured_queue_size)
    return Settings(
        app_env="development",
        questdb_pg_dsn=os.getenv("QUESTDB_PG_DSN", ""),
        questdb_ilp_conf=os.getenv("QUESTDB_ILP_CONF", ""),
        questdb_tick_queue_size=effective_queue_size,
        questdb_tick_batch_size=batch_size,
        questdb_tick_flush_interval_ms=10,
        questdb_tick_retry_max_seconds=1,
        questdb_tick_spool_dir=spool_dir or os.getenv("QUESTDB_TICK_SPOOL_DIR", "logs/tick-spool-load-smoke"),
        questdb_tick_spool_max_bytes=1024 * 1024 * 1024,
        questdb_tick_spool_segment_bytes=16 * 1024 * 1024,
        questdb_tick_error_log_interval_seconds=1,
    )


def drain_until_count(pipeline: TickPersistenceService, market: QuestDbMarketDataService, vt_symbol: str, expected: int, timeout_seconds: float) -> tuple[dict, int]:
    deadline = time.time() + timeout_seconds
    row_count = 0
    snapshot = pipeline.snapshot()
    while time.time() < deadline:
        pipeline.drain_once()
        snapshot = pipeline.snapshot()
        row_count = wait_for_row_count(market, vt_symbol, expected, timeout_seconds=0.5)
        if row_count >= expected and snapshot["queue_depth"] == 0 and snapshot["spool_rows"] == 0:
            return snapshot, row_count
        time.sleep(0.01)
    return snapshot, row_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Synthetic load smoke for the tick persistence queue and QuestDB writer.")
    parser.add_argument("--count", type=int, default=int(os.getenv("TICK_LOAD_SMOKE_COUNT", "2000")))
    parser.add_argument("--batch-size", type=int, default=int(os.getenv("TICK_LOAD_SMOKE_BATCH_SIZE", "1000")))
    parser.add_argument("--queue-size", type=int, default=int(os.getenv("TICK_LOAD_SMOKE_QUEUE_SIZE", "0")) or None)
    parser.add_argument("--vt-symbol", default=os.getenv("TICK_LOAD_SMOKE_VT_SYMBOL"))
    parser.add_argument("--spool-dir", default=os.getenv("TICK_LOAD_SMOKE_SPOOL_DIR"))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("TICK_LOAD_SMOKE_TIMEOUT_SECONDS", "30")))
    parser.add_argument("--max-enqueue-p95-ms", type=float, default=float(os.getenv("TICK_LOAD_SMOKE_MAX_ENQUEUE_P95_MS", "10")))
    args = parser.parse_args()

    settings = build_settings(count=args.count, batch_size=args.batch_size, queue_size=args.queue_size, spool_dir=args.spool_dir)
    if not settings.questdb_pg_dsn:
        print("skip: QUESTDB_PG_DSN is required", file=sys.stderr)
        return 2

    vt_symbol = args.vt_symbol or f"LOAD{int(time.time())}.LOCAL"
    base_time = datetime.now(timezone.utc)
    market = QuestDbMarketDataService(settings)
    pipeline = TickPersistenceService(settings, market, sleep_func=lambda _: None)
    enqueue_ms: list[float] = []
    received = 0
    started = time.perf_counter()

    market.start()
    try:
        for index in range(args.count):
            tick = build_tick(vt_symbol, index, base_time)
            before = time.perf_counter()
            accepted = pipeline.enqueue_tick(tick)
            enqueue_ms.append((time.perf_counter() - before) * 1000)
            if accepted:
                received += 1

        enqueue_done = time.perf_counter()
        before_drain_snapshot = pipeline.snapshot()
        snapshot, row_count = drain_until_count(pipeline, market, vt_symbol, received, args.timeout)
        finished = time.perf_counter()
        enqueue_p95 = percentile(enqueue_ms, 0.95)
        result = {
            "vt_symbol": vt_symbol,
            "received": received,
            "persisted": snapshot["persisted_total"],
            "questdb_rows": row_count,
            "diff": received - row_count,
            "dropped": snapshot["dropped_total"],
            "queue_capacity": snapshot["queue_capacity"],
            "queue_depth": snapshot["queue_depth"],
            "queue_depth_before_drain": before_drain_snapshot["queue_depth"],
            "spool_rows": snapshot["spool_rows"],
            "spool_rows_before_drain": before_drain_snapshot["spool_rows"],
            "spooled_total_before_drain": before_drain_snapshot["spooled_total"],
            "enqueue_avg_ms": round(statistics.fmean(enqueue_ms), 6) if enqueue_ms else 0.0,
            "enqueue_p50_ms": round(percentile(enqueue_ms, 0.50), 6),
            "enqueue_p95_ms": round(enqueue_p95, 6),
            "enqueue_p99_ms": round(percentile(enqueue_ms, 0.99), 6),
            "enqueue_max_ms": round(max(enqueue_ms), 6) if enqueue_ms else 0.0,
            "enqueue_total_seconds": round(enqueue_done - started, 6),
            "persistence_seconds": round(finished - started, 6),
            "enqueue_tps": round(received / max(enqueue_done - started, 0.000001), 2),
            "persist_tps": round(row_count / max(finished - started, 0.000001), 2),
            "write_protocol": market.write_protocol,
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        ok = result["diff"] == 0 and result["dropped"] == 0 and result["spool_rows"] == 0 and enqueue_p95 <= args.max_enqueue_p95_ms
        return 0 if ok else 1
    finally:
        pipeline.stop(timeout=2)
        market.stop()


if __name__ == "__main__":
    raise SystemExit(main())
