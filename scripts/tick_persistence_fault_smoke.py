from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
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


def build_settings(*, dsn: str, spool_dir: Path, batch_size: int, ilp_conf: str | None = None) -> Settings:
    return Settings(
        app_env="development",
        questdb_pg_dsn=dsn,
        questdb_ilp_conf=os.getenv("QUESTDB_ILP_CONF", "") if ilp_conf is None else ilp_conf,
        questdb_tick_batch_size=batch_size,
        questdb_tick_flush_interval_ms=10,
        questdb_tick_retry_max_seconds=1,
        questdb_tick_spool_dir=str(spool_dir),
        questdb_tick_spool_max_bytes=128 * 1024 * 1024,
        questdb_tick_spool_segment_bytes=1024 * 1024,
        questdb_tick_error_log_interval_seconds=1,
    )


def drain_until_empty(pipeline: TickPersistenceService, timeout_seconds: float) -> dict:
    deadline = time.time() + timeout_seconds
    snapshot = pipeline.snapshot()
    while time.time() < deadline:
        pipeline.drain_once()
        snapshot = pipeline.snapshot()
        if snapshot["queue_depth"] == 0 and snapshot["spool_rows"] == 0:
            return snapshot
        time.sleep(0.1)
    return snapshot


def run_fault_smoke(args: argparse.Namespace) -> dict:
    good_dsn = args.questdb_pg_dsn or os.getenv("QUESTDB_PG_DSN")
    if not good_dsn:
        raise RuntimeError("QUESTDB_PG_DSN is required")

    vt_symbol = args.vt_symbol or f"FAULT{int(time.time())}.LOCAL"
    base_time = datetime.now(timezone.utc)
    spool_dir = Path(args.spool_dir) if args.spool_dir else Path(tempfile.mkdtemp(prefix="vnpy-tick-fault-smoke-"))
    cleanup_spool = args.spool_dir is None
    outage_settings = build_settings(
        dsn=args.failure_questdb_pg_dsn,
        spool_dir=spool_dir,
        batch_size=args.count,
        ilp_conf="",
    )
    recovery_settings = build_settings(dsn=good_dsn, spool_dir=spool_dir, batch_size=args.count)

    outage_market = QuestDbMarketDataService(outage_settings)
    outage_pipeline = TickPersistenceService(outage_settings, outage_market, sleep_func=lambda _: None)
    received = 0
    try:
        for index in range(args.count):
            if outage_pipeline.enqueue_tick(build_tick(vt_symbol, index, base_time)):
                received += 1
        outage_pipeline.drain_once()
        outage_snapshot = outage_pipeline.snapshot()
    finally:
        outage_pipeline.stop(timeout=1)
        outage_market.stop()

    recovery_market = QuestDbMarketDataService(recovery_settings)
    recovery_pipeline = TickPersistenceService(recovery_settings, recovery_market, sleep_func=lambda _: None)
    try:
        recovery_market.start()
        replay_snapshot = drain_until_empty(recovery_pipeline, args.timeout)
        row_count = wait_for_row_count(recovery_market, vt_symbol, received, args.timeout)
        result = {
            "vt_symbol": vt_symbol,
            "received": received,
            "outage_failed": outage_snapshot["failed_total"],
            "outage_retry": outage_snapshot["retry_total"],
            "outage_spool_rows_before_restart": outage_snapshot["spool_rows"],
            "replay_persisted": replay_snapshot["persisted_total"],
            "questdb_rows": row_count,
            "diff": received - row_count,
            "dropped": outage_snapshot["dropped_total"] + replay_snapshot["dropped_total"],
            "spool_rows": replay_snapshot["spool_rows"],
            "write_protocol": recovery_market.write_protocol,
            "spool_dir": str(spool_dir),
        }
    finally:
        recovery_pipeline.stop(timeout=1)
        recovery_market.stop()
        if cleanup_spool:
            shutil.rmtree(spool_dir, ignore_errors=True)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Fault smoke test QuestDB tick spool and replay after a writer restart.")
    parser.add_argument("--count", type=int, default=int(os.getenv("TICK_FAULT_SMOKE_COUNT", "10")))
    parser.add_argument("--vt-symbol", default=os.getenv("TICK_FAULT_SMOKE_VT_SYMBOL"))
    parser.add_argument("--questdb-pg-dsn", default=os.getenv("QUESTDB_PG_DSN"))
    parser.add_argument("--failure-questdb-pg-dsn", default=os.getenv("TICK_FAULT_SMOKE_BAD_DSN", "postgresql://admin:quest@127.0.0.1:18812/qdb"))
    parser.add_argument("--spool-dir", default=os.getenv("TICK_FAULT_SMOKE_SPOOL_DIR"))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("TICK_FAULT_SMOKE_TIMEOUT_SECONDS", "20")))
    args = parser.parse_args()

    try:
        result = run_fault_smoke(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["diff"] == 0 and result["dropped"] == 0 and result["outage_spool_rows_before_restart"] == result["received"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
