from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
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


def build_tick(vt_symbol: str, index: int, base_time: datetime) -> dict:
    symbol, exchange = vt_symbol.split(".", 1)
    timestamp = base_time + timedelta(milliseconds=index)
    return {
        "vt_symbol": vt_symbol,
        "symbol": symbol,
        "exchange": exchange,
        "gateway_name": "SMOKE",
        "datetime": timestamp.isoformat(),
        "localtime": datetime.now(timezone.utc).isoformat(),
        "last_price": 3000 + index,
        "last_volume": 1,
        "volume": index + 1,
        "turnover": (3000 + index) * (index + 1),
        "open_interest": 100 + index,
        "bid_price_1": 2999 + index,
        "ask_price_1": 3001 + index,
        "bid_volume_1": 10,
        "ask_volume_1": 11,
        "trading_day": timestamp.strftime("%Y%m%d"),
        "action_day": timestamp.strftime("%Y%m%d"),
    }


def wait_for_row_count(market: QuestDbMarketDataService, vt_symbol: str, expected: int, timeout_seconds: float) -> int:
    deadline = time.time() + timeout_seconds
    row_count = 0
    while time.time() < deadline:
        try:
            row_count = int(market._connect().execute("SELECT count() FROM market_ticks WHERE vt_symbol = %s", (vt_symbol,)).fetchone()[0])
        except Exception:
            row_count = 0
            market._drop_connection()
        if row_count >= expected:
            return row_count
        time.sleep(0.25)
    return row_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test QuestDB tick persistence pipeline.")
    parser.add_argument("--count", type=int, default=int(os.getenv("TICK_SMOKE_COUNT", "10")))
    parser.add_argument("--vt-symbol", default=os.getenv("TICK_SMOKE_VT_SYMBOL"))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("TICK_SMOKE_TIMEOUT_SECONDS", "15")))
    args = parser.parse_args()

    settings = Settings()
    if not settings.questdb_pg_dsn:
        print("skip: QUESTDB_PG_DSN is required", file=sys.stderr)
        return 2

    vt_symbol = args.vt_symbol or f"SMOKE{int(time.time())}.LOCAL"
    market = QuestDbMarketDataService(settings)
    pipeline = TickPersistenceService(settings, market, sleep_func=lambda _: None)
    received = 0
    base_time = datetime.now(timezone.utc)

    market.start()
    try:
        for index in range(args.count):
            if pipeline.enqueue_tick(build_tick(vt_symbol, index, base_time)):
                received += 1
        while pipeline.snapshot()["queue_depth"] or pipeline.snapshot()["spool_rows"]:
            pipeline.drain_once()
        row_count = wait_for_row_count(market, vt_symbol, received, args.timeout)
        snapshot = pipeline.snapshot()
        result = {
            "vt_symbol": vt_symbol,
            "received": received,
            "persisted": snapshot["persisted_total"],
            "questdb_rows": row_count,
            "diff": received - row_count,
            "dropped": snapshot["dropped_total"],
            "lag_seconds": snapshot["persistence_lag_seconds"],
            "spool_rows": snapshot["spool_rows"],
            "write_protocol": market.write_protocol,
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["diff"] == 0 and result["dropped"] == 0 else 1
    finally:
        pipeline.stop(timeout=1)
        market.stop()


if __name__ == "__main__":
    raise SystemExit(main())
