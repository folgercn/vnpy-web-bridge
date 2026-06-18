from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any

from app.core.config import Settings, get_settings

try:
    import psycopg
except ImportError:  # pragma: no cover - covered in deployments with QuestDB enabled
    psycopg = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class QuestDbMarketDataService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.dsn = self.settings.questdb_pg_dsn
        self._lock = RLock()
        self._conn: Any | None = None
        self._initialized = False

    @property
    def enabled(self) -> bool:
        return bool(self.dsn)

    def start(self) -> None:
        if not self.enabled:
            return
        self._connect()
        self._init_schema()

    def stop(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
            self._conn = None
            self._initialized = False

    def save_tick(self, tick: dict[str, Any]) -> None:
        if not self.enabled:
            return

        vt_symbol = str(tick.get("vt_symbol") or "")
        last_price = _number(tick.get("last_price"))
        if not vt_symbol or last_price is None:
            return

        symbol = str(tick.get("symbol") or vt_symbol.split(".", 1)[0])
        exchange = str(tick.get("exchange") or vt_symbol.split(".", 1)[-1])
        timestamp = _parse_datetime(tick.get("datetime"))
        params = (
            timestamp,
            vt_symbol,
            symbol,
            exchange,
            _string_or_none(tick.get("gateway_name")),
            last_price,
            _number(tick.get("volume")),
            _number(tick.get("turnover")),
            _number(tick.get("open_interest")),
            _number(tick.get("bid_price_1")),
            _number(tick.get("ask_price_1")),
            _number(tick.get("bid_volume_1")),
            _number(tick.get("ask_volume_1")),
            json.dumps(tick, ensure_ascii=False, default=str),
        )

        try:
            with self._lock:
                conn = self._connect()
                conn.execute(
                    """
                    INSERT INTO market_ticks (
                        ts, vt_symbol, symbol, exchange, gateway_name,
                        last_price, volume, turnover, open_interest,
                        bid_price_1, ask_price_1, bid_volume_1, ask_volume_1, raw_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    params,
                )
        except Exception as exc:
            logger.warning("QuestDB tick write failed: %s", exc)
            self._drop_connection()

    def get_bars(self, symbol: str, exchange: str, interval: str = "1m", limit: int = 300) -> list[dict[str, Any]]:
        if not self.enabled:
            return []

        sample_by = _sample_by(interval)
        if not sample_by:
            return []

        vt_symbol = f"{symbol}.{exchange}"
        start = datetime.now(timezone.utc) - timedelta(minutes=max(limit, 1) * _interval_minutes(interval))
        safe_limit = min(max(int(limit), 1), 2000)

        try:
            with self._lock:
                conn = self._connect()
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM (
                        SELECT
                            ts,
                            first(last_price) AS open_price,
                            max(last_price) AS high_price,
                            min(last_price) AS low_price,
                            last(last_price) AS close_price,
                            last(volume) AS volume,
                            last(open_interest) AS open_interest
                        FROM market_ticks
                        WHERE vt_symbol = %s AND ts >= %s
                        SAMPLE BY {sample_by}
                    )
                    ORDER BY ts DESC
                    LIMIT {safe_limit}
                    """,
                    (vt_symbol, start),
                ).fetchall()
        except Exception as exc:
            logger.warning("QuestDB bar query failed: %s", exc)
            self._drop_connection()
            return []

        bars = [
            {
                "symbol": symbol,
                "exchange": exchange,
                "vt_symbol": vt_symbol,
                "datetime": row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0]),
                "interval": interval,
                "open_price": row[1],
                "high_price": row[2],
                "low_price": row[3],
                "close_price": row[4],
                "volume": row[5],
                "open_interest": row[6],
                "gateway_name": self.settings.vnpy_gateway_name,
            }
            for row in reversed(rows)
            if row[1] is not None and row[2] is not None and row[3] is not None and row[4] is not None
        ]
        return bars

    def _connect(self) -> Any:
        if psycopg is None:
            raise RuntimeError("psycopg 未安装，无法连接 QuestDB")
        if self._conn and not self._conn.closed:
            return self._conn
        self._conn = psycopg.connect(self.dsn, autocommit=True)
        self._initialized = False
        return self._conn

    def _init_schema(self) -> None:
        if self._initialized:
            return
        conn = self._connect()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS market_ticks (
                ts TIMESTAMP,
                vt_symbol SYMBOL CAPACITY 10000 CACHE,
                symbol SYMBOL CAPACITY 10000 CACHE,
                exchange SYMBOL CAPACITY 64 CACHE,
                gateway_name SYMBOL CAPACITY 64 CACHE,
                last_price DOUBLE,
                volume DOUBLE,
                turnover DOUBLE,
                open_interest DOUBLE,
                bid_price_1 DOUBLE,
                ask_price_1 DOUBLE,
                bid_volume_1 DOUBLE,
                ask_volume_1 DOUBLE,
                raw_json STRING
            ) TIMESTAMP(ts) PARTITION BY DAY WAL
            """
        )
        self._initialized = True

    def _drop_connection(self) -> None:
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
            self._conn = None
            self._initialized = False


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif value:
        raw = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(raw)
    else:
        parsed = datetime.now(timezone.utc)

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _number(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _string_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _sample_by(interval: str) -> str | None:
    return {"1m": "1m", "1h": "1h", "1d": "1d", "1w": "1w"}.get(interval)


def _interval_minutes(interval: str) -> int:
    return {"1m": 1, "1h": 60, "1d": 1440, "1w": 10080}.get(interval, 1)


market_data_service = QuestDbMarketDataService()
