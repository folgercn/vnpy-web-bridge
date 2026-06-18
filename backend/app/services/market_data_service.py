from __future__ import annotations

import json
import logging
from csv import DictReader
from datetime import datetime, timedelta, timezone
from io import StringIO
from threading import RLock
from typing import Any, Iterable

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

    def get_overview(self, limit: int = 500) -> list[dict[str, Any]]:
        if not self.enabled:
            return []

        safe_limit = min(max(int(limit), 1), 5000)
        try:
            with self._lock:
                conn = self._connect()
                self._init_schema()
                rows = conn.execute(
                    f"""
                    SELECT
                        vt_symbol,
                        symbol,
                        exchange,
                        count() AS row_count,
                        min(ts) AS start_time,
                        max(ts) AS end_time
                    FROM market_ticks
                    GROUP BY vt_symbol, symbol, exchange
                    ORDER BY end_time DESC
                    LIMIT {safe_limit}
                    """
                ).fetchall()
        except Exception as exc:
            logger.warning("QuestDB overview query failed: %s", exc)
            self._drop_connection()
            return []

        return [
            {
                "vt_symbol": row[0],
                "symbol": row[1],
                "exchange": row[2],
                "row_count": row[3],
                "start_time": _format_datetime(row[4]),
                "end_time": _format_datetime(row[5]),
            }
            for row in rows
        ]

    def query_ticks(
        self,
        symbol: str | None = None,
        exchange: str | None = None,
        vt_symbol: str | None = None,
        start: str | None = None,
        end: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if not self.enabled:
            return []

        where, params = _build_tick_filters(symbol=symbol, exchange=exchange, vt_symbol=vt_symbol, start=start, end=end)
        safe_limit = min(max(int(limit), 1), 5000)

        try:
            with self._lock:
                conn = self._connect()
                self._init_schema()
                rows = conn.execute(
                    f"""
                    SELECT
                        ts, vt_symbol, symbol, exchange, gateway_name,
                        last_price, volume, turnover, open_interest,
                        bid_price_1, ask_price_1, bid_volume_1, ask_volume_1
                    FROM market_ticks
                    {where}
                    ORDER BY ts DESC
                    LIMIT {safe_limit}
                    """,
                    params,
                ).fetchall()
        except Exception as exc:
            logger.warning("QuestDB tick query failed: %s", exc)
            self._drop_connection()
            return []

        return [_tick_row_to_dict(row) for row in rows]

    def import_ticks_csv(self, content: bytes) -> dict[str, Any]:
        if not self.enabled:
            return {"imported": 0, "skipped": 0, "enabled": False}

        text = content.decode("utf-8-sig")
        reader = DictReader(StringIO(text))
        imported = 0
        skipped = 0
        for row in reader:
            tick = _csv_row_to_tick(row)
            if not tick:
                skipped += 1
                continue
            before = imported
            self.save_tick(tick)
            imported += 1
            if imported == before:
                skipped += 1
        return {"imported": imported, "skipped": skipped, "enabled": True}

    def export_ticks_csv(self, rows: Iterable[dict[str, Any]]) -> str:
        headers = [
            "datetime",
            "vt_symbol",
            "symbol",
            "exchange",
            "gateway_name",
            "last_price",
            "volume",
            "turnover",
            "open_interest",
            "bid_price_1",
            "ask_price_1",
            "bid_volume_1",
            "ask_volume_1",
        ]
        output = StringIO()
        output.write(",".join(headers) + "\n")
        for row in rows:
            values = [_csv_escape(row.get(key, "")) for key in headers]
            output.write(",".join(values) + "\n")
        return output.getvalue()

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


def _format_datetime(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _build_tick_filters(
    symbol: str | None = None,
    exchange: str | None = None,
    vt_symbol: str | None = None,
    start: str | None = None,
    end: str | None = None,
) -> tuple[str, tuple[Any, ...]]:
    clauses: list[str] = []
    params: list[Any] = []
    if vt_symbol:
        clauses.append("vt_symbol = %s")
        params.append(vt_symbol)
    if symbol:
        clauses.append("symbol = %s")
        params.append(symbol)
    if exchange:
        clauses.append("exchange = %s")
        params.append(exchange)
    if start:
        clauses.append("ts >= %s")
        params.append(_parse_datetime(start))
    if end:
        clauses.append("ts <= %s")
        params.append(_parse_datetime(end))
    if not clauses:
        return "", tuple(params)
    return "WHERE " + " AND ".join(clauses), tuple(params)


def _tick_row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "datetime": _format_datetime(row[0]),
        "vt_symbol": row[1],
        "symbol": row[2],
        "exchange": row[3],
        "gateway_name": row[4],
        "last_price": row[5],
        "volume": row[6],
        "turnover": row[7],
        "open_interest": row[8],
        "bid_price_1": row[9],
        "ask_price_1": row[10],
        "bid_volume_1": row[11],
        "ask_volume_1": row[12],
    }


def _csv_row_to_tick(row: dict[str, str]) -> dict[str, Any] | None:
    vt_symbol = row.get("vt_symbol") or ""
    symbol = row.get("symbol") or vt_symbol.split(".", 1)[0]
    exchange = row.get("exchange") or (vt_symbol.split(".", 1)[1] if "." in vt_symbol else "")
    last_price = _number(row.get("last_price"))
    if not symbol or not exchange or last_price is None:
        return None
    return {
        "datetime": row.get("datetime") or row.get("ts"),
        "vt_symbol": vt_symbol or f"{symbol}.{exchange}",
        "symbol": symbol,
        "exchange": exchange,
        "gateway_name": row.get("gateway_name"),
        "last_price": last_price,
        "volume": _number(row.get("volume")),
        "turnover": _number(row.get("turnover")),
        "open_interest": _number(row.get("open_interest")),
        "bid_price_1": _number(row.get("bid_price_1")),
        "ask_price_1": _number(row.get("ask_price_1")),
        "bid_volume_1": _number(row.get("bid_volume_1")),
        "ask_volume_1": _number(row.get("ask_volume_1")),
    }


def _csv_escape(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    if any(char in text for char in [",", "\n", '"']):
        return '"' + text.replace('"', '""') + '"'
    return text


def _sample_by(interval: str) -> str | None:
    return {"1m": "1m", "1h": "1h", "1d": "1d", "1w": "1w"}.get(interval)


def _interval_minutes(interval: str) -> int:
    return {"1m": 1, "1h": 60, "1d": 1440, "1w": 10080}.get(interval, 1)


market_data_service = QuestDbMarketDataService()
