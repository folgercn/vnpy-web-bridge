from __future__ import annotations

from csv import DictReader
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import StringIO
import json
import logging
from threading import RLock
from typing import Any, Iterable

from app.core.config import Settings, get_settings

try:
    import psycopg
except ImportError:  # pragma: no cover - covered in deployments with QuestDB enabled
    psycopg = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2

TICK_NUMERIC_FIELDS = [
    "last_price",
    "last_volume",
    "volume",
    "turnover",
    "open_interest",
    "open_price",
    "high_price",
    "low_price",
    "pre_close",
    "limit_up",
    "limit_down",
    "bid_price_1",
    "bid_price_2",
    "bid_price_3",
    "bid_price_4",
    "bid_price_5",
    "ask_price_1",
    "ask_price_2",
    "ask_price_3",
    "ask_price_4",
    "ask_price_5",
    "bid_volume_1",
    "bid_volume_2",
    "bid_volume_3",
    "bid_volume_4",
    "bid_volume_5",
    "ask_volume_1",
    "ask_volume_2",
    "ask_volume_3",
    "ask_volume_4",
    "ask_volume_5",
]

TICK_SELECT_FIELDS = [
    "ts",
    "received_at",
    "ingest_id",
    "schema_version",
    "vt_symbol",
    "symbol",
    "exchange",
    "gateway_name",
    "name",
    "trading_day",
    "action_day",
    *TICK_NUMERIC_FIELDS,
]

TICK_CSV_HEADERS = [
    "datetime",
    "received_at",
    "ingest_id",
    "schema_version",
    "vt_symbol",
    "symbol",
    "exchange",
    "gateway_name",
    "name",
    "trading_day",
    "action_day",
    *TICK_NUMERIC_FIELDS,
]

SCHEMA_COLUMNS: list[tuple[str, str]] = [
    ("received_at", "TIMESTAMP"),
    ("ingest_id", "STRING"),
    ("schema_version", "INT"),
    ("name", "STRING"),
    ("trading_day", "STRING"),
    ("action_day", "STRING"),
    ("last_volume", "DOUBLE"),
    ("open_price", "DOUBLE"),
    ("high_price", "DOUBLE"),
    ("low_price", "DOUBLE"),
    ("pre_close", "DOUBLE"),
    ("limit_up", "DOUBLE"),
    ("limit_down", "DOUBLE"),
    ("bid_price_2", "DOUBLE"),
    ("bid_price_3", "DOUBLE"),
    ("bid_price_4", "DOUBLE"),
    ("bid_price_5", "DOUBLE"),
    ("ask_price_2", "DOUBLE"),
    ("ask_price_3", "DOUBLE"),
    ("ask_price_4", "DOUBLE"),
    ("ask_price_5", "DOUBLE"),
    ("bid_volume_2", "DOUBLE"),
    ("bid_volume_3", "DOUBLE"),
    ("bid_volume_4", "DOUBLE"),
    ("bid_volume_5", "DOUBLE"),
    ("ask_volume_2", "DOUBLE"),
    ("ask_volume_3", "DOUBLE"),
    ("ask_volume_4", "DOUBLE"),
    ("ask_volume_5", "DOUBLE"),
]


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

    @property
    def connected(self) -> bool:
        return bool(self._conn and not self._conn.closed)

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

    def health_check(self) -> dict[str, Any]:
        if not self.enabled:
            return {"configured": False, "connected": False, "status": "disabled"}
        with self._lock:
            conn = self._connect()
            conn.execute("SELECT 1")
        return {"configured": True, "connected": True, "status": "ok"}

    def save_tick(self, tick: dict[str, Any]) -> bool:
        if not self.enabled:
            return False

        row = self.normalize_tick(tick)
        if row is None:
            return False

        return self.save_tick_rows([row])

    def normalize_tick(self, tick: dict[str, Any]) -> dict[str, Any] | None:
        return _normalize_tick(tick)

    def save_tick_rows(self, rows: Iterable[dict[str, Any]]) -> bool:
        if not self.enabled:
            return False

        prepared_rows = [_prepare_tick_row(row) for row in rows]
        if not prepared_rows:
            return True

        columns = [*TICK_SELECT_FIELDS, "raw_json"]
        sql = f"""
            INSERT INTO market_ticks ({", ".join(columns)})
            VALUES ({", ".join(["%s"] * len(columns))})
        """
        params = [tuple(row[key] for key in TICK_SELECT_FIELDS) + (row["raw_json"],) for row in prepared_rows]
        try:
            with self._lock:
                conn = self._connect()
                for row_params in params:
                    conn.execute(sql, row_params)
            return True
        except Exception as exc:
            logger.warning("QuestDB tick write failed: %s", exc)
            self._drop_connection()
            return False

    def insert_tick_row(self, row: dict[str, Any]) -> bool:
        return self.save_tick_rows([row])

    def serialize_tick_row(self, row: dict[str, Any]) -> dict[str, Any]:
        return _serialize_tick_row(row)

    def deserialize_tick_row(self, row: dict[str, Any]) -> dict[str, Any]:
        return _prepare_tick_row(row)

    def save_tick_rows_or_raise(self, rows: Iterable[dict[str, Any]]) -> None:
        if not self.enabled:
            return
        prepared_rows = [_prepare_tick_row(row) for row in rows]
        if not prepared_rows:
            return
        columns = [*TICK_SELECT_FIELDS, "raw_json"]
        placeholders = ", ".join(["%s"] * len(columns))
        try:
            with self._lock:
                conn = self._connect()
                for row in prepared_rows:
                    conn.execute(
                        f"""
                        INSERT INTO market_ticks ({", ".join(columns)})
                        VALUES ({placeholders})
                        """,
                        tuple(row[key] for key in TICK_SELECT_FIELDS) + (row["raw_json"],),
                    )
        except Exception:
            self._drop_connection()
            raise

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
                    SELECT {", ".join(TICK_SELECT_FIELDS)}
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
            if self.save_tick(tick):
                imported += 1
            if imported == before:
                skipped += 1
        return {"imported": imported, "skipped": skipped, "enabled": True}

    def export_ticks_csv(self, rows: Iterable[dict[str, Any]]) -> str:
        output = StringIO()
        output.write(",".join(TICK_CSV_HEADERS) + "\n")
        for row in rows:
            values = [_csv_escape(row.get(key, "")) for key in TICK_CSV_HEADERS]
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
                received_at TIMESTAMP,
                ingest_id STRING,
                schema_version INT,
                vt_symbol SYMBOL CAPACITY 10000 CACHE,
                symbol SYMBOL CAPACITY 10000 CACHE,
                exchange SYMBOL CAPACITY 64 CACHE,
                gateway_name SYMBOL CAPACITY 64 CACHE,
                name STRING,
                trading_day STRING,
                action_day STRING,
                last_price DOUBLE,
                last_volume DOUBLE,
                volume DOUBLE,
                turnover DOUBLE,
                open_interest DOUBLE,
                open_price DOUBLE,
                high_price DOUBLE,
                low_price DOUBLE,
                pre_close DOUBLE,
                limit_up DOUBLE,
                limit_down DOUBLE,
                bid_price_1 DOUBLE,
                bid_price_2 DOUBLE,
                bid_price_3 DOUBLE,
                bid_price_4 DOUBLE,
                bid_price_5 DOUBLE,
                ask_price_1 DOUBLE,
                ask_price_2 DOUBLE,
                ask_price_3 DOUBLE,
                ask_price_4 DOUBLE,
                ask_price_5 DOUBLE,
                bid_volume_1 DOUBLE,
                bid_volume_2 DOUBLE,
                bid_volume_3 DOUBLE,
                bid_volume_4 DOUBLE,
                bid_volume_5 DOUBLE,
                ask_volume_1 DOUBLE,
                ask_volume_2 DOUBLE,
                ask_volume_3 DOUBLE,
                ask_volume_4 DOUBLE,
                ask_volume_5 DOUBLE,
                raw_json STRING
            ) TIMESTAMP(ts) PARTITION BY DAY WAL
            DEDUP UPSERT KEYS(ts, ingest_id)
            """
        )
        self._ensure_schema_columns(conn)
        self._enable_dedup(conn)
        self._initialized = True

    def _ensure_schema_columns(self, conn: Any) -> None:
        for name, data_type in SCHEMA_COLUMNS:
            try:
                conn.execute(f"ALTER TABLE market_ticks ADD COLUMN {name} {data_type}")
            except Exception as exc:
                message = str(exc).lower()
                if "exists" not in message and "duplicate" not in message:
                    raise RuntimeError(f"QuestDB schema upgrade failed for column {name}: {exc}") from exc

    def _enable_dedup(self, conn: Any) -> None:
        conn.execute("ALTER TABLE market_ticks DEDUP ENABLE UPSERT KEYS(ts, ingest_id)")

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


def _normalize_tick(tick: dict[str, Any]) -> dict[str, Any] | None:
    timestamp_value = tick.get("datetime") or tick.get("ts")
    if not timestamp_value:
        return None

    vt_symbol = _string_or_none(tick.get("vt_symbol"))
    symbol = _string_or_none(tick.get("symbol"))
    exchange = _string_or_none(tick.get("exchange"))
    if not vt_symbol and symbol and exchange:
        vt_symbol = f"{symbol}.{exchange}"
    if vt_symbol and not symbol:
        symbol = vt_symbol.split(".", 1)[0]
    if vt_symbol and not exchange and "." in vt_symbol:
        exchange = vt_symbol.split(".", 1)[1]

    timestamp = _parse_datetime(timestamp_value)
    last_price = _number(tick.get("last_price"))
    if not vt_symbol or not symbol or not exchange or last_price is None:
        return None

    raw_json = json.dumps(tick, ensure_ascii=False, default=str, sort_keys=True)
    schema_version = _int_or_default(tick.get("schema_version"), SCHEMA_VERSION)
    received_at = _parse_datetime(tick.get("received_at") or tick.get("localtime") or timestamp)
    row: dict[str, Any] = {
        "ts": timestamp,
        "received_at": received_at,
        "schema_version": schema_version,
        "vt_symbol": vt_symbol,
        "symbol": symbol,
        "exchange": exchange,
        "gateway_name": _string_or_none(tick.get("gateway_name")),
        "name": _string_or_none(tick.get("name")),
        "trading_day": _string_or_none(tick.get("trading_day")),
        "action_day": _string_or_none(tick.get("action_day")),
        "raw_json": raw_json,
    }
    for field in TICK_NUMERIC_FIELDS:
        row[field] = _number(tick.get(field))

    row["last_price"] = last_price
    row["ingest_id"] = _string_or_none(tick.get("ingest_id")) or _build_ingest_id(row)
    return row


def _build_ingest_id(row: dict[str, Any]) -> str:
    stable_fields = {
        key: (_format_datetime(value) if isinstance(value, datetime) else value)
        for key, value in row.items()
        if key != "ingest_id"
    }
    digest = sha256(json.dumps(stable_fields, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return digest[:32]


def _prepare_tick_row(row: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(row)
    prepared["ts"] = _parse_datetime(prepared.get("ts") or prepared.get("datetime"))
    prepared["received_at"] = _parse_datetime(prepared.get("received_at") or prepared["ts"])
    prepared["schema_version"] = _int_or_default(prepared.get("schema_version"), SCHEMA_VERSION)
    if not prepared.get("raw_json"):
        prepared["raw_json"] = json.dumps(prepared, ensure_ascii=False, default=str, sort_keys=True)
    for field in TICK_NUMERIC_FIELDS:
        prepared[field] = _number(prepared.get(field))
    return prepared


def _serialize_tick_row(row: dict[str, Any]) -> dict[str, Any]:
    serialized = dict(row)
    for key in ("ts", "received_at"):
        serialized[key] = _format_datetime(serialized.get(key))
    return serialized


def _number(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_or_default(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _string_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _format_datetime(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime) and value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
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
    data = dict(zip(TICK_SELECT_FIELDS, row, strict=False))
    data["datetime"] = _format_datetime(data.pop("ts", None))
    data["received_at"] = _format_datetime(data.get("received_at"))
    return data


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
        "name": row.get("name"),
        "received_at": row.get("received_at"),
        "ingest_id": row.get("ingest_id"),
        "schema_version": row.get("schema_version"),
        "last_price": last_price,
        "last_volume": _number(row.get("last_volume")),
        "volume": _number(row.get("volume")),
        "turnover": _number(row.get("turnover")),
        "open_interest": _number(row.get("open_interest")),
        "open_price": _number(row.get("open_price")),
        "high_price": _number(row.get("high_price")),
        "low_price": _number(row.get("low_price")),
        "pre_close": _number(row.get("pre_close")),
        "limit_up": _number(row.get("limit_up")),
        "limit_down": _number(row.get("limit_down")),
        "trading_day": row.get("trading_day"),
        "action_day": row.get("action_day"),
        **{field: _number(row.get(field)) for field in TICK_NUMERIC_FIELDS if field.startswith(("bid_", "ask_"))},
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
