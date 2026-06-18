from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import Settings
from app.services.market_data_service import QuestDbMarketDataService, TICK_SELECT_FIELDS, _normalize_tick


class FakeResult:
    def __init__(self, rows=None) -> None:
        self.rows = rows or []

    def fetchall(self):
        return self.rows


class FakeConnection:
    closed = False

    def __init__(self, rows=None) -> None:
        self.rows = rows or []
        self.calls: list[tuple[str, tuple | None]] = []

    def execute(self, sql: str, params: tuple | None = None) -> FakeResult:
        self.calls.append((sql, params))
        return FakeResult(self.rows)


class DuplicateColumnConnection(FakeConnection):
    def execute(self, sql: str, params: tuple | None = None) -> FakeResult:
        self.calls.append((sql, params))
        if "ALTER TABLE market_ticks ADD COLUMN" in sql:
            raise RuntimeError("column already exists")
        return FakeResult(self.rows)


class BrokenAlterConnection(FakeConnection):
    def execute(self, sql: str, params: tuple | None = None) -> FakeResult:
        self.calls.append((sql, params))
        if "ALTER TABLE market_ticks ADD COLUMN received_at" in sql:
            raise RuntimeError("table is read-only")
        return FakeResult(self.rows)


class FakeIlpBuffer:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def row(self, table_name: str, *, symbols: dict, columns: dict, at: datetime) -> None:
        self.rows.append({"table_name": table_name, "symbols": symbols, "columns": columns, "at": at})


class FakeIlpSender:
    created: list["FakeIlpSender"] = []

    def __init__(self, conf: str) -> None:
        self.conf = conf
        self.established = False
        self.closed = False
        self.flushes: list[dict] = []

    @classmethod
    def from_conf(cls, conf: str) -> "FakeIlpSender":
        sender = cls(conf)
        cls.created.append(sender)
        return sender

    def establish(self) -> None:
        self.established = True

    def new_buffer(self) -> FakeIlpBuffer:
        return FakeIlpBuffer()

    def flush(self, buffer: FakeIlpBuffer, *, transactional: bool = False) -> None:
        self.flushes.append({"rows": buffer.rows, "transactional": transactional})

    def close(self) -> None:
        self.closed = True


def test_market_data_service_is_noop_without_dsn() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn=""))

    service.save_tick({"vt_symbol": "rb2610.SHFE", "last_price": 3126})

    assert service.get_bars("rb2610", "SHFE") == []


def test_save_tick_writes_to_questdb_connection() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb"))
    connection = FakeConnection()
    service._conn = connection
    service._initialized = True

    saved = service.save_tick(
        {
            "vt_symbol": "rb2610.SHFE",
            "symbol": "rb2610",
            "exchange": "SHFE",
            "name": "螺纹钢",
            "datetime": "2026-06-18T10:00:00+08:00",
            "localtime": "2026-06-18T10:00:01+08:00",
            "last_price": 3126,
            "last_volume": 2,
            "volume": 100,
            "turnover": 312600,
            "open_interest": 200,
            "open_price": 3100,
            "high_price": 3130,
            "low_price": 3090,
            "pre_close": 3110,
            "limit_up": 3420,
            "limit_down": 2800,
            "bid_price_1": 3125,
            "bid_price_5": 3121,
            "ask_price_1": 3126,
            "ask_price_5": 3130,
            "bid_volume_1": 10,
            "bid_volume_5": 6,
            "ask_volume_1": 11,
            "ask_volume_5": 7,
            "trading_day": "20260618",
            "action_day": "20260618",
        }
    )

    assert saved is True
    assert len(connection.calls) == 1
    sql, params = connection.calls[0]
    assert "INSERT INTO market_ticks" in sql
    assert "schema_version" in sql
    assert "bid_price_5" in sql
    assert "ask_volume_5" in sql
    assert params
    assert params[TICK_SELECT_FIELDS.index("vt_symbol")] == "rb2610.SHFE"
    assert params[TICK_SELECT_FIELDS.index("ts")] == datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    assert params[TICK_SELECT_FIELDS.index("received_at")] == datetime(2026, 6, 18, 2, 0, 1, tzinfo=timezone.utc)
    assert params[TICK_SELECT_FIELDS.index("schema_version")] == 2
    assert params[TICK_SELECT_FIELDS.index("name")] == "螺纹钢"
    assert len(params[TICK_SELECT_FIELDS.index("ingest_id")]) == 32
    assert params[TICK_SELECT_FIELDS.index("last_price")] == 3126.0
    assert params[TICK_SELECT_FIELDS.index("last_volume")] == 2.0
    assert params[TICK_SELECT_FIELDS.index("bid_price_5")] == 3121.0
    assert params[TICK_SELECT_FIELDS.index("ask_volume_5")] == 7.0


def test_save_tick_uses_ilp_batch_when_configured(monkeypatch) -> None:
    FakeIlpSender.created = []
    monkeypatch.setattr("app.services.market_data_service.QuestDbSender", FakeIlpSender)
    service = QuestDbMarketDataService(
        Settings(
            questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb",
            questdb_ilp_conf="http::addr=questdb:9000;",
        )
    )
    connection = FakeConnection()
    service._conn = connection
    service._initialized = True

    saved = service.save_tick(
        {
            "vt_symbol": "rb2610.SHFE",
            "symbol": "rb2610",
            "exchange": "SHFE",
            "gateway_name": "CTP",
            "datetime": "2026-06-18T10:00:00+08:00",
            "received_at": "2026-06-18T10:00:01+08:00",
            "ingest_id": "event-1",
            "last_price": 3126,
            "volume": 100,
        }
    )

    assert saved is True
    assert service.write_protocol == "ilp"
    assert len(FakeIlpSender.created) == 1
    sender = FakeIlpSender.created[0]
    assert sender.conf == "http::addr=questdb:9000;"
    assert sender.established is True
    assert sender.flushes[0]["transactional"] is True
    row = sender.flushes[0]["rows"][0]
    assert row["table_name"] == "market_ticks"
    assert row["symbols"] == {
        "vt_symbol": "rb2610.SHFE",
        "symbol": "rb2610",
        "exchange": "SHFE",
        "gateway_name": "CTP",
    }
    assert row["columns"]["ingest_id"] == "event-1"
    assert row["columns"]["last_price"] == 3126.0
    assert row["columns"]["volume"] == 100.0
    assert row["at"] == datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    assert not any("INSERT INTO market_ticks" in call[0] for call in connection.calls)


def test_save_tick_rejects_tick_without_datetime_or_price() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb"))
    connection = FakeConnection()
    service._conn = connection
    service._initialized = True

    assert service.save_tick({"vt_symbol": "rb2610.SHFE", "last_price": 3126}) is False
    assert service.save_tick({"vt_symbol": "rb2610.SHFE", "datetime": "2026-06-18T10:00:00+08:00"}) is False

    assert connection.calls == []


def test_normalize_tick_builds_stable_ingest_id() -> None:
    tick = {
        "vt_symbol": "rb2610.SHFE",
        "datetime": "2026-06-18T10:00:00+08:00",
        "name": "螺纹钢",
        "last_price": 3126,
    }

    first = _normalize_tick(tick)
    second = _normalize_tick(tick)

    assert first
    assert second
    assert first["symbol"] == "rb2610"
    assert first["exchange"] == "SHFE"
    assert first["name"] == "螺纹钢"
    assert first["ts"] == datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc)
    assert first["received_at"] == first["ts"]
    assert first["ingest_id"] == second["ingest_id"]


def test_normalize_tick_infers_action_and_trading_day_for_day_session() -> None:
    row = _normalize_tick(
        {
            "vt_symbol": "rb2610.SHFE",
            "datetime": "2026-06-18T10:00:00+08:00",
            "last_price": 3126,
        }
    )

    assert row
    assert row["action_day"] == "20260618"
    assert row["trading_day"] == "20260618"


def test_normalize_tick_infers_next_trading_day_for_night_session() -> None:
    row = _normalize_tick(
        {
            "vt_symbol": "rb2610.SHFE",
            "datetime": "2026-06-12T21:00:00+08:00",
            "last_price": 3126,
        }
    )

    assert row
    assert row["action_day"] == "20260612"
    assert row["trading_day"] == "20260615"


def test_normalize_tick_keeps_explicit_ctp_trading_day() -> None:
    row = _normalize_tick(
        {
            "vt_symbol": "rb2610.SHFE",
            "datetime": "2026-06-12T21:00:00+08:00",
            "last_price": 3126,
            "action_day": "20260612",
            "trading_day": "20260616",
        }
    )

    assert row
    assert row["action_day"] == "20260612"
    assert row["trading_day"] == "20260616"


def test_normalize_tick_does_not_shift_cffex_evening_timestamp() -> None:
    row = _normalize_tick(
        {
            "vt_symbol": "IF2606.CFFEX",
            "datetime": "2026-06-12T21:00:00+08:00",
            "last_price": 4000,
        }
    )

    assert row
    assert row["action_day"] == "20260612"
    assert row["trading_day"] == "20260612"


def test_get_bars_reads_questdb_sampled_rows() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb", vnpy_gateway_name="CTP"))
    connection = FakeConnection(rows=[(datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc), 1.0, 3.0, 0.5, 2.0, 10.0, 20.0)])
    service._conn = connection
    service._initialized = True

    bars = service.get_bars("rb2610", "SHFE", "1m", 20)

    assert bars == [
        {
            "symbol": "rb2610",
            "exchange": "SHFE",
            "vt_symbol": "rb2610.SHFE",
            "datetime": "2026-06-18T02:00:00+00:00",
            "interval": "1m",
            "open_price": 1.0,
            "high_price": 3.0,
            "low_price": 0.5,
            "close_price": 2.0,
            "volume": 10.0,
            "open_interest": 20.0,
            "gateway_name": "CTP",
        }
    ]
    assert "SAMPLE BY 1m" in connection.calls[0][0]


def test_query_ticks_returns_schema_v2_fields() -> None:
    row = []
    for field in TICK_SELECT_FIELDS:
        if field == "ts":
            row.append(datetime(2026, 6, 18, 2, 0, tzinfo=timezone.utc))
        elif field == "received_at":
            row.append(datetime(2026, 6, 18, 2, 0, 1, tzinfo=timezone.utc))
        elif field == "ingest_id":
            row.append("abc123")
        elif field == "schema_version":
            row.append(2)
        elif field == "vt_symbol":
            row.append("rb2610.SHFE")
        elif field == "symbol":
            row.append("rb2610")
        elif field == "exchange":
            row.append("SHFE")
        elif field == "gateway_name":
            row.append("CTP")
        elif field == "name":
            row.append("螺纹钢")
        elif field in ("trading_day", "action_day"):
            row.append("20260618")
        else:
            row.append(1.0)
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb"))
    connection = FakeConnection(rows=[tuple(row)])
    service._conn = connection
    service._initialized = True

    ticks = service.query_ticks(vt_symbol="rb2610.SHFE")

    assert ticks[0]["datetime"] == "2026-06-18T02:00:00+00:00"
    assert ticks[0]["received_at"] == "2026-06-18T02:00:01+00:00"
    assert ticks[0]["ingest_id"] == "abc123"
    assert ticks[0]["schema_version"] == 2
    assert ticks[0]["name"] == "螺纹钢"
    assert ticks[0]["bid_price_5"] == 1.0
    assert "SELECT ts, received_at, ingest_id" in connection.calls[0][0]


def test_init_schema_is_idempotent_for_existing_v1_table() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb"))
    connection = DuplicateColumnConnection()
    service._conn = connection

    service._init_schema()

    assert service._initialized is True
    assert any("CREATE TABLE IF NOT EXISTS market_ticks" in call[0] for call in connection.calls)
    assert any("ALTER TABLE market_ticks ADD COLUMN received_at TIMESTAMP" in call[0] for call in connection.calls)
    assert any("ALTER TABLE market_ticks DEDUP ENABLE UPSERT KEYS(ts, ingest_id)" in call[0] for call in connection.calls)


def test_init_schema_fails_when_upgrade_column_fails() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb"))
    connection = BrokenAlterConnection()
    service._conn = connection

    try:
        service._init_schema()
    except RuntimeError as exc:
        assert "schema upgrade failed" in str(exc)
    else:
        raise AssertionError("schema upgrade failure should be raised")

    assert service._initialized is False


def test_import_ticks_csv_counts_failed_rows_as_skipped() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb"))
    connection = FakeConnection()
    service._conn = connection
    service._initialized = True

    result = service.import_ticks_csv(
        b"datetime,vt_symbol,last_price\n"
        b"2026-06-18T10:00:00+08:00,rb2610.SHFE,3126\n"
        b"2026-06-18T10:00:01+08:00,rb2610.SHFE,\n"
    )

    assert result == {"imported": 1, "skipped": 1, "enabled": True}


def test_csv_export_import_preserves_schema_v2_identity() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb"))
    exported = service.export_ticks_csv(
        [
            {
                "datetime": "2026-06-18T02:00:00+00:00",
                "received_at": "2026-06-18T02:00:01+00:00",
                "ingest_id": "stable-id",
                "schema_version": 2,
                "vt_symbol": "rb2610.SHFE",
                "symbol": "rb2610",
                "exchange": "SHFE",
                "gateway_name": "CTP",
                "name": "螺纹钢",
                "last_price": 3126,
            }
        ]
    )
    connection = FakeConnection()
    service._conn = connection
    service._initialized = True

    result = service.import_ticks_csv(exported.encode("utf-8"))

    assert result == {"imported": 1, "skipped": 0, "enabled": True}
    params = connection.calls[0][1]
    assert params
    assert params[TICK_SELECT_FIELDS.index("ingest_id")] == "stable-id"
    assert params[TICK_SELECT_FIELDS.index("received_at")] == datetime(2026, 6, 18, 2, 0, 1, tzinfo=timezone.utc)
