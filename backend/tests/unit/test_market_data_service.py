from __future__ import annotations

from datetime import datetime, timezone

from app.core.config import Settings
from app.services.market_data_service import QuestDbMarketDataService


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


def test_market_data_service_is_noop_without_dsn() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn=""))

    service.save_tick({"vt_symbol": "rb2610.SHFE", "last_price": 3126})

    assert service.get_bars("rb2610", "SHFE") == []


def test_save_tick_writes_to_questdb_connection() -> None:
    service = QuestDbMarketDataService(Settings(questdb_pg_dsn="postgresql://admin:quest@questdb:8812/qdb"))
    connection = FakeConnection()
    service._conn = connection
    service._initialized = True

    service.save_tick(
        {
            "vt_symbol": "rb2610.SHFE",
            "symbol": "rb2610",
            "exchange": "SHFE",
            "datetime": "2026-06-18T10:00:00+08:00",
            "last_price": 3126,
            "volume": 100,
            "open_interest": 200,
        }
    )

    assert len(connection.calls) == 1
    sql, params = connection.calls[0]
    assert "INSERT INTO market_ticks" in sql
    assert params
    assert params[1] == "rb2610.SHFE"
    assert params[5] == 3126.0


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
