from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from scripts.windows_simnow_lab import dashboard_v1
from scripts.windows_simnow_lab.executor_v1 import SimNowLabExecutorV1


def _db(path: Path) -> Path:
    with sqlite3.connect(path) as db:
        db.executescript(
            """
            CREATE TABLE runs (run_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, target_json TEXT NOT NULL,
                started_at TEXT NOT NULL, ended_at TEXT, status TEXT NOT NULL, error TEXT);
            CREATE TABLE orders (client_order_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, symbol TEXT NOT NULL,
                order_ref TEXT NOT NULL, direction TEXT NOT NULL, offset TEXT NOT NULL, quantity INTEGER NOT NULL,
                touch_price REAL NOT NULL, price_tick REAL NOT NULL, limit_price REAL NOT NULL,
                broker_order_id TEXT, status TEXT NOT NULL, traded REAL NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE trades (trade_key TEXT PRIMARY KEY, run_id TEXT NOT NULL, client_order_id TEXT,
                broker_order_id TEXT NOT NULL, trade_id TEXT NOT NULL, symbol TEXT NOT NULL, direction TEXT NOT NULL,
                offset TEXT NOT NULL, price REAL NOT NULL, volume REAL NOT NULL, trade_time TEXT, slippage REAL, created_at TEXT NOT NULL);
            CREATE TABLE snapshots (snapshot_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, phase TEXT NOT NULL,
                observed_at TEXT NOT NULL, positions_json TEXT NOT NULL, active_orders_json TEXT NOT NULL,
                account_json TEXT NOT NULL, equity REAL, available REAL, margin REAL, unrealized_pnl REAL);
            """
        )
    return path


def test_dashboard_aggregates_sqlite_into_stable_dto(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _db(tmp_path / "lab.sqlite3")
    monkeypatch.setenv("SIMNOW_LAB_RUNTIME_VERSION", "win-runtime-sha")
    target = {"targets": [{"product": "ag", "vt_symbol": "ag2610.SHFE", "quantity": 2}]}
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?)", ("a" * 32, "target-1", json.dumps(target), "2026-08-28T01:00:00Z", "2026-08-28T01:01:00Z", "DONE", None))
        db.execute("INSERT INTO orders VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("order-1", "a" * 32, "ag2610.SHFE", "1", "LONG", "OPEN", 2, 100, 1, 101, "CTP.1", "FILLED", 2, "2026-08-28T01:00:10Z", "2026-08-28T01:00:20Z"))
        db.execute("INSERT INTO trades VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", ("trade-1", "a" * 32, "order-1", "CTP.1", "1", "ag2610.SHFE", "LONG", "OPEN", 102, 2, "2026-08-28T01:00:20Z", 2, "2026-08-28T01:00:20Z"))
        db.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("before", "a" * 32, "BEFORE", "2026-08-28T01:00:00Z", "[]", "[]", "[]", 1000, 900, 100, 0))
        db.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("after", "a" * 32, "AFTER", "2026-08-28T01:01:00Z", json.dumps([{ "vt_symbol": "ag2610.SHFE", "direction": "LONG", "volume": 2, "pnl": 12.5 }]), "[]", "[]", 1010, 905, 105, 12.5))

    result = dashboard_v1.read_dashboard_v1(path)

    assert result["schema_version"] == "simnow_lab_dashboard_v1"
    assert result["runtime_version"] == "win-runtime-sha"
    assert result["summary"] == {"status": "DONE", "blocker": None, "last_run_id": "a" * 32, "target_id": "target-1", "started_at": "2026-08-28T01:00:00Z", "ended_at": "2026-08-28T01:01:00Z", "active_order_count": 0, "unknown_order_count": 0, "aligned_products": 1, "total_products": 1}
    assert result["portfolio"] == [{"product": "ag", "vt_symbol": "ag2610.SHFE", "target_quantity": 2, "current_quantity": 2, "delta": 0, "unrealized_pnl": 12.5, "status": "ALIGNED"}]
    assert result["metrics"] == {"equity": 1010.0, "available": 905.0, "margin": 105.0, "unrealized_pnl": 12.5, "realized_pnl": -2.5, "cumulative_pnl": 10.0, "daily_pnl": 10.0, "max_drawdown": 0.0, "slippage": 4.0, "trade_count": 1}
    assert set(result["series"]) == {"equity", "cumulative_pnl", "drawdown", "daily_pnl"}
    assert result["series"]["equity"][-1] == {"time": "2026-08-28T01:01:00Z", "value": 1010.0}
    assert result["runs"] == [{"run_id": "a" * 32, "target_id": "target-1", "status": "DONE", "started_at": "2026-08-28T01:00:00Z", "ended_at": "2026-08-28T01:01:00Z", "error": None}]
    assert result["orders"][0]["broker_order_id"] == "CTP.1"
    assert result["trades"][0]["slippage"] == 2.0
    assert result["snapshots"][-1]["snapshot_id"] == "after"
    assert result["incidents"] == []


def test_dashboard_empty_database_is_stable_and_cannot_write(tmp_path: Path) -> None:
    path = _db(tmp_path / "empty.sqlite3")

    result = dashboard_v1.read_dashboard_v1(path)

    assert result["summary"]["status"] == "NO_DATA"
    assert result["metrics"] == {"equity": 0.0, "available": 0.0, "margin": 0.0, "unrealized_pnl": 0.0, "realized_pnl": 0.0, "cumulative_pnl": 0.0, "daily_pnl": 0.0, "max_drawdown": 0.0, "slippage": 0.0, "trade_count": 0}
    with dashboard_v1._connect_read_only(path) as db, pytest.raises(sqlite3.OperationalError):
        db.execute("INSERT INTO runs VALUES('x','x','{}','x',NULL,'DONE',NULL)")


def test_dashboard_dispatch_touches_neither_execution_queries_nor_locks(tmp_path: Path) -> None:
    path = _db(tmp_path / "dispatch.sqlite3")

    class Forbidden:
        def __getattr__(self, _name: str) -> object:
            raise AssertionError("DASHBOARD must not access executor state")

    subject = object.__new__(SimNowLabExecutorV1)
    subject.db_path = path
    subject.main_engine = Forbidden()
    subject._thread_lock = Forbidden()

    assert subject.simnow_lab_get_run_v1("DASHBOARD")["summary"]["status"] == "NO_DATA"


def test_dashboard_uses_latest_snapshot_after_history_exceeds_limit(tmp_path: Path) -> None:
    path = _db(tmp_path / "history.sqlite3")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?)", ("a" * 32, "target", '{"targets":[]}', "2026-01-01T00:00:00Z", None, "DONE", None))
        db.executemany(
            "INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            [(f"s{index}", "a" * 32, "AFTER", f"2026-01-{1 + index // 100:02d}T00:{index % 60:02d}:00Z", "[]", "[]", "[]", index, index, 0, 0) for index in range(1001)],
        )

    assert dashboard_v1.read_dashboard_v1(path)["metrics"]["equity"] == 1000.0


def test_dashboard_counts_running_sqlite_orders_missing_from_before_snapshot(tmp_path: Path) -> None:
    path = _db(tmp_path / "active.sqlite3")
    run_id = "a" * 32
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO runs VALUES(?,?,?,?,?,?,?)",
            (run_id, "target", '{"targets":[]}', "2026-08-28T01:00:00Z", None, "RUNNING", None),
        )
        db.execute(
            "INSERT INTO orders VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "order-active", run_id, "ag2610.SHFE", "1", "LONG", "OPEN", 1,
                100, 1, 101, "CTP.1", "SUBMITTED", 0,
                "2026-08-28T01:00:10Z", "2026-08-28T01:00:10Z",
            ),
        )
        db.execute(
            "INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("before", run_id, "BEFORE", "2026-08-28T01:00:00Z", "[]", "[]", "[]", 1000, 900, 100, 0),
        )

    result = dashboard_v1.read_dashboard_v1(path)

    assert result["summary"]["active_order_count"] == 1
    assert {incident["code"] for incident in result["incidents"]} == {"ACTIVE_ORDERS"}


def test_dashboard_realized_pnl_subtracts_only_unrealized_change(tmp_path: Path) -> None:
    path = _db(tmp_path / "realized.sqlite3")
    run_id = "a" * 32
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO runs VALUES(?,?,?,?,?,?,?)",
            (run_id, "target", '{"targets":[]}', "2026-08-28T01:00:00Z", None, "DONE", None),
        )
        db.executemany(
            "INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            [
                ("before", run_id, "BEFORE", "2026-08-28T01:00:00Z", "[]", "[]", "[]", 1000, 900, 100, 25),
                ("after", run_id, "AFTER", "2026-08-28T01:01:00Z", "[]", "[]", "[]", 1010, 905, 105, 30),
            ],
        )

    assert dashboard_v1.read_dashboard_v1(path)["metrics"]["realized_pnl"] == 5.0


def test_dashboard_daily_pnl_uses_shanghai_calendar_day(tmp_path: Path) -> None:
    path = _db(tmp_path / "shanghai-day.sqlite3")
    run_id = "a" * 32
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO runs VALUES(?,?,?,?,?,?,?)",
            (run_id, "target", '{"targets":[]}', "2026-08-27T15:30:00Z", None, "DONE", None),
        )
        db.executemany(
            "INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            [
                ("before", run_id, "BEFORE", "2026-08-27T15:30:00Z", "[]", "[]", "[]", 100, 100, 0, 0),
                ("after", run_id, "AFTER", "2026-08-27T16:30:00Z", "[]", "[]", "[]", 110, 110, 0, 0),
            ],
        )

    daily = dashboard_v1.read_dashboard_v1(path)["series"]["daily_pnl"]

    assert daily == [
        {"time": "2026-08-27", "value": 0.0},
        {"time": "2026-08-28", "value": 10.0},
    ]
