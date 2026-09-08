from __future__ import annotations

import importlib.util
import sqlite3
from datetime import date
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "inspect_returns_v1.py"
SPEC = importlib.util.spec_from_file_location("inspect_returns_v1", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _database(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.executescript(
            """
            CREATE TABLE snapshots (observed_at TEXT NOT NULL, equity REAL, unrealized_pnl REAL);
            CREATE TABLE trades (created_at TEXT NOT NULL, volume REAL NOT NULL, slippage REAL);
            INSERT INTO snapshots VALUES ('2026-08-10T00:00:00Z', 1000, 10);
            INSERT INTO snapshots VALUES ('2026-08-15T00:00:00Z', 1015, 12);
            INSERT INTO trades VALUES ('2026-08-15T00:00:00Z', 2, 0.5);
            """
        )


def test_partial_month_keeps_missing_coverage_and_fee_unknown(tmp_path: Path) -> None:
    db_path = tmp_path / "lab.sqlite3"
    _database(db_path)

    report = MODULE.build_report(db_path, date(2026, 8, 1), date(2026, 8, 31))

    assert report["coverage"]["snapshots"]["records_in_requested_range"] == 2
    assert report["coverage"]["snapshots"]["requested_window_bracketed_by_observations"] is False
    assert report["observed_metrics"]["equity_change"] == 15.0
    assert report["fees"] == {"status": "UNVERIFIED_NO_FEE_FIELD", "value": None}
    assert report["strategy_net_return"]["value"] is None


def test_reader_cannot_write(tmp_path: Path) -> None:
    db_path = tmp_path / "readonly.sqlite3"
    _database(db_path)

    with MODULE._read_only(db_path) as db:
        try:
            db.execute("DELETE FROM snapshots")
        except sqlite3.OperationalError:
            pass
        else:
            raise AssertionError("returns reader unexpectedly wrote to SQLite")
