"""Read SIMNOW_LAB SQLite coverage for a Shanghai-calendar reporting interval."""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

SHANGHAI = timezone(timedelta(hours=8), name="Asia/Shanghai")


def _read_only(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def _range_start(day: date) -> datetime:
    return datetime.combine(day, time.min, tzinfo=SHANGHAI).astimezone(timezone.utc)


def _coverage(rows: list[sqlite3.Row], timestamp_key: str, start: datetime, end: datetime) -> tuple[list[tuple[datetime, sqlite3.Row]], dict[str, Any]]:
    valid = [(at, row) for row in rows if (at := _instant(row[timestamp_key])) is not None]
    valid.sort(key=lambda item: item[0])
    selected = [(at, row) for at, row in valid if start <= at < end]
    first, last = (valid[0][0], valid[-1][0]) if valid else (None, None)
    return selected, {
        "records_total": len(rows),
        "records_with_valid_time": len(valid),
        "invalid_time_rows": len(rows) - len(valid),
        "records_in_requested_range": len(selected),
        "first_observed_at": first.isoformat().replace("+00:00", "Z") if first else None,
        "last_observed_at": last.isoformat().replace("+00:00", "Z") if last else None,
        "requested_window_bracketed_by_observations": bool(first is not None and first <= start and last is not None and last >= end),
    }


def build_report(db_path: Path, start_day: date, end_day: date) -> dict[str, Any]:
    if end_day < start_day:
        raise ValueError("END_BEFORE_START")
    start, end = _range_start(start_day), _range_start(end_day + timedelta(days=1))
    with _read_only(db_path) as db:
        snapshot_rows = list(db.execute("SELECT observed_at,equity,unrealized_pnl FROM snapshots ORDER BY observed_at"))
        trade_rows = list(db.execute("SELECT created_at,volume,slippage FROM trades ORDER BY created_at"))
    snapshots, snapshot_coverage = _coverage(snapshot_rows, "observed_at", start, end)
    trades, trade_coverage = _coverage(trade_rows, "created_at", start, end)
    equity_rows = [(at, _number(row["equity"]), _number(row["unrealized_pnl"])) for at, row in snapshots]
    equity_rows = [row for row in equity_rows if row[1] is not None]
    equity_start = equity_rows[0][1] if equity_rows else None
    equity_end = equity_rows[-1][1] if equity_rows else None
    equity_change = equity_end - equity_start if equity_start is not None and equity_end is not None else None
    unrealized_start = equity_rows[0][2] if equity_rows else None
    unrealized_end = equity_rows[-1][2] if equity_rows else None
    realized_estimate = (
        equity_change - (unrealized_end - unrealized_start)
        if equity_change is not None and unrealized_start is not None and unrealized_end is not None
        else None
    )
    peak: float | None = None
    max_drawdown: float | None = None
    for _at, equity, _unrealized in equity_rows:
        peak = equity if peak is None else max(peak, equity)
        drawdown = equity - peak
        max_drawdown = drawdown if max_drawdown is None else min(max_drawdown, drawdown)
    slippage_sum, missing_slippage_rows = 0.0, 0
    for _at, row in trades:
        slippage, volume = _number(row["slippage"]), _number(row["volume"])
        if slippage is None or volume is None:
            missing_slippage_rows += 1
        else:
            slippage_sum += slippage * volume
    return {
        "schema_version": "vnpy_returns_report_v1",
        "requested_interval": {
            "start_date": start_day.isoformat(),
            "end_date": end_day.isoformat(),
            "timezone": "Asia/Shanghai",
        },
        "coverage": {"snapshots": snapshot_coverage, "trades": trade_coverage},
        "observed_metrics": {
            "equity_start": equity_start,
            "equity_end": equity_end,
            "equity_change": equity_change,
            "max_drawdown_amount": max_drawdown,
            "realized_pnl_change_estimate": realized_estimate,
            "trade_count": len(trades),
            "slippage_times_volume_sum": slippage_sum if not missing_slippage_rows else None,
            "slippage_rows_missing_value": missing_slippage_rows,
        },
        "strategy_net_return": {"status": "NOT_INDEPENDENTLY_VERIFIABLE", "value": None},
        "fees": {"status": "UNVERIFIED_NO_FEE_FIELD", "value": None},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db_path", type=Path)
    parser.add_argument("--start", required=True, type=date.fromisoformat)
    parser.add_argument("--end", required=True, type=date.fromisoformat)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.db_path, args.start, args.end)
    except (OSError, sqlite3.Error, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
