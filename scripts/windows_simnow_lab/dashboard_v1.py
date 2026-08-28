"""Issue #466 SQLite-only read model for the SIMNOW_LAB Dashboard."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SHANGHAI = timezone(timedelta(hours=8), name="Asia/Shanghai")


def _connect_read_only(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _json(value: Any, default: Any) -> Any:
    try:
        parsed = json.loads(value) if isinstance(value, str) else default
    except json.JSONDecodeError:
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _target_quantities(runs: list[dict[str, Any]]) -> dict[str, tuple[str, int]]:
    for run in runs:
        target = _json(run["target_json"], {})
        rows = target.get("targets") if isinstance(target, dict) else None
        if not isinstance(rows, list):
            continue
        result: dict[str, tuple[str, int]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            symbol, product, quantity = row.get("vt_symbol"), row.get("product"), row.get("quantity")
            if isinstance(symbol, str) and isinstance(product, str) and type(quantity) is int:
                result[symbol.lower()] = (product, quantity)
        if result:
            return result
    return {}


def _position_totals(rows: list[Any]) -> dict[str, dict[str, int | float]]:
    result: dict[str, dict[str, int | float]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        symbol = row.get("vt_symbol")
        if not isinstance(symbol, str):
            raw_symbol, exchange = row.get("symbol"), row.get("exchange")
            symbol = f"{raw_symbol}.{exchange}" if isinstance(raw_symbol, str) and isinstance(exchange, str) else None
        volume = row.get("volume")
        direction = str(row.get("direction", "")).upper()
        if not isinstance(symbol, str) or type(volume) not in {int, float} or volume < 0:
            continue
        bucket = result.setdefault(symbol.lower(), {"long_quantity": 0, "short_quantity": 0, "unrealized_pnl": 0.0})
        if direction == "LONG":
            bucket["long_quantity"] += int(volume)
        elif direction == "SHORT":
            bucket["short_quantity"] += int(volume)
        pnl = _number(row.get("pnl"))
        if pnl is not None:
            bucket["unrealized_pnl"] += pnl
    return result


def _shanghai_day(value: str) -> str:
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    observed_at = datetime.fromisoformat(normalized)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    return observed_at.astimezone(SHANGHAI).date().isoformat()


def _series(snapshots: list[dict[str, Any]], trades: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, float | None]]:
    equity_rows = [
        (row["observed_at"], _number(row["equity"]), _number(row["unrealized_pnl"]))
        for row in snapshots
        if _number(row["equity"]) is not None
    ]
    equity = [{"time": at, "value": value} for at, value, _unrealized in equity_rows]
    if not equity_rows:
        empty = {"equity": [], "cumulative_pnl": [], "drawdown": [], "daily_pnl": []}
        return empty, {"cumulative_pnl": None, "drawdown": None, "max_drawdown": None, "realized_pnl": None, "slippage": 0.0}
    baseline, peak = equity_rows[0][1], equity_rows[0][1]
    cumulative: list[dict[str, Any]] = []
    drawdown: list[dict[str, Any]] = []
    daily_last: dict[str, float] = {}
    for at, value, _unrealized in equity_rows:
        peak = max(peak, value)
        cumulative.append({"time": at, "value": value - baseline})
        drawdown.append({"time": at, "value": value - peak})
        daily_last[_shanghai_day(at)] = value
    prior = baseline
    daily = []
    for day, value in sorted(daily_last.items()):
        daily.append({"time": day, "value": value - prior})
        prior = value
    baseline_unrealized = equity_rows[0][2]
    latest_unrealized = equity_rows[-1][2]
    cumulative_value = cumulative[-1]["value"]
    slippage = sum((_number(row["slippage"]) or 0.0) * (_number(row["volume"]) or 0.0) for row in trades)
    return (
        {"equity": equity, "cumulative_pnl": cumulative, "drawdown": drawdown, "daily_pnl": daily},
        {
            "cumulative_pnl": cumulative_value,
            "drawdown": drawdown[-1]["value"],
            "max_drawdown": min(item["value"] for item in drawdown),
            "realized_pnl": cumulative_value - (latest_unrealized - baseline_unrealized)
            if latest_unrealized is not None and baseline_unrealized is not None
            else None,
            "slippage": slippage,
        },
    )


def _incidents(runs: list[dict[str, Any]], orders: list[dict[str, Any]], active_count: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for run in runs:
        if run["error"] or run["status"] == "FAILED":
            result.append({"code": "RUN_ERROR", "message": run["error"] or "FAILED", "observed_at": run["ended_at"] or run["started_at"], "run_id": run["run_id"]})
    for order in orders:
        if order["status"] == "UNKNOWN":
            result.append({"code": "UNKNOWN_ORDER", "message": "UNKNOWN", "observed_at": order["updated_at"], "run_id": order["run_id"]})
    if active_count:
        result.append({"code": "ACTIVE_ORDERS", "message": str(active_count), "observed_at": None, "run_id": None})
    return result


def read_dashboard_v1(db_path: str | Path) -> dict[str, Any]:
    """Return the stable Dashboard DTO without touching the Lab executor or CTP."""

    with _connect_read_only(Path(db_path)) as db:
        runs = [dict(row) for row in db.execute("SELECT run_id,target_id,target_json,started_at,ended_at,status,error FROM runs ORDER BY started_at DESC LIMIT 100")]
        orders = [dict(row) for row in db.execute("SELECT client_order_id,run_id,symbol,direction,offset,quantity,limit_price,broker_order_id,status,traded,created_at,updated_at FROM orders ORDER BY created_at DESC LIMIT 200")]
        trades = [dict(row) for row in db.execute("SELECT trade_key,run_id,client_order_id,broker_order_id,trade_id,symbol,direction,offset,price,volume,trade_time,slippage,created_at FROM trades ORDER BY created_at DESC LIMIT 500")]
        snapshots = [dict(row) for row in db.execute("SELECT * FROM (SELECT snapshot_id,run_id,phase,observed_at,positions_json,active_orders_json,account_json,equity,available,margin,unrealized_pnl FROM snapshots ORDER BY observed_at DESC LIMIT 1000) ORDER BY observed_at")]
        sqlite_active_count = db.execute(
            "SELECT COUNT(*) FROM orders WHERE status IN ('CREATED','SUBMITTED')"
        ).fetchone()[0]
    latest_snapshot = snapshots[-1] if snapshots else None
    latest_run = runs[0] if runs else None
    positions = _json(latest_snapshot["positions_json"], []) if latest_snapshot else []
    active_orders = _json(latest_snapshot["active_orders_json"], []) if latest_snapshot else []
    targets = _target_quantities(runs)
    actual = _position_totals(positions)
    portfolio = []
    for symbol in sorted(set(targets) | set(actual)):
        long_quantity = actual.get(symbol, {}).get("long_quantity", 0)
        short_quantity = actual.get(symbol, {}).get("short_quantity", 0)
        product, target_quantity = targets.get(symbol, (symbol.split(".", 1)[0], 0))
        current_quantity = long_quantity - short_quantity
        delta = target_quantity - current_quantity
        displayed_symbol = f"{symbol.rsplit('.', 1)[0]}.{symbol.rsplit('.', 1)[1].upper()}" if "." in symbol else symbol
        portfolio.append({"product": product, "vt_symbol": displayed_symbol, "target_quantity": target_quantity, "current_quantity": current_quantity, "delta": delta, "unrealized_pnl": actual.get(symbol, {}).get("unrealized_pnl", 0.0), "status": "ALIGNED" if delta == 0 else "DEGRADED"})
    series, calculated = _series(snapshots, trades)
    latest_metrics = latest_snapshot or {}
    active_count = max(len(active_orders), sqlite_active_count)
    unknown_count = sum(order["status"] == "UNKNOWN" for order in orders)
    blocker = "UNKNOWN_ORDER_PRESENT" if unknown_count else "ACTIVE_ORDERS_PRESENT" if active_count else latest_run["error"] if latest_run and latest_run["error"] else None
    state = "UNKNOWN" if unknown_count else "FAILED" if active_count else latest_run["status"] if latest_run else "NO_DATA"
    aligned_products = sum(row["delta"] == 0 for row in portfolio)
    return {
        "schema_version": "simnow_lab_dashboard_v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "runtime_version": os.environ.get("SIMNOW_LAB_RUNTIME_VERSION", "unknown"),
        "summary": {"status": state, "blocker": blocker, "last_run_id": latest_run["run_id"] if latest_run else None, "target_id": latest_run["target_id"] if latest_run else None, "started_at": latest_run["started_at"] if latest_run else None, "ended_at": latest_run["ended_at"] if latest_run else None, "active_order_count": active_count, "unknown_order_count": unknown_count, "aligned_products": aligned_products, "total_products": len(portfolio)},
        "metrics": {"equity": _number(latest_metrics.get("equity")) or 0.0, "available": _number(latest_metrics.get("available")) or 0.0, "margin": _number(latest_metrics.get("margin")) or 0.0, "unrealized_pnl": _number(latest_metrics.get("unrealized_pnl")) or 0.0, "realized_pnl": calculated["realized_pnl"] or 0.0, "cumulative_pnl": calculated["cumulative_pnl"] or 0.0, "daily_pnl": series["daily_pnl"][-1]["value"] if series["daily_pnl"] else 0.0, "max_drawdown": calculated["max_drawdown"] or 0.0, "slippage": calculated["slippage"] or 0.0, "trade_count": len(trades)},
        "series": series,
        "portfolio": portfolio,
        "runs": [{key: run[key] for key in ("run_id", "target_id", "status", "started_at", "ended_at", "error")} for run in runs],
        "orders": orders,
        "trades": trades,
        "snapshots": [{key: row[key] for key in ("snapshot_id", "run_id", "phase", "observed_at", "equity", "available", "margin", "unrealized_pnl")} for row in snapshots],
        "incidents": _incidents(runs, orders, active_count),
    }
