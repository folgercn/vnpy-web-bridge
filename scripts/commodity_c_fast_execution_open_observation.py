#!/usr/bin/env python3
"""Freeze Web Bridge CTP ticks as a create-only execution-open observation."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path

from research_warehouse.canonical import canonical_json_line, parse_json_strict, sha256
from research_warehouse.file_integrity import read_regular_strict
from research_warehouse.timeutil import format_utc

CONTRACT = re.compile(r"^(SHFE|INE)\.([a-z]{1,2})([0-9]{4})$")
PRODUCTS = {"ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn"}


def _private_parent(path: Path) -> None:
    parent = path.parent.resolve(strict=True)
    mode = parent.stat().st_mode & 0o777
    if mode & 0o077:
        raise RuntimeError("output parent must be private")


def _create(path: Path, raw: bytes) -> None:
    _private_parent(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb", closefd=True) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(fd)


def _day(value: object) -> str:
    text = str(value or "")
    if re.fullmatch(r"[0-9]{8}", text):
        text = f"{text[:4]}-{text[4:6]}-{text[6:]}"
    return date.fromisoformat(text).isoformat()


def _capture_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise TypeError("tick datetime is not text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("tick datetime has no timezone")
    return parsed.astimezone(timezone.utc)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create(args: argparse.Namespace) -> int:
    capture_raw = read_regular_strict(
        args.input, "Web Bridge CTP tick capture", limit=8 * 1024 * 1024
    )
    payload = parse_json_strict(capture_raw, "Web Bridge CTP tick capture")
    if isinstance(payload, dict):
        payload = payload.get("data")
    if not isinstance(payload, list):
        raise TypeError("tick capture must be a list or API data list")
    execution_day = date.fromisoformat(args.execution_day).isoformat()
    observed_at = _now_utc()
    selected: dict[str, tuple[datetime, dict[str, object]]] = {}
    for source in payload:
        if not isinstance(source, dict):
            continue
        symbol = str(source.get("symbol") or "").lower()
        exchange = str(source.get("exchange") or "").upper()
        exact = f"{exchange}.{symbol}"
        match = CONTRACT.fullmatch(exact)
        if match is None or match.group(2) not in PRODUCTS:
            continue
        try:
            trading_day = _day(source.get("trading_day"))
            tick_at = _capture_time(source.get("datetime"))
            price = float(source.get("open_price"))
        except (TypeError, ValueError):
            continue
        if (
            trading_day != execution_day
            or not math.isfinite(price)
            or price <= 0
            or tick_at > observed_at
        ):
            continue
        row = {
            "exact_contract": exact,
            "exchange": exchange,
            "open_price": price,
            "tick_datetime": format_utc(tick_at, "tick datetime"),
            "trading_day": trading_day,
            "gateway_name": str(source.get("gateway_name") or ""),
        }
        if row["gateway_name"] != "CTP":
            continue
        previous = selected.get(exact)
        if previous is None or tick_at > previous[0]:
            selected[exact] = (tick_at, row)
    rows = [selected[key][1] for key in sorted(selected)]
    covered = {CONTRACT.fullmatch(str(row["exact_contract"])).group(2) for row in rows}
    if covered != PRODUCTS:
        raise RuntimeError("tick capture does not cover all ten C_FAST products")
    tick_raw = canonical_json_line(rows)
    receipt = {
        "schema_version": "commodity_c_fast_execution_open_observation_v1",
        "purpose": "c_fast_execution_open_observation",
        "execution_day": execution_day,
        "observed_at": format_utc(observed_at, "observed_at"),
        "source": "SIMNOW_CTP_EXCHANGE_MARKET_DATA",
        "capture_raw_sha256": sha256(capture_raw),
        "capture_raw_bytes": len(capture_raw),
        "tick_export_raw_sha256": sha256(tick_raw),
        "tick_export_raw_bytes": len(tick_raw),
        "rows": rows,
        "authority": "RESEARCH_EVIDENCE_ONLY",
    }
    _create(args.ticks_output, tick_raw)
    _create(args.receipt_output, canonical_json_line(receipt))
    print(
        json.dumps(
            {
                "status": "C_FAST_EXECUTION_OPEN_OBSERVATION_CREATED",
                "rows": len(rows),
                "products": sorted(covered),
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--execution-day", required=True)
    parser.add_argument("--ticks-output", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path, required=True)
    return create(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
