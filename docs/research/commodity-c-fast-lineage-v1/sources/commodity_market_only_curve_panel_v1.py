#!/usr/bin/env python3
"""Build a market-only PIT daily commodity curve panel from official payloads.

The extractor reads only local SHFE/INE official daily JSON payloads.  It never
reads strategy events, trades, positions, labels, outcomes, or PnL.  Every
feature row is observed on ``source_official_day`` and is published only for
the next observed official trading day in ``available_official_day``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_SHFE_ROOT = PROJECT_ROOT / "raw" / "shfe_official_daily"
DEFAULT_INE_ROOT = PROJECT_ROOT / "raw" / "ine_official_daily"
DEFAULT_OUTPUT_DIR = (
    PROJECT_ROOT
    / "research"
    / "entry_redesign"
    / "scripts"
    / "output"
    / "commodity_market_only_curve_panel_v1_20260717"
)

FIXED_PRODUCTS = (
    ("ag", "SHFE"),
    ("al", "SHFE"),
    ("au", "SHFE"),
    ("bu", "SHFE"),
    ("cu", "SHFE"),
    ("rb", "SHFE"),
    ("ru", "SHFE"),
    ("sc", "INE"),
    ("sp", "SHFE"),
    ("zn", "SHFE"),
)
PRODUCT_TO_EXCHANGE = dict(FIXED_PRODUCTS)

CONTRACT_COLUMNS = [
    "source_official_day",
    "available_official_day",
    "product",
    "exchange",
    "exact_contract",
    "delivery_month",
    "delivery_yyyymm",
    "open",
    "high",
    "low",
    "close",
    "settlement",
    "pre_settlement",
    "volume",
    "turnover",
    "open_interest",
    "open_interest_change",
    "eligible_curve_contract",
    "delivery_rank",
    "oi_rank",
    "volume_rank",
]

FEATURE_COLUMNS = [
    "source_official_day",
    "available_official_day",
    "product",
    "exchange",
    "near_symbol",
    "near_delivery_month",
    "near_settlement",
    "near_open_interest",
    "next_symbol",
    "next_delivery_month",
    "next_settlement",
    "next_open_interest",
    "third_symbol",
    "third_delivery_month",
    "third_settlement",
    "third_open_interest",
    "near_next_gap_months",
    "next_third_gap_months",
    "near_next_log_carry_per_month",
    "near_next_log_carry_annualized",
    "next_third_log_carry_per_month",
    "next_third_log_carry_annualized",
    "curve_log_carry_curvature_per_month",
    "main_symbol",
    "main_delivery_month",
    "main_settlement",
    "main_open_interest",
    "secondary_symbol",
    "secondary_delivery_month",
    "secondary_settlement",
    "secondary_open_interest",
    "third_oi_symbol",
    "third_oi_delivery_month",
    "third_oi_settlement",
    "third_oi_open_interest",
    "main_secondary_near_symbol",
    "main_secondary_far_symbol",
    "main_secondary_gap_months",
    "main_secondary_log_carry_per_month",
    "main_secondary_log_carry_annualized",
    "eligible_contract_count",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shfe-root", type=Path, default=DEFAULT_SHFE_ROOT)
    parser.add_argument("--ine-root", type=Path, default=DEFAULT_INE_ROOT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _number(value: Any) -> float:
    if value is None or value == "":
        return float("nan")
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def _csv_number(value: float) -> str:
    if not math.isfinite(value):
        return ""
    return format(value, ".12g")


def delivery_yyyymm(delivery_month: str) -> int:
    if not re.fullmatch(r"\d{4}", delivery_month):
        raise ValueError(f"invalid delivery month: {delivery_month!r}")
    year = 2000 + int(delivery_month[:2])
    month = int(delivery_month[2:])
    if not 1 <= month <= 12:
        raise ValueError(f"invalid delivery month: {delivery_month!r}")
    return year * 100 + month


def month_index(yyyymm: int) -> int:
    return (yyyymm // 100) * 12 + (yyyymm % 100) - 1


def month_gap(near_yyyymm: int, far_yyyymm: int) -> int:
    return month_index(far_yyyymm) - month_index(near_yyyymm)


def log_carry_per_month(near_price: float, far_price: float, gap_months: int) -> float:
    if near_price <= 0 or far_price <= 0 or gap_months <= 0:
        raise ValueError("carry requires positive prices and positive delivery-month gap")
    # Positive means backwardation: the near contract is more expensive.
    return math.log(near_price / far_price) / gap_months


def discover_payloads(root: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    hashes: dict[str, str] = {}
    for path in sorted(root.glob("*/payloads/kx*.dat")):
        match = re.fullmatch(r"kx(\d{8})\.dat", path.name)
        if not match:
            continue
        official_day = match.group(1)
        digest = sha256_file(path)
        if official_day in found and hashes[official_day] != digest:
            raise RuntimeError(f"conflicting payloads for {official_day}: {found[official_day]} vs {path}")
        found[official_day] = path
        hashes[official_day] = digest
    if not found:
        raise RuntimeError(f"no official payloads under {root}")
    return found


def parse_payload_rows(
    path: Path,
    official_day: str,
    exchange: str,
    allowed_products: set[str],
) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    report_date = str(payload.get("report_date", ""))
    if report_date and report_date != official_day:
        raise RuntimeError(f"payload report_date mismatch: {path}: {report_date} != {official_day}")

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw in payload.get("o_curinstrument", []):
        product = str(raw.get("PRODUCTGROUPID", "")).strip()
        delivery_month = str(raw.get("DELIVERYMONTH", "")).strip()
        product_class = str(raw.get("PRODUCTCLASS", "")).strip()
        if product not in allowed_products or product_class != "1" or not re.fullmatch(r"\d{4}", delivery_month):
            continue
        key = (product, delivery_month)
        if key in seen:
            raise RuntimeError(f"duplicate exact contract row in {path}: {key}")
        seen.add(key)
        yyyymm = delivery_yyyymm(delivery_month)
        rows.append(
            {
                "source_official_day": datetime.strptime(official_day, "%Y%m%d").date().isoformat(),
                "product": product,
                "exchange": exchange,
                "exact_contract": f"{exchange}.{product}{delivery_month}",
                "delivery_month": delivery_month,
                "delivery_yyyymm": yyyymm,
                "open": _number(raw.get("OPENPRICE")),
                "high": _number(raw.get("HIGHESTPRICE")),
                "low": _number(raw.get("LOWESTPRICE")),
                "close": _number(raw.get("CLOSEPRICE")),
                "settlement": _number(raw.get("SETTLEMENTPRICE")),
                "pre_settlement": _number(raw.get("PRESETTLEMENTPRICE")),
                "volume": _number(raw.get("VOLUME")),
                "turnover": _number(raw.get("TURNOVER")),
                "open_interest": _number(raw.get("OPENINTEREST")),
                "open_interest_change": _number(raw.get("OPENINTERESTCHG")),
            }
        )
    return rows


def assign_source_day_ranks(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        raise ValueError("cannot rank an empty source-day group")
    source_yyyymm = int(rows[0]["source_official_day"].replace("-", "")[:6])
    for row in rows:
        eligible = (
            row["delivery_yyyymm"] > source_yyyymm
            and math.isfinite(row["settlement"])
            and row["settlement"] > 0
            and math.isfinite(row["open_interest"])
            and row["open_interest"] > 0
        )
        row["eligible_curve_contract"] = eligible
        row["delivery_rank"] = ""
        row["oi_rank"] = ""
        row["volume_rank"] = ""

    eligible_rows = [row for row in rows if row["eligible_curve_contract"]]
    by_delivery = sorted(eligible_rows, key=lambda row: (row["delivery_yyyymm"], row["exact_contract"]))
    by_oi = sorted(
        eligible_rows,
        key=lambda row: (-row["open_interest"], row["delivery_yyyymm"], row["exact_contract"]),
    )
    by_volume = sorted(
        eligible_rows,
        key=lambda row: (
            -(row["volume"] if math.isfinite(row["volume"]) else -1.0),
            row["delivery_yyyymm"],
            row["exact_contract"],
        ),
    )
    for rank, row in enumerate(by_delivery, start=1):
        row["delivery_rank"] = rank
    for rank, row in enumerate(by_oi, start=1):
        row["oi_rank"] = rank
    for rank, row in enumerate(by_volume, start=1):
        row["volume_rank"] = rank
    return rows


def _pick(rows: Iterable[dict[str, Any]], column: str, rank: int) -> dict[str, Any]:
    matches = [row for row in rows if row[column] == rank]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one {column}={rank}, got {len(matches)}")
    return matches[0]


def build_feature_row(rows: list[dict[str, Any]], available_official_day: str) -> dict[str, Any]:
    eligible = [row for row in rows if row["eligible_curve_contract"]]
    if len(eligible) < 3:
        raise RuntimeError(
            f"fewer than three eligible contracts: {rows[0]['source_official_day']} {rows[0]['product']}"
        )
    near = _pick(eligible, "delivery_rank", 1)
    next_contract = _pick(eligible, "delivery_rank", 2)
    third = _pick(eligible, "delivery_rank", 3)
    main = _pick(eligible, "oi_rank", 1)
    secondary = _pick(eligible, "oi_rank", 2)
    third_oi = _pick(eligible, "oi_rank", 3)

    gap12 = month_gap(near["delivery_yyyymm"], next_contract["delivery_yyyymm"])
    gap23 = month_gap(next_contract["delivery_yyyymm"], third["delivery_yyyymm"])
    carry12 = log_carry_per_month(near["settlement"], next_contract["settlement"], gap12)
    carry23 = log_carry_per_month(next_contract["settlement"], third["settlement"], gap23)

    oi_near, oi_far = sorted((main, secondary), key=lambda row: row["delivery_yyyymm"])
    oi_gap = month_gap(oi_near["delivery_yyyymm"], oi_far["delivery_yyyymm"])
    if oi_gap <= 0:
        raise RuntimeError("main and secondary resolve to the same delivery month")
    oi_carry = log_carry_per_month(oi_near["settlement"], oi_far["settlement"], oi_gap)

    return {
        "source_official_day": near["source_official_day"],
        "available_official_day": available_official_day,
        "product": near["product"],
        "exchange": near["exchange"],
        "near_symbol": near["exact_contract"],
        "near_delivery_month": near["delivery_month"],
        "near_settlement": near["settlement"],
        "near_open_interest": near["open_interest"],
        "next_symbol": next_contract["exact_contract"],
        "next_delivery_month": next_contract["delivery_month"],
        "next_settlement": next_contract["settlement"],
        "next_open_interest": next_contract["open_interest"],
        "third_symbol": third["exact_contract"],
        "third_delivery_month": third["delivery_month"],
        "third_settlement": third["settlement"],
        "third_open_interest": third["open_interest"],
        "near_next_gap_months": gap12,
        "next_third_gap_months": gap23,
        "near_next_log_carry_per_month": carry12,
        "near_next_log_carry_annualized": carry12 * 12.0,
        "next_third_log_carry_per_month": carry23,
        "next_third_log_carry_annualized": carry23 * 12.0,
        "curve_log_carry_curvature_per_month": carry12 - carry23,
        "main_symbol": main["exact_contract"],
        "main_delivery_month": main["delivery_month"],
        "main_settlement": main["settlement"],
        "main_open_interest": main["open_interest"],
        "secondary_symbol": secondary["exact_contract"],
        "secondary_delivery_month": secondary["delivery_month"],
        "secondary_settlement": secondary["settlement"],
        "secondary_open_interest": secondary["open_interest"],
        "third_oi_symbol": third_oi["exact_contract"],
        "third_oi_delivery_month": third_oi["delivery_month"],
        "third_oi_settlement": third_oi["settlement"],
        "third_oi_open_interest": third_oi["open_interest"],
        "main_secondary_near_symbol": oi_near["exact_contract"],
        "main_secondary_far_symbol": oi_far["exact_contract"],
        "main_secondary_gap_months": oi_gap,
        "main_secondary_log_carry_per_month": oi_carry,
        "main_secondary_log_carry_annualized": oi_carry * 12.0,
        "eligible_contract_count": len(eligible),
    }


def load_market_rows(shfe_root: Path, ine_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    shfe_payloads = discover_payloads(shfe_root)
    ine_payloads = discover_payloads(ine_root)
    if set(shfe_payloads) != set(ine_payloads):
        only_shfe = sorted(set(shfe_payloads) - set(ine_payloads))
        only_ine = sorted(set(ine_payloads) - set(shfe_payloads))
        raise RuntimeError(f"SHFE/INE official-day mismatch: only_shfe={only_shfe}, only_ine={only_ine}")

    shfe_products = {product for product, exchange in FIXED_PRODUCTS if exchange == "SHFE"}
    ine_products = {product for product, exchange in FIXED_PRODUCTS if exchange == "INE"}
    rows: list[dict[str, Any]] = []
    input_receipts: list[dict[str, Any]] = []
    for official_day in sorted(shfe_payloads):
        for exchange, path, products in (
            ("SHFE", shfe_payloads[official_day], shfe_products),
            ("INE", ine_payloads[official_day], ine_products),
        ):
            parsed = parse_payload_rows(path, official_day, exchange, products)
            rows.extend(parsed)
            input_receipts.append(
                {
                    "official_day": datetime.strptime(official_day, "%Y%m%d").date().isoformat(),
                    "exchange": exchange,
                    "relative_path": str(path.relative_to(PROJECT_ROOT)),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "selected_rows": len(parsed),
                }
            )
    return rows, {
        "shfe_payload_count": len(shfe_payloads),
        "ine_payload_count": len(ine_payloads),
        "official_day_start": datetime.strptime(min(shfe_payloads), "%Y%m%d").date().isoformat(),
        "official_day_end": datetime.strptime(max(shfe_payloads), "%Y%m%d").date().isoformat(),
        "input_receipts": input_receipts,
    }


def build_panels(raw_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    days: set[str] = set()
    for row in raw_rows:
        grouped[(row["source_official_day"], row["product"])].append(dict(row))
        days.add(row["source_official_day"])
    ordered_days = sorted(days)
    next_day = {day: ordered_days[index + 1] for index, day in enumerate(ordered_days[:-1])}

    contract_rows: list[dict[str, Any]] = []
    feature_rows: list[dict[str, Any]] = []
    for source_day in ordered_days[:-1]:
        available_day = next_day[source_day]
        if available_day <= source_day:
            raise RuntimeError("available day must be strictly after source day")
        for product, exchange in FIXED_PRODUCTS:
            key = (source_day, product)
            if key not in grouped:
                raise RuntimeError(f"missing fixed product/day: {source_day} {product}")
            ranked = assign_source_day_ranks(grouped[key])
            for row in ranked:
                row["available_official_day"] = available_day
                contract_rows.append(row)
            feature_rows.append(build_feature_row(ranked, available_day))
    return contract_rows, feature_rows


def validate_panels(contract_rows: list[dict[str, Any]], feature_rows: list[dict[str, Any]]) -> dict[str, Any]:
    expected_products = {product for product, _ in FIXED_PRODUCTS}
    feature_keys: set[tuple[str, str]] = set()
    counts: dict[str, int] = defaultdict(int)
    for row in feature_rows:
        key = (row["source_official_day"], row["product"])
        if key in feature_keys:
            raise RuntimeError(f"duplicate feature key: {key}")
        feature_keys.add(key)
        counts[row["product"]] += 1
        if row["available_official_day"] <= row["source_official_day"]:
            raise RuntimeError(f"non-causal availability: {key}")
        for column in (
            "near_next_log_carry_per_month",
            "near_next_log_carry_annualized",
            "next_third_log_carry_per_month",
            "curve_log_carry_curvature_per_month",
            "main_secondary_log_carry_per_month",
        ):
            if not math.isfinite(float(row[column])):
                raise RuntimeError(f"non-finite feature {column}: {key}")
        if int(row["near_next_gap_months"]) <= 0 or int(row["next_third_gap_months"]) <= 0:
            raise RuntimeError(f"non-positive maturity gap: {key}")
        if int(row["eligible_contract_count"]) < 3:
            raise RuntimeError(f"insufficient eligible curve depth: {key}")
    if set(counts) != expected_products or len(set(counts.values())) != 1:
        raise RuntimeError(f"unbalanced fixed panel: {dict(counts)}")

    contract_keys: set[tuple[str, str]] = set()
    for row in contract_rows:
        key = (row["source_official_day"], row["exact_contract"])
        if key in contract_keys:
            raise RuntimeError(f"duplicate contract key: {key}")
        contract_keys.add(key)
        if row["available_official_day"] <= row["source_official_day"]:
            raise RuntimeError(f"non-causal contract availability: {key}")

    return {
        "status": "PASS",
        "fixed_product_count": len(expected_products),
        "feature_rows": len(feature_rows),
        "contract_rows": len(contract_rows),
        "source_days_per_product": next(iter(set(counts.values()))),
        "source_official_day_start": min(row["source_official_day"] for row in feature_rows),
        "source_official_day_end": max(row["source_official_day"] for row in feature_rows),
        "available_official_day_start": min(row["available_official_day"] for row in feature_rows),
        "available_official_day_end": max(row["available_official_day"] for row in feature_rows),
        "min_eligible_contract_count": min(int(row["eligible_contract_count"]) for row in feature_rows),
        "future_main_chain_lookup_used": False,
        "pnl_or_outcome_read": False,
        "legacy_ledger_read": False,
        "network_accessed": False,
    }


def write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    column: _csv_number(value) if isinstance((value := row.get(column, "")), float) else value
                    for column in columns
                }
            )


def main() -> int:
    args = parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"refusing to overwrite existing output directory: {args.output_dir}")
    args.output_dir.mkdir(parents=True)

    raw_rows, input_summary = load_market_rows(args.shfe_root, args.ine_root)
    contract_rows, feature_rows = build_panels(raw_rows)
    preflight = validate_panels(contract_rows, feature_rows)

    contracts_path = args.output_dir / "curve_contract_daily.csv"
    features_path = args.output_dir / "curve_features_daily.csv"
    inputs_path = args.output_dir / "input_receipts.json"
    preflight_path = args.output_dir / "preflight.json"
    manifest_path = args.output_dir / "manifest.json"
    write_csv(contracts_path, contract_rows, CONTRACT_COLUMNS)
    write_csv(features_path, feature_rows, FEATURE_COLUMNS)
    inputs_path.write_text(json.dumps(input_summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    preflight_path.write_text(json.dumps(preflight, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    manifest = {
        "contract_id": "commodity_market_only_curve_panel_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "SEALED_PASS_MARKET_ONLY_CURVE_PANEL",
        "fixed_products": [product for product, _ in FIXED_PRODUCTS],
        "selection_contract": {
            "eligible_contract": "numeric delivery month, delivery_yyyymm > source calendar month, settlement > 0, OI > 0",
            "near_next_third": "same-source-day eligible contracts ordered by delivery month ascending",
            "main_secondary_third": "same-source-day eligible contracts ordered by OI descending; ties by delivery month then symbol",
            "carry_sign": "positive means backwardation",
            "carry_time_scale": "delivery-month gap; not exact DTE",
            "availability": "source official day features become available only on the next observed official trading day",
            "last_raw_day_without_local_t_plus_1_published": False,
        },
        "authority": {
            "features_only": True,
            "pnl_or_economic_replay_performed": False,
            "future_main_chain_lookup_used": False,
            "legacy_event_trade_position_label_pnl_ledger_read": False,
            "network_accessed": False,
            "runtime_or_live_change_authorized": False,
        },
        "preflight": preflight,
        "outputs": [],
    }
    for path in (contracts_path, features_path, inputs_path, preflight_path):
        manifest["outputs"].append(
            {
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output_dir": str(args.output_dir), "preflight": preflight}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
