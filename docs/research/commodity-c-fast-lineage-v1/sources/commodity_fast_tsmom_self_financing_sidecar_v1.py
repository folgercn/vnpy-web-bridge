#!/usr/bin/env python3
"""Fast TSMOM 截面中性候选的自融资 fixed-quantity exact-contract sidecar。

本 runner 只读取已经封存的官方日线曲线面板、研究 spec 与两个 fast TSMOM
开发 bundle。它不读取旧事件、交易、持仓、标签或 PnL 账本，不联网，也不授予
任何 shadow、testnet、live 或 production 权限。

主会计为连续数量、固定数量、自融资、逐日盯市；整数合约仅在明确的 1000 万元
示意资本下做 rounding sensitivity。3T/5T 是每个 fill 分别承担 1.5/2.5 tick 的
completed-round-trip stress；额外 1bp/fill 只是非正式手续费压力边界。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[4]
PANEL_DIR = (
    PROJECT_ROOT
    / "research/entry_redesign/scripts/output/commodity_market_only_curve_panel_v1_20260717"
)
FAMILY_DIR = (
    PROJECT_ROOT
    / "research/entry_redesign/scripts/output/commodity_fast_tsmom_family_dev_v1_20260717"
)
MECHANISM_DIR = (
    PROJECT_ROOT
    / "research/entry_redesign/scripts/output/commodity_fast_tsmom_mechanism_diagnostic_v1_20260717"
)
SPEC_FILE = (
    PROJECT_ROOT
    / "research/entry_redesign/scripts/output/commodity_market_only_spec_empirical_verifier_v1_20260717"
    / "commodity_research_spec_empirically_verified.csv"
)
AUDIT_REPORT = (
    PROJECT_ROOT
    / "research/entry_redesign/commodity_fast_tsmom_independent_audit_20260717.md"
)
TEST_FILE = (
    PROJECT_ROOT
    / "research/entry_redesign/scripts/futures_lead/tests"
    / "test_commodity_fast_tsmom_self_financing_sidecar_v1.py"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "research/entry_redesign/scripts/output/commodity_fast_tsmom_self_financing_sidecar_v1r1_20260717"
)

PRODUCTS = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
SECTORS = {
    "ag": "precious",
    "au": "precious",
    "al": "nonferrous",
    "cu": "nonferrous",
    "zn": "nonferrous",
    "rb": "ferrous",
    "bu": "energy_chemical",
    "ru": "energy_chemical",
    "sc": "energy",
    "sp": "light_industry",
}
ARMS = {
    "fast_cross_section_neutral": "score_fast",
    "neighbor_cross_section_neutral": "score_neighbor",
    "slow_cross_section_neutral": "score_slow",
}
MODES = ("fractional_fixed_quantity", "integer_contract_illustrative")
COST_SCENARIOS = {
    "GROSS": (0.0, 0.0),
    "3T": (1.5, 0.0),
    "5T": (2.5, 0.0),
    "5T_FEE_STRESS_1BP_PER_FILL": (2.5, 1.0),
}
WINDOWS = {
    "OOS_2025_READ_DEVELOPMENT": ("2025-01-01", "2025-12-31"),
    "HOLDOUT_2026H1_READ_DEVELOPMENT": ("2026-01-01", "2026-06-30"),
    "READ_2026YTD_THROUGH_0709": ("2026-01-01", "2026-07-09"),
}


@dataclass(frozen=True)
class Inputs:
    features: pd.DataFrame
    contracts: pd.DataFrame
    signals: pd.DataFrame
    spec: pd.DataFrame
    mechanism_daily: pd.DataFrame
    mechanism_summary: pd.DataFrame


@dataclass(frozen=True)
class Simulation:
    daily: pd.DataFrame
    executions: pd.DataFrame
    sector_daily: pd.DataFrame


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--initial-capital", type=float, default=10_000_000.0)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _render_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _binding(path: Path) -> dict[str, object]:
    return {"path": _render_path(path), "bytes": path.stat().st_size, "sha256": _sha256(path)}


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _bound_output_sha(manifest: dict, file_name: str) -> str:
    bindings = manifest.get("output_bindings")
    if not isinstance(bindings, list):
        raise ValueError("SOURCE_BUNDLE_HAS_NO_OUTPUT_BINDINGS")
    matches = [item["sha256"] for item in bindings if Path(item["path"]).name == file_name]
    if len(matches) != 1:
        raise ValueError(f"SOURCE_OUTPUT_BINDING_NOT_UNIQUE:{file_name}")
    return str(matches[0])


def _verify_source_bundle(directory: Path, required: tuple[str, ...]) -> dict:
    manifest = _read_json(directory / "manifest.json")
    if not str(manifest.get("status", "")).startswith("PASS"):
        raise ValueError(f"SOURCE_BUNDLE_NOT_PASS:{directory.name}")
    for flag in ("network_used", "production_authorized"):
        if manifest.get(flag) is not False:
            raise ValueError(f"SOURCE_BUNDLE_NOT_RESEARCH_ONLY:{directory.name}:{flag}")
    for name in required:
        if _sha256(directory / name) != _bound_output_sha(manifest, name):
            raise ValueError(f"SOURCE_BUNDLE_HASH_MISMATCH:{directory.name}:{name}")
    return manifest


def load_inputs() -> Inputs:
    family_manifest = _verify_source_bundle(FAMILY_DIR, ("monthly_signal_panel.csv",))
    mechanism_manifest = _verify_source_bundle(
        MECHANISM_DIR, ("daily_pnl.csv", "summary.csv")
    )
    if family_manifest.get("legacy_event_trade_position_pnl_ledger_read") is not False:
        raise ValueError("FAMILY_LEGACY_LEDGER_BOUNDARY_FAILED")
    if mechanism_manifest.get("legacy_event_trade_position_pnl_ledger_read") is not False:
        raise ValueError("MECHANISM_LEGACY_LEDGER_BOUNDARY_FAILED")

    panel_manifest = _read_json(PANEL_DIR / "manifest.json")
    if panel_manifest.get("status") != "SEALED_PASS_MARKET_ONLY_CURVE_PANEL":
        raise ValueError("PANEL_NOT_SEALED")
    authority = panel_manifest.get("authority", {})
    if authority.get("future_main_chain_lookup_used") is not False:
        raise ValueError("PANEL_FUTURE_MAIN_CHAIN_BOUNDARY_FAILED")
    if authority.get("legacy_event_trade_position_label_pnl_ledger_read") is not False:
        raise ValueError("PANEL_LEGACY_LEDGER_BOUNDARY_FAILED")
    panel_outputs = {item["path"]: item["sha256"] for item in panel_manifest["outputs"]}
    for name in ("curve_features_daily.csv", "curve_contract_daily.csv"):
        if _sha256(PANEL_DIR / name) != panel_outputs.get(name):
            raise ValueError(f"PANEL_HASH_MISMATCH:{name}")

    spec_manifest = _read_json(SPEC_FILE.with_name("manifest.json"))
    if spec_manifest.get("status") != "PASS" or spec_manifest.get("production_authorized") is not False:
        raise ValueError("SPEC_NOT_RESEARCH_ONLY_PASS")
    if _sha256(SPEC_FILE) != spec_manifest.get("outputs", {}).get(SPEC_FILE.name):
        raise ValueError("SPEC_HASH_MISMATCH")
    panel_contract_sha = panel_outputs["curve_contract_daily.csv"]
    if spec_manifest.get("source_panel_sha256") != panel_contract_sha:
        raise ValueError("SPEC_PANEL_BINDING_MISMATCH")

    features = pd.read_csv(
        PANEL_DIR / "curve_features_daily.csv",
        parse_dates=["source_official_day", "available_official_day"],
    )
    contracts = pd.read_csv(
        PANEL_DIR / "curve_contract_daily.csv",
        parse_dates=["source_official_day", "available_official_day"],
    )
    signals = pd.read_csv(
        FAMILY_DIR / "monthly_signal_panel.csv",
        parse_dates=["source_official_day", "available_official_day"],
    )
    mechanism_daily = pd.read_csv(MECHANISM_DIR / "daily_pnl.csv", parse_dates=["date"])
    mechanism_summary = pd.read_csv(MECHANISM_DIR / "summary.csv")
    spec = pd.read_csv(SPEC_FILE)

    if set(features["product"].unique()) != set(PRODUCTS):
        raise ValueError("FEATURE_UNIVERSE_MISMATCH")
    if set(spec["code"]) != set(PRODUCTS):
        raise ValueError("SPEC_UNIVERSE_MISMATCH")
    if not (features["available_official_day"] > features["source_official_day"]).all():
        raise ValueError("NON_CAUSAL_FEATURE_AVAILABILITY")
    if contracts.duplicated(["source_official_day", "product", "exact_contract"]).any():
        raise ValueError("DUPLICATE_EXACT_CONTRACT_DAY")
    if not spec["verification_status"].eq(
        "official_daily_empirically_verified_research_only"
    ).all():
        raise ValueError("SPEC_VERIFICATION_STATUS_FAILED")
    if not spec["research_5t_authorized"].astype(bool).all():
        raise ValueError("SPEC_RESEARCH_5T_BOUNDARY_FAILED")
    if spec["production_authorized"].astype(bool).any():
        raise ValueError("SPEC_PRODUCTION_BOUNDARY_FAILED")
    if (spec[["multiplier", "tick_size"]].astype(float) <= 0).any().any():
        raise ValueError("INVALID_MULTIPLIER_OR_TICK")
    return Inputs(features, contracts, signals, spec, mechanism_daily, mechanism_summary)


def _cap_weights(raw: dict[str, float], products: tuple[str, ...]) -> dict[str, float]:
    weights = {product: float(np.clip(raw.get(product, 0.0), -0.20, 0.20)) for product in products}
    for sector in sorted({SECTORS[product] for product in products}):
        members = [product for product in products if SECTORS[product] == sector]
        gross = sum(abs(weights[product]) for product in members)
        if gross > 0.35:
            scale = 0.35 / gross
            for product in members:
                weights[product] *= scale
    gross = sum(abs(value) for value in weights.values())
    if gross > 1.0:
        weights = {product: value / gross for product, value in weights.items()}
    return weights


def _neutral_weights(day: pd.DataFrame, score_column: str) -> dict[str, float]:
    by_product = day.set_index("product")
    raw = {
        product: float(by_product.loc[product, score_column])
        / max(float(by_product.loc[product, "vol60"]), 0.05)
        for product in PRODUCTS
    }
    mean = float(np.mean(list(raw.values())))
    centered = {product: raw[product] - mean for product in PRODUCTS}
    positive = sum(max(value, 0.0) for value in centered.values())
    negative = sum(max(-value, 0.0) for value in centered.values())
    if positive <= 1e-12 or negative <= 1e-12:
        return {product: 0.0 for product in PRODUCTS}
    weights = {
        product: (
            0.5 * centered[product] / positive
            if centered[product] > 0
            else 0.5 * centered[product] / negative
        )
        for product in PRODUCTS
    }
    weights = _cap_weights(weights, PRODUCTS)
    positive_gross = sum(max(value, 0.0) for value in weights.values())
    negative_gross = sum(max(-value, 0.0) for value in weights.values())
    balanced = min(positive_gross, negative_gross)
    if balanced <= 0:
        raise ValueError("NEUTRAL_CAP_REMOVED_A_LEG")
    for product, value in list(weights.items()):
        if value > 0:
            weights[product] = value * balanced / positive_gross
        elif value < 0:
            weights[product] = value * balanced / negative_gross
    if abs(sum(weights.values())) > 1e-12:
        raise ValueError("TARGET_NOT_DOLLAR_NEUTRAL")
    return weights


def build_monthly_targets(signals: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    signals = signals[signals["product"].isin(PRODUCTS)].copy()
    for execution_day, day in signals.groupby("available_official_day", sort=True):
        if day["incomplete_source_month"].astype(bool).any() or set(day["product"]) != set(PRODUCTS):
            continue
        by_product = day.set_index("product")
        for arm, score_column in ARMS.items():
            if day[[score_column, "vol60"]].isna().any().any():
                continue
            weights = _neutral_weights(day, score_column)
            for product, weight in weights.items():
                source = by_product.loc[product]
                rows.append(
                    {
                        "execution_day": execution_day,
                        "source_official_day": source["source_official_day"],
                        "arm": arm,
                        "score_column": score_column,
                        "product": product,
                        "sector": SECTORS[product],
                        "source_target_symbol": source["target_symbol"],
                        "target_weight": weight,
                        "score": source[score_column],
                        "vol60": source["vol60"],
                    }
                )
    targets = pd.DataFrame(rows)
    if targets.empty:
        raise ValueError("NO_MONTHLY_TARGETS")
    grouped = targets.groupby(["execution_day", "arm"])
    if grouped["product"].nunique().min() != len(PRODUCTS):
        raise ValueError("INCOMPLETE_MONTHLY_TARGET_UNIVERSE")
    if grouped["target_weight"].sum().abs().max() > 1e-12:
        raise ValueError("MONTHLY_TARGET_NET_EXPOSURE_FAILED")
    if grouped["target_weight"].apply(lambda values: values.abs().sum()).max() > 1.0 + 1e-12:
        raise ValueError("MONTHLY_TARGET_GROSS_CAP_FAILED")
    if targets["target_weight"].abs().max() > 0.20 + 1e-12:
        raise ValueError("MONTHLY_TARGET_PRODUCT_CAP_FAILED")
    sector_gross = targets.assign(abs_weight=targets["target_weight"].abs()).groupby(
        ["execution_day", "arm", "sector"]
    )["abs_weight"].sum()
    if sector_gross.max() > 0.35 + 1e-12:
        raise ValueError("MONTHLY_TARGET_SECTOR_CAP_FAILED")
    return targets.sort_values(["execution_day", "arm", "product"]).reset_index(drop=True)


def _price(
    lookup: pd.DataFrame, day: pd.Timestamp, product: str, symbol: str, field: str
) -> float:
    value = float(lookup.loc[(day, product, symbol), field])
    if not np.isfinite(value) or value <= 0:
        raise ValueError(f"INVALID_PRICE:{day}:{product}:{symbol}:{field}")
    return value


def simulate_one(
    inputs: Inputs,
    targets: pd.DataFrame,
    arm: str,
    mode: str,
    scenario: str,
    initial_capital: float,
) -> Simulation:
    if initial_capital <= 0 or not np.isfinite(initial_capital):
        raise ValueError("INVALID_INITIAL_CAPITAL")
    if mode not in MODES or scenario not in COST_SCENARIOS:
        raise ValueError("UNSUPPORTED_ACCOUNTING_MODE_OR_COST_SCENARIO")
    ticks_per_fill, fee_bps_per_fill = COST_SCENARIOS[scenario]
    arm_targets = targets[targets["arm"].eq(arm)].copy()
    target_map = {
        day: group.set_index("product")
        for day, group in arm_targets.groupby("execution_day", sort=True)
    }
    first_execution_day = min(target_map)
    price_lookup = inputs.contracts.set_index(
        ["source_official_day", "product", "exact_contract"]
    )[["open", "settlement"]]
    daily_main = inputs.features.set_index(["available_official_day", "product"])[
        "main_symbol"
    ].to_dict()
    spec = inputs.spec.set_index("code")
    multiplier = spec["multiplier"].astype(float).to_dict()
    tick_size = spec["tick_size"].astype(float).to_dict()
    days = [pd.Timestamp(day) for day in sorted(inputs.contracts["source_official_day"].unique())]

    quantities = {product: 0.0 for product in PRODUCTS}
    symbols: dict[str, str | None] = {product: None for product in PRODUCTS}
    equity = float(initial_capital)
    previous_day: pd.Timestamp | None = None
    daily_rows: list[dict[str, object]] = []
    execution_rows: list[dict[str, object]] = []
    sector_rows: list[dict[str, object]] = []

    for day in days:
        if day < first_execution_day:
            previous_day = day
            continue
        target = target_map.get(day)
        rebalance = target is not None
        desired_symbols: dict[str, str] = {}
        trade_flags: dict[str, bool] = {}
        for product in PRODUCTS:
            desired = daily_main.get((day, product))
            if desired is None:
                raise ValueError(f"MISSING_CAUSAL_DAILY_MAIN:{day}:{product}")
            desired_symbols[product] = str(desired)
            trade_flags[product] = rebalance or (
                symbols[product] is not None and symbols[product] != desired_symbols[product]
            )

        equity_previous = equity
        overnight_pnl = 0.0
        if previous_day is not None:
            for product in PRODUCTS:
                symbol = symbols[product]
                quantity = quantities[product]
                if symbol is None or quantity == 0.0:
                    continue
                overnight_pnl += quantity * multiplier[product] * (
                    _price(price_lookup, day, product, symbol, "open")
                    - _price(price_lookup, previous_day, product, symbol, "settlement")
                )
        equity_open = equity_previous + overnight_pnl
        if equity_open <= 0:
            raise ValueError("NON_POSITIVE_OPEN_EQUITY")

        tick_cost = 0.0
        fee_stress_cost = 0.0
        fill_notional = 0.0
        for product in PRODUCTS:
            if not trade_flags[product]:
                continue
            old_symbol = symbols[product]
            old_quantity = quantities[product]
            new_symbol = desired_symbols[product]
            if rebalance:
                target_weight = float(target.loc[product, "target_weight"])
                new_open = _price(price_lookup, day, product, new_symbol, "open")
                raw_quantity = target_weight * equity_open / (multiplier[product] * new_open)
                new_quantity = (
                    float(np.rint(raw_quantity))
                    if mode == "integer_contract_illustrative"
                    else float(raw_quantity)
                )
            else:
                target_weight = float("nan")
                new_quantity = old_quantity

            product_fill_notional = 0.0
            product_tick_cost = 0.0
            product_fee_cost = 0.0
            if old_symbol == new_symbol:
                traded_quantity = abs(new_quantity - old_quantity)
                open_price = _price(price_lookup, day, product, new_symbol, "open")
                product_fill_notional = traded_quantity * multiplier[product] * open_price
                product_tick_cost = (
                    traded_quantity * multiplier[product] * tick_size[product] * ticks_per_fill
                )
            else:
                if old_symbol is not None:
                    old_open = _price(price_lookup, day, product, old_symbol, "open")
                    product_fill_notional += (
                        abs(old_quantity) * multiplier[product] * old_open
                    )
                    product_tick_cost += (
                        abs(old_quantity)
                        * multiplier[product]
                        * tick_size[product]
                        * ticks_per_fill
                    )
                new_open = _price(price_lookup, day, product, new_symbol, "open")
                product_fill_notional += (
                    abs(new_quantity) * multiplier[product] * new_open
                )
                product_tick_cost += (
                    abs(new_quantity)
                    * multiplier[product]
                    * tick_size[product]
                    * ticks_per_fill
                )
            product_fee_cost = product_fill_notional * fee_bps_per_fill / 10_000.0
            tick_cost += product_tick_cost
            fee_stress_cost += product_fee_cost
            fill_notional += product_fill_notional
            quantities[product] = new_quantity
            symbols[product] = new_symbol

            realized_open_weight = (
                new_quantity
                * multiplier[product]
                * _price(price_lookup, day, product, new_symbol, "open")
                / equity_open
            )
            execution_rows.append(
                {
                    "date": day,
                    "arm": arm,
                    "accounting_mode": mode,
                    "cost_scenario": scenario,
                    "product": product,
                    "sector": SECTORS[product],
                    "rebalance": rebalance,
                    "roll": bool(old_symbol is not None and old_symbol != new_symbol),
                    "old_symbol": old_symbol or "",
                    "new_symbol": new_symbol,
                    "old_quantity": old_quantity,
                    "new_quantity": new_quantity,
                    "target_weight": target_weight,
                    "realized_open_weight": realized_open_weight,
                    "target_weight_error": (
                        realized_open_weight - target_weight if rebalance else np.nan
                    ),
                    "fill_notional": product_fill_notional,
                    "tick_cost": product_tick_cost,
                    "fee_stress_cost": product_fee_cost,
                }
            )

        intraday_pnl = 0.0
        product_notionals: dict[str, float] = {}
        for product in PRODUCTS:
            symbol = symbols[product]
            quantity = quantities[product]
            if symbol is None:
                product_notionals[product] = 0.0
                continue
            open_price = _price(price_lookup, day, product, symbol, "open")
            settlement = _price(price_lookup, day, product, symbol, "settlement")
            intraday_pnl += quantity * multiplier[product] * (settlement - open_price)
            product_notionals[product] = quantity * multiplier[product] * settlement
        gross_pnl = overnight_pnl + intraday_pnl
        equity = equity_open - tick_cost - fee_stress_cost + intraday_pnl
        if equity <= 0:
            raise ValueError("NON_POSITIVE_SETTLEMENT_EQUITY")
        net_return = equity / equity_previous - 1.0
        gross_return = gross_pnl / equity_previous
        gross_exposure = sum(abs(value) for value in product_notionals.values()) / equity
        net_exposure = sum(product_notionals.values()) / equity
        daily_rows.append(
            {
                "date": day,
                "arm": arm,
                "accounting_mode": mode,
                "cost_scenario": scenario,
                "gross_return": gross_return,
                "net_return": net_return,
                "equity": equity,
                "overnight_pnl": overnight_pnl,
                "intraday_pnl": intraday_pnl,
                "tick_cost": tick_cost,
                "fee_stress_cost": fee_stress_cost,
                "fill_notional": fill_notional,
                "fill_turnover": fill_notional / equity_open,
                "gross_exposure": gross_exposure,
                "net_exposure": net_exposure,
            }
        )
        for sector in sorted(set(SECTORS.values())):
            values = [
                product_notionals[product]
                for product in PRODUCTS
                if SECTORS[product] == sector
            ]
            sector_rows.append(
                {
                    "date": day,
                    "arm": arm,
                    "accounting_mode": mode,
                    "cost_scenario": scenario,
                    "sector": sector,
                    "sector_gross_exposure": sum(abs(value) for value in values) / equity,
                    "sector_net_exposure": sum(values) / equity,
                }
            )
        previous_day = day
    return Simulation(
        pd.DataFrame(daily_rows),
        pd.DataFrame(execution_rows),
        pd.DataFrame(sector_rows),
    )


def _compound(values: pd.Series) -> float:
    return float((1.0 + values.astype(float)).prod() - 1.0)


def _max_drawdown(values: pd.Series) -> float:
    compounded = (1.0 + values.astype(float).fillna(0.0)).cumprod().to_numpy()
    equity = pd.Series(np.concatenate(([1.0], compounded)))
    return float((equity / equity.cummax() - 1.0).min())


def summarize(daily: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for window, (start, end) in WINDOWS.items():
        sample = daily[daily["date"].between(start, end)]
        for keys, group in sample.groupby(
            ["arm", "accounting_mode", "cost_scenario"], sort=True
        ):
            arm, mode, scenario = keys
            returns = group["net_return"]
            daily_std = float(returns.std(ddof=1))
            monthly = group.assign(month=group["date"].dt.to_period("M")).groupby("month")[
                "net_return"
            ].apply(_compound)
            rows.append(
                {
                    "window": window,
                    "arm": arm,
                    "accounting_mode": mode,
                    "cost_scenario": scenario,
                    "days": len(group),
                    "total_return": _compound(returns),
                    "sharpe": (
                        float(returns.mean() / daily_std * math.sqrt(252.0))
                        if daily_std > 0
                        else np.nan
                    ),
                    "max_drawdown": _max_drawdown(returns),
                    "positive_months": int((monthly > 0).sum()),
                    "negative_months": int((monthly < 0).sum()),
                    "fill_turnover": float(group["fill_turnover"].sum()),
                    "mean_gross_exposure": float(group["gross_exposure"].mean()),
                    "mean_net_exposure": float(group["net_exposure"].mean()),
                    "max_abs_net_exposure": float(group["net_exposure"].abs().max()),
                }
            )
    return pd.DataFrame(rows)


def summarize_quarters(daily: pd.DataFrame) -> pd.DataFrame:
    sample = daily[
        daily["date"].between("2025-01-01", "2026-07-09")
        & daily["cost_scenario"].isin(["5T", "5T_FEE_STRESS_1BP_PER_FILL"])
    ].copy()
    sample["quarter"] = sample["date"].dt.to_period("Q").astype(str)
    return (
        sample.groupby(
            ["arm", "accounting_mode", "cost_scenario", "quarter"], sort=True
        )["net_return"]
        .apply(_compound)
        .rename("total_return")
        .reset_index()
    )


def top_day_removal(daily: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for window, (start, end) in WINDOWS.items():
        sample = daily[
            daily["date"].between(start, end)
            & daily["cost_scenario"].isin(["5T", "5T_FEE_STRESS_1BP_PER_FILL"])
        ]
        for keys, group in sample.groupby(
            ["arm", "accounting_mode", "cost_scenario"], sort=True
        ):
            arm, mode, scenario = keys
            ordered = group.sort_values("net_return", ascending=False)
            for top_k in (1, 3, 5):
                rows.append(
                    {
                        "window": window,
                        "arm": arm,
                        "accounting_mode": mode,
                        "cost_scenario": scenario,
                        "top_k_removed": top_k,
                        "total_return": _compound(group["net_return"]),
                        "removed_simple_return": float(ordered.head(top_k)["net_return"].sum()),
                        "without_top_k_return": _compound(ordered.iloc[top_k:]["net_return"]),
                    }
                )
    return pd.DataFrame(rows)


def sector_diagnostic(sector_daily: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for window, (start, end) in WINDOWS.items():
        sample = sector_daily[
            sector_daily["date"].between(start, end)
            & sector_daily["cost_scenario"].eq("5T")
        ]
        for keys, group in sample.groupby(
            ["arm", "accounting_mode", "sector"], sort=True
        ):
            arm, mode, sector = keys
            rows.append(
                {
                    "window": window,
                    "arm": arm,
                    "accounting_mode": mode,
                    "sector": sector,
                    "max_abs_sector_net_exposure": float(
                        group["sector_net_exposure"].abs().max()
                    ),
                    "mean_abs_sector_net_exposure": float(
                        group["sector_net_exposure"].abs().mean()
                    ),
                    "max_sector_gross_exposure": float(
                        group["sector_gross_exposure"].max()
                    ),
                }
            )
    return pd.DataFrame(rows)


def common_beta_diagnostic(daily: pd.DataFrame, mechanism_daily: pd.DataFrame) -> pd.DataFrame:
    common = mechanism_daily[mechanism_daily["arm"].eq("passive_long_vol")][
        ["date", "net_5t_return"]
    ].rename(columns={"net_5t_return": "common_proxy_return"})
    rows: list[dict[str, object]] = []
    sample_all = daily[daily["cost_scenario"].eq("5T")]
    for window, (start, end) in WINDOWS.items():
        sample = sample_all[sample_all["date"].between(start, end)]
        for keys, group in sample.groupby(["arm", "accounting_mode"], sort=True):
            arm, mode = keys
            merged = group[["date", "net_return"]].merge(common, on="date", how="inner")
            x = merged["common_proxy_return"].to_numpy(float)
            y = merged["net_return"].to_numpy(float)
            variance = float(np.var(x, ddof=1))
            beta = float(np.cov(x, y, ddof=1)[0, 1] / variance) if variance > 0 else np.nan
            alpha_daily = float(np.mean(y) - beta * np.mean(x)) if np.isfinite(beta) else np.nan
            correlation = float(np.corrcoef(x, y)[0, 1]) if len(x) > 1 else np.nan
            rows.append(
                {
                    "window": window,
                    "arm": arm,
                    "accounting_mode": mode,
                    "common_proxy": "legacy_passive_long_vol_net_5t_research_proxy",
                    "days": len(merged),
                    "beta": beta,
                    "annualized_linear_alpha": alpha_daily * 252.0,
                    "correlation": correlation,
                    "r_squared": correlation**2 if np.isfinite(correlation) else np.nan,
                }
            )
    return pd.DataFrame(rows)


def baseline_comparison(summary: pd.DataFrame, mechanism_summary: pd.DataFrame) -> pd.DataFrame:
    old_windows = {
        "OOS_2025": "OOS_2025_READ_DEVELOPMENT",
        "HOLDOUT_2026H1": "HOLDOUT_2026H1_READ_DEVELOPMENT",
        "HOLDOUT_2026YTD_THROUGH_0709": "READ_2026YTD_THROUGH_0709",
    }
    old = mechanism_summary[
        mechanism_summary["arm"].eq("fast_cross_section_neutral")
        & mechanism_summary["cost"].eq("5T")
    ][["window", "total_return"]].copy()
    old["window"] = old["window"].map(old_windows)
    old = old.rename(columns={"total_return": "legacy_weight_index_5t_return"})
    new = summary[
        summary["arm"].eq("fast_cross_section_neutral")
        & summary["accounting_mode"].eq("fractional_fixed_quantity")
        & summary["cost_scenario"].eq("5T")
    ][["window", "total_return"]].rename(
        columns={"total_return": "self_financing_fixed_quantity_5t_return"}
    )
    out = old.merge(new, on="window", how="inner")
    out["return_difference"] = (
        out["self_financing_fixed_quantity_5t_return"]
        - out["legacy_weight_index_5t_return"]
    )
    return out


def integer_rounding_diagnostic(
    executions: pd.DataFrame, daily: pd.DataFrame, initial_capital: float
) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    integer_exec = executions[
        executions["accounting_mode"].eq("integer_contract_illustrative")
        & executions["cost_scenario"].eq("5T")
        & executions["rebalance"]
    ]
    integer_daily = daily[
        daily["accounting_mode"].eq("integer_contract_illustrative")
        & daily["cost_scenario"].eq("5T")
    ]
    for window, (start, end) in WINDOWS.items():
        for arm in ARMS:
            e = integer_exec[
                integer_exec["arm"].eq(arm) & integer_exec["date"].between(start, end)
            ]
            d = integer_daily[
                integer_daily["arm"].eq(arm) & integer_daily["date"].between(start, end)
            ]
            rows.append(
                {
                    "window": window,
                    "arm": arm,
                    "initial_capital": initial_capital,
                    "rebalance_product_rows": len(e),
                    "mean_abs_target_weight_error": float(e["target_weight_error"].abs().mean()),
                    "max_abs_target_weight_error": float(e["target_weight_error"].abs().max()),
                    "mean_abs_daily_net_exposure": float(d["net_exposure"].abs().mean()),
                    "max_abs_daily_net_exposure": float(d["net_exposure"].abs().max()),
                }
            )
    return pd.DataFrame(rows)


def _percent(value: float) -> str:
    return f"{value * 100:+.2f}%"


def write_report(
    output_dir: Path,
    summary: pd.DataFrame,
    top_days: pd.DataFrame,
    sector: pd.DataFrame,
    beta: pd.DataFrame,
    comparison: pd.DataFrame,
    rounding: pd.DataFrame,
    initial_capital: float,
) -> None:
    selected = summary[
        summary["accounting_mode"].eq("fractional_fixed_quantity")
        & summary["cost_scenario"].isin(["5T", "5T_FEE_STRESS_1BP_PER_FILL"])
    ]
    lines = [
        "# Fast TSMOM 截面中性自融资 exact-contract sidecar v1r1",
        "",
        "## 结论",
        "",
        "本 sidecar 把既有 dollar-neutral 信号改成连续数量、固定数量、自融资、逐日权益漂移的 exact-contract 会计，并同时封存 fast、neighbor、slow 三个结构；不按结果择优。",
        "",
        f"它仍是 **post-discovery、nonconfirmatory、research-only、non-tradable**。整数合约使用 {initial_capital:,.0f} CNY 示意资本，只是 rounding sensitivity；没有正式 capital、margin 或 production authority。",
        "",
        "## 连续数量固定数量结果",
        "",
        "| 已读开发窗 | 结构 | 成本边界 | 总收益 | Sharpe | 最大回撤 |",
        "|---|---|---|---:|---:|---:|",
    ]
    for _, row in selected.sort_values(["window", "arm", "cost_scenario"]).iterrows():
        lines.append(
            f"| {row['window']} | `{row['arm']}` | `{row['cost_scenario']}` | "
            f"{_percent(float(row['total_return']))} | {float(row['sharpe']):.2f} | "
            f"{_percent(float(row['max_drawdown']))} |"
        )
    lines.extend(
        [
            "",
            "## Top-day 删除",
            "",
            "下表只列连续数量 5T 的 top5 删除；完整 top1/top3/top5 与 1bp/fill fee stress 见 CSV。",
            "",
            "| 已读开发窗 | 结构 | 原始 5T | 删除 top5 |",
            "|---|---|---:|---:|",
        ]
    )
    top5 = top_days[
        top_days["accounting_mode"].eq("fractional_fixed_quantity")
        & top_days["cost_scenario"].eq("5T")
        & top_days["top_k_removed"].eq(5)
    ]
    for _, row in top5.sort_values(["window", "arm"]).iterrows():
        lines.append(
            f"| {row['window']} | `{row['arm']}` | {_percent(float(row['total_return']))} | "
            f"{_percent(float(row['without_top_k_return']))} |"
        )

    fast_compare = comparison.set_index("window")
    lines.extend(["", "## 与旧 weight-return index 的关系", ""])
    for window, row in fast_compare.iterrows():
        lines.append(
            f"- {window}：旧 5T {_percent(float(row['legacy_weight_index_5t_return']))}；"
            f"自融资 fixed-quantity 5T {_percent(float(row['self_financing_fixed_quantity_5t_return']))}。"
        )

    max_sector = sector[
        sector["accounting_mode"].eq("fractional_fixed_quantity")
    ]["max_abs_sector_net_exposure"].max()
    fast_beta = beta[
        beta["arm"].eq("fast_cross_section_neutral")
        & beta["accounting_mode"].eq("fractional_fixed_quantity")
    ]
    lines.extend(
        [
            "",
            "## 风险与执行边界",
            "",
            f"- 固定数量会使原本月初 dollar-neutral 的组合随价格和权益漂移；观察到的最大单板块净敞口为 {_percent(float(max_sector))}。",
            "- 共同 beta 使用旧 bundle 的 `passive_long_vol net_5t` 作为研究代理，不是正式商品 beta 模型。",
        ]
    )
    for _, row in fast_beta.sort_values("window").iterrows():
        lines.append(
            f"  - {row['window']}：beta={float(row['beta']):+.3f}，"
            f"corr={float(row['correlation']):+.3f}，R²={float(row['r_squared']):.3f}。"
        )
    rounding_selected = rounding[
        rounding["arm"].eq("fast_cross_section_neutral")
    ]
    if not rounding_selected.empty:
        max_error = rounding_selected["max_abs_target_weight_error"].max()
        max_net = rounding_selected["max_abs_daily_net_exposure"].max()
        lines.append(
            f"- `{initial_capital:,.0f} CNY` 整数示意：fast 最大单品种 target rounding error "
            f"{_percent(float(max_error))}，最大组合净敞口 {_percent(float(max_net))}。"
        )
    lines.extend(
        [
            "- 3T/5T 仍只是 tick-impact stress；`5T_FEE_STRESS_1BP_PER_FILL` 额外加 1bp/fill，但不是正式手续费。",
            "- 未建模保证金、涨跌停、开盘可成交性、bid/ask、成交量参与率、经纪商费用和现金收益。",
            "- 整数结果依赖示意资本，不能解释为获批资金规模或现金 PnL authority。",
            "",
            "## 审计绑定",
            "",
            f"本 bundle 的 manifest 输入绑定独立审计报告 `{_render_path(AUDIT_REPORT)}`。该报告的结论是：旧 bundle 的机械开发回放 PASS，但 confirmatory/tradable FAIL。",
            "",
            "## 权限",
            "",
            "`confirmatory=false`、`tradable=false`、`production_authorized=false`。本结果不能进入 shadow、testnet、live 或 production。",
        ]
    )
    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_manifest(output_dir: Path) -> dict[str, object]:
    inputs = {
        "runner": Path(__file__).resolve(),
        "tests": TEST_FILE,
        "independent_audit_report": AUDIT_REPORT,
        "family_manifest": FAMILY_DIR / "manifest.json",
        "family_monthly_signal_panel": FAMILY_DIR / "monthly_signal_panel.csv",
        "mechanism_manifest": MECHANISM_DIR / "manifest.json",
        "mechanism_daily": MECHANISM_DIR / "daily_pnl.csv",
        "mechanism_summary": MECHANISM_DIR / "summary.csv",
        "panel_manifest": PANEL_DIR / "manifest.json",
        "curve_features_daily": PANEL_DIR / "curve_features_daily.csv",
        "curve_contract_daily": PANEL_DIR / "curve_contract_daily.csv",
        "research_spec": SPEC_FILE,
        "research_spec_manifest": SPEC_FILE.with_name("manifest.json"),
    }
    outputs = sorted(path for path in output_dir.iterdir() if path.is_file() and path.name != "manifest.json")
    manifest = {
        "schema_version": "commodity_fast_tsmom_self_financing_sidecar_v1r1_manifest",
        "status": "PASS_COMPLETE_POST_DISCOVERY_SELF_FINANCING_SIDECAR",
        "input_bindings": {name: _binding(path) for name, path in inputs.items()},
        "output_bindings": [_binding(path) for path in outputs],
        "accounting_scope": {
            "fractional_fixed_quantity_self_financing": True,
            "integer_contract_mode": "illustrative_configured_capital_only",
            "daily_equity_drift": True,
            "exact_contract_open_settlement": True,
            "roll_quantity_rule": "close old and open same quantity unless monthly rebalance coincides",
            "formal_capital_authorized": False,
            "formal_margin_model": False,
            "formal_fee_included": False,
            "fee_stress_1bp_per_fill_not_formal": True,
        },
        "future_main_chain_lookup_used": False,
        "legacy_event_trade_position_label_pnl_ledger_read": False,
        "network_used": False,
        "confirmatory": False,
        "tradable": False,
        "production_authorized": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def run(output_dir: Path, initial_capital: float) -> dict[str, pd.DataFrame]:
    if output_dir.exists():
        raise FileExistsError(f"OUTPUT_ALREADY_EXISTS:{output_dir}")
    inputs = load_inputs()
    targets = build_monthly_targets(inputs.signals)
    simulations: list[Simulation] = []
    for arm in ARMS:
        for mode in MODES:
            for scenario in COST_SCENARIOS:
                simulations.append(
                    simulate_one(inputs, targets, arm, mode, scenario, initial_capital)
                )
    daily = pd.concat([item.daily for item in simulations], ignore_index=True)
    executions = pd.concat([item.executions for item in simulations], ignore_index=True)
    sector_daily = pd.concat([item.sector_daily for item in simulations], ignore_index=True)
    summary = summarize(daily)
    quarterly = summarize_quarters(daily)
    top_days = top_day_removal(daily)
    sector = sector_diagnostic(sector_daily)
    beta = common_beta_diagnostic(daily, inputs.mechanism_daily)
    comparison = baseline_comparison(summary, inputs.mechanism_summary)
    rounding = integer_rounding_diagnostic(executions, daily, initial_capital)

    output_dir.mkdir(parents=True, exist_ok=False)
    outputs = {
        "monthly_targets.csv": targets,
        "daily_accounting.csv": daily,
        "executions.csv": executions,
        "sector_exposure_daily.csv": sector_daily,
        "summary.csv": summary,
        "quarterly_5t.csv": quarterly,
        "top_day_removal_5t.csv": top_days,
        "sector_exposure_diagnostic.csv": sector,
        "common_beta_diagnostic.csv": beta,
        "baseline_comparison.csv": comparison,
        "integer_rounding_diagnostic.csv": rounding,
    }
    for name, frame in outputs.items():
        frame.to_csv(output_dir / name, index=False)
    write_report(
        output_dir,
        summary,
        top_days,
        sector,
        beta,
        comparison,
        rounding,
        initial_capital,
    )
    receipt = {
        "status": "COMPLETE_POST_DISCOVERY_SELF_FINANCING_SIDECAR",
        "arms": list(ARMS),
        "accounting_modes": list(MODES),
        "cost_scenarios": {
            name: {"ticks_per_fill": values[0], "fee_bps_per_fill": values[1]}
            for name, values in COST_SCENARIOS.items()
        },
        "initial_capital": initial_capital,
        "initial_capital_authority": "illustrative_only",
        "roll_quantity_rule": "same quantity across roll unless monthly rebalance coincides",
        "known_source_data_end": str(inputs.features["source_official_day"].max().date()),
        "python": platform.python_version(),
        "pandas": pd.__version__,
        "numpy": np.__version__,
        "formal_fee_included": False,
        "formal_margin_model": False,
        "legacy_ledger_read": False,
        "network_used": False,
        "confirmatory": False,
        "tradable": False,
        "production_authorized": False,
    }
    (output_dir / "receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_manifest(output_dir)
    return {**outputs, "sector_exposure_daily.csv": sector_daily}


def main() -> None:
    args = _parse_args()
    outputs = run(args.output_dir, args.initial_capital)
    summary = outputs["summary.csv"]
    selected = summary[
        summary["accounting_mode"].eq("fractional_fixed_quantity")
        & summary["cost_scenario"].isin(["5T", "5T_FEE_STRESS_1BP_PER_FILL"])
    ]
    print(selected.to_string(index=False))
    print(f"output_dir={args.output_dir}")


if __name__ == "__main__":
    main()
