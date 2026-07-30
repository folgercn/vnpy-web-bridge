#!/usr/bin/env python3
"""商品期货快周期 TSMOM 固定家族开发回放。

只读取封存的官方日线曲线面板和 empirically-verified research spec；不读取
旧事件、交易、持仓或 PnL 账本。信号在 source day 收盘后形成，最早在下一
official day 的 exact-contract open 执行，并逐日跟随 PIT OI main 换月。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.entry_redesign.scripts.futures_lead import (
    commodity_carry_multihorizon_trend_dev_v1 as base,
)


DEFAULT_PANEL = base.DEFAULT_PANEL
DEFAULT_SPEC = base.DEFAULT_SPEC
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "research/entry_redesign/scripts/output/commodity_fast_tsmom_family_dev_v1_20260717"
)
PRODUCTS = base.PRODUCTS
SECTORS = base.SECTORS
ARMS = (
    "tsmom_slow_63_126_252",
    "tsmom_fast_21_63_126",
    "tsmom_neighbor_42_84_168",
    "tsmom_vol_regime_fast",
)
HORIZONS = (21, 42, 63, 84, 126, 168, 252)
WINDOWS = {
    "OOS_2025": ("2025-01-01", "2025-12-31"),
    "HOLDOUT_2026H1": ("2026-01-01", "2026-06-30"),
    "HOLDOUT_2026YTD_THROUGH_0709": ("2026-01-01", "2026-07-09"),
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel-dir", type=Path, default=DEFAULT_PANEL)
    parser.add_argument("--spec-file", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def _sign(value: float) -> float:
    return float(np.sign(value)) if np.isfinite(value) else float("nan")


def _mean_sign(row: pd.Series, horizons: tuple[int, ...]) -> float:
    values = [float(row[f"trend_{horizon}"]) for horizon in horizons]
    if not all(np.isfinite(value) for value in values):
        return float("nan")
    return float(np.mean([_sign(value) for value in values]))


def build_signal_panel(features: pd.DataFrame, contracts: pd.DataFrame) -> pd.DataFrame:
    """Build roll-jump-free daily PIT index, then take completed source month ends."""
    lookup = base._contract_lookup(contracts)
    rows: list[dict[str, object]] = []
    for product, group in features.groupby("product", sort=True):
        group = group.sort_values("source_official_day").reset_index(drop=True)
        index_level = 1.0
        previous: pd.Series | None = None
        for _, row in group.iterrows():
            daily_log_return = float("nan")
            if previous is not None:
                old_symbol = str(previous["main_symbol"])
                new_symbol = str(row["main_symbol"])
                previous_day = previous["source_official_day"]
                current_day = row["source_official_day"]
                previous_settlement = float(
                    lookup.loc[(previous_day, product, old_symbol), "settlement"]
                )
                current_comparable = float(
                    lookup.loc[(current_day, product, old_symbol), "settlement"]
                )
                if new_symbol != old_symbol:
                    new_settlement = float(
                        lookup.loc[(current_day, product, new_symbol), "settlement"]
                    )
                    if new_settlement <= 0:
                        raise ValueError("INVALID_NEW_ROLL_ANCHOR")
                if previous_settlement <= 0 or current_comparable <= 0:
                    raise ValueError("INVALID_TREND_SETTLEMENT")
                daily_log_return = math.log(current_comparable / previous_settlement)
                index_level *= math.exp(daily_log_return)
            rows.append(
                {
                    "source_official_day": row["source_official_day"],
                    "available_official_day": row["available_official_day"],
                    "product": product,
                    "target_symbol": row["main_symbol"],
                    "trend_index": index_level,
                    "trend_daily_log_return": daily_log_return,
                }
            )
            previous = row

    panel = pd.DataFrame(rows).sort_values(["product", "source_official_day"])
    grouped = panel.groupby("product", sort=False)
    for horizon in HORIZONS:
        panel[f"trend_{horizon}"] = np.log(
            panel["trend_index"] / grouped["trend_index"].shift(horizon)
        )
    panel["vol60"] = (
        grouped["trend_daily_log_return"]
        .rolling(60, min_periods=60)
        .std()
        .reset_index(level=0, drop=True)
        * math.sqrt(252.0)
    )
    panel["vol60_median252"] = (
        panel.groupby("product", sort=False)["vol60"]
        .rolling(252, min_periods=126)
        .median()
        .reset_index(level=0, drop=True)
    )
    panel["score_slow"] = panel.apply(lambda row: _mean_sign(row, (63, 126, 252)), axis=1)
    panel["score_fast"] = panel.apply(lambda row: _mean_sign(row, (21, 63, 126)), axis=1)
    panel["score_neighbor"] = panel.apply(lambda row: _mean_sign(row, (42, 84, 168)), axis=1)
    panel["score_vol_regime"] = np.where(
        panel["vol60"] >= panel["vol60_median252"],
        panel["score_fast"],
        -panel["trend_21"].map(_sign),
    )
    panel["source_month"] = panel["source_official_day"].dt.to_period("M")
    month_end = (
        panel.sort_values("source_official_day")
        .groupby(["product", "source_month"], as_index=False)
        .tail(1)
        .copy()
    )
    month_end["incomplete_source_month"] = month_end["source_month"].eq(
        panel["source_month"].max()
    )
    return month_end.sort_values(["available_official_day", "product"]).reset_index(drop=True)


def _arm_score(row: pd.Series, arm: str) -> float:
    mapping = {
        "tsmom_slow_63_126_252": "score_slow",
        "tsmom_fast_21_63_126": "score_fast",
        "tsmom_neighbor_42_84_168": "score_neighbor",
        "tsmom_vol_regime_fast": "score_vol_regime",
    }
    return float(row[mapping[arm]])


def build_monthly_targets(signals: pd.DataFrame, products: tuple[str, ...]) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    required = ["score_slow", "score_fast", "score_neighbor", "score_vol_regime", "vol60"]
    signals = signals[signals["product"].isin(products)].copy()
    for execution_day, day in signals.groupby("available_official_day", sort=True):
        if day["incomplete_source_month"].any():
            continue
        if set(day["product"]) != set(products) or day[required].isna().any().any():
            continue
        by_product = day.set_index("product")
        for arm in ARMS:
            raw = {
                product: _arm_score(by_product.loc[product], arm)
                * 0.10
                / max(float(by_product.loc[product, "vol60"]), 0.05)
                for product in products
            }
            weights = base._cap_weights(raw, products)
            for product, weight in weights.items():
                source = by_product.loc[product]
                rows.append(
                    {
                        "execution_day": execution_day,
                        "source_official_day": source["source_official_day"],
                        "arm": arm,
                        "product": product,
                        "sector": SECTORS[product],
                        "target_symbol": source["target_symbol"],
                        "target_weight": weight,
                        "score": _arm_score(source, arm),
                        "vol60": source["vol60"],
                    }
                )
    return pd.DataFrame(rows)


def replay(
    contracts: pd.DataFrame,
    features: pd.DataFrame,
    signals: pd.DataFrame,
    products: tuple[str, ...],
    tick_size: dict[str, float],
) -> base.ReplayResult:
    targets = build_monthly_targets(signals, products)
    previous_arms = base.ARMS
    try:
        base.ARMS = ARMS
        return base.replay_exact_contracts(
            contracts[contracts["product"].isin(products)],
            targets,
            features,
            products,
            tick_size,
        )
    finally:
        base.ARMS = previous_arms


def _compound(values: pd.Series) -> float:
    return float((1.0 + values.astype(float)).prod() - 1.0)


def summarize_windows(daily: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for window, (start, end) in WINDOWS.items():
        sample = daily[daily["date"].between(start, end)]
        for arm, group in sample.groupby("arm", sort=True):
            for cost, column in (("GROSS", "gross_return"), ("3T", "net_3t_return"), ("5T", "net_5t_return")):
                returns = group[column]
                daily_std = float(returns.std(ddof=1))
                monthly = (
                    group.assign(month=group["date"].dt.to_period("M"))
                    .groupby("month")[column]
                    .apply(_compound)
                )
                rows.append(
                    {
                        "window": window,
                        "arm": arm,
                        "cost": cost,
                        "days": len(group),
                        "total_return": _compound(returns),
                        "sharpe": float(returns.mean() / daily_std * math.sqrt(252.0)) if daily_std > 0 else np.nan,
                        "max_drawdown": base._max_drawdown(returns),
                        "positive_months": int((monthly > 0).sum()),
                        "negative_months": int((monthly < 0).sum()),
                        "fill_turnover": float(group["fill_turnover"].sum()),
                        "mean_gross_exposure": float(group["gross_exposure"].mean()),
                        "mean_net_exposure": float(group["net_exposure"].mean()),
                    }
                )
    return pd.DataFrame(rows)


def summarize_quarters(daily: pd.DataFrame) -> pd.DataFrame:
    sample = daily[daily["date"].between("2025-01-01", "2026-07-09")].copy()
    sample["quarter"] = sample["date"].dt.to_period("Q").astype(str)
    rows = []
    for (arm, quarter), group in sample.groupby(["arm", "quarter"], sort=True):
        returns = group["net_5t_return"]
        rows.append(
            {
                "arm": arm,
                "quarter": quarter,
                "days": len(group),
                "net_5t_return": _compound(returns),
                "max_drawdown_5t": base._max_drawdown(returns),
            }
        )
    return pd.DataFrame(rows)


def summarize_top_day(daily: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for window, (start, end) in WINDOWS.items():
        sample = daily[daily["date"].between(start, end)]
        for arm, group in sample.groupby("arm", sort=True):
            winner = group.loc[group["net_5t_return"].idxmax()]
            without = group.drop(index=winner.name)
            rows.append(
                {
                    "window": window,
                    "arm": arm,
                    "best_day": winner["date"],
                    "best_day_5t_return": winner["net_5t_return"],
                    "total_5t_return": _compound(group["net_5t_return"]),
                    "without_best_day_5t_return": _compound(without["net_5t_return"]),
                }
            )
    return pd.DataFrame(rows)


def summarize_leave_one(
    contracts: pd.DataFrame,
    features: pd.DataFrame,
    signals: pd.DataFrame,
    tick_size: dict[str, float],
) -> pd.DataFrame:
    rows = []
    omissions: list[tuple[str, str, tuple[str, ...]]] = []
    for omitted in PRODUCTS:
        omissions.append(("product", omitted, tuple(p for p in PRODUCTS if p != omitted)))
    for sector in sorted(set(SECTORS.values())):
        omissions.append(("sector", sector, tuple(p for p in PRODUCTS if SECTORS[p] != sector)))
    for omit_type, omitted, products in omissions:
        daily = replay(contracts, features, signals, products, tick_size).daily
        for window, (start, end) in WINDOWS.items():
            sample = daily[daily["date"].between(start, end)]
            for arm, group in sample.groupby("arm", sort=True):
                rows.append(
                    {
                        "omit_type": omit_type,
                        "omitted": omitted,
                        "window": window,
                        "arm": arm,
                        "net_5t_return": _compound(group["net_5t_return"]),
                        "max_drawdown_5t": base._max_drawdown(group["net_5t_return"]),
                    }
                )
    return pd.DataFrame(rows)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _binding(path: Path) -> dict[str, object]:
    try:
        rendered = str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        rendered = str(path)
    return {"path": rendered, "bytes": path.stat().st_size, "sha256": _sha256(path)}


def write_manifest(panel_dir: Path, spec_file: Path, output_dir: Path) -> dict[str, object]:
    inputs = {
        "runner": Path(__file__).resolve(),
        "base_runner": Path(base.__file__).resolve(),
        "panel_manifest": panel_dir / "manifest.json",
        "curve_features_daily": panel_dir / "curve_features_daily.csv",
        "curve_contract_daily": panel_dir / "curve_contract_daily.csv",
        "research_spec": spec_file,
        "research_spec_manifest": spec_file.with_name("manifest.json"),
    }
    outputs = sorted(p for p in output_dir.iterdir() if p.is_file() and p.name != "manifest.json")
    manifest = {
        "schema_version": "commodity_fast_tsmom_family_dev_v1_manifest",
        "status": "PASS_COMPLETE_POST_DISCOVERY_DEVELOPMENT_REPLAY",
        "input_bindings": {name: _binding(path) for name, path in inputs.items()},
        "output_bindings": [_binding(path) for path in outputs],
        "future_main_chain_lookup_used": False,
        "legacy_event_trade_position_pnl_ledger_read": False,
        "network_used": False,
        "formal_fee_included": False,
        "tradable": False,
        "production_authorized": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def run(panel_dir: Path, spec_file: Path, output_dir: Path) -> dict[str, pd.DataFrame]:
    features, contracts, panel_manifest = base._load(panel_dir)
    tick_size, spec_sha256 = base._load_research_spec(spec_file, panel_manifest)
    signals = build_signal_panel(features, contracts)
    full = replay(contracts, features, signals, PRODUCTS, tick_size)
    summary = summarize_windows(full.daily)
    quarters = summarize_quarters(full.daily)
    top_day = summarize_top_day(full.daily)
    leave_one = summarize_leave_one(contracts, features, signals, tick_size)
    targets = build_monthly_targets(signals, PRODUCTS)

    output_dir.mkdir(parents=True, exist_ok=False)
    summary.to_csv(output_dir / "summary.csv", index=False)
    quarters.to_csv(output_dir / "quarterly_5t.csv", index=False)
    top_day.to_csv(output_dir / "top_day_removal_5t.csv", index=False)
    leave_one.to_csv(output_dir / "leave_one_5t.csv", index=False)
    full.daily.to_csv(output_dir / "daily_pnl.csv", index=False)
    full.weights.to_csv(output_dir / "execution_weights.csv", index=False)
    targets.to_csv(output_dir / "monthly_targets.csv", index=False)
    signals.to_csv(output_dir / "monthly_signal_panel.csv", index=False)
    receipt = {
        "status": "COMPLETE_POST_DISCOVERY_DEVELOPMENT_REPLAY",
        "panel_contract_id": panel_manifest["contract_id"],
        "research_spec_sha256": spec_sha256,
        "arms": list(ARMS),
        "products": list(PRODUCTS),
        "signal_availability": "source close, next official day exact-contract open",
        "roll_rule": "daily PIT OI main; old-contract return closes switch interval",
        "cost_scope": "3T/5T tick impact stress only; formal fee unavailable",
        "candidate_status": "nonconfirmatory_post_discovery_development",
        "legacy_ledger_read": False,
        "network_used": False,
        "tradable": False,
        "production_authorized": False,
    }
    (output_dir / "receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_manifest(panel_dir, spec_file, output_dir)
    return {
        "summary": summary,
        "quarters": quarters,
        "top_day": top_day,
        "leave_one": leave_one,
        "daily": full.daily,
        "targets": targets,
        "signals": signals,
    }


def main() -> None:
    args = _parse_args()
    outputs = run(args.panel_dir, args.spec_file, args.output_dir)
    selected = outputs["summary"]
    print(selected[selected["cost"].eq("5T")].to_string(index=False))
    print(f"output_dir={args.output_dir}")


if __name__ == "__main__":
    main()
