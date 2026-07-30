#!/usr/bin/env python3
"""One-shot guardband-v2 counterfactual for the frozen lot-aware allocator.

This research-only runner changes exactly one axis from the v1 allocator: the
pre-registered target buffers become product=12%, sector=27%, gross=80%, and
target net=0.  Scheduler weights, capital ladder, joint integer algorithm,
strict hard caps, monthly-only re-optimization, daily drift monitoring and 5T
self-financing accounting are reused unchanged from v1.  No buffer scan or
result-conditioned reweighting is permitted.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.entry_redesign.scripts.futures_lead import (
    commodity_candidate_lot_aware_safe_allocator_v1 as base,
)


OUTROOT = base.OUTROOT
DEFAULT_OUTPUT = OUTROOT / "commodity_candidate_lot_aware_safe_allocator_guardband_v2_20260717"
TEST_FILE = Path(__file__).with_name("tests") / "test_commodity_candidate_lot_aware_safe_allocator_guardband_v2.py"
V1_OUTPUT = base.DEFAULT_OUTPUT

PRODUCTS = base.PRODUCTS
SECTORS = base.SECTORS
COMBINATION_ARMS = base.COMBINATION_ARMS
WINDOWS = base.WINDOWS
CAPITAL_LADDER_CNY = base.CAPITAL_LADDER_CNY
HARD_LIMITS = base.HARD_LIMITS
USABILITY_GATES = base.USABILITY_GATES

# The only changed research axis. These values are fixed before viewing v2.
BUFFER_LIMITS = {
    "product": 0.12,
    "sector": 0.27,
    "gross": 0.80,
    "target_net": 0.0,
}

UNCHANGED_V1_AXES = {
    "combination_arms": COMBINATION_ARMS,
    "capital_ladder_cny": list(CAPITAL_LADDER_CNY),
    "hard_limits_strict": HARD_LIMITS,
    "tick_stress_per_fill_side": base.TICK_STRESS_PER_FILL_SIDE,
    "neighbourhood_radius_lots": base.NEIGHBOURHOOD_RADIUS_LOTS,
    "beam_width": base.BEAM_WIDTH,
    "net_error_penalty": base.NET_ERROR_PENALTY,
    "usability_gates": USABILITY_GATES,
    "monthly_target_dates_only": True,
    "daily_auto_reweight": False,
    "roll_preserves_integer_lots": True,
}


def _activate_guardband() -> None:
    """Bind the imported v1 implementation to the sole v2 parameter change."""
    if base.CAPITAL_LADDER_CNY != CAPITAL_LADDER_CNY:
        raise ValueError("V1_CAPITAL_LADDER_CHANGED")
    if base.COMBINATION_ARMS != COMBINATION_ARMS:
        raise ValueError("V1_SCHEDULER_WEIGHTS_CHANGED")
    if base.HARD_LIMITS != HARD_LIMITS:
        raise ValueError("V1_HARD_LIMITS_CHANGED")
    if base.TICK_STRESS_PER_FILL_SIDE != 2.5:
        raise ValueError("V1_5T_ACCOUNTING_CHANGED")
    if base.NEIGHBOURHOOD_RADIUS_LOTS != 2 or base.BEAM_WIDTH != 2048:
        raise ValueError("V1_INTEGER_SEARCH_CHANGED")
    base.BUFFER_LIMITS = dict(BUFFER_LIMITS)


def buffer_one_target(source: dict[str, float]) -> dict[str, float]:
    _activate_guardband()
    return base.buffer_one_target(source)


def build_buffered_targets(targets: pd.DataFrame) -> pd.DataFrame:
    _activate_guardband()
    return base.build_buffered_targets(targets)


def joint_integer_allocate(
    target: dict[str, float], unit_weights: dict[str, float]
) -> base.Allocation:
    _activate_guardband()
    return base.joint_integer_allocate(target, unit_weights)


def _minimum_text(decisions: pd.DataFrame, arm: str, column: str) -> str:
    selected = decisions[decisions["combination_arm"].eq(arm) & decisions[column]]
    if selected.empty:
        return "无"
    return f"{int(selected['initial_capital_cny'].min()):,} CNY"


def _common_minimum_text(decisions: pd.DataFrame, column: str) -> str:
    common = decisions.groupby("initial_capital_cny")[column].all()
    common = common[common]
    if common.empty:
        return "无"
    return f"{int(common.index.min()):,} CNY"


def build_v1_comparison(summary: pd.DataFrame, decisions: pd.DataFrame) -> pd.DataFrame:
    v1_summary = pd.read_csv(V1_OUTPUT / "capital_summary.csv")
    v1_decisions = pd.read_csv(V1_OUTPUT / "capital_decision.csv")
    keys = ["window", "combination_arm", "initial_capital_cny"]
    metrics = [
        "total_return",
        "max_drawdown",
        "zero_contract_rate",
        "mean_executable_products",
        "mean_abs_buffered_target_error",
        "any_risk_breach_days",
        "holding_drift_breach_days",
    ]
    left = summary[keys + metrics].copy()
    right = v1_summary[keys + metrics].copy()
    merged = left.merge(right, on=keys, suffixes=("_v2", "_v1"), validate="one_to_one")
    for metric in metrics:
        merged[f"{metric}_delta_v2_minus_v1"] = merged[f"{metric}_v2"] - merged[f"{metric}_v1"]

    decision_keys = ["combination_arm", "initial_capital_cny"]
    flags = ["research_operational_usable", "testnet_safe_research_compatible"]
    decision_compare = decisions[decision_keys + flags].merge(
        v1_decisions[decision_keys + flags],
        on=decision_keys,
        suffixes=("_v2", "_v1"),
        validate="one_to_one",
    )
    return merged.merge(decision_compare, on=decision_keys, validate="many_to_one")


def _yn(value: object) -> str:
    return "是" if bool(value) else "否"


def render_report(summary: pd.DataFrame, decisions: pd.DataFrame, comparison: pd.DataFrame) -> str:
    lines = [
        "# 强候选 lot-aware safe allocator guardband v2 单一反证（2026-07-17）",
        "",
        "状态：`RESEARCH_ONLY_FIXED_GUARDBAND_V2_NOT_TRADABLE`。本次只把v1预注册buffer收紧为product 12%、sector 27%、gross 80%、target net 0；未扫描其他buffer，未按结果调scheduler权重。",
        "",
        "## 结论",
        "",
    ]
    for arm in COMBINATION_ARMS:
        research_min = _minimum_text(decisions, arm, "research_operational_usable")
        safe_min = _minimum_text(decisions, arm, "testnet_safe_research_compatible")
        lines.append(
            f"- `{arm}` 最低研究可用资本：**{research_min}**；最低safe-compatible研究资本：**{safe_min}**。"
        )
    lines += [
        f"- 两个scheduler共同的最低研究可用资本：**{_common_minimum_text(decisions, 'research_operational_usable')}**。",
        f"- 两个scheduler共同的最低safe-compatible研究资本：**{_common_minimum_text(decisions, 'testnet_safe_research_compatible')}**。",
        "- safe-compatible仅是历史回放诊断标签；所有shadow/testnet/live/production authority仍为false。",
        "",
        "## 唯一固定变更",
        "",
        "- v1 buffer：product 14%、sector 30%、gross 90%、target net 0。",
        "- v2 guardband：product 12%、sector 27%、gross 80%、target net 0。",
        "- 不变：`CORE_EQUAL_TARGET=50%C+50%D`、`CORE_PLUS_RESERVE_TARGET=40%C+40%D+20%R`；资本梯度100k至20m；联合整数beam算法；严格硬上限15%/35%/100%/|net|10%；每单边fill 2.5 ticks；self-financing会计。",
        "- 非月度日期不自动重调；exact-contract换月保留lot数量；每日按结算后equity逐日监控漂移。",
        "",
        "## 两个判定窗口",
        "",
        "| scheduler | 资本 | 窗口 | 收益 | 回撤 | 零合约率 | 平均覆盖品种 | 平均buffer误差 | daily breach日 | 漂移breach日 |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    required = set(USABILITY_GATES["required_windows"])
    for _, row in summary[summary["window"].isin(required)].sort_values(
        ["combination_arm", "initial_capital_cny", "window"]
    ).iterrows():
        lines.append(
            f"| `{row.combination_arm}` | {int(row.initial_capital_cny):,} | {row.window} | "
            f"{row.total_return:+.2%} | {row.max_drawdown:+.2%} | {row.zero_contract_rate:.1%} | "
            f"{row.mean_executable_products:.1f} | {row.mean_abs_buffered_target_error:.2%} | "
            f"{int(row.any_risk_breach_days)} | {int(row.holding_drift_breach_days)} |"
        )

    lines += [
        "",
        "## 全回放逐日硬约束与资本判定",
        "",
        "`daily breach`覆盖完整可回放区间至2026-07-09，不只覆盖两个判定窗口；任一product/sector/gross/net严格硬上限越界即失败。",
        "",
        "| scheduler | 资本 | 全回放breach日 | product | sector | gross | net | 研究可用 | safe-compatible |",
        "|---|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for _, decision in decisions.sort_values(["combination_arm", "initial_capital_cny"]).iterrows():
        replay = summary[
            summary["combination_arm"].eq(decision.combination_arm)
            & summary["initial_capital_cny"].eq(decision.initial_capital_cny)
            & summary["window"].eq("READ_2026YTD_THROUGH_0709")
        ]
        # Window summaries do not span 2025+2026 together, so use the maximum
        # over all emitted windows only for this display. The decision itself is
        # computed from the full daily replay in base.assess_capital.
        full = comparison[
            comparison["combination_arm"].eq(decision.combination_arm)
            & comparison["initial_capital_cny"].eq(decision.initial_capital_cny)
        ]
        # Exact full-replay counts are attached by run before report rendering.
        row = decision
        lines.append(
            f"| `{row.combination_arm}` | {int(row.initial_capital_cny):,} | "
            f"{int(row.full_replay_any_risk_breach_days)} | {int(row.full_replay_product_breach_days)} | "
            f"{int(row.full_replay_sector_breach_days)} | {int(row.full_replay_gross_breach_days)} | "
            f"{int(row.full_replay_net_breach_days)} | {_yn(row.research_operational_usable)} | "
            f"{_yn(row.testnet_safe_research_compatible)} |"
        )

    v1_breach = int(comparison["any_risk_breach_days_v1"].sum())
    v2_breach = int(comparison["any_risk_breach_days_v2"].sum())
    lines += [
        "",
        "## v1对照解释",
        "",
        f"- 两个判定窗口、全部资本和scheduler汇总的risk-breach日计数由v1的 **{v1_breach}** 降至v2的 **{v2_breach}**；该数字是分层汇总计数，不是唯一日期数。",
        "- 收益、覆盖、误差和零合约率均完整报告，收紧guardband造成的经济或离散化代价不得隐藏。",
        "- 本反证只回答固定12%/27%/80%是否足以在现有历史回放中形成safe-compatible资本层；不允许据结果继续尝试11%、13%或其他buffer。",
        "",
        "## 边界",
        "",
        "- 未纳入正式手续费、保证金、实时bid/ask、容量、涨跌停与交易所下单约束；safe-compatible不等于可交易。",
        "- finite-neighbourhood beam是固定确定性启发式，不声称全局整数最优。",
        "- `confirmatory=false`、`tradable=false`、`shadow_authorized=false`、`testnet_authorized=false`、`live_authorized=false`、`production_authorized=false`。",
    ]
    return "\n".join(lines) + "\n"


def _attach_full_replay_counts(decisions: pd.DataFrame, daily: pd.DataFrame) -> pd.DataFrame:
    columns = {
        "any_risk_breach": "full_replay_any_risk_breach_days",
        "product_breach_count": "full_replay_product_breach_days",
        "sector_breach_count": "full_replay_sector_breach_days",
        "gross_breach": "full_replay_gross_breach_days",
        "net_breach": "full_replay_net_breach_days",
    }
    rows = []
    for (arm, capital), group in daily.groupby(["combination_arm", "initial_capital_cny"]):
        rows.append(
            {
                "combination_arm": arm,
                "initial_capital_cny": int(capital),
                "full_replay_any_risk_breach_days": int(group["any_risk_breach"].sum()),
                "full_replay_product_breach_days": int((group["product_breach_count"] > 0).sum()),
                "full_replay_sector_breach_days": int((group["sector_breach_count"] > 0).sum()),
                "full_replay_gross_breach_days": int(group["gross_breach"].sum()),
                "full_replay_net_breach_days": int(group["net_breach"].sum()),
                "full_replay_start": group["date"].min(),
                "full_replay_end": group["date"].max(),
                "full_replay_days": len(group),
            }
        )
    return decisions.merge(pd.DataFrame(rows), on=["combination_arm", "initial_capital_cny"], validate="one_to_one")


def run(output_dir: Path) -> dict[str, pd.DataFrame]:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    _activate_guardband()
    inputs, source_targets = base.load_inputs()
    buffered_targets = build_buffered_targets(source_targets)
    simulations = [
        base.simulate_one(inputs, buffered_targets, arm, capital)
        for arm in COMBINATION_ARMS
        for capital in CAPITAL_LADDER_CNY
    ]
    daily = pd.concat([simulation.daily for simulation in simulations], ignore_index=True)
    allocations = pd.concat([simulation.allocations for simulation in simulations], ignore_index=True)
    optimizer = pd.concat([simulation.optimizer_events for simulation in simulations], ignore_index=True)
    summary = base.summarize(daily, allocations, optimizer)
    decisions = base.assess_capital(summary, daily, optimizer)
    decisions = _attach_full_replay_counts(decisions, daily)
    breaches = daily[daily["any_risk_breach"]].copy()
    comparison = build_v1_comparison(summary, decisions)

    output_dir.mkdir(parents=True, exist_ok=False)
    outputs = {
        "buffered_monthly_targets.csv": buffered_targets,
        "daily_accounting.csv": daily,
        "allocation_rows.csv": allocations,
        "optimizer_events.csv": optimizer,
        "capital_summary.csv": summary,
        "capital_decision.csv": decisions,
        "risk_breach_rows.csv": breaches,
        "v1_v2_comparison.csv": comparison,
    }
    for name, frame in outputs.items():
        frame.to_csv(output_dir / name, index=False)

    contract = {
        "schema_version": "commodity_candidate_lot_aware_safe_allocator_guardband_v2_contract",
        "status": "FIXED_ONE_SHOT_BEFORE_GUARDBAND_V2_RESULT_ASSESSMENT",
        "sole_changed_axis_from_v1": {
            "name": "pre_registered_buffer_limits",
            "v1": {"product": 0.14, "sector": 0.30, "gross": 0.90, "target_net": 0.0},
            "v2": BUFFER_LIMITS,
        },
        "unchanged_v1_axes": UNCHANGED_V1_AXES,
        "other_buffer_trials_permitted": False,
        "result_conditioned_weight_change_permitted": False,
        "network_used": False,
        "legacy_event_trade_position_label_pnl_ledger_read": False,
        "confirmatory": False,
        "tradable": False,
        "shadow_authorized": False,
        "testnet_authorized": False,
        "live_authorized": False,
        "production_authorized": False,
    }
    (output_dir / "guardband_contract.json").write_text(
        json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(
        render_report(summary, decisions, comparison), encoding="utf-8"
    )
    receipt = {
        "status": "COMPLETE_FIXED_ONE_SHOT_GUARDBAND_V2_COUNTERFACTUAL",
        "fixed_guardband": BUFFER_LIMITS,
        "fixed_runs_completed": len(COMBINATION_ARMS) * len(CAPITAL_LADDER_CNY),
        "buffer_scan_used": False,
        "result_conditioned_reweight_used": False,
        "daily_auto_reweight_used": False,
        "full_replay_start": str(pd.Timestamp(daily["date"].min()).date()),
        "full_replay_end": str(pd.Timestamp(daily["date"].max()).date()),
        "network_used": False,
        "legacy_event_trade_position_label_pnl_ledger_read": False,
        "confirmatory": False,
        "tradable": False,
        "shadow_authorized": False,
        "testnet_authorized": False,
        "live_authorized": False,
        "production_authorized": False,
        "python": platform.python_version(),
        "pandas": pd.__version__,
        "numpy": np.__version__,
    }
    (output_dir / "receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    inputs_bound = {
        "runner_v2": Path(__file__).resolve(),
        "tests_v2": TEST_FILE,
        "allocator_v1_runner": Path(base.__file__).resolve(),
        "allocator_v1_manifest": V1_OUTPUT / "manifest.json",
        "allocator_v1_summary": V1_OUTPUT / "capital_summary.csv",
        "allocator_v1_decision": V1_OUTPUT / "capital_decision.csv",
        "canonical_manifest": base.CANONICAL_DIR / "manifest.json",
        "canonical_monthly_targets": base.CANONICAL_TARGETS,
        "integer_ladder_manifest": base.LADDER_DIR / "manifest.json",
        "panel_manifest": base.canonical.PANEL_DIR / "manifest.json",
        "research_spec": base.canonical.SPEC_FILE,
    }
    files = sorted(path for path in output_dir.iterdir() if path.is_file() and path.name != "manifest.json")
    manifest = {
        "schema_version": "commodity_candidate_lot_aware_safe_allocator_guardband_v2_manifest",
        "status": "PASS_FIXED_ONE_SHOT_GUARDBAND_V2_COUNTERFACTUAL",
        "input_bindings": {name: base._binding(path) for name, path in inputs_bound.items()},
        "output_bindings": [base._binding(path) for path in files],
        "sole_changed_axis_from_v1": "buffer_14_30_90_to_12_27_80_target_net_zero_unchanged",
        "two_scheduler_weights_unchanged": True,
        "joint_integer_algorithm_unchanged": True,
        "capital_ladder_unchanged": True,
        "five_tick_accounting_unchanged": True,
        "strict_hard_caps_15_35_100_10_unchanged": True,
        "holding_drift_monitored_daily": True,
        "daily_auto_reweight_used": False,
        "buffer_scan_used": False,
        "result_conditioned_reweight_used": False,
        "network_used": False,
        "legacy_event_trade_position_label_pnl_ledger_read": False,
        "confirmatory": False,
        "tradable": False,
        "shadow_authorized": False,
        "testnet_authorized": False,
        "live_authorized": False,
        "production_authorized": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    outputs = run(args.output_dir)
    print(outputs["capital_decision.csv"].to_string(index=False))
    print(f"output_dir={args.output_dir}")


if __name__ == "__main__":
    main()
