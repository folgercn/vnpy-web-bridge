from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from research.entry_redesign.scripts.futures_lead.commodity_fast_tsmom_family_dev_v1 import (
    ARMS,
    _arm_score,
    _mean_sign,
    build_monthly_targets,
)


def test_mean_sign_is_equal_vote_not_raw_return_average() -> None:
    row = pd.Series({"trend_21": 0.01, "trend_63": -0.50, "trend_126": 0.02})
    assert _mean_sign(row, (21, 63, 126)) == 1.0 / 3.0


def test_arm_score_mapping_is_fixed() -> None:
    row = pd.Series(
        {"score_slow": -1.0, "score_fast": 1.0, "score_neighbor": 1.0 / 3.0, "score_vol_regime": -1.0 / 3.0}
    )
    assert [_arm_score(row, arm) for arm in ARMS] == [-1.0, 1.0, 1.0 / 3.0, -1.0 / 3.0]


def test_terminal_incomplete_month_is_fail_closed() -> None:
    day = pd.Timestamp("2026-07-10")
    signals = pd.DataFrame(
        [
            {
                "source_official_day": pd.Timestamp("2026-07-09"),
                "available_official_day": day,
                "product": "al",
                "target_symbol": "SHFE.al2608",
                "score_slow": 1.0,
                "score_fast": 1.0,
                "score_neighbor": 1.0,
                "score_vol_regime": 1.0,
                "vol60": 0.2,
                "incomplete_source_month": True,
            }
        ]
    )
    assert build_monthly_targets(signals, ("al",)).empty


def test_weights_respect_product_and_gross_caps() -> None:
    products = ("ag", "al", "au", "bu", "cu", "rb", "ru", "sc", "sp", "zn")
    rows = []
    for product in products:
        rows.append(
            {
                "source_official_day": pd.Timestamp("2025-01-27"),
                "available_official_day": pd.Timestamp("2025-02-03"),
                "product": product,
                "target_symbol": f"X.{product}2506",
                "score_slow": 1.0,
                "score_fast": 1.0,
                "score_neighbor": 1.0,
                "score_vol_regime": 1.0,
                "vol60": 0.05,
                "incomplete_source_month": False,
            }
        )
    targets = build_monthly_targets(pd.DataFrame(rows), products)
    for _, group in targets.groupby("arm"):
        assert group["target_weight"].abs().max() <= 0.20 + 1e-12
        assert group["target_weight"].abs().sum() <= 1.0 + 1e-12


def test_final_manifest_is_research_only_if_present() -> None:
    output = (
        Path(__file__).resolve().parents[2]
        / "output/commodity_fast_tsmom_family_dev_v1_20260717/manifest.json"
    )
    if output.exists():
        manifest = json.loads(output.read_text(encoding="utf-8"))
        assert manifest["production_authorized"] is False
        assert manifest["tradable"] is False
        assert manifest["legacy_event_trade_position_pnl_ledger_read"] is False
        assert manifest["network_used"] is False
        assert len(manifest["input_bindings"]) == 7
        assert len(manifest["output_bindings"]) == 9
