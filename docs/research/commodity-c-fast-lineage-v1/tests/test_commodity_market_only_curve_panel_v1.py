import math

from research.entry_redesign.scripts.futures_lead.commodity_market_only_curve_panel_v1 import (
    assign_source_day_ranks,
    build_feature_row,
    delivery_yyyymm,
    log_carry_per_month,
    month_gap,
)


def _row(day: str, delivery: str, settlement: float, oi: float, volume: float = 1.0):
    return {
        "source_official_day": day,
        "product": "cu",
        "exchange": "SHFE",
        "exact_contract": f"SHFE.cu{delivery}",
        "delivery_month": delivery,
        "delivery_yyyymm": delivery_yyyymm(delivery),
        "open": settlement,
        "high": settlement,
        "low": settlement,
        "close": settlement,
        "settlement": settlement,
        "pre_settlement": settlement,
        "volume": volume,
        "turnover": volume * settlement,
        "open_interest": oi,
        "open_interest_change": 0.0,
    }


def test_delivery_month_math_and_backwardation_sign():
    assert month_gap(202412, 202501) == 1
    assert month_gap(202501, 202505) == 4
    assert log_carry_per_month(110.0, 100.0, 1) > 0
    assert log_carry_per_month(100.0, 110.0, 1) < 0


def test_current_delivery_month_is_excluded_and_t_plus_one_is_explicit():
    rows = [
        _row("2025-01-02", "2501", 120.0, 9999.0),
        _row("2025-01-02", "2502", 110.0, 200.0),
        _row("2025-01-02", "2503", 100.0, 500.0),
        _row("2025-01-02", "2505", 90.0, 300.0),
    ]
    ranked = assign_source_day_ranks(rows)
    feature = build_feature_row(ranked, "2025-01-03")

    assert feature["source_official_day"] == "2025-01-02"
    assert feature["available_official_day"] == "2025-01-03"
    assert feature["near_symbol"] == "SHFE.cu2502"
    assert feature["next_symbol"] == "SHFE.cu2503"
    assert feature["third_symbol"] == "SHFE.cu2505"
    assert feature["main_symbol"] == "SHFE.cu2503"
    assert feature["secondary_symbol"] == "SHFE.cu2505"
    assert feature["third_oi_symbol"] == "SHFE.cu2502"
    assert feature["near_next_gap_months"] == 1
    assert feature["next_third_gap_months"] == 2
    assert feature["near_next_log_carry_per_month"] > 0
    assert math.isclose(
        feature["near_next_log_carry_annualized"],
        feature["near_next_log_carry_per_month"] * 12.0,
    )


def test_oi_ranking_uses_only_current_source_day_values():
    day_one = assign_source_day_ranks(
        [
            _row("2025-01-02", "2502", 100.0, 300.0),
            _row("2025-01-02", "2503", 101.0, 200.0),
            _row("2025-01-02", "2504", 102.0, 100.0),
        ]
    )
    day_two = assign_source_day_ranks(
        [
            _row("2025-01-03", "2502", 100.0, 100.0),
            _row("2025-01-03", "2503", 101.0, 200.0),
            _row("2025-01-03", "2504", 102.0, 300.0),
        ]
    )
    feature_one = build_feature_row(day_one, "2025-01-03")
    feature_two = build_feature_row(day_two, "2025-01-06")

    assert feature_one["main_symbol"] == "SHFE.cu2502"
    assert feature_two["main_symbol"] == "SHFE.cu2504"
    assert feature_one["available_official_day"] == day_two[0]["source_official_day"]
