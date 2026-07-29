"""Frozen C_FAST Research history quality contract."""

from __future__ import annotations

from typing import Final

TARGET_PRODUCTS: Final = (
    "ag",
    "al",
    "au",
    "bu",
    "cu",
    "rb",
    "ru",
    "sc",
    "sp",
    "zn",
)
PRODUCT_EXCHANGES: Final = {
    "ag": "SHFE",
    "al": "SHFE",
    "au": "SHFE",
    "bu": "SHFE",
    "cu": "SHFE",
    "rb": "SHFE",
    "ru": "SHFE",
    "sc": "INE",
    "sp": "SHFE",
    "zn": "SHFE",
}
TREND_HISTORY_OFFICIAL_DAYS: Final = 126
VOLATILITY_LOOKBACK_OFFICIAL_DAYS: Final = 60
REQUIRED_HISTORY_OFFICIAL_DAYS: Final = (
    TREND_HISTORY_OFFICIAL_DAYS + VOLATILITY_LOOKBACK_OFFICIAL_DAYS
)
DAILY_EVIDENCE_CLASS: Final = "OFFICIAL_DAILY_SUMMARY_POST_CLOSE"
