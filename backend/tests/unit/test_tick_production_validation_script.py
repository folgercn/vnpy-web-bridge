from __future__ import annotations

from pathlib import Path
import runpy

import pytest


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "tick_production_validation.py"
MODULE = runpy.run_path(str(SCRIPT), run_name="tick_production_validation")


def test_select_complete_trading_day_requires_night_and_day() -> None:
    selected = MODULE["select_complete_trading_day"](
        [
            {"trading_day": "20260717", "rows": 100, "start": "2026-07-17T09:00:00", "end": "2026-07-17T15:00:00"},
            {"trading_day": "20260716", "rows": 200, "start": "2026-07-15T21:00:00", "end": "2026-07-16T15:00:00"},
        ]
    )
    assert selected["trading_day"] == "20260716"


def test_select_complete_trading_day_fails_without_full_session() -> None:
    with pytest.raises(MODULE["ValidationError"]):
        MODULE["select_complete_trading_day"](
            [{"trading_day": "20260717", "rows": 100, "start": "2026-07-17T09:00:00", "end": "2026-07-17T15:00:00"}]
        )


def test_render_markdown_is_sanitized_summary() -> None:
    result = {
        "started_at": "start",
        "finished_at": "finish",
        "historical_day": {
            "trading_day": "20260716",
            "rows": 200,
            "symbols": 3,
            "exchange_count": 2,
            "start": "night",
            "end": "day",
            "peak_tps": 20,
            "average_active_tps": 10,
        },
        "checks": [{"name": "final_no_drops", "ok": True, "secret": "must-not-render"}],
        "faults": [{"name": "questdb_outage", "started_at": "now"}],
    }
    markdown = MODULE["render_markdown"](result)
    assert "final_no_drops" in markdown
    assert "questdb_outage" in markdown
    assert "must-not-render" not in markdown
