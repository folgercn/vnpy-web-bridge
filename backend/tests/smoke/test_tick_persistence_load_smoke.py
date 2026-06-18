from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.getenv("RUN_TICK_PERSISTENCE_LOAD_SMOKE") != "true" or not os.getenv("QUESTDB_PG_DSN"),
    reason="tick persistence load smoke 需要 RUN_TICK_PERSISTENCE_LOAD_SMOKE=true 和 QUESTDB_PG_DSN",
)
def test_tick_persistence_load_smoke_script() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    result = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "tick_persistence_load_smoke.py"), "--count", "100", "--batch-size", "50"],
        cwd=repo_root,
        check=False,
        text=True,
        capture_output=True,
        timeout=90,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(result.stdout)
    assert payload["received"] == 100
    assert payload["questdb_rows"] == 100
    assert payload["diff"] == 0
    assert payload["dropped"] == 0
    assert payload["spool_rows"] == 0
    assert payload["enqueue_p95_ms"] <= 10
