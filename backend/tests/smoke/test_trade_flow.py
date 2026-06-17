from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.getenv("VNPY_ALLOW_TRADE_TEST") != "true",
    reason="真实交易 smoke 必须显式设置 VNPY_ALLOW_TRADE_TEST=true",
)
def test_trade_flow_script_requires_explicit_allow_trade() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    result = subprocess.run(
        [sys.executable, str(repo_root / "test_rpc_trade_flow.py"), "--allow-trade"],
        cwd=repo_root,
        check=False,
        text=True,
        capture_output=True,
        timeout=90,
    )
    assert result.returncode in {0, 2, 3}
