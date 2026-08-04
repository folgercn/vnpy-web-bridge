#!/usr/bin/env python3
"""Repository wrapper for the packaged deployment-drain bootstrap command."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.deployment_drain_bootstrap import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
