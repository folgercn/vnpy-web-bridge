from __future__ import annotations

import logging


def get_logger(name: str) -> logging.Logger:
    """Return a package logger without changing an application's root logging."""

    return logging.getLogger(f"research_lab.{name}")
