"""Shared bounded clock-skew limits for Execution snapshot validation."""

from .models import FUTURE_SKEW_SECONDS, SNAPSHOT_STALE_SECONDS

__all__ = ["FUTURE_SKEW_SECONDS", "SNAPSHOT_STALE_SECONDS"]
