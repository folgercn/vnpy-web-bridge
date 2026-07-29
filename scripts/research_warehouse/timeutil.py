"""Canonical UTC timestamp handling."""

from datetime import datetime, timezone

from .errors import RegistryError


def require_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise RegistryError(f"{label} must be timezone-aware UTC")
    return value.astimezone(timezone.utc)


def format_utc(value: datetime, label: str = "timestamp") -> str:
    normalized = require_utc(value, label)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RegistryError(f"{label} must use canonical UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RegistryError(f"{label} is not an ISO 8601 timestamp") from exc
    normalized = require_utc(parsed, label)
    if format_utc(normalized, label) != value:
        raise RegistryError(f"{label} is not canonical")
    return normalized
