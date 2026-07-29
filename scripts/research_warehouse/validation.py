"""Schema-drift checks for exact official response bytes."""

from __future__ import annotations

from typing import Any

from .canonical import parse_json_strict
from .errors import RegistryError
from .models import SourceEndpoint

AUTHORITATIVE_DAY_FIELDS = {
    "shfe-kx-dat-observed-2026-07-29-v1": "report_date",
    "ine-kx-dat-observed-2026-07-29-v1": "report_date",
}


def validate_source_bytes(
    raw: bytes,
    source: SourceEndpoint,
    trade_day: str,
) -> None:
    if not raw:
        raise RegistryError("official source response is empty")
    if source.media_type != "application/json":
        raise RegistryError("v1 acquisition only admits frozen JSON sources")
    payload = parse_json_strict(raw, "official source response")
    if not isinstance(payload, dict):
        raise RegistryError("official source response must be a JSON object")
    missing_top = set(source.required_top_level_fields) - set(payload)
    if missing_top:
        raise RegistryError(
            "official source schema drift; missing top-level fields: "
            + ", ".join(sorted(missing_top))
        )
    day_field = AUTHORITATIVE_DAY_FIELDS.get(source.endpoint_schema_version)
    if day_field is None:
        raise RegistryError("source schema has no frozen authoritative day binding")
    compact_day = trade_day.replace("-", "")
    if payload.get(day_field) != compact_day:
        raise RegistryError(
            "official source response day does not match requested trade_day"
        )
    rows: Any = payload[source.required_top_level_fields[0]]
    if not isinstance(rows, list) or not rows:
        raise RegistryError("official source response must contain non-empty rows")
    required = set(source.required_row_fields)
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise RegistryError(f"official source row {index} is not an object")
        missing = required - set(row)
        if missing:
            raise RegistryError(
                f"official source row {index} schema drift; missing: "
                + ", ".join(sorted(missing))
            )
