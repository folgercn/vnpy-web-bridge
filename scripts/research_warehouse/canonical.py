"""Canonical JSON and digest primitives for immutable custody evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .errors import RegistryError


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RegistryError(f"value is not canonical JSON: {exc}") from exc


def canonical_json_line(value: Any) -> bytes:
    return canonical_json(value) + b"\n"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def parse_json_strict(
    raw: bytes,
    label: str,
    *,
    decimal_numbers_as_strings: bool = False,
) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=str if decimal_numbers_as_strings else float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RegistryError(f"{label} is not strict JSON: {exc}") from exc
