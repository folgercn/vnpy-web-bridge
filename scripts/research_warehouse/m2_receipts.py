"""Create-only daily-run and monitor receipt contracts."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import false_authority
from .m2_runtime_input import require_day, require_sha
from .m2_runtime_paths import RuntimePaths
from .publication import create_only_bytes
from .timeutil import parse_utc

RUN_RECEIPT_SCHEMA = "vnpy_research_m2_daily_run_receipt_v1"
MONITOR_RECEIPT_SCHEMA = "vnpy_research_m2_monitor_receipt_v1"
SOURCE_IDS = (
    "shfe-daily-market-data-v1",
    "ine-daily-market-data-v1",
)
RUN_KEYS = {
    "schema_version",
    "receipt_id",
    "trade_day",
    "completed_at",
    "registry_raw_sha256",
    "calendar_raw_sha256",
    "calendar_availability_anchor_raw_sha256",
    "sources",
    "authority",
}
RUN_SOURCE_KEYS = {
    "source_id",
    "exchange",
    "object_id",
    "observation_id",
    "revision_id",
    "raw_sha256",
    "raw_bytes",
    "raw_relative_path",
}
MONITOR_KEYS = {
    "schema_version",
    "receipt_id",
    "checked_at",
    "runtime_input_raw_sha256",
    "facts",
    "result",
    "authority",
}


def run_receipt_id(payload: dict[str, Any]) -> str:
    value = dict(payload)
    value["receipt_id"] = ""
    return "run-" + sha256(canonical_json(value))


def validate_run_receipt(value: object) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != RUN_KEYS
        or value["schema_version"] != RUN_RECEIPT_SCHEMA
        or value["authority"] != false_authority()
    ):
        raise RegistryError("M2 daily run receipt contract mismatch")
    require_day(value["trade_day"], "run receipt trade_day")
    parse_utc(value["completed_at"], "run receipt completed_at")
    require_sha(value["registry_raw_sha256"], "run receipt registry")
    require_sha(value["calendar_raw_sha256"], "run receipt calendar")
    require_sha(
        value["calendar_availability_anchor_raw_sha256"],
        "run receipt calendar availability anchor",
    )
    sources = value["sources"]
    if (
        not isinstance(sources, list)
        or len(sources) != len(SOURCE_IDS)
        or any(not isinstance(item, dict) for item in sources)
        or any(set(item) != RUN_SOURCE_KEYS for item in sources)
        or [item["source_id"] for item in sources] != list(SOURCE_IDS)
    ):
        raise RegistryError("M2 run receipt must bind exact SHFE/INE sources")
    for index, item in enumerate(sources):
        if item["exchange"] != ("SHFE", "INE")[index] or any(
            not isinstance(item[field], str) or not item[field]
            for field in ("object_id", "observation_id", "revision_id")
        ):
            raise RegistryError("M2 run receipt source identity is invalid")
        require_sha(item["raw_sha256"], "run receipt raw")
        if (
            not isinstance(item["raw_bytes"], int)
            or isinstance(item["raw_bytes"], bool)
            or item["raw_bytes"] < 1
        ):
            raise RegistryError("M2 run receipt raw_bytes is invalid")
        relative = item["raw_relative_path"]
        pure = PurePosixPath(relative) if isinstance(relative, str) else None
        if (
            pure is None
            or pure.is_absolute()
            or not pure.parts
            or pure.parts[0] != "raw"
            or ".." in pure.parts
        ):
            raise RegistryError("M2 run receipt raw path is unsafe")
    if value["receipt_id"] != run_receipt_id(value):
        raise RegistryError("M2 run receipt ID binding mismatch")
    return value


def load_run_receipt(path: Path) -> dict[str, Any]:
    raw = read_regular_strict(path, "M2 daily run receipt")
    payload = validate_run_receipt(parse_json_strict(raw, "M2 daily run receipt"))
    if raw != canonical_json_line(payload):
        raise RegistryError("M2 daily run receipt is not canonical JSON")
    if path.name != f"{payload['trade_day']}.json":
        raise RegistryError("M2 daily run receipt path binding mismatch")
    return payload


def publish_run_receipt(
    paths: RuntimePaths,
    payload: dict[str, Any],
    *,
    directory: Path | None = None,
) -> Path:
    validated = validate_run_receipt(payload)
    destination = directory or paths.run_receipts
    if destination not in (paths.run_receipts, paths.history_run_receipts):
        raise RegistryError("M2 run receipt directory is outside frozen runtime")
    return create_only_bytes(
        destination / f"{validated['trade_day']}.json",
        canonical_json_line(validated),
        "M2 daily run receipt",
        temporary_dir=paths.temporary,
    )


def publish_monitor_receipt(
    paths: RuntimePaths,
    *,
    checked_at: str,
    runtime_input_raw_sha256: str,
    facts: dict[str, Any],
    result: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    parse_utc(checked_at, "monitor checked_at")
    require_sha(runtime_input_raw_sha256, "monitor runtime input")
    payload = {
        "schema_version": MONITOR_RECEIPT_SCHEMA,
        "receipt_id": "",
        "checked_at": checked_at,
        "runtime_input_raw_sha256": runtime_input_raw_sha256,
        "facts": facts,
        "result": result,
        "authority": false_authority(),
    }
    payload["receipt_id"] = "monitor-" + sha256(
        canonical_json({**payload, "receipt_id": ""})
    )
    path = create_only_bytes(
        paths.monitor_receipts / f"{payload['receipt_id']}.json",
        canonical_json_line(payload),
        "M2 monitor receipt",
        temporary_dir=paths.temporary,
    )
    return path, payload


def load_monitor_receipt(
    path: Path,
    *,
    expected_raw_sha256: str,
) -> dict[str, Any]:
    expected = require_sha(expected_raw_sha256, "trusted monitor receipt")
    raw = read_regular_strict(path, "M2 monitor receipt")
    if sha256(raw) != expected:
        raise RegistryError("M2 monitor receipt raw SHA256 mismatch")
    payload = parse_json_strict(raw, "M2 monitor receipt")
    if (
        not isinstance(payload, dict)
        or set(payload) != MONITOR_KEYS
        or payload["schema_version"] != MONITOR_RECEIPT_SCHEMA
        or payload["authority"] != false_authority()
        or raw != canonical_json_line(payload)
    ):
        raise RegistryError("M2 monitor receipt contract mismatch")
    parse_utc(payload["checked_at"], "monitor checked_at")
    require_sha(payload["runtime_input_raw_sha256"], "monitor runtime input")
    expected_id = "monitor-" + sha256(canonical_json({**payload, "receipt_id": ""}))
    if payload["receipt_id"] != expected_id or path.name != f"{expected_id}.json":
        raise RegistryError("M2 monitor receipt ID/path binding mismatch")
    return payload
