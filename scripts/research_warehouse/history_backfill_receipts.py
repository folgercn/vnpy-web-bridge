"""Create-only receipt contract for one bounded historical acquisition."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from .canonical import canonical_json, canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .m2_isolation_contracts import false_authority
from .m2_runtime_input import require_day, require_sha
from .m2_runtime_paths import RuntimePaths
from .publication import create_only_bytes
from .timeutil import parse_utc

BACKFILL_RECEIPT_SCHEMA = "vnpy_research_m2_history_backfill_receipt_v1"
BACKFILL_KEYS = {
    "schema_version",
    "receipt_id",
    "started_at",
    "completed_at",
    "through_trade_day",
    "required_official_days",
    "official_days",
    "calendar_raw_sha256",
    "calendar_availability_anchor_raw_sha256",
    "registry_raw_sha256",
    "base_manifest_sequence",
    "base_manifest_head_seal_sha256",
    "base_manifest_head_commit_seal_sha256",
    "daily_receipts",
    "authority",
}
DAILY_KEYS = {
    "trade_day",
    "run_receipt_relative_path",
    "run_receipt_raw_sha256",
    "source_raw_sha256",
    "source_raw_bytes",
}


def backfill_receipt_id(payload: dict[str, Any]) -> str:
    return "backfill-" + sha256(canonical_json({**payload, "receipt_id": ""}))


def validate_backfill_receipt(value: object) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != BACKFILL_KEYS
        or value["schema_version"] != BACKFILL_RECEIPT_SCHEMA
        or value["authority"] != false_authority()
    ):
        raise RegistryError("M2 history backfill receipt contract mismatch")
    parse_utc(value["started_at"], "backfill started_at")
    started = parse_utc(value["started_at"], "backfill started_at")
    completed = parse_utc(value["completed_at"], "backfill completed_at")
    if completed < started:
        raise RegistryError("M2 history backfill completion predates start")
    require_day(value["through_trade_day"], "backfill through_trade_day")
    count = value["required_official_days"]
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 1
        or count > 366
    ):
        raise RegistryError("M2 history backfill day count is invalid")
    days = value["official_days"]
    if (
        not isinstance(days, list)
        or len(days) != count
        or days != sorted(set(days))
        or days[-1] != value["through_trade_day"]
    ):
        raise RegistryError("M2 history backfill official-day plan is invalid")
    for day in days:
        require_day(day, "backfill official day")
    for field in (
        "calendar_raw_sha256",
        "calendar_availability_anchor_raw_sha256",
        "registry_raw_sha256",
    ):
        require_sha(value[field], field)
    sequence = value["base_manifest_sequence"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
    ):
        raise RegistryError("M2 history backfill base sequence is invalid")
    for field in (
        "base_manifest_head_seal_sha256",
        "base_manifest_head_commit_seal_sha256",
    ):
        if value[field] is not None:
            require_sha(value[field], field)
    if sequence == 0:
        if (
            value["base_manifest_head_seal_sha256"] is not None
            or value["base_manifest_head_commit_seal_sha256"] is not None
        ):
            raise RegistryError("M2 history backfill genesis pins are inconsistent")
    elif (
        value["base_manifest_head_seal_sha256"] is None
        or value["base_manifest_head_commit_seal_sha256"] is None
    ):
        raise RegistryError("M2 history backfill base pins are incomplete")
    daily = value["daily_receipts"]
    if (
        not isinstance(daily, list)
        or len(daily) != count
        or [item.get("trade_day") for item in daily] != days
    ):
        raise RegistryError("M2 history backfill daily receipts are incomplete")
    for item in daily:
        if not isinstance(item, dict) or set(item) != DAILY_KEYS:
            raise RegistryError("M2 history backfill daily receipt contract mismatch")
        require_day(item["trade_day"], "backfill daily trade_day")
        require_sha(item["run_receipt_raw_sha256"], "backfill run receipt")
        source_hashes = item["source_raw_sha256"]
        source_bytes = item["source_raw_bytes"]
        if (
            not isinstance(source_hashes, list)
            or len(source_hashes) != 2
            or any(require_sha(raw, "backfill source raw") != raw for raw in source_hashes)
            or not isinstance(source_bytes, list)
            or len(source_bytes) != 2
            or any(
                isinstance(size, bool) or not isinstance(size, int) or size < 1
                for size in source_bytes
            )
        ):
            raise RegistryError("M2 history backfill source binding is invalid")
        expected_path = f"history-run-receipts/{item['trade_day']}.json"
        if item["run_receipt_relative_path"] != expected_path:
            raise RegistryError("M2 history backfill run receipt path mismatch")
    if value["receipt_id"] != backfill_receipt_id(value):
        raise RegistryError("M2 history backfill receipt ID mismatch")
    return value


def publish_backfill_receipt(
    runtime: RuntimePaths,
    payload: dict[str, Any],
) -> Path:
    validated = validate_backfill_receipt(payload)
    return create_only_bytes(
        runtime.backfill_receipts / f"{validated['receipt_id']}.json",
        canonical_json_line(validated),
        "M2 history backfill receipt",
        temporary_dir=runtime.temporary,
    )


def load_backfill_receipt(
    path: Path,
    *,
    expected_raw_sha256: str | None = None,
    private: bool = True,
    expected_owner_uid: int | None = None,
) -> dict[str, Any]:
    def validate_descriptor(descriptor: int) -> None:
        info = os.fstat(descriptor)
        if (
            expected_owner_uid is None
            or info.st_uid != expected_owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RegistryError("M2 history backfill receipt owner/mode mismatch")

    raw = read_regular_strict(
        path,
        "M2 history backfill receipt",
        private=private,
        descriptor_validator=(
            validate_descriptor if expected_owner_uid is not None else None
        ),
    )
    if expected_raw_sha256 is not None and sha256(raw) != require_sha(
        expected_raw_sha256,
        "M2 history backfill receipt",
    ):
        raise RegistryError("M2 history backfill receipt SHA256 mismatch")
    payload = validate_backfill_receipt(
        parse_json_strict(raw, "M2 history backfill receipt")
    )
    if raw != canonical_json_line(payload):
        raise RegistryError("M2 history backfill receipt is not canonical JSON")
    if path.name != f"{payload['receipt_id']}.json":
        raise RegistryError("M2 history backfill receipt path binding mismatch")
    return payload
