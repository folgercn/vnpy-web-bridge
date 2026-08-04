#!/usr/bin/env python3
"""Fail-closed verifier for the legacy web-bridge restart gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SHA256 = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
COMMIT = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
class GateError(ValueError):
    """The restart gate could not prove that deployment is safe."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise GateError(f"non-finite JSON number is forbidden: {value}")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _read_regular_json(
    path: Path,
    *,
    label: str,
    owner_only: bool = False,
) -> tuple[dict[str, Any], bytes]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise GateError(f"{label} is unavailable: {path}") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or (owner_only and stat.S_IMODE(info.st_mode) & 0o077)
        ):
            raise GateError(
                f"{label} must be a secure regular file owned by the current user"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GateError(f"{label} is not readable canonical JSON") from exc
    if not isinstance(payload, dict):
        raise GateError(f"{label} must be a JSON object")
    return payload, raw


def _parse_time(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise GateError(f"{field} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise GateError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _require_hash(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise GateError(f"{field} must be a non-zero lowercase sha256")
    return value


def verify_gate(
    *,
    receipt: dict[str, Any],
    recheck: dict[str, Any],
    receipt_schema: dict[str, Any],
    recheck_schema: dict[str, Any],
    receipt_raw_sha256: str,
    expected_plan_id: str,
    expected_source_commit: str,
    expected_unit: str,
    now: datetime,
    max_recheck_age_seconds: int,
) -> None:
    errors = sorted(
        Draft202012Validator(
            receipt_schema,
            format_checker=FormatChecker(),
        ).iter_errors(receipt),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise GateError(f"receipt schema validation failed: {errors[0].message}")
    errors = sorted(
        Draft202012Validator(
            recheck_schema,
            format_checker=FormatChecker(),
        ).iter_errors(recheck),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise GateError(f"recheck schema validation failed: {errors[0].message}")
    if not COMMIT.fullmatch(expected_source_commit):
        raise GateError("expected source commit must be a full non-zero lowercase SHA")
    if max_recheck_age_seconds < 1 or max_recheck_age_seconds > 300:
        raise GateError("max recheck age must be between 1 and 300 seconds")

    expected = {
        "release_plan_id": expected_plan_id,
        "target_source_commit_sha": expected_source_commit,
        "unit": expected_unit,
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise GateError(f"{field} binding mismatch")

    receipt_core = dict(receipt)
    receipt_core_sha = _require_hash(
        receipt_core.pop("receipt_core_sha256", None),
        field="receipt.receipt_core_sha256",
    )
    receipt_core.pop("receipt_id", None)
    if _sha256_json(receipt_core) != receipt_core_sha:
        raise GateError("receipt core hash mismatch")
    if receipt.get("receipt_id") != f"safe-restart-{receipt_core_sha}":
        raise GateError("receipt id does not match receipt core hash")
    if recheck.get("receipt_raw_sha256") != receipt_raw_sha256:
        raise GateError("recheck receipt hash mismatch")

    for field in (
        "receipt_id",
        "deployment_attempt_id",
        "release_plan_core_sha256",
        "restart_action_sha256",
        "drain_epoch",
        "execution_epoch",
    ):
        if receipt.get(field) != recheck.get(field):
            raise GateError(f"{field} changed after receipt issuance")
    receipt_snapshot = dict(receipt["snapshot"])
    recheck_snapshot = dict(recheck["snapshot"])
    receipt_captured_at = _parse_time(
        receipt_snapshot.pop("captured_at"), field="receipt.snapshot.captured_at"
    )
    recheck_captured_at = _parse_time(
        recheck_snapshot.pop("captured_at"), field="recheck.snapshot.captured_at"
    )
    if receipt_snapshot != recheck_snapshot:
        raise GateError("snapshot changed after receipt issuance")
    if recheck_captured_at < receipt_captured_at:
        raise GateError("recheck snapshot predates receipt snapshot")

    if recheck.get("schema_version") != "web_bridge_safe_restart_recheck_v1":
        raise GateError("unsupported recheck schema version")

    issued_at = _parse_time(receipt.get("issued_at"), field="issued_at")
    expires_at = _parse_time(receipt.get("expires_at"), field="expires_at")
    checked_at = _parse_time(recheck.get("checked_at"), field="checked_at")
    ttl_seconds = receipt.get("ttl_seconds")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
        raise GateError("ttl_seconds must be an integer")
    if (expires_at - issued_at).total_seconds() != ttl_seconds:
        raise GateError("receipt timestamp interval does not match ttl_seconds")
    current = now.astimezone(timezone.utc)
    if not (issued_at <= checked_at <= current < expires_at):
        raise GateError("receipt or recheck is not currently fresh")
    if (current - checked_at).total_seconds() > max_recheck_age_seconds:
        raise GateError("pre-restart recheck evidence is stale")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--recheck", type=Path, required=True)
    parser.add_argument("--receipt-schema", type=Path, required=True)
    parser.add_argument("--recheck-schema", type=Path, required=True)
    parser.add_argument("--expected-plan-id", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-unit", default="web-bridge")
    parser.add_argument("--max-recheck-age-seconds", type=int, default=30)
    parser.add_argument("--now", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        now = (
            _parse_time(args.now, field="now")
            if args.now
            else datetime.now(timezone.utc)
        )
        receipt, receipt_raw = _read_regular_json(
            args.receipt, label="receipt", owner_only=True
        )
        recheck, _ = _read_regular_json(
            args.recheck, label="recheck evidence", owner_only=True
        )
        receipt_schema, _ = _read_regular_json(
            args.receipt_schema, label="receipt schema"
        )
        recheck_schema, _ = _read_regular_json(
            args.recheck_schema, label="recheck schema"
        )
        verify_gate(
            receipt=receipt,
            recheck=recheck,
            receipt_schema=receipt_schema,
            recheck_schema=recheck_schema,
            receipt_raw_sha256=hashlib.sha256(receipt_raw).hexdigest(),
            expected_plan_id=args.expected_plan_id,
            expected_source_commit=args.expected_source_commit,
            expected_unit=args.expected_unit,
            now=now,
            max_recheck_age_seconds=args.max_recheck_age_seconds,
        )
    except (GateError, OSError) as exc:
        print(f"safe-restart gate blocked: {exc}", file=sys.stderr)
        return 2
    print(f"safe-restart gate verified receipt {receipt['receipt_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
