#!/usr/bin/env python3
"""Fail-closed C_FAST T1 query bootstrap.

This process never opens the DSN.  It re-reads the fixed production pins and
then atomically replaces itself with the frozen readonly audit process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


PIN_ROOT = Path("/run/c-fast-t1-readiness-v2-pins")
PIN_NAMES = {
    "provenance": "provenance-keyring.sha256",
    "t1": "t1-authority-keyring.sha256",
    "query_v3": "query-v3-authority-keyring.sha256",
    "l3": "l3-authority-keyring.sha256",
    "outcome": "outcome-keyring.sha256",
    "custody": "packet-custody.path",
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_INVOCATION_BYTES = 64 * 1024
AUDIT_FLAGS = (
    "--manifest",
    "--start",
    "--end",
    "--dsn-file",
    "--expected-endpoint-identity-sha256",
    "--expected-manifest-sha256",
    "--json-output",
    "--csv-output",
    "--markdown-output",
    "--readonly-proof-output",
    "--pre-connect-query-gate",
    "--expected-pre-connect-gate-raw-sha256",
    "--expected-pre-connect-gate-canonical-sha256",
)
GATE_HASH_FLAGS = (
    "--expected-pre-connect-gate-raw-sha256",
    "--expected-pre-connect-gate-canonical-sha256",
)


class QueryChildError(RuntimeError):
    """Expected pre-network bootstrap failure."""


def _read_root_pin(path: Path, label: str) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise QueryChildError(f"{label} pin is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QueryChildError(f"{label} pin metadata is unsafe")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise QueryChildError(f"{label} pin cannot be read") from exc
    if len(raw) > 4096 or b"\x00" in raw:
        raise QueryChildError(f"{label} pin content is invalid")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise QueryChildError(f"{label} pin is not UTF-8") from exc
    if not value:
        raise QueryChildError(f"{label} pin is empty")
    return value


def verify_active_pins(
    expected: dict[str, str],
    *,
    pin_root: Path = PIN_ROOT,
) -> None:
    try:
        info = pin_root.lstat()
    except OSError as exc:
        raise QueryChildError("active pin root is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QueryChildError("active pin root metadata is unsafe")
    observed = {
        key: _read_root_pin(pin_root / name, key)
        for key, name in PIN_NAMES.items()
    }
    for key in ("provenance", "t1", "query_v3", "l3", "outcome"):
        if SHA256_PATTERN.fullmatch(expected[key]) is None:
            raise QueryChildError(f"expected {key} pin is invalid")
        if observed[key] != expected[key]:
            raise QueryChildError("active pins changed before query boundary")
    try:
        observed_custody = Path(observed["custody"]).resolve(strict=True)
        expected_custody = Path(expected["custody"]).resolve(strict=True)
    except OSError as exc:
        raise QueryChildError("active custody cannot be resolved") from exc
    if observed_custody != expected_custody:
        raise QueryChildError("active custody changed before query boundary")


def _reject_constant(value: str) -> None:
    raise QueryChildError(f"JSON constant {value!r} is forbidden")


def load_audit_invocation(path: Path) -> list[str]:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise QueryChildError("audit invocation must be a regular file")
        raw = path.read_bytes()
    except OSError as exc:
        raise QueryChildError("audit invocation is unavailable") from exc
    if len(raw) > MAX_INVOCATION_BYTES:
        raise QueryChildError("audit invocation is oversized")
    try:
        value: Any = json.loads(
            raw,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryChildError("audit invocation JSON is invalid") from exc
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise QueryChildError("audit invocation must be non-empty strings")
    if len(value) != 3 + 2 * len(AUDIT_FLAGS) or value[1] != "-I":
        raise QueryChildError("audit invocation shape is invalid")
    if tuple(value[3::2]) != AUDIT_FLAGS:
        raise QueryChildError("audit invocation flags are not frozen")
    if Path(value[0]).resolve(strict=True) != Path(sys.executable).resolve(
        strict=True
    ):
        raise QueryChildError("audit invocation Python is not current")
    script = Path(value[2]).resolve(strict=True)
    if script.name != "commodity_c_fast_l1_l5_audit.py":
        raise QueryChildError("audit invocation script is not frozen")
    return value


def child_environment() -> dict[str, str]:
    allowed = ("LANG", "LC_ALL", "PATH", "SSL_CERT_DIR", "SSL_CERT_FILE", "TZ")
    return {key: os.environ[key] for key in allowed if key in os.environ}


def verify_gate_binding(
    invocation: list[str],
    expected_raw_sha256: str,
    expected_canonical_sha256: str,
) -> None:
    expected_suffix = [
        GATE_HASH_FLAGS[0],
        expected_raw_sha256,
        GATE_HASH_FLAGS[1],
        expected_canonical_sha256,
    ]
    if invocation[-len(expected_suffix) :] != expected_suffix:
        raise QueryChildError(
            "audit invocation gate expectations are not bootstrap-bound"
        )
    invocation_core = invocation[: -len(expected_suffix)]
    try:
        index = invocation.index("--pre-connect-query-gate")
        gate_path = Path(invocation[index + 1])
    except (ValueError, IndexError) as exc:
        raise QueryChildError("audit invocation lacks query gate") from exc
    try:
        info = gate_path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise QueryChildError("query gate metadata is unsafe")
        raw = gate_path.read_bytes()
        payload = json.loads(raw, parse_constant=_reject_constant)
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QueryChildError("query gate is invalid") from exc
    if (
        hashlib.sha256(raw).hexdigest() != expected_raw_sha256
        or hashlib.sha256(canonical).hexdigest()
        != expected_canonical_sha256
    ):
        raise QueryChildError("query gate binding changed before exec")
    if not isinstance(payload, dict):
        raise QueryChildError("query gate is invalid")
    core_raw = json.dumps(
        invocation_core,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if (
        payload.get("audit_invocation_core_raw_sha256")
        != hashlib.sha256(core_raw).hexdigest()
        or payload.get("audit_invocation_core_canonical_sha256")
        != hashlib.sha256(core_raw).hexdigest()
    ):
        raise QueryChildError("audit invocation core binding changed before exec")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-invocation", type=Path, required=True)
    parser.add_argument("--expected-provenance-pin", required=True)
    parser.add_argument("--expected-t1-pin", required=True)
    parser.add_argument("--expected-query-v3-pin", required=True)
    parser.add_argument("--expected-l3-pin", required=True)
    parser.add_argument("--expected-outcome-pin", required=True)
    parser.add_argument("--expected-custody", required=True)
    parser.add_argument("--expected-gate-raw-sha256", required=True)
    parser.add_argument("--expected-gate-canonical-sha256", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        invocation = load_audit_invocation(args.audit_invocation)
        verify_gate_binding(
            invocation,
            args.expected_gate_raw_sha256,
            args.expected_gate_canonical_sha256,
        )
        verify_active_pins(
            {
                "provenance": args.expected_provenance_pin,
                "t1": args.expected_t1_pin,
                "query_v3": args.expected_query_v3_pin,
                "l3": args.expected_l3_pin,
                "outcome": args.expected_outcome_pin,
                "custody": args.expected_custody,
            }
        )
        os.execve(invocation[0], invocation, child_environment())
    except (OSError, QueryChildError) as exc:
        print(f"T1 query child blocked before network: {exc}", file=sys.stderr)
        return 78
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
