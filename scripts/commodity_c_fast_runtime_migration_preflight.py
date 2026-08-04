#!/usr/bin/env python3
"""Create-only preflight for explicit legacy COMPLETE → runtime migration.

The report is evidence only.  It never writes an Acceptance, Runtime
Authorization, enable event, order, position, or terminal archive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any


SESSION_RE = re.compile(r"^cfast-shakedown-[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _read_object(path: Path, label: str) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"{label}_FILE_INVALID")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label}_ROOT_INVALID")
    return payload


def _plan_checksum_valid(session: dict[str, Any]) -> bool:
    core = {
        key: value
        for key, value in session.items()
        if key
        not in {
            "schema_version",
            "plan_hash",
            "status",
            "started_by",
            "previewed_at_utc",
            "completed_at_utc",
            "execution",
            "terminal_checksum",
            "continuous_authorized",
        }
    }
    return bool(
        isinstance(session.get("plan_hash"), str)
        and sha256_json(core) == session.get("plan_hash")
    )


def _execution_checksum_valid(session: dict[str, Any]) -> bool:
    execution = session.get("execution")
    if not isinstance(execution, dict):
        return False
    checksum = execution.get("state_checksum")
    return bool(
        isinstance(checksum, str)
        and checksum
        == sha256_json(
            {key: value for key, value in execution.items() if key != "state_checksum"}
        )
    )


def _terminal_checksum_valid(session: dict[str, Any]) -> bool:
    execution = session.get("execution")
    expected = sha256_json(
        {
            "session_id": session.get("session_id"),
            "plan_hash": session.get("plan_hash"),
            "status": session.get("status"),
            "completed_at_utc": session.get("completed_at_utc"),
            "execution_state_checksum": (
                execution.get("state_checksum")
                if isinstance(execution, dict)
                else None
            ),
        }
    )
    return session.get("terminal_checksum") == expected


def _positions(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    try:
        return {
            str(key): int(quantity)
            for key, quantity in value.items()
            if int(quantity) != 0
        }
    except (TypeError, ValueError):
        return None


def _load_chain(archive_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    blockers: list[str] = []
    if not archive_dir.is_dir() or archive_dir.is_symlink():
        return [], ["ARCHIVE_DIR_INVALID"]
    rows: list[dict[str, Any]] = []
    for path in sorted(archive_dir.iterdir()):
        if path.name == ".terminal-archive.lock":
            continue
        if not path.name.endswith(".json") or not SESSION_RE.fullmatch(path.stem):
            blockers.append("ARCHIVE_UNKNOWN_ARTIFACT")
            continue
        try:
            session = _read_object(path, "ARCHIVE")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            blockers.append("ARCHIVE_READ_INVALID")
            continue
        if (
            session.get("session_id") != path.stem
            or not _plan_checksum_valid(session)
            or not _execution_checksum_valid(session)
            or not _terminal_checksum_valid(session)
        ):
            blockers.append("ARCHIVE_CHECKSUM_INVALID")
            continue
        rows.append(session)
    if blockers:
        return rows, sorted(set(blockers))
    by_previous: dict[str | None, list[dict[str, Any]]] = {}
    for row in rows:
        previous = row.get("previous_terminal_checksum")
        if previous is not None and not SHA256_RE.fullmatch(str(previous)):
            return rows, ["ARCHIVE_PREDECESSOR_INVALID"]
        by_previous.setdefault(previous, []).append(row)
    roots = by_previous.get(None, [])
    if len(roots) != 1:
        return rows, ["ARCHIVE_CHAIN_ROOT_INVALID"]
    ordered = [roots[0]]
    seen = {str(roots[0]["terminal_checksum"])}
    while True:
        children = by_previous.get(str(ordered[-1]["terminal_checksum"]), [])
        if not children:
            break
        if len(children) != 1:
            return rows, ["ARCHIVE_CHAIN_FORKED"]
        child = children[0]
        checksum = str(child["terminal_checksum"])
        if checksum in seen:
            return rows, ["ARCHIVE_CHAIN_CYCLE"]
        seen.add(checksum)
        ordered.append(child)
    if len(ordered) != len(rows):
        return rows, ["ARCHIVE_CHAIN_DISCONNECTED"]
    return ordered, []


def migration_preflight(
    *,
    terminal_pointer: dict[str, Any],
    archive_dir: Path,
    live_facts: dict[str, Any],
    expected_account_sha256: str,
) -> dict[str, Any]:
    blockers: list[str] = []
    chain, chain_blockers = _load_chain(archive_dir)
    blockers.extend(chain_blockers)
    if not SHA256_RE.fullmatch(expected_account_sha256):
        blockers.append("EXPECTED_ACCOUNT_INVALID")
    if (
        terminal_pointer.get("status") != "COMPLETE"
        or not _plan_checksum_valid(terminal_pointer)
        or not _execution_checksum_valid(terminal_pointer)
        or not _terminal_checksum_valid(terminal_pointer)
    ):
        blockers.append("TERMINAL_POINTER_INVALID")
    tail = chain[-1] if chain else None
    if tail is None or any(
        terminal_pointer.get(field) != tail.get(field)
        for field in (
            "session_id",
            "plan_hash",
            "terminal_checksum",
            "source_snapshot_hash",
        )
    ):
        blockers.append("TERMINAL_POINTER_NOT_CHAIN_TIP")
    observed_account = str(live_facts.get("account_sha256") or "")
    if (
        terminal_pointer.get("account_hash") != expected_account_sha256
        or observed_account != expected_account_sha256
    ):
        blockers.append("ACCOUNT_BINDING_MISMATCH")
    active_orders = live_facts.get("active_orders")
    if not isinstance(active_orders, list) or active_orders:
        blockers.append("ACTIVE_ORDERS_NOT_ZERO")
    execution = terminal_pointer.get("execution")
    reconciliation = (
        execution.get("reconciliation")
        if isinstance(execution, dict)
        else None
    )
    expected_positions = (
        reconciliation.get("expected_positions")
        if isinstance(reconciliation, dict)
        else None
    )
    archived_observed_positions = (
        reconciliation.get("observed_positions")
        if isinstance(reconciliation, dict)
        else None
    )
    observed_positions = live_facts.get("positions")
    normalized_expected = _positions(expected_positions)
    normalized_archived_observed = _positions(archived_observed_positions)
    normalized_observed = _positions(observed_positions)
    if (
        not isinstance(reconciliation, dict)
        or reconciliation.get("matched") is not True
        or reconciliation.get("active_order_ids") not in (None, [])
        or normalized_expected is None
        or normalized_archived_observed != normalized_expected
        or normalized_observed != normalized_expected
    ):
        blockers.append("POSITION_RECONCILIATION_MISMATCH")
    if not SHA256_RE.fullmatch(
        str(terminal_pointer.get("source_snapshot_hash") or "")
    ):
        blockers.append("SIGNED_TARGET_OWNERSHIP_MISSING")
    core = {
        "schema_version": "commodity_c_fast_runtime_migration_preflight_v1",
        "eligible": not blockers,
        "blockers": sorted(set(blockers)),
        "terminal_session_id": terminal_pointer.get("session_id"),
        "terminal_checksum": terminal_pointer.get("terminal_checksum"),
        "archive_chain_length": len(chain),
        "archive_chain_tip_terminal_checksum": (
            tail.get("terminal_checksum") if tail else None
        ),
        "source_snapshot_hash": terminal_pointer.get("source_snapshot_hash"),
        "expected_simnow_account_sha256": expected_account_sha256,
        "reconciled_positions": (
            dict(sorted(normalized_observed.items()))
            if normalized_observed is not None
            else None
        ),
        "active_orders_count": (
            len(active_orders) if isinstance(active_orders, list) else None
        ),
        "automatic_enable": False,
        "production_allowed": False,
        "live_allowed": False,
        "countable_forward": False,
    }
    return {**core, "report_sha256": sha256_json(core)}


def _publish(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        raw = canonical_json(payload) + b"\n"
        if os.write(descriptor, raw) != len(raw):
            raise OSError("short write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--terminal-pointer", type=Path, required=True)
    result.add_argument("--archive-dir", type=Path, required=True)
    result.add_argument("--live-facts", type=Path, required=True)
    result.add_argument("--expected-account-sha256", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    report = migration_preflight(
        terminal_pointer=_read_object(args.terminal_pointer, "TERMINAL_POINTER"),
        archive_dir=args.archive_dir,
        live_facts=_read_object(args.live_facts, "LIVE_FACTS"),
        expected_account_sha256=args.expected_account_sha256,
    )
    _publish(args.output, report)
    print(f"migration preflight report written create-only: {args.output}")
    print("Runtime Authorization was not enabled.")
    return 0 if report["eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
