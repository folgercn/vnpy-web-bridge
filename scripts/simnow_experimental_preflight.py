"""One-shot, read-only preflight for the isolated SIMNOW_EXPERIMENTAL lane.

This intentionally reuses the runner's validation and dry-run planner path.  It
does not publish custody artifacts, acquire a leader, create an Execution
command, or contact the Gateway directly.  A non-zero exit means an operator
can fix a local/runtime blocker before a SimNow window rather than discovering
it after an ``--execute`` invocation.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "backend", ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.control_execution_client import ExecutionClient, ExecutionClientError  # noqa: E402
from simnow_experimental_materialize_target import (  # noqa: E402
    ExperimentalTargetError,
    read_json_stable,
    validate_planner_bundle,
    validate_test_target_bundle_binding,
)
from simnow_experimental_run_once import ExperimentalRunError, preview_once  # noqa: E402


EXPECTED_UID_GID = 65532
REQUIRED_NEGATIVE_FLAGS = (
    "PRODUCTION",
    "LIVE_TRADING_AUTHORIZED",
    "COUNTABLE_FORWARD",
    "OFFICIAL_FORWARD_CLAIMED",
)


class PreflightStop(RuntimeError):
    """Typed no-mutation stop with a useful operator-facing category."""

    def __init__(self, category: str, reason: str) -> None:
        super().__init__(reason)
        self.category = category
        self.reason = reason


def _is_false(value: str) -> bool:
    return value.strip().lower() in {"0", "false", "no"}


def _is_true(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


def _require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise PreflightStop("env", f"{name} is unset")
    return value


def _check_runtime_identity() -> None:
    if (os.geteuid(), os.getegid()) != (EXPECTED_UID_GID, EXPECTED_UID_GID):
        raise PreflightStop(
            "runtime-identity",
            f"expected uid/gid {EXPECTED_UID_GID}:{EXPECTED_UID_GID}, "
            f"got {os.geteuid()}:{os.getegid()}",
        )


def _check_readonly_file(path: Path, *, label: str) -> None:
    try:
        if not path.is_file() or not os.access(path, os.R_OK):
            raise PreflightStop("mount", f"{label} is not readable: {path}")
        if os.access(path, os.W_OK):
            raise PreflightStop("mount", f"{label} is unexpectedly writable: {path}")
    except OSError as exc:
        raise PreflightStop("mount", f"{label} is unavailable: {path}") from exc


def _check_readonly_directory(path: Path, *, label: str) -> None:
    try:
        if not path.is_dir() or not os.access(path, os.R_OK | os.X_OK):
            raise PreflightStop("mount", f"{label} is not traversable: {path}")
        if os.access(path, os.W_OK):
            raise PreflightStop("mount", f"{label} is unexpectedly writable: {path}")
        # Listing verifies that a 0700 named-volume ancestor is actually
        # traversable by this runtime instead of deferring PermissionError to
        # the formal-quote reader.
        next(path.iterdir(), None)
    except OSError as exc:
        raise PreflightStop("mount", f"{label} is unavailable: {path}") from exc


def _check_environment() -> None:
    for name in REQUIRED_NEGATIVE_FLAGS:
        if not _is_false(_require_env(name)):
            raise PreflightStop("env", f"{name} must remain false")
    if not _is_true(_require_env("SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED")):
        raise PreflightStop("custody-config", "SIMNOW_TRUSTED_KEYLESS_CUSTODY_ENABLED is not true")
    _require_env("CONTROL_EXECUTION_SHARED_SECRET")
    _require_env("PHASE_C_CUSTODY_SHARED_SECRET")
    _require_env("CONTROL_EXECUTION_BASE_URL")
    _require_env("PHASE_C_EXECUTION_URL")
    _require_env("PHASE_C_EXECUTION_SHARED_SECRET")
    _require_env("PHASE_C_CUSTODY_URL")


def _probe_endpoint(url: str, *, label: str, headers: Mapping[str, str] | None = None) -> None:
    try:
        response = httpx.get(url, headers=headers, timeout=5.0)
    except httpx.HTTPError as exc:
        raise PreflightStop("endpoint", f"{label} is unreachable") from exc
    if response.status_code != 200:
        raise PreflightStop("endpoint", f"{label} returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise PreflightStop("endpoint", f"{label} returned non-JSON") from exc
    if not isinstance(payload, Mapping) or payload.get("status") not in {"ready", "ok"}:
        raise PreflightStop("endpoint", f"{label} is not ready")


def _check_endpoints() -> None:
    execution = _require_env("CONTROL_EXECUTION_BASE_URL").rstrip("/")
    custody = _require_env("PHASE_C_CUSTODY_URL").rstrip("/")
    secret = _require_env("CONTROL_EXECUTION_SHARED_SECRET")
    _probe_endpoint(
        f"{execution}/health/live",
        label="execution",
        headers={"X-Control-Execution-Secret": secret},
    )
    _probe_endpoint(f"{custody}/health/ready", label="custody")


async def _check_execution_state(execution: ExecutionClient) -> None:
    """Verify the existing no-work state without altering it."""

    try:
        status = (await execution.status()).as_dict()
    except ExecutionClientError as exc:
        raise PreflightStop("execution-state", "Execution status is unavailable") from exc
    reconciliation = status.get("reconciliation")
    plan = status.get("plan")
    authority = status.get("authority")
    if (
        status.get("lifecycle") != "READY"
        or not isinstance(plan, Mapping)
        or plan.get("state") != "IDLE"
        or not isinstance(authority, Mapping)
        or authority.get("state") != "DISABLED"
        or not isinstance(reconciliation, Mapping)
        or reconciliation.get("state") != "RECONCILED"
        or reconciliation.get("unknown_outcomes") != 0
        or status.get("send_intents") != []
    ):
        raise PreflightStop("execution-state", "Execution is not READY/IDLE/DISABLED/RECONCILED")


def _read_inputs(target_path: Path, bundle_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    _check_readonly_file(target_path, label="target")
    _check_readonly_file(bundle_path, label="monthly bundle")
    try:
        target = read_json_stable(target_path)
        bundle = validate_planner_bundle(read_json_stable(bundle_path))
        target = validate_test_target_bundle_binding(target, bundle)
    except (ExperimentalTargetError, OSError, ValueError, TypeError) as exc:
        raise PreflightStop("input", "target/monthly bundle validation failed") from exc
    return target, bundle


def _classify_preview_stop(exc: Exception) -> PreflightStop:
    message = str(exc) or exc.__class__.__name__
    if "broker facts" in message or "Execution fresh broker facts" in message:
        return PreflightStop("account-facts", message)
    if "formal bid/ask" in message:
        return PreflightStop("formal-quotes", message)
    return PreflightStop("dry-run", message)


async def run_preflight(
    *, target_path: Path, bundle_path: Path,
    market_state_dir: Path, market_projection_dir: Path,
    expires_at: str | None = None,
) -> dict[str, str]:
    """Run the complete no-mutation check once and return compact PASS facts."""

    _check_runtime_identity()
    _check_environment()
    _check_readonly_directory(market_state_dir, label="market-data")
    _check_readonly_directory(market_projection_dir, label="market-projection")
    target, bundle = _read_inputs(target_path, bundle_path)
    _check_endpoints()
    execution = ExecutionClient()
    await _check_execution_state(execution)
    try:
        result = await preview_once(
            target,
            bundle,
            execution=execution,
            formal_state_dir=market_state_dir,
            formal_projection_dir=market_projection_dir,
            expires_at=expires_at
            or (datetime.now(timezone.utc) + timedelta(minutes=5)).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z"),
        )
    except (ExperimentalRunError, ExecutionClientError) as exc:
        raise _classify_preview_stop(exc) from exc
    return {
        "uid": str(os.geteuid()),
        "mounts": "ok",
        "execution": "ready",
        "custody": "ready",
        "preview": str(result.get("status", "ok")),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--monthly-planner-bundle", type=Path, required=True)
    parser.add_argument("--market-state-dir", type=Path, default=Path("/run/market-data"))
    parser.add_argument(
        "--market-projection-dir", type=Path, default=Path("/run/market-projection")
    )
    parser.add_argument("--expires-at")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = asyncio.run(
            run_preflight(
                target_path=args.target,
                bundle_path=args.monthly_planner_bundle,
                market_state_dir=args.market_state_dir,
                market_projection_dir=args.market_projection_dir,
                expires_at=args.expires_at,
            )
        )
    except PreflightStop as exc:
        print(f"STOP {exc.category}={exc.reason}")
        return 1
    print("PASS " + " ".join(f"{key}={value}" for key, value in result.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
