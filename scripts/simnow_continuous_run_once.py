"""One config-only STATIC_CORE_EQUAL continuous SIMNOW control pass.

This is the R1 orchestration foundation for issue #362.  Its public seam takes
one root-managed configuration path.  Dynamic research/control values (day,
month, custody version, account facts, completion, clock and clients) are
resolved privately during the pass and cannot be supplied by a caller.

The production adapter is recovery-first: installed event and plan custody
roots are queried before any mutation, every first send requires fresh account
and formal-quote evidence, and response-loss paths only query the same
deterministic key.  Real mutation still requires the root-managed
``simnow_execution_enabled`` switch plus the external night-run gates.
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import hashlib
import json
import os
import stat
import sys
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "backend", ROOT / "scripts"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app.control_execution_client import (  # noqa: E402
    ExecutionClient,
    ExecutionClientError,
    ExecutionUnknownOutcomeError,
    ExecutionClientSettings,
)
from app.execution.full_account_ownership import (  # noqa: E402
    DesiredContinuousTargetBinding,
    ExpectedPredecessorCompletionBinding,
    ExpectedSameEventCloseCompletionBinding,
    FullAccountOwnershipDisposition,
    FullAccountPredecessorMode,
    classify_full_account_ownership,
    classify_same_event_close_completion,
)
from app.execution.gateway_contracts import GatewaySnapshot  # noqa: E402
from app.execution.executable_target_adapter import (  # noqa: E402
    StaticCoreEqualFullPortfolioPhaseHandoff,
    build_full_portfolio_quote_requests,
    build_static_core_equal_full_portfolio_keyless_decision,
)
from app.execution.formal_tick_reader import (  # noqa: E402
    read_simnow_continuous_v3_formal_tick_bindings,
)
from app.phase_c.adapters import UnknownOutcomeError  # noqa: E402
from app.phase_c.client import (  # noqa: E402
    PhaseCRemoteSettings,
    RemotePhaseCWorkflowClient,
)
from app.phase_c.models import (  # noqa: E402
    ContinuousEventHeadDTO,
    TrustedKeylessContinuousEventInstallContinuationDTO,
    TrustedKeylessContinuousEventUploadDTO,
    TrustedKeylessTargetPlanInstallContinuationDTO,
    TrustedKeylessTargetPlanUploadDTO,
)
from research_warehouse.continuous_event_selector import (  # noqa: E402
    BuiltContinuousEventSelection,
    MonthlyFinalTargetCandidate,
    TerminalPredecessorPinCandidate,
    build_continuous_event_candidate_selection,
)
from research_warehouse.daily_roll_predecessor_catalog import (  # noqa: E402
    CurrentCatalogHeadProof,
    DailyRollPredecessorCatalogError,
    load_current_catalog_head,
)
from research_warehouse.file_integrity import read_regular_strict  # noqa: E402
from research_warehouse.m2_isolation_contracts import false_authority  # noqa: E402
from research_warehouse.m2_runtime_loader import (  # noqa: E402
    load_runtime_context_readonly,
)
from research_warehouse.timeutil import format_utc, parse_utc  # noqa: E402
from research_warehouse.monthly_due_source import (  # noqa: E402
    MONTHLY_DUE,
    resolve_monthly_due_source,
)
from research_warehouse.verified_daily_pit_main_roll_source import (  # noqa: E402
    BuiltVerifiedDailyPitMainRollSource,
)
from research_warehouse.verified_monthly_final_target import (  # noqa: E402
    VerifiedMonthlyPlannerBundle,
    replay_verified_monthly_planner_bundle,
)
from shared.artifact_contracts.v1 import (  # noqa: E402
    new_artifact_envelope,
    validate_artifact_envelope,
)
from shared.commodity_execution import (  # noqa: E402
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    target_position_projection_hash,
)
from shared.phase_c_workflow import continuous_event_v1 as event_contract  # noqa: E402
from simnow_run_once import (  # noqa: E402
    _accepted_start_receipt,
    _command,
    _completed,
    _completion_state,
    _final_reconcile_completed,
    _submit_reconcile_with_ready_snapshot,
)


CONFIG_SCHEMA = "web-bridge-simnow-continuous-run-once-config-v1"
PHASE_KEY_DOMAIN = "web-bridge-simnow-continuous-phase-custody-v1"
_PHASES = ("CLOSE", "OPEN")
_EVENT_AUTHORITY_FIELDS = frozenset(
    {
        "account_data_read",
        "control_authorized",
        "deployment_authorized",
        "execution_authorized",
        "network_beyond_allowlist_authorized",
        "order_authorized",
        "permit_authorized",
        "position_mutation_authorized",
        "production_authorized",
        "rpc_authorized",
        "trading_authorized",
    }
)
_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "run_lock_path",
        "warehouse_runtime_input_path",
        "warehouse_runtime_input_raw_sha256",
        "warehouse_operator_state_path",
        "warehouse_history_receipt_path",
        "warehouse_history_receipt_raw_sha256",
        "warehouse_manifest_public_key_path",
        "warehouse_manifest_public_key_raw_sha256",
        "warehouse_signed_baseline_batch_path",
        "warehouse_business_public_key_path",
        "warehouse_business_public_key_raw_sha256",
        "warehouse_business_signer_key_id",
        "warehouse_contract_registry_path",
        "warehouse_contract_registry_raw_sha256",
        "warehouse_shfe_contract_parameters_path",
        "warehouse_shfe_contract_parameters_raw_sha256",
        "warehouse_shfe_contract_parameters_observed_at",
        "bootstrap_source_month",
        "bootstrap_execution_month",
        "bootstrap_static_core_equal_sha256",
        "bootstrap_position_manager_sha256",
        "bootstrap_final_target_sha256",
        "simnow_execution_enabled",
        "plan_expiry_seconds",
        "completion_timeout_seconds",
        "completion_poll_seconds",
        "phase_c_custody_url",
        "phase_c_execution_url",
        "phase_c_custody_shared_secret",
        "phase_c_execution_shared_secret",
        "execution_url",
        "execution_shared_secret",
        "leader_owner_id",
        "principal",
        "operator",
        "authority",
    }
)
_SHA = set("0123456789abcdef")


class ContinuousRunError(RuntimeError):
    """One pass cannot safely establish the next deterministic action."""


class ContinuousRunBusy(ContinuousRunError):
    """Another local pass holds the OS process lock."""


@dataclass(frozen=True, slots=True)
class _Config:
    raw: dict[str, Any]

    def path(self, field: str) -> Path:
        return Path(self.raw[field])


@dataclass(frozen=True, slots=True)
class _WarehouseResolution:
    root_fingerprint: str
    catalog: CurrentCatalogHeadProof
    planner: VerifiedMonthlyPlannerBundle | None
    selection: BuiltContinuousEventSelection


@dataclass(frozen=True, slots=True)
class _TerminalCompletion:
    recovery: dict[str, Any]
    completion: dict[str, Any]


class _Backend(Protocol):
    def event_head(self) -> ContinuousEventHeadDTO: ...

    def warehouse(self, head: ContinuousEventHeadDTO) -> _WarehouseResolution: ...

    async def recovery(self, key: str) -> dict[str, Any]: ...

    async def completion(self, plan_id: str) -> dict[str, Any] | None: ...

    async def account_facts(self) -> dict[str, Any]: ...

    def custody_version(self) -> int: ...

    def continue_event(self, head: ContinuousEventHeadDTO) -> None: ...

    def publish_event(self, artifact: dict[str, Any], *, version: int) -> None: ...

    def plan_adapter_ready(self) -> bool: ...

    async def advance_installed_event(
        self, *, event: dict[str, Any], phase_keys: Mapping[str, str]
    ) -> dict[str, Any]: ...


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _canonical_line(value: Any) -> bytes:
    return _canonical(value) + b"\n"


def _is_sha(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value).issubset(_SHA)


def _require_absolute_path(value: object, field: str) -> None:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise ContinuousRunError(f"{field} must be an absolute path")


def _stat_identity(value: os.stat_result | Any) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_uid),
        int(value.st_gid),
        int(value.st_mode),
        int(value.st_nlink),
        int(value.st_size),
    )


def _require_root_managed(path: Path) -> bytes:
    path = Path(path)
    if not path.is_absolute():
        raise ContinuousRunError("continuous runner config path must be absolute")
    try:
        parent = path.parent.lstat()
        info = path.lstat()
    except OSError as exc:
        raise ContinuousRunError("continuous runner config is unavailable") from exc
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or parent.st_uid != os.geteuid()
        or info.st_uid != os.geteuid()
        or parent.st_gid != os.getegid()
        or info.st_gid != os.getegid()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or info.st_size < 2
        or info.st_size > 64 * 1024
    ):
        raise ContinuousRunError(
            "continuous runner config must be service-owned private 0700/0600"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(info):
            raise ContinuousRunError("continuous runner config changed while opening")
        raw = os.read(descriptor, info.st_size + 1)
        after = os.fstat(descriptor)
        try:
            named = path.lstat()
            parent_after = path.parent.lstat()
        except OSError as exc:
            raise ContinuousRunError(
                "continuous runner config changed while reading"
            ) from exc
        if (
            len(raw) != info.st_size
            or _stat_identity(after) != _stat_identity(info)
            or _stat_identity(named) != _stat_identity(info)
            or _stat_identity(parent_after) != _stat_identity(parent)
        ):
            raise ContinuousRunError("continuous runner config changed while reading")
        return raw
    except OSError as exc:
        raise ContinuousRunError("continuous runner config cannot be read") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_config(path: Path) -> _Config:
    raw = _require_root_managed(Path(path))
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContinuousRunError("continuous runner config is invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != _CONFIG_FIELDS
        or value.get("schema_version") != CONFIG_SCHEMA
        or _canonical_line(value) != raw
        or value.get("authority") != false_authority()
    ):
        raise ContinuousRunError("continuous runner config contract mismatch")
    for field in (
        "run_lock_path",
        "warehouse_runtime_input_path",
        "warehouse_operator_state_path",
        "warehouse_history_receipt_path",
        "warehouse_manifest_public_key_path",
        "warehouse_signed_baseline_batch_path",
        "warehouse_business_public_key_path",
        "warehouse_contract_registry_path",
        "warehouse_shfe_contract_parameters_path",
    ):
        _require_absolute_path(value[field], field)
    for field in (
        "warehouse_manifest_public_key_raw_sha256",
        "warehouse_runtime_input_raw_sha256",
        "warehouse_history_receipt_raw_sha256",
        "warehouse_business_public_key_raw_sha256",
        "warehouse_contract_registry_raw_sha256",
        "warehouse_shfe_contract_parameters_raw_sha256",
        "bootstrap_static_core_equal_sha256",
        "bootstrap_position_manager_sha256",
        "bootstrap_final_target_sha256",
    ):
        if not _is_sha(value[field]):
            raise ContinuousRunError(f"{field} is invalid")
    for field in ("bootstrap_source_month", "bootstrap_execution_month"):
        candidate = value[field]
        try:
            parsed = datetime.fromisoformat(f"{candidate}-01T00:00:00+00:00")
        except (TypeError, ValueError) as exc:
            raise ContinuousRunError(f"{field} is invalid") from exc
        if parsed.strftime("%Y-%m") != candidate:
            raise ContinuousRunError(f"{field} is invalid")
    observed_at = value["warehouse_shfe_contract_parameters_observed_at"]
    if not isinstance(observed_at, str):
        raise ContinuousRunError("warehouse_shfe_contract_parameters_observed_at is invalid")
    try:
        parsed_observed_at = parse_utc(
            observed_at, "warehouse_shfe_contract_parameters_observed_at"
        )
    except (TypeError, ValueError) as exc:
        raise ContinuousRunError(
            "warehouse_shfe_contract_parameters_observed_at is invalid"
        ) from exc
    if format_utc(
        parsed_observed_at, "warehouse_shfe_contract_parameters_observed_at"
    ) != observed_at:
        raise ContinuousRunError("warehouse_shfe_contract_parameters_observed_at is invalid")
    if type(value["simnow_execution_enabled"]) is not bool:
        raise ContinuousRunError("simnow_execution_enabled is invalid")
    for field, minimum, maximum in (
        ("plan_expiry_seconds", 10, 600),
        ("completion_timeout_seconds", 10, 3600),
        ("completion_poll_seconds", 0.1, 10),
    ):
        candidate = value[field]
        if (
            isinstance(candidate, bool)
            or not isinstance(candidate, (int, float))
            or not minimum <= float(candidate) <= maximum
        ):
            raise ContinuousRunError(f"{field} is invalid")
    for field in (
        "phase_c_custody_url",
        "phase_c_execution_url",
        "phase_c_custody_shared_secret",
        "phase_c_execution_shared_secret",
        "execution_url",
        "execution_shared_secret",
        "leader_owner_id",
        "principal",
        "operator",
        "warehouse_business_signer_key_id",
    ):
        if not isinstance(value[field], str) or not value[field]:
            raise ContinuousRunError(f"{field} is invalid")
    if (
        value["phase_c_custody_url"] != "http://artifact-custody:8091"
        or value["phase_c_execution_url"] != "http://execution-orchestrator:8090"
        or value["execution_url"] != "http://execution-orchestrator:8090"
        or value["leader_owner_id"] != "simnow-continuous-runner-issue362"
        or value["principal"] != "control-api"
        or value["operator"] != "simnow-continuous-runner"
    ):
        raise ContinuousRunError("continuous runner private identity is invalid")
    return _Config(dict(value))


@contextmanager
def _one_process(lock_path: Path):
    """Take an existing private lock file without creating runtime state."""

    lock_path = Path(lock_path)
    if not lock_path.is_absolute():
        raise ContinuousRunError("continuous runner lock path must be absolute")
    descriptor = -1
    try:
        parent = lock_path.parent.lstat()
        info = lock_path.lstat()
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or parent.st_uid != os.geteuid()
            or info.st_uid != os.geteuid()
            or parent.st_gid != os.getegid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(parent.st_mode) != 0o700
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ContinuousRunError("continuous runner lock is unsafe")
        descriptor = os.open(
            lock_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        if _stat_identity(os.fstat(descriptor)) != _stat_identity(info):
            raise ContinuousRunError("continuous runner lock changed while opening")
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ContinuousRunError("continuous runner lock is unavailable") from exc
    except ContinuousRunError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ContinuousRunBusy("continuous runner is already active") from exc
        try:
            named = lock_path.lstat()
            parent_after = lock_path.parent.lstat()
        except OSError as exc:
            raise ContinuousRunError("continuous runner lock changed") from exc
        if _stat_identity(named) != _stat_identity(info) or _stat_identity(
            parent_after
        ) != _stat_identity(parent):
            raise ContinuousRunError("continuous runner lock changed")
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _phase_key(event_id: str, phase: str) -> str:
    if phase not in _PHASES or not isinstance(event_id, str) or not event_id:
        raise ContinuousRunError("continuous phase identity is invalid")
    return _sha256(
        _canonical(
            {
                "domain": PHASE_KEY_DOMAIN,
                "event_id": event_id,
                "phase": phase,
            }
        )
    )


def _execution_run_id(event_id: str, expected_phase: str | None) -> str:
    if expected_phase not in {None, *_PHASES}:
        raise ContinuousRunError("continuous execution phase is invalid")
    return (
        "continuous-run-"
        + _sha256(
            _canonical(
                {
                    "domain": "web-bridge-simnow-continuous-execution-run-v1",
                    "event_id": event_id,
                    "expected_phase": expected_phase,
                }
            )
        )[:48]
    )


def _head_fingerprint(head: ContinuousEventHeadDTO) -> str:
    value = head.model_dump(
        mode="json",
        exclude={"request_nonce", "head_sha256", "custody_hmac_sha256"},
    )
    return _sha256(_canonical(value))


def _completion_matches_recovery(
    completion: Mapping[str, Any], recovery: Mapping[str, Any]
) -> bool:
    common = {
        "plan_id": "plan_id",
        "plan_hash": "plan_hash",
        "phase": "phase",
        "expected_after_position_hash": "expected_after_position_hash",
    }
    if any(
        completion.get(left) != recovery.get(right) for left, right in common.items()
    ):
        return False
    if completion.get("target_position_hash") != recovery.get(
        "expected_after_position_hash"
    ) or completion.get("lineage") != recovery.get("lineage"):
        return False
    if recovery.get("schema_version") == "web_bridge_execution_target_plan_recovery_v3":
        return all(
            completion.get(field) == recovery.get(field)
            for field in (
                "execution_run_id",
                "creation_quote_proof_sha256",
                "start_quote_proof_sha256",
            )
        )
    return True


async def _terminal_completion(
    backend: _Backend, *, event_id: str
) -> tuple[_TerminalCompletion | None, dict[str, str], str | None]:
    """Resolve the terminal plan by deterministic event/phase keys only."""

    keys = {phase: _phase_key(event_id, phase) for phase in _PHASES}
    completed: dict[str, _TerminalCompletion] = {}
    pending: dict[str, str] = {}
    for phase in _PHASES:
        recovery = await backend.recovery(keys[phase])
        if recovery.get("custody_idempotency_key") != keys[phase]:
            raise ContinuousRunError("foreign target-plan recovery projection")
        state = recovery.get("state")
        if state == "BEFORE_CUSTODY":
            pending[phase] = "BEFORE_CUSTODY"
            continue
        if recovery.get("phase") != phase:
            raise ContinuousRunError("target-plan recovery phase mismatches key")
        if state == "CUSTODY_PUBLISHED_NOT_INSTALLED":
            pending[phase] = f"{phase}_PUBLISHED_NOT_INSTALLED"
            continue
        if state not in {"CUSTODY_PUBLISHED_NOT_PREVIEWED", "INSTALLED"}:
            raise ContinuousRunError("target-plan recovery state is invalid")
        plan_id = recovery.get("plan_id")
        if not isinstance(plan_id, str) or not plan_id:
            raise ContinuousRunError("target-plan recovery lacks exact plan identity")
        completion = await backend.completion(plan_id)
        if completion is None:
            pending[phase] = f"{phase}_ACTIVE_OR_NOT_STARTED"
            continue
        if not _completion_matches_recovery(completion, recovery):
            raise ContinuousRunError("foreign execution completion projection")
        completed[phase] = _TerminalCompletion(dict(recovery), dict(completion))
    if "OPEN" in completed:
        if pending.get("CLOSE") not in {None, "BEFORE_CUSTODY"}:
            raise ContinuousRunError(
                "OPEN completion conflicts with unfinished CLOSE recovery"
            )
        return completed["OPEN"], keys, None
    # Once an OPEN custody root exists, CLOSE can no longer represent the
    # event's terminal boundary.  ACTIVE/unknown OPEN is query-only and must
    # never be collapsed back to an older CLOSE completion.
    if pending.get("OPEN") != "BEFORE_CUSTODY":
        return None, keys, pending.get("OPEN", "OPEN_RECOVERY_INVALID")
    if "CLOSE" in completed:
        return completed["CLOSE"], keys, None
    return None, keys, pending.get("CLOSE", "PRIOR_EVENT_PHASE_MISSING")


def _require_terminal_closes_head(
    head: ContinuousEventHeadDTO, terminal: _TerminalCompletion
) -> None:
    """Bind an exact completion back to the installed event it closes."""

    current = head.current_event
    if head.state != "INSTALLED" or current is None:
        raise ContinuousRunError("completion predecessor lacks installed event root")
    completion = terminal.completion
    recovery = terminal.recovery
    payload = current.artifact["payload"]
    monthly = payload["monthly"]
    phase = completion.get("phase")
    if (
        phase not in _PHASES
        or recovery.get("custody_idempotency_key")
        != _phase_key(current.idempotency_key, str(phase))
        or not _completion_matches_recovery(completion, recovery)
        or completion.get("target_position_hash")
        != payload["desired_target"]["target_position_hash"]
        or completion.get("lineage")
        != {
            "static_core_equal_sha256": monthly["static_core_equal_sha256"],
            "position_manager_sha256": monthly["position_manager_sha256"],
            "final_target_sha256": monthly["final_target_sha256"],
        }
    ):
        raise ContinuousRunError(
            "terminal completion does not close the installed event root"
        )


def _require_intermediate_close_binds_head(
    head: ContinuousEventHeadDTO, terminal: _TerminalCompletion
) -> None:
    current = head.current_event
    if head.state != "INSTALLED" or current is None:
        raise ContinuousRunError("intermediate CLOSE lacks installed event root")
    payload = current.artifact["payload"]
    monthly = payload["monthly"]
    if (
        terminal.completion.get("phase") != "CLOSE"
        or terminal.recovery.get("custody_idempotency_key")
        != _phase_key(current.idempotency_key, "CLOSE")
        or not _completion_matches_recovery(terminal.completion, terminal.recovery)
        or terminal.completion.get("lineage")
        != {
            "static_core_equal_sha256": monthly["static_core_equal_sha256"],
            "position_manager_sha256": monthly["position_manager_sha256"],
            "final_target_sha256": monthly["final_target_sha256"],
        }
    ):
        raise ContinuousRunError(
            "intermediate CLOSE does not bind the installed event root"
        )


def _target_positions(candidate: Mapping[str, Any]) -> dict[str, Any]:
    positions: dict[str, Any] = {}
    for row in candidate["targets"]:
        quantity = row["target_quantity"]
        if not quantity:
            continue
        exchange, symbol = row["exact_contract"].split(".")
        direction = "LONG" if quantity > 0 else "SHORT"
        positions[f"{symbol}.{exchange}.{direction}.CTP.continuous-target-v1"] = {
            "gateway_name": "CTP",
            "symbol": symbol,
            "exchange": exchange,
            "direction": direction,
            "volume": abs(quantity),
        }
    return positions


def _desired_binding(resolved: _WarehouseResolution) -> DesiredContinuousTargetBinding:
    selection = resolved.selection
    planner = resolved.planner
    if selection.event_candidate_raw is None or planner is None:
        raise ContinuousRunError("ownership classification lacks selected event")
    final = planner.final_target
    return DesiredContinuousTargetBinding(
        event_id=str(selection.event_candidate_id),
        source_event_raw=selection.event_candidate_raw,
        source_event_raw_sha256=_sha256(selection.event_candidate_raw),
        selection_sha256=selection.selection_sha256,
        final_target_raw=final.final_target_raw,
        final_target_sha256=final.final_target_sha256,
        static_core_equal_sha256=final.static_core_equal_sha256,
        position_manager_sha256=final.position_manager_sha256,
        lineage_final_target_sha256=final.final_target_sha256,
    )


def _installed_desired_binding(
    predecessor_head: ContinuousEventHeadDTO,
) -> DesiredContinuousTargetBinding:
    current = predecessor_head.current_event
    if predecessor_head.state != "INSTALLED" or current is None:
        raise ContinuousRunError("ownership predecessor lacks installed event")
    payload = current.artifact["payload"]
    monthly = payload["monthly"]
    source_event_raw = payload["source_event_raw"].encode()
    return DesiredContinuousTargetBinding(
        event_id=payload["event_id"],
        source_event_raw=source_event_raw,
        source_event_raw_sha256=payload["source_event_raw_sha256"],
        selection_sha256=payload["selection_sha256"],
        final_target_raw=monthly["final_target_raw"].encode(),
        final_target_sha256=monthly["final_target_sha256"],
        static_core_equal_sha256=monthly["static_core_equal_sha256"],
        position_manager_sha256=monthly["position_manager_sha256"],
        lineage_final_target_sha256=monthly["final_target_sha256"],
    )


def _event_desired_binding(event: Mapping[str, Any]) -> DesiredContinuousTargetBinding:
    payload = event["payload"]
    monthly = payload["monthly"]
    source_event_raw = payload["source_event_raw"].encode()
    return DesiredContinuousTargetBinding(
        event_id=payload["event_id"],
        source_event_raw=source_event_raw,
        source_event_raw_sha256=payload["source_event_raw_sha256"],
        selection_sha256=payload["selection_sha256"],
        final_target_raw=monthly["final_target_raw"].encode(),
        final_target_sha256=monthly["final_target_sha256"],
        static_core_equal_sha256=monthly["static_core_equal_sha256"],
        position_manager_sha256=monthly["position_manager_sha256"],
        lineage_final_target_sha256=monthly["final_target_sha256"],
    )


def _expected_predecessor_binding(
    predecessor_head: ContinuousEventHeadDTO,
    predecessor: _TerminalCompletion,
) -> ExpectedPredecessorCompletionBinding:
    current = predecessor_head.current_event
    if predecessor_head.state != "INSTALLED" or current is None:
        raise ContinuousRunError("ownership predecessor lacks installed event")
    recovery = predecessor.recovery
    lineage = recovery["lineage"]
    return ExpectedPredecessorCompletionBinding(
        canonical_completion_sha256=_sha256(_canonical(predecessor.completion)),
        plan_id=recovery["plan_id"],
        plan_hash=recovery["plan_hash"],
        phase=recovery["phase"],
        static_core_equal_sha256=lineage["static_core_equal_sha256"],
        position_manager_sha256=lineage["position_manager_sha256"],
        final_target_sha256=lineage["final_target_sha256"],
        target_position_hash=recovery["expected_after_position_hash"],
        terminal_target_id=current.idempotency_key,
        terminal_target_raw_sha256=current.artifact_raw_sha256,
    )


def _classify_prior_close_ownership(
    *,
    facts: Mapping[str, Any],
    predecessor_head: ContinuousEventHeadDTO,
    predecessor: _TerminalCompletion,
):
    """Prove a CLOSE completed the installed prior event, not the next event."""

    if predecessor.completion.get("phase") != "CLOSE":
        raise ContinuousRunError("prior CLOSE classifier received another phase")
    return classify_full_account_ownership(
        account_facts=facts,
        predecessor_mode=FullAccountPredecessorMode.COMPLETION,
        expected_predecessor=_expected_predecessor_binding(
            predecessor_head, predecessor
        ),
        completion=predecessor.completion,
        desired_target=_installed_desired_binding(predecessor_head),
        now=datetime.now(timezone.utc),
    )


def _classify_ownership(
    *,
    resolved: _WarehouseResolution,
    facts: Mapping[str, Any],
    predecessor_head: ContinuousEventHeadDTO,
    predecessor: _TerminalCompletion | None,
):
    """Apply the real full-account classifier to resolver-owned evidence."""

    desired = _desired_binding(resolved)
    expected = None
    completion = None
    mode = FullAccountPredecessorMode.GENESIS_FLAT
    if predecessor is not None:
        completion = predecessor.completion
        expected = _expected_predecessor_binding(predecessor_head, predecessor)
        mode = FullAccountPredecessorMode.COMPLETION
    return classify_full_account_ownership(
        account_facts=facts,
        predecessor_mode=mode,
        expected_predecessor=expected,
        completion=completion,
        desired_target=desired,
        now=datetime.now(timezone.utc),
    )


def _assemble_verified_event(
    *,
    resolved: _WarehouseResolution,
    facts: Mapping[str, Any],
    predecessor_head: ContinuousEventHeadDTO,
    predecessor: _TerminalCompletion | None,
) -> dict[str, Any]:
    """Privately close root replay, exact completion and fresh account facts."""

    selection = resolved.selection
    planner = resolved.planner
    if selection.event_candidate_raw is None or planner is None:
        raise ContinuousRunError("no selected event can be assembled")
    source_event_raw = selection.event_candidate_raw
    source_event = json.loads(source_event_raw)
    candidate = source_event["candidate"]
    selection_raw = selection.selection_raw
    final = planner.final_target
    daily = json.loads(resolved.catalog.artifact_raw)
    facts_raw = _canonical_line(dict(facts))
    observed_at = str(facts.get("observed_at", ""))
    if not observed_at.endswith("Z"):
        raise ContinuousRunError("account facts observed_at is not explicit UTC")
    # The fresh account snapshot is the final non-repeatable input.  Root event
    # bytes must remain identical across a response-loss retry of that snapshot.
    verified_at = observed_at
    desired_hash = target_position_projection_hash(
        _target_positions(candidate),
        account_scope="account:windows",
        environment="SIMNOW",
    )

    if predecessor is None:
        predecessor_payload = {
            "mode": "GENESIS_FLAT",
            "completion_raw": None,
            "completion_raw_sha256": None,
            "completion_plan_id": None,
            "completion_plan_hash": None,
            "completion_phase": None,
            "completion_target_position_hash": None,
            "terminal_target_id": None,
            "terminal_target_raw_sha256": None,
            "static_core_equal_sha256": None,
            "position_manager_sha256": None,
            "final_target_sha256": None,
        }
    else:
        _require_terminal_closes_head(predecessor_head, predecessor)
        completion = predecessor.completion
        prior_event = predecessor_head.current_event
        assert prior_event is not None
        if candidate["trigger_kind"] == "ROLL_ONLY" and (
            candidate["predecessor_terminal_target_id"] != prior_event.idempotency_key
            or candidate["predecessor_terminal_target_raw_sha256"]
            != prior_event.artifact_raw_sha256
        ):
            raise ContinuousRunError("ROLL predecessor terminal root mismatches")
        completion_raw = _canonical_line(completion)
        lineage = completion["lineage"]
        predecessor_payload = {
            "mode": "COMPLETION",
            "completion_raw": completion_raw.decode(),
            "completion_raw_sha256": _sha256(completion_raw),
            "completion_plan_id": completion["plan_id"],
            "completion_plan_hash": completion["plan_hash"],
            "completion_phase": completion["phase"],
            "completion_target_position_hash": completion["target_position_hash"],
            "terminal_target_id": prior_event.idempotency_key,
            "terminal_target_raw_sha256": (prior_event.artifact_raw_sha256),
            "static_core_equal_sha256": lineage["static_core_equal_sha256"],
            "position_manager_sha256": lineage["position_manager_sha256"],
            "final_target_sha256": lineage["final_target_sha256"],
        }

    payload = {
        "schema_version": event_contract.CONTINUOUS_EVENT_SCHEMA_VERSION,
        "event_id": source_event["event_id"],
        "source_event_raw": source_event_raw.decode(),
        "source_event_raw_sha256": _sha256(source_event_raw),
        "selection_id": selection.selection_id,
        "selection_sha256": selection.selection_sha256,
        "selection_raw": selection_raw.decode(),
        "selection_raw_sha256": _sha256(selection_raw),
        "candidate_id": candidate["candidate_id"],
        "trigger_kind": candidate["trigger_kind"],
        "strategy_id": "STATIC_CORE_EQUAL",
        "execution_lane": "simnow_shakedown",
        "precedence_rule_id": event_contract.PRECEDENCE_RULE_ID,
        "monthly_precedence_applied": json.loads(selection_raw)[
            "monthly_precedence_applied"
        ],
        "verified_at": verified_at,
        "monthly": {
            "final_target_raw": final.final_target_raw.decode(),
            "final_target_raw_sha256": final.final_target_raw_sha256,
            "final_target_sha256": final.final_target_sha256,
            "static_core_equal_sha256": final.static_core_equal_sha256,
            "position_manager_sha256": final.position_manager_sha256,
            "baseline_batch_raw_sha256": final.baseline_batch_raw_sha256,
            "source_month": final.source_month,
            "execution_day": final.execution_day,
            "quantity_vector_sha256": final.quantity_vector_sha256,
            "monthly_exact_contract_map_sha256": (
                final.monthly_exact_contract_map_sha256
            ),
        },
        "daily": {
            "artifact_id": daily["artifact_id"],
            "artifact_raw_sha256": resolved.catalog.artifact_raw_sha256,
            "official_day": daily["official_day"],
            "execution_day": daily["execution_day"],
            "continuity_mode": daily["verified_lineage"]["continuity"]["mode"],
            "previous_exact_contract_map_sha256": candidate[
                "previous_exact_contract_map_sha256"
            ],
            "exact_contract_map_sha256": candidate["exact_contract_map_sha256"],
            "catalog_receipt_raw_sha256": resolved.catalog.receipt_raw_sha256,
            "catalog_artifact_raw_sha256": resolved.catalog.artifact_raw_sha256,
            "operator_state_raw_sha256": resolved.catalog.operator_state_raw_sha256,
            "operator_manifest_sequence": (resolved.catalog.operator_manifest_sequence),
            "manifest_genesis_seal_sha256": (
                resolved.catalog.manifest_genesis_seal_sha256
            ),
            "manifest_head_seal_sha256": (resolved.catalog.manifest_head_seal_sha256),
            "manifest_head_commit_seal_sha256": (
                resolved.catalog.manifest_head_commit_seal_sha256
            ),
            "commit_anchor_ledger_raw_sha256": (
                resolved.catalog.commit_anchor_ledger_raw_sha256
            ),
            "catalog_last_trade_day": resolved.catalog.last_trade_day,
        },
        "desired_target": {
            "target_position_hash": desired_hash,
            "quantity_vector_sha256": candidate["quantity_vector_sha256"],
            "exact_contract_map_sha256": candidate["exact_contract_map_sha256"],
        },
        "account_facts": {
            "account_facts_raw": facts_raw.decode(),
            "account_facts_raw_sha256": _sha256(facts_raw),
            "snapshot_id": facts["snapshot_id"],
            "account_facts_sha256": facts["account_facts_sha256"],
            "observed_at": facts["observed_at"],
            "state_version": facts["execution_binding"]["state_version"],
            "position_snapshot_hash": facts["position_snapshot_hash"],
            "current_target_position_hash": target_position_projection_hash(
                facts["positions"],
                account_scope="account:windows",
                environment="SIMNOW",
            ),
            "active_order_count": facts["active_order_count"],
            "active_orders_sha256": facts["active_orders_sha256"],
            "lifecycle": facts["status_binding"]["lifecycle"],
            "reconciliation_state": facts["status_binding"]["reconciliation"]["state"],
            "unknown_outcomes": facts["status_binding"]["reconciliation"][
                "unknown_outcomes"
            ],
            "plan_state": facts["execution_binding"]["plan_state"],
            "nonterminal_send_intent_count": facts["execution_binding"][
                "nonterminal_send_intent_count"
            ],
        },
        "predecessor": predecessor_payload,
        "event_ready": True,
        "installable": True,
        "production_allowed": False,
        "live_trading_authorized": False,
        "countable_forward": False,
        "official_forward_claimed": False,
        "target_plan_authorized": False,
        "dispatch_authorized": False,
        "order_authorized": False,
        "position_mutation_authorized": False,
        "authority": {field: False for field in _EVENT_AUTHORITY_FIELDS},
    }
    event_contract.validate_simnow_continuous_event_v1(payload)
    artifact = new_artifact_envelope(
        artifact_type=event_contract.CONTINUOUS_EVENT_ARTIFACT_TYPE,
        trust_domain=event_contract.CONTINUOUS_EVENT_TRUST_DOMAIN,
        producer_id="simnow-continuous-run-once",
        producer_version="r1",
        schema_ref=event_contract.CONTINUOUS_EVENT_SCHEMA_VERSION,
        payload=payload,
        generated_at=verified_at,
        scope=event_contract.CONTINUOUS_EVENT_SCOPE,
        predecessor_refs=[],
        lineage=[],
    )
    validate_artifact_envelope(artifact)
    return artifact


async def _run_locked(backend: _Backend) -> dict[str, Any]:
    h0 = backend.event_head()
    h0_fingerprint = _head_fingerprint(h0)
    if h0.state == "PUBLISHED_NOT_INSTALLED":
        if not backend.plan_adapter_ready():
            return {
                "status": "STOP",
                "reason": "INSTALLED_EVENT_PLAN_ADAPTER_UNAVAILABLE",
                "custody_mutated": False,
                "leader_mutated": False,
                "execution_mutated": False,
                "gateway_mutated": False,
            }
        try:
            backend.continue_event(h0)
        except UnknownOutcomeError:
            recovered = backend.event_head()
            if (
                recovered.state != "INSTALLED"
                or recovered.current_event is None
                or h0.current_event is None
                or recovered.current_event.idempotency_key
                != h0.current_event.idempotency_key
                or recovered.current_event.artifact != h0.current_event.artifact
            ):
                raise ContinuousRunError("event continuation outcome is unknown")
        else:
            recovered = backend.event_head()
            if (
                recovered.state != "INSTALLED"
                or recovered.current_event is None
                or h0.current_event is None
                or recovered.current_event.idempotency_key
                != h0.current_event.idempotency_key
                or recovered.current_event.artifact != h0.current_event.artifact
            ):
                raise ContinuousRunError("event continuation readback mismatches")
        return {
            "status": "EVENT_STORED_CONTINUATION",
            "custody_mutated": True,
            "custody_mutation": "INSTALL_ONLY",
            "leader_mutated": False,
            "execution_mutated": False,
            "gateway_mutated": False,
        }

    try:
        r0 = backend.warehouse(h0)
    except DailyRollPredecessorCatalogError as exc:
        if (
            str(exc) != "daily roll predecessor catalog is empty"
            or h0.state != "NO_EVENT"
            or h0.current_event is not None
        ):
            raise
        h1 = backend.event_head()
        if _head_fingerprint(h1) != h0_fingerprint:
            raise ContinuousRunError("NO_EVENT custody root drifted before catalog")
        return {
            "status": "NO_EVENT",
            "custody_mutated": False,
            "leader_mutated": False,
            "execution_mutated": False,
            "gateway_mutated": False,
        }
    terminal: _TerminalCompletion | None = None
    if h0.current_event is not None:
        terminal, _prior_keys, active = await _terminal_completion(
            backend, event_id=h0.current_event.idempotency_key
        )
        if terminal is None:
            lifecycle = await backend.advance_installed_event(
                event=h0.current_event.artifact,
                phase_keys=_prior_keys,
            )
            return {
                "status": "PRIOR_EVENT_ADVANCED",
                "reason": active or "PRIOR_EVENT_PHASE_MISSING",
                "lifecycle": lifecycle,
            }
        if (
            terminal.completion.get("phase") == "CLOSE"
            and terminal.completion.get("target_position_hash")
            != h0.current_event.artifact["payload"]["desired_target"][
                "target_position_hash"
            ]
        ):
            _require_intermediate_close_binds_head(h0, terminal)
            lifecycle = await backend.advance_installed_event(
                event=h0.current_event.artifact,
                phase_keys=_prior_keys,
            )
            return {
                "status": "PRIOR_EVENT_ADVANCED_AFTER_CLOSE",
                "lifecycle": lifecycle,
            }
        _require_terminal_closes_head(h0, terminal)
    if r0.selection.event_candidate_raw is None:
        r1 = backend.warehouse(h0)
        h1 = backend.event_head()
        if (
            r1.root_fingerprint != r0.root_fingerprint
            or _head_fingerprint(h1) != h0_fingerprint
        ):
            raise ContinuousRunError("NO_EVENT roots drifted during classification")
        return {
            "status": "NO_EVENT",
            "custody_mutated": False,
            "leader_mutated": False,
            "execution_mutated": False,
            "gateway_mutated": False,
        }

    phase_keys = {
        phase: _phase_key(r0.selection.event_candidate_id or "", phase)
        for phase in _PHASES
    }

    # Account facts are deliberately the last non-repeatable business read.
    facts = await backend.account_facts()
    r1 = backend.warehouse(h0)
    h1 = backend.event_head()
    if (
        r1.root_fingerprint != r0.root_fingerprint
        or _head_fingerprint(h1) != h0_fingerprint
    ):
        raise ContinuousRunError("continuous event roots drifted before publication")
    artifact: dict[str, Any]
    if terminal is not None and terminal.completion.get("phase") == "CLOSE":
        prior_ownership = _classify_prior_close_ownership(
            facts=facts,
            predecessor_head=h0,
            predecessor=terminal,
        )
        if (
            prior_ownership.disposition
            is not FullAccountOwnershipDisposition.ALREADY_COMPLETED_MATCHED
            or prior_ownership.reason_code.value
            != "CLOSE_COMPLETION_TARGET_ALREADY_SATISFIED"
        ):
            raise ContinuousRunError(
                f"prior CLOSE ownership stopped: {prior_ownership.reason_code.value}"
            )
        current = h0.current_event
        if (
            current is None
            or r0.selection.event_candidate_id == current.idempotency_key
        ):
            return {
                "status": "NOOP",
                "reason": "PRIOR_CLOSE_EVENT_ALREADY_TERMINAL",
                "custody_mutated": False,
                "leader_mutated": False,
                "execution_mutated": False,
                "gateway_mutated": False,
            }
        artifact = _assemble_verified_event(
            resolved=r0,
            facts=facts,
            predecessor_head=h0,
            predecessor=terminal,
        )
        assembled_payload = artifact["payload"]
        if (
            assembled_payload["desired_target"]["target_position_hash"]
            == assembled_payload["account_facts"]["current_target_position_hash"]
        ):
            return {
                "status": "NOOP",
                "reason": "NEXT_TARGET_ALREADY_SATISFIED_AFTER_PRIOR_CLOSE",
                "custody_mutated": False,
                "leader_mutated": False,
                "execution_mutated": False,
                "gateway_mutated": False,
            }
    else:
        ownership = _classify_ownership(
            resolved=r0,
            facts=facts,
            predecessor_head=h0,
            predecessor=terminal,
        )
        if ownership.disposition is FullAccountOwnershipDisposition.STOP:
            raise ContinuousRunError(
                f"full-account ownership stopped: {ownership.reason_code.value}"
            )
        if ownership.disposition in {
            FullAccountOwnershipDisposition.ALREADY_SATISFIED,
            FullAccountOwnershipDisposition.ALREADY_COMPLETED_MATCHED,
        }:
            return {
                "status": "NOOP",
                "reason": ownership.reason_code.value,
                "custody_mutated": False,
                "leader_mutated": False,
                "execution_mutated": False,
                "gateway_mutated": False,
            }
        if ownership.disposition is not FullAccountOwnershipDisposition.NEW_TARGET:
            raise ContinuousRunError(
                "full-account ownership disposition is unsupported"
            )
        artifact = _assemble_verified_event(
            resolved=r0,
            facts=facts,
            predecessor_head=h0,
            predecessor=terminal,
        )
    event_id = artifact["payload"]["event_id"]
    if not backend.plan_adapter_ready():
        return {
            "status": "STOP",
            "reason": "INSTALLED_EVENT_PLAN_ADAPTER_UNAVAILABLE",
            "event_id": event_id,
            "custody_mutated": False,
            "leader_mutated": False,
            "execution_mutated": False,
            "gateway_mutated": False,
        }
    version = backend.custody_version()  # exactly once, immediately before publish
    try:
        backend.publish_event(artifact, version=version)
    except UnknownOutcomeError:
        recovered = backend.event_head()
        if (
            recovered.state != "INSTALLED"
            or recovered.current_event is None
            or recovered.current_event.idempotency_key != event_id
            or recovered.current_event.artifact != artifact
        ):
            raise ContinuousRunError("event publication outcome is unknown")
    installed = backend.event_head()
    if (
        installed.state != "INSTALLED"
        or installed.current_event is None
        or installed.current_event.idempotency_key != event_id
        or installed.current_event.artifact != artifact
    ):
        raise ContinuousRunError("installed event readback mismatches publication")
    lifecycle = await backend.advance_installed_event(
        event=artifact, phase_keys=phase_keys
    )
    return {
        "status": "EVENT_INSTALLED",
        "event_id": event_id,
        "phase_keys": phase_keys,
        "custody_mutated": True,
        "lifecycle": lifecycle,
    }


class _ProductionBackend:
    """Authenticated custody, research, planning and Execution lifecycle adapter."""

    def __init__(self, config: _Config) -> None:
        self.config = config
        value = config.raw
        self.phase_c = RemotePhaseCWorkflowClient(
            PhaseCRemoteSettings(
                custody_url=value["phase_c_custody_url"].rstrip("/"),
                execution_url=value["phase_c_execution_url"].rstrip("/"),
                custody_secret=value["phase_c_custody_shared_secret"],
                execution_secret=value["phase_c_execution_shared_secret"],
            )
        )
        self.execution = ExecutionClient(
            ExecutionClientSettings(
                base_url=value["execution_url"].rstrip("/"),
                shared_secret=value["execution_shared_secret"],
            )
        )

    def event_head(self) -> ContinuousEventHeadDTO:
        return self.phase_c.continuous_event_head()

    def _planner(self, source_month: str, catalog: CurrentCatalogHeadProof):
        context = load_runtime_context_readonly(
            self.config.path("warehouse_runtime_input_path"),
            allow_readonly_projected_root=True,
        )
        if (
            context.runtime_input.raw_sha256
            != self.config.raw["warehouse_runtime_input_raw_sha256"]
        ):
            raise ContinuousRunError("Warehouse runtime input root pin changed")
        history_raw = read_regular_strict(
            self.config.path("warehouse_history_receipt_path"),
            "continuous runner Warehouse history receipt",
        )
        if (
            _sha256(history_raw)
            != self.config.raw["warehouse_history_receipt_raw_sha256"]
        ):
            raise ContinuousRunError("Warehouse history receipt root pin changed")
        return replay_verified_monthly_planner_bundle(
            runtime_input_path=self.config.path("warehouse_runtime_input_path"),
            expected_runtime_input_raw_sha256=self.config.raw[
                "warehouse_runtime_input_raw_sha256"
            ],
            operator_state_path=self.config.path("warehouse_operator_state_path"),
            expected_operator_state_raw_sha256=catalog.operator_state_raw_sha256,
            history_receipt_path=self.config.path("warehouse_history_receipt_path"),
            expected_history_receipt_raw_sha256=self.config.raw[
                "warehouse_history_receipt_raw_sha256"
            ],
            manifest_public_key_path=self.config.path(
                "warehouse_manifest_public_key_path"
            ),
            expected_manifest_public_key_raw_sha256=self.config.raw[
                "warehouse_manifest_public_key_raw_sha256"
            ],
            signed_baseline_batch_path=self.config.path(
                "warehouse_signed_baseline_batch_path"
            ),
            business_public_key_path=self.config.path(
                "warehouse_business_public_key_path"
            ),
            expected_business_public_key_raw_sha256=self.config.raw[
                "warehouse_business_public_key_raw_sha256"
            ],
            expected_business_signer_key_id=self.config.raw[
                "warehouse_business_signer_key_id"
            ],
            contract_registry_path=self.config.path("warehouse_contract_registry_path"),
            expected_contract_registry_raw_sha256=self.config.raw[
                "warehouse_contract_registry_raw_sha256"
            ],
            source_month=source_month,
            allow_readonly_projected_root=True,
        )

    def warehouse(self, head: ContinuousEventHeadDTO) -> _WarehouseResolution:
        context = load_runtime_context_readonly(
            self.config.path("warehouse_runtime_input_path")
        )
        if (
            context.runtime_input.raw_sha256
            != self.config.raw["warehouse_runtime_input_raw_sha256"]
        ):
            raise ContinuousRunError("Warehouse runtime input root pin changed")
        catalog = load_current_catalog_head(
            self.config.path("warehouse_operator_state_path")
        )
        due = resolve_monthly_due_source(
            current_catalog_head=catalog,
            calendar=context.calendar,
            calendar_availability=context.availability,
        )
        daily_payload = json.loads(catalog.artifact_raw)
        daily = BuiltVerifiedDailyPitMainRollSource(
            artifact_raw=catalog.artifact_raw,
            artifact_id=daily_payload["artifact_id"],
            artifact_raw_sha256=catalog.artifact_raw_sha256,
        )
        planner: VerifiedMonthlyPlannerBundle | None = None
        monthly_candidate = None
        predecessor_monthly = None
        predecessor_terminal = None
        if due.status == MONTHLY_DUE:
            planner = self._planner(due.source_month, catalog)
            monthly_candidate = MonthlyFinalTargetCandidate(
                final_target_raw=planner.final_target.final_target_raw,
                static_core_equal_sha256=planner.final_target.static_core_equal_sha256,
                position_manager_sha256=planner.final_target.position_manager_sha256,
                baseline_batch_raw_sha256=planner.final_target.baseline_batch_raw_sha256,
            )
        elif head.state == "NO_EVENT" and head.current_event is None:
            daily_official_day = datetime.fromisoformat(
                str(daily_payload["official_day"])
            ).date()
            execution_month = self.config.raw["bootstrap_execution_month"]
            if daily_official_day.strftime("%Y-%m") == execution_month:
                planner = self._planner(
                    self.config.raw["bootstrap_source_month"], catalog
                )
                final = planner.final_target
                expected = {
                    "static_core_equal_sha256": self.config.raw[
                        "bootstrap_static_core_equal_sha256"
                    ],
                    "position_manager_sha256": self.config.raw[
                        "bootstrap_position_manager_sha256"
                    ],
                    "final_target_sha256": self.config.raw[
                        "bootstrap_final_target_sha256"
                    ],
                }
                actual = {
                    "static_core_equal_sha256": final.static_core_equal_sha256,
                    "position_manager_sha256": final.position_manager_sha256,
                    "final_target_sha256": final.final_target_sha256,
                }
                if (
                    actual != expected
                    or final.source_month != self.config.raw["bootstrap_source_month"]
                    or final.execution_day[:7] != execution_month
                    or final.execution_day > daily_payload["official_day"]
                ):
                    raise ContinuousRunError(
                        "SIMNOW Genesis bootstrap monthly root mismatches config"
                    )
                monthly_candidate = MonthlyFinalTargetCandidate(
                    final_target_raw=final.final_target_raw,
                    static_core_equal_sha256=final.static_core_equal_sha256,
                    position_manager_sha256=final.position_manager_sha256,
                    baseline_batch_raw_sha256=final.baseline_batch_raw_sha256,
                )
        elif head.current_event is not None:
            prior = head.current_event.artifact["payload"]
            source_month = prior["monthly"]["source_month"]
            planner = self._planner(source_month, catalog)
            predecessor_monthly = MonthlyFinalTargetCandidate(
                final_target_raw=planner.final_target.final_target_raw,
                static_core_equal_sha256=planner.final_target.static_core_equal_sha256,
                position_manager_sha256=planner.final_target.position_manager_sha256,
                baseline_batch_raw_sha256=planner.final_target.baseline_batch_raw_sha256,
            )
            predecessor_terminal = TerminalPredecessorPinCandidate(
                terminal_target_id=head.current_event.idempotency_key,
                terminal_target_raw_sha256=head.current_event.artifact_raw_sha256,
                monthly_final_target_sha256=planner.final_target.final_target_sha256,
                quantity_vector_sha256=planner.final_target.quantity_vector_sha256,
                exact_contract_map_sha256=prior["desired_target"][
                    "exact_contract_map_sha256"
                ],
                execution_day=prior["daily"]["execution_day"],
            )
        selection = build_continuous_event_candidate_selection(
            verified_daily_artifact=daily,
            monthly_candidate=monthly_candidate,
            predecessor_monthly_target=predecessor_monthly,
            predecessor_terminal=predecessor_terminal,
            simnow_genesis_bootstrap_execution_month=(
                self.config.raw["bootstrap_execution_month"]
                if head.state == "NO_EVENT"
                and head.current_event is None
                and monthly_candidate is not None
                and due.status != MONTHLY_DUE
                else None
            ),
        )
        fixed_source_hashes = {
            field: _sha256(
                read_regular_strict(
                    self.config.path(field),
                    f"continuous runner {field}",
                )
            )
            for field in (
                "warehouse_history_receipt_path",
                "warehouse_manifest_public_key_path",
                "warehouse_signed_baseline_batch_path",
                "warehouse_business_public_key_path",
                "warehouse_contract_registry_path",
                "warehouse_shfe_contract_parameters_path",
            )
        }
        fingerprint = _sha256(
            _canonical(
                {
                    "runtime_input": context.runtime_input.raw_sha256,
                    "calendar": context.calendar.raw_sha256,
                    "availability": context.availability.raw_sha256,
                    "catalog_receipt": catalog.receipt_raw_sha256,
                    "catalog_artifact": catalog.artifact_raw_sha256,
                    "operator_state": catalog.operator_state_raw_sha256,
                    "selection": selection.selection_sha256,
                    "planner": planner.planner_bundle_sha256 if planner else None,
                    "fixed_sources": fixed_source_hashes,
                }
            )
        )
        return _WarehouseResolution(fingerprint, catalog, planner, selection)

    async def recovery(self, key: str) -> dict[str, Any]:
        return (await self.execution.target_plan_recovery(key)).as_dict()

    async def completion(self, plan_id: str) -> dict[str, Any] | None:
        value = await self.execution.completion(plan_id)
        return value.as_dict() if value is not None else None

    async def account_facts(self) -> dict[str, Any]:
        return (await self.execution.account_facts()).as_dict()

    def custody_version(self) -> int:
        return self.phase_c.custody_current_version().version

    def continue_event(self, head: ContinuousEventHeadDTO) -> None:
        publication = head.publication
        current = head.current_event
        if publication is None or current is None:
            raise ContinuousRunError("stored event continuation evidence is incomplete")
        self.phase_c.install_published_trusted_keyless_continuous_event(
            TrustedKeylessContinuousEventInstallContinuationDTO(
                idempotency_key=current.idempotency_key,
                correlation_id=str(publication.correlation_id),
                publish_receipt_id=str(publication.publish_receipt_id),
                publish_receipt_sha256=str(publication.publish_receipt_sha256),
                publish_expected_custody_version=int(
                    publication.publish_expected_custody_version
                ),
                publish_resulting_custody_version=int(
                    publication.publish_resulting_custody_version
                ),
                artifact=current.artifact,
            )
        )

    def publish_event(self, artifact: dict[str, Any], *, version: int) -> None:
        event_id = artifact["payload"]["event_id"]
        self.phase_c.install_trusted_keyless_continuous_event(
            TrustedKeylessContinuousEventUploadDTO(
                idempotency_key=event_id,
                expected_custody_version=version,
                correlation_id=f"continuous-event-{_sha256(event_id.encode())[:32]}",
                artifact=artifact,
            )
        )

    def plan_adapter_ready(self) -> bool:
        return bool(self.config.raw["simnow_execution_enabled"])

    def _actor(self) -> dict[str, str]:
        return {
            "service": "control-api",
            "principal": self.config.raw["principal"],
            "operator": self.config.raw["operator"],
            "role": "admin",
        }

    def _planner_for_installed_event(
        self, event: Mapping[str, Any]
    ) -> VerifiedMonthlyPlannerBundle:
        payload = event["payload"]
        monthly = payload["monthly"]
        daily = payload["daily"]
        catalog = load_current_catalog_head(
            self.config.path("warehouse_operator_state_path")
        )
        if (
            catalog.receipt_raw_sha256 != daily["catalog_receipt_raw_sha256"]
            or catalog.artifact_raw_sha256 != daily["catalog_artifact_raw_sha256"]
            or catalog.operator_state_raw_sha256 != daily["operator_state_raw_sha256"]
        ):
            raise ContinuousRunError(
                "installed event Warehouse root changed before TargetPlan"
            )
        planner = self._planner(monthly["source_month"], catalog)
        final = planner.final_target
        if (
            final.final_target_raw.decode() != monthly["final_target_raw"]
            or final.final_target_raw_sha256 != monthly["final_target_raw_sha256"]
            or final.final_target_sha256 != monthly["final_target_sha256"]
            or final.static_core_equal_sha256 != monthly["static_core_equal_sha256"]
            or final.position_manager_sha256 != monthly["position_manager_sha256"]
            or final.quantity_vector_sha256 != monthly["quantity_vector_sha256"]
            or final.monthly_exact_contract_map_sha256
            != monthly["monthly_exact_contract_map_sha256"]
        ):
            raise ContinuousRunError(
                "installed event monthly planner bundle mismatches custody root"
            )
        return planner

    @staticmethod
    def _gateway_snapshot(value: Mapping[str, Any]) -> GatewaySnapshot:
        return GatewaySnapshot(
            snapshot_id=str(value["snapshot_id"]),
            generation=int(value["generation"]),
            connected=value["connected"] is True,
            active_order_count=int(value["active_order_count"]),
            position_snapshot_hash=str(value["position_snapshot_hash"]),
            observed_at=str(value["observed_at"]),
            orders=dict(value["active_orders"]),
            positions=dict(value["positions"]),
            account_scope=str(value["account_scope"]),
            environment=str(value["environment"]),
            fresh=value["fresh"] is True,
        )

    async def _build_immediate_plan(
        self,
        *,
        event: Mapping[str, Any],
        expected_phase: str | None = None,
    ) -> tuple[StaticCoreEqualFullPortfolioPhaseHandoff | None, str | None]:
        payload = event["payload"]
        event_id = str(payload["event_id"])
        planner = self._planner_for_installed_event(event)
        projection = await self.execution.reconciliation_snapshot()
        snapshot = projection.as_dict()
        binding = snapshot["state_binding"]
        if (
            snapshot["active_order_count"] != 0
            or binding["lifecycle"] != "READY"
            or binding["reconciliation"]["state"] != "RECONCILED"
            or binding["reconciliation"]["unknown_outcomes"] != 0
        ):
            raise ContinuousRunError(
                "Execution reconciliation snapshot is not planner-ready"
            )
        now = datetime.now(timezone.utc)
        generated_at = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        run_id = _execution_run_id(event_id, expected_phase)
        reconciliation = dict(binding["reconciliation"])
        gateway = self._gateway_snapshot(snapshot)
        requirements = build_full_portfolio_quote_requests(
            static_core_equal_projection=planner.static_core_equal_projection,
            static_core_equal_freeze_contract=(
                planner.static_core_equal_freeze_contract
            ),
            static_core_equal_target_evidence=(
                planner.static_core_equal_target_evidence
            ),
            position_manager_snapshot=planner.position_manager_snapshot,
            position_manager_sha256=planner.position_manager_sha256,
            current_facts=gateway,
            reconciliation=reconciliation,
            run_id=run_id,
            event_generated_at=generated_at,
            now=now,
            target_plan_version=3,
        )
        formal_quotes: dict[str, Any] = {}
        if requirements.requirements:
            bindings = read_simnow_continuous_v3_formal_tick_bindings(
                tuple(row.request for row in requirements.requirements),
                clock=lambda: datetime.now(timezone.utc),
            )
            formal_quotes = {
                row.exact_contract: binding.as_dict()
                for row, binding in zip(
                    requirements.requirements, bindings, strict=True
                )
            }
        decision_now = datetime.now(timezone.utc)
        expiry = (
            (
                decision_now
                + timedelta(seconds=float(self.config.raw["plan_expiry_seconds"]))
            )
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        decision = build_static_core_equal_full_portfolio_keyless_decision(
            static_core_equal_projection=planner.static_core_equal_projection,
            static_core_equal_freeze_contract=(
                planner.static_core_equal_freeze_contract
            ),
            static_core_equal_target_evidence=(
                planner.static_core_equal_target_evidence
            ),
            position_manager_snapshot=planner.position_manager_snapshot,
            position_manager_sha256=planner.position_manager_sha256,
            current_facts=gateway,
            reconciliation=reconciliation,
            quote_requirements=requirements,
            formal_quotes_by_exact_contract=formal_quotes,
            run_id=run_id,
            event_generated_at=generated_at,
            expires_at=expiry if requirements.requirements else None,
            now=decision_now,
            target_plan_version=3,
        )
        if (
            decision.static_core_equal_sha256
            != payload["monthly"]["static_core_equal_sha256"]
            or decision.position_manager_sha256
            != payload["monthly"]["position_manager_sha256"]
            or decision.final_target_sha256 != payload["monthly"]["final_target_sha256"]
            or decision.final_position_hash
            != payload["desired_target"]["target_position_hash"]
        ):
            raise ContinuousRunError(
                "TargetPlan decision does not bind installed event target"
            )
        if decision.noop:
            return None, None
        handoff = decision.close_handoff or decision.open_handoff
        if handoff is None:
            raise ContinuousRunError("TargetPlan decision has no immediate handoff")
        phase = str(handoff.target_plan["phase"])
        if phase != requirements.phase or (
            expected_phase is not None and phase != expected_phase
        ):
            raise ContinuousRunError("TargetPlan immediate phase mismatches recovery")
        return handoff, phase

    @staticmethod
    def _recovery_matches_handoff(
        recovery: Mapping[str, Any],
        handoff: StaticCoreEqualFullPortfolioPhaseHandoff,
        *,
        phase_key: str,
    ) -> bool:
        plan = handoff.target_plan
        return bool(
            recovery.get("custody_idempotency_key") == phase_key
            and recovery.get("target_plan_schema_version") == plan.get("schema_version")
            and recovery.get("plan_id") == plan.get("plan_id")
            and recovery.get("plan_hash") == plan.get("plan_hash")
            and recovery.get("phase") == plan.get("phase")
            and recovery.get("lineage") == plan.get("lineage")
            and recovery.get("expected_before_position_hash")
            == plan.get("expected_before_position_hash")
            and recovery.get("expected_after_position_hash")
            == plan.get("expected_after_position_hash")
        )

    @staticmethod
    def _require_recovery_binds_event(
        recovery: Mapping[str, Any],
        event: Mapping[str, Any],
        *,
        phase_key: str,
        phase: str,
    ) -> None:
        payload = event["payload"]
        monthly = payload["monthly"]
        expected_lineage = {
            "static_core_equal_sha256": monthly["static_core_equal_sha256"],
            "position_manager_sha256": monthly["position_manager_sha256"],
            "final_target_sha256": monthly["final_target_sha256"],
        }
        allowed_run_ids = {_execution_run_id(payload["event_id"], None)}
        if phase == "OPEN":
            allowed_run_ids.add(_execution_run_id(payload["event_id"], "OPEN"))
        if (
            recovery.get("target_plan_schema_version")
            != KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
            or recovery.get("custody_idempotency_key") != phase_key
            or recovery.get("phase") != phase
            or recovery.get("lineage") != expected_lineage
            or recovery.get("execution_run_id") not in allowed_run_ids
            or (
                phase == "OPEN"
                and recovery.get("expected_after_position_hash")
                != payload["desired_target"]["target_position_hash"]
            )
        ):
            raise ContinuousRunError(
                "installed TargetPlan does not bind the continuous event root"
            )

    async def _install_or_recover_plan(
        self,
        *,
        phase_key: str,
        handoff: StaticCoreEqualFullPortfolioPhaseHandoff | None,
    ) -> dict[str, Any]:
        recovery = (await self.execution.target_plan_recovery(phase_key)).as_dict()
        state = recovery["state"]
        if state == "BEFORE_CUSTODY":
            if handoff is None:
                raise ContinuousRunError("TargetPlan recovery lacks a local handoff")
            artifact = handoff.trusted_keyless_custody_artifact()
            version = self.phase_c.custody_current_version().version
            try:
                self.phase_c.install_trusted_keyless_target_plan(
                    TrustedKeylessTargetPlanUploadDTO(
                        idempotency_key=phase_key,
                        expected_custody_version=version,
                        correlation_id=f"continuous-plan-{phase_key[:48]}",
                        artifact=artifact,
                    )
                )
            except UnknownOutcomeError:
                pass
            recovery = (await self.execution.target_plan_recovery(phase_key)).as_dict()
            state = recovery["state"]
        if state == "CUSTODY_PUBLISHED_NOT_INSTALLED":
            if recovery.get("install_only_allowed") is not True:
                raise ContinuousRunError(
                    "stored TargetPlan cannot continue after custody version drift"
                )
            publication = self.phase_c.target_plan_publication(phase_key)
            if publication.state != "PUBLISHED_NOT_INSTALLED":
                raise ContinuousRunError("TargetPlan publication state drifted")
            try:
                self.phase_c.install_published_trusted_keyless_target_plan(
                    TrustedKeylessTargetPlanInstallContinuationDTO(
                        idempotency_key=phase_key,
                        correlation_id=str(publication.correlation_id),
                        publisher_principal=str(publication.publisher_principal),
                        publish_receipt_id=str(publication.publish_receipt_id),
                        publish_receipt_sha256=str(publication.publish_receipt_sha256),
                        publish_expected_custody_version=int(
                            publication.publish_expected_custody_version
                        ),
                        publish_resulting_custody_version=int(
                            publication.publish_resulting_custody_version
                        ),
                        artifact_id=str(publication.artifact_id),
                        artifact_canonical_sha256=str(
                            publication.artifact_canonical_sha256
                        ),
                        artifact_raw_sha256=str(publication.artifact_raw_sha256),
                        artifact_schema_ref=publication.artifact_schema_ref,
                        plan_schema_version=publication.plan_schema_version,
                        plan_id=str(publication.plan_id),
                        plan_hash=str(publication.plan_hash),
                        plan_phase=publication.plan_phase,
                        scope=publication.scope,
                        plan_expires_at=str(publication.plan_expires_at),
                    )
                )
            except UnknownOutcomeError:
                pass
            recovery = (await self.execution.target_plan_recovery(phase_key)).as_dict()
            state = recovery["state"]
        if state not in {"CUSTODY_PUBLISHED_NOT_PREVIEWED", "INSTALLED"}:
            raise ContinuousRunError("TargetPlan did not reach installed custody")
        if handoff is not None and not self._recovery_matches_handoff(
            recovery, handoff, phase_key=phase_key
        ):
            raise ContinuousRunError("TargetPlan recovery mismatches planned handoff")
        return recovery

    async def _release_leader(self, token: Any) -> None:
        try:
            await self.execution.release_leader(token)
        except ExecutionClientError as exc:
            status = await self.execution.leader_status()
            if (
                status.held
                and status.epoch == token.epoch
                and status.fencing_token == token.fencing_token
            ):
                raise ContinuousRunError(
                    "Execution leader release outcome remains unknown"
                ) from exc

    def _allows_retired_plan_replacement(self) -> bool:
        """Whether this lane may replace a fully retired foreign plan.

        The audited continuous lane retains its existing IDLE-only admission.
        SIMNOW_EXPERIMENTAL opts in explicitly, after checking the same
        zero-work boundary that Execution exposes through account-facts v2.
        """

        return False

    @staticmethod
    def _has_zero_work_boundary(
        status: Mapping[str, Any], *, require_leader_clear: bool
    ) -> bool:
        reconciliation = status.get("reconciliation")
        broker = status.get("broker")
        intents = status.get("send_intents")
        if (
            status.get("lifecycle") != "READY"
            or not isinstance(reconciliation, Mapping)
            or reconciliation.get("state") != "RECONCILED"
            or reconciliation.get("unknown_outcomes") != 0
            or not isinstance(broker, Mapping)
            or broker.get("active_order_count") != 0
            or not isinstance(intents, list)
            or any(
                not isinstance(intent, Mapping)
                or intent.get("state") not in {"RECONCILED", "CANCELLED", "TERMINAL"}
                for intent in intents
            )
        ):
            return False
        if require_leader_clear:
            leader = status.get("leader")
            return isinstance(leader, Mapping) and leader.get("held") is False
        return True

    @classmethod
    def _is_retired_execution_boundary(
        cls, status: Mapping[str, Any], *, require_leader_clear: bool
    ) -> bool:
        plan = status.get("plan")
        authority = status.get("authority")
        return (
            isinstance(plan, Mapping)
            and plan.get("state") == "TERMINAL"
            and isinstance(authority, Mapping)
            and authority.get("state") == "REVOKED"
            and cls._has_zero_work_boundary(
                status, require_leader_clear=require_leader_clear
            )
        )

    @classmethod
    def _is_new_plan_admission_boundary(
        cls, status: Mapping[str, Any], *, require_leader_clear: bool
    ) -> bool:
        plan = status.get("plan")
        authority = status.get("authority")
        return (
            isinstance(plan, Mapping)
            and isinstance(authority, Mapping)
            and (
                (plan.get("state") == "IDLE" and authority.get("state") == "DISABLED")
                or (
                    plan.get("state") == "TERMINAL"
                    and authority.get("state") == "REVOKED"
                )
            )
            and cls._has_zero_work_boundary(
                status, require_leader_clear=require_leader_clear
            )
        )

    def _require_post_renew_status(
        self,
        status: Mapping[str, Any],
        recovery: Mapping[str, Any],
        *,
        allow_active: bool,
    ) -> None:
        """Require the fresh post-renew status to remain on this plan boundary."""

        if status.get("lifecycle") != "READY":
            raise ContinuousRunError("Execution is not READY after leader renew")
        reconciliation = status.get("reconciliation", {})
        if (
            reconciliation.get("state") != "RECONCILED"
            or reconciliation.get("unknown_outcomes") != 0
        ):
            raise ContinuousRunError(
                "Execution is not reconciled after leader renew"
            )
        plan = status.get("plan", {})
        state = plan.get("state")
        plan_id = recovery["plan_id"]
        plan_hash = recovery["plan_hash"]
        if self._allows_retired_plan_replacement() and state in {"IDLE", "TERMINAL"}:
            if not self._is_new_plan_admission_boundary(
                status, require_leader_clear=False
            ):
                raise ContinuousRunError("Execution plan admission boundary is invalid")
            if state == "TERMINAL":
                return
        if state == "IDLE":
            return
        if state == "ACTIVE" and allow_active:
            if plan.get("plan_id") != plan_id or plan.get("plan_hash") != plan_hash:
                raise ContinuousRunError("Execution holds a foreign active plan")
            return
        if state != "PREVIEWED":
            raise ContinuousRunError("Execution holds a foreign non-preview plan")
        if (
            plan.get("plan_id") != f"preview-{str(plan_hash)[:16]}"
            or plan.get("plan_hash") != plan_hash
            or plan.get("preview_mode") != "simnow_preview"
            or plan.get("preview_receipt_id") != recovery.get("receipt_id")
            or plan.get("preview_receipt_sha256") != recovery.get("receipt_sha256")
            or plan.get("preview_artifact_id") != recovery.get("artifact_id")
            or plan.get("preview_artifact_sha256") != recovery.get("artifact_sha256")
        ):
            raise ContinuousRunError("Execution preview is foreign to this plan")

    def _require_start_status(
        self, status: Mapping[str, Any], recovery: Mapping[str, Any]
    ) -> None:
        """Require the final fresh pre-start status and authority boundary."""

        self._require_post_renew_status(status, recovery, allow_active=False)
        authority = status.get("authority", {})
        if (
            authority.get("state") != "ENABLED"
            or authority.get("artifact_id") != recovery.get("plan_id")
            or authority.get("artifact_hash") != recovery.get("plan_hash")
            or authority.get("expires_at") != recovery.get("expires_at")
        ):
            raise ContinuousRunError("Execution authority is foreign to this plan")

    async def _drive_installed_plan(
        self, recovery: Mapping[str, Any]
    ) -> dict[str, Any]:
        plan_id = str(recovery["plan_id"])
        plan_hash = str(recovery["plan_hash"])
        phase = str(recovery["phase"])
        phase_key = str(recovery["custody_idempotency_key"])
        quote_state = recovery.get("start_quote_proof_state")
        if quote_state in {
            "REPLAN_REQUIRED",
            "SOURCE_UNAVAILABLE",
            "EVIDENCE_INVALID",
        }:
            return {
                "state": "BLOCKED",
                "phase": phase,
                "plan_id": plan_id,
                "code": str(quote_state),
                "leader_mutated": False,
                "execution_mutated": False,
                "gateway_mutated": False,
            }
        actor = self._actor()
        token = None
        try:
            status = (await self.execution.status()).as_dict()
            if (
                status.get("plan", {}).get("state") == "TERMINAL"
                and status.get("plan", {}).get("plan_id") == plan_id
                and status.get("plan", {}).get("plan_hash") == plan_hash
            ):
                completion = await self.execution.completion(plan_id)
                if completion is None:
                    raise ContinuousRunError(
                        "terminal TargetPlan lacks completion archive"
                    )
                return {"state": "COMPLETED", "phase": phase, "plan_id": plan_id}

            current_plan = status.get("plan", {})
            current_state = current_plan.get("state")
            preview_matches = bool(
                current_state == "PREVIEWED"
                and current_plan.get("plan_id") == f"preview-{plan_hash[:16]}"
                and current_plan.get("plan_hash") == plan_hash
            )
            exact_plan_matches = bool(
                current_plan.get("plan_id") == plan_id
                and current_plan.get("plan_hash") == plan_hash
            )
            new_plan_boundary = self._is_new_plan_admission_boundary(
                status, require_leader_clear=True
            )
            retired_boundary = (
                new_plan_boundary and current_state == "TERMINAL"
            )
            if (
                current_state != "IDLE"
                and not (preview_matches or exact_plan_matches)
                and not (
                    self._allows_retired_plan_replacement() and retired_boundary
                )
            ):
                raise ContinuousRunError(
                    "Execution holds a foreign non-idle TargetPlan"
                )

            if self._allows_retired_plan_replacement() and current_state in {
                "IDLE",
                "TERMINAL",
            }:
                if not new_plan_boundary:
                    raise ContinuousRunError(
                        "Execution plan admission boundary is invalid"
                    )

            leader = status.get("leader", {})
            if leader.get("held"):
                raise ContinuousRunError(
                    "Execution leader is already held; wait for exact lease recovery"
                )
            token = await self.execution.acquire_leader(
                self.config.raw["leader_owner_id"]
            )
            token = await self.execution.renew_leader(token)
            status = (await self.execution.status()).as_dict()

            if recovery.get("start_quote_proof_state") == "STARTED_MATCHED" or (
                status.get("plan", {}).get("state") == "ACTIVE"
                and status.get("plan", {}).get("plan_id") == plan_id
            ):
                self._require_post_renew_status(status, recovery, allow_active=True)
                snapshot = await self.execution.reconciliation_snapshot()
                await self.execution.resume_active_plan(
                    plan_id=plan_id,
                    plan_hash=plan_hash,
                    leader_token=token,
                    reconciliation_snapshot=snapshot,
                )
            else:
                self._require_post_renew_status(status, recovery, allow_active=False)
                now = (
                    datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                if (
                    status.get("plan", {}).get("state") == "IDLE"
                    or (
                        self._allows_retired_plan_replacement()
                        and self._is_retired_execution_boundary(
                            status, require_leader_clear=False
                        )
                    )
                ):
                    await self.execution.submit(
                        _command(
                            name="preview",
                            suffix=f"continuous-preview-{phase_key[:32]}",
                            version=status["state_version"],
                            actor=actor,
                            now=now,
                            payload={
                                "plan_hash": plan_hash,
                                "artifact_hash": recovery["artifact_sha256"],
                                "mode": "simnow_preview",
                                "receipt_id": recovery["receipt_id"],
                            },
                        )
                    )
                    status = (await self.execution.status()).as_dict()
                if status.get("reconciliation", {}).get("state") != "RECONCILED":
                    await _submit_reconcile_with_ready_snapshot(
                        self.execution,
                        suffix=f"continuous-reconcile-{phase_key[:32]}",
                        version=status["state_version"],
                        actor=actor,
                        now=now,
                        reconciliation_run_id=(
                            f"continuous-reconcile-{phase_key[:40]}"
                        ),
                        reason="fresh continuous SIMNOW plan facts",
                    )
                    status = (await self.execution.status()).as_dict()
                if status.get("authority", {}).get("state") != "ENABLED":
                    await self.execution.submit(
                        _command(
                            name="enable",
                            suffix=f"continuous-enable-{phase_key[:32]}",
                            version=status["state_version"],
                            actor=actor,
                            now=now,
                            payload={
                                "authority_artifact_id": plan_id,
                                "authority_hash": plan_hash,
                                "expires_at": recovery["expires_at"],
                                "reason": "trusted continuous SIMNOW custody",
                            },
                        )
                    )
                    status = (await self.execution.status()).as_dict()
                token = await self.execution.renew_leader(token)
                status = (await self.execution.status()).as_dict()
                self._require_start_status(status, recovery)
                start = _command(
                    name="start",
                    suffix=f"continuous-start-{phase_key[:32]}",
                    version=status["state_version"],
                    actor=actor,
                    now=now,
                    fence={
                        "leader_epoch": token.epoch,
                        "fencing_token": token.fencing_token,
                    },
                    payload={
                        "plan_id": plan_id,
                        "plan_hash": plan_hash,
                        "reason": "start exact continuous SIMNOW plan",
                    },
                )
                try:
                    await self.execution.submit(start)
                except (ExecutionUnknownOutcomeError, ExecutionClientError):
                    try:
                        receipt = await self.execution.receipt(
                            start["idempotency_key"], actor=actor
                        )
                    except ExecutionClientError:
                        receipt = None
                    if not _accepted_start_receipt(receipt, command=start):
                        raise ContinuousRunError(
                            "TargetPlan start outcome is unknown; query only"
                        )

            deadline = asyncio.get_running_loop().time() + float(
                self.config.raw["completion_timeout_seconds"]
            )
            reconciled_versions: set[int] = set()
            while True:
                status = (await self.execution.status()).as_dict()
                state = _completion_state(status, plan_id=plan_id, plan_hash=plan_hash)
                if state == "unknown_outcome":
                    raise ContinuousRunError("TargetPlan has an unknown broker outcome")
                if state == "ready_for_final_reconcile":
                    break
                if state == "pending_intents":
                    version = status["state_version"]
                    if version not in reconciled_versions:
                        token = await self.execution.renew_leader(token)
                        command, response = await _submit_reconcile_with_ready_snapshot(
                            self.execution,
                            suffix=(
                                f"continuous-completion-{phase_key[:24]}-{version}"
                            ),
                            version=version,
                            actor=actor,
                            now=datetime.now(timezone.utc)
                            .replace(microsecond=0)
                            .isoformat()
                            .replace("+00:00", "Z"),
                            reconciliation_run_id=(
                                f"continuous-completion-{phase_key[:24]}-{version}"
                            ),
                            reason="query-only continuous SIMNOW intent reconciliation",
                        )
                        reconciled_versions.add(version)
                        final_status = (await self.execution.status()).as_dict()
                        if _final_reconcile_completed(
                            response,
                            plan_id=plan_id,
                            plan_hash=plan_hash,
                            expected_after_position_hash=recovery[
                                "expected_after_position_hash"
                            ],
                            final_status=final_status,
                            idempotency_key=command["idempotency_key"],
                        ):
                            status = final_status
                            break
                if asyncio.get_running_loop().time() >= deadline:
                    return {
                        "state": "ACTIVE",
                        "phase": phase,
                        "plan_id": plan_id,
                        "reason": f"completion_timeout:{state}",
                    }
                await asyncio.sleep(float(self.config.raw["completion_poll_seconds"]))

            if not _completed(status, plan_id=plan_id, plan_hash=plan_hash):
                token = await self.execution.renew_leader(token)
                command, response = await _submit_reconcile_with_ready_snapshot(
                    self.execution,
                    suffix=f"continuous-final-{phase_key[:32]}",
                    version=status["state_version"],
                    actor=actor,
                    now=datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    reconciliation_run_id=f"continuous-final-{phase_key[:40]}",
                    reason="final continuous SIMNOW reconciliation",
                )
                status = (await self.execution.status()).as_dict()
                if not _final_reconcile_completed(
                    response,
                    plan_id=plan_id,
                    plan_hash=plan_hash,
                    expected_after_position_hash=recovery[
                        "expected_after_position_hash"
                    ],
                    final_status=status,
                    idempotency_key=command["idempotency_key"],
                ) or not _completed(status, plan_id=plan_id, plan_hash=plan_hash):
                    raise ContinuousRunError(
                        "TargetPlan final reconciliation did not archive"
                    )
            return {"state": "COMPLETED", "phase": phase, "plan_id": plan_id}
        finally:
            if token is not None:
                await self._release_leader(token)

    async def advance_installed_event(
        self, *, event: dict[str, Any], phase_keys: Mapping[str, str]
    ) -> dict[str, Any]:
        if not self.config.raw["simnow_execution_enabled"]:
            return {
                "state": "BLOCKED",
                "code": "SIMNOW_EXECUTION_NOT_ENABLED",
                "leader_mutated": False,
                "execution_mutated": False,
                "gateway_mutated": False,
            }
        event_contract.validate_simnow_continuous_event_v1(event["payload"])
        event_id = event["payload"]["event_id"]
        if any(
            phase_keys.get(phase) != _phase_key(event_id, phase) for phase in _PHASES
        ):
            raise ContinuousRunError("installed event phase keys are foreign")

        close_recovery = (
            await self.execution.target_plan_recovery(phase_keys["CLOSE"])
        ).as_dict()
        open_recovery = (
            await self.execution.target_plan_recovery(phase_keys["OPEN"])
        ).as_dict()
        if open_recovery["state"] != "BEFORE_CUSTODY":
            installed = await self._install_or_recover_plan(
                phase_key=phase_keys["OPEN"], handoff=None
            )
            self._require_recovery_binds_event(
                installed,
                event,
                phase_key=phase_keys["OPEN"],
                phase="OPEN",
            )
            direct_run_id = _execution_run_id(event_id, None)
            post_close_run_id = _execution_run_id(event_id, "OPEN")
            if installed.get("execution_run_id") == post_close_run_id:
                if close_recovery.get("state") not in {
                    "CUSTODY_PUBLISHED_NOT_PREVIEWED",
                    "INSTALLED",
                }:
                    raise ContinuousRunError(
                        "post-CLOSE OPEN lacks installed CLOSE recovery root"
                    )
                self._require_recovery_binds_event(
                    close_recovery,
                    event,
                    phase_key=phase_keys["CLOSE"],
                    phase="CLOSE",
                )
                close_completion = await self.execution.completion(
                    str(close_recovery["plan_id"])
                )
                if close_completion is None or not _completion_matches_recovery(
                    close_completion.as_dict(), close_recovery
                ):
                    raise ContinuousRunError(
                        "post-CLOSE OPEN lacks exact CLOSE completion"
                    )
            elif (
                installed.get("execution_run_id") == direct_run_id
                and close_recovery.get("state") != "BEFORE_CUSTODY"
            ):
                raise ContinuousRunError(
                    "direct OPEN conflicts with an existing CLOSE plan"
                )
            return await self._drive_installed_plan(installed)

        if close_recovery["state"] != "BEFORE_CUSTODY":
            installed_close = await self._install_or_recover_plan(
                phase_key=phase_keys["CLOSE"], handoff=None
            )
            self._require_recovery_binds_event(
                installed_close,
                event,
                phase_key=phase_keys["CLOSE"],
                phase="CLOSE",
            )
            completion = await self.execution.completion(
                str(installed_close["plan_id"])
            )
            if completion is None:
                result = await self._drive_installed_plan(installed_close)
                if result["state"] != "COMPLETED":
                    return result
                completion = await self.execution.completion(
                    str(installed_close["plan_id"])
                )
            if completion is None:
                raise ContinuousRunError("CLOSE completion archive is unavailable")
            facts = await self.execution.account_facts()
            recovery_raw = _canonical_line(installed_close)
            classified = classify_same_event_close_completion(
                account_facts=facts,
                expected_close=ExpectedSameEventCloseCompletionBinding(
                    installed_event_id=event_id,
                    installed_event_raw_sha256=event["payload"][
                        "source_event_raw_sha256"
                    ],
                    close_recovery_raw=recovery_raw,
                    close_recovery_raw_sha256=_sha256(recovery_raw),
                ),
                completion_raw=_canonical_line(completion.as_dict()),
                desired_target=_event_desired_binding(event),
                now=datetime.now(timezone.utc),
            )
            if (
                classified.disposition
                is FullAccountOwnershipDisposition.ALREADY_COMPLETED_MATCHED
            ):
                return {
                    "state": "COMPLETED",
                    "phase": "CLOSE",
                    "plan_id": installed_close["plan_id"],
                }
            if (
                classified.disposition
                is not FullAccountOwnershipDisposition.RESUME_AFTER_CLOSE
            ):
                raise ContinuousRunError(
                    "same-event CLOSE does not authorize fresh OPEN planning"
                )
            handoff, phase = await self._build_immediate_plan(
                event=event, expected_phase="OPEN"
            )
            if handoff is None or phase != "OPEN":
                raise ContinuousRunError("fresh post-CLOSE OPEN plan is missing")
            installed_open = await self._install_or_recover_plan(
                phase_key=phase_keys["OPEN"], handoff=handoff
            )
            self._require_recovery_binds_event(
                installed_open,
                event,
                phase_key=phase_keys["OPEN"],
                phase="OPEN",
            )
            return await self._drive_installed_plan(installed_open)

        handoff, phase = await self._build_immediate_plan(event=event)
        if handoff is None or phase is None:
            return {"state": "NOOP", "phase": None, "plan_id": None}
        installed = await self._install_or_recover_plan(
            phase_key=phase_keys[phase], handoff=handoff
        )
        self._require_recovery_binds_event(
            installed,
            event,
            phase_key=phase_keys[phase],
            phase=phase,
        )
        return await self._drive_installed_plan(installed)


async def run_once(config_path: Path) -> dict[str, Any]:
    """Run one pass.  No dynamic DTO, clock, day, version or client is public."""

    config = _load_config(Path(config_path))
    with _one_process(config.path("run_lock_path")):
        return await _run_locked(_ProductionBackend(config))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="one root-managed continuous SIMNOW control pass"
    )
    parser.add_argument("--config", required=True, type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = asyncio.run(run_once(args.config))
    except ContinuousRunBusy as exc:
        print(json.dumps({"status": "BUSY", "error": str(exc)}, sort_keys=True))
        return 75
    except Exception as exc:  # noqa: BLE001 - CLI fail-closed boundary
        print(json.dumps({"status": "STOP", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
