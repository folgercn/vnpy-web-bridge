"""Pure control decisions for C_FAST continuous SimNow execution.

The execution service owns RPC and order side effects.  This module keeps the
authorization-independent ordering rules explicit: recognise an already
completed snapshot before loading expiring authority, distinguish waiting
conditions from hard drift, and never create a new plan during crash recovery.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable, Mapping

from app.schemas.commodity_c_fast_execution_permit import (
    CommodityCFastSimNowExecutionPermitDTO,
)
from app.schemas.commodity_c_fast_shadow import (
    CommodityCFastRuntimeExecutableSnapshotDTO,
    CommodityCFastRuntimeSnapshotDTO,
    CommodityCFastShakedownSnapshotDTO,
)
from app.services.commodity_c_fast_runtime_authorization import (
    CommodityCFastRuntimeAuthorizationError,
    CommodityCFastRuntimeAuthorizationService,
    VerifiedCommodityCFastRuntimeAuthorization,
)


class ContinuousDecision(StrEnum):
    ALREADY_COMPLETED = "ALREADY_COMPLETED"
    VERIFY_NEW_SNAPSHOT = "VERIFY_NEW_SNAPSHOT"
    WAITING = "WAITING"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    RESTORE_AFTER_PREFLIGHT = "RESTORE_AFTER_PREFLIGHT"
    HARD_REVOKE = "HARD_REVOKE"


@dataclass(frozen=True, slots=True)
class ContinuousOutcome:
    decision: ContinuousDecision
    reason: str


@dataclass(frozen=True, slots=True)
class ResolvedContinuousAuthority:
    mode: str
    snapshot: CommodityCFastRuntimeSnapshotDTO
    snapshot_sha256: str
    runtime_authorization: VerifiedCommodityCFastRuntimeAuthorization | None
    legacy_permit: CommodityCFastSimNowExecutionPermitDTO | None


def resolve_continuous_authority(
    *,
    snapshot: CommodityCFastRuntimeSnapshotDTO,
    snapshot_sha256: str,
    actual_account_sha256: str,
    selected_products: list[str],
    runtime_authorization: CommodityCFastRuntimeAuthorizationService,
    legacy_permit_provider: Callable[
        [CommodityCFastShakedownSnapshotDTO, str],
        CommodityCFastSimNowExecutionPermitDTO,
    ]
    | None,
) -> ResolvedContinuousAuthority:
    """Resolve v2 runtime authority without touching the legacy permit path.

    The DTO type is the downgrade boundary.  A runtime executable snapshot can
    only use persistent Runtime Authorization; a legacy shakedown snapshot can
    only use the preserved one-shot Permit verifier.
    """

    if isinstance(snapshot, CommodityCFastRuntimeExecutableSnapshotDTO):
        verified = runtime_authorization.verify_snapshot(
            snapshot=snapshot,
            snapshot_sha256=snapshot_sha256,
            actual_account_sha256=actual_account_sha256,
            selected_products=selected_products,
            snapshot_signature_verified=True,
        )
        return ResolvedContinuousAuthority(
            mode="RUNTIME_AUTHORIZATION",
            snapshot=snapshot,
            snapshot_sha256=snapshot_sha256,
            runtime_authorization=verified,
            legacy_permit=None,
        )
    if isinstance(snapshot, CommodityCFastShakedownSnapshotDTO):
        if legacy_permit_provider is None:
            raise CommodityCFastRuntimeAuthorizationError(
                "LEGACY_EXECUTION_PERMIT_PROVIDER_MISSING"
            )
        permit = legacy_permit_provider(snapshot, snapshot_sha256)
        if not isinstance(permit, CommodityCFastSimNowExecutionPermitDTO):
            raise CommodityCFastRuntimeAuthorizationError(
                "LEGACY_EXECUTION_PERMIT_INVALID"
            )
        return ResolvedContinuousAuthority(
            mode="LEGACY_EXECUTION_PERMIT",
            snapshot=snapshot,
            snapshot_sha256=snapshot_sha256,
            runtime_authorization=None,
            legacy_permit=permit,
        )
    raise CommodityCFastRuntimeAuthorizationError(
        "EXECUTABLE_SNAPSHOT_SCHEMA_UNAUTHORIZED"
    )


def completed_snapshot_outcome(
    terminal_session: Mapping[str, Any] | None,
    *,
    snapshot_id: str,
    snapshot_sha256: str,
) -> ContinuousOutcome:
    """Classify identity using only static terminal facts.

    This function intentionally does not accept an Acceptance, Runtime
    Authorization, or legacy Permit.  Those artifacts can be expired or
    consumed and are irrelevant when recognising the exact terminal snapshot.
    """

    if not isinstance(terminal_session, Mapping):
        return ContinuousOutcome(
            ContinuousDecision.HARD_REVOKE,
            "terminal_session_missing",
        )
    if terminal_session.get("status") != "COMPLETE":
        return ContinuousOutcome(
            ContinuousDecision.HARD_REVOKE,
            "terminal_session_not_complete",
        )
    terminal_id = str(terminal_session.get("source_snapshot_id") or "")
    terminal_hash = str(
        terminal_session.get("source_snapshot_hash") or ""
    )
    if terminal_id == snapshot_id and terminal_hash == snapshot_sha256:
        return ContinuousOutcome(
            ContinuousDecision.ALREADY_COMPLETED,
            "snapshot_already_completed",
        )
    if terminal_id == snapshot_id or terminal_hash == snapshot_sha256:
        return ContinuousOutcome(
            ContinuousDecision.HARD_REVOKE,
            "snapshot_identity_hash_inconsistent",
        )
    return ContinuousOutcome(
        ContinuousDecision.VERIFY_NEW_SNAPSHOT,
        "new_snapshot_detected",
    )


def restart_outcome(
    *,
    active_plan_status: str | None,
    runtime_authorization_state: str,
    planned_shutdown_marker: bool,
) -> ContinuousOutcome:
    """Return the only safe restart action before any automatic preview."""

    if active_plan_status and active_plan_status != "COMPLETE":
        return ContinuousOutcome(
            ContinuousDecision.RECOVERY_REQUIRED,
            "active_plan_requires_recovery",
        )
    if runtime_authorization_state != "ACTIVE":
        return ContinuousOutcome(
            ContinuousDecision.WAITING,
            "runtime_authorization_not_active",
        )
    if planned_shutdown_marker:
        return ContinuousOutcome(
            ContinuousDecision.RESTORE_AFTER_PREFLIGHT,
            "planned_restart_requires_full_preflight",
        )
    return ContinuousOutcome(
        ContinuousDecision.RESTORE_AFTER_PREFLIGHT,
        "crash_restart_requires_full_preflight",
    )


__all__ = [
    "ContinuousDecision",
    "ContinuousOutcome",
    "ResolvedContinuousAuthority",
    "completed_snapshot_outcome",
    "resolve_continuous_authority",
    "restart_outcome",
]
