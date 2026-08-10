"""One-shot, fail-closed Windows fence ceremony coordinator.

The CLI is verification-only.  Programmatic live orchestration is deliberately
limited to an injected, immediately authorized action seam: it never signs,
opens a Windows connection, or exposes an automatic live command.
"""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .contracts import canonical_json_bytes
from .host_observer_v1 import NativeWindowsHostObserverV1
from .installer_trust_anchor_v1 import (
    canonical_public_keyring_v1,
    load_production_installer_trust_anchor_v1,
    validate_anchor_keyring_bytes_v1,
)
from .installer_windows_v1 import (
    FinalWindowsFenceInstallerV1,
    WindowsFinalInstallerError,
)
from .native_windows_installer_host_v1 import NativeWindowsFenceInstallerHostV1
from .offline_signing_v1 import (
    OfflineSigningError,
    require_fresh_zero_preflight_v1,
    verify_public_artifact_v1,
)
from .release_bundle_v1 import CHAIN_ORDER, verify_signing_closure_chain_v1


class WindowsFenceCeremonyError(RuntimeError):
    """Stable fail-closed ceremony error."""


@dataclass(frozen=True)
class CeremonyEventEvidenceV1:
    """Opaque raw evidence returned by one action and bound to its successor."""

    event_sequence: int
    install_attempt_id: str
    service_name: str
    raw: bytes
    previous_event_raw_sha256: str | None

    @property
    def raw_sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


@dataclass(frozen=True)
class CeremonyReservationEvidenceV1:
    """Event-3 evidence, including the action's durable create-only assertion."""

    event: CeremonyEventEvidenceV1
    reservation_id: str
    durable_create_only: bool


@dataclass(frozen=True)
class CeremonyQueryEvidenceV1:
    """Evidence returned by the only permitted post-event-3 recovery action."""

    install_attempt_id: str
    service_name: str
    raw: bytes
    frontier_sequence: int
    restart_dispatches: int = 0


@dataclass(frozen=True)
class CeremonyStepContextV1:
    """Exact attempt identity and predecessor evidence supplied to every seam."""

    install_attempt_id: str
    service_name: str
    previous_event: CeremonyEventEvidenceV1 | None


@dataclass(frozen=True)
class WindowsFenceCeremonyActionsV1(Protocol):
    """Injected action seam; never exposed by the safe CLI.

    Each mutating operation must return the evidence it created.  The runner
    passes that evidence to the next operation, preventing callers from
    supplying a detached pre-built event-5/6/7 closure.
    """

    def run_events_1_to_2(
        self, *, context: CeremonyStepContextV1
    ) -> tuple[CeremonyEventEvidenceV1, CeremonyEventEvidenceV1]: ...

    def capture_publish_receipt_draft(
        self, *, context: CeremonyStepContextV1
    ) -> bytes: ...

    def reserve_event_3_durable_create_only(
        self, *, context: CeremonyStepContextV1
    ) -> CeremonyReservationEvidenceV1: ...

    def run_event_4(
        self, *, context: CeremonyStepContextV1
    ) -> CeremonyEventEvidenceV1: ...

    def dispatch_restart_once_for_event_5(
        self,
        *,
        context: CeremonyStepContextV1,
        signed_restart_authorization: bytes,
    ) -> None: ...

    def append_event_5(
        self, *, context: CeremonyStepContextV1, scm_dispatch_evidence_raw: bytes
    ) -> CeremonyEventEvidenceV1: ...

    def capture_scm_dispatch_evidence_draft(
        self, *, context: CeremonyStepContextV1
    ) -> bytes: ...

    def await_event_6(
        self, *, context: CeremonyStepContextV1, startup_receipt_raw: bytes
    ) -> CeremonyEventEvidenceV1: ...

    def capture_startup_receipt_draft(
        self, *, context: CeremonyStepContextV1
    ) -> bytes: ...

    def await_event_7(
        self, *, context: CeremonyStepContextV1, attestation_raw: bytes
    ) -> CeremonyEventEvidenceV1: ...

    def capture_attestation_draft(self, *, context: CeremonyStepContextV1) -> bytes: ...

    def query_same_attempt_only(
        self, *, context: CeremonyStepContextV1, cause: str
    ) -> CeremonyQueryEvidenceV1: ...


@dataclass(frozen=True)
class CeremonyResultV1:
    mode: str
    install_attempt_id: str
    service_name: str
    completed_events: tuple[int, ...]
    restart_dispatches: int
    status: str = "COMPLETED"
    observer_draft: bytes | None = None
    missing_artifacts: tuple[str, ...] = ()


class NativeWindowsFenceCeremonyActionsV1:
    """Thin concrete binding to the existing final installer/native host.

    This is intentionally not a second installer or ledger.  It turns the
    existing journal records and observer drafts into the runner's opaque
    evidence objects.  Drafts are handed to the existing offline v1 observer
    signer; only its verified raw output is joined into Events 5-7. Missing
    production observer capabilities remain
    terminal and are handled by the runner's same-attempt query-only rule.
    """

    def __init__(
        self,
        *,
        installer: FinalWindowsFenceInstallerV1,
        observer: NativeWindowsHostObserverV1,
        bundle_raw: bytes,
    ) -> None:
        if (
            type(installer) is not FinalWindowsFenceInstallerV1
            or type(observer) is not NativeWindowsHostObserverV1
            or type(getattr(installer, "_host", None))
            is not NativeWindowsFenceInstallerHostV1
            or type(bundle_raw) is not bytes
            or not bundle_raw
        ):
            raise WindowsFenceCeremonyError("CEREMONY_NATIVE_ACTIONS_REQUIRED")
        self._installer = installer
        self._observer = observer
        self._bundle_raw = bundle_raw

    @staticmethod
    def _event(
        context: CeremonyStepContextV1, sequence: int, raw: bytes
    ) -> CeremonyEventEvidenceV1:
        return CeremonyEventEvidenceV1(
            event_sequence=sequence,
            install_attempt_id=context.install_attempt_id,
            service_name=context.service_name,
            raw=raw,
            previous_event_raw_sha256=(
                None
                if context.previous_event is None
                else context.previous_event.raw_sha256
            ),
        )

    def run_events_1_to_2(
        self, *, context: CeremonyStepContextV1
    ) -> tuple[CeremonyEventEvidenceV1, CeremonyEventEvidenceV1]:
        self._installer.stage_and_publish(bundle_raw=self._bundle_raw)
        return (
            self._event(
                context, 1, self._installer.read_event_readback(event_sequence=1)
            ),
            self._event(
                CeremonyStepContextV1(
                    context.install_attempt_id,
                    context.service_name,
                    self._event(
                        context,
                        1,
                        self._installer.read_event_readback(event_sequence=1),
                    ),
                ),
                2,
                self._installer.read_event_readback(event_sequence=2),
            ),
        )

    def capture_publish_receipt_draft(self, *, context: CeremonyStepContextV1) -> bytes:
        del context
        return self._observer.capture_publish_receipt()

    def reserve_event_3_durable_create_only(
        self, *, context: CeremonyStepContextV1
    ) -> CeremonyReservationEvidenceV1:
        self._installer.reserve_event3_and_apply_target()
        event = self._event(
            context, 3, self._installer.read_event_readback(event_sequence=3)
        )
        return CeremonyReservationEvidenceV1(
            event=event,
            reservation_id=event.raw_sha256,
            durable_create_only=True,
        )

    def run_event_4(self, *, context: CeremonyStepContextV1) -> CeremonyEventEvidenceV1:
        self._installer.query_service_runtime_readback()
        return self._event(
            context, 4, self._installer.read_event_readback(event_sequence=4)
        )

    def dispatch_restart_once_for_event_5(
        self,
        *,
        context: CeremonyStepContextV1,
        signed_restart_authorization: bytes,
    ) -> None:
        del context
        self._installer.dispatch_reserved_restart_once(
            restart_authorization_raw=signed_restart_authorization
        )

    def append_event_5(
        self, *, context: CeremonyStepContextV1, scm_dispatch_evidence_raw: bytes
    ) -> CeremonyEventEvidenceV1:
        return self._event(
            context,
            5,
            self._installer.append_signed_evidence_event(
                event_sequence=5, evidence_raw=scm_dispatch_evidence_raw
            ),
        )

    def capture_scm_dispatch_evidence_draft(
        self, *, context: CeremonyStepContextV1
    ) -> bytes:
        del context
        return self._observer.capture_scm_dispatch_evidence()

    def await_event_6(
        self, *, context: CeremonyStepContextV1, startup_receipt_raw: bytes
    ) -> CeremonyEventEvidenceV1:
        return self._event(
            context,
            6,
            self._installer.append_signed_evidence_event(
                event_sequence=6, evidence_raw=startup_receipt_raw
            ),
        )

    def capture_startup_receipt_draft(self, *, context: CeremonyStepContextV1) -> bytes:
        del context
        return self._observer.capture_startup_receipt()

    def await_event_7(
        self, *, context: CeremonyStepContextV1, attestation_raw: bytes
    ) -> CeremonyEventEvidenceV1:
        return self._event(
            context,
            7,
            self._installer.append_signed_evidence_event(
                event_sequence=7, evidence_raw=attestation_raw
            ),
        )

    def capture_attestation_draft(self, *, context: CeremonyStepContextV1) -> bytes:
        del context
        return self._observer.capture_attestation()

    def query_same_attempt_only(
        self, *, context: CeremonyStepContextV1, cause: str
    ) -> CeremonyQueryEvidenceV1:
        del cause
        frontier = 0
        raw = b""
        for sequence in range(7, 0, -1):
            try:
                raw = self._installer.read_event_readback(event_sequence=sequence)
                frontier = sequence
                break
            except WindowsFinalInstallerError:
                continue
        if frontier in {2, 4, 5, 6, 7}:
            self._installer.resume_from_secure_journal(frontier_sequence=frontier)
        restart_dispatches = 0
        if frontier >= 3:
            restart = self._installer.query_unknown_restart_only()
            if restart == "RESTART_DISPATCHED_OR_UNKNOWN_FROZEN":
                restart_dispatches = 1
        if not raw:
            raw = b"native-journal-empty"
        return CeremonyQueryEvidenceV1(
            context.install_attempt_id,
            context.service_name,
            raw,
            frontier,
            restart_dispatches,
        )


class WindowsFenceCeremonyRunnerV1:
    """Advance a journaled ceremony without replaying a completed mutation.

    The protected native journal remains the sole durable source.  This runner
    only projects its frontier into the existing action seam; it never stores
    evidence or attempts to manufacture an unavailable observer fact.
    """

    def __init__(
        self,
        *,
        public_keyring_raw: bytes,
        expected_public_keyring_sha256: str,
        now: datetime,
    ) -> None:
        self._public_keyring_raw = public_keyring_raw
        self._expected_keyring_sha256 = expected_public_keyring_sha256
        self._now = now

    def verify_dry_run(self, artifacts: Mapping[str, bytes]) -> CeremonyResultV1:
        closure = self._verify_closure(artifacts)
        return CeremonyResultV1(
            mode="dry-run",
            install_attempt_id=str(closure["install_attempt_id"]),
            service_name=str(closure["service_name"]),
            completed_events=(1, 2, 3, 4, 5, 6, 7),
            restart_dispatches=0,
        )

    def run_once(
        self,
        *,
        artifacts: Mapping[str, bytes],
        dry_run: bool = True,
        actions: WindowsFenceCeremonyActionsV1 | None = None,
    ) -> CeremonyResultV1:
        if dry_run:
            closure = self._verify_closure(artifacts)
            return CeremonyResultV1(
                mode="dry-run",
                install_attempt_id=str(closure["install_attempt_id"]),
                service_name=str(closure["service_name"]),
                completed_events=(1, 2, 3, 4, 5, 6, 7),
                restart_dispatches=0,
            )
        if actions is None:
            raise WindowsFenceCeremonyError("CEREMONY_LIVE_ACTIONS_REQUIRED")
        admission = self._verify_live_artifacts(artifacts)
        context = CeremonyStepContextV1(
            install_attempt_id=str(admission["install_attempt_id"]),
            service_name=str(admission["service_name"]),
            previous_event=None,
        )
        frontier = self._query_frontier(actions, context=context)
        if frontier.frontier_sequence == 1:
            raise WindowsFenceCeremonyError("CEREMONY_PRE_EVENT3_PARTIAL_QUERY_ONLY")
        if frontier.frontier_sequence == 0:
            try:
                event_1, event_2 = actions.run_events_1_to_2(context=context)
                self._require_event(event_1, sequence=1, context=context)
                context = self._next_context(context, event_1)
                self._require_event(event_2, sequence=2, context=context)
                context = self._next_context(context, event_2)
                frontier = CeremonyQueryEvidenceV1(
                    context.install_attempt_id,
                    context.service_name,
                    event_2.raw,
                    2,
                    0,
                )
            except Exception as exc:
                raise WindowsFenceCeremonyError("CEREMONY_PRE_EVENT3_FAILED") from exc
        else:
            context = CeremonyStepContextV1(
                context.install_attempt_id,
                context.service_name,
                CeremonyEventEvidenceV1(
                    frontier.frontier_sequence,
                    context.install_attempt_id,
                    context.service_name,
                    frontier.raw,
                    None,
                ),
            )

        if frontier.frontier_sequence == 2:
            publish_draft = self._capture_observer_draft(
                actions, context=context, artifact="publish_receipt"
            )
            if "publish_receipt" not in artifacts:
                return self._waiting(
                    context,
                    frontier,
                    status="WAITING_PUBLISH_SIGNATURE",
                    draft=publish_draft,
                    missing=("publish_receipt",),
                )
            self._verify_observer_handoff(
                draft=publish_draft,
                raw=artifacts["publish_receipt"],
                expected_schema="windows_rpc_durable_fence_publish_receipt_v1",
            )
            if "restart_authorization" not in artifacts:
                return self._waiting(
                    context,
                    frontier,
                    status="WAITING_PUBLISH_SIGNATURE",
                    draft=None,
                    missing=("restart_authorization",),
                )
            publish = self._verify_signed_publish_receipt(
                artifacts,
                preflight=admission["preflight"],
                manifest=admission["manifest"],
            )
            self._verify_signed_restart_authorization(
                artifacts,
                preflight=admission["preflight"],
                manifest=admission["manifest"],
                publish=publish,
            )
            context = self._reserve_event3(actions, context=context)
            frontier = CeremonyQueryEvidenceV1(
                context.install_attempt_id,
                context.service_name,
                context.previous_event.raw,
                3,
            )

        if frontier.frontier_sequence == 3:
            event_4 = self._run_post_event3_step(
                actions,
                context=context,
                sequence=4,
                cause="event_4_unknown",
                action=lambda: actions.run_event_4(context=context),
            )
            context = self._next_context(context, event_4)
            frontier = CeremonyQueryEvidenceV1(
                context.install_attempt_id,
                context.service_name,
                event_4.raw,
                4,
                frontier.restart_dispatches,
            )

        if frontier.frontier_sequence == 4:
            if frontier.restart_dispatches == 0:
                self._verify_restart_inputs(artifacts, admission=admission)
                try:
                    actions.dispatch_restart_once_for_event_5(
                        context=context,
                        signed_restart_authorization=artifacts["restart_authorization"],
                    )
                except Exception as exc:
                    self._query_only_after_event3(
                        actions, context=context, cause="event_5_restart_unknown"
                    )
                    raise WindowsFenceCeremonyError(
                        "CEREMONY_POST_EVENT3_QUERY_ONLY"
                    ) from exc
                frontier = CeremonyQueryEvidenceV1(
                    context.install_attempt_id,
                    context.service_name,
                    frontier.raw,
                    4,
                    1,
                )
            scm_draft = self._capture_observer_draft(
                actions, context=context, artifact="scm_dispatch_evidence"
            )
            if "scm_dispatch_evidence" not in artifacts:
                return self._waiting(
                    context,
                    frontier,
                    status="WAITING_SCM_SIGNATURE",
                    draft=scm_draft,
                    missing=("scm_dispatch_evidence",),
                )
            event_5 = self._append_signed_observer_event(
                actions,
                context=context,
                sequence=5,
                draft=scm_draft,
                raw=artifacts["scm_dispatch_evidence"],
                schema="windows_rpc_durable_fence_scm_dispatch_evidence_v1",
            )
            context = self._next_context(context, event_5)
            frontier = CeremonyQueryEvidenceV1(
                context.install_attempt_id, context.service_name, event_5.raw, 5, 1
            )

        if frontier.frontier_sequence == 5:
            startup_draft = self._capture_observer_draft(
                actions, context=context, artifact="startup_receipt"
            )
            if "startup_receipt" not in artifacts:
                return self._waiting(
                    context,
                    frontier,
                    status="WAITING_STARTUP_SIGNATURE",
                    draft=startup_draft,
                    missing=("startup_receipt",),
                )
            event_6 = self._append_signed_observer_event(
                actions,
                context=context,
                sequence=6,
                draft=startup_draft,
                raw=artifacts["startup_receipt"],
                schema="windows_rpc_durable_fence_startup_receipt_v1",
            )
            context = self._next_context(context, event_6)
            frontier = CeremonyQueryEvidenceV1(
                context.install_attempt_id, context.service_name, event_6.raw, 6, 1
            )

        if frontier.frontier_sequence == 6:
            attestation_draft = self._capture_observer_draft(
                actions, context=context, artifact="attestation"
            )
            if "attestation" not in artifacts:
                return self._waiting(
                    context,
                    frontier,
                    status="WAITING_ATTESTATION_SIGNATURE",
                    draft=attestation_draft,
                    missing=("attestation",),
                )
            self._append_signed_observer_event(
                actions,
                context=context,
                sequence=7,
                draft=attestation_draft,
                raw=artifacts["attestation"],
                schema="windows_rpc_durable_fence_foundation_attestation_v1",
            )
            frontier = CeremonyQueryEvidenceV1(
                context.install_attempt_id, context.service_name, b"completed", 7, 1
            )

        if frontier.frontier_sequence != 7:
            raise WindowsFenceCeremonyError("CEREMONY_FRONTIER_UNSUPPORTED")
        return CeremonyResultV1(
            mode="live",
            install_attempt_id=context.install_attempt_id,
            service_name=context.service_name,
            completed_events=(1, 2, 3, 4, 5, 6, 7),
            restart_dispatches=frontier.restart_dispatches,
        )

    @staticmethod
    def _waiting(
        context: CeremonyStepContextV1,
        frontier: CeremonyQueryEvidenceV1,
        *,
        status: str,
        draft: bytes | None,
        missing: tuple[str, ...],
    ) -> CeremonyResultV1:
        return CeremonyResultV1(
            mode="live",
            install_attempt_id=context.install_attempt_id,
            service_name=context.service_name,
            completed_events=tuple(range(1, frontier.frontier_sequence + 1)),
            restart_dispatches=frontier.restart_dispatches,
            status=status,
            observer_draft=draft,
            missing_artifacts=missing,
        )

    def _capture_observer_draft(
        self,
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
        artifact: str,
    ) -> bytes:
        capture = {
            "publish_receipt": actions.capture_publish_receipt_draft,
            "scm_dispatch_evidence": actions.capture_scm_dispatch_evidence_draft,
            "startup_receipt": actions.capture_startup_receipt_draft,
            "attestation": actions.capture_attestation_draft,
        }.get(artifact)
        if capture is None:
            raise WindowsFenceCeremonyError("CEREMONY_OBSERVER_ARTIFACT_INVALID")
        try:
            draft = capture(context=context)
        except Exception as exc:
            raise WindowsFenceCeremonyError(
                "CEREMONY_OBSERVER_DRAFT_UNAVAILABLE"
            ) from exc
        if type(draft) is not bytes or not draft:
            raise WindowsFenceCeremonyError("CEREMONY_OBSERVER_DRAFT_INVALID")
        return draft

    def _reserve_event3(
        self,
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
    ) -> CeremonyStepContextV1:
        # Event 3 is an uncertainty boundary: after the call, only an exact
        # same-attempt journal query is allowed if its result is unknown.
        try:
            reservation = actions.reserve_event_3_durable_create_only(context=context)
            if (
                type(reservation) is not CeremonyReservationEvidenceV1
                or not isinstance(reservation.reservation_id, str)
                or not reservation.reservation_id
                or reservation.durable_create_only is not True
            ):
                raise WindowsFenceCeremonyError(
                    "CEREMONY_EVENT3_DURABLE_RESERVATION_REQUIRED"
                )
            self._require_event(reservation.event, sequence=3, context=context)
            return self._next_context(context, reservation.event)
        except Exception as exc:
            self._query_only_after_event3(
                actions, context=context, cause="event_3_unknown"
            )
            raise WindowsFenceCeremonyError("CEREMONY_POST_EVENT3_QUERY_ONLY") from exc

    def _append_signed_observer_event(
        self,
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
        sequence: int,
        draft: bytes,
        raw: bytes,
        schema: str,
    ) -> CeremonyEventEvidenceV1:
        evidence_raw = self._verify_observer_handoff(
            draft=draft, raw=raw, expected_schema=schema
        )
        if sequence == 5:
            action = lambda: actions.append_event_5(
                context=context, scm_dispatch_evidence_raw=evidence_raw
            )
        elif sequence == 6:
            action = lambda: actions.await_event_6(
                context=context, startup_receipt_raw=evidence_raw
            )
        elif sequence == 7:
            action = lambda: actions.await_event_7(
                context=context, attestation_raw=evidence_raw
            )
        else:
            raise WindowsFenceCeremonyError("CEREMONY_OBSERVER_EVENT_INVALID")
        return self._run_post_event3_step(
            actions,
            context=context,
            sequence=sequence,
            cause=f"event_{sequence}_unknown",
            action=action,
        )

    def _verify_restart_inputs(
        self, artifacts: Mapping[str, bytes], *, admission: Mapping[str, Any]
    ) -> None:
        if (
            "publish_receipt" not in artifacts
            or "restart_authorization" not in artifacts
        ):
            raise WindowsFenceCeremonyError("CEREMONY_LIVE_ARTIFACT_SET_REQUIRED")
        publish = self._verify_signed_publish_receipt(
            artifacts,
            preflight=admission["preflight"],
            manifest=admission["manifest"],
        )
        self._verify_signed_restart_authorization(
            artifacts,
            preflight=admission["preflight"],
            manifest=admission["manifest"],
            publish=publish,
        )

    def _dispatch_capture_and_append_event_5(
        self,
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
        signed_restart_authorization: bytes,
        artifacts: Mapping[str, bytes],
    ) -> CeremonyEventEvidenceV1:
        # Dispatch is the mutation boundary. The SCM observer may only read
        # after it; an unsigned draft never reaches the native journal.
        actions.dispatch_restart_once_for_event_5(
            context=context, signed_restart_authorization=signed_restart_authorization
        )
        scm_dispatch_evidence_raw = self._verify_observer_handoff(
            draft=actions.capture_scm_dispatch_evidence_draft(context=context),
            raw=artifacts["scm_dispatch_evidence"],
            expected_schema="windows_rpc_durable_fence_scm_dispatch_evidence_v1",
        )
        return actions.append_event_5(
            context=context,
            scm_dispatch_evidence_raw=scm_dispatch_evidence_raw,
        )

    def _capture_and_await_event_6(
        self,
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
        artifacts: Mapping[str, bytes],
    ) -> CeremonyEventEvidenceV1:
        startup_receipt_raw = self._verify_observer_handoff(
            draft=actions.capture_startup_receipt_draft(context=context),
            raw=artifacts["startup_receipt"],
            expected_schema="windows_rpc_durable_fence_startup_receipt_v1",
        )
        return actions.await_event_6(
            context=context, startup_receipt_raw=startup_receipt_raw
        )

    def _capture_and_await_event_7(
        self,
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
        artifacts: Mapping[str, bytes],
    ) -> CeremonyEventEvidenceV1:
        attestation_raw = self._verify_observer_handoff(
            draft=actions.capture_attestation_draft(context=context),
            raw=artifacts["attestation"],
            expected_schema="windows_rpc_durable_fence_foundation_attestation_v1",
        )
        return actions.await_event_7(context=context, attestation_raw=attestation_raw)

    @staticmethod
    def _next_context(
        context: CeremonyStepContextV1, event: CeremonyEventEvidenceV1
    ) -> CeremonyStepContextV1:
        return CeremonyStepContextV1(
            install_attempt_id=context.install_attempt_id,
            service_name=context.service_name,
            previous_event=event,
        )

    @staticmethod
    def _require_event(
        event: CeremonyEventEvidenceV1,
        *,
        sequence: int,
        context: CeremonyStepContextV1,
    ) -> None:
        expected_previous = (
            None
            if context.previous_event is None
            else context.previous_event.raw_sha256
        )
        if (
            type(event) is not CeremonyEventEvidenceV1
            or event.event_sequence != sequence
            or event.install_attempt_id != context.install_attempt_id
            or event.service_name != context.service_name
            or type(event.raw) is not bytes
            or not event.raw
            or event.previous_event_raw_sha256 != expected_previous
        ):
            raise WindowsFenceCeremonyError("CEREMONY_EVENT_EVIDENCE_BINDING_INVALID")

    def _run_post_event3_step(
        self,
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
        sequence: int,
        cause: str,
        action: Callable[[], CeremonyEventEvidenceV1],
    ) -> CeremonyEventEvidenceV1:
        try:
            event = action()
            self._require_event(event, sequence=sequence, context=context)
            return event
        except Exception as exc:
            self._query_only_after_event3(actions, context=context, cause=cause)
            raise WindowsFenceCeremonyError("CEREMONY_POST_EVENT3_QUERY_ONLY") from exc

    @staticmethod
    def _query_frontier(
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
    ) -> CeremonyQueryEvidenceV1:
        try:
            query = actions.query_same_attempt_only(
                context=context, cause="attempt_frontier"
            )
            if (
                type(query) is not CeremonyQueryEvidenceV1
                or query.install_attempt_id != context.install_attempt_id
                or query.service_name != context.service_name
                or type(query.raw) is not bytes
                or not query.raw
                or query.frontier_sequence not in range(8)
                or query.restart_dispatches not in (0, 1)
                or (query.frontier_sequence < 4 and query.restart_dispatches != 0)
                or (query.frontier_sequence >= 5 and query.restart_dispatches != 1)
            ):
                raise WindowsFenceCeremonyError("CEREMONY_QUERY_EVIDENCE_INVALID")
            return query
        except WindowsFenceCeremonyError:
            raise
        except Exception as exc:
            raise WindowsFenceCeremonyError("CEREMONY_ATTEMPT_QUERY_FAILED") from exc

    @staticmethod
    def _query_only_after_event3(
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
        cause: str,
    ) -> None:
        try:
            query = actions.query_same_attempt_only(context=context, cause=cause)
            if (
                type(query) is not CeremonyQueryEvidenceV1
                or query.install_attempt_id != context.install_attempt_id
                or query.service_name != context.service_name
                or type(query.raw) is not bytes
                or not query.raw
                or query.frontier_sequence < 3
                or query.frontier_sequence > 7
            ):
                raise WindowsFenceCeremonyError("CEREMONY_QUERY_EVIDENCE_INVALID")
        except Exception:  # noqa: BLE001 - no post-event-3 recovery may mutate.
            # Query failure is still terminal.  Never compensate, retry a
            # mutation, or dispatch a second restart after event 3.
            return

    def _verify_live_artifacts(
        self, artifacts: Mapping[str, bytes]
    ) -> Mapping[str, Any]:
        """Admit static signed inputs; observer handoffs arrive post-mutation."""
        required = {"zero_preflight", "manifest"}
        permitted = required | {
            "publish_receipt",
            "restart_authorization",
            "scm_dispatch_evidence",
            "startup_receipt",
            "attestation",
        }
        if (
            not required.issubset(artifacts)
            or not set(artifacts).issubset(permitted)
            or any(
                type(artifacts[name]) is not bytes or not artifacts[name]
                for name in required
            )
        ):
            raise WindowsFenceCeremonyError("CEREMONY_LIVE_ARTIFACT_SET_REQUIRED")
        if (
            hashlib.sha256(self._public_keyring_raw).hexdigest()
            != self._expected_keyring_sha256
        ):
            raise WindowsFenceCeremonyError("CEREMONY_TRUST_KEYRING_PIN_MISMATCH")
        try:
            pins = canonical_public_keyring_v1(
                self._public_keyring_raw, self._expected_keyring_sha256
            )
            preflight = require_fresh_zero_preflight_v1(
                artifacts["zero_preflight"], pin=pins.observer, now=self._now
            ).value
            manifest = verify_public_artifact_v1(
                artifacts["manifest"], pin=pins.manifest
            ).value
            preflight_sha = hashlib.sha256(artifacts["zero_preflight"]).hexdigest()
            if (
                manifest.get("schema_version")
                != "windows_rpc_durable_fence_install_manifest_v1"
                or manifest.get("preflight_receipt_raw_sha256") != preflight_sha
                or manifest.get("restart_authorized") is not False
                or manifest.get("automatic_restart_allowed") is not False
            ):
                raise OfflineSigningError("SIGNING_CHAIN_RESTART_AUTHORIZATION_INVALID")
            install_attempt_id = preflight.get("install_attempt_id")
            service_name = preflight.get("service_name")
            if (
                not isinstance(install_attempt_id, str)
                or not install_attempt_id.startswith("windows-fence-install-")
                or not isinstance(service_name, str)
                or not service_name
                or manifest.get("install_attempt_id") != install_attempt_id
                or manifest.get("service_name") != service_name
            ):
                raise OfflineSigningError("SIGNING_CHAIN_IDENTITY_MISMATCH")
        except (KeyError, OfflineSigningError, ValueError) as exc:
            raise WindowsFenceCeremonyError(
                "CEREMONY_LIVE_ARTIFACT_VERIFICATION_FAILED"
            ) from exc
        return {
            "install_attempt_id": install_attempt_id,
            "service_name": service_name,
            "preflight": preflight,
            "manifest": manifest,
        }

    def _verify_observer_handoff(
        self, *, draft: bytes, raw: bytes, expected_schema: str
    ) -> bytes:
        """Accept only the existing v1 signer output for this exact draft."""
        if type(draft) is not bytes or not draft or type(raw) is not bytes or not raw:
            raise WindowsFenceCeremonyError("CEREMONY_OBSERVER_HANDOFF_INVALID")
        try:
            pins = canonical_public_keyring_v1(
                self._public_keyring_raw, self._expected_keyring_sha256
            )
            verified = verify_public_artifact_v1(raw, pin=pins.observer).value
            unsigned = {
                key: value for key, value in verified.items() if key != "signature"
            }
            if (
                verified.get("schema_version") != expected_schema
                or canonical_json_bytes(unsigned) != draft
            ):
                raise OfflineSigningError("SIGNING_OBSERVER_HANDOFF_MISMATCH")
        except (OfflineSigningError, ValueError) as exc:
            raise WindowsFenceCeremonyError(
                "CEREMONY_OBSERVER_HANDOFF_VERIFICATION_FAILED"
            ) from exc
        return raw

    def _verify_signed_publish_receipt(
        self,
        artifacts: Mapping[str, bytes],
        *,
        preflight: Mapping[str, Any],
        manifest: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        try:
            pins = canonical_public_keyring_v1(
                self._public_keyring_raw, self._expected_keyring_sha256
            )
            publish = verify_public_artifact_v1(
                artifacts["publish_receipt"], pin=pins.observer
            ).value
            if (
                publish.get("schema_version")
                != "windows_rpc_durable_fence_publish_receipt_v1"
                or publish.get("install_manifest_raw_sha256")
                != hashlib.sha256(artifacts["manifest"]).hexdigest()
                or publish.get("preflight_receipt_raw_sha256")
                != hashlib.sha256(artifacts["zero_preflight"]).hexdigest()
                or publish.get("install_attempt_id")
                != preflight.get("install_attempt_id")
                or publish.get("service_name") != preflight.get("service_name")
                or manifest.get("install_attempt_id")
                != preflight.get("install_attempt_id")
            ):
                raise OfflineSigningError("SIGNING_CHAIN_PUBLISH_RECEIPT_INVALID")
            return publish
        except (KeyError, OfflineSigningError, ValueError) as exc:
            raise WindowsFenceCeremonyError(
                "CEREMONY_LIVE_ARTIFACT_VERIFICATION_FAILED"
            ) from exc

    def _verify_signed_restart_authorization(
        self,
        artifacts: Mapping[str, bytes],
        *,
        preflight: Mapping[str, Any],
        manifest: Mapping[str, Any],
        publish: Mapping[str, Any],
    ) -> None:
        try:
            pins = canonical_public_keyring_v1(
                self._public_keyring_raw, self._expected_keyring_sha256
            )
            restart = verify_public_artifact_v1(
                artifacts["restart_authorization"], pin=pins.restart
            ).value
            if (
                restart.get("schema_version")
                != "windows_rpc_durable_fence_restart_authorization_v1"
                or restart.get("install_manifest_raw_sha256")
                != hashlib.sha256(artifacts["manifest"]).hexdigest()
                or restart.get("preflight_receipt_raw_sha256")
                != hashlib.sha256(artifacts["zero_preflight"]).hexdigest()
                or restart.get("publish_receipt_raw_sha256")
                != hashlib.sha256(artifacts["publish_receipt"]).hexdigest()
                or restart.get("install_attempt_id")
                != preflight.get("install_attempt_id")
                or restart.get("service_name") != preflight.get("service_name")
                or publish.get("install_attempt_id")
                != preflight.get("install_attempt_id")
                or manifest.get("install_attempt_id")
                != preflight.get("install_attempt_id")
                or restart.get("restart_authorized") is not True
                or restart.get("automatic_restart_allowed") is not False
                or restart.get("maximum_restart_dispatches") != 1
                or restart.get("dispatch_consumption_required") is not True
                or not self._valid_restart_window(restart)
            ):
                raise OfflineSigningError("SIGNING_CHAIN_RESTART_AUTHORIZATION_INVALID")
        except (KeyError, OfflineSigningError, ValueError) as exc:
            raise WindowsFenceCeremonyError(
                "CEREMONY_LIVE_ARTIFACT_VERIFICATION_FAILED"
            ) from exc

    def _valid_restart_window(self, restart: Mapping[str, Any]) -> bool:
        try:
            not_before = datetime.fromisoformat(
                str(restart["not_before_utc"]).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
            expires = datetime.fromisoformat(
                str(restart["expires_at_utc"]).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except (TypeError, ValueError):
            return False
        return not_before <= self._now.astimezone(timezone.utc) < expires

    def _verify_closure(self, artifacts: Mapping[str, bytes]) -> Mapping[str, object]:
        if (
            hashlib.sha256(self._public_keyring_raw).hexdigest()
            != self._expected_keyring_sha256
        ):
            raise WindowsFenceCeremonyError("CEREMONY_TRUST_KEYRING_PIN_MISMATCH")
        if set(artifacts) != set(CHAIN_ORDER) or any(
            type(raw) is not bytes for raw in artifacts.values()
        ):
            raise WindowsFenceCeremonyError("CEREMONY_SIGNED_ARTIFACT_SET_REQUIRED")
        try:
            return verify_signing_closure_chain_v1(
                artifacts, public_keyring_raw=self._public_keyring_raw, now=self._now
            )
        except OfflineSigningError as exc:
            raise WindowsFenceCeremonyError(
                "CEREMONY_SIGNED_ARTIFACT_VERIFICATION_FAILED"
            ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-dir", type=Path, required=True)
    parser.add_argument("--now-utc", required=True)
    options = parser.parse_args(argv)
    try:
        now = datetime.fromisoformat(options.now_utc.replace("Z", "+00:00"))
        anchor = load_production_installer_trust_anchor_v1()
        public_keyring_raw = anchor.keyring_path.read_bytes()
        validate_anchor_keyring_bytes_v1(anchor, public_keyring_raw)
        artifacts = {
            name: (options.inputs_dir / f"{name}.json").read_bytes()
            for name in CHAIN_ORDER
        }
        result = WindowsFenceCeremonyRunnerV1(
            public_keyring_raw=public_keyring_raw,
            expected_public_keyring_sha256=anchor.keyring_raw_sha256,
            now=now,
        ).verify_dry_run(artifacts)
    except (OSError, ValueError, WindowsFenceCeremonyError) as exc:
        parser.error(f"dry-run ceremony verification failed: {exc}")
    print(canonical_json_bytes(result.__dict__).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CeremonyEventEvidenceV1",
    "CeremonyQueryEvidenceV1",
    "CeremonyReservationEvidenceV1",
    "CeremonyResultV1",
    "CeremonyStepContextV1",
    "NativeWindowsFenceCeremonyActionsV1",
    "WindowsFenceCeremonyActionsV1",
    "WindowsFenceCeremonyError",
    "WindowsFenceCeremonyRunnerV1",
]
