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
from .installer_trust_anchor_v1 import (
    canonical_public_keyring_v1,
    load_production_installer_trust_anchor_v1,
    validate_anchor_keyring_bytes_v1,
)
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
    ) -> CeremonyEventEvidenceV1: ...

    def await_event_6(
        self, *, context: CeremonyStepContextV1
    ) -> CeremonyEventEvidenceV1: ...

    def await_event_7(
        self, *, context: CeremonyStepContextV1
    ) -> CeremonyEventEvidenceV1: ...

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


class WindowsFenceCeremonyRunnerV1:
    """Advance 1→7 once, turning every post-event-3 uncertainty into query-only."""

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
        if frontier.frontier_sequence >= 3:
            raise WindowsFenceCeremonyError("CEREMONY_POST_EVENT3_QUERY_ONLY")
        try:
            event_1, event_2 = actions.run_events_1_to_2(context=context)
            self._require_event(event_1, sequence=1, context=context)
            context = self._next_context(context, event_1)
            self._require_event(event_2, sequence=2, context=context)
            context = self._next_context(context, event_2)
        except Exception as exc:
            raise WindowsFenceCeremonyError("CEREMONY_PRE_EVENT3_FAILED") from exc

        # The event-3 call itself is an uncertainty boundary: a timeout can
        # mean its durable create-only reservation committed remotely.
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
            event_3 = reservation.event
            self._require_event(event_3, sequence=3, context=context)
            context = self._next_context(context, event_3)
        except Exception as exc:
            self._query_only_after_event3(
                actions, context=context, cause="event_3_unknown"
            )
            raise WindowsFenceCeremonyError("CEREMONY_POST_EVENT3_QUERY_ONLY") from exc

        event_4 = self._run_post_event3_step(
            actions,
            context=context,
            sequence=4,
            cause="event_4_unknown",
            action=lambda: actions.run_event_4(context=context),
        )
        context = self._next_context(context, event_4)
        event_5 = self._run_post_event3_step(
            actions,
            context=context,
            sequence=5,
            cause="event_5_restart_unknown",
            action=lambda: self._reserve_and_dispatch_event_5(
                actions,
                context=context,
                signed_restart_authorization=artifacts["restart_authorization"],
            ),
        )
        context = self._next_context(context, event_5)
        event_6 = self._run_post_event3_step(
            actions,
            context=context,
            sequence=6,
            cause="event_6_unknown",
            action=lambda: actions.await_event_6(context=context),
        )
        context = self._next_context(context, event_6)
        self._run_post_event3_step(
            actions,
            context=context,
            sequence=7,
            cause="event_7_unknown",
            action=lambda: actions.await_event_7(context=context),
        )
        return CeremonyResultV1(
            mode="live",
            install_attempt_id=context.install_attempt_id,
            service_name=context.service_name,
            completed_events=(1, 2, 3, 4, 5, 6, 7),
            restart_dispatches=1,
        )

    def _reserve_and_dispatch_event_5(
        self,
        actions: WindowsFenceCeremonyActionsV1,
        *,
        context: CeremonyStepContextV1,
        signed_restart_authorization: bytes,
    ) -> CeremonyEventEvidenceV1:
        return actions.dispatch_restart_once_for_event_5(
            context=context, signed_restart_authorization=signed_restart_authorization
        )

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
        """Admit exactly the signed v1 inputs available before event 1.

        Post-restart receipts and all event artifacts are intentionally absent:
        they must be produced through the installer journal, not pre-supplied
        to the runner.
        """
        required = {
            "zero_preflight",
            "manifest",
            "publish_receipt",
            "restart_authorization",
        }
        if set(artifacts) != required or any(
            type(raw) is not bytes or not raw for raw in artifacts.values()
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
            publish = verify_public_artifact_v1(
                artifacts["publish_receipt"], pin=pins.observer
            ).value
            restart = verify_public_artifact_v1(
                artifacts["restart_authorization"], pin=pins.restart
            ).value
            preflight_sha = hashlib.sha256(artifacts["zero_preflight"]).hexdigest()
            manifest_sha = hashlib.sha256(artifacts["manifest"]).hexdigest()
            publish_sha = hashlib.sha256(artifacts["publish_receipt"]).hexdigest()
            if (
                manifest.get("schema_version")
                != "windows_rpc_durable_fence_install_manifest_v1"
                or publish.get("schema_version")
                != "windows_rpc_durable_fence_publish_receipt_v1"
                or restart.get("schema_version")
                != "windows_rpc_durable_fence_restart_authorization_v1"
                or manifest.get("preflight_receipt_raw_sha256") != preflight_sha
                or publish.get("install_manifest_raw_sha256") != manifest_sha
                or publish.get("preflight_receipt_raw_sha256") != preflight_sha
                or restart.get("install_manifest_raw_sha256") != manifest_sha
                or restart.get("preflight_receipt_raw_sha256") != preflight_sha
                or restart.get("publish_receipt_raw_sha256") != publish_sha
                or manifest.get("restart_authorized") is not False
                or manifest.get("automatic_restart_allowed") is not False
                or restart.get("restart_authorized") is not True
                or restart.get("automatic_restart_allowed") is not False
                or restart.get("maximum_restart_dispatches") != 1
                or restart.get("dispatch_consumption_required") is not True
                or not self._valid_restart_window(restart)
            ):
                raise OfflineSigningError("SIGNING_CHAIN_RESTART_AUTHORIZATION_INVALID")
            install_attempt_id = preflight.get("install_attempt_id")
            service_name = preflight.get("service_name")
            if (
                not isinstance(install_attempt_id, str)
                or not install_attempt_id.startswith("windows-fence-install-")
                or not isinstance(service_name, str)
                or not service_name
                or any(
                    item.get("install_attempt_id") != install_attempt_id
                    or item.get("service_name") != service_name
                    for item in (manifest, publish, restart)
                )
            ):
                raise OfflineSigningError("SIGNING_CHAIN_IDENTITY_MISMATCH")
        except (KeyError, OfflineSigningError, ValueError) as exc:
            raise WindowsFenceCeremonyError(
                "CEREMONY_LIVE_ARTIFACT_VERIFICATION_FAILED"
            ) from exc
        return {"install_attempt_id": install_attempt_id, "service_name": service_name}

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
    "WindowsFenceCeremonyActionsV1",
    "WindowsFenceCeremonyError",
    "WindowsFenceCeremonyRunnerV1",
]
