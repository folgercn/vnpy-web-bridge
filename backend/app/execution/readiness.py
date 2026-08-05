"""Bounded, read-only gateway readiness evidence for Execution."""

from __future__ import annotations

from datetime import datetime
from queue import Empty, Queue
from threading import Lock, Thread
from typing import TYPE_CHECKING, Any

from .errors import ExecutionError, GatewayTimeout, GatewayUnavailable, SnapshotRejected
from .models import parse_utc, utc_now, validate_identifier

if TYPE_CHECKING:
    from .gateway import GatewaySnapshot
    from .orchestrator import ExecutionOrchestrator


class GatewayReadinessProbe:
    """Allow at most one bounded read-only gateway probe at a time."""

    def __init__(
        self, service: ExecutionOrchestrator, *, timeout_seconds: float
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 10:
            raise ValueError("readiness timeout must be within (0, 10] seconds")
        self._service = service
        self._timeout_seconds = timeout_seconds
        self._inflight = Lock()

    def probe(self) -> GatewaySnapshot:
        if not self._inflight.acquire(blocking=False):
            raise GatewayUnavailable("a gateway readiness probe is already in flight")
        outcome: Queue[tuple[bool, Any]] = Queue(maxsize=1)

        def worker() -> None:
            try:
                outcome.put((True, self._service.gateway.snapshot()))
            except (
                ExecutionError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ) as exc:
                outcome.put((False, exc))
            finally:
                self._inflight.release()

        Thread(
            target=worker,
            name="execution-gateway-readiness",
            daemon=True,
        ).start()
        try:
            succeeded, value = outcome.get(timeout=self._timeout_seconds)
        except Empty as exc:
            raise GatewayTimeout("gateway readiness probe timed out") from exc
        if not succeeded:
            if isinstance(value, (GatewayTimeout, GatewayUnavailable)):
                raise value
            raise GatewayUnavailable(
                f"gateway readiness probe failed: {value}"
            ) from value
        return self._validate(value)

    def _validate(self, value: Any) -> GatewaySnapshot:
        snapshot = self._service._coerce_snapshot(value)
        try:
            validate_identifier(snapshot.snapshot_id, "snapshot_id")
            parse_utc(snapshot.observed_at, field_name="snapshot.observed_at")
            observed_at = datetime.fromisoformat(
                snapshot.observed_at.removesuffix("Z") + "+00:00"
            )
        except (TypeError, ValueError) as exc:
            raise SnapshotRejected(
                "gateway readiness snapshot identity/time is invalid"
            ) from exc
        if not isinstance(snapshot.connected, bool) or snapshot.connected is not True:
            raise SnapshotRejected("gateway readiness snapshot is disconnected")
        if not isinstance(snapshot.fresh, bool) or snapshot.fresh is not True:
            raise SnapshotRejected("gateway readiness snapshot is not fresh")
        now = utc_now()
        if observed_at > now or (now - observed_at).total_seconds() > 60:
            raise SnapshotRejected("gateway readiness snapshot timestamp is stale")
        if snapshot.account_scope != self._service.scope:
            raise SnapshotRejected("gateway readiness account scope mismatch")
        if snapshot.environment != self._service.environment:
            raise SnapshotRejected("gateway readiness environment mismatch")
        if (
            isinstance(snapshot.generation, bool)
            or not isinstance(snapshot.generation, int)
            or snapshot.generation < 0
        ):
            raise SnapshotRejected("gateway readiness generation is invalid")
        durable_generation = self._service.repository.snapshot()["broker"]["generation"]
        if snapshot.generation < durable_generation:
            raise SnapshotRejected("gateway readiness generation regressed")
        return snapshot


__all__ = ["GatewayReadinessProbe"]
