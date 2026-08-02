from __future__ import annotations

from threading import RLock
from typing import Any

from app.schemas.commodity_c_fast_execution_quality_evidence_export import (
    CFastExecutionQualityEvidenceExportDTO,
)
from app.services.commodity_c_fast_execution_quality_evidence_export import (
    build_execution_quality_evidence_export,
)
from app.services.commodity_c_fast_execution_quality_sidecar import (
    OfflineExecutionQualitySidecar,
)


class CFastExecutionQualityReadonlyRepositoryError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CommodityCFastExecutionQualityReadonlyRepository:
    """Failure-isolated exact projection over one fixed durable sidecar.

    The repository owns no callback-shaped alternate state path. Recovery
    always replays the bound ``OfflineExecutionQualitySidecar`` through the
    existing strongly typed evidence-export builder. A replay or validation
    failure trips only this repository until an explicit lifecycle recovery.
    """

    def __init__(self, source: OfflineExecutionQualitySidecar) -> None:
        if type(source) is not OfflineExecutionQualitySidecar:
            raise CFastExecutionQualityReadonlyRepositoryError(
                "READONLY_REPOSITORY_SOURCE_TYPE_INVALID"
            )
        self._source = source
        self._lock = RLock()
        self._blocked = False
        self._last_error: str | None = None
        self._generation = 0
        self._snapshot: CFastExecutionQualityEvidenceExportDTO | None = None

    def is_bound_to(self, source: OfflineExecutionQualitySidecar) -> bool:
        return self._source is source

    def recover(self) -> dict[str, object]:
        with self._lock:
            try:
                snapshot = build_execution_quality_evidence_export(self._source)
            except Exception as exc:
                self._blocked = True
                self._snapshot = None
                self._last_error = str(getattr(exc, "code", type(exc).__name__))
                return self._status_locked()
            self._snapshot = snapshot
            self._generation += 1
            self._blocked = False
            self._last_error = None
            return self._status_locked()

    def intents(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            snapshot = self._require_snapshot_locked()
            return tuple(row.model_dump(mode="json") for row in snapshot.intents)

    def execution_quality(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            snapshot = self._require_snapshot_locked()
            return tuple(row.model_dump(mode="json") for row in snapshot.evidence)

    def status(self) -> dict[str, object]:
        with self._lock:
            return self._status_locked()

    def _require_snapshot_locked(
        self,
    ) -> CFastExecutionQualityEvidenceExportDTO:
        if self._blocked:
            raise CFastExecutionQualityReadonlyRepositoryError(
                "READONLY_REPOSITORY_BLOCKED_REQUIRES_EXPLICIT_RECOVERY"
            )
        if self._snapshot is None:
            raise CFastExecutionQualityReadonlyRepositoryError(
                "READONLY_REPOSITORY_NOT_RECOVERED"
            )
        return self._snapshot

    def _status_locked(self) -> dict[str, object]:
        snapshot = self._snapshot
        return {
            "schema_version": (
                "commodity_c_fast_execution_quality_readonly_repository_status_v1"
            ),
            "repository_state": (
                "BLOCKED_FAIL_CLOSED"
                if self._blocked
                else (
                    "RECOVERED_READONLY"
                    if snapshot is not None
                    else "CREATED_NOT_RECOVERED"
                )
            ),
            "blocked_fail_closed": self._blocked,
            "last_error": self._last_error,
            "recovery_generation": self._generation,
            "intent_count": (snapshot.intent_count if snapshot is not None else None),
            "execution_quality_record_count": (
                snapshot.evidence_record_count if snapshot is not None else None
            ),
            "source_journal_record_count": (
                snapshot.source_journal_record_count if snapshot is not None else None
            ),
            "source_journal_tip_record_hash": (
                snapshot.source_journal_tip_record_hash
                if snapshot is not None
                else None
            ),
            "projection_schema_version": (
                snapshot.schema_version if snapshot is not None else None
            ),
            "exact_contracts": (
                list(snapshot.exact_contracts) if snapshot is not None else []
            ),
            "read_only": True,
            "questdb_connected": False,
            "database_mutation_authorized": False,
            "runtime_active": False,
            "execution_quality_implemented": False,
            "orders_sent": 0,
            "positions_modified": 0,
        }


__all__ = [
    "CFastExecutionQualityReadonlyRepositoryError",
    "CommodityCFastExecutionQualityReadonlyRepository",
]
