from __future__ import annotations

import json
from collections.abc import Callable
from threading import RLock
from typing import Any

from app.services.commodity_c_fast_execution_quality_sidecar import SidecarState


class CFastExecutionQualityReadonlyRepositoryError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _detached(value: object) -> Any:
    return json.loads(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


class CommodityCFastExecutionQualityReadonlyRepository:
    """Failure-isolated read projection over a durable sidecar state loader.

    The repository receives only a zero-argument read callback. It cannot
    append journal rows, connect to QuestDB or acquire order/account handles.
    A loader failure trips only this repository until explicit recovery.
    """

    def __init__(self, state_loader: Callable[[], SidecarState]) -> None:
        if not callable(state_loader):
            raise CFastExecutionQualityReadonlyRepositoryError(
                "READONLY_REPOSITORY_LOADER_INVALID"
            )
        self._state_loader = state_loader
        self._lock = RLock()
        self._blocked = False
        self._last_error: str | None = None
        self._generation = 0
        self._snapshot: dict[str, Any] | None = None

    def recover(self) -> dict[str, object]:
        with self._lock:
            try:
                state = self._state_loader()
                if type(state) is not SidecarState:
                    raise CFastExecutionQualityReadonlyRepositoryError(
                        "READONLY_REPOSITORY_STATE_TYPE_INVALID"
                    )
                snapshot = self._project(state)
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
            return tuple(_detached(row) for row in snapshot["intents"])

    def execution_quality(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            snapshot = self._require_snapshot_locked()
            return tuple(_detached(row) for row in snapshot["execution_quality"])

    def status(self) -> dict[str, object]:
        with self._lock:
            return self._status_locked()

    def _require_snapshot_locked(self) -> dict[str, Any]:
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
            "intent_count": (
                len(snapshot["intents"]) if snapshot is not None else None
            ),
            "execution_quality_record_count": (
                len(snapshot["execution_quality"]) if snapshot is not None else None
            ),
            "read_only": True,
            "questdb_connected": False,
            "database_mutation_authorized": False,
            "runtime_active": False,
            "execution_quality_implemented": False,
            "orders_sent": 0,
            "positions_modified": 0,
        }

    @staticmethod
    def _project(state: SidecarState) -> dict[str, Any]:
        intents: list[dict[str, Any]] = []
        for intent_id, record in sorted(
            state.intents.items(),
            key=lambda item: item[1].sequence,
        ):
            anchor = state.anchors.get(intent_id)
            intents.append(
                {
                    "intent_id": intent_id,
                    "intent_record_hash": record.record_hash,
                    "anchor_record_hash": (
                        anchor.record_hash if anchor is not None else None
                    ),
                    "durably_created_at_utc": (
                        anchor.payload["durably_created_at_utc"]
                        if anchor is not None
                        else None
                    ),
                    "intent": _detached(record.payload["intent"]),
                }
            )
        evidence = [
            {
                "intent_id": str(record.payload["intent_id"]),
                "target_key": str(record.payload["target_key"]),
                "completion_state": str(record.payload["completion_state"]),
                "record_hash": record.record_hash,
                "payload": _detached(record.payload),
            }
            for record in sorted(
                state.evidence.values(),
                key=lambda item: item.sequence,
            )
        ]
        return {
            "intents": intents,
            "execution_quality": evidence,
        }


__all__ = [
    "CFastExecutionQualityReadonlyRepositoryError",
    "CommodityCFastExecutionQualityReadonlyRepository",
]
