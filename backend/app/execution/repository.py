"""Durable execution state repositories.

The production Phase A deployment maps this interface to the Postgres
``execution`` schema.  For offline work and unit tests we provide an atomic
JSON-file implementation with the same compare-and-swap semantics.  It is
deliberately boring: every mutation is serialized, fsynced and replaced as a
whole, so a process restart cannot turn an uncertain write into an apparently
safe empty state.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

try:  # POSIX deployment (Linux/macOS); in-memory repositories do not need it.
    import fcntl
except ImportError:  # pragma: no cover - Windows tooling uses the in-memory store
    fcntl = None  # type: ignore[assignment]

from .errors import ExpectedVersionConflict, RepositoryUnavailableError
from .models import (
    EPOCH_TIMESTAMP,
    IDEMPOTENCY_RE,
    IDENTIFIER_RE,
    SHA256_RE,
    UNKNOWN_ID,
    UTC_RE,
    AuthorityState,
    BrokerState,
    PlanState,
    ReconciliationState,
    format_utc,
    sha256_json,
)


def _state_digest(state: Mapping[str, Any]) -> str:
    candidate = deepcopy(dict(state))
    candidate.pop("state_hash", None)
    try:
        return sha256_json(candidate)
    except Exception as exc:
        raise RepositoryUnavailableError(
            "durable state cannot be canonically hashed"
        ) from exc


def _require_log_timestamp(value: Any, field: str) -> None:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise RepositoryUnavailableError(f"durable log {field} is invalid")


def _validate_receipt_entry(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise RepositoryUnavailableError("durable receipt is invalid")
    required = {
        "service",
        "idempotency_key",
        "command_hash",
        "command_id",
        "correlation_id",
        "actor",
        "status",
        "state_version",
        "result",
        "observed_at",
    }
    if set(value) != required:
        raise RepositoryUnavailableError("durable receipt fields are invalid")
    if not isinstance(value["service"], str) or not IDENTIFIER_RE.fullmatch(
        value["service"]
    ):
        raise RepositoryUnavailableError("durable receipt service is invalid")
    if not isinstance(value["idempotency_key"], str) or not IDEMPOTENCY_RE.fullmatch(
        value["idempotency_key"]
    ):
        raise RepositoryUnavailableError("durable receipt idempotency key is invalid")
    for field in ("command_hash",):
        if not isinstance(value[field], str) or not SHA256_RE.fullmatch(value[field]):
            raise RepositoryUnavailableError(f"durable receipt {field} is invalid")
    for field in ("command_id", "correlation_id"):
        if not isinstance(value[field], str) or not IDENTIFIER_RE.fullmatch(
            value[field]
        ):
            raise RepositoryUnavailableError(f"durable receipt {field} is invalid")
    actor = value["actor"]
    if not isinstance(actor, Mapping) or set(actor) != {
        "service",
        "principal",
        "operator",
        "role",
    }:
        raise RepositoryUnavailableError("durable receipt actor is invalid")
    if any(not isinstance(actor[field], str) or not actor[field] for field in actor):
        raise RepositoryUnavailableError("durable receipt actor is invalid")
    if value["status"] not in {"COMPLETED", "REJECTED"}:
        raise RepositoryUnavailableError("durable receipt status is invalid")
    if (
        isinstance(value["state_version"], bool)
        or not isinstance(value["state_version"], int)
        or value["state_version"] < 1
    ):
        raise RepositoryUnavailableError("durable receipt state version is invalid")
    if not isinstance(value["result"], Mapping):
        raise RepositoryUnavailableError("durable receipt result is invalid")
    _require_log_timestamp(value["observed_at"], "observed_at")


def _validate_audit_entry(value: Any) -> None:
    if not isinstance(value, Mapping) or not isinstance(value.get("kind"), str):
        raise RepositoryUnavailableError("durable audit entry is invalid")
    kind = value["kind"]
    if kind == "command_receipt":
        payload = dict(value)
        payload.pop("kind", None)
        _validate_receipt_entry(payload)
        return
    schemas = {
        "reconcile_rejected": {"kind", "reason", "observed_at"},
        "cancel_rejected": {"kind", "target_intent_id", "reason", "observed_at"},
        "emergency_stop": {"kind", "reason", "observed_at"},
        "fail_closed_halt": {"kind", "reason", "observed_at"},
        "test": {"kind", "observed_at"},
    }
    required = schemas.get(kind)
    if required is None or set(value) != required:
        raise RepositoryUnavailableError("durable audit entry fields are invalid")
    _require_log_timestamp(value["observed_at"], "observed_at")
    if "reason" in value and (
        not isinstance(value["reason"], str) or not value["reason"]
    ):
        raise RepositoryUnavailableError("durable audit reason is invalid")
    if "target_intent_id" in value and (
        not isinstance(value["target_intent_id"], str)
        or not IDENTIFIER_RE.fullmatch(value["target_intent_id"])
    ):
        raise RepositoryUnavailableError("durable audit target is invalid")


def _validate_archive_entry(value: Any) -> None:
    if not isinstance(value, Mapping) or not isinstance(value.get("kind"), str):
        raise RepositoryUnavailableError("durable terminal archive entry is invalid")
    kind = value["kind"]
    if kind == "plan_terminal":
        if set(value) != {
            "kind",
            "plan_id",
            "plan_hash",
            "plan_version",
            "archived_at",
        }:
            raise RepositoryUnavailableError("durable plan archive fields are invalid")
        if not isinstance(value["plan_id"], str) or not IDENTIFIER_RE.fullmatch(
            value["plan_id"]
        ):
            raise RepositoryUnavailableError("durable plan archive id is invalid")
        if not isinstance(value["plan_hash"], str) or not SHA256_RE.fullmatch(
            value["plan_hash"]
        ):
            raise RepositoryUnavailableError("durable plan archive hash is invalid")
        if (
            isinstance(value["plan_version"], bool)
            or not isinstance(value["plan_version"], int)
            or value["plan_version"] < 0
        ):
            raise RepositoryUnavailableError("durable plan archive version is invalid")
        _require_log_timestamp(value["archived_at"], "archived_at")
        return
    if kind == "intent_terminal":
        if set(value) != {
            "kind",
            "intent_id",
            "idempotency_key",
            "broker_order_id",
            "archived_at",
        }:
            raise RepositoryUnavailableError(
                "durable intent archive fields are invalid"
            )
        if not isinstance(value["intent_id"], str) or not IDENTIFIER_RE.fullmatch(
            value["intent_id"]
        ):
            raise RepositoryUnavailableError("durable intent archive id is invalid")
        if not isinstance(
            value["idempotency_key"], str
        ) or not IDEMPOTENCY_RE.fullmatch(value["idempotency_key"]):
            raise RepositoryUnavailableError("durable intent archive key is invalid")
        if value["broker_order_id"] is not None and not isinstance(
            value["broker_order_id"], str
        ):
            raise RepositoryUnavailableError(
                "durable intent archive broker id is invalid"
            )
        _require_log_timestamp(value["archived_at"], "archived_at")
        return
    if kind == "final_plan_completed":
        if set(value) != {
            "kind",
            "plan_id",
            "plan_hash",
            "plan_version",
            "receipt_id",
            "final_position_hash",
            "archived_at",
        }:
            raise RepositoryUnavailableError(
                "durable final plan archive fields are invalid"
            )
        for field in ("plan_id", "receipt_id"):
            if not isinstance(value[field], str) or not IDENTIFIER_RE.fullmatch(
                value[field]
            ):
                raise RepositoryUnavailableError(
                    f"durable final plan archive {field} is invalid"
                )
        for field in ("plan_hash", "final_position_hash"):
            if not isinstance(value[field], str) or not SHA256_RE.fullmatch(
                value[field]
            ):
                raise RepositoryUnavailableError(
                    f"durable final plan archive {field} is invalid"
                )
        if (
            isinstance(value["plan_version"], bool)
            or not isinstance(value["plan_version"], int)
            or value["plan_version"] < 0
        ):
            raise RepositoryUnavailableError(
                "durable final plan archive version is invalid"
            )
        _require_log_timestamp(value["archived_at"], "archived_at")
        return
    raise RepositoryUnavailableError("durable terminal archive kind is invalid")


def _initial_state(scope: str) -> dict[str, Any]:
    state = {
        "schema_version": "execution_durable_state_v1",
        "state_version": 0,
        "lifecycle": "STARTING",
        "authority": AuthorityState().as_dict(),
        "plan": PlanState().as_dict(),
        "send_intents": {},
        "intent_keys": {},
        "unknown_outcomes": {},
        "reconciliation": ReconciliationState().as_dict(),
        "broker": BrokerState().as_dict(),
        "lease": {
            "scope": scope,
            "owner_id": "",
            "epoch": 0,
            "fencing_token": 0,
            "lease_expires_at": EPOCH_TIMESTAMP,
            "instance_id": "",
        },
        "receipts": {},
        "audit": [],
        "terminal_archive": [],
    }
    state["previous_state_hash"] = ""
    state["state_hash"] = _state_digest(state)
    return state


def _validate_state(
    raw: Any, scope: str, *, verify_hash: bool = True
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise RepositoryUnavailableError("durable state is not an object")
    state = deepcopy(dict(raw))
    if state.get("schema_version") != "execution_durable_state_v1":
        raise RepositoryUnavailableError("durable state schema version is unknown")
    # A malformed/unknown state is never silently interpreted as empty.  Keep a
    # small compatibility allowance for files created by early offline tools,
    # but require every safety-critical section to exist and have the expected
    # object shape.
    required_sections = {
        "state_version",
        "lifecycle",
        "authority",
        "plan",
        "send_intents",
        "intent_keys",
        "unknown_outcomes",
        "reconciliation",
        "broker",
        "lease",
        "receipts",
        "audit",
        "terminal_archive",
        "previous_state_hash",
        "state_hash",
    }
    missing = required_sections.difference(state)
    if missing:
        raise RepositoryUnavailableError(
            f"durable state missing safety section(s): {', '.join(sorted(missing))}"
        )
    exact_sections = required_sections | {"schema_version"}
    if set(state) != exact_sections:
        raise RepositoryUnavailableError("durable state fields are not exact")
    if isinstance(state.get("state_version"), bool) or not isinstance(
        state["state_version"], int
    ):
        raise RepositoryUnavailableError("durable state version is invalid")
    if state["state_version"] < 0:
        raise RepositoryUnavailableError("durable state version is negative")
    if not isinstance(state["lease"], Mapping):
        raise RepositoryUnavailableError("durable lease is invalid")
    if state["lease"].get("scope") != scope:
        raise RepositoryUnavailableError(
            "durable lease scope does not match repository"
        )
    for section in ("authority", "plan", "reconciliation", "broker"):
        if not isinstance(state.get(section), Mapping):
            raise RepositoryUnavailableError(f"durable {section} is invalid")
    for section in ("send_intents", "intent_keys", "unknown_outcomes", "receipts"):
        if not isinstance(state.get(section), Mapping):
            raise RepositoryUnavailableError(f"durable {section} is invalid")
    for section in ("audit", "terminal_archive"):
        if not isinstance(state.get(section), list):
            raise RepositoryUnavailableError(f"durable {section} is invalid")
    for entry in state["audit"]:
        _validate_audit_entry(entry)
    for entry in state["terminal_archive"]:
        _validate_archive_entry(entry)
    lifecycle_values = {
        "STARTING",
        "READY",
        "DEGRADED",
        "DRAINING",
        "HALTED_RECONCILE_REQUIRED",
        "HALTED_UNKNOWN_OUTCOME",
        "STOPPING",
    }
    if state.get("lifecycle") not in lifecycle_values:
        raise RepositoryUnavailableError("durable lifecycle is unknown")
    if state["authority"].get("state") not in {
        "DISABLED",
        "ENABLED",
        "EXPIRED",
        "REVOKED",
        "UNKNOWN",
    }:
        raise RepositoryUnavailableError("durable authority state is unknown")
    if state["plan"].get("state") not in {
        "IDLE",
        "PREVIEWED",
        "ACTIVE",
        "STOPPING",
        "TERMINAL",
        "UNKNOWN",
    }:
        raise RepositoryUnavailableError("durable plan state is unknown")
    if state["reconciliation"].get("state") not in {
        "NOT_REQUIRED",
        "REQUIRED",
        "IN_PROGRESS",
        "RECONCILED",
        "UNKNOWN",
    }:
        raise RepositoryUnavailableError("durable reconciliation state is unknown")
    authority = state["authority"]
    if set(authority) != {"state", "artifact_id", "artifact_hash", "expires_at"}:
        raise RepositoryUnavailableError("durable authority fields are invalid")
    if not isinstance(authority.get("artifact_id"), str) or not IDENTIFIER_RE.fullmatch(
        authority["artifact_id"]
    ):
        raise RepositoryUnavailableError("durable authority artifact id is invalid")
    if not isinstance(authority.get("artifact_hash"), str) or not SHA256_RE.fullmatch(
        authority["artifact_hash"]
    ):
        raise RepositoryUnavailableError("durable authority hash is invalid")
    if not isinstance(authority.get("expires_at"), str) or not UTC_RE.fullmatch(
        authority["expires_at"]
    ):
        raise RepositoryUnavailableError("durable authority expiry is invalid")
    plan = state["plan"]
    if set(plan) != {
        "state",
        "plan_id",
        "plan_hash",
        "version",
        "preview_mode",
        "preview_receipt_id",
        "preview_receipt_sha256",
        "preview_artifact_id",
        "preview_artifact_sha256",
    }:
        raise RepositoryUnavailableError("durable plan fields are invalid")
    if not isinstance(plan.get("plan_id"), str) or not IDENTIFIER_RE.fullmatch(
        plan["plan_id"]
    ):
        raise RepositoryUnavailableError("durable plan id is invalid")
    if not isinstance(plan.get("plan_hash"), str) or not SHA256_RE.fullmatch(
        plan["plan_hash"]
    ):
        raise RepositoryUnavailableError("durable plan hash is invalid")
    if (
        isinstance(plan.get("version"), bool)
        or not isinstance(plan.get("version"), int)
        or plan["version"] < 0
    ):
        raise RepositoryUnavailableError("durable plan version is invalid")
    if plan.get("preview_mode") not in {"", "offline_preview", "simnow_preview"}:
        raise RepositoryUnavailableError("durable preview mode is invalid")
    if not isinstance(plan.get("preview_receipt_id"), str) or not IDENTIFIER_RE.fullmatch(
        plan["preview_receipt_id"]
    ):
        raise RepositoryUnavailableError("durable preview receipt id is invalid")
    for field in ("preview_receipt_sha256", "preview_artifact_sha256"):
        if not isinstance(plan.get(field), str) or not SHA256_RE.fullmatch(plan[field]):
            raise RepositoryUnavailableError(f"durable {field} is invalid")
    if not isinstance(plan.get("preview_artifact_id"), str) or not IDENTIFIER_RE.fullmatch(
        plan["preview_artifact_id"]
    ):
        raise RepositoryUnavailableError("durable preview artifact id is invalid")
    preview_defaults = (
        plan["preview_receipt_id"] == UNKNOWN_ID
        and plan["preview_receipt_sha256"] == "0" * 64
        and plan["preview_artifact_id"] == UNKNOWN_ID
        and plan["preview_artifact_sha256"] == "0" * 64
    )
    if plan["preview_mode"] == "simnow_preview" and preview_defaults:
        raise RepositoryUnavailableError("SIMNOW preview is missing custody provenance")
    if plan["preview_mode"] != "simnow_preview" and not preview_defaults:
        raise RepositoryUnavailableError("non-SIMNOW preview retains custody provenance")
    lease = state["lease"]
    if set(lease) != {
        "scope",
        "owner_id",
        "epoch",
        "fencing_token",
        "lease_expires_at",
        "instance_id",
    }:
        raise RepositoryUnavailableError("durable lease fields are invalid")
    for field in ("epoch", "fencing_token"):
        value = lease.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RepositoryUnavailableError(f"durable lease {field} is invalid")
    expiry = lease.get("lease_expires_at")
    if not isinstance(expiry, str) or not UTC_RE.fullmatch(expiry):
        raise RepositoryUnavailableError("durable lease expiry is invalid")
    owner = lease.get("owner_id")
    if owner and (not isinstance(owner, str) or not IDENTIFIER_RE.fullmatch(owner)):
        raise RepositoryUnavailableError("durable lease owner is invalid")
    instance_id = lease.get("instance_id")
    if owner and (
        not isinstance(instance_id, str) or not IDENTIFIER_RE.fullmatch(instance_id)
    ):
        raise RepositoryUnavailableError("durable lease instance is invalid")
    if not owner and instance_id != "":
        raise RepositoryUnavailableError("released lease retains an instance")
    broker = state["broker"]
    if set(broker) != {
        "connected",
        "generation",
        "active_order_count",
        "position_snapshot_hash",
        "last_snapshot_at",
        "orders",
        "positions",
    }:
        raise RepositoryUnavailableError("durable broker fields are invalid")
    if not isinstance(broker.get("connected"), bool):
        raise RepositoryUnavailableError("durable broker connected flag is invalid")
    for field in ("generation", "active_order_count"):
        value = broker.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RepositoryUnavailableError(f"durable broker {field} is invalid")
    if not isinstance(
        broker.get("position_snapshot_hash"), str
    ) or not SHA256_RE.fullmatch(broker["position_snapshot_hash"]):
        raise RepositoryUnavailableError("durable broker position hash is invalid")
    if not isinstance(broker.get("last_snapshot_at"), str) or not UTC_RE.fullmatch(
        broker["last_snapshot_at"]
    ):
        raise RepositoryUnavailableError("durable broker snapshot timestamp is invalid")
    for field in ("orders", "positions"):
        if not isinstance(broker.get(field, {}), Mapping):
            raise RepositoryUnavailableError(
                f"durable broker {field} facts are invalid"
            )
    if not isinstance(state.get("previous_state_hash"), str) or (
        state["previous_state_hash"]
        and not SHA256_RE.fullmatch(state["previous_state_hash"])
    ):
        raise RepositoryUnavailableError("durable previous state hash is invalid")
    if state["state_version"] > 0 and not state["previous_state_hash"]:
        raise RepositoryUnavailableError(
            "durable state hash chain predecessor is missing"
        )
    if not isinstance(state.get("state_hash"), str) or not SHA256_RE.fullmatch(
        state["state_hash"]
    ):
        raise RepositoryUnavailableError("durable state hash is invalid")
    intent_states = {
        "PERSISTED",
        "SUBMITTED",
        "ACKNOWLEDGED",
        "UNKNOWN_OUTCOME",
        "RECONCILED",
        "CANCEL_REQUESTED",
        "CANCELLED",
        "TERMINAL",
    }
    for intent_id, raw_intent in state["send_intents"].items():
        if str(intent_id).startswith("key:"):
            raise RepositoryUnavailableError(
                "legacy intent key aliases are not canonical durable state"
            )
        if not isinstance(raw_intent, Mapping):
            raise RepositoryUnavailableError("durable send intent is invalid")
        if (
            raw_intent.get("intent_id") != intent_id
            or raw_intent.get("state") not in intent_states
        ):
            raise RepositoryUnavailableError(
                "durable send intent identity/state is invalid"
            )
        if not isinstance(
            raw_intent.get("plan_id"), str
        ) or not IDENTIFIER_RE.fullmatch(raw_intent["plan_id"]):
            raise RepositoryUnavailableError("durable send intent plan id is invalid")
        if not isinstance(raw_intent.get("plan_hash"), str) or not SHA256_RE.fullmatch(
            raw_intent["plan_hash"]
        ):
            raise RepositoryUnavailableError("durable send intent plan hash is invalid")
        idempotency_key = raw_intent.get("idempotency_key")
        if not isinstance(idempotency_key, str) or not IDEMPOTENCY_RE.fullmatch(
            idempotency_key
        ):
            raise RepositoryUnavailableError(
                "durable send intent idempotency key is invalid"
            )
        if raw_intent.get("action", "send") not in {"send", "cancel"}:
            raise RepositoryUnavailableError("durable send intent action is invalid")
        request_hash = raw_intent.get("request_hash", "")
        if request_hash and (
            not isinstance(request_hash, str) or not SHA256_RE.fullmatch(request_hash)
        ):
            raise RepositoryUnavailableError(
                "durable send intent request hash is invalid"
            )
        receipt_id = raw_intent.get("receipt_id")
        receipt_hash = raw_intent.get("receipt_hash")
        if receipt_id is not None and (
            not isinstance(receipt_id, str) or not IDENTIFIER_RE.fullmatch(receipt_id)
        ):
            raise RepositoryUnavailableError(
                "durable send intent receipt id is invalid"
            )
        if receipt_hash is not None and (
            not isinstance(receipt_hash, str) or not SHA256_RE.fullmatch(receipt_hash)
        ):
            raise RepositoryUnavailableError(
                "durable send intent receipt hash is invalid"
            )
        target_intent_id = raw_intent.get("target_intent_id")
        if target_intent_id is not None and (
            not isinstance(target_intent_id, str)
            or not IDENTIFIER_RE.fullmatch(target_intent_id)
        ):
            raise RepositoryUnavailableError("durable send intent target is invalid")
        for field in ("leader_epoch", "fencing_token"):
            value = raw_intent.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise RepositoryUnavailableError("durable send intent fence is invalid")
        if not isinstance(raw_intent.get("created_at"), str) or not UTC_RE.fullmatch(
            raw_intent["created_at"]
        ):
            raise RepositoryUnavailableError("durable send intent timestamp is invalid")
    for idempotency_key, intent_id in state["intent_keys"].items():
        if (
            not isinstance(idempotency_key, str)
            or not IDEMPOTENCY_RE.fullmatch(idempotency_key)
            or not isinstance(intent_id, str)
            or intent_id not in state["send_intents"]
            or state["send_intents"][intent_id].get("idempotency_key")
            != idempotency_key
        ):
            raise RepositoryUnavailableError(
                "durable intent idempotency index is invalid"
            )
    for intent_id in state["unknown_outcomes"]:
        if intent_id not in state["send_intents"]:
            raise RepositoryUnavailableError("durable unknown outcome has no intent")
    for key, receipt in state["receipts"].items():
        if not isinstance(key, str) or ":" not in key:
            raise RepositoryUnavailableError("durable receipt index key is invalid")
        _validate_receipt_entry(receipt)
        if key != f"{receipt['service']}:{receipt['idempotency_key']}":
            raise RepositoryUnavailableError("durable receipt index binding is invalid")
    for intent_id, raw_intent in state["send_intents"].items():
        if (
            raw_intent.get("state") == "UNKNOWN_OUTCOME"
            and intent_id not in state["unknown_outcomes"]
        ):
            raise RepositoryUnavailableError(
                "durable unknown intent is missing its outcome record"
            )
    if state["reconciliation"].get("unknown_outcomes") != len(
        state["unknown_outcomes"]
    ):
        raise RepositoryUnavailableError(
            "durable reconciliation unknown count is inconsistent"
        )
    if verify_hash and _state_digest(state) != state["state_hash"]:
        raise RepositoryUnavailableError("durable state hash mismatch")
    return state


class DurableExecutionRepository:
    """Thread-safe durable state with explicit availability/failure controls."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        scope: str = "account:default",
    ) -> None:
        self.path = Path(path) if path is not None else None
        self.scope = scope
        self._lock = RLock()
        self.available = True
        self._durable_initialized = bool(self.path and self.path.exists())
        self._state = self._load()

    def _load(self) -> dict[str, Any]:
        if self.path is None or not self.path.exists():
            return _initial_state(self.scope)
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RepositoryUnavailableError(
                "cannot read durable execution state"
            ) from exc
        return _validate_state(raw, self.scope, verify_hash=True)

    def _require_available(self) -> None:
        if not self.available:
            raise RepositoryUnavailableError("durable execution repository unavailable")

    @contextmanager
    def _file_guard(self, *, exclusive: bool) -> Iterator[None]:
        """Serialize independent repository objects sharing one state path."""

        if self.path is None or fcntl is None:
            yield
            return
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            with lock_path.open("a+", encoding="utf-8") as handle:
                operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                fcntl.flock(handle.fileno(), operation)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise RepositoryUnavailableError(
                "cannot lock durable execution state"
            ) from exc

    def _refresh_from_disk(self) -> None:
        if self.path is None:
            return
        if not self.path.exists():
            if self._durable_initialized:
                raise RepositoryUnavailableError("durable execution state was deleted")
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            candidate = _validate_state(raw, self.scope, verify_hash=True)
            current_version = int(self._state.get("state_version", 0))
            candidate_version = int(candidate["state_version"])
            if candidate_version < current_version:
                raise RepositoryUnavailableError("durable state version regressed")
            if candidate_version == current_version and candidate[
                "state_hash"
            ] != self._state.get("state_hash"):
                raise RepositoryUnavailableError(
                    "durable state replacement at the same version"
                )
            if candidate_version > current_version:
                if candidate.get("previous_state_hash") != self._state.get(
                    "state_hash"
                ):
                    raise RepositoryUnavailableError(
                        "durable state hash chain was replaced"
                    )
                for section, field in (
                    ("lease", "epoch"),
                    ("lease", "fencing_token"),
                    ("plan", "version"),
                    ("broker", "generation"),
                ):
                    if int(candidate[section].get(field, 0)) < int(
                        self._state[section].get(field, 0)
                    ):
                        raise RepositoryUnavailableError(
                            f"durable {section} {field} regressed"
                        )
            self._state = candidate
        except (OSError, json.JSONDecodeError) as exc:
            raise RepositoryUnavailableError(
                "cannot refresh durable execution state"
            ) from exc

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._require_available()
            with self._file_guard(exclusive=False):
                self._refresh_from_disk()
                return deepcopy(self._state)

    read = snapshot

    @property
    def state_version(self) -> int:
        with self._lock:
            self._require_available()
            with self._file_guard(exclusive=False):
                self._refresh_from_disk()
                return int(self._state["state_version"])

    def _persist(self, state: Mapping[str, Any]) -> None:
        if self.path is None:
            candidate = deepcopy(dict(state))
            candidate["previous_state_hash"] = self._state.get("state_hash", "")
            candidate["state_hash"] = _state_digest(candidate)
            _validate_state(candidate, self.scope, verify_hash=True)
            self._state = candidate
            return
        parent = self.path.parent
        try:
            candidate = deepcopy(dict(state))
            candidate["previous_state_hash"] = self._state.get("state_hash", "")
            candidate["state_hash"] = _state_digest(candidate)
            _validate_state(candidate, self.scope, verify_hash=True)
            parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.", dir=str(parent)
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(
                        candidate,
                        handle,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_name, self.path)
                # Persist the directory entry as well.  Some filesystems do not
                # expose a directory fsync; failure there means indeterminate
                # durability and must remain fail closed.
                directory_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
        except OSError as exc:
            raise RepositoryUnavailableError(
                "cannot durably write execution state"
            ) from exc
        self._state = candidate
        self._durable_initialized = True

    @staticmethod
    def _assert_append_only(
        previous: Mapping[str, Any], candidate: Mapping[str, Any]
    ) -> None:
        for section in ("audit", "terminal_archive"):
            old_values = list(previous.get(section, []))
            new_values = list(candidate.get(section, []))
            if (
                len(new_values) < len(old_values)
                or new_values[: len(old_values)] != old_values
            ):
                raise RepositoryUnavailableError(
                    f"durable {section} is not append-only"
                )
        old_intents = previous.get("send_intents", {})
        new_intents = candidate.get("send_intents", {})
        for intent_id, old_intent in old_intents.items():
            if intent_id not in new_intents:
                raise RepositoryUnavailableError("durable send intent was deleted")
            if new_intents[intent_id].get("intent_id") != old_intent.get("intent_id"):
                raise RepositoryUnavailableError("durable send intent identity changed")
        for key, old_intent_id in previous.get("intent_keys", {}).items():
            if candidate.get("intent_keys", {}).get(key) != old_intent_id:
                raise RepositoryUnavailableError(
                    "durable idempotency index was removed or changed"
                )
        for key, old_receipt in previous.get("receipts", {}).items():
            if candidate.get("receipts", {}).get(key) != old_receipt:
                raise RepositoryUnavailableError(
                    "durable command receipt was removed or changed"
                )
        old_lease = previous.get("lease", {})
        new_lease = candidate.get("lease", {})
        for field in ("epoch", "fencing_token"):
            try:
                old_value = int(old_lease.get(field, 0))
                new_value = int(new_lease.get(field, 0))
            except (TypeError, ValueError) as exc:
                raise RepositoryUnavailableError(
                    f"durable lease {field} is invalid"
                ) from exc
            if new_value < old_value:
                raise RepositoryUnavailableError(f"durable lease {field} regressed")
        old_plan = previous.get("plan", {})
        new_plan = candidate.get("plan", {})
        try:
            old_plan_version = int(old_plan.get("version", 0))
            new_plan_version = int(new_plan.get("version", 0))
        except (TypeError, ValueError) as exc:
            raise RepositoryUnavailableError("durable plan version is invalid") from exc
        if new_plan_version < old_plan_version:
            raise RepositoryUnavailableError("durable plan version regressed")
        old_broker = previous.get("broker", {})
        new_broker = candidate.get("broker", {})
        try:
            old_generation = int(old_broker.get("generation", 0))
            new_generation = int(new_broker.get("generation", 0))
        except (TypeError, ValueError) as exc:
            raise RepositoryUnavailableError(
                "durable broker generation is invalid"
            ) from exc
        if new_generation < old_generation:
            raise RepositoryUnavailableError("durable broker generation regressed")

    def mutate(
        self,
        mutator: Callable[[dict[str, Any]], Any],
        *,
        expected_version: int | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        """Apply one serialized mutation and increment the durable version.

        ``mutator`` runs against a detached copy.  If it raises, no version or
        file is changed.  The returned state is another detached copy.
        """

        with self._lock:
            self._require_available()
            with self._file_guard(exclusive=True):
                self._refresh_from_disk()
                current = int(self._state["state_version"])
                if expected_version is not None and expected_version != current:
                    raise ExpectedVersionConflict(expected_version, current)
                candidate = deepcopy(self._state)
                result = mutator(candidate)
                self._assert_append_only(self._state, candidate)
                candidate["state_version"] = current + 1
                self._persist(candidate)
                return result, deepcopy(candidate)

    def replace(
        self, state: Mapping[str, Any], *, expected_version: int | None = None
    ) -> dict[str, Any]:
        """Replace the complete document, useful for deterministic recovery tests."""

        def writer(candidate: dict[str, Any]) -> None:
            replacement = _validate_state(state, self.scope)
            candidate.clear()
            candidate.update(replacement)

        _, result = self.mutate(writer, expected_version=expected_version)
        return result

    def append_audit(
        self, record: Mapping[str, Any], *, expected_version: int | None = None
    ) -> dict[str, Any]:
        def writer(state: dict[str, Any]) -> None:
            value = deepcopy(dict(record))
            value.setdefault("observed_at", format_utc(datetime.now(timezone.utc)))
            state["audit"].append(value)

        _, result = self.mutate(writer, expected_version=expected_version)
        return result

    # Explicit state-owner methods make the durable contract discoverable to
    # adapters and keep callers from reaching into the raw document for common
    # operations.  Each method is still one CAS/versioned mutation.
    def get_active_plan(self) -> dict[str, Any]:
        return deepcopy(self.snapshot()["plan"])

    def put_active_plan(
        self, plan: Mapping[str, Any], *, expected_version: int | None = None
    ) -> dict[str, Any]:
        def writer(state: dict[str, Any]) -> None:
            state["plan"] = deepcopy(dict(plan))

        _, result = self.mutate(writer, expected_version=expected_version)
        return deepcopy(result["plan"])

    def get_authority(self) -> dict[str, Any]:
        return deepcopy(self.snapshot()["authority"])

    def put_authority(
        self, authority: Mapping[str, Any], *, expected_version: int | None = None
    ) -> dict[str, Any]:
        def writer(state: dict[str, Any]) -> None:
            state["authority"] = deepcopy(dict(authority))

        _, result = self.mutate(writer, expected_version=expected_version)
        return deepcopy(result["authority"])

    def get_intent(self, intent_id: str) -> dict[str, Any] | None:
        value = self.snapshot()["send_intents"].get(intent_id)
        return deepcopy(value) if isinstance(value, Mapping) else None

    def list_intents(self) -> list[dict[str, Any]]:
        state = self.snapshot()
        return [
            deepcopy(value)
            for key, value in state["send_intents"].items()
            if not str(key).startswith("key:")
        ]

    list_send_intents = list_intents

    def put_intent(
        self,
        intent_id: str,
        intent: Mapping[str, Any],
        *,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        def writer(state: dict[str, Any]) -> None:
            value = deepcopy(dict(intent))
            state["send_intents"][intent_id] = value
            idempotency_key = value.get("idempotency_key")
            if isinstance(idempotency_key, str) and idempotency_key:
                state["intent_keys"][idempotency_key] = intent_id

        _, result = self.mutate(writer, expected_version=expected_version)
        return deepcopy(result["send_intents"][intent_id])

    save_intent = put_intent
    persist_intent = put_intent
    persist_send_intent = put_intent

    def get_unknown_outcomes(self) -> dict[str, Any]:
        return deepcopy(self.snapshot()["unknown_outcomes"])

    def set_unknown_outcome(
        self,
        intent_id: str,
        value: Mapping[str, Any],
        *,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        def writer(state: dict[str, Any]) -> None:
            state["unknown_outcomes"][intent_id] = deepcopy(dict(value))
            raw = state["send_intents"].get(intent_id)
            if isinstance(raw, dict):
                raw["state"] = "UNKNOWN_OUTCOME"
            state["reconciliation"]["state"] = "UNKNOWN"
            state["reconciliation"]["unknown_outcomes"] = len(state["unknown_outcomes"])
            state["lifecycle"] = "HALTED_UNKNOWN_OUTCOME"

        _, result = self.mutate(writer, expected_version=expected_version)
        return deepcopy(result["unknown_outcomes"].get(intent_id, {}))

    def clear_unknown_outcome(
        self, intent_id: str, *, expected_version: int | None = None
    ) -> dict[str, Any]:
        def writer(state: dict[str, Any]) -> None:
            state["unknown_outcomes"].pop(intent_id, None)
            raw = state["send_intents"].get(intent_id)
            if isinstance(raw, dict):
                raw["state"] = "RECONCILED"
            count = len(state["unknown_outcomes"])
            state["reconciliation"]["unknown_outcomes"] = count
            if count == 0:
                state["reconciliation"]["state"] = "RECONCILED"

        _, result = self.mutate(writer, expected_version=expected_version)
        return deepcopy(result["unknown_outcomes"])

    def get_reconciliation(self) -> dict[str, Any]:
        return deepcopy(self.snapshot()["reconciliation"])

    def put_reconciliation(
        self, value: Mapping[str, Any], *, expected_version: int | None = None
    ) -> dict[str, Any]:
        def writer(state: dict[str, Any]) -> None:
            state["reconciliation"] = deepcopy(dict(value))

        _, result = self.mutate(writer, expected_version=expected_version)
        return deepcopy(result["reconciliation"])

    def get_lease(self) -> dict[str, Any]:
        return deepcopy(self.snapshot()["lease"])

    def get_receipt(self, service: str, idempotency_key: str) -> dict[str, Any] | None:
        value = self.snapshot()["receipts"].get(f"{service}:{idempotency_key}")
        return deepcopy(value) if isinstance(value, Mapping) else None

    def append_terminal_archive(
        self, record: Mapping[str, Any], *, expected_version: int | None = None
    ) -> dict[str, Any]:
        def writer(state: dict[str, Any]) -> None:
            value = deepcopy(dict(record))
            value.setdefault("archived_at", format_utc(datetime.now(timezone.utc)))
            state["terminal_archive"].append(value)

        _, result = self.mutate(writer, expected_version=expected_version)
        return deepcopy(result["terminal_archive"][-1])

    def mark_unavailable(self) -> None:
        with self._lock:
            self.available = False

    def mark_available(self) -> None:
        with self._lock:
            self.available = True

    def set_available(self, value: bool = True) -> None:
        with self._lock:
            self.available = bool(value)


class InMemoryExecutionRepository(DurableExecutionRepository):
    """Explicit name for tests; it still has full CAS/version semantics."""

    def __init__(self, *, scope: str = "account:default") -> None:
        super().__init__(None, scope=scope)


JsonExecutionRepository = DurableExecutionRepository
ExecutionStateRepository = DurableExecutionRepository
DurableStateRepository = DurableExecutionRepository


@dataclass(frozen=True, slots=True)
class RepositoryTransaction:
    """Small marker returned by adapters that expose transaction metadata."""

    state_version: int
