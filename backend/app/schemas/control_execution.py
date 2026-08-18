"""Typed DTOs at the Control API/Execution boundary.

The command and status schemas are private service contracts.  Keeping the
validation entry points in this small module gives the Control API and its
tests one import surface while the actual command semantics remain owned by
``app.execution.models``.  No legacy trading service is imported here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from shared.commodity_execution import (
    KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION,
    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION,
    sha256_json,
)

from app.execution.models import (
    EPOCH_TIMESTAMP,
    FUTURE_SKEW_SECONDS,
    IDENTIFIER_RE,
    SHA256_RE,
    SNAPSHOT_STALE_SECONDS,
    UTC_RE,
    CommandEnvelope,
    parse_utc,
)

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "schemas"
    / "web-bridge-execution-status-v1.schema.json"
)


def _load_status_validator() -> Draft202012Validator:
    """Load the frozen status schema without depending on the process cwd."""

    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        # Images copy the public schema into ``/app/docs``.  The fallback is
        # intentionally explicit instead of accepting arbitrary dictionaries;
        # it keeps health/status fail closed when packaging is incomplete.
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "schema_version",
                "service",
                "service_version",
                "observed_at",
                "lifecycle",
                "state_version",
                "leader",
                "authority",
                "plan",
                "send_intents",
                "reconciliation",
                "safe_to_restart",
                "broker",
            ],
            "properties": {
                "schema_version": {"const": "web_bridge_execution_status_v1"},
                "service": {"const": "execution-orchestrator"},
                "service_version": {"type": "string"},
                "observed_at": {"type": "string"},
                "lifecycle": {"type": "string"},
                "state_version": {"type": "integer", "minimum": 0},
                "leader": {"type": "object"},
                "authority": {"type": "object"},
                "plan": {"type": "object"},
                "send_intents": {"type": "array"},
                "reconciliation": {"type": "object"},
                "safe_to_restart": {"type": "boolean"},
                "broker": {"type": "object"},
            },
        }
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


_STATUS_VALIDATOR = _load_status_validator()


_LEADER_TOKEN_FIELDS = frozenset(
    {
        "scope",
        "owner_id",
        "held",
        "epoch",
        "fencing_token",
        "lease_expires_at",
        "instance_id",
    }
)
_LEADER_STATUS_FIELDS = _LEADER_TOKEN_FIELDS | {"state"}
_LEADER_STATES = frozenset({"ACTIVE", "EXPIRED_BOUND", "RELEASED"})


def _detached_object(value: Any, *, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be an object")
    try:
        return json.loads(
            json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} is not canonical JSON") from exc


def _validate_leader_common(
    candidate: dict[str, Any], *, fields: frozenset[str]
) -> None:
    if set(candidate) != fields:
        raise ValueError("execution leader fields are not exact")
    if (
        not isinstance(candidate["scope"], str)
        or IDENTIFIER_RE.fullmatch(candidate["scope"]) is None
    ):
        raise ValueError("execution leader scope is invalid")
    owner_id = candidate["owner_id"]
    instance_id = candidate["instance_id"]
    if owner_id and (
        not isinstance(owner_id, str) or IDENTIFIER_RE.fullmatch(owner_id) is None
    ):
        raise ValueError("execution leader owner_id is invalid")
    if not isinstance(owner_id, str):
        raise ValueError("execution leader owner_id is invalid")
    if owner_id:
        if (
            not isinstance(instance_id, str)
            or IDENTIFIER_RE.fullmatch(instance_id) is None
        ):
            raise ValueError("execution leader instance_id is invalid")
    elif instance_id != "":
        raise ValueError("released execution leader retains an instance_id")
    for field in ("epoch", "fencing_token"):
        value = candidate[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"execution leader {field} is invalid")
    if not isinstance(candidate["held"], bool):
        raise ValueError("execution leader held is invalid")
    if (
        not isinstance(candidate["lease_expires_at"], str)
        or UTC_RE.fullmatch(candidate["lease_expires_at"]) is None
    ):
        raise ValueError("execution leader lease_expires_at is invalid")
    if owner_id and (candidate["epoch"] < 1 or candidate["fencing_token"] < 1):
        raise ValueError("owned execution leader is missing a fence")


@dataclass(frozen=True, slots=True)
class ExecutionLeaderTokenProjection:
    """Strict Control-side projection of one currently held lease token."""

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionLeaderTokenProjection:
        candidate = _detached_object(value, name="execution leader token")
        _validate_leader_common(candidate, fields=_LEADER_TOKEN_FIELDS)
        if (
            candidate["held"] is not True
            or not candidate["owner_id"]
            or not candidate["instance_id"]
            or candidate["lease_expires_at"] == EPOCH_TIMESTAMP
        ):
            raise ValueError("execution leader token is not held")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionLeaderTokenProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def token_dict(self) -> dict[str, Any]:
        token = self.model_dump()
        token.pop("held")
        return token

    @property
    def owner_id(self) -> str:
        return str(self.value["owner_id"])

    @property
    def instance_id(self) -> str:
        return str(self.value["instance_id"])

    @property
    def scope(self) -> str:
        return str(self.value["scope"])

    @property
    def epoch(self) -> int:
        return int(self.value["epoch"])

    @property
    def fencing_token(self) -> int:
        return int(self.value["fencing_token"])


@dataclass(frozen=True, slots=True)
class ExecutionLeaderStatusProjection:
    """Strict read-only lease status with an explicit durable binding state."""

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionLeaderStatusProjection:
        candidate = _detached_object(value, name="execution leader status")
        _validate_leader_common(candidate, fields=_LEADER_STATUS_FIELDS)
        state = candidate["state"]
        if not isinstance(state, str) or state not in _LEADER_STATES:
            raise ValueError("execution leader state is invalid")
        owner_id = candidate["owner_id"]
        instance_id = candidate["instance_id"]
        expiry = candidate["lease_expires_at"]
        if state == "ACTIVE":
            valid = (
                candidate["held"] is True
                and bool(owner_id)
                and bool(instance_id)
                and expiry != EPOCH_TIMESTAMP
            )
        elif state == "EXPIRED_BOUND":
            valid = (
                candidate["held"] is False
                and bool(owner_id)
                and bool(instance_id)
                and expiry != EPOCH_TIMESTAMP
            )
        else:
            valid = (
                candidate["held"] is False
                and owner_id == ""
                and instance_id == ""
                and expiry == EPOCH_TIMESTAMP
            )
        if not valid:
            raise ValueError("execution leader status has mixed state bindings")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionLeaderStatusProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    @property
    def held(self) -> bool:
        return bool(self.value["held"])

    @property
    def state(self) -> str:
        return str(self.value["state"])

    @property
    def owner_id(self) -> str:
        return str(self.value["owner_id"])

    @property
    def instance_id(self) -> str:
        return str(self.value["instance_id"])

    @property
    def scope(self) -> str:
        return str(self.value["scope"])

    @property
    def epoch(self) -> int:
        return int(self.value["epoch"])

    @property
    def fencing_token(self) -> int:
        return int(self.value["fencing_token"])


@dataclass(frozen=True, slots=True)
class ExecutionStatusProjection:
    """A read-only, schema-validated Execution projection.

    The projection stores a detached JSON value.  Control code can safely
    retain it for an audit/receipt projection without gaining a writable
    reference to Execution durable state.
    """

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionStatusProjection:
        if not isinstance(value, Mapping):
            raise TypeError("execution status projection must be an object")
        candidate = json.loads(
            json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
        )
        errors = sorted(
            _STATUS_VALIDATOR.iter_errors(candidate), key=lambda e: list(e.path)
        )
        if errors:
            first = errors[0]
            path = ".".join(str(item) for item in first.path)
            location = f" at {path}" if path else ""
            raise ValueError(
                f"invalid execution status projection{location}: {first.message}"
            )
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionStatusProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @property
    def lifecycle(self) -> str:
        return str(self.value["lifecycle"])

    @property
    def state_version(self) -> int:
        return int(self.value["state_version"])

    @property
    def safe_to_restart(self) -> bool:
        return bool(self.value["safe_to_restart"])


_COMPLETION_FIELDS = frozenset(
    {
        "plan_id",
        "plan_hash",
        "schema_version",
        "phase",
        "lineage",
        "expected_after_position_hash",
        "target_position_hash",
        "archived_at",
    }
)
_COMPLETION_V3_FIELDS = frozenset(
    {
        *_COMPLETION_FIELDS,
        "execution_run_id",
        "creation_quote_proof_sha256",
        "start_quote_proof_sha256",
    }
)
_COMPLETION_LINEAGE_FIELDS = frozenset(
    {
        "static_core_equal_sha256",
        "position_manager_sha256",
        "final_target_sha256",
    }
)


@dataclass(frozen=True, slots=True)
class ExecutionCompletionProjection:
    """Strict read-only projection of one completed TargetPlan v2/v3.

    This DTO intentionally excludes archived broker rows, receipts, authority
    material and every other mutable Execution field.  It is sufficient to
    identify an already-completed immutable target without turning Control
    into another Execution state store.
    """

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionCompletionProjection:
        if not isinstance(value, Mapping):
            raise TypeError("execution completion projection must be an object")
        candidate = json.loads(
            json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
        )
        fields = set(candidate)
        if fields not in {_COMPLETION_FIELDS, _COMPLETION_V3_FIELDS}:
            raise ValueError("execution completion projection fields are not exact")
        if (
            not isinstance(candidate["plan_id"], str)
            or IDENTIFIER_RE.fullmatch(candidate["plan_id"]) is None
        ):
            raise ValueError("execution completion plan_id is invalid")
        for field in (
            "plan_hash",
            "expected_after_position_hash",
            "target_position_hash",
        ):
            if (
                not isinstance(candidate[field], str)
                or SHA256_RE.fullmatch(candidate[field]) is None
            ):
                raise ValueError(f"execution completion {field} is invalid")
        if (
            fields == _COMPLETION_FIELDS
            and candidate["schema_version"] != KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
        ) or (
            fields == _COMPLETION_V3_FIELDS
            and candidate["schema_version"] != KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
        ):
            raise ValueError("execution completion schema/version variant mismatches")
        if fields == _COMPLETION_V3_FIELDS:
            if (
                not isinstance(candidate["execution_run_id"], str)
                or IDENTIFIER_RE.fullmatch(candidate["execution_run_id"]) is None
            ):
                raise ValueError("execution completion execution_run_id is invalid")
            for field in (
                "creation_quote_proof_sha256",
                "start_quote_proof_sha256",
            ):
                _strict_sha(candidate[field], field=field)
        if candidate["phase"] not in {"CLOSE", "OPEN"}:
            raise ValueError("execution completion phase is invalid")
        lineage = candidate["lineage"]
        if not isinstance(lineage, Mapping) or set(lineage) != (
            _COMPLETION_LINEAGE_FIELDS
        ):
            raise ValueError("execution completion lineage fields are not exact")
        for field in _COMPLETION_LINEAGE_FIELDS:
            if (
                not isinstance(lineage[field], str)
                or SHA256_RE.fullmatch(lineage[field]) is None
            ):
                raise ValueError(f"execution completion lineage {field} is invalid")
        if (
            candidate["target_position_hash"]
            != candidate["expected_after_position_hash"]
        ):
            raise ValueError("execution completion target position binding mismatches")
        if (
            not isinstance(candidate["archived_at"], str)
            or UTC_RE.fullmatch(candidate["archived_at"]) is None
        ):
            raise ValueError("execution completion archived_at is invalid")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionCompletionProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @property
    def plan_id(self) -> str:
        return str(self.value["plan_id"])

    @property
    def target_position_hash(self) -> str:
        return str(self.value["target_position_hash"])


_ACCOUNT_FACTS_FIELDS = frozenset(
    {
        "schema_version",
        "service",
        "service_version",
        "account_scope",
        "environment",
        "snapshot_id",
        "generation",
        "observed_at",
        "connected",
        "fresh",
        "position_snapshot_hash",
        "positions",
        "active_order_count",
        "active_orders_sha256",
        "active_orders",
        "status_binding",
        "account_facts_sha256",
    }
)
_ACCOUNT_FACTS_V2_FIELDS = _ACCOUNT_FACTS_FIELDS | {"execution_binding"}
_EXECUTION_BINDING_FIELDS = frozenset(
    {
        "state_version",
        "plan_state",
        "send_intents",
        "send_intents_sha256",
        "nonterminal_send_intent_count",
    }
)
_TERMINAL_SEND_INTENT_STATES = frozenset({"RECONCILED", "CANCELLED", "TERMINAL"})
_SEND_INTENT_REQUIRED_FIELDS = frozenset(
    {
        "intent_id",
        "idempotency_key",
        "state",
        "plan_id",
        "plan_hash",
        "leader_epoch",
        "fencing_token",
        "created_at",
    }
)
_SEND_INTENT_OPTIONAL_FIELDS = frozenset(
    {
        "action",
        "request_hash",
        "target_intent_id",
        "receipt_id",
        "receipt_hash",
        "broker_order_id",
        "unknown_reason",
    }
)
_STATUS_BINDING_FIELDS = frozenset(
    {
        "status_schema_version",
        "state_version",
        "status_observed_at",
        "lifecycle",
        "reconciliation",
        "broker",
        "durable_active_orders_sha256",
        "durable_positions_sha256",
        "snapshot_identity_mode",
    }
)
_RECONCILIATION_FIELDS = frozenset(
    {
        "state",
        "run_id",
        "last_completed_at",
        "unknown_outcomes",
        "fresh_snapshot_id",
    }
)
_BROKER_FIELDS = frozenset(
    {
        "connected",
        "generation",
        "active_order_count",
        "position_snapshot_hash",
        "last_snapshot_at",
    }
)


def _strict_nonnegative_int(value: Any, *, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} is invalid")


def _strict_sha(value: Any, *, field: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")


def _strict_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")
    try:
        parse_utc(value, field_name=field)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} is invalid") from exc
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


@dataclass(frozen=True, slots=True)
class ExecutionAccountFactsProjection:
    """Strict Control-side view of one full, fresh Execution-owned account read."""

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionAccountFactsProjection:
        candidate = _detached_object(value, name="execution account facts")
        if set(candidate) != _ACCOUNT_FACTS_FIELDS:
            raise ValueError("execution account facts fields are not exact")
        if (
            candidate["schema_version"] != "web_bridge_execution_account_facts_v1"
            or candidate["service"] != "execution-orchestrator"
            or not isinstance(candidate["service_version"], str)
            or not candidate["service_version"]
            or not isinstance(candidate["account_scope"], str)
            or IDENTIFIER_RE.fullmatch(candidate["account_scope"]) is None
            or not isinstance(candidate["environment"], str)
            or not candidate["environment"]
            or not isinstance(candidate["snapshot_id"], str)
            or IDENTIFIER_RE.fullmatch(candidate["snapshot_id"]) is None
            or candidate["connected"] is not True
            or candidate["fresh"] is not True
        ):
            raise ValueError("execution account facts identity is invalid")
        _strict_nonnegative_int(candidate["generation"], field="generation")
        _strict_nonnegative_int(
            candidate["active_order_count"], field="active_order_count"
        )
        observed_at = _strict_utc(candidate["observed_at"], field="observed_at")
        for field in (
            "position_snapshot_hash",
            "active_orders_sha256",
            "account_facts_sha256",
        ):
            _strict_sha(candidate[field], field=field)
        positions = candidate["positions"]
        orders = candidate["active_orders"]
        if not isinstance(positions, Mapping) or not isinstance(orders, Mapping):
            raise ValueError("execution account fact rows are invalid")
        if any(
            not isinstance(key, str) or not isinstance(row, Mapping)
            for facts in (positions, orders)
            for key, row in facts.items()
        ):
            raise ValueError("execution account fact rows are invalid")
        if candidate["active_order_count"] != len(orders):
            raise ValueError("execution active order count does not close")
        if candidate["position_snapshot_hash"] != sha256_json(dict(positions)):
            raise ValueError("execution position facts hash does not close")
        if candidate["active_orders_sha256"] != sha256_json(dict(orders)):
            raise ValueError("execution active order facts hash does not close")

        binding = candidate["status_binding"]
        if not isinstance(binding, Mapping) or set(binding) != _STATUS_BINDING_FIELDS:
            raise ValueError("execution account facts status binding is not exact")
        if (
            binding["status_schema_version"] != "web_bridge_execution_status_v1"
            or not isinstance(binding["lifecycle"], str)
            or not binding["lifecycle"]
            or binding["snapshot_identity_mode"]
            not in {"EXACT", "GENERATION_FACT_HASH_EQUIVALENT"}
        ):
            raise ValueError("execution account facts status identity is invalid")
        _strict_nonnegative_int(binding["state_version"], field="state_version")
        _strict_utc(binding["status_observed_at"], field="status_observed_at")
        _strict_sha(
            binding["durable_active_orders_sha256"],
            field="durable_active_orders_sha256",
        )
        _strict_sha(
            binding["durable_positions_sha256"],
            field="durable_positions_sha256",
        )
        reconciliation = binding["reconciliation"]
        broker = binding["broker"]
        if (
            not isinstance(reconciliation, Mapping)
            or set(reconciliation) != _RECONCILIATION_FIELDS
            or not isinstance(broker, Mapping)
            or set(broker) != _BROKER_FIELDS
        ):
            raise ValueError("execution account facts durable binding is not exact")
        for field in ("state", "run_id", "fresh_snapshot_id"):
            if not isinstance(reconciliation[field], str):
                raise ValueError("execution reconciliation binding is invalid")
        _strict_utc(reconciliation["last_completed_at"], field="last_completed_at")
        _strict_nonnegative_int(
            reconciliation["unknown_outcomes"], field="unknown_outcomes"
        )
        if not isinstance(broker["connected"], bool):
            raise ValueError("execution durable broker connected flag is invalid")
        for field in ("generation", "active_order_count"):
            _strict_nonnegative_int(broker[field], field=f"broker.{field}")
        _strict_sha(
            broker["position_snapshot_hash"], field="broker.position_snapshot_hash"
        )
        durable_observed_at = _strict_utc(
            broker["last_snapshot_at"], field="broker.last_snapshot_at"
        )
        stable_snapshot_identity = candidate["snapshot_id"].startswith("snapshot-peek-")
        if stable_snapshot_identity:
            _strict_sha(
                candidate["snapshot_id"].removeprefix("snapshot-peek-"),
                field="snapshot peek facts hash",
            )
        if (
            reconciliation["state"] != "RECONCILED"
            or reconciliation["unknown_outcomes"] != 0
            or broker["connected"] is not True
            or broker["generation"] != candidate["generation"]
            or broker["position_snapshot_hash"] != candidate["position_snapshot_hash"]
            or binding["durable_positions_sha256"]
            != candidate["position_snapshot_hash"]
            or broker["active_order_count"] != candidate["active_order_count"]
            or binding["durable_active_orders_sha256"]
            != candidate["active_orders_sha256"]
            or binding["snapshot_identity_mode"]
            != (
                "EXACT"
                if stable_snapshot_identity
                else "GENERATION_FACT_HASH_EQUIVALENT"
            )
            or (
                stable_snapshot_identity
                and reconciliation["fresh_snapshot_id"] != candidate["snapshot_id"]
            )
            or durable_observed_at > observed_at
        ):
            raise ValueError(
                "execution account facts are not bound to reconciled status"
            )
        preimage = {
            key: candidate[key] for key in candidate if key != "account_facts_sha256"
        }
        if candidate["account_facts_sha256"] != sha256_json(preimage):
            raise ValueError("execution account facts projection hash does not close")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionAccountFactsProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


@dataclass(frozen=True, slots=True)
class ExecutionAccountFactsProjectionV2:
    """Strict #362 readiness view bound to one complete Execution state."""

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionAccountFactsProjectionV2:
        candidate = _detached_object(value, name="execution account facts v2")
        if set(candidate) != _ACCOUNT_FACTS_V2_FIELDS:
            raise ValueError("execution account facts v2 fields are not exact")
        if candidate["schema_version"] != "web_bridge_execution_account_facts_v2":
            raise ValueError("execution account facts v2 identity is invalid")

        # Reuse the complete v1 row/status closure instead of maintaining a
        # second interpretation of positions, orders or durable reconciliation.
        v1 = {
            key: candidate[key]
            for key in _ACCOUNT_FACTS_FIELDS
            if key != "account_facts_sha256"
        }
        v1["schema_version"] = "web_bridge_execution_account_facts_v1"
        v1["account_facts_sha256"] = sha256_json(v1)
        ExecutionAccountFactsProjection.from_mapping(v1)

        binding = candidate["execution_binding"]
        if not isinstance(binding, Mapping) or set(binding) != (
            _EXECUTION_BINDING_FIELDS
        ):
            raise ValueError("execution account facts v2 binding is not exact")
        _strict_nonnegative_int(binding["state_version"], field="state_version")
        _strict_nonnegative_int(
            binding["nonterminal_send_intent_count"],
            field="nonterminal_send_intent_count",
        )
        _strict_sha(binding["send_intents_sha256"], field="send_intents_sha256")
        intents = binding["send_intents"]
        if not isinstance(intents, Mapping) or any(
            not isinstance(intent_id, str)
            or not isinstance(row, Mapping)
            or not _SEND_INTENT_REQUIRED_FIELDS.issubset(row)
            or not set(row).issubset(
                _SEND_INTENT_REQUIRED_FIELDS | _SEND_INTENT_OPTIONAL_FIELDS
            )
            or row.get("intent_id") != intent_id
            or not isinstance(row.get("state"), str)
            or not isinstance(row.get("idempotency_key"), str)
            or not row.get("idempotency_key")
            or not isinstance(row.get("plan_id"), str)
            or IDENTIFIER_RE.fullmatch(row["plan_id"]) is None
            or not isinstance(row.get("plan_hash"), str)
            or SHA256_RE.fullmatch(row["plan_hash"]) is None
            or any(
                isinstance(row.get(field), bool)
                or not isinstance(row.get(field), int)
                or row[field] < 1
                for field in ("leader_epoch", "fencing_token")
            )
            or not isinstance(row.get("created_at"), str)
            or UTC_RE.fullmatch(row["created_at"]) is None
            for intent_id, row in intents.items()
        ):
            raise ValueError("execution account facts v2 send intents are invalid")
        nonterminal_count = sum(
            row["state"] not in _TERMINAL_SEND_INTENT_STATES for row in intents.values()
        )
        status = candidate["status_binding"]
        if (
            binding["state_version"] != status["state_version"]
            or binding["plan_state"] not in {"IDLE", "TERMINAL"}
            or binding["send_intents_sha256"] != sha256_json(dict(intents))
            or binding["nonterminal_send_intent_count"] != nonterminal_count
            or nonterminal_count != 0
            or status["lifecycle"] != "READY"
            or candidate["active_order_count"] != 0
            or candidate["active_orders"] != {}
        ):
            raise ValueError("execution account facts v2 are not planner-ready")
        preimage = {
            key: candidate[key] for key in candidate if key != "account_facts_sha256"
        }
        if candidate["account_facts_sha256"] != sha256_json(preimage):
            raise ValueError(
                "execution account facts v2 projection hash does not close"
            )
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionAccountFactsProjectionV2:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


_RECONCILIATION_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "service",
        "service_version",
        "account_scope",
        "environment",
        "snapshot_id",
        "generation",
        "observed_at",
        "connected",
        "fresh",
        "position_snapshot_hash",
        "positions",
        "active_order_count",
        "active_orders_sha256",
        "active_orders",
        "state_binding",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "official_forward_claimed",
        "reconciliation_snapshot_sha256",
    }
)
_RECONCILIATION_STATE_BINDING_FIELDS = frozenset(
    {
        "state_version",
        "durable_broker_generation",
        "lifecycle",
        "reconciliation",
    }
)
_LIFECYCLE_VALUES = frozenset(
    {
        "STARTING",
        "READY",
        "DEGRADED",
        "DRAINING",
        "HALTED_RECONCILE_REQUIRED",
        "HALTED_UNKNOWN_OUTCOME",
        "STOPPING",
    }
)
_RECONCILIATION_STATE_VALUES = frozenset(
    {"NOT_REQUIRED", "REQUIRED", "IN_PROGRESS", "RECONCILED", "UNKNOWN"}
)


@dataclass(frozen=True, slots=True)
class ExecutionReconciliationSnapshotProjection:
    """Fresh broker facts beside one non-mutating durable state projection."""

    value: dict[str, Any]

    @classmethod
    def from_mapping(
        cls,
        value: Any,
        *,
        now: datetime | None = None,
    ) -> ExecutionReconciliationSnapshotProjection:
        candidate = _detached_object(value, name="execution reconciliation snapshot")
        if set(candidate) != _RECONCILIATION_SNAPSHOT_FIELDS:
            raise ValueError("execution reconciliation snapshot fields are not exact")
        if (
            candidate["schema_version"]
            != "web_bridge_execution_reconciliation_snapshot_v1"
            or candidate["service"] != "execution-orchestrator"
            or not isinstance(candidate["service_version"], str)
            or not candidate["service_version"]
            or not isinstance(candidate["account_scope"], str)
            or IDENTIFIER_RE.fullmatch(candidate["account_scope"]) is None
            or not isinstance(candidate["environment"], str)
            or not candidate["environment"]
            or not isinstance(candidate["snapshot_id"], str)
            or IDENTIFIER_RE.fullmatch(candidate["snapshot_id"]) is None
            or candidate["connected"] is not True
            or candidate["fresh"] is not True
            or any(
                candidate[field] is not False
                for field in (
                    "production_allowed",
                    "live_trading_authorized",
                    "countable_forward",
                    "official_forward_claimed",
                )
            )
        ):
            raise ValueError("execution reconciliation snapshot identity is invalid")
        _strict_nonnegative_int(candidate["generation"], field="generation")
        _strict_nonnegative_int(
            candidate["active_order_count"], field="active_order_count"
        )
        observed_at = _strict_utc(candidate["observed_at"], field="observed_at")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("execution reconciliation validation clock is invalid")
        current = current.astimezone(timezone.utc)
        if (observed_at - current).total_seconds() > FUTURE_SKEW_SECONDS or (
            current - observed_at
        ).total_seconds() > SNAPSHOT_STALE_SECONDS:
            raise ValueError("execution reconciliation snapshot timestamp is stale")
        for field in (
            "position_snapshot_hash",
            "active_orders_sha256",
            "reconciliation_snapshot_sha256",
        ):
            _strict_sha(candidate[field], field=field)
        positions = candidate["positions"]
        orders = candidate["active_orders"]
        if not isinstance(positions, Mapping) or not isinstance(orders, Mapping):
            raise ValueError("execution reconciliation snapshot rows are invalid")
        if any(
            not isinstance(key, str) or not isinstance(row, Mapping)
            for facts in (positions, orders)
            for key, row in facts.items()
        ):
            raise ValueError("execution reconciliation snapshot rows are invalid")
        if (
            candidate["active_order_count"] != len(orders)
            or candidate["position_snapshot_hash"] != sha256_json(dict(positions))
            or candidate["active_orders_sha256"] != sha256_json(dict(orders))
        ):
            raise ValueError("execution reconciliation snapshot facts do not close")
        binding = candidate["state_binding"]
        if (
            not isinstance(binding, Mapping)
            or set(binding) != _RECONCILIATION_STATE_BINDING_FIELDS
            or not isinstance(binding["lifecycle"], str)
            or binding["lifecycle"] not in _LIFECYCLE_VALUES
            or not isinstance(binding["reconciliation"], Mapping)
            or set(binding["reconciliation"]) != _RECONCILIATION_FIELDS
        ):
            raise ValueError("execution reconciliation state binding is not exact")
        _strict_nonnegative_int(binding["state_version"], field="state_version")
        _strict_nonnegative_int(
            binding["durable_broker_generation"],
            field="durable_broker_generation",
        )
        if candidate["generation"] < binding["durable_broker_generation"]:
            raise ValueError("execution reconciliation snapshot generation regressed")
        reconciliation = binding["reconciliation"]
        if reconciliation["state"] not in _RECONCILIATION_STATE_VALUES:
            raise ValueError("execution reconciliation state binding is invalid")
        for field in ("run_id", "fresh_snapshot_id"):
            if (
                not isinstance(reconciliation[field], str)
                or IDENTIFIER_RE.fullmatch(reconciliation[field]) is None
            ):
                raise ValueError("execution reconciliation state binding is invalid")
        _strict_utc(reconciliation["last_completed_at"], field="last_completed_at")
        _strict_nonnegative_int(
            reconciliation["unknown_outcomes"], field="unknown_outcomes"
        )
        preimage = {
            key: candidate[key]
            for key in candidate
            if key != "reconciliation_snapshot_sha256"
        }
        if candidate["reconciliation_snapshot_sha256"] != sha256_json(preimage):
            raise ValueError("execution reconciliation snapshot hash does not close")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionReconciliationSnapshotProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


_ACTIVE_PLAN_RESUME_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "plan_id",
        "plan_hash",
        "leader_token",
        "reconciliation_snapshot",
    }
)
_ACTIVE_PLAN_RESUME_FIELDS = frozenset(
    {
        "schema_version",
        "plan_id",
        "plan_hash",
        "state",
        "expected_intent_count",
        "terminal_intent_count",
        "queried_intent_count",
        "new_intent_count",
        "reused_intent_count",
        "intents",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "resume_sha256",
    }
)
_ACTIVE_PLAN_RESUME_INTENT_FIELDS = frozenset({"intent_id", "state", "resume_action"})
_ACTIVE_PLAN_RESUME_INTENT_STATES = frozenset(
    {
        "PERSISTED",
        "SUBMITTED",
        "ACKNOWLEDGED",
        "UNKNOWN_OUTCOME",
        "TERMINAL",
        "RECONCILED",
        "CANCELLED",
    }
)
_ACTIVE_PLAN_RESUME_TERMINAL_STATES = frozenset({"TERMINAL", "RECONCILED", "CANCELLED"})
_ACTIVE_PLAN_RESUME_ACTIONS = frozenset(
    {"TERMINAL_REUSED", "REUSED", "QUERY_ONLY", "FIRST_SEND"}
)


@dataclass(frozen=True, slots=True)
class ExecutionActivePlanResumeRequest:
    """Strict high-level request for one installed ACTIVE plan.

    The request intentionally carries no order payload.  Execution derives the
    complete deterministic intent set from its create-only TargetPlan copy.
    """

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionActivePlanResumeRequest:
        candidate = _detached_object(value, name="execution active plan resume")
        if set(candidate) != _ACTIVE_PLAN_RESUME_REQUEST_FIELDS:
            raise ValueError("execution active plan resume fields are not exact")
        if (
            candidate["schema_version"]
            != "web_bridge_execution_active_plan_resume_request_v1"
            or not isinstance(candidate["plan_id"], str)
            or IDENTIFIER_RE.fullmatch(candidate["plan_id"]) is None
        ):
            raise ValueError("execution active plan resume identity is invalid")
        _strict_sha(candidate["plan_hash"], field="plan_hash")
        leader = ExecutionLeaderTokenProjection.from_mapping(candidate["leader_token"])
        snapshot = ExecutionReconciliationSnapshotProjection.from_mapping(
            candidate["reconciliation_snapshot"]
        )
        candidate["leader_token"] = leader.model_dump()
        candidate["reconciliation_snapshot"] = snapshot.model_dump()
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionActivePlanResumeRequest:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


@dataclass(frozen=True, slots=True)
class ExecutionActivePlanResumeProjection:
    """Order-free result of exact deterministic ACTIVE-plan recovery."""

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionActivePlanResumeProjection:
        candidate = _detached_object(value, name="execution active plan resume result")
        if set(candidate) != _ACTIVE_PLAN_RESUME_FIELDS:
            raise ValueError("execution active plan resume result fields are not exact")
        if (
            candidate["schema_version"] != "web_bridge_execution_active_plan_resume_v1"
            or candidate["state"] not in {"ACTIVE", "TERMINAL"}
            or not isinstance(candidate["plan_id"], str)
            or IDENTIFIER_RE.fullmatch(candidate["plan_id"]) is None
            or any(
                candidate[field] is not False
                for field in (
                    "production_allowed",
                    "live_trading_authorized",
                    "countable_forward",
                )
            )
        ):
            raise ValueError("execution active plan resume result identity is invalid")
        for field in ("plan_hash", "resume_sha256"):
            _strict_sha(candidate[field], field=field)
        for field in (
            "expected_intent_count",
            "terminal_intent_count",
            "queried_intent_count",
            "new_intent_count",
            "reused_intent_count",
        ):
            _strict_nonnegative_int(candidate[field], field=field)
        intents = candidate["intents"]
        if not isinstance(intents, list) or any(
            not isinstance(row, Mapping)
            or set(row) != _ACTIVE_PLAN_RESUME_INTENT_FIELDS
            or not isinstance(row["intent_id"], str)
            or IDENTIFIER_RE.fullmatch(row["intent_id"]) is None
            or row["state"] not in _ACTIVE_PLAN_RESUME_INTENT_STATES
            or row["resume_action"] not in _ACTIVE_PLAN_RESUME_ACTIONS
            for row in intents
        ):
            raise ValueError("execution active plan resume intents are invalid")
        intent_ids = [str(row["intent_id"]) for row in intents]
        terminal_count = sum(
            row["state"] in _ACTIVE_PLAN_RESUME_TERMINAL_STATES for row in intents
        )
        queried_count = sum(row["resume_action"] == "QUERY_ONLY" for row in intents)
        new_count = sum(row["resume_action"] == "FIRST_SEND" for row in intents)
        expected_count = candidate["expected_intent_count"]
        if (
            expected_count < 1
            or len(intents) != expected_count
            or len(set(intent_ids)) != expected_count
            or candidate["terminal_intent_count"] != terminal_count
            or candidate["queried_intent_count"] != queried_count
            or candidate["new_intent_count"] != new_count
            or candidate["reused_intent_count"] != expected_count - new_count
            or (candidate["state"] == "TERMINAL")
            is not (terminal_count == expected_count)
        ):
            raise ValueError("execution active plan resume counts do not close")
        preimage = {key: candidate[key] for key in candidate if key != "resume_sha256"}
        if candidate["resume_sha256"] != sha256_json(preimage):
            raise ValueError("execution active plan resume hash does not close")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionActivePlanResumeProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


_RECOVERY_BEFORE_CUSTODY_FIELDS = frozenset(
    {
        "schema_version",
        "state",
        "custody_idempotency_key",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "recovery_sha256",
    }
)
_RECOVERY_BOUND_FIELDS = frozenset(
    {
        "schema_version",
        "state",
        "custody_idempotency_key",
        "custody_install_idempotency_key",
        "custody_version",
        "receipt_id",
        "receipt_sha256",
        "artifact_id",
        "artifact_sha256",
        "artifact_envelope_sha256",
        "installed",
        "target_plan_schema_version",
        "plan_id",
        "plan_hash",
        "phase",
        "lineage",
        "account_scope",
        "environment",
        "gateway_name",
        "generated_at",
        "expires_at",
        "expected_before_position_hash",
        "expected_after_position_hash",
        "order_set_sha256",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "recovery_sha256",
    }
)
_RECOVERY_PUBLISHED_NOT_INSTALLED_FIELDS = frozenset(
    {
        "schema_version",
        "state",
        "custody_idempotency_key",
        "custody_install_idempotency_key",
        "observed_custody_version",
        "publisher_principal",
        "correlation_id",
        "publish_receipt_id",
        "publish_receipt_sha256",
        "publish_expected_custody_version",
        "publish_resulting_custody_version",
        "artifact_id",
        "artifact_canonical_sha256",
        "artifact_sha256",
        "artifact_schema_ref",
        "artifact_envelope_sha256",
        "installed",
        "install_only_allowed",
        "recovery_action",
        "target_plan_schema_version",
        "plan_id",
        "plan_hash",
        "phase",
        "lineage",
        "account_scope",
        "environment",
        "gateway_name",
        "generated_at",
        "expires_at",
        "expected_before_position_hash",
        "expected_after_position_hash",
        "order_set_sha256",
        "production_allowed",
        "live_trading_authorized",
        "countable_forward",
        "recovery_sha256",
    }
)
_RECOVERY_V3_IDENTITY_FIELDS = frozenset(
    {"execution_run_id", "creation_quote_proof_sha256"}
)
_RECOVERY_V3_START_FIELDS = frozenset(
    {
        "start_quote_proof_state",
        "start_quote_proof_sha256",
        "can_start_same_plan",
    }
)
_RECOVERY_PUBLISHED_NOT_INSTALLED_V3_FIELDS = frozenset(
    {*_RECOVERY_PUBLISHED_NOT_INSTALLED_FIELDS, *_RECOVERY_V3_IDENTITY_FIELDS}
)
_RECOVERY_BOUND_V3_FIELDS = frozenset(
    {
        *_RECOVERY_BOUND_FIELDS,
        *_RECOVERY_V3_IDENTITY_FIELDS,
        *_RECOVERY_V3_START_FIELDS,
    }
)


@dataclass(frozen=True, slots=True)
class ExecutionTargetPlanRecoveryProjection:
    """Strict custody/installation state for immutable v2/v3 plan recovery."""

    value: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> ExecutionTargetPlanRecoveryProjection:
        candidate = _detached_object(value, name="execution target plan recovery")
        fields = set(candidate)
        if fields == _RECOVERY_BEFORE_CUSTODY_FIELDS:
            if (
                candidate["schema_version"]
                != "web_bridge_execution_target_plan_recovery_v1"
                or candidate["state"] != "BEFORE_CUSTODY"
                or any(
                    candidate[field] is not False
                    for field in (
                        "production_allowed",
                        "live_trading_authorized",
                        "countable_forward",
                    )
                )
                or not isinstance(candidate["custody_idempotency_key"], str)
                or IDENTIFIER_RE.fullmatch(candidate["custody_idempotency_key"]) is None
            ):
                raise ValueError(
                    "execution before-custody recovery identity is invalid"
                )
            _strict_sha(candidate["recovery_sha256"], field="recovery_sha256")
            preimage = {
                key: candidate[key] for key in candidate if key != "recovery_sha256"
            }
            if candidate["recovery_sha256"] != sha256_json(preimage):
                raise ValueError("execution target plan recovery hash does not close")
            return cls(candidate)
        if fields in {
            _RECOVERY_PUBLISHED_NOT_INSTALLED_FIELDS,
            _RECOVERY_PUBLISHED_NOT_INSTALLED_V3_FIELDS,
        }:
            v3 = fields == _RECOVERY_PUBLISHED_NOT_INSTALLED_V3_FIELDS
            if (
                candidate["schema_version"]
                != (
                    "web_bridge_execution_target_plan_recovery_v3"
                    if v3
                    else "web_bridge_execution_target_plan_recovery_v2"
                )
                or candidate["state"] != "CUSTODY_PUBLISHED_NOT_INSTALLED"
                or candidate["target_plan_schema_version"]
                != (
                    KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
                    if v3
                    else KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
                )
                or candidate["artifact_schema_ref"]
                != candidate["target_plan_schema_version"]
                or candidate["installed"] is not False
                or not isinstance(candidate["install_only_allowed"], bool)
                or candidate["recovery_action"]
                != (
                    "INSTALL_ONLY"
                    if candidate["install_only_allowed"]
                    else "STOP_VERSION_DRIFT"
                )
                or candidate["phase"] not in {"CLOSE", "OPEN"}
                or candidate["environment"] != "SIMNOW"
                or candidate["gateway_name"] != "CTP"
                or any(
                    candidate[field] is not False
                    for field in (
                        "production_allowed",
                        "live_trading_authorized",
                        "countable_forward",
                    )
                )
            ):
                raise ValueError(
                    "execution published-only recovery identity is invalid"
                )
            for field in (
                "custody_idempotency_key",
                "custody_install_idempotency_key",
                "publisher_principal",
                "correlation_id",
                "publish_receipt_id",
                "artifact_id",
                "plan_id",
                "account_scope",
            ):
                if (
                    not isinstance(candidate[field], str)
                    or IDENTIFIER_RE.fullmatch(candidate[field]) is None
                ):
                    raise ValueError(
                        f"execution published-only recovery {field} is invalid"
                    )
            if candidate["custody_install_idempotency_key"] != (
                f"install-{candidate['custody_idempotency_key']}"
            ):
                raise ValueError(
                    "execution published-only recovery custody key mismatches"
                )
            for field in (
                "observed_custody_version",
                "publish_expected_custody_version",
                "publish_resulting_custody_version",
            ):
                _strict_nonnegative_int(candidate[field], field=field)
            if (
                candidate["publish_resulting_custody_version"]
                != candidate["publish_expected_custody_version"] + 1
                or candidate["observed_custody_version"]
                < candidate["publish_resulting_custody_version"]
                or candidate["install_only_allowed"]
                is not (
                    candidate["observed_custody_version"]
                    == candidate["publish_resulting_custody_version"]
                )
            ):
                raise ValueError(
                    "execution published-only recovery custody version is invalid"
                )
            for field in (
                "publish_receipt_sha256",
                "artifact_canonical_sha256",
                "artifact_sha256",
                "artifact_envelope_sha256",
                "plan_hash",
                "expected_before_position_hash",
                "expected_after_position_hash",
                "order_set_sha256",
                "recovery_sha256",
            ):
                _strict_sha(candidate[field], field=field)
            if v3:
                if (
                    not isinstance(candidate["execution_run_id"], str)
                    or IDENTIFIER_RE.fullmatch(candidate["execution_run_id"]) is None
                ):
                    raise ValueError(
                        "execution published-only recovery execution_run_id is invalid"
                    )
                _strict_sha(
                    candidate["creation_quote_proof_sha256"],
                    field="creation_quote_proof_sha256",
                )
            for field in ("generated_at", "expires_at"):
                _strict_utc(candidate[field], field=field)
            lineage = candidate["lineage"]
            if (
                not isinstance(lineage, Mapping)
                or set(lineage) != _COMPLETION_LINEAGE_FIELDS
            ):
                raise ValueError(
                    "execution published-only recovery lineage is not exact"
                )
            for field in _COMPLETION_LINEAGE_FIELDS:
                _strict_sha(lineage[field], field=f"lineage.{field}")
            preimage = {
                key: candidate[key] for key in candidate if key != "recovery_sha256"
            }
            if candidate["recovery_sha256"] != sha256_json(preimage):
                raise ValueError("execution target plan recovery hash does not close")
            return cls(candidate)
        if fields not in {_RECOVERY_BOUND_FIELDS, _RECOVERY_BOUND_V3_FIELDS}:
            raise ValueError("execution target plan recovery fields are not exact")
        v3 = fields == _RECOVERY_BOUND_V3_FIELDS
        if (
            candidate["schema_version"]
            != (
                "web_bridge_execution_target_plan_recovery_v3"
                if v3
                else "web_bridge_execution_target_plan_recovery_v1"
            )
            or candidate["target_plan_schema_version"]
            != (
                KEYLESS_TARGET_PLAN_V3_SCHEMA_VERSION
                if v3
                else KEYLESS_TARGET_PLAN_V2_SCHEMA_VERSION
            )
            or candidate["state"]
            not in {"CUSTODY_PUBLISHED_NOT_PREVIEWED", "INSTALLED"}
            or not isinstance(candidate["installed"], bool)
            or candidate["installed"] is not (candidate["state"] == "INSTALLED")
            or candidate["phase"] not in {"CLOSE", "OPEN"}
            or candidate["environment"] != "SIMNOW"
            or candidate["gateway_name"] != "CTP"
            or any(
                candidate[field] is not False
                for field in (
                    "production_allowed",
                    "live_trading_authorized",
                    "countable_forward",
                )
            )
        ):
            raise ValueError("execution target plan recovery identity is invalid")
        for field in (
            "custody_idempotency_key",
            "custody_install_idempotency_key",
            "receipt_id",
            "artifact_id",
            "plan_id",
            "account_scope",
        ):
            if (
                not isinstance(candidate[field], str)
                or IDENTIFIER_RE.fullmatch(candidate[field]) is None
            ):
                raise ValueError(f"execution target plan recovery {field} is invalid")
        if candidate["custody_install_idempotency_key"] != (
            f"install-{candidate['custody_idempotency_key']}"
        ):
            raise ValueError("execution target plan recovery custody key mismatches")
        _strict_nonnegative_int(candidate["custody_version"], field="custody_version")
        if candidate["custody_version"] < 1:
            raise ValueError(
                "execution target plan recovery custody version is invalid"
            )
        for field in (
            "receipt_sha256",
            "artifact_sha256",
            "artifact_envelope_sha256",
            "plan_hash",
            "expected_before_position_hash",
            "expected_after_position_hash",
            "order_set_sha256",
            "recovery_sha256",
        ):
            _strict_sha(candidate[field], field=field)
        if v3:
            if (
                not isinstance(candidate["execution_run_id"], str)
                or IDENTIFIER_RE.fullmatch(candidate["execution_run_id"]) is None
            ):
                raise ValueError(
                    "execution target plan recovery execution_run_id is invalid"
                )
            _strict_sha(
                candidate["creation_quote_proof_sha256"],
                field="creation_quote_proof_sha256",
            )
            start_state = candidate["start_quote_proof_state"]
            allowed_start_states = {
                "NOT_INSTALLED",
                "NOT_STARTED",
                "READY",
                "REPLAN_REQUIRED",
                "SOURCE_UNAVAILABLE",
                "EVIDENCE_INVALID",
                "STARTED_MATCHED",
            }
            if start_state not in allowed_start_states:
                raise ValueError(
                    "execution target plan recovery start quote state is invalid"
                )
            proof_hash = candidate["start_quote_proof_sha256"]
            if proof_hash is not None:
                _strict_sha(proof_hash, field="start_quote_proof_sha256")
            if not isinstance(candidate["can_start_same_plan"], bool):
                raise ValueError(
                    "execution target plan recovery can_start_same_plan is invalid"
                )
            has_proof = start_state in {"READY", "STARTED_MATCHED"}
            if (
                (proof_hash is not None) is not has_proof
                or candidate["can_start_same_plan"] is not (start_state == "READY")
                or (candidate["installed"] is False)
                is not (start_state == "NOT_INSTALLED")
            ):
                raise ValueError(
                    "execution target plan recovery start quote binding mismatches"
                )
        for field in ("generated_at", "expires_at"):
            _strict_utc(candidate[field], field=field)
        lineage = candidate["lineage"]
        if (
            not isinstance(lineage, Mapping)
            or set(lineage) != _COMPLETION_LINEAGE_FIELDS
        ):
            raise ValueError("execution target plan recovery lineage is not exact")
        for field in _COMPLETION_LINEAGE_FIELDS:
            _strict_sha(lineage[field], field=f"lineage.{field}")
        preimage = {
            key: candidate[key] for key in candidate if key != "recovery_sha256"
        }
        if candidate["recovery_sha256"] != sha256_json(preimage):
            raise ValueError("execution target plan recovery hash does not close")
        return cls(candidate)

    @classmethod
    def model_validate(cls, value: Any) -> ExecutionTargetPlanRecoveryProjection:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        del mode
        return json.loads(json.dumps(self.value, ensure_ascii=False))

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @property
    def plan_id(self) -> str:
        return str(self.value.get("plan_id", ""))

    @property
    def state(self) -> str:
        return str(self.value["state"])


# Explicit aliases make the boundary discoverable to callers that use the
# conventional DTO naming while retaining the shared execution model.
ControlExecutionCommandDTO = CommandEnvelope
CommandEnvelopeDTO = CommandEnvelope
ExecutionStatusDTO = ExecutionStatusProjection
ExecutionStatusProjectionDTO = ExecutionStatusProjection
ExecutionCompletionDTO = ExecutionCompletionProjection
ExecutionCompletionProjectionDTO = ExecutionCompletionProjection
ExecutionAccountFactsDTO = ExecutionAccountFactsProjectionV2
ExecutionAccountFactsV1DTO = ExecutionAccountFactsProjection
ExecutionAccountFactsV2DTO = ExecutionAccountFactsProjectionV2
ExecutionReconciliationSnapshotDTO = ExecutionReconciliationSnapshotProjection
ExecutionActivePlanResumeRequestDTO = ExecutionActivePlanResumeRequest
ExecutionActivePlanResumeDTO = ExecutionActivePlanResumeProjection
ExecutionTargetPlanRecoveryDTO = ExecutionTargetPlanRecoveryProjection
ExecutionLeaderStatusDTO = ExecutionLeaderStatusProjection
ExecutionLeaderTokenDTO = ExecutionLeaderTokenProjection


__all__ = [
    "CommandEnvelope",
    "CommandEnvelopeDTO",
    "ControlExecutionCommandDTO",
    "ExecutionCompletionDTO",
    "ExecutionCompletionProjection",
    "ExecutionCompletionProjectionDTO",
    "ExecutionAccountFactsDTO",
    "ExecutionAccountFactsProjection",
    "ExecutionAccountFactsProjectionV2",
    "ExecutionAccountFactsV1DTO",
    "ExecutionAccountFactsV2DTO",
    "ExecutionActivePlanResumeDTO",
    "ExecutionActivePlanResumeProjection",
    "ExecutionActivePlanResumeRequest",
    "ExecutionActivePlanResumeRequestDTO",
    "ExecutionLeaderStatusDTO",
    "ExecutionLeaderStatusProjection",
    "ExecutionLeaderTokenDTO",
    "ExecutionLeaderTokenProjection",
    "ExecutionReconciliationSnapshotDTO",
    "ExecutionReconciliationSnapshotProjection",
    "ExecutionStatusDTO",
    "ExecutionStatusProjection",
    "ExecutionStatusProjectionDTO",
    "ExecutionTargetPlanRecoveryDTO",
    "ExecutionTargetPlanRecoveryProjection",
]
