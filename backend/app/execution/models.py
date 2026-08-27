"""Contract-facing typed models for the Phase A execution boundary.

This module deliberately uses the standard library.  The execution process is
also used by small offline acceptance tools where importing the legacy FastAPI
application (and its optional dependencies) would accidentally create another
state owner.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar

from .errors import CommandValidationError, UnknownCommandError

SCHEMA_VERSION = "web_bridge_control_execution_command_v1"
STATUS_SCHEMA_VERSION = "web_bridge_execution_status_v1"
SERVICE = "execution-orchestrator"
CONTROL_SERVICE = "control-api"
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")

COMMANDS = (
    "status",
    "overview",
    "preview",
    "enable",
    "revoke",
    "start",
    "stop",
    "reconcile",
    "drain",
    "safe_to_restart",
)
ROLES = ("viewer", "trader", "admin", "system")
MODES = ("offline_preview", "simnow_preview")

ZERO_HASH = "0" * 64
UNKNOWN_ID = "unknown00"
EPOCH_TIMESTAMP = "1970-01-01T00:00:00Z"
FUTURE_SKEW_SECONDS = 2
SNAPSHOT_STALE_SECONDS = 60


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    """Format an aware datetime using the schema's UTC ``Z`` representation."""

    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone aware")
    value = value.astimezone(timezone.utc)
    text = value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    # The schema accepts one to six fractional digits.  Avoid noisy trailing 0s.
    if "." in text:
        head, tail = text[:-1].split(".", 1)
        tail = tail.rstrip("0")
        text = f"{head}{('.' + tail) if tail else ''}Z"
    return text


def parse_utc(value: Any, *, field_name: str = "timestamp") -> str:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise CommandValidationError(f"{field_name} must be a UTC Z timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CommandValidationError(f"{field_name} is not a valid timestamp") from exc
    return value


def _strict_string(
    value: Any, field_name: str, *, min_length: int = 1, max_length: int = 128
) -> str:
    if not isinstance(value, str) or not (min_length <= len(value) <= max_length):
        raise CommandValidationError(
            f"{field_name} must be a string of length {min_length}..{max_length}"
        )
    return value


def validate_identifier(value: Any, field_name: str = "identifier") -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise CommandValidationError(f"{field_name} is not a valid identifier")
    return value


def validate_idempotency_key(value: Any) -> str:
    if not isinstance(value, str) or not IDEMPOTENCY_RE.fullmatch(value):
        raise CommandValidationError("idempotency_key is not valid")
    return value


def validate_sha256(value: Any, field_name: str = "hash") -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise CommandValidationError(f"{field_name} must be a lowercase SHA-256 hash")
    return value


def _strict_int(value: Any, field_name: str, *, minimum: int = 0) -> int:
    # bool is an int subclass, but is not a valid schema integer here.
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CommandValidationError(f"{field_name} must be an integer >= {minimum}")
    return value


def canonical_json(value: Any) -> str:
    """Return deterministic JSON and reject values not representable in JSON."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CommandValidationError("value is not canonical JSON") from exc


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Actor:
    service: str
    principal: str
    operator: str
    role: str

    @classmethod
    def from_mapping(cls, value: Any) -> Actor:
        if not isinstance(value, Mapping):
            raise CommandValidationError("actor must be an object")
        _reject_unknown(value, {"service", "principal", "operator", "role"}, "actor")
        required(value, ("service", "principal", "operator", "role"), "actor")
        service = _strict_string(value["service"], "actor.service")
        if service != CONTROL_SERVICE:
            raise CommandValidationError("actor.service must be control-api")
        role = value["role"]
        if not isinstance(role, str) or role not in ROLES:
            raise CommandValidationError("actor.role is not supported")
        return cls(
            service=service,
            principal=_strict_string(value["principal"], "actor.principal"),
            operator=_strict_string(value["operator"], "actor.operator"),
            role=role,
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "service": self.service,
            "principal": self.principal,
            "operator": self.operator,
            "role": self.role,
        }


@dataclass(frozen=True, slots=True)
class ExpectedVersion:
    state_version: int
    plan_hash: str | None = None
    authority_hash: str | None = None
    leader_epoch: int | None = None
    fencing_token: int | None = None

    @classmethod
    def from_mapping(cls, value: Any) -> ExpectedVersion:
        if not isinstance(value, Mapping):
            raise CommandValidationError("expected must be an object")
        allowed = {
            "state_version",
            "plan_hash",
            "authority_hash",
            "leader_epoch",
            "fencing_token",
        }
        _reject_unknown(value, allowed, "expected")
        required(value, ("state_version",), "expected")
        kwargs: dict[str, Any] = {
            "state_version": _strict_int(
                value["state_version"], "expected.state_version"
            ),
        }
        for name in ("leader_epoch", "fencing_token"):
            if name in value:
                kwargs[name] = _strict_int(value[name], f"expected.{name}")
        for name in ("plan_hash", "authority_hash"):
            if name in value:
                kwargs[name] = validate_sha256(value[name], f"expected.{name}")
        return cls(**kwargs)

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"state_version": self.state_version}
        for name in ("plan_hash", "authority_hash", "leader_epoch", "fencing_token"):
            value = getattr(self, name)
            if value is not None:
                result[name] = value
        return result


def required(value: Mapping[str, Any], names: Iterable[str], context: str) -> None:
    missing = [name for name in names if name not in value]
    if missing:
        raise CommandValidationError(
            f"{context} missing required field(s): {', '.join(missing)}"
        )


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = set(value).difference(allowed)
    if unknown:
        raise CommandValidationError(
            f"{context} contains unknown field(s): {', '.join(sorted(unknown))}"
        )


def _payload(command: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CommandValidationError("payload must be an object")
    raw = dict(value)
    specs: dict[str, tuple[set[str], tuple[str, ...]]] = {
        "status": (set(), ()),
        "overview": (set(), ()),
        "preview": (
            {"plan_hash", "artifact_hash", "mode", "receipt_id"},
            ("plan_hash", "artifact_hash", "mode"),
        ),
        "enable": (
            {"authority_artifact_id", "authority_hash", "expires_at", "reason"},
            ("authority_artifact_id", "authority_hash", "expires_at", "reason"),
        ),
        "revoke": ({"reason"}, ("reason",)),
        "start": (
            {"plan_id", "plan_hash", "reason"},
            ("plan_id", "plan_hash", "reason"),
        ),
        "stop": ({"reason"}, ("reason",)),
        "reconcile": (
            {
                "reconciliation_run_id",
                "snapshot_id",
                "snapshot_fact_binding",
                "reason",
            },
            ("reconciliation_run_id", "snapshot_id", "reason"),
        ),
        "drain": ({"drain_id", "reason", "deadline_at"}, ("drain_id", "reason")),
        "safe_to_restart": ({"receipt_id", "reason"}, ("receipt_id", "reason")),
    }
    if command not in specs:
        raise UnknownCommandError(command)
    allowed, required_names = specs[command]
    _reject_unknown(raw, allowed, f"{command}.payload")
    required(raw, required_names, f"{command}.payload")
    if command in ("status", "overview") and raw:
        raise CommandValidationError(f"{command}.payload must be empty")
    if command == "preview":
        validate_sha256(raw["plan_hash"], "payload.plan_hash")
        validate_sha256(raw["artifact_hash"], "payload.artifact_hash")
        if not isinstance(raw["mode"], str) or raw["mode"] not in MODES:
            raise CommandValidationError("payload.mode is not supported")
        if raw["mode"] == "simnow_preview":
            if "receipt_id" not in raw:
                raise CommandValidationError(
                    "simnow_preview requires payload.receipt_id"
                )
            validate_identifier(raw["receipt_id"], "payload.receipt_id")
        elif "receipt_id" in raw:
            raise CommandValidationError(
                "offline_preview does not accept payload.receipt_id"
            )
    elif command == "enable":
        validate_identifier(
            raw["authority_artifact_id"], "payload.authority_artifact_id"
        )
        validate_sha256(raw["authority_hash"], "payload.authority_hash")
        parse_utc(raw["expires_at"], field_name="payload.expires_at")
        _strict_string(raw["reason"], "payload.reason", min_length=8, max_length=500)
    elif command in ("revoke", "stop"):
        _strict_string(raw["reason"], "payload.reason", min_length=8, max_length=500)
    elif command == "start":
        validate_identifier(raw["plan_id"], "payload.plan_id")
        validate_sha256(raw["plan_hash"], "payload.plan_hash")
        _strict_string(raw["reason"], "payload.reason", min_length=8, max_length=500)
    elif command == "reconcile":
        validate_identifier(
            raw["reconciliation_run_id"], "payload.reconciliation_run_id"
        )
        validate_identifier(raw["snapshot_id"], "payload.snapshot_id")
        if "snapshot_fact_binding" in raw:
            binding = raw["snapshot_fact_binding"]
            if not isinstance(binding, Mapping) or set(binding) != {
                "generation",
                "position_snapshot_hash",
                "active_order_count",
                "active_orders_sha256",
                "state_version",
                "durable_broker_generation",
            }:
                raise CommandValidationError(
                    "payload.snapshot_fact_binding is invalid"
                )
            for field in (
                "generation",
                "active_order_count",
                "state_version",
                "durable_broker_generation",
            ):
                value = binding[field]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise CommandValidationError(
                        f"payload.snapshot_fact_binding.{field} is invalid"
                    )
            validate_sha256(
                binding["position_snapshot_hash"],
                "payload.snapshot_fact_binding.position_snapshot_hash",
            )
            validate_sha256(
                binding["active_orders_sha256"],
                "payload.snapshot_fact_binding.active_orders_sha256",
            )
        _strict_string(raw["reason"], "payload.reason", min_length=8, max_length=500)
    elif command == "drain":
        validate_identifier(raw["drain_id"], "payload.drain_id")
        _strict_string(raw["reason"], "payload.reason", min_length=8, max_length=500)
        if "deadline_at" in raw:
            parse_utc(raw["deadline_at"], field_name="payload.deadline_at")
    elif command == "safe_to_restart":
        validate_identifier(raw["receipt_id"], "payload.receipt_id")
        _strict_string(raw["reason"], "payload.reason", min_length=8, max_length=500)
    # Make a detached JSON-compatible copy; mutable caller dictionaries must not
    # be able to alter a receipt fingerprint after validation.
    try:
        return json.loads(canonical_json(raw))
    except (
        json.JSONDecodeError
    ) as exc:  # pragma: no cover - canonical_json catches this
        raise CommandValidationError("payload is not JSON-compatible") from exc


@dataclass(frozen=True, slots=True)
class CommandEnvelope:
    schema_version: str
    command_id: str
    idempotency_key: str
    correlation_id: str
    issued_at: str
    actor: Actor
    command: str
    expected: ExpectedVersion
    payload: dict[str, Any] = field(default_factory=dict)

    ALLOWED_FIELDS: ClassVar[set[str]] = {
        "schema_version",
        "command_id",
        "idempotency_key",
        "correlation_id",
        "issued_at",
        "actor",
        "command",
        "expected",
        "payload",
    }

    @classmethod
    def from_mapping(cls, value: Any) -> CommandEnvelope:
        if not isinstance(value, Mapping):
            raise CommandValidationError("command envelope must be an object")
        _reject_unknown(value, cls.ALLOWED_FIELDS, "command envelope")
        required(value, tuple(cls.ALLOWED_FIELDS), "command envelope")
        if value["schema_version"] != SCHEMA_VERSION:
            raise CommandValidationError("unsupported command schema_version")
        command = value["command"]
        if not isinstance(command, str) or command not in COMMANDS:
            raise UnknownCommandError(str(command))
        return cls(
            schema_version=SCHEMA_VERSION,
            command_id=validate_identifier(value["command_id"], "command_id"),
            idempotency_key=validate_idempotency_key(value["idempotency_key"]),
            correlation_id=validate_identifier(
                value["correlation_id"], "correlation_id"
            ),
            issued_at=parse_utc(value["issued_at"], field_name="issued_at"),
            actor=Actor.from_mapping(value["actor"]),
            command=command,
            expected=ExpectedVersion.from_mapping(value["expected"]),
            payload=_payload(command, value["payload"]),
        )

    @classmethod
    def model_validate(cls, value: Any) -> CommandEnvelope:
        return cls.from_mapping(value)

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "command_id": self.command_id,
            "idempotency_key": self.idempotency_key,
            "correlation_id": self.correlation_id,
            "issued_at": self.issued_at,
            "actor": self.actor.as_dict(),
            "command": self.command,
            "expected": self.expected.as_dict(),
            "payload": json.loads(canonical_json(self.payload)),
        }
        return result

    def canonical_command(self) -> dict[str, Any]:
        """Semantic command identity used by idempotency receipts.

        ``command_id``, correlation and issuance time are transport metadata and
        may change when a caller retries the same idempotent request.  Actor,
        expected version, command and payload remain part of the hash.
        """

        return {
            "actor": self.actor.as_dict(),
            "command": self.command,
            "expected": self.expected.as_dict(),
            "payload": self.payload,
        }

    def canonical_payload(self) -> str:
        return canonical_json(self.payload)

    def command_hash(self) -> str:
        return sha256_json(self.canonical_command())

    # Aliases used by callers that call this a fingerprint rather than hash.
    fingerprint = command_hash


@dataclass(frozen=True, slots=True)
class LeaderToken:
    scope: str
    owner_id: str
    epoch: int
    fencing_token: int
    lease_expires_at: str
    # Internal process-instance binding.  It is deliberately omitted from the
    # public status projection but is required for lease renew/mutation
    # admission, so two processes sharing an owner_id cannot share a token.
    instance_id: str = ""

    def as_dict(self, *, held: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "scope": self.scope,
            "owner_id": self.owner_id,
            "held": held,
            "epoch": self.epoch,
            "fencing_token": self.fencing_token,
            "lease_expires_at": self.lease_expires_at,
        }
        if self.instance_id:
            result["instance_id"] = self.instance_id
        return result


@dataclass(frozen=True, slots=True)
class AuthorityState:
    state: str = "DISABLED"
    artifact_id: str = UNKNOWN_ID
    artifact_hash: str = ZERO_HASH
    expires_at: str = EPOCH_TIMESTAMP

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "artifact_id": self.artifact_id,
            "artifact_hash": self.artifact_hash,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class PlanState:
    state: str = "IDLE"
    plan_id: str = UNKNOWN_ID
    plan_hash: str = ZERO_HASH
    version: int = 0
    # Preview provenance is durable execution evidence, rather than a hint
    # retained by a transient Control request.  In particular, a final SIMNOW
    # runner may start only from a simnow_preview bound to this receipt.
    preview_mode: str = ""
    preview_receipt_id: str = UNKNOWN_ID
    preview_receipt_sha256: str = ZERO_HASH
    preview_artifact_id: str = UNKNOWN_ID
    preview_artifact_sha256: str = ZERO_HASH

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "version": self.version,
            "preview_mode": self.preview_mode,
            "preview_receipt_id": self.preview_receipt_id,
            "preview_receipt_sha256": self.preview_receipt_sha256,
            "preview_artifact_id": self.preview_artifact_id,
            "preview_artifact_sha256": self.preview_artifact_sha256,
        }


@dataclass(frozen=True, slots=True)
class SendIntent:
    intent_id: str
    idempotency_key: str
    state: str
    plan_id: str
    plan_hash: str
    leader_epoch: int
    fencing_token: int
    created_at: str
    action: str = "send"
    broker_order_id: str | None = None
    request_hash: str = ZERO_HASH
    target_intent_id: str | None = None
    unknown_reason: str | None = None
    receipt_id: str | None = None
    receipt_hash: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "intent_id": self.intent_id,
            "idempotency_key": self.idempotency_key,
            "state": self.state,
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "leader_epoch": self.leader_epoch,
            "fencing_token": self.fencing_token,
            "created_at": self.created_at,
        }
        if self.broker_order_id is not None:
            result["broker_order_id"] = self.broker_order_id
        if self.receipt_id is not None:
            result["receipt_id"] = self.receipt_id
        if self.receipt_hash is not None:
            result["receipt_hash"] = self.receipt_hash
        return result


@dataclass(frozen=True, slots=True)
class ReconciliationState:
    state: str = "REQUIRED"
    run_id: str = UNKNOWN_ID
    last_completed_at: str = EPOCH_TIMESTAMP
    unknown_outcomes: int = 0
    fresh_snapshot_id: str = UNKNOWN_ID

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "run_id": self.run_id,
            "last_completed_at": self.last_completed_at,
            "unknown_outcomes": self.unknown_outcomes,
            "fresh_snapshot_id": self.fresh_snapshot_id,
        }


@dataclass(frozen=True, slots=True)
class BrokerState:
    connected: bool = False
    generation: int = 0
    active_order_count: int = 0
    position_snapshot_hash: str = ZERO_HASH
    last_snapshot_at: str = EPOCH_TIMESTAMP
    orders: dict[str, Any] = field(default_factory=dict)
    positions: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "connected": self.connected,
            "generation": self.generation,
            "active_order_count": self.active_order_count,
            "position_snapshot_hash": self.position_snapshot_hash,
            "last_snapshot_at": self.last_snapshot_at,
            "orders": dict(self.orders),
            "positions": dict(self.positions),
        }


@dataclass(frozen=True, slots=True)
class CommandReceipt:
    service: str
    idempotency_key: str
    command_hash: str
    command_id: str
    correlation_id: str
    actor: dict[str, str]
    status: str
    state_version: int
    result: dict[str, Any]
    observed_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "idempotency_key": self.idempotency_key,
            "command_hash": self.command_hash,
            "command_id": self.command_id,
            "correlation_id": self.correlation_id,
            "actor": dict(self.actor),
            "status": self.status,
            "state_version": self.state_version,
            "result": self.result,
            "observed_at": self.observed_at,
        }
