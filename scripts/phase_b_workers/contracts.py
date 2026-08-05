"""Versioned data contracts shared by the three Phase B workers.

Only standard-library types are used here.  The wire representation is stable
JSON so a producer and a consumer can be upgraded independently.  Hashes are
computed over canonical JSON with sorted keys and no whitespace.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import CONTRACT_VERSION, WORKER_PACKAGE_VERSION


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime | None = None) -> str:
    value = value or utc_now()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: object) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        text = str(value or "").strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        result = datetime.fromisoformat(text)
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _json_default(value: object) -> object:
    if isinstance(value, datetime):
        return isoformat(value)
    if hasattr(value, "as_dict"):
        return value.as_dict()
    raise TypeError(f"unsupported JSON value: {type(value)!r}")


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        default=_json_default,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_hex(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _number(value: object) -> float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return number


def _redact_mapping(value: Mapping[str, object]) -> dict[str, object]:
    """Return safe diagnostics without secret/account/path material."""

    blocked = (
        "token",
        "secret",
        "password",
        "credential",
        "private",
        "account",
        "key",
        "path",
    )
    output: dict[str, object] = {}
    for key, item in value.items():
        name = str(key).lower()
        if any(part in name for part in blocked):
            output[str(key)] = "[redacted]"
        elif isinstance(item, Mapping):
            output[str(key)] = _redact_mapping(item)
        elif isinstance(item, (list, tuple)):
            output[str(key)] = [
                _redact_mapping(entry) if isinstance(entry, Mapping) else entry
                for entry in item
            ]
        else:
            output[str(key)] = item
    return output


@dataclass(frozen=True)
class WorkerIdentity:
    service_id: str
    source_revision: str = "unknown"
    image_reference: str = "phase-b-worker:local"
    image_digest: str = "unknown"
    build_created_at_utc: str = "unknown"
    config_hash: str = "unknown"
    contract_versions: tuple[str, ...] = (CONTRACT_VERSION,)
    database_schema_versions: tuple[str, ...] = ()
    runtime_mode: str = "disabled"
    production_allowed: bool = False
    live_trading_authorized: bool = False
    countable_forward: bool = False

    @classmethod
    def from_environment(
        cls, service_id: str, *, runtime_mode: str = "disabled"
    ) -> WorkerIdentity:
        versions = tuple(
            item.strip()
            for item in os.getenv("PHASE_B_CONTRACT_VERSIONS", CONTRACT_VERSION).split(
                ","
            )
            if item.strip()
        ) or (CONTRACT_VERSION,)
        return cls(
            service_id=service_id,
            source_revision=os.getenv("SOURCE_REVISION", "unknown"),
            image_reference=os.getenv("IMAGE_REFERENCE", "phase-b-worker:local"),
            image_digest=os.getenv("IMAGE_DIGEST", "unknown"),
            build_created_at_utc=os.getenv("BUILD_CREATED_AT_UTC", "unknown"),
            config_hash=os.getenv("CONFIG_HASH", "unknown"),
            contract_versions=versions,
            database_schema_versions=tuple(
                item.strip()
                for item in os.getenv("DATABASE_SCHEMA_VERSIONS", "").split(",")
                if item.strip()
            ),
            runtime_mode=runtime_mode,
            # These are deliberately constants, not environment-controlled.
            production_allowed=False,
            live_trading_authorized=False,
            countable_forward=False,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "source_revision": self.source_revision,
            "image_reference": self.image_reference,
            "image_digest": self.image_digest,
            "build_created_at_utc": self.build_created_at_utc,
            "config_hash": self.config_hash,
            "contract_versions": list(self.contract_versions),
            "database_schema_versions": list(self.database_schema_versions),
            "runtime_mode": self.runtime_mode,
            "production_allowed": False,
            "live_trading_authorized": False,
            "countable_forward": False,
            "package_version": WORKER_PACKAGE_VERSION,
        }


@dataclass(frozen=True)
class HealthSnapshot:
    service_id: str
    status: str
    checked_at_utc: str
    process_started_at_utc: str
    dependencies: Mapping[str, object] = field(default_factory=dict)
    last_error_code: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "status": self.status,
            "checked_at_utc": self.checked_at_utc,
            "process_started_at_utc": self.process_started_at_utc,
            "dependencies": _redact_mapping(self.dependencies),
            "last_error_code": self.last_error_code,
        }


@dataclass(frozen=True)
class ReadinessSnapshot:
    service_id: str
    ready: bool
    checked_at_utc: str
    version_compatible: bool
    config_loaded: bool
    dependencies_ready: bool
    state_recovered: bool
    blockers: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "ready": bool(self.ready),
            "checked_at_utc": self.checked_at_utc,
            "version_compatible": bool(self.version_compatible),
            "config_loaded": bool(self.config_loaded),
            "dependencies_ready": bool(self.dependencies_ready),
            "state_recovered": bool(self.state_recovered),
            "blockers": list(self.blockers),
        }


@dataclass
class WorkerMetrics:
    service_id: str
    started_at_utc: str
    counters: dict[str, int] = field(default_factory=dict)
    queue_depth: int = 0
    worker_generation: str = "unknown"
    checkpoint_or_watermark: int | str | None = None
    oldest_pending_age_seconds: float | None = None
    last_success_at_utc: str | None = None

    def increment(self, name: str, amount: int = 1) -> None:
        self.counters[name] = int(self.counters.get(name, 0)) + amount

    def as_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "started_at_utc": self.started_at_utc,
            "service_info": {
                "service_id": self.service_id,
                "contract_version": CONTRACT_VERSION,
            },
            "counters": dict(sorted(self.counters.items())),
            "queue_depth": self.queue_depth,
            "worker_generation": self.worker_generation,
            "checkpoint_or_watermark": self.checkpoint_or_watermark,
            "oldest_pending_age_seconds": self.oldest_pending_age_seconds,
            "last_success_at_utc": self.last_success_at_utc,
        }


@dataclass(frozen=True)
class GatewayTickEnvelope:
    """Typed tick ingress owned by a read-only gateway adapter.

    The source capability is part of the signed/hashed envelope instead of an
    informal caller convention.  Worker code rejects every capability except
    ``market_data.read`` and therefore cannot be handed an order-capable RPC
    client by mistake.
    """

    event_id: str
    source_service: str
    source_generation: str
    source_seq: int
    observed_at_utc: str
    capability: str
    payload: Mapping[str, object]
    envelope_hash: str

    @classmethod
    def create(
        cls,
        *,
        event_id: str,
        source_service: str,
        source_generation: str,
        source_seq: int,
        payload: Mapping[str, object],
        observed_at: datetime | None = None,
    ) -> GatewayTickEnvelope:
        body: dict[str, object] = {
            "contract_version": CONTRACT_VERSION,
            "event_id": str(event_id),
            "source_service": str(source_service),
            "source_generation": str(source_generation),
            "source_seq": int(source_seq),
            "observed_at_utc": isoformat(observed_at),
            "capability": "market_data.read",
            "payload": dict(payload),
        }
        return cls(
            envelope_hash=sha256_hex(body),
            **{k: v for k, v in body.items() if k != "contract_version"},
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> GatewayTickEnvelope:
        payload = value.get("payload")
        if not isinstance(payload, Mapping):
            raise TypeError("gateway tick payload must be an object")
        envelope = cls(
            event_id=str(value.get("event_id") or ""),
            source_service=str(value.get("source_service") or ""),
            source_generation=str(value.get("source_generation") or ""),
            source_seq=int(value.get("source_seq") or 0),
            observed_at_utc=isoformat(parse_time(value.get("observed_at_utc"))),
            capability=str(value.get("capability") or ""),
            payload=dict(payload),
            envelope_hash=str(value.get("envelope_hash") or ""),
        )
        if (
            not envelope.event_id
            or not envelope.source_service
            or envelope.source_seq < 1
        ):
            raise ValueError("gateway tick identity/source sequence is invalid")
        normalized_source = envelope.source_service.lower().replace("-", "_")
        if "vnpy_rpc" in normalized_source or "rpc_service" in normalized_source:
            raise ValueError(
                "legacy RPC services are not valid market-data ingress owners"
            )
        if envelope.capability != "market_data.read":
            raise ValueError("only market_data.read ingress is accepted")
        forbidden = {"send_order", "cancel_order", "send", "cancel", "order_request"}
        if forbidden.intersection(str(key).lower() for key in envelope.payload):
            raise ValueError(
                "order-capable payload fields are forbidden on tick ingress"
            )
        if envelope.envelope_hash != envelope.compute_hash():
            raise ValueError("gateway tick envelope hash mismatch")
        return envelope

    def compute_hash(self) -> str:
        return sha256_hex(
            {
                "contract_version": CONTRACT_VERSION,
                "event_id": self.event_id,
                "source_service": self.source_service,
                "source_generation": self.source_generation,
                "source_seq": self.source_seq,
                "observed_at_utc": self.observed_at_utc,
                "capability": self.capability,
                "payload": dict(self.payload),
            }
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "contract_version": CONTRACT_VERSION,
            "event_id": self.event_id,
            "source_service": self.source_service,
            "source_generation": self.source_generation,
            "source_seq": self.source_seq,
            "observed_at_utc": self.observed_at_utc,
            "capability": self.capability,
            "payload": dict(self.payload),
            "envelope_hash": self.envelope_hash,
        }


@dataclass(frozen=True)
class VerifiedTick:
    """Canonical tick event written once by market-data-worker."""

    stream_generation: str
    ingest_id: str
    ingest_seq: int
    event_time_utc: str
    vt_symbol: str
    source: str
    source_event_id: str
    received_at_utc: str
    bid_price: float | None = None
    ask_price: float | None = None
    last_price: float | None = None
    bid_volume: float | None = None
    ask_volume: float | None = None
    last_volume: float | None = None
    raw_hash: str = ""
    event_hash: str = ""

    @classmethod
    def from_raw(
        cls,
        raw: Mapping[str, object],
        *,
        stream_generation: str,
        ingest_seq: int,
        source: str = "readonly_market_source",
        received_at: datetime | None = None,
    ) -> VerifiedTick:
        symbol = str(raw.get("vt_symbol") or raw.get("symbol") or "").strip()
        if not symbol:
            raise ValueError("vt_symbol is required")
        event_value = (
            raw.get("event_time_utc") or raw.get("datetime") or raw.get("timestamp")
        )
        event_time = parse_time(event_value or received_at or utc_now())
        source_event_id = str(
            raw.get("source_event_id") or raw.get("event_id") or raw.get("id") or ""
        ).strip()
        received = received_at or utc_now()
        body = {
            "event_time_utc": isoformat(event_time),
            "vt_symbol": symbol,
            "source": source,
            "source_event_id": source_event_id,
            "bid_price": _number(raw.get("bid_price") or raw.get("bidPrice")),
            "ask_price": _number(raw.get("ask_price") or raw.get("askPrice")),
            "last_price": _number(
                raw.get("last_price") or raw.get("lastPrice") or raw.get("price")
            ),
            "bid_volume": _number(raw.get("bid_volume") or raw.get("bidVolume")),
            "ask_volume": _number(raw.get("ask_volume") or raw.get("askVolume")),
            "last_volume": _number(
                raw.get("last_volume") or raw.get("lastVolume") or raw.get("volume")
            ),
        }
        raw_hash = sha256_hex(_redact_mapping(raw))
        ingest_id = source_event_id or sha256_hex({"source": source, **body})[:32]
        tick = cls(
            stream_generation=stream_generation,
            ingest_id=ingest_id,
            ingest_seq=int(ingest_seq),
            received_at_utc=isoformat(received),
            raw_hash=raw_hash,
            event_hash="",
            **body,
        )
        return cls(**{**tick.__dict__, "event_hash": tick.compute_event_hash()})

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> VerifiedTick:
        required = (
            "stream_generation",
            "ingest_id",
            "ingest_seq",
            "event_time_utc",
            "vt_symbol",
            "event_hash",
        )
        missing = [name for name in required if name not in value]
        if missing:
            raise ValueError(f"verified tick missing fields: {','.join(missing)}")
        tick = cls(
            stream_generation=str(value["stream_generation"]),
            ingest_id=str(value["ingest_id"]),
            ingest_seq=int(value["ingest_seq"]),
            event_time_utc=isoformat(parse_time(value["event_time_utc"])),
            vt_symbol=str(value["vt_symbol"]),
            source=str(value.get("source") or "readonly_market_source"),
            source_event_id=str(value.get("source_event_id") or ""),
            received_at_utc=isoformat(
                parse_time(value.get("received_at_utc") or value["event_time_utc"])
            ),
            bid_price=_number(value.get("bid_price")),
            ask_price=_number(value.get("ask_price")),
            last_price=_number(value.get("last_price")),
            bid_volume=_number(value.get("bid_volume")),
            ask_volume=_number(value.get("ask_volume")),
            last_volume=_number(value.get("last_volume")),
            raw_hash=str(value.get("raw_hash") or ""),
            event_hash=str(value["event_hash"]),
        )
        if tick.event_hash != tick.compute_event_hash():
            raise ValueError("verified tick event_hash mismatch")
        return tick

    def body(self) -> dict[str, object]:
        return {
            "contract_version": CONTRACT_VERSION,
            "stream_generation": self.stream_generation,
            "ingest_id": self.ingest_id,
            "ingest_seq": int(self.ingest_seq),
            "event_time_utc": self.event_time_utc,
            "vt_symbol": self.vt_symbol,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "received_at_utc": self.received_at_utc,
            "bid_price": self.bid_price,
            "ask_price": self.ask_price,
            "last_price": self.last_price,
            "bid_volume": self.bid_volume,
            "ask_volume": self.ask_volume,
            "last_volume": self.last_volume,
            "raw_hash": self.raw_hash,
        }

    def compute_event_hash(self) -> str:
        return sha256_hex(self.body())

    def as_dict(self) -> dict[str, object]:
        value = self.body()
        value["event_hash"] = self.event_hash
        return value


@dataclass(frozen=True)
class ExecutionQualityEvidence:
    evidence_id: str
    stream_generation: str
    ingest_id: str
    ingest_seq: int
    source_event_hash: str
    measured_at_utc: str
    algorithm_version: str
    metrics: Mapping[str, object]
    evidence_hash: str

    @classmethod
    def for_tick(
        cls,
        tick: VerifiedTick,
        *,
        metrics: Mapping[str, object],
        algorithm_version: str = "eq_v1",
        measured_at: datetime | None = None,
    ) -> ExecutionQualityEvidence:
        # Default to the durable source observation, not wall-clock processing
        # time, so crash replay recreates the identical evidence hash.
        measured = isoformat(measured_at or parse_time(tick.received_at_utc))
        body = {
            "contract_version": CONTRACT_VERSION,
            "stream_generation": tick.stream_generation,
            "ingest_id": tick.ingest_id,
            "ingest_seq": tick.ingest_seq,
            "source_event_hash": tick.event_hash,
            "measured_at_utc": measured,
            "algorithm_version": algorithm_version,
            "metrics": dict(metrics),
        }
        evidence_hash = sha256_hex(body)
        return cls(
            evidence_id=f"{tick.stream_generation}:{tick.ingest_id}:{algorithm_version}",
            evidence_hash=evidence_hash,
            **{key: value for key, value in body.items() if key != "contract_version"},
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "contract_version": CONTRACT_VERSION,
            "evidence_id": self.evidence_id,
            "stream_generation": self.stream_generation,
            "ingest_id": self.ingest_id,
            "ingest_seq": self.ingest_seq,
            "source_event_hash": self.source_event_hash,
            "measured_at_utc": self.measured_at_utc,
            "algorithm_version": self.algorithm_version,
            "metrics": _redact_mapping(self.metrics),
            "evidence_hash": self.evidence_hash,
        }


@dataclass(frozen=True)
class IncidentEvent:
    incident_id: str
    episode_key: str
    service_id: str
    severity: str
    state: str
    summary: str
    occurred_at_utc: str
    source_revision: str
    details: Mapping[str, object] = field(default_factory=dict)
    event_hash: str = ""

    @classmethod
    def create(
        cls,
        *,
        service_id: str,
        episode_key: str,
        severity: str,
        state: str,
        summary: str,
        source_revision: str,
        details: Mapping[str, object] | None = None,
        occurred_at: datetime | None = None,
    ) -> IncidentEvent:
        occurred = isoformat(occurred_at)
        safe_details = _redact_mapping(details or {})
        incident_id = sha256_hex(
            {
                "service_id": service_id,
                "episode_key": episode_key,
                "occurred_at_utc": occurred,
            }
        )[:32]
        body = {
            "incident_id": incident_id,
            "episode_key": episode_key,
            "service_id": service_id,
            "severity": severity,
            "state": state,
            "summary": summary,
            "occurred_at_utc": occurred,
            "source_revision": source_revision,
            "details": safe_details,
        }
        return cls(event_hash=sha256_hex(body), **body)

    def as_dict(self) -> dict[str, object]:
        value = {
            "contract_version": CONTRACT_VERSION,
            "incident_id": self.incident_id,
            "episode_key": self.episode_key,
            "service_id": self.service_id,
            "severity": self.severity,
            "state": self.state,
            "summary": self.summary,
            "occurred_at_utc": self.occurred_at_utc,
            "source_revision": self.source_revision,
            "details": _redact_mapping(self.details),
        }
        value["event_hash"] = self.event_hash
        return value


def project_dependency(value: object) -> dict[str, object]:
    """Normalize one external health/metrics projection to safe JSON."""

    if isinstance(value, HealthSnapshot):
        return value.as_dict()
    if isinstance(value, ReadinessSnapshot):
        return value.as_dict()
    if isinstance(value, Mapping):
        return _redact_mapping(value)
    raise TypeError("dependency projection must be a mapping or typed snapshot")
