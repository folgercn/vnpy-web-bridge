"""Revalidate unsigned observation receipts against trusted source contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import sha256
from .custody_locks import stable_custody_identity
from .custody_transition import legacy_custody_identity_is_authorized
from .errors import RegistryError
from .filesystem import SAFE_COMPONENT, WarehousePaths, read_regular_strict
from .models import SourceEndpoint, SourceRegistry
from .observation_contracts import (
    CUSTODY_IDENTITY_SCHEME_V2,
    HTTP_METADATA_KEYS,
    ID_PATTERN,
    OBSERVATION_KEYS,
    OBSERVATION_SCHEMA,
    OBSERVATION_SCHEMA_V2,
    OBSERVATION_V2_KEYS,
    SHA256_PATTERN,
    observation_id,
    raw_object_id,
    validate_trade_day,
)
from .policy import render_endpoint
from .timeutil import parse_utc
from .validation import validate_source_bytes


def _safe_relative(paths: WarehousePaths, value: object) -> Path:
    if not isinstance(value, str):
        raise RegistryError("raw_relative_path must be a string")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise RegistryError("raw_relative_path is unsafe")
    absolute = paths.root / relative
    try:
        absolute.relative_to(paths.raw)
    except ValueError as exc:
        raise RegistryError("raw_relative_path is outside raw custody") from exc
    return absolute


def _trusted_source(
    registry: SourceRegistry,
    payload: dict[str, Any],
) -> SourceEndpoint:
    source_id = payload["source_id"]
    try:
        source = registry.source(source_id)
    except KeyError as exc:
        raise RegistryError("observation source is not in trusted registry") from exc
    if (
        payload["registry_raw_sha256"] != registry.raw_sha256
        or payload["exchange"] != source.exchange
        or payload["endpoint_schema_version"] != source.endpoint_schema_version
    ):
        raise RegistryError("observation trusted source contract binding mismatch")
    expected_url = render_endpoint(
        source.endpoint_template,
        payload["trade_day"].replace("-", ""),
    )
    if payload["source_url"] != expected_url:
        raise RegistryError("observation exact source URL binding mismatch")
    return source


def _validate_http_metadata(
    payload: dict[str, Any],
    source: SourceEndpoint,
) -> None:
    if payload["http_status"] != 200:
        raise RegistryError("observation HTTP status must be 200")
    metadata = payload["http_metadata"]
    if not isinstance(metadata, dict) or set(metadata) != HTTP_METADATA_KEYS:
        raise RegistryError("observation HTTP metadata fields are invalid")
    if any(
        value is not None and not isinstance(value, str)
        for value in metadata.values()
    ):
        raise RegistryError("observation HTTP metadata value type mismatch")
    content_length = metadata["content-length"]
    if content_length is not None:
        try:
            parsed_length = int(content_length)
        except ValueError as exc:
            raise RegistryError("observation HTTP content-length is invalid") from exc
        if parsed_length != payload["raw_bytes"]:
            raise RegistryError("observation HTTP content-length binding mismatch")
    content_type = metadata["content-type"]
    if (
        content_type is None
        or content_type.split(";", 1)[0].strip().lower() != source.media_type
    ):
        raise RegistryError("observation HTTP content-type binding mismatch")


def _observation_schema(payload: dict[str, Any]) -> str:
    schema = payload.get("schema_version")
    if schema == OBSERVATION_SCHEMA:
        if set(payload) != OBSERVATION_KEYS:
            raise RegistryError("observation fields do not match v1 schema")
        return schema
    if schema == OBSERVATION_SCHEMA_V2:
        if (
            set(payload) != OBSERVATION_V2_KEYS
            or payload.get("custody_identity_scheme") != CUSTODY_IDENTITY_SCHEME_V2
        ):
            raise RegistryError("observation fields do not match v2 schema")
        return schema
    raise RegistryError("observation schema mismatch")


def _validate_custody_identity(
    paths: WarehousePaths,
    payload: dict[str, Any],
    schema: str,
) -> None:
    claimed = payload["custody_identity_sha256"]
    if not isinstance(claimed, str) or SHA256_PATTERN.fullmatch(claimed) is None:
        raise RegistryError("observation custody_identity_sha256 is invalid")
    if schema == OBSERVATION_SCHEMA:
        if not legacy_custody_identity_is_authorized(paths, claimed):
            raise RegistryError("observation custody identity binding mismatch")
        return
    if claimed != stable_custody_identity(paths):
        raise RegistryError("observation stable custody identity binding mismatch")


def validate_observation(
    paths: WarehousePaths,
    payload: object,
    registry: SourceRegistry,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RegistryError("observation payload must be an object")
    schema = _observation_schema(payload)
    claimed = payload["observation_id"]
    if not isinstance(claimed, str) or claimed != observation_id(payload):
        raise RegistryError("observation ID binding mismatch")
    if payload["authority"] != "RESEARCH_EVIDENCE_ONLY":
        raise RegistryError("observation authority mismatch")
    text_fields = (
        "source_id",
        "exchange",
        "trade_day",
        "source_url",
        "collector_version",
        "endpoint_schema_version",
    )
    if any(not isinstance(payload[field], str) for field in text_fields):
        raise RegistryError("observation text field type mismatch")
    if any(
        SAFE_COMPONENT.fullmatch(payload[field]) is None
        for field in ("source_id", "exchange")
    ):
        raise RegistryError("observation source/exchange binding is unsafe")
    validate_trade_day(payload["trade_day"])
    source = _trusted_source(registry, payload)
    first = parse_utc(payload["first_seen_at"], "first_seen_at")
    last = parse_utc(payload["last_seen_at"], "last_seen_at")
    observed = parse_utc(payload["observed_at"], "observed_at")
    if first > observed or last != observed:
        raise RegistryError("observation first/last seen ordering is invalid")
    sequence = payload["observation_sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise RegistryError("observation sequence is invalid")
    for field in ("revision_id", "object_id"):
        if not isinstance(payload[field], str) or ID_PATTERN.fullmatch(
            payload[field]
        ) is None:
            raise RegistryError(f"observation {field} is invalid")
    for field in ("supersedes_revision_id", "supersedes_object_id"):
        value = payload[field]
        if value is not None and (
            not isinstance(value, str) or ID_PATTERN.fullmatch(value) is None
        ):
            raise RegistryError(f"observation {field} is invalid")
    digest = payload["raw_sha256"]
    if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
        raise RegistryError("observation raw SHA256 is invalid")
    raw_path = _safe_relative(paths, payload["raw_relative_path"])
    expected_relative = (
        Path("raw")
        / payload["exchange"].lower()
        / payload["trade_day"]
        / payload["source_id"]
        / f"{digest}.raw"
    )
    if Path(payload["raw_relative_path"]) != expected_relative:
        raise RegistryError("observation raw custody path binding mismatch")
    if (
        not isinstance(payload["raw_bytes"], int)
        or isinstance(payload["raw_bytes"], bool)
        or payload["raw_bytes"] < 0
    ):
        raise RegistryError("observation raw byte count is invalid")
    expected_object_id = raw_object_id(source, payload["trade_day"], digest)
    if payload["object_id"] != expected_object_id:
        raise RegistryError("observation object ID binding mismatch")
    for field in ("registry_raw_sha256", "custody_identity_sha256"):
        value = payload[field]
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise RegistryError(f"observation {field} is invalid")
    _validate_custody_identity(paths, payload, schema)
    _validate_http_metadata(payload, source)
    raw = read_regular_strict(raw_path, "observation raw object")
    if len(raw) != payload["raw_bytes"] or sha256(raw) != digest:
        raise RegistryError("observation/raw exact-byte binding mismatch")
    validate_source_bytes(raw, source, payload["trade_day"])
    return payload
