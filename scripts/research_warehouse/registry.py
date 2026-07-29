"""Strict parser for the frozen SHFE/INE source registry."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import RegistryError
from .models import SourceEndpoint, SourceRegistry
from .policy import (
    APPROVED_EXCHANGES,
    APPROVED_MEDIA_TYPES,
    validate_authority,
    validate_https_url,
)

REGISTRY_SCHEMA_VERSION = "vnpy_research_source_registry_v1"
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
MAX_REGISTRY_BYTES = 1024 * 1024
SOURCE_KEYS = frozenset(
    {
        "allowed_hosts",
        "availability_policy",
        "documentation_url",
        "endpoint_schema_version",
        "endpoint_template",
        "exchange",
        "license_policy",
        "media_type",
        "owner",
        "owner_reference_url",
        "required_row_fields",
        "required_top_level_fields",
        "source_id",
        "use_terms_url",
    }
)
ROOT_KEYS = frozenset(
    {
        "authority",
        "published_at",
        "registry_id",
        "schema_version",
        "sources",
        "timestamp_storage",
        "timezone",
    }
)
EXCHANGE_HOSTS = {
    "SHFE": "www.shfe.com.cn",
    "INE": "www.ine.cn",
}


def _read_exact_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RegistryError(f"source registry is unavailable: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RegistryError("source registry must be a regular non-symlink file")
    if before.st_nlink != 1:
        raise RegistryError("source registry must not be a hardlink")
    if before.st_size > MAX_REGISTRY_BYTES:
        raise RegistryError("source registry exceeds size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        raw = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw += chunk
            if len(raw) > MAX_REGISTRY_BYTES:
                raise RegistryError("source registry exceeds size limit")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    current = path.lstat()
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_nlink,
    )
    if identity(before) != identity(opened) or identity(opened) != identity(after):
        raise RegistryError("source registry changed while being read")
    if identity(after) != identity(current):
        raise RegistryError("source registry changed after being read")
    return raw


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise RegistryError(f"{label} must be a non-empty trimmed string")
    return value


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RegistryError(f"{label} must be a non-empty array")
    result = tuple(_string(item, label) for item in value)
    if len(set(result)) != len(result):
        raise RegistryError(f"{label} contains duplicates")
    return result


def _utc_timestamp(value: Any, label: str) -> str:
    text = _string(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RegistryError(f"{label} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise RegistryError(f"{label} must be stored as UTC")
    if not text.endswith("Z"):
        raise RegistryError(f"{label} must use canonical Z notation")
    return text


def _source(value: Any) -> SourceEndpoint:
    if not isinstance(value, dict) or set(value) != SOURCE_KEYS:
        raise RegistryError("source entry fields do not match the frozen schema")
    source_id = _string(value["source_id"], "source_id")
    if ID_PATTERN.fullmatch(source_id) is None:
        raise RegistryError(f"invalid source_id: {source_id}")
    exchange = _string(value["exchange"], "exchange")
    if exchange not in APPROVED_EXCHANGES:
        raise RegistryError(f"exchange is not approved: {exchange}")
    hosts = tuple(
        host.lower()
        for host in _string_tuple(value["allowed_hosts"], "allowed_hosts")
    )
    expected_host = EXCHANGE_HOSTS[exchange]
    if hosts != (expected_host,):
        raise RegistryError(
            f"{source_id} must freeze the exact official host {expected_host}"
        )
    media_type = _string(value["media_type"], "media_type")
    if media_type not in APPROVED_MEDIA_TYPES:
        raise RegistryError(f"media type is not approved: {media_type}")
    if value["license_policy"] != "OFFICIAL_PUBLIC_ENDPOINT_USE_TERMS_APPLY":
        raise RegistryError("source license policy is not the frozen policy")
    endpoint = _string(value["endpoint_template"], "endpoint_template")
    validate_https_url(
        endpoint,
        allowed_hosts=hosts,
        label="endpoint_template",
        allow_template=True,
    )
    for field in (
        "documentation_url",
        "owner_reference_url",
        "use_terms_url",
    ):
        validate_https_url(
            _string(value[field], field),
            allowed_hosts=hosts,
            label=field,
        )
    return SourceEndpoint(
        source_id=source_id,
        exchange=exchange,
        owner=_string(value["owner"], "owner"),
        owner_reference_url=value["owner_reference_url"],
        license_policy=_string(value["license_policy"], "license_policy"),
        use_terms_url=value["use_terms_url"],
        endpoint_template=endpoint,
        documentation_url=value["documentation_url"],
        allowed_hosts=hosts,
        media_type=media_type,
        endpoint_schema_version=_string(
            value["endpoint_schema_version"], "endpoint_schema_version"
        ),
        availability_policy=_string(
            value["availability_policy"], "availability_policy"
        ),
        required_top_level_fields=_string_tuple(
            value["required_top_level_fields"], "required_top_level_fields"
        ),
        required_row_fields=_string_tuple(
            value["required_row_fields"], "required_row_fields"
        ),
    )


def load_registry(path: Path) -> SourceRegistry:
    raw = _read_exact_regular(path)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError("source registry is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or set(payload) != ROOT_KEYS:
        raise RegistryError("source registry fields do not match the frozen schema")
    if payload["schema_version"] != REGISTRY_SCHEMA_VERSION:
        raise RegistryError("source registry schema_version mismatch")
    registry_id = _string(payload["registry_id"], "registry_id")
    if ID_PATTERN.fullmatch(registry_id) is None:
        raise RegistryError("invalid registry_id")
    if payload["timezone"] != "Asia/Shanghai":
        raise RegistryError("source registry must freeze Asia/Shanghai")
    if payload["timestamp_storage"] != "UTC":
        raise RegistryError("source registry must store timestamps as UTC")
    sources_value = payload["sources"]
    if not isinstance(sources_value, list) or len(sources_value) != 2:
        raise RegistryError("v1 registry must contain exactly SHFE and INE sources")
    sources = tuple(_source(item) for item in sources_value)
    if {item.exchange for item in sources} != APPROVED_EXCHANGES:
        raise RegistryError("v1 registry must cover exactly SHFE and INE")
    if len({item.source_id for item in sources}) != len(sources):
        raise RegistryError("source_id values must be unique")
    authority = validate_authority(payload["authority"])
    return SourceRegistry(
        registry_id=registry_id,
        schema_version=payload["schema_version"],
        published_at=_utc_timestamp(payload["published_at"], "published_at"),
        raw=raw,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        timezone=payload["timezone"],
        timestamp_storage=payload["timestamp_storage"],
        authority=authority,
        sources=sources,
    )
