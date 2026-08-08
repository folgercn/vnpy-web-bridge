"""Create and consume the bounded Phase-B monitor projection contract.

Each producer owns one projection directory and updates only its own file.
The monitor receives those directories read-only; a projection can describe
health, but can never grant authority or change producer state.
"""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from collections.abc import Mapping
from pathlib import Path

from .contracts import (
    CONTRACT_VERSION,
    HealthSnapshot,
    ReadinessSnapshot,
    WorkerIdentity,
    isoformat,
    parse_time,
    sha256_hex,
)

PROJECTION_SCHEMA_VERSION = "phase-b-worker-projection-v1"
REQUIRED_PROJECTION_SERVICES = frozenset(
    {"artifact-custody", "market-data-worker", "execution-quality-worker"}
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProjectionError(ValueError):
    pass


def build_projection(
    *,
    service_id: str,
    generation: str,
    health: HealthSnapshot | Mapping[str, object],
    readiness: ReadinessSnapshot | Mapping[str, object],
    version: WorkerIdentity | Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(generation, str) or not generation or len(generation) > 192:
        raise ProjectionError("PROJECTION_GENERATION_INVALID")
    payload = {
        "health": health.as_dict() if hasattr(health, "as_dict") else dict(health),
        "readiness": readiness.as_dict()
        if hasattr(readiness, "as_dict")
        else dict(readiness),
        "version": version.as_dict() if hasattr(version, "as_dict") else dict(version),
    }
    return {
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "service_id": service_id,
        "generation": generation,
        "projected_at_utc": isoformat(),
        "payload": payload,
        "payload_sha256": sha256_hex(payload),
        "production": False,
        "live": False,
        "countable_forward": False,
    }


def validate_projection(
    value: Mapping[str, object],
    *,
    expected_service_id: str,
    max_age_seconds: float = 60.0,
) -> dict[str, object]:
    if set(value) != {
        "schema_version",
        "service_id",
        "generation",
        "projected_at_utc",
        "payload",
        "payload_sha256",
        "production",
        "live",
        "countable_forward",
    }:
        raise ProjectionError("PROJECTION_SCHEMA_INVALID")
    if value.get("schema_version") != PROJECTION_SCHEMA_VERSION:
        raise ProjectionError("PROJECTION_SCHEMA_INVALID")
    if value.get("service_id") != expected_service_id:
        raise ProjectionError("PROJECTION_SERVICE_ID_MISMATCH")
    generation = value.get("generation")
    if not isinstance(generation, str) or not generation:
        raise ProjectionError("PROJECTION_GENERATION_INVALID")
    if any(
        value.get(flag) is not False
        for flag in ("production", "live", "countable_forward")
    ):
        raise ProjectionError("PROJECTION_AUTHORITY_INVALID")
    payload = value.get("payload")
    if not isinstance(payload, Mapping) or set(payload) != {
        "health",
        "readiness",
        "version",
    }:
        raise ProjectionError("PROJECTION_PAYLOAD_INVALID")
    if value.get("payload_sha256") != sha256_hex(payload):
        raise ProjectionError("PROJECTION_HASH_MISMATCH")
    if (
        not isinstance(value.get("payload_sha256"), str)
        or _SHA256.fullmatch(str(value["payload_sha256"])) is None
    ):
        raise ProjectionError("PROJECTION_HASH_INVALID")
    for key in ("health", "readiness", "version"):
        nested = payload[key]
        if (
            not isinstance(nested, Mapping)
            or nested.get("service_id") != expected_service_id
        ):
            raise ProjectionError("PROJECTION_SERVICE_ID_MISMATCH")
    version = payload["version"]
    if CONTRACT_VERSION not in version.get("contract_versions", []):
        raise ProjectionError("PROJECTION_VERSION_INVALID")
    observed = parse_time(value.get("projected_at_utc"))
    age = (parse_time(isoformat()) - observed).total_seconds()
    if age < -5.0 or age > max(1.0, float(max_age_seconds)):
        raise ProjectionError("PROJECTION_STALE")
    return dict(value)


def publish_projection(
    directory: str | Path | None, projection: Mapping[str, object]
) -> None:
    """Atomically replace the sole producer-owned projection file."""

    if directory is None:
        return
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ProjectionError("PROJECTION_DIRECTORY_INVALID")
    os.chmod(root, 0o700)
    service_id = str(projection.get("service_id") or "")
    if not service_id:
        raise ProjectionError("PROJECTION_SERVICE_ID_INVALID")
    raw = (
        json.dumps(
            dict(projection), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        + "\n"
    ).encode("utf-8")
    temporary = root / f".{service_id}.{uuid.uuid4().hex}.tmp"
    target = root / f"{service_id}.json"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ProjectionError("PROJECTION_WRITE_FAILED")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, target)
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
