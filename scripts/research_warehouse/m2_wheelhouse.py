"""Exact-byte offline wheelhouse contracts for the M2 release."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_json_line, parse_json_strict, sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .manifest_contracts import SHA256_PATTERN

WHEELHOUSE_SCHEMA = "vnpy_research_m2_wheelhouse_manifest_v1"
PYTHON_VERSION = "3.12"
WHEEL_KEYS = {"filename", "raw_sha256"}
WHEELHOUSE_KEYS = {"schema_version", "python_version", "wheels"}
SAFE_WHEEL_PATTERN = re.compile(r"^[A-Za-z0-9_.+-]+\.whl$")


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RegistryError(f"{label} fields do not match v1")
    return value


def _regular_bytes(path: Path, label: str) -> bytes:
    return read_regular_strict(path, label, private=False)


def _safe_filename(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or SAFE_WHEEL_PATTERN.fullmatch(value) is None
        or PurePosixPath(value).name != value
    ):
        raise RegistryError(f"{label} is unsafe")
    return value


def create_wheelhouse_manifest(wheelhouse: Path) -> dict[str, Any]:
    try:
        root = wheelhouse.resolve(strict=True)
    except OSError as exc:
        raise RegistryError("M2 wheelhouse is unavailable") from exc
    if not root.is_dir():
        raise RegistryError("M2 wheelhouse must be a directory")
    wheels = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        filename = _safe_filename(path.name, "M2 wheel filename")
        raw = _regular_bytes(path, f"M2 wheel {filename}")
        wheels.append({"filename": filename, "raw_sha256": sha256(raw)})
    if not wheels:
        raise RegistryError("M2 wheelhouse is empty")
    return {
        "schema_version": WHEELHOUSE_SCHEMA,
        "python_version": PYTHON_VERSION,
        "wheels": wheels,
    }


def load_wheelhouse_manifest(
    path: Path,
    *,
    expected_raw_sha256: str,
) -> tuple[dict[str, Any], str]:
    if SHA256_PATTERN.fullmatch(expected_raw_sha256) is None:
        raise RegistryError("expected M2 wheelhouse manifest SHA256 is invalid")
    raw = _regular_bytes(path, "M2 wheelhouse manifest")
    if sha256(raw) != expected_raw_sha256:
        raise RegistryError("M2 wheelhouse manifest raw SHA256 mismatch")
    value = parse_json_strict(raw, "M2 wheelhouse manifest")
    _exact(value, WHEELHOUSE_KEYS, "M2 wheelhouse manifest")
    if (
        value["schema_version"] != WHEELHOUSE_SCHEMA
        or value["python_version"] != PYTHON_VERSION
        or canonical_json_line(value) != raw
        or not isinstance(value["wheels"], list)
        or not value["wheels"]
    ):
        raise RegistryError("M2 wheelhouse manifest contract mismatch")
    names = []
    for wheel in value["wheels"]:
        _exact(wheel, WHEEL_KEYS, "M2 wheel")
        names.append(_safe_filename(wheel["filename"], "M2 wheel filename"))
        if (
            not isinstance(wheel["raw_sha256"], str)
            or SHA256_PATTERN.fullmatch(wheel["raw_sha256"]) is None
        ):
            raise RegistryError("M2 wheel SHA256 is invalid")
    if names != sorted(names) or len(names) != len(set(names)):
        raise RegistryError("M2 wheel manifest must be unique and sorted")
    return value, expected_raw_sha256


def verify_wheelhouse(
    wheelhouse: Path,
    manifest: dict[str, Any],
) -> None:
    try:
        root = wheelhouse.resolve(strict=True)
        actual_names = sorted(item.name for item in root.iterdir())
    except OSError as exc:
        raise RegistryError("M2 wheelhouse is unavailable") from exc
    expected_names = [item["filename"] for item in manifest["wheels"]]
    if actual_names != expected_names:
        raise RegistryError("M2 wheelhouse membership mismatch")
    for item in manifest["wheels"]:
        path = root / item["filename"]
        if sha256(_regular_bytes(path, f"M2 wheel {path.name}")) != item["raw_sha256"]:
            raise RegistryError(f"M2 wheel raw SHA256 mismatch: {path.name}")
