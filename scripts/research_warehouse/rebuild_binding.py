"""Trusted tool/dependency bindings for deterministic rebuilds."""

from __future__ import annotations

import re
from pathlib import Path

from .canonical import sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict
from .normalization_models import NormalizationBinding

GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def load_normalization_binding(
    *,
    tool_commit_sha: str,
    dependency_lock_path: Path,
    expected_dependency_lock_sha256: str,
    registry_raw_sha256: str,
) -> NormalizationBinding:
    if (
        not isinstance(tool_commit_sha, str)
        or GIT_SHA_PATTERN.fullmatch(tool_commit_sha) is None
    ):
        raise RegistryError("tool commit must be a lowercase 40-byte Git SHA")
    if (
        not isinstance(expected_dependency_lock_sha256, str)
        or not isinstance(registry_raw_sha256, str)
        or SHA256_PATTERN.fullmatch(expected_dependency_lock_sha256) is None
        or SHA256_PATTERN.fullmatch(registry_raw_sha256) is None
    ):
        raise RegistryError("normalization binding SHA256 is invalid")
    raw = read_regular_strict(
        dependency_lock_path,
        "dependency lock",
        limit=2 * 1024 * 1024,
        private=False,
    )
    if sha256(raw) != expected_dependency_lock_sha256:
        raise RegistryError("dependency lock hash mismatch")
    return NormalizationBinding(
        tool_commit_sha=tool_commit_sha,
        dependency_lock_sha256=expected_dependency_lock_sha256,
        registry_raw_sha256=registry_raw_sha256,
    )
